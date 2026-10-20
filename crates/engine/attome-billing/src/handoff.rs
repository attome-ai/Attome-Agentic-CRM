//! Hand-offs after commit (roadmap F3-T11): change-feed consumers (D-358
//! cursor model) that turn the subscription service's named events into
//! the events the revenue (F11) and churn (O3) features read. Nothing here
//! runs inside a subscription change: the consumers run every minute
//! (`EngineJob::BillingHandoffSweep`) on what has committed.
//!
//! - `attome-billing/churn-signal`: each `billing.subscription.cancelled`
//!   gives one `billing.subscription.churned` event (its `after` names the
//!   effective date and the reason). A replayed cancel event emits nothing
//!   more: a churned event written after the cancel already answers it.
//! - `attome-billing/revenue`: each subscription event gives one
//!   `billing.revenue_segment` event whose `after` lists the subscription's
//!   live segments (line, valid_from, valid_to, quantity, unit price and
//!   the period amount). The feed carries the whole current state, so the
//!   revenue schedule converges whatever it missed.
//!
//! Entitlements (G10) are not handed off: a subscription line carries no
//! entitlement kind, quantity or coverage window, which G10's entitlement
//! needs (the task's stop rule).

use attome_core::change_feed::{self, ChangeEvent, ChangeOperation, ChangePayload};
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// The churn consumer's cursor name; never reused.
pub const CHURN_CONSUMER: &str = "attome-billing/churn-signal";
/// The revenue consumer's cursor name; never reused.
pub const REVENUE_CONSUMER: &str = "attome-billing/revenue";

/// The event a cancellation hands to churn.
pub const CHURNED: &str = "billing.subscription.churned";
/// The event that carries a subscription's segments to revenue.
pub const REVENUE_SEGMENT: &str = "billing.revenue_segment";

/// Events per batch, and batches per run.
pub const BATCH: i64 = 500;
pub const MAX_BATCHES: usize = 10;

/// What one run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HandoffRun {
    pub churned: u64,
    pub revenue_events: u64,
}

/// Whether an event is one of the subscription service's own. Pure.
pub fn is_subscription_event(event: &ChangeEvent) -> bool {
    event.entity_logicalname == "subscription"
        && event
            .event_name
            .as_deref()
            .is_some_and(|n| n.starts_with("billing.subscription.") && n != CHURNED)
}

/// Runs both consumers.
pub async fn run(db: &DbPool) -> Result<HandoffRun, AppError> {
    Ok(HandoffRun {
        churned: churn(db).await?,
        revenue_events: revenue(db).await?,
    })
}

/// Reads one consumer's batches, handing each event to `handle`, and
/// advances the cursor after each batch. Returns how many events `handle`
/// acted on.
async fn consume<F, Fut>(db: &DbPool, consumer: &str, mut handle: F) -> Result<u64, AppError>
where
    F: FnMut(ChangeEvent) -> Fut,
    Fut: std::future::Future<Output = Result<bool, AppError>>,
{
    let mut acted = 0;
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = change_feed::read_batch(&mut conn, consumer, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        let full = events.len() >= usize::try_from(BATCH).unwrap_or(usize::MAX);
        for event in events {
            if handle(event).await? {
                acted += 1;
            }
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        change_feed::advance(&mut conn, consumer, &last).await?;
        if !full {
            break;
        }
    }
    Ok(acted)
}

async fn churn(db: &DbPool) -> Result<u64, AppError> {
    consume(db, CHURN_CONSUMER, |event| async move {
        if event.entity_logicalname != "subscription"
            || event.event_name.as_deref() != Some("billing.subscription.cancelled")
        {
            return Ok(false);
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let answered: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM entity_change_event \
                WHERE entity_logicalname = 'subscription' AND record_id = $1 \
                  AND event_name = $2 AND created_at >= $3)",
        )
        .bind(event.record_id)
        .bind(CHURNED)
        .bind(event.created_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if answered {
            return Ok(false);
        }
        let row: Option<(Option<chrono::NaiveDate>, Option<String>, Option<Uuid>)> =
            sqlx::query_as(
                "SELECT cancel_effective, cancel_reason, account_ref FROM subscription WHERE id = $1",
            )
            .bind(event.record_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let Some((effective, reason, account)) = row else {
            return Ok(false);
        };
        change_feed::emit_with(
            &mut tx,
            "subscription",
            event.record_id,
            ChangeOperation::Update,
            Some(CHURNED),
            &ChangePayload {
                after: Some(json!({
                    "account_ref": account,
                    "effective": effective,
                    "reason": reason,
                })),
                ..ChangePayload::default()
            },
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        Ok(true)
    })
    .await
}

type SegmentRow = (
    Uuid,
    chrono::NaiveDate,
    Option<chrono::NaiveDate>,
    Option<f64>,
    Option<f64>,
    Option<String>,
);

/// One segment as the revenue event lists it. Pure.
pub fn segment_json(row: &SegmentRow) -> Value {
    let (line, from, to, quantity, unit_price, model) = row;
    let period_amount = match (model.as_deref(), quantity, unit_price) {
        (Some("flat"), _, Some(price)) => Some(*price),
        (_, Some(q), Some(p)) => Some(q * p),
        _ => None,
    };
    json!({
        "line": line,
        "valid_from": from,
        "valid_to": to,
        "quantity": quantity,
        "unit_price": unit_price,
        "period_amount": period_amount,
    })
}

async fn revenue(db: &DbPool) -> Result<u64, AppError> {
    let mut seen = std::collections::HashSet::new();
    consume(db, REVENUE_CONSUMER, |event| {
        // One revenue event per subscription per batch is enough: it
        // carries the whole current state.
        let first = is_subscription_event(&event) && seen.insert(event.record_id);
        async move {
            if !first {
                return Ok(false);
            }
            let mut tx = attome_db::tx::begin(db).await?;
            let rows: Vec<SegmentRow> = sqlx::query_as(
                "SELECT s.line_ref, s.valid_from, s.valid_to, s.quantity::float8, \
                        s.unit_price::float8, l.charge_model \
                   FROM subscription_segment s JOIN subscription_line l ON l.id = s.line_ref \
                  WHERE l.subscription_ref = $1 \
                    AND (s.is_active IS NULL OR s.is_active = true) \
                    AND (s.valid_to IS NULL OR s.valid_to > s.valid_from) \
                  ORDER BY s.line_ref, s.valid_from",
            )
            .bind(event.record_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            change_feed::emit_with(
                &mut tx,
                "subscription",
                event.record_id,
                ChangeOperation::Update,
                Some(REVENUE_SEGMENT),
                &ChangePayload {
                    after: Some(Value::Array(rows.iter().map(segment_json).collect())),
                    ..ChangePayload::default()
                },
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(true)
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Utc};

    fn event(name: Option<&str>) -> ChangeEvent {
        ChangeEvent {
            id: Uuid::now_v7(),
            entity_logicalname: "subscription".into(),
            record_id: Uuid::now_v7(),
            operation: "update".into(),
            event_name: name.map(str::to_owned),
            created_at: Utc::now(),
            changed_attributes: Vec::new(),
        }
    }

    #[test]
    fn only_the_service_events_feed_revenue() {
        assert!(is_subscription_event(&event(Some(
            "billing.subscription.amended"
        ))));
        assert!(!is_subscription_event(&event(Some(CHURNED))));
        assert!(!is_subscription_event(&event(Some(REVENUE_SEGMENT))));
        assert!(!is_subscription_event(&event(None)));
    }

    #[test]
    fn a_segment_carries_its_period_amount() {
        let line = Uuid::now_v7();
        let from = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap();
        let per_unit = segment_json(&(line, from, None, Some(10.0), Some(100.0), None));
        assert_eq!(per_unit["period_amount"], 1000.0);
        let flat = segment_json(&(
            line,
            from,
            None,
            Some(10.0),
            Some(100.0),
            Some("flat".into()),
        ));
        assert_eq!(flat["period_amount"], 100.0);
    }
}
