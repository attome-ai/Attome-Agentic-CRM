//! Commission credits from won deals (roadmap F10-T3, the won-deal source).
//!
//! [`sweep_won_deals`] reads opportunity changes off the change feed (its
//! own cursor, `attome-commission/credits`). For a deal at `closed_won` it
//! writes one `comp_credit` per revenue split, to the split member's
//! participation in a published plan with a `split_amount` component, for
//! the split's stored amount (D7-T4; never recomputed here). A deal with no
//! splits credits its owner with the deal amount. Credits are keyed by
//! source (`split`, the split id), so a replayed event writes nothing twice.
//!
//! The credit is dated on the deal's close date (today when it has none)
//! and lands in the period containing that date; when that period is
//! approved or locked it lands in the next open one, with a zero
//! `comp_adjustment` naming the locked period it belonged to (F10-T7).
//! Amounts stay in the deal's currency: no exchange rates exist yet.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use uuid::Uuid;

/// The change-feed consumer that writes credits.
pub const CREDIT_CONSUMER: &str = "attome-commission/credits";

const SWEEP_BATCH: i64 = 200;

/// One credit to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSource {
    pub user: Uuid,
    /// `split` (or `order`, `invoice`, `payment` as those sources land).
    pub kind: &'static str,
    pub source_id: String,
    /// Decimal text.
    pub amount: String,
    pub currency: Option<String>,
    pub credited_on: NaiveDate,
}

/// The credits a won deal gives: one per revenue split with a member user,
/// or the owner's whole amount when it has no splits.
pub fn won_deal_credits(
    deal: Uuid,
    owner: Option<Uuid>,
    deal_amount: Option<String>,
    currency: Option<String>,
    credited_on: NaiveDate,
    splits: &[(Uuid, Option<Uuid>, Option<String>)],
) -> Vec<CreditSource> {
    if splits.is_empty() {
        return match (owner, deal_amount) {
            (Some(user), Some(amount)) => vec![CreditSource {
                user,
                kind: "split",
                source_id: format!("{deal}:owner"),
                amount,
                currency,
                credited_on,
            }],
            _ => Vec::new(),
        };
    }
    splits
        .iter()
        .filter_map(|(split, user, amount)| {
            Some(CreditSource {
                user: (*user)?,
                kind: "split",
                source_id: split.to_string(),
                amount: amount.clone()?,
                currency: currency.clone(),
                credited_on,
            })
        })
        .collect()
}

/// The participation a credit goes to: the user's in the latest published
/// plan version that measures `measure` and covers the date.
async fn participant_for(
    db: &attome_db::DbPool,
    user: Uuid,
    measure: &str,
    on: NaiveDate,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT p.id FROM plan_participant p \
         JOIN comp_plan_version v ON v.id = p.plan_version_ref \
         WHERE p.user_ref = $1 AND v.published_at IS NOT NULL \
           AND (p.is_active IS NULL OR p.is_active = true) \
           AND (v.is_active IS NULL OR v.is_active = true) \
           AND (p.starts_on IS NULL OR p.starts_on::date <= $3) \
           AND (p.ends_on IS NULL OR p.ends_on::date >= $3) \
           AND EXISTS (SELECT 1 FROM comp_component c WHERE c.plan_version_ref = v.id \
               AND c.measure = $2 AND (c.is_active IS NULL OR c.is_active = true)) \
         ORDER BY v.published_at DESC, p.id LIMIT 1",
    )
    .bind(user)
    .bind(measure)
    .bind(on)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Writes one credit unless the participant already has one for the same
/// source; whether a row was written.
pub async fn credit_from_source(
    state: &EngineState,
    participant: Uuid,
    source: &CreditSource,
) -> Result<bool, AppError> {
    let Some((period, locked_original)) =
        crate::close::late_credit_target(&state.base.db, source.credited_on).await?
    else {
        tracing::warn!(
            %participant,
            source = %source.source_id,
            on = %source.credited_on,
            "commission credit: no open period for the credit's date; not written"
        );
        return Ok(false);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-commission/credit:{participant}:{}:{}",
            source.kind, source.source_id
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this credit is being written by another worker",
        ));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM comp_credit WHERE participant_ref = $1 \
             AND source_kind = $2 AND source_id = $3 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(participant)
    .bind(source.kind)
    .bind(&source.source_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO comp_credit \
           (participant_ref, period_ref, source_kind, source_id, amount, currency, credited_on, \
            owner_ref) \
         VALUES ($1, $2, $3, $4, $5::numeric, $6, $7, $8)",
    )
    .bind(participant)
    .bind(period)
    .bind(source.kind)
    .bind(&source.source_id)
    .bind(&source.amount)
    .bind(&source.currency)
    .bind(source.credited_on)
    .bind(source.user)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(original) = locked_original {
        sqlx::query(
            "INSERT INTO comp_adjustment (participant_ref, period_ref, amount, reason, owner_ref) \
             VALUES ($1, $2, 0, $3, $4)",
        )
        .bind(participant)
        .bind(period)
        .bind(format!(
            "late credit {} {} dated {} belongs to closed period {original}",
            source.kind, source.source_id, source.credited_on
        ))
        .bind(source.user)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

type DealRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
);

/// Credits one deal if it is won; credits written.
pub async fn credit_won_deal(state: &EngineState, deal: Uuid) -> Result<u64, AppError> {
    let db = &state.base.db;
    let row: Option<DealRow> = sqlx::query_as(
        "SELECT stage, owner_ref, amount::text, currency, close_date::date FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((stage, owner, amount, currency, close_date)) = row else {
        return Ok(0);
    };
    if stage.as_deref() != Some("closed_won") {
        return Ok(0);
    }
    let splits: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT s.id, m.user_ref, s.amount::text FROM opportunity_split s \
         JOIN opportunity_team_member m ON m.id = s.member_ref \
         LEFT JOIN sales_split_type t ON t.id = s.split_type_ref \
         WHERE s.opportunity_ref = $1 AND COALESCE(t.counts_as_revenue, true) \
           AND (s.is_active IS NULL OR s.is_active = true) ORDER BY s.id",
    )
    .bind(deal)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let on = close_date.unwrap_or_else(|| Utc::now().date_naive());
    let mut written = 0;
    for source in won_deal_credits(deal, owner, amount, currency, on, &splits) {
        let Some(participant) = participant_for(db, source.user, "split_amount", on).await? else {
            continue;
        };
        if credit_from_source(state, participant, &source).await? {
            written += 1;
        }
    }
    Ok(written)
}

/// Credits every deal that changed and is won; credits written.
pub async fn sweep_won_deals(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, CREDIT_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    // Without the packs that define these tables there is nothing to do;
    // the cursor still moves past the batch.
    let installed: bool = sqlx::query_scalar(
        "SELECT bool_and(to_regclass(t) IS NOT NULL) FROM unnest($1::text[]) AS t",
    )
    .bind(&["comp_credit", "opportunity_split"][..])
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CREDIT_CONSUMER, &last).await?;
        return Ok(0);
    }
    let mut deals: Vec<Uuid> = events
        .iter()
        .filter(|e| e.entity_logicalname == "opportunity")
        .map(|e| e.record_id)
        .collect();
    deals.sort_unstable();
    deals.dedup();
    let mut written = 0;
    for deal in deals {
        written += credit_won_deal(state, deal).await?;
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, CREDIT_CONSUMER, &last).await?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 1).unwrap_or_default()
    }

    #[test]
    fn split_amounts_credit_each_participant() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let (s1, s2) = (Uuid::from_u128(11), Uuid::from_u128(12));
        let credits = won_deal_credits(
            Uuid::from_u128(9),
            Some(a),
            Some("1000".into()),
            Some("SAR".into()),
            day(),
            &[
                (s1, Some(a), Some("600.00".into())),
                (s2, Some(b), Some("400.00".into())),
            ],
        );
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].user, a);
        assert_eq!(credits[0].amount, "600.00");
        assert_eq!(credits[1].source_id, s2.to_string());
    }

    #[test]
    fn a_deal_without_splits_credits_its_owner_once() {
        let owner = Uuid::from_u128(1);
        let deal = Uuid::from_u128(9);
        let credits = won_deal_credits(deal, Some(owner), Some("500".into()), None, day(), &[]);
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].source_id, format!("{deal}:owner"));
        assert!(won_deal_credits(deal, None, Some("500".into()), None, day(), &[]).is_empty());
    }

    #[test]
    fn a_split_without_a_member_user_or_amount_credits_nobody() {
        let credits = won_deal_credits(
            Uuid::from_u128(9),
            None,
            None,
            None,
            day(),
            &[
                (Uuid::from_u128(11), None, Some("1".into())),
                (Uuid::from_u128(12), Some(Uuid::from_u128(1)), None),
            ],
        );
        assert!(credits.is_empty());
    }
}
