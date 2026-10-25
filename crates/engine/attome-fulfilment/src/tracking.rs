//! F6-T10: shipment status follows the carrier.
//!
//! [`apply`] is the one path a carrier update takes, from the track route
//! or the [`JOB`] poll: an update is applied once. It is ignored when its
//! event key equals the shipment's `last_event_key` or its time is not
//! newer than `last_event_at`; otherwise status, key and time move in one
//! transaction with a `fulfilment.shipment.<status>` change-feed event. A
//! first `delivered` sets `delivered_on` and adds the shipped quantities to
//! the order lines' `quantity_delivered`; a `failed_attempt` opens one
//! `failed_delivery` exception for the shipment.
//!
//! The poll runs every 30 minutes over booked shipments not yet in a final
//! status, asks each carrier for up to [`crate::carrier`]'s batch of
//! waybills per call, and skips a carrier whose system pushes its events
//! (`push_events`). Two workers never poll at once (advisory lock).
//!
//! Pushed events arrive through the integration webhook
//! (`/api/v1/integrations/{system}/webhook`, one integration system per
//! carrier) as `carrier.tracking` integration events; each poll first reads
//! the new ones from the change feed (consumer [`CONSUMER`]) and applies
//! them the same way.

use std::collections::BTreeMap;

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_integration::carrier as seam;
use attome_integration::connector::adapters::carrier_aramex::TrackingUpdate;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "fulfilment_tracking";

/// Statuses a carrier no longer moves.
pub const FINAL: [&str; 4] = ["delivered", "refused", "returned", "cancelled"];

/// Most shipments one poll reads.
const POLL_LIMIT: i64 = 2_000;

/// The change-feed consumer that reads pushed tracking events.
pub const CONSUMER: &str = "attome-fulfilment/carrier_events";

/// Events read per batch, and most batches per run.
const PUSH_BATCH: i64 = 500;
const PUSH_MAX_BATCHES: usize = 10;

/// Pushed events older than this are passed over (a new deployment never
/// replays history).
const PUSH_FRESH_HOURS: i64 = 24;

/// Whether an update with `key` at `at` is new for a shipment whose last
/// event was `last_key` at `last_at`. Pure.
pub fn is_new(
    last_key: Option<&str>,
    last_at: Option<DateTime<Utc>>,
    key: &str,
    at: DateTime<Utc>,
) -> bool {
    last_key != Some(key) && last_at.is_none_or(|last| at > last)
}

/// When an update happened; now when the carrier gave no time.
pub fn time_of(update: &TrackingUpdate) -> DateTime<Utc> {
    update
        .at_ms
        .and_then(DateTime::from_timestamp_millis)
        .unwrap_or_else(Utc::now)
}

/// Applies one carrier update to shipment `id`, once. `actor` is the person
/// who asked (the track route), recorded as a business event; a poll has
/// none. Answers whether the shipment moved.
pub async fn apply(
    state: &EngineState,
    id: Uuid,
    carrier: &str,
    update: &TrackingUpdate,
    actor: Option<Uuid>,
) -> Result<bool, AppError> {
    let at = time_of(update);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let moved: Option<(Option<String>, Option<Uuid>)> = sqlx::query_as(
        "WITH prev AS (SELECT id, status::text AS status FROM shipment WHERE id = $1 FOR UPDATE) \
         UPDATE shipment s SET status = $2, last_event_key = $3, last_event_at = $4, \
                delivered_on = CASE WHEN $2 = 'delivered' AND prev.status IS DISTINCT FROM 'delivered' \
                                    THEN $4 ELSE s.delivered_on END, \
                modified_at = now(), row_version = s.row_version + 1 \
           FROM prev \
          WHERE s.id = prev.id \
            AND s.last_event_key IS DISTINCT FROM $3 \
            AND (s.last_event_at IS NULL OR s.last_event_at < $4) \
         RETURNING prev.status, s.fulfilment_order_ref",
    )
    .bind(id)
    .bind(update.status)
    .bind(&update.code)
    .bind(at)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((previous, order)) = moved else {
        return Ok(false);
    };
    change_feed::emit_tx(&mut tx, "shipment", id, ChangeOperation::Update).await?;
    change_feed::emit_named(
        &mut tx,
        "shipment",
        id,
        ChangeOperation::Update,
        &format!("fulfilment.shipment.{}", update.status),
    )
    .await?;

    if update.status == "delivered" && previous.as_deref() != Some("delivered") {
        let lines: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE fulfilment_order_line l \
                SET quantity_delivered = COALESCE(l.quantity_delivered, 0) + s.quantity, \
                    modified_at = now(), row_version = l.row_version + 1 \
               FROM shipment_line s \
              WHERE s.shipment_ref = $1 AND l.id = s.fulfilment_order_line_ref \
                AND (s.is_active IS NULL OR s.is_active = true) \
             RETURNING l.id",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        for line in lines {
            change_feed::emit_tx(
                &mut tx,
                "fulfilment_order_line",
                line,
                ChangeOperation::Update,
            )
            .await?;
        }
    }
    if update.status == "failed_attempt"
        && let Some(order) = order
    {
        let opened: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO fulfilment_exception \
                 (id, fulfilment_order_ref, shipment_ref, kind, reason, suggested_action, status, \
                  created_by, owner_ref) \
             SELECT uuidv7(), o.id, $2, 'failed_delivery', $3, $4, 'open', \
                    COALESCE(o.created_by, o.owner_ref), o.owner_ref \
               FROM fulfilment_order o \
              WHERE o.id = $1 \
                AND NOT EXISTS (SELECT 1 FROM fulfilment_exception e \
                                 WHERE e.shipment_ref = $2 AND e.kind::text = 'failed_delivery' \
                                   AND e.status::text = 'open' \
                                   AND (e.is_active IS NULL OR e.is_active = true)) \
             RETURNING id",
        )
        .bind(order)
        .bind(id)
        .bind(format!("{carrier} could not deliver ({})", update.code))
        .bind(crate::exceptions::suggested_action("failed_delivery"))
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if let Some(exception) = opened {
            change_feed::emit_tx(
                &mut tx,
                "fulfilment_exception",
                exception,
                ChangeOperation::Create,
            )
            .await?;
        }
    }
    if let Some(actor) = actor {
        write_business_event_in_tx(
            &mut tx,
            &audit_service(state),
            BusinessEvent::new(
                "shipment",
                id,
                AuditOperation::Update,
                "fulfilment.shipment_tracked",
                actor,
            )
            .comment(format!("{carrier} {}: {}", update.code, update.status)),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// Applies the pushed tracking events that arrived since the last run.
/// Answers how many shipments moved.
pub async fn drain_pushed(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let mut moved = 0;
    for _ in 0..PUSH_MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = change_feed::read_batch(&mut conn, CONSUMER, PUSH_BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        let fresh_after = Utc::now() - chrono::Duration::hours(PUSH_FRESH_HOURS);
        for event in events.iter().filter(|e| {
            e.entity_logicalname == "integration_event"
                && e.event_name.is_none()
                && e.created_at >= fresh_after
        }) {
            match apply_pushed(state, event.record_id).await {
                Ok(n) => moved += n,
                Err(error) => {
                    tracing::warn!(event = %event.record_id, %error, "fulfilment tracking: pushed event not applied");
                }
            }
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(PUSH_BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(moved)
}

async fn apply_pushed(state: &EngineState, event_id: Uuid) -> Result<usize, AppError> {
    let db = &state.base.db;
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT e.event_type, e.payload, \
                CASE WHEN s.config IS JSON OBJECT THEN s.config::jsonb ->> 'carrier' END \
           FROM integration_event e \
           JOIN integration_system s ON s.id::text = e.system_ref::text \
          WHERE e.id = $1",
    )
    .bind(event_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((event_type, payload, Some(carrier))) = row else {
        return Ok(0);
    };
    if event_type != seam::PUSH_EVENT {
        return Ok(0);
    }
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
    let updates = seam::decode_push(&carrier, &payload);
    if updates.is_empty() {
        return Ok(0);
    }
    let numbers: Vec<String> = updates.iter().map(|(n, _)| n.clone()).collect();
    let shipments: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, tracking_number FROM shipment \
          WHERE carrier::text = $1 AND tracking_number = ANY($2) \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&carrier)
    .bind(&numbers)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut moved = 0;
    for (number, update) in &updates {
        for (id, _) in shipments.iter().filter(|(_, n)| n == number) {
            if apply(state, *id, &carrier, update, None).await? {
                moved += 1;
            }
        }
    }
    Ok(moved)
}

/// One poll: pushed events first, then every booked shipment not in a
/// final status, by carrier. Answers how many moved.
pub async fn poll(state: &EngineState) -> Result<usize, AppError> {
    let pushed = drain_pushed(state).await?;
    Ok(pushed + poll_carriers(state).await?)
}

async fn poll_carriers(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    // The lock only keeps two workers from polling at once; the carrier
    // calls run after it is released (never inside a transaction).
    let mut guard = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-fulfilment/tracking:poll")
        .fetch_one(&mut *guard)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(0);
    }
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, carrier::text, tracking_number FROM shipment \
          WHERE carrier IS NOT NULL AND COALESCE(tracking_number, '') <> '' \
            AND COALESCE(status::text, '') <> ALL($1) \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY last_event_at NULLS FIRST, id LIMIT $2",
    )
    .bind(FINAL.map(str::to_owned).to_vec())
    .bind(POLL_LIMIT)
    .fetch_all(&mut *guard)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(guard).await?;

    let mut by_carrier: BTreeMap<String, Vec<(Uuid, String)>> = BTreeMap::new();
    for (id, carrier, tracking) in rows {
        if seam::CARRIERS.contains(&carrier.as_str()) {
            by_carrier.entry(carrier).or_default().push((id, tracking));
        }
    }
    let mut moved = 0;
    for (carrier, shipments) in by_carrier {
        if seam::pushes_events(state, &carrier).await? {
            continue;
        }
        let numbers: Vec<String> = shipments.iter().map(|(_, n)| n.clone()).collect();
        let updates = match seam::track_many(state, &carrier, &numbers).await {
            Ok(Some(updates)) => updates,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%carrier, %error, "fulfilment tracking: carrier poll failed");
                continue;
            }
        };
        let by_number: BTreeMap<String, TrackingUpdate> = updates.into_iter().collect();
        for (id, number) in &shipments {
            let Some(update) = by_number.get(number) else {
                continue;
            };
            match apply(state, *id, &carrier, update, None).await {
                Ok(true) => moved += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(shipment = %id, %error, "fulfilment tracking: update not applied");
                }
            }
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(s, 0).unwrap_or_default()
    }

    /// F6-T10: the same carrier event (same key, or a time not after the
    /// last one) changes nothing; a later event does.
    #[test]
    fn tracking_same_event_applied_once() {
        assert!(is_new(None, None, "OD@1", at(100)));
        assert!(!is_new(Some("OD@1"), Some(at(100)), "OD@1", at(100)));
        assert!(!is_new(Some("OD@1"), Some(at(100)), "OD@1", at(200)));
        assert!(!is_new(Some("OD@1"), Some(at(100)), "DL@0", at(50)));
        assert!(!is_new(Some("OD@1"), Some(at(100)), "DL@1", at(100)));
        assert!(is_new(Some("OD@1"), Some(at(100)), "DL@2", at(200)));
        let update = TrackingUpdate {
            code: "SH005".into(),
            status: "delivered",
            at_ms: Some(200_000),
        };
        assert_eq!(time_of(&update), at(200));
    }
}
