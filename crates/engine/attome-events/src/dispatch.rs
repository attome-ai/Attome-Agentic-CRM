//! Dispatcher tick (M62 plan §3 "Dispatcher job") — for every active
//! `kind = 'webhook'` subscription, reads its outbox cursor, applies the
//! subscription's filter, and enqueues one delivery job per newly-matched
//! event. Enqueued on a schedule (`server::jobs::spawn_events_dispatch_
//! scheduler`, `EngineJob::EventsDispatchTick`) — see that job's doc
//! comment in `attome_jobs::job` for the full contract.
//!
//! Only `kind = 'webhook'` is dispatched in Phase 1 — `job`/`workflow`/
//! `internal` subscriptions are accepted at the schema level (migration
//! `0143`) for the plan's full target shape, but their delivery handlers are
//! Phase 2 work (D-403's Phase 1 note); the admin API also refuses to create
//! one today (`admin::valid_kind`).

use attome_core::jobs::EngineJob;
use attome_core::{EngineState, change_feed};
use attome_types::AppError;
use uuid::Uuid;

use crate::filter::SubscriptionFilter;
use crate::telemetry;

#[derive(sqlx::FromRow)]
struct ActiveSubscription {
    id: Uuid,
    filter_entity_logicalnames: Option<Vec<String>>,
    filter_operations: Option<Vec<String>>,
    filter_event_names: Option<Vec<String>>,
    filter_expression: Option<String>,
    payload_shape: String,
}

/// The `change_consumer_cursor.consumer` key one subscription's
/// outbox read position is stored under — `pub` so integration tests can
/// assert against the real key shape rather than a copy of it.
pub fn consumer_key(subscription_id: Uuid) -> String {
    format!("events:{subscription_id}")
}

/// Runs one tick across every active webhook subscription. Returns the
/// number of delivery jobs newly enqueued (0 is the common case: an idle
/// deployment with nothing new in the outbox). Each subscription is
/// independent — one subscription's read/enqueue failure does not stop the
/// tick from processing the rest; it is logged and surfaces on the next
/// scheduled tick automatically (the cursor for that subscription simply
/// did not advance).
pub async fn dispatch_pending(state: &EngineState) -> Result<u64, AppError> {
    let batch_size = state.base.config.events.dispatch_batch_size;

    let subs: Vec<ActiveSubscription> = sqlx::query_as(
        "SELECT id, filter_entity_logicalnames, filter_operations, filter_event_names, \
                filter_expression, payload_shape \
         FROM event_subscription \
         WHERE is_deleted = FALSE AND is_active = TRUE AND kind = 'webhook'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut enqueued_total = 0u64;
    for sub in &subs {
        match dispatch_one(state, sub, batch_size).await {
            Ok(n) => {
                telemetry::dispatched("webhook", n);
                enqueued_total += n;
            }
            Err(e) => {
                telemetry::dispatch_failed("webhook");
                tracing::warn!(
                    subscription_id = %sub.id,
                    error = %e,
                    "events dispatch: one subscription's tick failed, continuing with the rest"
                );
            }
        }
    }
    // M62 E1: the backlog gauges ride this tick (every `EventsDispatchTick`
    // runs it). Observational: a failed read is logged inside, never raised.
    telemetry::refresh_gauges(&state.base.db).await;
    Ok(enqueued_total)
}

async fn dispatch_one(
    state: &EngineState,
    sub: &ActiveSubscription,
    batch_size: i64,
) -> Result<u64, AppError> {
    let consumer = consumer_key(sub.id);
    let filter = SubscriptionFilter::new(
        sub.filter_entity_logicalnames.clone(),
        sub.filter_operations.clone(),
        sub.filter_event_names.clone(),
        sub.filter_expression.clone(),
    );

    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = change_feed::read_batch(&mut conn, &consumer, batch_size).await?;
    if events.is_empty() {
        return Ok(0);
    }

    let mut enqueued = 0u64;
    for event in &events {
        if !filter.matches(event) {
            continue;
        }
        // The INSERT ... ON CONFLICT DO NOTHING below IS the idempotency
        // key (subscription_id + event_id, migration 0144's unique
        // constraint) — a delivery job is enqueued only for a row this call
        // actually inserted, so a re-read of an already-processed event
        // (crash between enqueue and cursor advance, or an overlapping run)
        // creates neither a duplicate row nor a duplicate job.
        let with_changes = crate::payload::PayloadShape::from_stored(&sub.payload_shape)
            == crate::payload::PayloadShape::Changes;
        if let Some(delivery_id) =
            create_delivery_row_shaped(&state.base.db, sub.id, event, with_changes).await?
        {
            // Belt-and-suspenders dedup: the row above already guarantees at
            // most one delivery row per (subscription, event), and
            // `enqueue_dedup` additionally guarantees at most one eligible
            // (Pending/Running/Failed) job row per `delivery_id` — so a
            // crash-and-retry of this whole function can never double-enqueue
            // the job even if it somehow re-inserted the row.
            attome_jobs::enqueue_dedup(
                &state.base.db,
                EngineJob::EventsDeliverWebhook { delivery_id },
                &delivery_id.to_string(),
            )
            .await
            .map_err(AppError::internal)?;
            enqueued += 1;
        }
    }

    // Advance the cursor only after every event this batch read has been
    // durably handled (matched-and-enqueued, or filtered out) — M62 plan §3
    // "advances the cursor only after enqueue commits". A crash between the
    // last enqueue above and this advance simply re-reads (and re-filters,
    // idempotently) the same batch on the next tick.
    if let Some(last) = events.last() {
        change_feed::advance(&mut conn, &consumer, last).await?;
    }

    Ok(enqueued)
}

/// Inserts the delivery row for one matched `(subscription, event)` pair.
/// `Ok(None)` — not an error — when a row for that exact pair already
/// exists (migration `0144`'s `UNIQUE (subscription_ref, event_id)`): this
/// IS the idempotency key the M62 plan asks for, and `pub` here so
/// integration tests can prove the property directly rather than through a
/// copy of this query.
pub async fn create_delivery_row(
    db: &attome_db::DbPool,
    subscription_id: Uuid,
    event: &change_feed::ChangeEvent,
) -> Result<Option<Uuid>, AppError> {
    create_delivery_row_shaped(db, subscription_id, event, false).await
}

/// M13-T1: [`create_delivery_row`] that also keeps the event name and the
/// changed attribute names, and, for a `changes`-shaped subscription
/// (`with_changes`), the outbox row's old and new values, so the body can be
/// built after the outbox row is pruned. Other shapes copy no values.
pub async fn create_delivery_row_shaped(
    db: &attome_db::DbPool,
    subscription_id: Uuid,
    event: &change_feed::ChangeEvent,
    with_changes: bool,
) -> Result<Option<Uuid>, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO event_delivery \
            (subscription_ref, event_id, event_entity_logicalname, event_record_id, event_operation, \
             event_name, changed_attributes, changes_before, changes_after) \
         SELECT $1, $2, $3, $4, $5, $6, $7, e.before, e.after \
           FROM (SELECT 1) AS one \
           LEFT JOIN entity_change_event e ON $8 AND e.id = $2 \
         ON CONFLICT (subscription_ref, event_id) DO NOTHING \
         RETURNING id",
    )
    .bind(subscription_id)
    .bind(event.id)
    .bind(&event.entity_logicalname)
    .bind(event.record_id)
    .bind(&event.operation)
    .bind(&event.event_name)
    .bind(&event.changed_attributes)
    .bind(with_changes)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}
