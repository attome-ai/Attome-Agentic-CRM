//! M19 (Audit) gap list — dispatch for `kind = 'audit'` subscriptions
//! (migration `0280`). Parallel to, and entirely independent of,
//! [`crate::dispatch`]'s `kind = 'webhook'` tick: that one reads
//! `entity_change_event` (the generic entity-mutation outbox) via
//! `attome_core::change_feed`; this one reads `audit_header`
//! directly.
//!
//! **Why a separate source, not a filter on the existing outbox.**
//! `AuditService::write_header` (`attome-audit/src/service.rs`) persists via
//! `attome_core::crud::append_only_insert` directly (C-17 (M01 §7)
//! renamed it from `insert`) — not through
//! `entity_mutation.rs`'s create/update/delete handlers, which are the only
//! callers of `change_feed::emit`/`emit_many`. Verified by reading
//! `crud.rs` end to end: a plain dynamic `INSERT ... RETURNING id` with no
//! outbox side effect. An audit header write therefore never produces an
//! `entity_change_event` row, so a `kind = 'webhook'` subscription
//! filtered to `audit_header` would simply never fire.
//!
//! **Ordering — the one thing this module cannot inherit from
//! `change_feed`.** `0104`'s `commit_xid` cursor exists because
//! `entity_change_event.created_at` (transaction-start time) does
//! not track commit order under concurrent writers, and a plain
//! `created_at`/`id` cursor silently loses events from a long transaction.
//! `audit_header.id` is a `uuidv7()` generated at INSERT time, and
//! `AuditService::acquire_chain_lock` takes a non-blocking, no-retry
//! `pg_try_advisory_xact_lock` scoped **per organization** before that
//! INSERT — a losing concurrent writer's whole mutation fails outright
//! rather than queuing, so for any ONE organization, `id` order and commit
//! order coincide exactly (the same property `fetch_last_hash`'s own doc
//! comment already relies on). Across DIFFERENT organizations writing
//! concurrently that guarantee does not hold. Rather than duplicating
//! `0104`'s (materially larger) `commit_xid` machinery for a Phase-1 push
//! feature, this module applies the same bounded mitigation
//! `attome_audit::admin`'s streamed export uses: a batch read never considers
//! a row less than [`DISPATCH_SAFETY_MARGIN_SECS`] old, giving any
//! still-in-flight concurrent writer time to commit first. A deployment
//! with multiple root organizations writing audit events at high
//! concurrency and needing a stronger guarantee should track a
//! `commit_xid` column on `audit_header` as follow-up work, not assume
//! this module already provides it.
//!
//! **Cursor storage.** Reuses `change_consumer_cursor` (the same
//! table `attome_core::change_feed`'s webhook consumers use) under key
//! `"audit-events:{subscription_id}"` — distinct from
//! `dispatch::consumer_key`'s `"events:{id}"` so the two are never
//! confused, though collision was never possible anyway (one subscription
//! row is only ever `kind = 'webhook'` XOR `kind = 'audit'`).
//! `attome_core::change_feed::cursor` is reused as-is for the
//! get-or-create read (it only touches the generic cursor table, not the
//! entity-change outbox — verified by reading its body), but `advance` is
//! NOT reused: that function computes its `GREATEST` bound from
//! `entity_change_event.commit_xid`, the wrong table for this
//! source. [`advance_audit_cursor`] does the equivalent `GREATEST`-guarded,
//! never-rewinds update directly against `last_id`.

use attome_core::{EngineState, change_feed};
use attome_types::AppError;
use uuid::Uuid;

use crate::filter::SubscriptionFilter;

/// See this module's doc comment.
const DISPATCH_SAFETY_MARGIN_SECS: i64 = 30;

#[derive(sqlx::FromRow)]
struct ActiveAuditSubscription {
    id: Uuid,
    filter_entity_logicalnames: Option<Vec<String>>,
    filter_operations: Option<Vec<String>>,
}

/// One `audit_header` row as this dispatcher reads it — deliberately
/// narrower than `attome_audit::admin`'s export row: only what's needed to
/// filter-match and to build the delivery row's denormalized columns.
struct AuditHeaderEvent {
    id: Uuid,
    entity_name: Option<String>,
    operation: i32,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// The `change_consumer_cursor.consumer` key one audit subscription's
/// read position is stored under — `pub` for the same reason
/// `dispatch::consumer_key` is: integration tests assert the real key shape.
pub fn consumer_key(subscription_id: Uuid) -> String {
    format!("audit-events:{subscription_id}")
}

/// Lowercase name for `audit_header.operation`'s integer discriminant —
/// what `filter_operations` is matched against and what
/// `event_delivery.event_operation` stores for this source, so an
/// operator reading the deliveries admin list sees `"update"`/
/// `"faileld_login"` rather than a bare integer. Deliberately a small local
/// copy rather than a dependency on `attome-audit`'s `AuditOperation` enum —
/// `attome-events` stays decoupled from `attome-audit`'s crate, the same way it
/// already denormalizes `ChangeOperation`'s names independently of
/// `attome-core::change_feed`'s own enum. Kept in sync with
/// `attome_audit::model::AuditOperation` by the
/// `audit_operation_names_match_model` test below, which reads that enum's
/// source directly.
fn audit_operation_name(op: i32) -> &'static str {
    match op {
        0 => "create",
        1 => "update",
        2 => "soft_delete",
        3 => "hard_delete",
        4 => "restore",
        5 => "merge",
        6 => "clone",
        7 => "import",
        8 => "export",
        9 => "login",
        10 => "logout",
        11 => "failed_login",
        12 => "permission_change",
        13 => "role_change",
        14 => "owner_change",
        15 => "approved",
        16 => "rejected",
        17 => "submitted",
        18 => "cancelled",
        19 => "closed",
        20 => "activated",
        21 => "erasure",
        22 => "mfa_reset",
        23 => "account_disabled",
        24 => "account_enabled",
        25 => "file_scanned",
        26 => "escalated",
        _ => "unknown",
    }
}

/// Runs one tick across every active `kind = 'audit'` subscription. Same
/// per-subscription isolation as `dispatch::dispatch_pending`: one
/// subscription's failure is logged and does not stop the rest.
pub async fn dispatch_pending(state: &EngineState) -> Result<u64, AppError> {
    let batch_size = state.base.config.events.dispatch_batch_size;

    let subs: Vec<ActiveAuditSubscription> = sqlx::query_as(
        "SELECT id, filter_entity_logicalnames, filter_operations \
         FROM event_subscription \
         WHERE is_deleted = FALSE AND is_active = TRUE AND kind = 'audit'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut enqueued_total = 0u64;
    for sub in &subs {
        match dispatch_one(state, sub, batch_size).await {
            Ok(n) => {
                crate::telemetry::dispatched("audit", n);
                enqueued_total += n;
            }
            Err(e) => {
                crate::telemetry::dispatch_failed("audit");
                tracing::warn!(
                    subscription_id = %sub.id,
                    error = %e,
                    "audit events dispatch: one subscription's tick failed, continuing with the rest"
                );
            }
        }
    }
    Ok(enqueued_total)
}

async fn dispatch_one(
    state: &EngineState,
    sub: &ActiveAuditSubscription,
    batch_size: i64,
) -> Result<u64, AppError> {
    let consumer = consumer_key(sub.id);

    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let position = change_feed::cursor(&mut conn, &consumer).await?;

    let ceiling = chrono::Utc::now() - chrono::Duration::seconds(DISPATCH_SAFETY_MARGIN_SECS);

    let rows: Vec<(Uuid, Option<String>, i32, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, entity_name, operation, created_at \
         FROM audit_header \
         WHERE is_active = true \
           AND ($1::uuid IS NULL OR id > $1) \
           AND created_at < $2 \
         ORDER BY id ASC \
         LIMIT $3",
    )
    .bind(position.last_id)
    .bind(ceiling)
    .bind(batch_size)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    if rows.is_empty() {
        return Ok(0);
    }
    let events: Vec<AuditHeaderEvent> = rows
        .into_iter()
        .map(
            |(id, entity_name, operation, created_at)| AuditHeaderEvent {
                id,
                entity_name,
                operation,
                created_at,
            },
        )
        .collect();

    let filter = SubscriptionFilter::new(
        sub.filter_entity_logicalnames.clone(),
        sub.filter_operations.clone(),
        // An audit-header event is never named, and `filter_expression`
        // (M45 Phase 3) evaluates against a `ChangeEvent`'s fields, which an
        // audit-header row is not — `matches_audit` consults neither, so
        // there is nothing to pass through for either.
        None,
        None,
    );

    let mut enqueued = 0u64;
    for event in &events {
        let op_name = audit_operation_name(event.operation);
        if !filter.matches_audit(event.entity_name.as_deref(), op_name) {
            continue;
        }
        if let Some(delivery_id) = create_delivery_row(&state.base.db, sub.id, event).await? {
            attome_jobs::enqueue_dedup(
                &state.base.db,
                attome_core::jobs::EngineJob::EventsDeliverWebhook { delivery_id },
                &delivery_id.to_string(),
            )
            .await
            .map_err(AppError::internal)?;
            enqueued += 1;
        }
    }

    if let Some(last) = events.last() {
        advance_audit_cursor(&mut conn, &consumer, last.id, last.created_at).await?;
    }

    Ok(enqueued)
}

/// Inserts the delivery row for one matched audit header. `event_id` is the
/// header's own `id` (there is no separate outbox-row id for this source);
/// `event_entity_logicalname`/`event_record_id` carry the sentinel
/// `"audit_header"`/the header's own id — `delivery::deliver` reads
/// `event_delivery.event_entity_logicalname` back to decide which
/// payload builder to use, so this sentinel is load-bearing, not
/// decorative. Same `ON CONFLICT DO NOTHING` idempotency-key shape as
/// `dispatch::create_delivery_row`.
async fn create_delivery_row(
    db: &attome_db::DbPool,
    subscription_id: Uuid,
    event: &AuditHeaderEvent,
) -> Result<Option<Uuid>, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO event_delivery \
            (subscription_ref, event_id, event_entity_logicalname, event_record_id, event_operation) \
         VALUES ($1, $2, 'audit_header', $2, $3) \
         ON CONFLICT (subscription_ref, event_id) DO NOTHING \
         RETURNING id",
    )
    .bind(subscription_id)
    .bind(event.id)
    .bind(audit_operation_name(event.operation))
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// `GREATEST`-guarded, never-rewinds cursor advance — see this module's doc
/// comment for why `change_feed::advance` (which reads `commit_xid` off
/// `entity_change_event`) cannot be reused here.
async fn advance_audit_cursor(
    conn: &mut sqlx::PgConnection,
    consumer: &str,
    last_id: Uuid,
    last_created_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE change_consumer_cursor \
            SET last_id = GREATEST(COALESCE(last_id, $2), $2), \
                last_created_at = $3, \
                updated_at = NOW() \
          WHERE consumer = $1",
    )
    .bind(consumer)
    .bind(last_id)
    .bind(last_created_at)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_key_is_distinct_from_the_webhook_dispatcher_namespace() {
        let id = Uuid::now_v7();
        assert_ne!(consumer_key(id), crate::dispatch::consumer_key(id));
        assert!(consumer_key(id).starts_with("audit-events:"));
    }

    #[test]
    fn every_operation_discriminant_has_a_name() {
        for op in 0..=26 {
            assert_ne!(
                audit_operation_name(op),
                "unknown",
                "operation {op} has no name — attome_audit::model::AuditOperation added a \
                 discriminant this table needs updating for"
            );
        }
        assert_eq!(audit_operation_name(27), "unknown");
    }

    /// Cross-checks this file's local name table against
    /// `attome_audit::model::AuditOperation`'s actual discriminants (read as
    /// source text, the same `include_str!` cross-check pattern
    /// `change_feed.rs`'s `wire_values_match_the_check_constraint` test
    /// uses) — every `Name = N,` line in that enum must have a matching
    /// entry here, so a discriminant added to the model without a matching
    /// name here fails this test instead of silently exporting `"unknown"`
    /// to a SIEM/webhook target.
    #[test]
    fn audit_operation_names_match_model() {
        let model_src = include_str!("../../attome-audit/src/model.rs");
        let expected: &[(i32, &str)] = &[
            (0, "create"),
            (1, "update"),
            (2, "soft_delete"),
            (3, "hard_delete"),
            (4, "restore"),
            (5, "merge"),
            (6, "clone"),
            (7, "import"),
            (8, "export"),
            (9, "login"),
            (10, "logout"),
            (11, "failed_login"),
            (12, "permission_change"),
            (13, "role_change"),
            (14, "owner_change"),
            (15, "approved"),
            (16, "rejected"),
            (17, "submitted"),
            (18, "cancelled"),
            (19, "closed"),
            (20, "activated"),
            (21, "erasure"),
            (22, "mfa_reset"),
            (23, "account_disabled"),
            (24, "account_enabled"),
            (25, "file_scanned"),
            (26, "escalated"),
        ];
        for (discriminant, name) in expected {
            assert_eq!(audit_operation_name(*discriminant), *name);
        }
        // Every discriminant this file names must appear in the model
        // source as `= {discriminant},` (loosely — enough to catch a
        // renumbering without being a full parser).
        for (discriminant, _) in expected {
            let needle = format!("= {discriminant},");
            assert!(
                model_src.contains(&needle),
                "attome_audit::model::AuditOperation source no longer contains a discriminant \
                 `{discriminant}` this file's name table expects — update both together"
            );
        }
    }
}
