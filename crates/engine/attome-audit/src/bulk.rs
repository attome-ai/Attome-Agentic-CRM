//! Bulk parent audit events (audit plan item 3.10, D-541 rule 5, C13/I13).
//!
//! `BulkAccepted`/`BulkCompleted` share the operation's `batch_id` with their
//! per-record events, and use the same category/entity as those per-record
//! events — today that is always `Entity` + the target entity, since every
//! current bulk/staged-import/bulk-transform caller writes ordinary entity
//! mutations. They follow the **same policy decision** as the per-record
//! operation: since no policy resolver exists yet (Phase 5), that means
//! writing unconditionally, exactly like the per-record events they parent
//! (D-541: "when entity policy does not audit that operation, neither parent
//! is written" — today nothing consults policy at all, so this is always the
//! "audited" branch).

use sqlx::Postgres;
use uuid::Uuid;

use attome_types::AppError;

use crate::initiator::Attribution;
use crate::model::{AuditEvent, AuditOperation, AuditOutcome, EventExtras};
use crate::service::AuditService;

/// Writes the `BulkAccepted` parent event in `tx` — the same transaction that
/// enqueues the durable job, or the start of a synchronous bulk call (D-541
/// rule 5). If `tx` rolls back, no parent event and no operation exists, same
/// as plan item 3.10 rule 1.
///
/// `event.operation` and `event.record_id` are overwritten by this call;
/// every other field (category, entity_name, organization_ref, user_context,
/// source, `batch_id`, `event_comment`) is the caller's — set `batch_id` to
/// the same id the per-record events for this operation will carry.
pub async fn write_bulk_accepted(
    audit: &AuditService<'_>,
    tx: &mut sqlx::Transaction<'_, Postgres>,
    mut event: AuditEvent,
    attribution: Attribution,
    requested_count: i32,
) -> Result<Uuid, AppError> {
    event.operation = AuditOperation::BulkAccepted;
    event.record_id = None;
    let extras = EventExtras {
        requested_count: Some(requested_count),
        ..Default::default()
    };
    audit
        .write_in_tx_with_extras(tx, event, attribution, extras)
        .await
}

/// Writes the `BulkCompleted` parent event in `tx` — the transaction that
/// records the terminal state — unless one already exists for this
/// `batch_id`. D-541 rule 5: exactly one `BulkCompleted` per `batch_id`,
/// enforced by `pg_try_advisory_xact_lock` (two-argument form, guidelines §2,
/// key `"attome-audit/bulk-complete:{batch_id}"` under this crate's own
/// `ADVISORY_LOCK_NAMESPACE`) plus an existence check against both
/// `audit_header` (already chained) and `audit_ingest` (captured but
/// not yet drained) — a resumed or retried terminal-state write must never
/// write a second completion (plan item 3.10 rule 3, tested by
/// `bulk_parent_events::retry_writes_one_completion`).
///
/// Returns `Ok(None)` when a `BulkCompleted` event already exists for this
/// `batch_id` (this call is a no-op) or a concurrent writer currently holds
/// the lock; `Ok(Some(id))` when this call wrote it.
///
/// `event.operation`/`event.record_id` are overwritten, same as
/// [`write_bulk_accepted`]. `event.batch_id` must be `Some`.
pub async fn write_bulk_completed_once(
    audit: &AuditService<'_>,
    tx: &mut sqlx::Transaction<'_, Postgres>,
    mut event: AuditEvent,
    attribution: Attribution,
    outcome: AuditOutcome,
    affected_count: i32,
    failed_count: i32,
) -> Result<Option<Uuid>, AppError> {
    let batch_id = event
        .batch_id
        .ok_or_else(|| AppError::internal("BulkCompleted requires event.batch_id"))?;

    let key = format!("attome-audit/bulk-complete:{batch_id}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        // A concurrent writer already holds this batch_id's completion lock
        // inside its own open transaction — "already being completed" is
        // exactly the outcome this call wants, so this is a no-op rather
        // than a conflict.
        return Ok(None);
    }

    let already_written: bool = sqlx::query_scalar(
        "SELECT (EXISTS (
             SELECT 1 FROM audit_header WHERE batch_id = $1 AND operation = $2
         ) OR EXISTS (
             SELECT 1 FROM audit_ingest
              WHERE payload->'event'->>'batch_id' = $1::text
                AND payload->'event'->>'operation' = 'BulkCompleted'
         ))",
    )
    .bind(batch_id)
    .bind(AuditOperation::BulkCompleted as i32)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if already_written {
        return Ok(None);
    }

    event.operation = AuditOperation::BulkCompleted;
    event.record_id = None;
    let extras = EventExtras {
        outcome: Some(outcome),
        affected_count: Some(affected_count),
        failed_count: Some(failed_count),
        ..Default::default()
    };
    audit
        .write_in_tx_with_extras(tx, event, attribution, extras)
        .await
        .map(Some)
}
