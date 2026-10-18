//! P-idempotency-hardening §4.4 (Phase 3) — the durable Postgres tier for
//! "mandatory" mutating operations (`idempotency.mandatory_operations`
//! config). Sits alongside the default Redis-only gate in `idempotency.rs`,
//! not in place of it: see that plan's §4.4 "why not Postgres for
//! everything" / "why not Redis forever" alternatives-considered discussion.
//!
//! Backed by migration `0066_core_idempotency_record.sql`.
//!
//! Live-verified against a real Postgres (D-215): acquire/replay/conflict
//! round trip, the concurrent-acquire race, and the `complete_in_tx`
//! atomicity claim (a rolled-back transaction leaves the record `pending`,
//! not `completed`) — see `attome-server/tests/idempotency_durable.rs`.
//!
//! Over HTTP (Z5-T12), `attome-api/tests/bulk_mutation.rs` drives the whole
//! tier through the middleware: a byte-identical replay with one operation,
//! `409 idempotency_conflict` for the same key with another body, and a key
//! run again after the retention sweep.
//!
//! D-207 follow-up (live-verified by the stale-pending tests in
//! `attome-server/tests/idempotency_durable.rs`): before this, a request that crashed after
//! `acquire_or_check` returned `Acquired` but before `complete_in_tx`/
//! `complete_best_effort`/`release_on_failure` ever ran left that identity's
//! row stuck at `state = 'pending'` permanently — `core_idempotency_record_
//! identity_unique` (migration `0066`) has no `is_deleted` scoping, so
//! `PlatformJob::PruneIdempotencyRecords`' retention sweep (soft-delete only,
//! `crates/server/src/jobs.rs`) can never free the slot either, and
//! `resolve_existing` reports `InProgress` forever with no way for a
//! legitimate retry using the SAME idempotency key to ever complete.
//! `reclaim_stale_pending` closes that: once a `pending` row has sat
//! untouched past `STALE_PENDING_AFTER_MINUTES`, a retry with the identical
//! identity AND `body_hash` may take it over and actually run the operation,
//! rather than being told to wait on a request that's never coming back.
//!
//! B2 (BSV-F04): the sweep's soft-deleted rows no longer hold their key either
//! — `acquire_or_check` hard-deletes a swept row for the same identity before
//! it inserts, and the stale reclaim matches live rows only. Bounding the
//! storage of swept rows nobody reuses (a second, longer hard-delete window in
//! the prune job) is still owed in `crates/server/src/jobs.rs`.

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use uuid::Uuid;

use crate::state::AppState;

pub(crate) const STATE_COMPLETED: &str = "completed";

/// How long a `pending` `idempotency_record` row must sit untouched
/// before a retry may reclaim it instead of being told `InProgress` forever.
/// Same value and same class of problem as `xrm_notification::dispatch`'s
/// `PROCESSING_STALE_AFTER_MINUTES` (a synchronous processing step with no
/// poller to reclaim a crash mid-flight) — the two mandatory-tier routes
/// (`bulk` enqueue, `staged-import` approve) both call `complete_in_tx` in
/// the same transaction as a single fast enqueue/approve write, never after
/// waiting on the underlying job to actually finish, so 5 minutes is
/// generously above any realistic single-request processing time while still
/// being short enough that a client's own retry (typically seconds to low
/// minutes after a timeout) doesn't wait unreasonably long.
const STALE_PENDING_AFTER_MINUTES: i64 = 5;

/// Threaded through request extensions from the mandatory-operation gate
/// (`idempotency::idempotency`) to a handler that wants its idempotency
/// completion write to land in the SAME database transaction as its own
/// mutation — the only way to make "mutation committed" and "idempotency
/// record marked completed" atomic (no separate-write window either can be
/// lost independently of the other). A handler that never reads this
/// extension (via `Option<Extension<DurableIdempotencyHandle>>`) is
/// unaffected: `idempotency::idempotency`'s own post-response step
/// (`complete_best_effort`) completes the record generically instead —
/// still durable (Postgres, not a 300ms-bounded Redis write), but not
/// atomic with that handler's own mutation. See `complete_in_tx`'s doc
/// comment.
#[derive(Debug, Clone, Copy)]
pub struct DurableIdempotencyHandle {
    pub record_id: Uuid,
}

/// A previously-completed record's response, ready to replay verbatim.
pub struct CachedRecord {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for CachedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedRecord").finish_non_exhaustive()
    }
}

pub enum AcquireOutcome {
    /// No prior record for this identity — caller now owns `record_id` and
    /// must run the operation, then complete it (via `complete_in_tx`,
    /// preferred, or let the caller fall back to `complete_best_effort`).
    Acquired { record_id: Uuid },
    /// A prior attempt with the same identity AND the same `body_hash`
    /// already completed — replay its response verbatim.
    Replay(CachedRecord),
    /// A prior attempt with the same identity is still in flight (or the
    /// row briefly vanished between a lost race and this lookup — see
    /// `acquire_or_check`'s inline comment). Never silently re-runs the
    /// operation.
    InProgress,
    /// The same `(principal, method, operation, client_key)` identity was
    /// already used with a DIFFERENT `body_hash` — the caller reused an
    /// idempotency key for a materially different request.
    DifferentRequest,
}

impl std::fmt::Debug for AcquireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquireOutcome").finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct ExistingRow {
    body_hash: String,
    state: String,
    response_status: Option<i16>,
    response_headers: Option<serde_json::Value>,
    response_body: Option<Vec<u8>>,
}

/// Acquires a new durable record, or resolves what to do with an existing
/// one for the same `(principal_ref, http_method, operation, client_key)`
/// identity. `body_hash` must be the same digest `idempotency.rs` already
/// computes for the Redis tier (content-type + body), so a mismatched retry
/// is caught identically on both tiers.
pub async fn acquire_or_check(
    state: &AppState,
    principal_ref: Uuid,
    http_method: &str,
    operation: &str,
    client_key: &str,
    body_hash: &str,
) -> Result<AcquireOutcome, AppError> {
    // BSV-F04 (B2) — the identity constraint ignores `is_deleted`, so a row
    // the retention sweep soft-deleted used to hold its key forever (every
    // reuse answered `InProgress`). A swept row is outside the dedup window
    // by definition, so a reuse is a new request (the client contract in the
    // attome-server plan §2.3): drop the swept row and acquire afresh. Both
    // statements share one short transaction; the INSERT's `ON CONFLICT`
    // still picks exactly one winner among concurrent reuses.
    let mut tx = attome_db::tx::begin(&state.db).await?;
    sqlx::query(
        "DELETE FROM idempotency_record
         WHERE principal_ref = $1 AND http_method = $2 AND operation = $3 AND client_key = $4
           AND is_deleted = TRUE",
    )
    .bind(principal_ref)
    .bind(http_method)
    .bind(operation)
    .bind(client_key)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        AppError::internal(format!(
            "idempotency durable-tier swept-row release failed: {e}"
        ))
    })?;
    let acquired: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO idempotency_record
            (principal_ref, http_method, operation, client_key, body_hash, state)
         VALUES ($1, $2, $3, $4, $5, 'pending')
         ON CONFLICT ON CONSTRAINT idempotency_record_identity_unique DO NOTHING
         RETURNING id",
    )
    .bind(principal_ref)
    .bind(http_method)
    .bind(operation)
    .bind(client_key)
    .bind(body_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::internal(format!("idempotency durable-tier acquire failed: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| AppError::internal(format!("idempotency durable-tier acquire failed: {e}")))?;

    if let Some(record_id) = acquired {
        return Ok(AcquireOutcome::Acquired { record_id });
    }

    if let Some(record_id) = reclaim_stale_pending(
        &state.db,
        principal_ref,
        http_method,
        operation,
        client_key,
        body_hash,
    )
    .await?
    {
        return Ok(AcquireOutcome::Acquired { record_id });
    }

    resolve_existing(
        &state.db,
        principal_ref,
        http_method,
        operation,
        client_key,
        body_hash,
    )
    .await
}

/// Sound only under invariant I5 (`document/xrm/pending_full_plan/
/// attome-server-hardening.md`): every durable-tier operation completes its
/// record inside the mutation's own transaction (`complete_in_tx`). Then a
/// row still `pending` after `STALE_PENDING_AFTER_MINUTES` proves the
/// mutation never committed, and re-running it is safe. A route completed
/// only by `complete_best_effort` breaks that proof — a crash after its
/// commit but before the completion write leaves a `pending` row for a
/// mutation that DID apply, and this reclaim would run it a second time.
/// That is why a best-effort completion is counted and logged as an alarm.
///
/// See this module's top-level D-207 doc comment. Requires the SAME
/// `body_hash` as the stale row, not just the same identity — a differing
/// hash under a still-stale key falls through to `resolve_existing`, which
/// correctly reports `DifferentRequest` instead of this function silently
/// taking over someone else's abandoned, differently-shaped attempt.
///
/// Race-safe without `FOR UPDATE`/`SKIP LOCKED`: this `UPDATE ... WHERE
/// state = 'pending' AND updated_at < ...` takes the row's write lock the
/// same way any single-row `UPDATE` does. A second, concurrent reclaim
/// attempt for the identical identity blocks behind that lock and then
/// re-evaluates its own `WHERE` clause against the now-committed row — whose
/// `updated_at` this statement just refreshed to `NOW()` — so it no longer
/// matches and affects zero rows. Exactly one caller ever gets `Some(id)`,
/// same guarantee `acquire_or_check`'s `INSERT ... ON CONFLICT DO NOTHING`
/// already gives the fresh-acquire path (see
/// `concurrent_acquire_for_the_same_identity_has_exactly_one_winner`).
///
/// B2 (BSV-F04) — only live rows are reclaimed. A `pending` row the
/// retention sweep already soft-deleted is released by `acquire_or_check`
/// instead and the retry acquires a fresh record, so a completion never lands
/// on a swept row that no later lookup (`resolve_existing` reads live rows
/// only) could replay.
async fn reclaim_stale_pending(
    db: &DbPool,
    principal_ref: Uuid,
    http_method: &str,
    operation: &str,
    client_key: &str,
    body_hash: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "UPDATE idempotency_record
         SET updated_at = NOW(), row_version = row_version + 1
         WHERE principal_ref = $1 AND http_method = $2 AND operation = $3 AND client_key = $4
           AND body_hash = $5 AND state = 'pending' AND is_deleted = FALSE
           AND updated_at < NOW() - make_interval(mins => $6)
         RETURNING id",
    )
    .bind(principal_ref)
    .bind(http_method)
    .bind(operation)
    .bind(client_key)
    .bind(body_hash)
    .bind(STALE_PENDING_AFTER_MINUTES as i32)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        AppError::internal(format!(
            "idempotency durable-tier stale-pending reclaim failed: {e}"
        ))
    })
}

async fn resolve_existing(
    db: &DbPool,
    principal_ref: Uuid,
    http_method: &str,
    operation: &str,
    client_key: &str,
    body_hash: &str,
) -> Result<AcquireOutcome, AppError> {
    let existing: Option<ExistingRow> = sqlx::query_as(
        "SELECT body_hash, state, response_status, response_headers, response_body
         FROM idempotency_record
         WHERE principal_ref = $1 AND http_method = $2 AND operation = $3 AND client_key = $4
           AND is_deleted = FALSE",
    )
    .bind(principal_ref)
    .bind(http_method)
    .bind(operation)
    .bind(client_key)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal(format!("idempotency durable-tier lookup failed: {e}")))?;

    let Some(existing) = existing else {
        // The row that lost us the INSERT ON CONFLICT DO NOTHING was deleted
        // between that statement and this SELECT (e.g. `release_on_failure`
        // ran for a failed attempt, or the retention prune raced this
        // request into the same instant — extremely unlikely given hour-
        // granularity retention, but not impossible). Report `InProgress`
        // rather than silently re-attempting the INSERT: the safe default
        // is "tell the client to retry," never "run the mutation a second
        // time without being sure this is a fresh key."
        return Ok(AcquireOutcome::InProgress);
    };

    if existing.body_hash != body_hash {
        return Ok(AcquireOutcome::DifferentRequest);
    }

    if existing.state != STATE_COMPLETED {
        return Ok(AcquireOutcome::InProgress);
    }

    let status = existing.response_status.unwrap_or(200).max(0) as u16;
    let headers: Vec<(String, String)> = existing
        .response_headers
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();
    let body = existing.response_body.unwrap_or_default();

    Ok(AcquireOutcome::Replay(CachedRecord {
        status,
        headers,
        body,
    }))
}

/// Atomic completion — call from inside the SAME transaction as the
/// mutation this record protects, immediately before that transaction
/// commits. This is the concrete mechanism that closes the gap this whole
/// durable tier exists for: a crash between "mutation committed" and
/// "idempotency record marked completed" cannot happen when they are the
/// same commit. `mutation_ref` should name the row the mutation
/// created/claimed (e.g. `xrm_automation_bulk_operation.id`), for audit/debugging
/// traceability — optional, pass `None` if there's no single natural row to
/// point at.
///
/// B1 (BSV-F05) — the `WHERE state = 'pending'` guard makes this safe to
/// call at most once meaningfully, and a completion that affects zero rows is
/// now a hard **error rather than a silent no-op**. Zero rows means this
/// caller no longer owns the record: after `STALE_PENDING_AFTER_MINUTES` a
/// retry's `reclaim_stale_pending` hands the SAME `record_id` to a second
/// holder, and the first holder's late completion would otherwise mark the
/// second holder's still-running work as done — so a replay would serve the
/// abandoned attempt's response. Returning `RowNotFound` rolls the caller's
/// own transaction back, so its mutation does not commit either: the safe
/// direction for an attempt that lost ownership mid-flight.
pub async fn complete_in_tx(
    tx: &mut Tx<'_>,
    record_id: Uuid,
    mutation_ref: Option<Uuid>,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), sqlx::Error> {
    let headers_json = serde_json::to_value(headers).unwrap_or_else(|_| serde_json::json!([]));
    let completed = sqlx::query(
        "UPDATE idempotency_record
         SET state = 'completed', response_status = $2, response_headers = $3,
             response_body = $4, mutation_ref = $5, updated_at = NOW(),
             row_version = row_version + 1
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(record_id)
    .bind(status as i16)
    .bind(headers_json)
    .bind(body)
    .bind(mutation_ref)
    .execute(&mut **tx)
    .await?;
    if completed.rows_affected() == 0 {
        // B1 (BSV-F05): the record is not `pending` any more — a retry
        // reclaimed it as stale, or it was completed/released elsewhere.
        // Refusing rolls this caller's transaction back, so the mutation this
        // completion was meant to make atomic does not commit either.
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Generic, non-atomic completion — `idempotency::idempotency`'s
/// post-response fallback for a mandatory route whose handler did NOT call
/// `complete_in_tx` itself (i.e. wasn't given the `DurableIdempotencyHandle`
/// extension, or ignored it). Durable (a Postgres row, not a best-effort
/// Redis `SET` with a 300ms timeout), but still a second write issued after
/// the mutation's own transaction already committed — a crash in the narrow
/// window between the two is possible for a route that hasn't been given
/// true transactional linkage via `complete_in_tx`. Safe to call
/// unconditionally after any mandatory-route success response: the
/// `WHERE state = 'pending'` guard makes it a no-op if the handler already
/// self-completed the row.
///
/// Under I5 that no-op is the only expected outcome. Completing a row here
/// means a mandatory route skipped `complete_in_tx`, which makes
/// `reclaim_stale_pending` unsafe for it, so it is logged at `error` and
/// counted in `idempotency_durable_non_atomic_completion_total`.
pub async fn complete_best_effort(
    state: &AppState,
    record_id: Uuid,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) {
    let headers_json = serde_json::to_value(headers).unwrap_or_else(|_| serde_json::json!([]));
    let result = sqlx::query(
        "UPDATE idempotency_record
         SET state = 'completed', response_status = $2, response_headers = $3,
             response_body = $4, updated_at = NOW(), row_version = row_version + 1
         WHERE id = $1 AND state = 'pending'",
    )
    .bind(record_id)
    .bind(status as i16)
    .bind(headers_json)
    .bind(body)
    .execute(&state.db)
    .await;
    match result {
        Ok(done) if done.rows_affected() > 0 => {
            metrics::counter!("idempotency_durable_non_atomic_completion_total").increment(1);
            tracing::error!(
                %record_id,
                "idempotency durable-tier record completed outside the mutation's transaction; \
                 the handler did not call complete_in_tx, so a crash in this window could \
                 re-run the mutation (invariant I5)"
            );
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(
                %error,
                %record_id,
                "idempotency durable-tier best-effort completion write failed"
            );
        }
    }
}

/// Releases a pending record after the guarded handler failed (4xx/5xx) —
/// mirrors the Redis tier's existing del-on-error behavior
/// (`idempotency::idempotency`): a failed attempt must never poison the key
/// for a legitimate retry. Hard-deletes rather than soft-deletes: unlike the
/// retention prune (which keeps completed rows for audit/debugging), a
/// never-completed pending row has no value to retain, and a hard delete
/// lets a retry's `INSERT ... ON CONFLICT DO NOTHING` win outright instead
/// of tripping the unique constraint against a dead row.
pub async fn release_on_failure(state: &AppState, record_id: Uuid) {
    let result = sqlx::query("DELETE FROM idempotency_record WHERE id = $1 AND state = 'pending'")
        .bind(record_id)
        .execute(&state.db)
        .await;
    if let Err(error) = result {
        tracing::error!(
            %error,
            %record_id,
            "idempotency durable-tier release-on-failure failed"
        );
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// Only the pure header-(de)serialization shape is unit-testable here — every
// other function in this file does live SQL against `idempotency_record`
// (no `AppState`-free seam to test around, same constraint as this crate's
// other `State<AppState>` middleware, e.g. `auth.rs`'s `test_state` helper
// needing a real Postgres/Redis/object-store connection). See this file's
// top doc comment for what's still owed against live infrastructure.
#[cfg(test)]
mod tests {
    /// `complete_in_tx`/`complete_best_effort` write `serde_json::to_value(headers)`
    /// into the `response_headers` JSONB column; `resolve_existing` reads it
    /// back via `serde_json::from_value::<Vec<(String, String)>>`. A bug in
    /// either direction would silently drop or corrupt replayed headers
    /// (e.g. `Location` on a replayed 201) rather than fail loudly, since
    /// `resolve_existing` maps a decode error to `unwrap_or_default()`
    /// (empty headers) instead of propagating it — pin the round trip here.
    #[test]
    fn headers_round_trip_through_the_same_json_shape_the_db_column_stores() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("location".to_string(), "/api/v1/contact/123".to_string()),
        ];
        let json = serde_json::to_value(&headers).expect("serialize headers");
        let decoded: Vec<(String, String)> =
            serde_json::from_value(json).expect("deserialize headers");
        assert_eq!(decoded, headers);
    }

    #[test]
    fn empty_headers_round_trip_to_an_empty_vec_not_a_decode_failure() {
        let headers: Vec<(String, String)> = vec![];
        let json = serde_json::to_value(&headers).expect("serialize empty headers");
        let decoded: Vec<(String, String)> =
            serde_json::from_value(json).expect("deserialize empty headers");
        assert!(decoded.is_empty());
    }
}
