//! P-read-your-writes-lsn — shared LSN-capturing write-pin helper. Both
//! `entity_crud.rs`'s six inline mutation sites and `admin.rs`'s
//! `pin_write_best_effort` (its own seven call sites) route through this one
//! function, so the primary-LSN-capture and TTL-reconciliation logic lives
//! in exactly one place rather than being duplicated at every call site.

use attome_core::EngineState;
use uuid::Uuid;

/// Captures the primary's current WAL insert LSN and pins `user_id` to the
/// primary until the replica's watermark reaches it, or the reconciled TTL
/// elapses — see `attome_cache::sticky_primary::pin_write_with_lsn`'s doc
/// comment for the LSN comparison, and `AppState::read_pool` for where it's
/// consumed.
///
/// The captured LSN is deliberately a separate query against the same
/// primary pool the write itself just used (`pg_current_wal_insert_lsn()`),
/// not spliced into the mutation's own `RETURNING` clause — see
/// `P-read-your-writes-lsn.md` §4(1)'s "alternative considered" for why:
/// `entity_crud.rs`'s generic mutation-query builder is shared and risky to
/// touch for a latency win on an already-cheap follow-up query. Because
/// other concurrent commits can advance the insert LSN between the write and
/// this query, the captured value is always `>=` the write's own commit LSN
/// — conservative, never incorrect (worst case: a replica is trusted a
/// little later than strictly necessary, never too early).
///
/// Best-effort, same posture as the P1.12 mechanism this replaces: call
/// right after every successful mutation's transaction commits. A failure at
/// either step (LSN query or Redis write) is logged and swallowed — never
/// allowed to fail an otherwise-successful write over a caching concern
/// (guidelines §0.1: correctness of the write outranks this nicety).
pub async fn pin_write_with_current_lsn(state: &EngineState, user_id: Uuid, action: &str) {
    // Z2-T6: with no replica every read is on the primary already.
    if !state.base.config.database.has_read_replica() {
        return;
    }
    let lsn: Result<String, sqlx::Error> =
        sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
            .fetch_one(&state.base.db)
            .await;
    let lsn = match lsn {
        Ok(lsn) => lsn,
        Err(e) => {
            tracing::warn!(error = %e, action, "sticky-primary LSN capture failed");
            return;
        }
    };

    // §4(6): the pin must live at least as long as the deployment's own
    // declared lag tolerance, so the LSN check and the lag circuit breaker
    // never contradict each other. `replica_max_lag_secs` unset (today's
    // universal default) makes this byte-identical to the old TTL-only
    // ceiling.
    let ttl_secs = state
        .base
        .config
        .database
        .sticky_primary_ttl_secs
        .max(state.base.config.database.replica_max_lag_secs.unwrap_or(0));

    if let Err(e) =
        attome_cache::sticky_primary::pin_write_with_lsn(&state.base.redis, user_id, &lsn, ttl_secs)
            .await
    {
        tracing::warn!(error = %e, action, "sticky-primary pin failed");
    }
}
