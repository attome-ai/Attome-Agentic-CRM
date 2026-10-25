//! P-read-your-writes-lsn Phase 2 — an always-on, correctness-critical cache
//! of the read replica's replay position, deliberately separate from the
//! metrics-gated `spawn_replica_lag_refresh` (D-125, `crate::metrics`):
//! `AppState::read_pool`'s routing decision must never depend on whether an
//! operator happens to have Prometheus scraping enabled
//! (`observability.metrics_port`) — see `main.rs`'s spawn site, which is
//! deliberately outside that gate for this poller only.
//!
//! Correctness argument for comparing a cached (up to `interval` stale)
//! watermark against a pinned write's LSN, instead of querying Postgres on
//! the read's own critical path: replica replay position is monotonically
//! non-decreasing. If the *last* poll recorded `replay_lsn >= pinned_lsn`,
//! replay must have already reached `pinned_lsn` by that poll's time — and
//! since `pinned_lsn` was captured strictly after the write's own commit,
//! the poll necessarily happened at or after that commit too. Pure LSN-value
//! comparison is sufficient; no wall-clock bookkeeping is needed, and the
//! comparison only ever under-reports catch-up (safe: falls back to the
//! primary a little longer than strictly necessary), never over-reports it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::state::AppState;

/// The replica's last-polled replay position, cached on `AppState` behind an
/// `ArcSwapOption` and read on every `read_pool` call as one atomic load — no
/// Postgres query on the request's own critical path (guidelines §10/§14.4).
#[derive(Debug, Clone)]
pub struct ReplicaWatermark {
    /// `pg_last_wal_replay_lsn()::text`, raw `pg_lsn` text — compared against
    /// a pinned write's captured LSN via `attome_cache::sticky_primary::lsn_ge`.
    pub replay_lsn: String,
    /// `EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp()))`,
    /// floored at 0 — feeds `database.replica_max_lag_secs`'s circuit
    /// breaker in `AppState::route_if_lag_ok`.
    pub lag_seconds: f64,
    /// A9 (BSV-F21) — when this watermark was polled, and the age past which
    /// the whole value must be treated as unknown rather than trusted.
    pub polled_at: Instant,
    /// 3x the poll interval: two poll periods of slack for a slow query plus
    /// one for scheduling jitter. A failed or hung poll keeps the *previous*
    /// value, so without an age bound a partition to the standby would keep
    /// routing unpinned reads to a replica of arbitrarily stale, unknown lag
    /// for as long as the partition lasts — the exact failure BSV-F21 names.
    pub stale_after: Duration,
}

impl ReplicaWatermark {
    /// A9 (BSV-F21) — true once this watermark is too old to trust.
    pub fn is_stale(&self) -> bool {
        self.polled_at.elapsed() > self.stale_after
    }
}

/// Detached polling loop, same shape as `metrics::spawn_pool_gauge_refresh`.
/// Caller (`main.rs`) spawns this whenever `database.readonly` is
/// configured — NOT gated on `observability.metrics_port` (contrast with
/// `metrics::spawn_replica_lag_refresh`): this cache feeds a correctness
/// decision (`read_pool`'s routing), not only a dashboard.
pub fn spawn_watermark_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            // A9 (BSV-F21) — bound the poll. A hung query would otherwise
            // stall this loop forever while the cached value silently aged;
            // the age bound in `ReplicaWatermark::is_stale` is what makes the
            // reader safe, and this deadline is what keeps the loop itself
            // ticking.
            let _ = tokio::time::timeout(interval, refresh_once(&state, interval)).await;
            // AB2-T4: a new timeline on the primary is a leader change.
            let _ = tokio::time::timeout(interval, watch_leader(&state)).await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// AB2-T4: the primary's last seen timeline (0: not read yet). Process
/// state that only decides when to set the shared pin; a restart re-reads it.
static LAST_TIMELINE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// AB2-T4: whether a timeline read after `previous` is a leader change: a
/// different value after one was known. Pure.
pub fn leader_changed(previous: i64, current: i64) -> bool {
    previous != 0 && current != previous
}

/// AB2-T4: reads the primary's timeline and, when it changed, sets the
/// global read pin for `database.failover_pin_secs`. A role that may not
/// call `pg_control_checkpoint()` simply never sees a change.
async fn watch_leader(state: &AppState) {
    let secs = state.config.database.failover_pin_secs;
    if secs == 0 || !state.config.database.has_read_replica() {
        return;
    }
    let timeline: Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT timeline_id::bigint FROM pg_control_checkpoint()")
            .fetch_one(&state.db)
            .await;
    let Ok(current) = timeline else {
        return;
    };
    let previous = LAST_TIMELINE.swap(current, std::sync::atomic::Ordering::Relaxed);
    if leader_changed(previous, current) {
        tracing::warn!(
            event = "db.leader_changed",
            previous,
            current,
            pin_secs = secs,
            "database leader changed; reads go to the primary while replicas catch up"
        );
        if let Err(error) = attome_cache::sticky_primary::set_global_pin(&state.redis, secs).await {
            tracing::warn!(%error, "failover read pin not set");
        }
    }
}

#[derive(sqlx::FromRow)]
struct WatermarkRow {
    replay_lsn: Option<String>,
    lag_seconds: Option<f64>,
}

async fn refresh_once(state: &AppState, interval: Duration) {
    let row: Result<WatermarkRow, sqlx::Error> = sqlx::query_as(
        "SELECT
             pg_last_wal_replay_lsn()::text AS replay_lsn,
             EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp()))::float8 AS lag_seconds",
    )
    .fetch_one(&state.db_readonly)
    .await;

    match row {
        Ok(WatermarkRow {
            replay_lsn: Some(replay_lsn),
            lag_seconds,
        }) => {
            state
                .replica_watermark
                .store(Some(Arc::new(ReplicaWatermark {
                    replay_lsn,
                    lag_seconds: lag_seconds.unwrap_or(0.0).max(0.0),
                    polled_at: Instant::now(),
                    stale_after: interval.saturating_mul(3),
                })));
        }
        Ok(WatermarkRow {
            replay_lsn: None, ..
        }) => {
            // `pg_last_wal_replay_lsn()` is NULL when this connection isn't
            // actually in recovery — same condition `metrics::
            // spawn_replica_lag_refresh`'s doc comment documents. D-153 gave
            // `ReadonlyDbCredentials` optional `host`/`port` fields so
            // `database.readonly` CAN point at a genuinely distinct standby,
            // but that's opt-in: a deployment that leaves them unset still
            // gets `db_readonly` reaching the identical backend as `db`, so
            // this branch fires there too. Leave the cache at its previous
            // value rather than fabricate a watermark — `read_pool` treats
            // "no watermark yet" as "not caught up", so an unwired deployment
            // fails closed toward the primary for any pinned read, never
            // toward stale data; it just never benefits from the
            // replica-routing optimization until `database.readonly.host`/
            // `.port` are actually set and pointed at a real standby.
            //
            // D-156: promoted from `debug!` to `warn!` — this is the one
            // signal that surfaces "the replica-routing optimization is dark"
            // to an operator who hasn't wired `readonly.host`/`.port` at all
            // (a supported, non-error configuration per D-155, but one worth
            // a loud recurring log rather than something only visible with
            // debug-level tracing enabled). `verify_readonly_identity`
            // (`attome_db::pool`, boot-time) is a distinct, one-shot check for
            // "is this even the same database" — it doesn't overlap with this
            // poller's ongoing "is it actually a standby" signal.
            tracing::warn!(
                "replica watermark refresh: db_readonly answered but pg_last_wal_replay_lsn() \
                 is NULL (not actually a standby from this connection's point of view) — reads \
                 will never route to db_readonly until database.readonly.host/.port point at a \
                 real standby"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "replica watermark refresh failed");
        }
    }
}
