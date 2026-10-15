//! P-observability-bcdr Track A — audit-chainer lag gauge. Lives here (not
//! `attome-server`) because it needs `attome_audit::verify`/`chainer`, and
//! `base-*` crates must compile with zero `xrm-*` dependencies.
//!
//! No per-organization label: D-002 is single-tenant-per-deployment, the same
//! assumption `attome_cache`'s moka key convention already makes ("one
//! deployment serves exactly one customer") — if more than one organization
//! ever has audit activity in one deployment, the worst (max) lag is
//! reported, since an alert on "is the chainer behind" cares about that, not
//! a per-org breakdown.

use attome_db::DbPool;
use attome_server::AppState;
use std::collections::BTreeSet;
use std::time::Duration;

/// Detached `tokio::spawn` loop, same shape as
/// `attome_server::metrics::spawn_pool_gauge_refresh` — see that function's
/// doc comment for why this doesn't need shutdown tracking.
pub fn spawn_chainer_lag_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            refresh_once(&state.db).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn refresh_once(db: &DbPool) {
    // P-health-readiness: shares its aggregation logic with the
    // `/health/dependencies` diagnostic endpoint (`attome_audit::chainer::
    // aggregate_lag`) so the two can never silently diverge in how "lag" is
    // computed.
    match attome_audit::chainer::aggregate_lag(db).await {
        Ok(agg) => {
            metrics::gauge!("audit_chainer_lag_seconds").set(agg.max_lag_seconds as f64);
            metrics::gauge!("audit_chainer_pending_ingest").set(agg.total_pending_ingest as f64);
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: chainer lag aggregation failed");
        }
    }
}

/// P-job-system-hardening (b) — access-log stream consumer-lag gauge
/// (guidelines §11: queue backlog must stay an observable signal, same
/// reasoning as `spawn_chainer_lag_refresh` above). Lives here rather than
/// `attome_server::metrics` for the same reason that one does: it needs
/// `attome_s2s::telemetry`, and `base-*` must stay free of `xrm-*` deps.
pub fn spawn_s2s_telemetry_lag_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            match attome_s2s::telemetry::access_log_lag(&state.redis_coordination).await {
                Ok(pending) => metrics::gauge!("s2s_access_log_stream_pending").set(pending as f64),
                Err(e) => {
                    tracing::warn!(error = %e, "metrics refresh: s2s access-log lag query failed")
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// P-db-maintenance item (d) — bloat visibility for the four
/// RANGE-partitioned tables (migrations/0026_audit_partitioning.sql).
/// Detached `tokio::spawn` loop, same shape as `spawn_chainer_lag_refresh`
/// above. A partitioned table itself has no storage or `pg_stat_user_tables`
/// row — `pg_partition_tree` (PG14+) walks to its actual leaf partitions,
/// whose stats are summed/maxed so this reads as "the table" to an operator,
/// matching how the rest of the platform never surfaces partitioning as a
/// user-visible detail.
pub fn spawn_partition_bloat_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            refresh_bloat_once(&state.db, "audit_header").await;
            refresh_bloat_once(&state.db, "audit_detail").await;
            refresh_bloat_once(&state.db, "audit_snapshot").await;
            refresh_bloat_once(&state.db, "s2s_access_log").await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// P-audit-chain-hardening item (e) — the ingest circuit breaker's only
/// writer. Correctness/availability mechanism, not pure observability, so
/// unlike every other `spawn_*_refresh` in this file it must run whether or
/// not `observability.metrics_port` is enabled — `main.rs` spawns this one
/// unconditionally, alongside the license reload task in
/// `EngineSystemBuilder::build()`, not inside the `metrics_port != 0` block the
/// others live in.
///
/// Reuses `attome_audit::chainer::aggregate_lag` rather than a new query — the
/// same aggregation `spawn_chainer_lag_refresh` already reports as
/// `audit_chainer_pending_ingest`, so the breaker's threshold and that gauge
/// can never silently disagree about what "backlog" means.
pub fn spawn_ingest_backlog_refresh(state: AppState, interval: Duration, threshold: i64) {
    tokio::spawn(async move {
        loop {
            match attome_audit::chainer::aggregate_lag(&state.db).await {
                Ok(agg) => {
                    let exceeded = agg.total_pending_ingest >= threshold;
                    let was_exceeded = state
                        .audit_ingest_backlog_exceeded
                        .swap(exceeded, std::sync::atomic::Ordering::Relaxed);
                    if exceeded && !was_exceeded {
                        tracing::error!(
                            pending = agg.total_pending_ingest,
                            threshold,
                            "audit ingest backlog breaker TRIPPED — rejecting new mutating \
                             requests with 503 until the chainer drains audit_ingest back \
                             under the threshold",
                        );
                    } else if was_exceeded && !exceeded {
                        tracing::info!(
                            pending = agg.total_pending_ingest,
                            threshold,
                            "audit ingest backlog breaker cleared — mutating requests are no \
                             longer being rejected",
                        );
                    }
                    metrics::gauge!("audit_ingest_backlog_breaker_tripped").set(if exceeded {
                        1.0
                    } else {
                        0.0
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "audit ingest backlog poll failed — leaving the breaker in its last \
                         known state rather than guessing",
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// P-file-upload-pipeline §8's own documented risk mitigation (D-144): "an
/// operator-facing metric for scan-queue backlog should ship alongside this,
/// same class as the chainer-lag gauge already exists for the audit
/// chainer" — this is that gauge. Reports how many `upload_session`
/// rows are waiting on or currently in `files_scan.rs::process` (`uploaded`
/// = enqueued, not yet claimed; `scanning` = claimed, mid-scan) and how old
/// the oldest of them is, so a stalled `clamd` (unreachable, or still
/// downloading its first-boot signature database, see
/// `docker-compose.clamav.yml`'s own comment) shows up as a growing gauge
/// rather than only as silent per-session retry/backoff.
pub fn spawn_upload_scan_backlog_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            refresh_upload_scan_backlog_once(&state.db).await;
            refresh_idempotency_stuck_once(&state.db).await;
            refresh_change_feed_lag_once(&state.db).await;
            tokio::time::sleep(interval).await;
        }
    });
}

#[derive(sqlx::FromRow)]
struct UploadScanBacklogRow {
    pending: i64,
    oldest_seconds: Option<f64>,
}

async fn refresh_upload_scan_backlog_once(db: &DbPool) {
    let row: Result<UploadScanBacklogRow, sqlx::Error> = sqlx::query_as(
        "SELECT COUNT(*)::bigint AS pending,
                EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::float8 AS oldest_seconds
         FROM upload_session
         WHERE status IN ('uploaded', 'scanning') AND is_deleted = false",
    )
    .fetch_one(db)
    .await;

    match row {
        Ok(row) => {
            metrics::gauge!("upload_scan_backlog_pending").set(row.pending as f64);
            metrics::gauge!("upload_scan_backlog_oldest_seconds")
                .set(row.oldest_seconds.unwrap_or(0.0));
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: upload-scan backlog query failed");
        }
    }
}

/// L7-T7: each change-feed consumer's lag, as
/// `change_feed_consumer_lag_seconds{consumer}`. Consumers are few and named
/// by the platform or an administrator, so the label set stays small.
async fn refresh_change_feed_lag_once(db: &DbPool) {
    match attome_core::change_feed::consumer_health(db).await {
        Ok(consumers) => {
            for consumer in consumers {
                metrics::gauge!(
                    "change_feed_consumer_lag_seconds",
                    "consumer" => consumer.consumer,
                )
                .set(consumer.lag_seconds);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: change-feed consumer lag failed");
        }
    }
}

/// S9-T6: durable idempotency keys still `pending` ten minutes after they
/// were taken. A request that outlives the request timeout this much died
/// mid-flight, so whether its change committed is unknown and every retry of
/// it answers `idempotency_outcome_unknown` until the row is pruned.
async fn refresh_idempotency_stuck_once(db: &DbPool) {
    let stuck: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM idempotency_record
         WHERE state = 'pending' AND is_deleted = FALSE
           AND created_at < NOW() - INTERVAL '10 minutes'",
    )
    .fetch_one(db)
    .await;
    match stuck {
        Ok(stuck) => metrics::gauge!("idempotency_pending_stuck").set(stuck as f64),
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: stuck idempotency key count failed");
        }
    }
}

#[derive(sqlx::FromRow)]
struct BloatRow {
    dead_tuples: Option<i64>,
    live_tuples: Option<i64>,
    seconds_since_last_autovacuum: Option<f64>,
    total_bytes: Option<i64>,
}

/// Table name is one of the four hardcoded literals above, never request
/// data — still routed through a bound-parameter query rather than string
/// interpolation, since `::regclass` accepts a bound text value fine.
async fn refresh_bloat_once(db: &DbPool, table: &str) {
    let row: Result<BloatRow, sqlx::Error> = sqlx::query_as(
        "SELECT
             SUM(s.n_dead_tup)::bigint AS dead_tuples,
             SUM(s.n_live_tup)::bigint AS live_tuples,
             EXTRACT(EPOCH FROM (NOW() - MAX(s.last_autovacuum)))::float8 AS seconds_since_last_autovacuum,
             SUM(pg_total_relation_size(s.relid))::bigint AS total_bytes
         FROM pg_partition_tree($1::regclass) pt
         JOIN pg_stat_user_tables s ON s.relid = pt.relid
         WHERE pt.isleaf",
    )
    .bind(table)
    .fetch_one(db)
    .await;

    match row {
        Ok(row) => {
            metrics::gauge!("db_bloat_dead_tuples", "table" => table.to_string())
                .set(row.dead_tuples.unwrap_or(0) as f64);
            metrics::gauge!("db_bloat_live_tuples", "table" => table.to_string())
                .set(row.live_tuples.unwrap_or(0) as f64);
            metrics::gauge!("db_bloat_total_bytes", "table" => table.to_string())
                .set(row.total_bytes.unwrap_or(0) as f64);
            // No autovacuum has ever run (fresh partition) → 0, not left stale.
            metrics::gauge!("db_bloat_seconds_since_last_autovacuum", "table" => table.to_string())
                .set(row.seconds_since_last_autovacuum.unwrap_or(0.0));
        }
        Err(e) => {
            tracing::warn!(error = %e, table = %table, "metrics refresh: partition bloat query failed");
        }
    }
}

/// D-195 / P-four-eyes-approval — reaps `approval_request` rows still
/// `pending` past `expires_at` (`attome_approval::sweep_expired`), same
/// detached `tokio::spawn` loop shape as every other `spawn_*_refresh` in
/// this file. Without this, a forgotten approval request stays "pending"
/// (and therefore decidable) forever instead of expiring — a silent
/// standing approval opportunity, not merely a stale gauge, which is why
/// this reaps state rather than only reporting it.
///
/// The loop is also the crate's approval-queue reporting tick (BAP-13):
/// after each sweep it re-reads the crate's own queries and emits the
/// queue's gauges, so an operator sees a stuck request or a stale claim in
/// the same scrape interval that would have reaped an expired one.
///
/// The sweep itself is no longer unverified:
/// `cargo test -p attome-api --test approval_lifecycle` exercises
/// `sweep_expired_reaps_a_backdated_pending_request` against a real
/// `approval_request` table, and `attome-approval`'s own `sweeps`
/// suite proves the bounded, poison-proof per-row sweep this calls.
pub fn spawn_approval_expiry_sweep(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        let mut gauge_labels = ApprovalGaugeLabels::default();
        loop {
            // C10-A: an expiring agent-action request fails its conversation
            // tool call in the sweep's own transaction. BAP-9: the report
            // variant also returns how many due rows were skipped, so a
            // poisoned row is a counter, not a silent shortfall.
            match attome_approval::sweep_expired_report_with(
                &state.db,
                &attome_ai::conversation_event::ApprovalConversationHook,
                attome_approval::EXPIRY_SWEEP_BATCH,
            )
            .await
            {
                Ok(outcome) => {
                    if outcome.expired > 0 {
                        tracing::info!(
                            expired = outcome.expired,
                            "swept expired pending approval requests"
                        );
                        metrics::counter!("approval_requests_expired_total")
                            .increment(outcome.expired);
                    }
                    if outcome.failed > 0 {
                        tracing::warn!(
                            failed = outcome.failed,
                            "approval expiry sweep could not expire some due rows; they stay pending for a later tick",
                        );
                        metrics::counter!("approval_expiry_sweep_failed_total")
                            .increment(outcome.failed);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "approval-expiry sweep failed");
                }
            }
            refresh_approval_queue_once(&state.db, &mut gauge_labels).await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// BAP-13 / BAP-F8 — the approval queue's gauges, from the base crate's own
/// queries (base layer owns the SQL and has no `metrics` dependency; this
/// composition layer turns the rows into series, exactly as
/// `refresh_upload_scan_backlog_once` does for upload sessions).
///
/// - `approval_requests{status,action_type}` — the whole queue by state, so
///   a growing `approved` or `executing` bucket is visible, not only
///   `pending`.
/// - `approval_oldest_pending_age_seconds{action_type}` — how long the
///   oldest waiting request of each type has waited. A type that has never
///   had anything pending since this process started is absent; a type whose
///   pending queue has since drained reads `0`.
///
/// Both queries only return buckets that currently have rows, and the
/// exporter keeps a gauge's last value forever, so a bucket that drains to
/// zero would otherwise report its old value indefinitely (an "oldest
/// pending > 1h" alert that never clears). `labels` remembers the label sets
/// the previous successful tick emitted, and any set missing this tick is
/// set to `0`. It is observational and rebuilt from the database every tick
/// (guidelines §5); a failed query leaves it untouched so the next good tick
/// still zeros what drained in between.
/// - `approval_executing_stale` — claims past their lease: an approved
///   action whose holder died, so whether it ran is unknown. Nothing retries
///   these automatically (D-518), which is exactly why the count is the
///   operator's way to find them.
///
/// The event-driven `approval_auto_decisions_total{outcome}` counter is not
/// here: a policy timeout is the only automatic decider, so it is
/// incremented where that decision is made
/// (`attome_audit::approval::apply_and_audit_step_timeout`).
async fn refresh_approval_queue_once(db: &DbPool, labels: &mut ApprovalGaugeLabels) {
    match attome_approval::status_counts(db).await {
        Ok(buckets) => {
            let current: BTreeSet<(String, String)> = buckets
                .iter()
                .map(|b| (b.status.clone(), b.action_type.clone()))
                .collect();
            for (status, action_type) in labels_to_zero(&labels.status_counts, &current) {
                metrics::gauge!(
                    "approval_requests",
                    "status" => status,
                    "action_type" => action_type,
                )
                .set(0.0);
            }
            for bucket in buckets {
                metrics::gauge!(
                    "approval_requests",
                    "status" => bucket.status,
                    "action_type" => bucket.action_type,
                )
                .set(bucket.count as f64);
            }
            labels.status_counts = current;
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: approval status counts failed");
        }
    }

    match attome_approval::oldest_pending_age_seconds(db).await {
        Ok(ages) => {
            let current: BTreeSet<String> = ages.iter().map(|(t, _)| t.clone()).collect();
            for action_type in labels_to_zero(&labels.oldest_pending, &current) {
                metrics::gauge!(
                    "approval_oldest_pending_age_seconds",
                    "action_type" => action_type,
                )
                .set(0.0);
            }
            for (action_type, seconds) in ages {
                metrics::gauge!(
                    "approval_oldest_pending_age_seconds",
                    "action_type" => action_type,
                )
                .set(seconds);
            }
            labels.oldest_pending = current;
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: approval oldest-pending age failed");
        }
    }

    match attome_approval::stale_executing_count(db).await {
        Ok(stale) => metrics::gauge!("approval_executing_stale").set(stale as f64),
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: approval stale-claim count failed");
        }
    }
}

/// The label sets the approval gauges emitted on the last successful tick —
/// see [`refresh_approval_queue_once`]. Process-local and observational:
/// losing it (a restart) only means a drained bucket from before the restart
/// is absent rather than `0`, since the exporter itself starts empty.
#[derive(Debug, Default)]
struct ApprovalGaugeLabels {
    status_counts: BTreeSet<(String, String)>,
    oldest_pending: BTreeSet<String>,
}

/// The label sets that had a value last tick and have none this tick, so
/// must be set to `0` rather than keep reporting their stale value.
fn labels_to_zero<K: Ord + Clone>(previous: &BTreeSet<K>, current: &BTreeSet<K>) -> Vec<K> {
    previous.difference(current).cloned().collect()
}

#[cfg(test)]
mod approval_gauge_tests {
    use super::*;

    #[test]
    fn a_drained_bucket_is_zeroed_and_live_ones_are_not() {
        let previous: BTreeSet<&str> = ["pending/a", "pending/b", "approved/a"].into();
        let current: BTreeSet<&str> = ["pending/a", "rejected/c"].into();
        assert_eq!(
            labels_to_zero(&previous, &current),
            vec!["approved/a", "pending/b"]
        );
    }

    #[test]
    fn nothing_is_zeroed_on_the_first_tick_or_when_nothing_drained() {
        let empty: BTreeSet<String> = BTreeSet::new();
        let some: BTreeSet<String> = ["x".to_string()].into();
        assert!(labels_to_zero(&empty, &some).is_empty());
        assert!(labels_to_zero(&some, &some).is_empty());
        assert_eq!(labels_to_zero(&some, &empty), vec!["x".to_string()]);
    }
}
