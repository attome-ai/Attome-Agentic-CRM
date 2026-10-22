//! P-observability-bcdr Track A — `GET /metrics` (Prometheus text format).
//!
//! Deliberately NOT part of the public app router (`app::apply_outer_layers` /
//! `ServerBuilder`): it's served on its own listener bound to
//! `config.observability.metrics_port` (0 = disabled — see `AppConfig::validate`),
//! so it never touches CORS/auth/the bypass list and nginx has no route to it at
//! all. See `crates/server/src/main.rs` for where this is wired in.

use axum::{Router, extract::State, http::header, response::IntoResponse, routing::get};
use axum_prometheus::{
    AXUM_HTTP_REQUESTS_DURATION_SECONDS, EndpointLabel, PrometheusMetricLayer,
    PrometheusMetricLayerBuilder,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::state::AppState;

/// Builds the HTTP-request-metrics Tower layer and its paired render handle.
/// Call once per process (each call installs a fresh global recorder) —
/// `crates/server/src/main.rs` does this once, conditionally,
/// when `observability.metrics_port != 0`.
pub fn build_layer_and_handle() -> (PrometheusMetricLayer<'static>, PrometheusHandle) {
    let pair: (PrometheusMetricLayer<'static>, PrometheusHandle) =
        PrometheusMetricLayerBuilder::new()
            .with_metrics_from_fn(install_recorder)
            // A4 (BSV-F10) — axum sets `MatchedPath` only on real (non-fallback)
            // routes, so the default `EndpointLabel::MatchedPath` falls back to the
            // raw request URI for anything unmatched. With metrics enabled a
            // scanner hitting random paths would grow the registry one series per
            // path, without limit. One `unmatched` series instead.
            .with_endpoint_label_type(EndpointLabel::MatchedPathWithFallbackFn(unmatched_endpoint))
            .build_pair();
    // attome-db hardening 4.3 — attome-db is metrics-free, so it reports each pool
    // acquire timeout through a set-once hook instead. Installed here because
    // this is where the process gets its recorder; a second call is a no-op.
    attome_db::set_acquire_timeout_hook(record_db_pool_acquire_timeout);
    // attome-db plan 3.1b — same set-once shape for `57014` (statement timeout).
    attome_db::set_statement_timeout_hook(record_db_statement_timeout);
    // Z2-T12: per-role pool pressure.
    attome_db::set_pool_pressure_hooks(attome_db::PoolPressureHooks {
        wait: record_db_pool_acquire_wait,
        timeout: record_db_pool_role_acquire_timeout,
    });
    // Z2-T3: transaction retries on serialization failure or deadlock.
    attome_db::set_tx_retry_hooks(attome_db::TxRetryHooks {
        retry: record_db_tx_retry,
        exhausted: record_db_tx_retry_exhausted,
    });
    // AA1-T6: the latency screen reads the same registry `/metrics` renders.
    let _ = RENDER_HANDLE.set(pair.1.clone());
    pair
}

/// The handle of this process's recorder, once metrics are on (AA1-T6).
static RENDER_HANDLE: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();

/// The current Prometheus text, or `None` when metrics are off
/// (`observability.metrics_port = 0`).
pub fn render_current() -> Option<String> {
    RENDER_HANDLE.get().map(PrometheusHandle::render)
}

/// One route's request latency, from the request-duration histogram.
#[derive(Debug, Clone, PartialEq, serde::Serialize, utoipa::ToSchema)]
pub struct RouteLatency {
    pub method: String,
    pub endpoint: String,
    pub count: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// The `name="value"` labels of one exposition line, in order.
pub(crate) fn labels_of(line: &str) -> Vec<(String, String)> {
    let Some(start) = line.find('{') else {
        return Vec::new();
    };
    let Some(end) = line.rfind('}') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = &line[start + 1..end];
    while let Some(eq) = rest.find("=\"") {
        let key = rest[..eq].trim_start_matches(',').trim().to_owned();
        let after = &rest[eq + 2..];
        let Some(close) = after.find('"') else { break };
        out.push((key, after[..close].to_owned()));
        rest = &after[close + 1..];
    }
    out
}

/// The `q` quantile of a cumulative histogram (`(upper bound, count)` sorted,
/// `+Inf` last), interpolated linearly inside its bucket, in seconds.
pub fn quantile(buckets: &[(f64, u64)], q: f64) -> f64 {
    let Some(&(_, total)) = buckets.last() else {
        return 0.0;
    };
    if total == 0 {
        return 0.0;
    }
    let rank = q * total as f64;
    let mut lower = 0.0;
    let mut below = 0u64;
    for &(upper, count) in buckets {
        if count as f64 >= rank {
            if upper.is_infinite() {
                return lower;
            }
            let inside = count.saturating_sub(below);
            if inside == 0 {
                return upper;
            }
            let fraction = (rank - below as f64) / inside as f64;
            return lower + (upper - lower) * fraction.clamp(0.0, 1.0);
        }
        lower = upper;
        below = count;
    }
    lower
}

/// Every route's p50, p95 and p99 from the Prometheus text, slowest p95 first.
pub fn route_latencies(text: &str) -> Vec<RouteLatency> {
    use std::collections::BTreeMap;
    let bucket_name = format!("{AXUM_HTTP_REQUESTS_DURATION_SECONDS}_bucket{{");
    let mut series: BTreeMap<(String, String), BTreeMap<String, u64>> = BTreeMap::new();
    for line in text.lines().filter(|l| l.starts_with(&bucket_name)) {
        let labels = labels_of(line);
        let get = |k: &str| {
            labels
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        let (Some(method), Some(endpoint), Some(le)) = (get("method"), get("endpoint"), get("le"))
        else {
            continue;
        };
        let Some(count) = line
            .rsplit(' ')
            .next()
            .and_then(|v| v.trim().parse::<f64>().ok())
        else {
            continue;
        };
        // Across status codes, the same route's buckets add up.
        let count = count as u64;
        *series
            .entry((method, endpoint))
            .or_default()
            .entry(le)
            .or_default() += count;
    }
    let mut out: Vec<RouteLatency> = series
        .into_iter()
        .map(|((method, endpoint), by_le)| {
            let mut buckets: Vec<(f64, u64)> = by_le
                .into_iter()
                .filter_map(|(le, c)| {
                    let bound = if le == "+Inf" {
                        f64::INFINITY
                    } else {
                        le.parse().ok()?
                    };
                    Some((bound, c))
                })
                .collect();
            buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
            let ms = |q| (quantile(&buckets, q) * 1000.0 * 10.0).round() / 10.0;
            RouteLatency {
                count: buckets.last().map_or(0, |b| b.1),
                p50_ms: ms(0.50),
                p95_ms: ms(0.95),
                p99_ms: ms(0.99),
                method,
                endpoint,
            }
        })
        .filter(|r| r.count > 0)
        .collect();
    out.sort_by(|a, b| b.p95_ms.total_cmp(&a.p95_ms));
    out
}

#[cfg(test)]
mod latency_tests {
    use super::*;

    /// AA10-T6: the reading is the p95 of the requests since the previous
    /// reading, not since the process started.
    #[test]
    fn server_load_reads_the_last_window() {
        let text = |fast: u64, slow: u64| {
            let name = AXUM_HTTP_REQUESTS_DURATION_SECONDS;
            format!(
                "{name}_bucket{{method=\"GET\",endpoint=\"/a\",le=\"0.05\"}} {fast}\n\
                 {name}_bucket{{method=\"GET\",endpoint=\"/a\",le=\"0.5\"}} {}\n\
                 {name}_bucket{{method=\"GET\",endpoint=\"/a\",le=\"+Inf\"}} {}\n",
                fast + slow,
                fast + slow
            )
        };
        let load = ServerLoad::default();
        let first = load.reading_from(Some(&text(100, 0)));
        assert!(first.p95_ms.unwrap() <= 50.0, "{first:?}");
        // The next window holds only slow requests.
        let second = load.reading_from(Some(&text(100, 50)));
        assert!(second.p95_ms.unwrap() > 300.0, "{second:?}");
        // Nothing served since: no reading, so nothing is slowed.
        assert_eq!(load.reading_from(Some(&text(100, 50))).p95_ms, None);
        assert_eq!(load.reading_from(None).p95_ms, None);
    }

    #[test]
    fn percentiles_come_from_the_buckets() {
        let text = format!(
            "{n}_bucket{{method=\"GET\",status=\"200\",endpoint=\"/api/v1/x\",le=\"0.01\"}} 50\n\
             {n}_bucket{{method=\"GET\",status=\"200\",endpoint=\"/api/v1/x\",le=\"0.1\"}} 90\n\
             {n}_bucket{{method=\"GET\",status=\"200\",endpoint=\"/api/v1/x\",le=\"1\"}} 100\n\
             {n}_bucket{{method=\"GET\",status=\"200\",endpoint=\"/api/v1/x\",le=\"+Inf\"}} 100\n\
             {n}_bucket{{method=\"GET\",status=\"500\",endpoint=\"/api/v1/x\",le=\"+Inf\"}} 0\n\
             other_metric 3\n",
            n = AXUM_HTTP_REQUESTS_DURATION_SECONDS
        );
        let routes = route_latencies(&text);
        assert_eq!(routes.len(), 1);
        let r = &routes[0];
        assert_eq!(
            (r.method.as_str(), r.endpoint.as_str(), r.count),
            ("GET", "/api/v1/x", 100)
        );
        assert!((r.p50_ms - 10.0).abs() < 0.01, "{r:?}");
        // The 95th request is half-way through the 0.1 - 1 s bucket.
        assert!((r.p95_ms - 550.0).abs() < 0.01, "{r:?}");
        assert_eq!(quantile(&[], 0.5), 0.0);
    }
}

/// M86 O1 — the request-duration histogram's buckets, in seconds. Every SLO
/// class's latency objective (runtime-performance §1.1) is a bucket edge, so
/// the `attome-slo` recording rules read an exact ratio instead of
/// interpolating; a missing edge is what `SloLatencyBucketMissing` reports.
/// The library default (5, 10, 25, 50, 100, 250 ms, …) has none of the 15, 20,
/// 30, 40, 60, 120, 150, 200 or 300 ms edges the classes use.
pub(crate) const HTTP_DURATION_BUCKETS: &[f64] = &[
    0.005, 0.010, 0.015, 0.020, 0.030, 0.040, 0.060, 0.100, 0.120, 0.150, 0.200, 0.300, 0.500, 1.0,
    2.5, 5.0,
];

/// `axum_prometheus::Handle::default()` with [`HTTP_DURATION_BUCKETS`] in
/// place of the library's buckets: the same global recorder, the same 5 s
/// upkeep task, and the same once-per-process rule (a second global recorder
/// is refused, as the library's own default refuses it).
#[expect(
    clippy::expect_used,
    reason = "the bucket list is a non-empty constant and the layer is built once per process"
)]
fn install_recorder() -> PrometheusHandle {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(AXUM_HTTP_REQUESTS_DURATION_SECONDS.to_owned()),
            HTTP_DURATION_BUCKETS,
        )
        // Only an empty bucket list is refused, and this one is a non-empty const.
        .expect("HTTP_DURATION_BUCKETS is non-empty")
        .build_recorder();
    let handle = recorder.handle();
    let upkeep = handle.clone();
    // Process-lifetime supervision, as in the library default: histograms
    // drain their buffers only on upkeep.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            upkeep.run_upkeep();
        }
    });
    metrics::set_global_recorder(recorder)
        .expect("build_layer_and_handle is called once per process");
    handle
}

/// `db_pool_acquire_wait_seconds{role}`: how long `tx::begin` waited.
fn record_db_pool_acquire_wait(role: &str, waited: Duration) {
    metrics::histogram!("db_pool_acquire_wait_seconds", "role" => role.to_owned())
        .record(waited.as_secs_f64());
}

/// `db_pool_role_acquire_timeouts_total{role}`.
fn record_db_tx_retry(class: &str) {
    metrics::counter!("db_tx_retries_total", "class" => class.to_owned()).increment(1);
}

fn record_db_tx_retry_exhausted(class: &str) {
    metrics::counter!("db_tx_retry_exhausted_total", "class" => class.to_owned()).increment(1);
}

fn record_db_pool_role_acquire_timeout(role: &str) {
    metrics::counter!("db_pool_role_acquire_timeouts_total", "role" => role.to_owned())
        .increment(1);
}

/// Counts one PostgreSQL statement timeout (`57014`) that reached
/// `attome_db::classify`. Like the acquire-timeout counter, a floor.
fn record_db_statement_timeout() {
    metrics::counter!("db_statement_timeouts_total").increment(1);
}

/// A4 (BSV-F10) — the single bounded `endpoint` label for an unmatched path.
/// A `fn` (not a closure) because `EndpointLabel::MatchedPathWithFallbackFn`
/// holds a `for<'f> fn(&'f str) -> String` pointer.
fn unmatched_endpoint(_raw_path: &str) -> String {
    "unmatched".to_owned()
}

/// Counts one database pool acquire timeout that reached `attome_db::tx::begin`
/// or `attome_db::classify`. A query site that still maps a pool error with
/// `AppError::internal` never reaches the hook, so the counter is a floor, not
/// an exact count.
fn record_db_pool_acquire_timeout() {
    metrics::counter!("db_pool_acquire_timeouts_total").increment(1);
}

/// Bare `GET /metrics` router — unauthenticated by design (internal scrape
/// endpoint, never proxied through nginx). Generic over `S` the same way
/// `app::health_routes` is, though in practice this is always merged as its
/// own tiny router with `PrometheusHandle` as state, not `AppState`.
pub fn metrics_routes(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(handle)
}

async fn render_metrics(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        handle.render(),
    )
}

/// D-619 ruling 4 (runtime-performance P1.3) — called on every connect of the
/// job wake-up `LISTEN` session; every connect after the first is a reconnect
/// and counts in `apalis_listen_reconnects_total`.
pub fn record_job_wakeup_listener_connect() {
    static CONNECTED_ONCE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let reconnect = CONNECTED_ONCE.swap(true, std::sync::atomic::Ordering::Relaxed);
    let counter = metrics::counter!("apalis_listen_reconnects_total");
    if reconnect {
        counter.increment(1);
    } else {
        // Registers the series at 0, so "no reconnects" is a sample, not absence.
        counter.absolute(0);
    }
}

/// attome-jobs plan BJB-14a — one outcome sample per job run, by kind.
///
/// Lives here rather than in `crates/server` so that crate needs no `metrics`
/// dependency of its own (it already depends on attome-server), and so every
/// emitter shares one counter name and one label set. apalis's own metrics are
/// aggregate, so without this a job kind's failure rate is not observable.
pub fn record_platform_job_outcome(kind: &str, outcome: &str) {
    metrics::counter!(
        "platform_jobs_total",
        "kind" => kind.to_owned(),
        "outcome" => outcome.to_owned()
    )
    .increment(1);
}

/// attome-jobs plan BJB-14a, histogram half — how long a job kind actually took.
///
/// Paired with `record_platform_job_outcome` and emitted from the same call
/// site, so a kind's latency and its failure rate are read from one place. The
/// bucket set is the crate's default (metrics' own boundaries), which is
/// deliberately coarse: this is a "is the sweep getting slower" signal, not an
/// SLO.
pub fn record_platform_job_duration(kind: &str, seconds: f64) {
    metrics::histogram!("platform_job_duration_seconds", "kind" => kind.to_owned()).record(seconds);
}

/// Periodic gauge refresh for signals that are current-state, not events —
/// DB pool utilization, Redis reachability/latency, apalis backlog. Detached
/// `tokio::spawn` loop (same shape as the existing license hourly-recheck
/// task) rather than a shutdown-tracked future: it holds no external
/// resource that needs draining, only reads and records to the in-process
/// recorder, so letting it die with the process on shutdown is fine.
///
/// A gauge here reflects "as of the last tick", not "as of now" — that's the
/// standard pull-metric tradeoff, and `interval` (main.rs passes 15s) is
/// short relative to any reasonable Prometheus scrape interval.
pub fn spawn_pool_gauge_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            // Bound the whole pass (same shape as replica_watermark.rs's
            // spawn_watermark_refresh). `refresh_once` runs several serial DB
            // queries plus Redis/storage probes; one hung call would otherwise
            // stall the loop and freeze every gauge (redis_up,
            // object_storage_up, the pool gauges) at its last healthy value.
            if tokio::time::timeout(interval, refresh_once(&state))
                .await
                .is_err()
            {
                tracing::warn!(
                    timeout_secs = interval.as_secs_f64(),
                    "metrics refresh: pass timed out; gauges not updated after the stalled step"
                );
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn refresh_once(state: &AppState) {
    metrics::gauge!("db_pool_size").set(state.db.size() as f64);
    metrics::gauge!("db_pool_idle").set(state.db.num_idle() as f64);
    // attome-db plan 4.1 — sessions opened outside every pool (workflow claims,
    // platform seed lock, attribute-index builds) still take a server slot.
    metrics::gauge!("db_unpooled_sessions_open").set(attome_db::unpooled_sessions_open() as f64);
    metrics::gauge!("db_readonly_pool_size").set(state.db_readonly.size() as f64);
    metrics::gauge!("db_readonly_pool_idle").set(state.db_readonly.num_idle() as f64);
    // P-api-consistency-hardening (a) — absent (no gauge emitted) rather than
    // a fabricated 0 whenever database.readonly isn't configured, same
    // "unset means no signal" convention as the apalis worker-age gauge
    // below.
    if let Some(pool) = &state.db_readonly_primary {
        metrics::gauge!("db_readonly_primary_pool_size").set(pool.size() as f64);
        metrics::gauge!("db_readonly_primary_pool_idle").set(pool.num_idle() as f64);
    }
    // attome-db hardening 4.3 — the DDL-capable pool entity provisioning and boot
    // seeding use. `create_migrator_pool` always builds its own pool, so these
    // are real numbers even when it falls back to the runtime identity.
    metrics::gauge!("db_migrator_pool_size").set(state.db_migrator.size() as f64);
    metrics::gauge!("db_migrator_pool_idle").set(state.db_migrator.num_idle() as f64);
    // attome-profiler plan BPR-32: the profiler's own posture was invisible at
    // runtime, so an operator could not tell a node with the layer applied from
    // one without. Recorded here (not at boot only) so it survives a reload and
    // is scrapeable next to the other posture gauges.
    metrics::gauge!("profiler_enabled").set(if state.config.observability.profiler_enabled {
        1.0
    } else {
        0.0
    });

    // attome-jobs plan BJB-14b / BJB-3: the queue's own backlog signals. Both
    // queries already existed in attome-jobs with no emitter, so a growing retry
    // pile or a job stuck at the head of the queue was invisible to Prometheus.
    // An empty queue sets the age to 0: the recorder has no idle timeout, so
    // skipping the write would leave the last non-empty age in place forever
    // and `apalis_oldest_pending_age_seconds > 900` would never clear after
    // the queue drains. A failed query leaves the previous value (and warns).
    for (batch, queue) in [(false, "interactive"), (true, "batch")] {
        match attome_jobs::retrying_count(&state.db, batch).await {
            Ok(n) => metrics::gauge!("apalis_retrying_jobs", "queue" => queue).set(n as f64),
            Err(e) => {
                tracing::warn!(error = %e, queue, "metrics refresh: retrying_count failed")
            }
        }
        match attome_jobs::oldest_pending_age_seconds(&state.db, batch).await {
            Ok(Some(age)) => {
                metrics::gauge!("apalis_oldest_pending_age_seconds", "queue" => queue).set(age)
            }
            Ok(None) => {
                metrics::gauge!("apalis_oldest_pending_age_seconds", "queue" => queue).set(0.0)
            }
            Err(e) => {
                tracing::warn!(error = %e, queue, "metrics refresh: oldest_pending_age failed")
            }
        }
    }

    // ...and the periodic schedules' own staleness: the alert threshold is
    // twice the schedule's interval, so a sweep that stopped running is a
    // silent gap without this. A schedule that has never succeeded emits no
    // sample (the caller's alert rule treats absence as "not yet").
    match attome_jobs::schedule::last_success_ages(&state.db).await {
        Ok(rows) => {
            for (name, age) in rows {
                if let Some(age) = age {
                    metrics::gauge!("job_schedule_last_success_age_seconds", "name" => name)
                        .set(age);
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "metrics refresh: last_success_ages failed"),
    }

    // attome-cache plan BCA-22 / BCA-F4: the coordination store's memory posture.
    // Both gauges are emitted unconditionally, including a 0 ceiling, because
    // "no maxmemory configured" is itself the alarm - before BCA-22 nothing in
    // this repo set one, so a runaway keyspace grew until the host killed it.
    match attome_cache::persistence::memory_probe(&state.redis_coordination).await {
        Ok(m) => {
            metrics::gauge!("redis_coordination_used_memory_bytes").set(m.used_memory_bytes as f64);
            metrics::gauge!("redis_coordination_maxmemory_bytes").set(m.maxmemory_bytes as f64);
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: coordination memory probe failed")
        }
    }

    let start = Instant::now();
    let redis_ok = state.redis.ping().await;
    let redis_ms = start.elapsed().as_secs_f64() * 1000.0;
    metrics::gauge!("redis_up").set(if redis_ok { 1.0 } else { 0.0 });
    if redis_ok {
        metrics::gauge!("redis_ping_ms").set(redis_ms);
    }

    // P-redis-security-ha, closes ENTERPRISE-AUDIT-2026-07-24.md finding #31:
    // `state.redis_coordination` (S2S nonce/rate-limit, general HTTP rate
    // limiter, idempotency gate — D-027) is a clone of `state.redis` unless a
    // deployment sets `cache.roles.coordination`, so pinging it unconditionally
    // costs one extra PING on the common case and reports the same numbers
    // twice (same tradeoff already accepted for the `db`/`db_readonly` pair
    // above). This is the gauge half of the gap: before this, a coordination-
    // only outage on a deployment that HAS split the role reported `redis_up
    // == 1` (the general pool was fine) with no distinct signal that every
    // S2S/rate-limit/idempotency call was being rejected.
    let coord_start = Instant::now();
    let redis_coordination_ok = state.redis_coordination.ping().await;
    let redis_coordination_ms = coord_start.elapsed().as_secs_f64() * 1000.0;
    metrics::gauge!("redis_coordination_up").set(if redis_coordination_ok { 1.0 } else { 0.0 });
    if redis_coordination_ok {
        metrics::gauge!("redis_coordination_ping_ms").set(redis_coordination_ms);
        refresh_coordination_persistence_gauges(state).await;
    }

    refresh_apalis_gauges_once(state).await;

    // P-observability-completion — ObjectStorageDown alert source. Reuses
    // attome_storage::health_check (already bounded by its own 2s timeout,
    // same HEAD-against-a-never-real-key probe `/health/dependencies`
    // calls) rather than a second storage-reachability implementation.
    let storage_health = attome_storage::health_check(&state.storage).await;
    metrics::gauge!("object_storage_up").set(if storage_health.reachable { 1.0 } else { 0.0 });
}

/// D-685 — is the coordination store's keyspace actually going to survive a
/// restart? Scoped to `redis_coordination` on purpose: that's the pool holding
/// the S2S replay nonces (`s2s:nonce:*`, `SET NX EX 300`) and the unflushed
/// access-log stream, i.e. the only Redis state whose loss is a security or
/// audit event rather than a cold cache. (It is a clone of `state.redis`
/// unless `cache.roles.coordination` is set, so the common single-instance
/// deployment is covered either way — same reasoning as the ping above.)
///
/// Feeds `RedisPersistenceDisabled`/`RedisSnapshotStale` in
/// `observability/alerts.yml`. Only called when the coordination ping just
/// succeeded, so an unreachable store reports through `redis_coordination_up`
/// and doesn't also burn this function's timeouts every tick.
async fn refresh_coordination_persistence_gauges(state: &AppState) {
    let status = match attome_cache::persistence::probe(&state.redis_coordination).await {
        Ok(status) => status,
        Err(e) => {
            // Deliberately not a fabricated 0: a probe failure means "unknown",
            // and emitting `policy_configured = 0` here would fire the critical
            // persistence alarm on what is really a probe outage. Same
            // "unset means no signal" convention as the readonly-pool and
            // apalis worker-age gauges above.
            tracing::warn!(error = %e, "metrics refresh: coordination persistence probe failed");
            return;
        }
    };

    metrics::gauge!("redis_coordination_persistence_policy_configured")
        .set(if status.policy_configured { 1.0 } else { 0.0 });

    if let Some(changes) = status.changes_since_last_save {
        metrics::gauge!("redis_coordination_persistence_changes_since_save").set(changes as f64);
    }

    // Absent rather than zero when nothing has ever been saved — a fresh
    // instance inside its first snapshot interval has no age to report, and a
    // 0 here would read as "saved just now", the exact opposite of the truth.
    if let Some(last_save) = status.last_success_save
        && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
    {
        let age = now.as_secs() as i64 - last_save;
        metrics::gauge!("redis_coordination_persistence_last_save_age_seconds")
            .set(age.max(0) as f64);
    }
}

/// P-job-queue-hardening (D-165) — one set of gauges per queue (`fast`/
/// `batch`, matching `attome_jobs`'s two `job_type` namespaces).
/// `apalis_dead_letter_jobs` and `apalis_worker_last_seen_age_seconds` are
/// new here; `apalis_pending_jobs` keeps its name but gains a `"queue"`
/// label instead of reporting one flat number. `apalis_pending_jobs_by_priority`
/// (M08 checklist item 1) adds a `"priority"` label (`low`/`normal`/`high`,
/// `JobPriority::label`) on top of `"queue"`, so a lane backing up behind
/// another shows up distinctly from the flat per-queue total above.
async fn refresh_apalis_gauges_once(state: &AppState) {
    for (queue, batch) in [("fast", false), ("batch", true)] {
        match attome_jobs::pending_count(&state.db, batch).await {
            Ok(count) => metrics::gauge!("apalis_pending_jobs", "queue" => queue).set(count as f64),
            Err(e) => {
                tracing::warn!(error = %e, queue, "metrics refresh: apalis pending_count query failed")
            }
        }

        // M08 checklist item 1 (priority lanes) — per-lane backlog, so a lane
        // backing up behind another is visible instead of only the flat
        // per-queue total above.
        for priority in attome_jobs::JobPriority::ALL {
            match attome_jobs::pending_count_by_priority(&state.db, batch, priority).await {
                Ok(count) => {
                    metrics::gauge!("apalis_pending_jobs_by_priority", "queue" => queue, "priority" => priority.label())
                        .set(count as f64)
                }
                Err(e) => {
                    tracing::warn!(error = %e, queue, priority = priority.label(), "metrics refresh: apalis pending_count_by_priority query failed")
                }
            }
        }

        match attome_jobs::dead_letter_count(&state.db, batch).await {
            Ok(count) => {
                metrics::gauge!("apalis_dead_letter_jobs", "queue" => queue).set(count as f64)
            }
            Err(e) => {
                tracing::warn!(error = %e, queue, "metrics refresh: apalis dead_letter_count query failed")
            }
        }

        match attome_jobs::worker_last_seen_age_seconds(&state.db, batch).await {
            Ok(Some(age)) => {
                metrics::gauge!("apalis_worker_last_seen_age_seconds", "queue" => queue).set(age)
            }
            // No worker of this type has ever registered (e.g. right after a
            // fresh boot, before the first heartbeat) — leave the gauge
            // unset rather than publishing a fabricated 0, which would read
            // as "just seen" instead of "unknown".
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, queue, "metrics refresh: apalis worker_last_seen_age_seconds query failed")
            }
        }
    }
}

/// P-ha-failover-hardening item (e), D-125 — replica-lag gauge
/// (`db_replica_lag_bytes`/`db_replica_lag_seconds`), the metric half of that
/// plan's §4(e): a `ReplicaLagHigh` alert (`observability/alerts.yml`) and
/// the `database.replica_max_lag_secs` policy hook (`P-read-your-writes-lsn`,
/// not this plan) both consume it. Lives in `attome-server` (not `xrm-server`,
/// unlike `spawn_chainer_lag_refresh`) because it only touches
/// `AppState.db`/`db_readonly`, both `base-*` concepts.
///
/// Caller (`main.rs`) only spawns this when `database.readonly` is
/// configured — same "dark unless opted into" convention as every other
/// gauge in this file. Detached `tokio::spawn` loop, same shape as
/// `spawn_pool_gauge_refresh`.
///
/// **Schema-level gap closed by D-155, wiring is still per-deployment.**
/// `AppConfig::readonly_database_url` used to build `db_readonly`'s
/// connection string from the SAME `database.host`/`.port`/`.dbname` as the
/// primary pool no matter what — `ReadonlyDbCredentials` only overrode
/// user/password. D-155 gave it optional `host`/`port` fields, so a
/// deployment CAN now point `database.readonly` at a genuinely distinct
/// endpoint (e.g. `deploy/ha/haproxy.cfg`'s `postgres_replicas` listener, or
/// a pgbouncer `attome_ro` alias on its own port). That change is unverified
/// against a live Postgres (no daemon reachable in the session that wrote
/// it — see D-155) and, more importantly, is opt-in: a deployment that
/// leaves `readonly.host`/`.port` unset still gets the exact pre-D-155
/// behavior (`db_readonly` reaching the identical backend as `db`), so
/// `pg_is_in_recovery()` there will still read `false` unless an operator
/// has actually set the override AND actually pointed it at a real standby.
/// `refresh_once` below detects that case either way (logs at `debug`,
/// reports an honest zero rather than a fabricated "healthy replica"
/// reading) — this gauge is not proof of a wired replica by itself, check
/// `database.readonly.host`/`.port` are actually set before trusting a
/// nonzero-or-zero reading either way.
pub fn spawn_replica_lag_refresh(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            refresh_replica_lag_once(&state).await;
            tokio::time::sleep(interval).await;
        }
    });
}

#[derive(sqlx::FromRow)]
struct ReplicaLagRow {
    in_recovery: bool,
    lag_bytes: Option<i64>,
    lag_seconds: Option<f64>,
}

/// P-read-your-writes-lsn §4(7) — records *why* `AppState::read_pool` sent a
/// read where it went: `none_replica`/`caught_up_replica` (no protection
/// needed / replica confirmed caught up), `pending_primary` (pin active,
/// replica not yet caught up), `circuit_breaker_primary`
/// (`database.replica_max_lag_secs` tripped), `legacy_primary` (rolling
/// upgrade, pre-LSN pin value), `redis_error_primary` (fail-closed). Cheap —
/// one counter increment, no I/O — and, unlike the watermark poller that
/// feeds `read_pool`'s actual decision (`replica_watermark::spawn_watermark_refresh`,
/// always on), this counter is genuinely observability-only: it lives behind
/// the same `observability.metrics_port` gate as every other metric in this
/// file (a no-op call when no recorder was ever installed, same as every
/// other `metrics::` call site in this platform).
pub(crate) fn record_read_routing_decision(decision: &'static str) {
    metrics::counter!("read_routing_decisions_total", "decision" => decision).increment(1);
}

/// D-344 — the gate's current belief about one durability capability, as the
/// numeric `CapabilityState` discriminant (0 unknown, 1 available, 2
/// unavailable, 3 disabled). Set by `capability::CapabilityRegistry::record`
/// on every probe round, so a dashboard can show the same thing
/// `/health/dependencies`'s `capabilities` block reports without polling it.
///
/// Deliberately a gauge over the *enforced* state, not the raw probe result:
/// what an operator needs to see is what the gate is doing to traffic, which
/// the `capability.failure_threshold` window makes lag a single failed probe
/// on purpose.
pub(crate) fn record_capability_state(capability: &'static str, state: u8) {
    metrics::gauge!("capability_state", "capability" => capability).set(state as f64);
}

/// Z5-T11: one request a protective layer refused, as
/// `http_rejections_total{layer, reason}`. Both labels are fixed strings
/// from a short list per layer, never a path, address or identifier; the
/// counter is the signal, so a refusal needs no warn log of its own.
pub fn record_rejection(layer: &'static str, reason: &'static str) {
    metrics::counter!("http_rejections_total", "layer" => layer, "reason" => reason).increment(1);
}

/// D-344 — one request refused with 503 `capability_unavailable`. The pair of
/// this and `capability_state` is what distinguishes "the object store is
/// down and nobody was uploading anyway" from "the object store is down and
/// we are turning customers away", which are very different pages at 3am.
pub(crate) fn record_capability_rejection(capability: &'static str) {
    metrics::counter!("capability_rejections_total", "capability" => capability).increment(1);
}

/// AA10-T6: the last replica lag this process read, in milliseconds;
/// `u64::MAX` until one is read (no replica, or not read yet).
static LAST_REPLICA_LAG_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

fn remember_replica_lag(seconds: f64) {
    let ms = (seconds.max(0.0) * 1000.0) as u64;
    LAST_REPLICA_LAG_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// AA10-T6: this node's load for [`attome_jobs::throttle`]: the p95 of the
/// requests served since the last reading (all routes, from the request
/// duration histogram), and the last replica lag. Both are `None` when
/// metrics are off or nothing has been measured, which slows nothing down.
#[derive(Debug, Default)]
pub struct ServerLoad {
    previous: std::sync::Mutex<Vec<(f64, u64)>>,
}

/// Every route's request duration buckets added together, `+Inf` last.
pub(crate) fn all_route_buckets(text: &str) -> Vec<(f64, u64)> {
    use std::collections::BTreeMap;
    let bucket_name = format!("{AXUM_HTTP_REQUESTS_DURATION_SECONDS}_bucket{{");
    let mut by_le: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines().filter(|l| l.starts_with(&bucket_name)) {
        let Some(le) = labels_of(line)
            .into_iter()
            .find(|(k, _)| k == "le")
            .map(|(_, v)| v)
        else {
            continue;
        };
        let Some(count) = line
            .rsplit(' ')
            .next()
            .and_then(|v| v.trim().parse::<f64>().ok())
        else {
            continue;
        };
        *by_le.entry(le).or_default() += count as u64;
    }
    let mut buckets: Vec<(f64, u64)> = by_le
        .into_iter()
        .filter_map(|(le, c)| {
            let bound = if le == "+Inf" {
                f64::INFINITY
            } else {
                le.parse().ok()?
            };
            Some((bound, c))
        })
        .collect();
    buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
    buckets
}

impl ServerLoad {
    /// The p95, in ms, of the requests between `previous` and `now`.
    fn window_p95_ms(previous: &[(f64, u64)], now: &[(f64, u64)]) -> Option<f64> {
        let delta: Vec<(f64, u64)> = now
            .iter()
            .map(|&(bound, count)| {
                let before = previous
                    .iter()
                    .find(|(b, _)| *b == bound)
                    .map_or(0, |(_, c)| *c);
                (bound, count.saturating_sub(before))
            })
            .collect();
        let total = delta.last().map_or(0, |d| d.1);
        (total > 0).then(|| quantile(&delta, 0.95) * 1000.0)
    }

    /// One reading from the Prometheus text `text`.
    pub fn reading_from(&self, text: Option<&str>) -> attome_jobs::throttle::LoadReading {
        let p95_ms = text.and_then(|text| {
            let now = all_route_buckets(text);
            let mut previous = self
                .previous
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let p95 = Self::window_p95_ms(&previous, &now);
            *previous = now;
            p95
        });
        let lag = LAST_REPLICA_LAG_MS.load(std::sync::atomic::Ordering::Relaxed);
        attome_jobs::throttle::LoadReading {
            p95_ms,
            replica_lag_secs: (lag != u64::MAX).then(|| lag as f64 / 1000.0),
        }
    }
}

impl attome_jobs::throttle::LoadSource for ServerLoad {
    fn reading(&self) -> attome_jobs::throttle::LoadReading {
        self.reading_from(render_current().as_deref())
    }
}

async fn refresh_replica_lag_once(state: &AppState) {
    let primary_lsn: Result<String, sqlx::Error> =
        sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
            .fetch_one(&state.db)
            .await;
    let primary_lsn = match primary_lsn {
        Ok(lsn) => lsn,
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: replica lag — primary LSN query failed");
            return;
        }
    };

    // `pg_wal_lsn_diff`/`pg_last_wal_replay_lsn`/`pg_last_xact_replay_timestamp`
    // are evaluated against `db_readonly` — the connection this gauge is
    // actually trying to characterize. `pg_is_in_recovery()` is what tells
    // apart "this is really a standby" from the known gap documented on
    // `spawn_replica_lag_refresh` above.
    let row: Result<ReplicaLagRow, sqlx::Error> = sqlx::query_as(
        "SELECT
             pg_is_in_recovery() AS in_recovery,
             pg_wal_lsn_diff($1::pg_lsn, pg_last_wal_replay_lsn())::bigint AS lag_bytes,
             EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp()))::float8 AS lag_seconds",
    )
    .bind(&primary_lsn)
    .fetch_one(&state.db_readonly)
    .await;

    match row {
        Ok(row) if row.in_recovery => {
            metrics::gauge!("db_replica_lag_bytes").set(row.lag_bytes.unwrap_or(0) as f64);
            // No transaction has replayed yet on a brand-new replica -> 0, not stale.
            metrics::gauge!("db_replica_lag_seconds").set(row.lag_seconds.unwrap_or(0.0).max(0.0));
            remember_replica_lag(row.lag_seconds.unwrap_or(0.0));
        }
        Ok(_) => {
            metrics::gauge!("db_replica_lag_bytes").set(0.0);
            metrics::gauge!("db_replica_lag_seconds").set(0.0);
            tracing::debug!(
                "metrics refresh: replica lag — db_readonly answered but pg_is_in_recovery() = false \
                 (not actually a standby from this connection's point of view); see \
                 spawn_replica_lag_refresh's doc comment for the known pool-wiring gap this inherits"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "metrics refresh: replica lag query failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HTTP_DURATION_BUCKETS;

    /// AA13-T3: every SLO class's p99 budget in the catalogue is an exact
    /// histogram edge, so its latency burn rules read a real `le` bucket
    /// (SloLatencyBucketMissing is the runtime guard; this is the build-time
    /// one).
    #[test]
    fn every_catalogue_p99_has_a_histogram_bucket() {
        let catalogue: serde_json::Value =
            serde_json::from_str(include_str!("../../../../observability/slo-catalogue.json"))
                .unwrap();
        let classes = catalogue["classes"].as_array().unwrap();
        assert!(!classes.is_empty());
        for class in classes {
            if class["kind"] != "http" {
                continue;
            }
            for (profile, target) in class["targets"].as_object().unwrap() {
                let Some(p99_ms) = target["p99_ms"].as_f64() else {
                    continue;
                };
                let seconds = p99_ms / 1000.0;
                assert!(
                    HTTP_DURATION_BUCKETS
                        .iter()
                        .any(|edge| (edge - seconds).abs() < 1e-9),
                    "{} ({profile}) p99 {p99_ms} ms has no bucket in HTTP_DURATION_BUCKETS",
                    class["id"]
                );
            }
        }
    }
}
