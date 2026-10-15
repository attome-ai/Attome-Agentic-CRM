//! P-health-readiness (extended by P-observability-completion) — `GET
//! /health/dependencies`: read-only diagnostic coverage for object storage,
//! apalis job workers, email/SMTP and the audit chainer.
//! Deliberately separate from `attome_server::health_routes`'s `/health/ready`
//! (readiness — gates load-balancer/Kubernetes traffic routing on DB/Redis/
//! registry) and `attome_server::liveness_routes`'s `/health` (liveness — must
//! never depend on anything, including Redis; see that function's doc
//! comment): a down SMTP relay, a stalled job worker, or a lagging audit
//! chainer must never pull an otherwise-healthy, DB-serving node out of
//! rotation. This endpoint therefore **always returns 200** — a
//! diagnostic-only endpoint that can return a non-200 status is one careless
//! `livenessProbe:` edit away from becoming a second, accidental readiness
//! gate. **Administrators only** (U9-T2): unlike `/health` and `/health/ready`,
//! which a load balancer polls, this one describes the deployment's
//! internals (which relays and workers exist, their lag), so a monitor reads
//! it with an administrator API key. It no longer reports which modules are
//! on.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Value, json};

#[utoipa::path(
    get,
    path = "/health/dependencies",
    tag = "operations",
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn dependencies(State(state): State<EngineState>, _ctx: Authorized<Admin>) -> Json<Value> {
    let (storage, email) = tokio::join!(
        attome_storage::health_check(&state.base.storage),
        attome_email::health_check_with_timeout(
            &state.base.config.email,
            attome_email::CAPABILITY_PROBE_TIMEOUT,
        ),
    );

    // P-production-safety-profile follow-up — `storage.clamd_address` empty
    // is a deliberate "malware scanning disabled" configuration (fails
    // closed on upload instead, see `AppConfig::validate_production_profile`'s
    // `check_not_placeholder` doc comment), never attempt a connection in
    // that case.
    let clamd_address = state.base.config.storage.clamd_address.trim();
    let clamav = if clamd_address.is_empty() {
        json!({ "enabled": false })
    } else {
        let health = attome_storage::clamav_health_check(clamd_address).await;
        json!({ "enabled": true, "reachable": health.reachable, "latency_ms": health.latency_ms, "error": health.error })
    };
    let (fast_age, batch_age) = tokio::join!(
        attome_jobs::worker_last_seen_age_seconds(&state.base.db, false),
        attome_jobs::worker_last_seen_age_seconds(&state.base.db, true),
    );

    let audit = if state.base.config.audit.chainer_enabled {
        match attome_audit::chainer::aggregate_lag(&state.base.db).await {
            Ok(agg) => json!({
                "enabled": true,
                "organizations_pending": agg.organizations_pending,
                "total_pending_ingest": agg.total_pending_ingest,
                "max_lag_seconds": agg.max_lag_seconds,
            }),
            Err(e) => json!({ "enabled": true, "error": e.to_string() }),
        }
    } else {
        // D-029: no automatic fallback to the sync path — a disabled
        // chainer is a deliberate deployment choice, not a failure.
        json!({ "enabled": false })
    };

    // D-344 (amends D-167) — the enforceable half. Everything above is a
    // *live* probe run for this request; this block is what the route-level
    // gate (`attome_server::capability`) is currently enforcing, as maintained
    // by `crate::capability_probe::spawn_capability_refresh`.
    //
    // The two can legitimately disagree for up to one probe interval — a
    // relay that came back thirty seconds ago reads `reachable: true` above
    // and still `unavailable` here, because the gate has not re-probed yet.
    // That difference is exactly what an operator asking "why am I still
    // getting 503s, it's back up" needs to see, so both are reported rather
    // than one being derived from the other.
    //
    // `audit_ingest` is listed alongside them but is deliberately NOT a
    // `Capability`: its breaker predates this mechanism, gates *all*
    // mutating verbs globally through `attome_server::middleware::
    // mutation_gate` rather than a named set of routes, and reusing the
    // existing flag keeps one source of truth instead of adding a second
    // one that could drift.
    let capabilities = state.base.capabilities.snapshot();
    let audit_ingest_tripped = state
        .base
        .audit_ingest_backlog_exceeded
        .load(std::sync::atomic::Ordering::Relaxed);

    Json(json!({
        "storage": storage,
        "email": email,
        "clamav": clamav,
        "jobs": {
            "fast":  { "worker_last_seen_age_seconds": fast_age.ok().flatten() },
            "batch": { "worker_last_seen_age_seconds": batch_age.ok().flatten() },
        },
        "audit_chainer": audit,
        "capabilities": {
            "gated_routes": capabilities,
            "audit_ingest": {
                "breaker_tripped": audit_ingest_tripped,
                "scope": "all mutating verbs (global), see D-167/P-audit-chain-hardening",
            },
        },
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/health/dependencies", get(dependencies))
        .route("/api/v1/admin/latency", get(latency))
        .route("/api/v1/admin/ops/metrics/names", get(metric_names))
        .route("/api/v1/admin/ops/metrics/catalogue", get(metric_catalogue))
        .route("/api/v1/admin/ops/nodes", get(ops_nodes))
        .route("/api/v1/admin/ops/metrics/query", get(metric_query))
}

/// The most points one metric query returns.
const MAX_POINTS: i64 = 2_000;

/// `GET /api/v1/admin/ops/metrics/query`.
#[derive(serde::Deserialize, utoipa::IntoParams)]
struct MetricQuery {
    /// A metric name, as `GET .../metrics/names` lists them.
    name: String,
    /// Start (UTC, ISO-8601); default an hour ago.
    from: Option<chrono::DateTime<chrono::Utc>>,
    /// End (UTC); default now.
    to: Option<chrono::DateTime<chrono::Utc>>,
    /// Seconds per point, 60 to 86,400; default 60.
    step: Option<i64>,
    /// Only series whose labels include these (a JSON object), for example
    /// `{"endpoint":"/api/v1/{entity}"}`.
    labels: Option<String>,
}

/// One point: the bucket's start and the average of the samples in it.
#[derive(serde::Serialize, utoipa::ToSchema, sqlx::FromRow)]
struct MetricPoint {
    at: chrono::DateTime<chrono::Utc>,
    value: f64,
}

/// U4-T4: a metric's values over time from the built-in metrics store
/// (U4-T1), averaged per `step`. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ops/metrics/query",
    tag = "operations",
    params(MetricQuery),
    responses(
        (status = 200, description = "The points, oldest first", body = attome_types::PaginatedResponse<MetricPoint>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "A bad range, step or labels filter", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn metric_query(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    axum::extract::Query(query): axum::extract::Query<MetricQuery>,
) -> Result<Json<attome_types::PaginatedResponse<MetricPoint>>, attome_types::AppError> {
    use attome_types::AppError;
    let to = query.to.unwrap_or_else(chrono::Utc::now);
    let from = query.from.unwrap_or(to - chrono::Duration::hours(1));
    let step = query.step.unwrap_or(60);
    if !(60..=86_400).contains(&step) {
        return Err(AppError::Validation("step is 60 to 86400 seconds".into()));
    }
    if from >= to || to - from > chrono::Duration::days(31) {
        return Err(AppError::Validation(
            "from must be before to, at most 31 days apart".into(),
        ));
    }
    if (to - from).num_seconds() / step > MAX_POINTS {
        return Err(AppError::Validation(format!(
            "at most {MAX_POINTS} points; use a larger step"
        )));
    }
    let labels: Value = match query
        .labels
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(value @ Value::Object(_)) => value,
            _ => return Err(AppError::Validation("labels is a JSON object".into())),
        },
        None => json!({}),
    };
    let points: Vec<MetricPoint> = sqlx::query_as(
        "SELECT date_bin(make_interval(secs => $4), ts, $2) AS at, avg(value) AS value \
         FROM ops_metric_sample \
         WHERE name = $1 AND ts >= $2 AND ts < $3 AND labels @> $5 \
         GROUP BY 1 ORDER BY 1",
    )
    .bind(query.name.trim())
    .bind(from)
    .bind(to)
    .bind(step as f64)
    .bind(&labels)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let total = i64::try_from(points.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        points, total, 1, MAX_POINTS,
    )))
}

/// One node, from its heartbeat in the metrics store.
#[derive(serde::Serialize, utoipa::ToSchema, sqlx::FromRow)]
struct OpsNode {
    node: String,
    version: Option<String>,
    last_seen: chrono::DateTime<chrono::Utc>,
    /// It stored its metrics in the last three minutes.
    healthy: bool,
}

/// U4-T4: the nodes that stored metrics in the last day, from their
/// once-a-minute heartbeat (`attome_node_up`); a node silent for three
/// minutes is shown as unhealthy. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ops/nodes",
    tag = "operations",
    responses(
        (status = 200, description = "Every node seen in the last day", body = attome_types::PaginatedResponse<OpsNode>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn ops_nodes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<attome_types::PaginatedResponse<OpsNode>>, attome_types::AppError> {
    use attome_types::AppError;
    let nodes: Vec<OpsNode> = sqlx::query_as(
        "SELECT labels->>'node' AS node, \
                (array_agg(labels->>'version' ORDER BY ts DESC))[1] AS version, \
                max(ts) AS last_seen, \
                max(ts) > now() - interval '3 minutes' AS healthy \
         FROM ops_metric_sample \
         WHERE name = $1 AND ts > now() - interval '1 day' AND labels ? 'node' \
         GROUP BY 1 ORDER BY 1",
    )
    .bind(attome_server::metrics_store::NODE_UP)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let total = i64::try_from(nodes.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        nodes,
        total,
        1,
        total.max(1),
    )))
}

/// U4-T2: every metric this server emits, with its kind, unit and meaning in
/// English and Arabic.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ops/metrics/catalogue",
    tag = "operations",
    responses(
        (status = 200, description = "The metric catalogue, by name", body = attome_types::PaginatedResponse<attome_server::metrics_catalogue::MetricInfo>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn metric_catalogue(
    _ctx: Authorized<Admin>,
) -> Json<attome_types::PaginatedResponse<attome_server::metrics_catalogue::MetricInfo>> {
    let items = attome_server::metrics_catalogue::CATALOGUE.to_vec();
    let total = items.len() as i64;
    Json(attome_types::PaginatedResponse::new(
        items,
        total,
        1,
        total.max(1),
    ))
}

/// U4-T4: the metric names sampled in the last hour.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ops/metrics/names",
    tag = "operations",
    responses(
        (status = 200, description = "Metric names, sorted", body = attome_types::PaginatedResponse<String>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn metric_names(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<attome_types::PaginatedResponse<String>>, attome_types::AppError> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT name FROM ops_metric_sample WHERE ts >= now() - interval '1 hour' ORDER BY name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let total = i64::try_from(names.len()).map_err(attome_types::AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        names,
        total,
        1,
        total.max(1),
    )))
}

/// `GET /api/v1/admin/latency`.
#[derive(serde::Serialize, utoipa::ToSchema)]
struct LatencyReport {
    /// Metrics are on in this process (`observability.metrics_port` set).
    enabled: bool,
    /// Every route seen since this process started, slowest p95 first.
    routes: Vec<attome_server::metrics::RouteLatency>,
}

/// AA1-T6: per-route p50, p95 and p99 latency on this node since it started,
/// from the same request-duration histogram `/metrics` exposes. Administrators
/// only. Empty, with `enabled: false`, when metrics are off.
#[utoipa::path(
    get,
    path = "/api/v1/admin/latency",
    tag = "operations",
    responses(
        (status = 200, description = "Per-route latency on this node", body = LatencyReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn latency(_ctx: Authorized<Admin>) -> Json<LatencyReport> {
    let text = attome_server::metrics::render_current();
    Json(LatencyReport {
        enabled: text.is_some(),
        routes: text
            .as_deref()
            .map(attome_server::metrics::route_latencies)
            .unwrap_or_default(),
    })
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    dependencies,
    latency,
    metric_query,
    metric_names,
    metric_catalogue,
    ops_nodes
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
