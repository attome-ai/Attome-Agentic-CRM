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
use attome_server::authz::{Admin, Authorized, SelfService};
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
    // AB5-T8: the last 90 days of degraded periods.
    let history = match crate::capability_probe::degraded_history(&state.base.db).await {
        Ok(periods) => json!(periods),
        Err(e) => json!({ "error": e.to_string() }),
    };
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
        "degraded_history": history,
        "capabilities": {
            "gated_routes": capabilities,
            "audit_ingest": {
                "breaker_tripped": audit_ingest_tripped,
                "scope": "all mutating verbs (global), see D-167/P-audit-chain-hardening",
            },
        },
    }))
}

/// AB5-T6: the read-only reason this node should hold, from the operator
/// switch and the database-size ceiling. The operator's switch wins.
fn read_only_reason(
    operator: bool,
    database_bytes: Option<i64>,
    ceiling: Option<u64>,
) -> Option<attome_server::read_only::ReadOnlyReason> {
    use attome_server::read_only::ReadOnlyReason;
    if operator {
        return Some(ReadOnlyReason::Operator);
    }
    match (database_bytes, ceiling) {
        (Some(size), Some(limit)) if u64::try_from(size).unwrap_or(0) >= limit => {
            Some(ReadOnlyReason::Disk)
        }
        _ => None,
    }
}

/// AB5-T6: keeps this node's read-only reason current: the `ops.read_only`
/// setting (which every node's settings refresh picks up) and, when
/// `deployment.read_only_at_database_bytes` is set, the database's size.
/// Process-lifetime supervision; a failed size read keeps the last answer.
pub fn spawn_read_only_refresh(state: EngineState, interval: std::time::Duration) {
    tokio::spawn(async move {
        let mut database_bytes: Option<i64> = None;
        loop {
            let operator = attome_core::setting_registry()
                .get("ops.read_only")
                .map(|d| state.settings.load().resolve(d, None, None).0)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let ceiling = state.base.config.deployment.read_only_at_database_bytes;
            if ceiling.is_some() {
                match sqlx::query_scalar::<_, i64>("SELECT pg_database_size(current_database())")
                    .fetch_one(&state.base.db)
                    .await
                {
                    Ok(size) => database_bytes = Some(size),
                    Err(error) => {
                        tracing::warn!(%error, "read-only refresh: database size read failed")
                    }
                }
            }
            let reason = read_only_reason(operator, database_bytes, ceiling);
            let before = attome_server::read_only::set(&state.base.read_only, reason);
            if before != reason {
                match reason {
                    Some(reason) => tracing::error!(
                        reason = reason.as_str(),
                        database_bytes,
                        "read-only mode ON: every write answers 503 read_only"
                    ),
                    None => tracing::info!("read-only mode OFF: writes are accepted again"),
                }
            }
            metrics::gauge!("attome_read_only").set(if reason.is_some() { 1.0 } else { 0.0 });
            tokio::time::sleep(interval).await;
        }
    });
}

/// AA12-T1: one Web Vitals measurement from a browser.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct WebVital {
    /// `LCP` (largest contentful paint) or `INP` (interaction to next paint).
    name: String,
    /// The measurement in milliseconds.
    value: f64,
    /// The screen's first path segment (e.g. `xrm`, `admin`), for grouping.
    #[serde(default)]
    area: Option<String>,
}

/// The screen area a vital is grouped under: the first path segment, when it
/// is a short lowercase word, so the label stays a handful of values.
fn vital_area(area: Option<&str>) -> &str {
    match area.map(str::trim) {
        Some(a)
            if !a.is_empty()
                && a.len() <= 24
                && a.chars().all(|c| c.is_ascii_lowercase() || c == '-') =>
        {
            a
        }
        _ => "other",
    }
}

/// AA12-T1: records a browser's LCP or INP in the metrics registry, so the
/// built-in metrics store keeps its sum and count per minute
/// (`attome_web_vital_ms`).
#[utoipa::path(
    post,
    path = "/api/v1/telemetry/web-vitals",
    tag = "operations",
    request_body = WebVital,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "a browser's page-speed measurement; no business or security effect"
    )))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Not LCP or INP, or not a time from 0 to 10 minutes", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn web_vital(
    _ctx: Authorized<SelfService>,
    Json(body): Json<WebVital>,
) -> Result<axum::http::StatusCode, attome_types::AppError> {
    let name = match body.name.as_str() {
        "LCP" => "lcp",
        "INP" => "inp",
        _ => {
            return Err(attome_types::AppError::Validation(
                "name is LCP or INP".into(),
            ));
        }
    };
    if !body.value.is_finite() || !(0.0..=600_000.0).contains(&body.value) {
        return Err(attome_types::AppError::Validation(
            "value is milliseconds from 0 to 600000".into(),
        ));
    }
    let area = vital_area(body.area.as_deref()).to_owned();
    metrics::histogram!("attome_web_vital_ms", "vital" => name, "area" => area).record(body.value);
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/health/dependencies", get(dependencies))
        .route(
            "/api/v1/telemetry/web-vitals",
            axum::routing::post(web_vital),
        )
        .route("/api/v1/admin/latency", get(latency))
        .route("/api/v1/admin/ops/metrics/names", get(metric_names))
        .route("/api/v1/admin/ops/metrics/catalogue", get(metric_catalogue))
        .route("/api/v1/admin/ops/nodes", get(ops_nodes))
        .route("/api/v1/admin/deploys", get(deploys))
        .route("/api/v1/admin/conflicts", get(conflicts))
        .route("/api/v1/system/status", get(system_status))
        .route(
            "/api/v1/admin/ops/requests/{request_id}",
            get(request_trail),
        )
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

/// A job a request queued.
#[derive(serde::Serialize, utoipa::ToSchema, sqlx::FromRow)]
struct RequestJob {
    id: String,
    job_type: String,
    status: String,
    variant: Option<String>,
}

/// An audit event a request wrote.
#[derive(serde::Serialize, utoipa::ToSchema, sqlx::FromRow)]
struct RequestAudit {
    id: uuid::Uuid,
    entity_name: Option<String>,
    record_id: Option<uuid::Uuid>,
    event_name: Option<String>,
    changed_on: Option<chrono::DateTime<chrono::Utc>>,
}

/// What one request led to.
#[derive(serde::Serialize, utoipa::ToSchema)]
struct RequestTrail {
    request_id: String,
    jobs: Vec<RequestJob>,
    audit: Vec<RequestAudit>,
}

/// Rows of each kind a trail lists at most.
const MAX_TRAIL: i64 = 100;

/// U4-T5: the jobs a request queued and the audit events it wrote, found by
/// the request id every response carries (`x-request-id`). Administrators
/// only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ops/requests/{request_id}",
    tag = "operations",
    params(("request_id" = String, Path)),
    responses(
        (status = 200, description = "The request's jobs and audit events, at most 100 of each", body = RequestTrail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "An empty or overlong request id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn request_trail(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Result<Json<RequestTrail>, attome_types::AppError> {
    use attome_types::AppError;
    let request_id = request_id.trim().to_owned();
    if request_id.is_empty() || request_id.len() > 128 {
        return Err(AppError::Validation(
            "request_id is 1 to 128 characters".into(),
        ));
    }
    let jobs: Vec<RequestJob> = sqlx::query_as(
        "SELECT id, job_type, status, job->>'variant' AS variant FROM apalis.jobs \
         WHERE job->>'request_id' = $1 ORDER BY run_at LIMIT $2",
    )
    .bind(&request_id)
    .bind(MAX_TRAIL)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let audit: Vec<RequestAudit> = sqlx::query_as(
        "SELECT id, entity_name::text, record_id, event_name::text, changed_on FROM audit_header \
         WHERE request_id = $1 ORDER BY changed_on NULLS LAST, id LIMIT $2",
    )
    .bind(&request_id)
    .bind(MAX_TRAIL)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    Ok(Json(RequestTrail {
        request_id,
        jobs,
        audit,
    }))
}

/// One feature that is down or slow right now.
#[derive(serde::Serialize, utoipa::ToSchema, PartialEq, Eq, Debug)]
pub struct DegradedFeature {
    /// `files`, `email`, `notifications`, `imports` or `bulk`.
    pub feature: &'static str,
    /// The translation key of the message to show; never a raw error.
    pub message_key: String,
}

/// What a signed-in person should know about the system right now.
#[derive(serde::Serialize, utoipa::ToSchema, Debug)]
pub struct SystemStatus {
    /// Changes are refused for now (the audit backlog guard is holding writes).
    pub read_only: bool,
    /// AB5-T6: `operator`, `disk` or `recovery` while read-only mode is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_reason: Option<String>,
    pub degraded: Vec<DegradedFeature>,
}

/// AB5-T2: the degraded features, one per feature, from the capabilities
/// that are down.
pub fn degraded_features(down: &[attome_server::Capability]) -> Vec<DegradedFeature> {
    let mut out: Vec<DegradedFeature> = Vec::new();
    for capability in down {
        for feature in capability.affected_features() {
            if out.iter().any(|d| d.feature == *feature) {
                continue;
            }
            out.push(DegradedFeature {
                feature,
                message_key: format!("systemStatus.{feature}"),
            });
        }
    }
    out
}

/// AB5-T2: what is down or slow right now, for any signed-in person: the
/// features affected, as message keys, and whether changes are refused. No
/// dependency names or errors are shown.
#[utoipa::path(
    get,
    path = "/api/v1/system/status",
    tag = "operations",
    responses(
        (status = 200, description = "The degraded features and whether changes are refused", body = SystemStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn system_status(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
) -> Json<SystemStatus> {
    let registry = &state.base.capabilities;
    let down: Vec<attome_server::Capability> = attome_server::Capability::ALL
        .into_iter()
        .filter(|c| registry.state(*c) == attome_server::CapabilityState::Unavailable)
        .collect();
    let read_only = attome_server::read_only::current(&state.base.read_only);
    Json(SystemStatus {
        read_only: read_only.is_some()
            || state
                .base
                .audit_ingest_backlog_exceeded
                .load(std::sync::atomic::Ordering::Relaxed),
        read_only_reason: read_only.map(|r| r.as_str().to_owned()),
        degraded: degraded_features(&down),
    })
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

/// AB7-T8: the most recent deploys and restarts across every node, newest
/// first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/deploys",
    tag = "operations",
    responses(
        (status = 200, description = "The last 100 starts and drains", body = attome_types::PaginatedResponse<attome_server::deploy_event::DeployEvent>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn deploys(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<
    Json<attome_types::PaginatedResponse<attome_server::deploy_event::DeployEvent>>,
    attome_types::AppError,
> {
    const RECENT_DEPLOYS: i64 = 100;
    let events = attome_server::deploy_event::recent(&state.base.db, RECENT_DEPLOYS)
        .await
        .map_err(attome_db::classify)?;
    let total = i64::try_from(events.len()).map_err(attome_types::AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        events,
        total,
        1,
        RECENT_DEPLOYS,
    )))
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ConflictsQuery {
    /// How many days back, today included: 1 to 366, default 30.
    days: Option<i64>,
}

/// A16-T7: version conflicts of the last `days` days by entity and source
/// (`api`, `bulk`, `import`), most first: where people overwrite each other.
#[utoipa::path(
    get,
    path = "/api/v1/admin/conflicts",
    tag = "operations",
    params(ConflictsQuery),
    responses(
        (status = 200, description = "Conflict totals by entity and source", body = attome_types::PaginatedResponse<attome_records::entity_crud::history::ConflictCount>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn conflicts(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    axum::extract::Query(query): axum::extract::Query<ConflictsQuery>,
) -> Result<
    Json<attome_types::PaginatedResponse<attome_records::entity_crud::history::ConflictCount>>,
    attome_types::AppError,
> {
    let items = attome_records::entity_crud::history::conflict_totals(
        &state.base.db,
        query.days.unwrap_or(30),
    )
    .await?;
    let total = i64::try_from(items.len()).map_err(attome_types::AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        items,
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
#[openapi(
    paths(
        web_vital,
        dependencies,
        latency,
        metric_query,
        metric_names,
        metric_catalogue,
        ops_nodes,
        deploys,
        conflicts,
        request_trail,
        system_status
    ),
    components(schemas(WebVital))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use attome_server::Capability;

    #[test]
    fn read_only_follows_the_switch_then_the_size_ceiling() {
        use attome_server::read_only::ReadOnlyReason;
        assert_eq!(read_only_reason(false, None, None), None);
        assert_eq!(
            read_only_reason(true, None, None),
            Some(ReadOnlyReason::Operator)
        );
        assert_eq!(read_only_reason(false, Some(10), Some(100)), None);
        assert_eq!(
            read_only_reason(false, Some(100), Some(100)),
            Some(ReadOnlyReason::Disk)
        );
        assert_eq!(
            read_only_reason(true, Some(100), Some(100)),
            Some(ReadOnlyReason::Operator)
        );
        assert_eq!(read_only_reason(false, Some(1_000), None), None);
    }

    #[test]
    fn a_vital_area_is_a_short_word_or_other() {
        assert_eq!(vital_area(Some("xrm")), "xrm");
        assert_eq!(vital_area(Some("record-form")), "record-form");
        assert_eq!(vital_area(Some("Xrm")), "other");
        assert_eq!(vital_area(Some("a/b")), "other");
        assert_eq!(vital_area(Some("")), "other");
        assert_eq!(vital_area(None), "other");
    }

    #[test]
    fn status_lists_degraded_feature() {
        assert!(degraded_features(&[]).is_empty());
        let both = degraded_features(&[Capability::Email, Capability::FastJobs]);
        let features: Vec<&str> = both.iter().map(|d| d.feature).collect();
        assert_eq!(
            features,
            vec!["email", "notifications"],
            "email is listed once"
        );
        assert_eq!(both[0].message_key, "systemStatus.email");
        for capability in Capability::ALL {
            assert!(
                !capability.affected_features().is_empty(),
                "{}",
                capability.as_str()
            );
        }
    }
}
