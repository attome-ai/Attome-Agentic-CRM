//! Profiler Admin API — the read side of the "Profiler" dashboard: aggregate
//! call count/avg/min/max/total-since-start per `measure!()` probe
//! (`attome-profiler`), grouped into API + sub-part trees, plus a recent-trace
//! waterfall sample per top-level probe — and the operator's `DELETE` reset
//! that clears the profiler keyspace without flushing the store the security
//! controls live on (BPR-31).
//!
//! All routes are under /api/v1/admin/profiler/ and require `system.admin`
//! (mounted with `strict_authz` in `system.rs`, same as `s2s_admin`).

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

fn map_err(op: &'static str) -> impl Fn(attome_profiler::ProfilerError) -> AppError {
    move |e| AppError::internal(format!("profiler {op} failed: {e}"))
}

#[derive(Serialize, ToSchema)]
struct StatOut {
    name: String,
    count: u64,
    total_ms: f64,
    avg_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

impl From<attome_profiler::StatRow> for StatOut {
    fn from(r: attome_profiler::StatRow) -> Self {
        Self {
            name: r.name,
            count: r.count,
            total_ms: r.total_ms,
            avg_ms: r.avg_ms,
            min_ms: r.min_ms,
            max_ms: r.max_ms,
        }
    }
}

#[derive(Serialize, ToSchema)]
struct ApiGroupOut {
    api: StatOut,
    parts: Vec<StatOut>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiler/stats",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = Vec<ApiGroupOut>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<Vec<ApiGroupOut>>, AppError> {
    let rows = attome_profiler::read_stats(&state.base.redis)
        .await
        .map_err(map_err("read_stats"))?;

    Ok(Json(
        attome_profiler::group_hierarchy(rows)
            .into_iter()
            .map(|g| ApiGroupOut {
                api: g.api.into(),
                parts: g.parts.into_iter().map(Into::into).collect(),
            })
            .collect(),
    ))
}

#[derive(Deserialize, IntoParams)]
struct TraceQuery {
    /// Top-level probe name, e.g. `"entity.create"` or `"GET /api/v1/entities/{logicalname}"`
    /// — a query param, not a path segment, since probe names routinely
    /// contain `/` and spaces that a path segment can't carry unencoded.
    name: String,
    #[serde(default = "default_trace_limit")]
    limit: i64,
}

fn default_trace_limit() -> i64 {
    20
}

#[derive(Serialize, ToSchema)]
struct TracePartOut {
    name: String,
    ms: f64,
}

#[derive(Serialize, ToSchema)]
struct TraceSampleOut {
    ts: i64,
    total_ms: f64,
    parts: Vec<TracePartOut>,
}

impl From<attome_profiler::TraceSample> for TraceSampleOut {
    fn from(s: attome_profiler::TraceSample) -> Self {
        Self {
            ts: s.ts,
            total_ms: s.total_ms,
            parts: s
                .parts
                .into_iter()
                .map(|p| TracePartOut {
                    name: p.name,
                    ms: p.ms,
                })
                .collect(),
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiler/trace",
    tag = "admin",
    params(TraceQuery),
    responses(
        (status = 200, description = "Success", body = Vec<TraceSampleOut>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn trace(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<TraceQuery>,
) -> Result<Json<Vec<TraceSampleOut>>, AppError> {
    if q.name.trim().is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let limit = q.limit.clamp(1, 50);

    let samples = attome_profiler::read_trace(&state.base.redis, &q.name, limit)
        .await
        .map_err(map_err("read_trace"))?;

    Ok(Json(samples.into_iter().map(Into::into).collect()))
}

/// Resets the profiler: unlinks every `attome-profiler:*` key (plus the legacy
/// `profiler:*` namespace that predates the rename and never expired) so an
/// operator can start a clean measurement window without flushing the store
/// the security controls live on. Admin-only, audited (D-542: the `x-audit`
/// declaration below plus the in-transaction event this handler writes), and
/// idempotent — a second call still answers 204 with nothing left to delete.
///
/// The reset itself is a Redis `UNLINK`, not a database mutation, so there is
/// no domain transaction to ride: a transaction is opened solely for the
/// mandatory audit event, and a write failure fails the request (the unlink
/// is idempotent, so retrying is safe).
///
/// BPR-16: every profiler site — the request middleware, the boot and job
/// flushes, and these three routes — uses the general `state.base.redis` pool,
/// never the fail-closed `redis_coordination` one, so the dashboard reads the
/// store the writers write and profiler load cannot compete with the pre-auth
/// limiter or S2S nonces (D-397).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/profiler/stats",
    tag = "admin",
    responses(
        (status = 204, description = "Profiler keys removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(
        attome_audit::AuditCategory::Configuration,
        attome_audit::AuditOperation::HardDelete,
    )])))),
)]
async fn reset_stats(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
) -> Result<StatusCode, AppError> {
    let deleted = attome_profiler::reset(&state.base.redis)
        .await
        .map_err(map_err("reset"))?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::HardDelete,
            ctx.user_id,
            "attome-profiler",
            None,
        )
        .named("profiler.reset")
        .comment(format!("deleted {deleted} profiler keys")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/profiler/stats",
            get(stats).delete(reset_stats),
        )
        .route("/api/v1/admin/profiler/trace", get(trace))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(stats, trace, reset_stats))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
