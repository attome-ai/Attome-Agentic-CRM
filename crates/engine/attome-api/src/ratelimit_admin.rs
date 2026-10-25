//! Rate-limit bans (roadmap Q20-T5): an administrator sees who is under a
//! temporary ban (five tripped limit windows in an hour) and can lift one.
//! Lifting is a security event.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_server::middleware::rate_limit::{ActiveBan, lift_ban, list_bans};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};

/// Rate-limit bans
///
/// Rate-limit bans. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/rate-limits/bans",
    tag = "admin",
    operation_id = "list_rate_limit_bans",
    responses(
        (status = 200, description = "Every temporary ban still in force", body = PaginatedResponse<ActiveBan>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn bans(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<ActiveBan>>, AppError> {
    let items = list_bans(&state.base.redis_coordination).await?;
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// Lift a rate-limit ban
///
/// Lift a rate-limit ban. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/rate-limits/bans/{bucket}",
    tag = "admin",
    operation_id = "lift_rate_limit_ban",
    params(("bucket" = String, Path, description = "`user:{id}` or `ip:{address}`")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "The ban is lifted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No ban for that caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn lift(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(bucket): Path<String>,
) -> Result<StatusCode, AppError> {
    if !lift_ban(&state.base.redis_coordination, &bucket).await? {
        return Err(AppError::NotFound);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "rate_limit_ban",
            None,
        )
        .named("rate_limit.ban_lifted"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(bucket = %bucket, by = %ctx.user_id, "rate limit: ban lifted");
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/rate-limits/bans", get(bans))
        .route("/api/v1/admin/rate-limits/bans/{bucket}", delete(lift))
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(bans, lift), components(schemas(ActiveBan)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
