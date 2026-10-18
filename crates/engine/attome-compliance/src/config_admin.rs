//! Z1-T7: `GET /api/v1/admin/config/starts` lists node starts with their
//! configuration fingerprints, newest first; `GET
//! /api/v1/admin/config/starts/diff?a={id}&b={id}` names the keys whose
//! values differ between two starts (secret values are never stored, so
//! never shown). Administrators only.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, OnePageQuery, PageBase, PageWindow,
    PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::config_starts::{self, ConfigStartRow};

/// One changed key in a comparison.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigChange {
    /// The dotted configuration path, e.g. `app.port`.
    pub path: String,
    #[schema(value_type = Object)]
    pub before: serde_json::Value,
    #[schema(value_type = Object)]
    pub after: serde_json::Value,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct StartsDiffQuery {
    /// The earlier start.
    pub a: Uuid,
    /// The later start.
    pub b: Uuid,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/config/starts",
    tag = "admin-config",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Node starts with their configuration fingerprints, newest first", body = PaginatedResponse<ConfigStartRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_config_starts(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ConfigStartRow>>, AppError> {
    let window = PageWindow::resolve(page.page, page.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    Ok(Json(config_starts::list(&state.base.db, window).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/config/starts/diff",
    tag = "admin-config",
    params(StartsDiffQuery),
    responses(
        (status = 200, description = "The configuration keys whose values differ, by dotted path", body = PaginatedResponse<ConfigChange>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such start", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn diff_config_starts(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<StartsDiffQuery>,
) -> Result<Json<PaginatedResponse<ConfigChange>>, AppError> {
    let changes: Vec<ConfigChange> = config_starts::diff(&state.base.db, query.a, query.b)
        .await?
        .into_iter()
        .map(|c| ConfigChange {
            path: c.path,
            before: c.before,
            after: c.after,
        })
        .collect();
    let total = i64::try_from(changes.len()).unwrap_or(i64::MAX);
    let page_size = total.max(1);
    Ok(Json(PaginatedResponse::new(changes, total, 1, page_size)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/config/starts", get(list_config_starts))
        .route("/api/v1/admin/config/starts/diff", get(diff_config_starts))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_config_starts, diff_config_starts))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
