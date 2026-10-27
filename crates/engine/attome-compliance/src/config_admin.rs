//! Z1-T7: `GET /api/v1/admin/config/starts` lists node starts with their
//! configuration fingerprints, newest first; `GET
//! /api/v1/admin/config/starts/diff?a={id}&b={id}` names the keys whose
//! values differ between two starts (secret values are never stored, so
//! never shown). Administrators only.
//!
//! Z1-T8: `GET /api/v1/admin/secrets` lists every secret the configuration
//! holds with its users, key ids and age, and no value.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
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
use crate::secret_inventory::{self, SecretInventoryRow};

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
#[into_params(parameter_in = Query)]
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
    _ctx: Authorized<Privilege<area::Security>>,
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
    _ctx: Authorized<Privilege<area::Security>>,
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

#[utoipa::path(
    get,
    path = "/api/v1/admin/secrets",
    tag = "admin-config",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Every secret of this node's configuration by name: the features that use it, its key ids, the active one and its age. Never a value.", body = PaginatedResponse<SecretInventoryRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_secrets(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Security>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SecretInventoryRow>>, AppError> {
    let window = PageWindow::resolve(page.page, page.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let config = &state.base.config;
    Ok(Json(
        secret_inventory::list(
            &state.base.db,
            config.secret_inventory(),
            config.security.secret_max_age_days,
            window,
        )
        .await?,
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/config/starts", get(list_config_starts))
        .route("/api/v1/admin/config/starts/diff", get(diff_config_starts))
        .route("/api/v1/admin/secrets", get(list_secrets))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_config_starts, diff_config_starts, list_secrets))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
