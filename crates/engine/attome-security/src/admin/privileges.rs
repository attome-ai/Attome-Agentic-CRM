//! Privilege catalog (read-only).

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct PrivilegeItem {
    id: Uuid,
    key: String,
    name: String,
    description: Option<String>,
}

impl std::fmt::Debug for PrivilegeItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegeItem").finish_non_exhaustive()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/security/privileges",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PrivilegeItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_privileges(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PrivilegeItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, key, name, description FROM privilege \
         WHERE is_active = true ORDER BY key LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privilege WHERE is_active = true")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, key, name, description)| PrivilegeItem {
            id,
            key,
            name,
            description,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/security/privileges", get(list_privileges))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_privileges))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
