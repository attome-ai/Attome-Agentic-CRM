//! User lookup (P-rls-admin-ui addition). Every mutation in this module tree
//! that takes a `user_email` (`teams::AddTeamMemberBody`,
//! `shares::resolve_principal`, etc.) resolves it inline via an exact
//! `lower(email) = lower($1)` match — this is the one read-only search a
//! user-centric admin screen needs first: find candidates while typing an
//! email, or resolve the `user_id` an `effective-access` preview needs.
//! Prefix-matched (not full substring — email search-as-you-type is
//! overwhelmingly prefix-driven) and capped at 20 rows, same bounded-result-
//! set posture every other list endpoint here takes.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub(super) struct UserLookupItem {
    id: Uuid,
    email: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct UserListItem {
    id: Uuid,
    user_name: Option<String>,
    email: Option<String>,
    is_active: bool,
}

/// List users
///
/// P-admin-list-pagination: previously a flat `LIMIT 500` with no `total` and
/// no way to see past row 500 — a deployment with more users than that had
/// rows silently invisible to admins, with no signal that truncation had
/// happened. Same `PaginatedResponse<T>`/`page`+`page_size` envelope every
/// other admin-list endpoint in this codebase uses (see `jobs_admin.rs`'s
/// dead-letter list) — `page` is one-based: page 1 is the first page.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/users",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<UserListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_users(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<UserListItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, user_name, email, is_active
         FROM user_account
         ORDER BY email NULLS LAST, user_name NULLS LAST
         LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_account")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, user_name, email, is_active)| UserListItem {
            id,
            user_name,
            email,
            is_active,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct UserLookupQuery {
    /// The text the email address starts with.
    email: String,
}

/// Look up users
///
/// Finds users whose email starts with the text typed, at most 20, for pickers. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/users/lookup",
    tag = "admin-security",
    params(UserLookupQuery),
    responses(
        (status = 200, description = "Success", body = Vec<UserLookupItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn lookup_users(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<UserLookupQuery>,
) -> Result<Json<Vec<UserLookupItem>>, AppError> {
    let prefix = query.email.trim();
    if prefix.is_empty() {
        return Ok(Json(Vec::new()));
    }

    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, email FROM user_account WHERE email ILIKE $1 || '%' \
         ORDER BY email LIMIT 20",
    )
    .bind(prefix)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, email)| UserLookupItem { id, email })
            .collect(),
    ))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/security/users", get(list_users))
        .route("/api/v1/admin/security/users/lookup", get(lookup_users))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_users, lookup_users))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
