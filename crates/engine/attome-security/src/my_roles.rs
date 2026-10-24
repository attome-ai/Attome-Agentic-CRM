//! T2-T2: `GET /api/v1/me/roles`, the signed-in person's own role names,
//! held directly or through a team. Pages use it to show a component only to
//! some roles; it is a layout hint, never an authorization decision (every
//! data read a page makes is checked on its own).

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

/// The caller's role names.
#[derive(Debug, Serialize, ToSchema)]
pub struct MyRoles {
    /// Distinct names, sorted.
    pub items: Vec<String>,
}

const ROLE_NAMES: &str = "SELECT DISTINCT r.name FROM role r \
      JOIN user_account_mm_role ur ON ur.role_ref = r.id \
     WHERE ur.user_ref = $1 AND ur.is_deleted = false AND r.is_deleted = false AND r.is_active \
    UNION \
    SELECT DISTINCT r.name FROM role r \
      JOIN role_mm_team rt ON rt.role_ref = r.id \
      JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref \
     WHERE ut.user_ref = $1 AND ut.is_deleted = false AND rt.is_deleted = false \
       AND r.is_deleted = false AND r.is_active \
    ORDER BY 1";

#[utoipa::path(
    get,
    path = "/api/v1/me/roles",
    tag = "auth",
    responses(
        (status = 200, description = "The caller's role names", body = MyRoles),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Returns the caller's own role names.
///
/// The roles held directly or through a team, distinct and sorted. A page
/// uses them to show a component only to some roles; they decide nothing
/// about access.
async fn my_roles(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<MyRoles>, AppError> {
    let items: Vec<String> = sqlx::query_scalar(ROLE_NAMES)
        .bind(ctx.user_id)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(MyRoles { items }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/me/roles", get(my_roles))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(my_roles))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
