//! Q10-T9: `GET /api/v1/admin/security/privilege-removal-proposals`, the
//! drafts `crate::usage::propose_unused` makes for privileges no holder of a
//! role used in 90 days, for access-review campaigns (Q11). Read only.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::usage::{RemovalProposal, list_proposals};

#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct ProposalQuery {
    /// `draft`, `accepted` or `dismissed`; every proposal when omitted.
    #[serde(default)]
    status: Option<String>,
}

/// Privilege removal proposals
///
/// Drafts for role privileges none of the role's holders used in 90 days, newest first. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/privilege-removal-proposals",
    tag = "admin-security",
    params(OnePageQuery, ProposalQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RemovalProposal>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Query(page): Query<OnePageQuery>,
    Query(query): Query<ProposalQuery>,
) -> Result<Json<PaginatedResponse<RemovalProposal>>, AppError> {
    let status = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if status.is_some_and(|s| !["draft", "accepted", "dismissed"].contains(&s)) {
        return Err(AppError::Validation(
            "status is draft, accepted or dismissed".into(),
        ));
    }
    let window = page.window();
    let (items, total) =
        list_proposals(&state.base.db, status, window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/privilege-removal-proposals",
        get(list),
    )
}
