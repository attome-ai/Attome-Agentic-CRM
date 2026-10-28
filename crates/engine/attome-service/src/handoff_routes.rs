//! AI7-T5: hand-off routes for people.
//!
//! - `GET /api/v1/service/handoffs` — the hand-offs waiting for the caller
//!   (to them, or to a queue they are a member of);
//! - `POST /api/v1/service/handoffs/{id}/accept` and `.../return` (`{note}`)
//!   under `If-Match`;
//! - `POST /api/v1/service/tickets/{id}/handoff` — a person hands a ticket to
//!   a person, a queue or an agent;
//! - `GET /api/v1/service/tickets/{id}/handoffs` — a ticket's hand-offs, for
//!   its hand-off card (AI7-T6).
//!
//! Each handler parses, calls one `crate::handoff` function and shapes the
//! answer; the permission rules and the SQL live there.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{TicketRead, TicketUpdate};
use crate::handoff::{Handoff, ToKind};

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// A hand-back to the agent.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffReturn {
    /// What the agent should do next.
    pub note: String,
}

/// A person's hand-off of a ticket.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewTicketHandoff {
    pub to_kind: ToKind,
    pub to_ref: Uuid,
    pub summary: String,
    pub reasoning: String,
}

/// A hand-off recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct HandoffCreated {
    pub id: Uuid,
    pub ticket_id: Uuid,
}

/// List my hand-offs
///
/// The hand-offs waiting for the caller: to them, or to a queue they are a member of.
#[utoipa::path(
    get,
    path = "/api/v1/service/handoffs",
    tag = "service",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Hand-offs waiting for the caller or their queues", body = PaginatedResponse<Handoff>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_handoffs(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketRead>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<Handoff>>, AppError> {
    Ok(Json(
        crate::handoff::pending_for(&state.base.db, ctx.user_id, &page).await?,
    ))
}

/// List a ticket's hand-offs
///
/// Every hand-off of the ticket, between agents and people, with its outcome.
#[utoipa::path(
    get,
    path = "/api/v1/service/tickets/{id}/handoffs",
    tag = "service",
    params(("id" = Uuid, Path, description = "The ticket"), OnePageQuery),
    responses(
        (status = 200, description = "The ticket's hand-offs, newest first", body = PaginatedResponse<Handoff>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.read", body = ErrorResponse),
        (status = 404, description = "No such ticket the caller can see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_ticket_handoffs(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketRead>>,
    Path(ticket): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<Handoff>>, AppError> {
    Ok(Json(
        crate::handoff::for_ticket(&state, &ctx, ticket, &page).await?,
    ))
}

/// Accept a hand-off
///
/// Takes the handed-off work, with the hand-off's `If-Match` row version. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/handoffs/{id}/accept",
    tag = "service",
    params(
        ("id" = Uuid, Path, description = "The hand-off"),
        ("If-Match" = String, Header, description = "The hand-off's row_version, quoted"),
    ),
    responses(
        (status = 200, description = "Accepted; the ticket is the caller's", body = Handoff),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not handed to the caller or a queue of theirs", body = ErrorResponse),
        (status = 404, description = "No such hand-off", body = ErrorResponse),
        (status = 409, description = "No longer waiting, a stale row_version, or another hand-off in progress", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn accept_handoff(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Handoff>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        crate::handoff::accept(&state, ctx.user_id, id, expected).await?,
    ))
}

/// Return a hand-off
///
/// Gives the work back with a note, with the hand-off's `If-Match` row version. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/handoffs/{id}/return",
    tag = "service",
    params(
        ("id" = Uuid, Path, description = "The hand-off"),
        ("If-Match" = String, Header, description = "The hand-off's row_version, quoted"),
    ),
    request_body = HandoffReturn,
    responses(
        (status = 200, description = "Returned; the agent resumes", body = Handoff),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller is not the ticket's assignee", body = ErrorResponse),
        (status = 404, description = "No such hand-off", body = ErrorResponse),
        (status = 409, description = "Already closed, a stale row_version, or another hand-off in progress", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed, no note, or not an agent's hand-off", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn return_handoff(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<HandoffReturn>,
) -> Result<Json<Handoff>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        crate::handoff::give_back(&state, ctx.user_id, id, &body.note, expected).await?,
    ))
}

/// Hand a ticket off
///
/// A person hands the ticket to another person or a queue, with a summary of where it stands. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/tickets/{id}/handoff",
    tag = "service",
    params(("id" = Uuid, Path, description = "The ticket")),
    request_body = NewTicketHandoff,
    responses(
        (status = 201, description = "Handed off", body = HandoffCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.update", body = ErrorResponse),
        (status = 404, description = "No such ticket the caller can see", body = ErrorResponse),
        (status = 409, description = "A hand-off of this ticket is already waiting or in progress", body = ErrorResponse),
        (status = 422, description = "No summary or reasoning, or a target the caller cannot see", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_ticket_handoff(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(ticket): Path<Uuid>,
    Json(body): Json<NewTicketHandoff>,
) -> Result<(StatusCode, Json<HandoffCreated>), AppError> {
    let id = crate::handoff::hand_off_by_person(
        &state,
        &ctx,
        ticket,
        body.to_kind,
        body.to_ref,
        &body.summary,
        &body.reasoning,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(HandoffCreated {
            id,
            ticket_id: ticket,
        }),
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service/handoffs", get(list_handoffs))
        .route("/api/v1/service/handoffs/{id}/accept", post(accept_handoff))
        .route("/api/v1/service/handoffs/{id}/return", post(return_handoff))
        .route(
            "/api/v1/service/tickets/{id}/handoff",
            post(post_ticket_handoff),
        )
        .route(
            "/api/v1/service/tickets/{id}/handoffs",
            get(list_ticket_handoffs),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_handoffs,
        list_ticket_handoffs,
        accept_handoff,
        return_handoff,
        post_ticket_handoff
    ),
    components(schemas(Handoff, HandoffReturn, NewTicketHandoff, HandoffCreated, ToKind))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn accept_and_return_need_if_match() {
        let mut headers = HeaderMap::new();
        assert!(if_match(&headers).is_err());
        headers.insert(IF_MATCH, HeaderValue::from_static("\"2\""));
        assert_eq!(if_match(&headers).expect("a version"), 2);
    }
}
