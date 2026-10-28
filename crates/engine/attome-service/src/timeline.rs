//! `GET /api/v1/ticket/{id}/timeline` (M85 Incident Management) — the
//! ticket's audit events, status transitions, communications and linked
//! decisions in one newest-first feed.
//!
//! **A thin caller since D-601.** The merge, its per-source authorization and
//! its field filter live in the entity-generic record timeline,
//! `attome_records::entity_crud::timeline` (`GET /api/v1/{entity}/{id}/timeline`,
//! basic-units plan U3, ruling B-R4). This route keeps its original contract:
//! the four original kinds only (notes and activities are on the generic
//! route), the first `MAX_PAGE_SIZE` entries, and the
//! `PaginatedResponse<T>` envelope (page 1, `page_size` = that ceiling).
//! Clients that want paging or the other kinds call the generic route with
//! `service_ticket` as the entity.
//!
//! The status transitions come from the ticket's state model
//! (`platform-bundles/attome-service.json`, `state_field = "status"`) like any
//! other entity's, not from a hard-coded column.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_records::entity_crud::timeline::{TimelineOptions, record_timeline};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, MAX_PAGE_SIZE, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use uuid::Uuid;

pub use attome_records::entity_crud::timeline::{TimelineEntry, TimelineEntryKind};

use crate::auth::TicketRead;

const TICKET_ENTITY: &str = "service_ticket";

/// The kinds this route has always returned.
const TICKET_TIMELINE_KINDS: [TimelineEntryKind; 4] = [
    TimelineEntryKind::AuditEvent,
    TimelineEntryKind::StateTransition,
    TimelineEntryKind::Communication,
    TimelineEntryKind::Decision,
];

/// One ticket's timeline: the generic record timeline, restricted to the four
/// original kinds and the first `MAX_PAGE_SIZE` entries. `NotFound` when the
/// caller cannot see the ticket itself.
pub async fn build_timeline(
    state: &EngineState,
    ctx: &SecurityContext,
    ticket_id: Uuid,
) -> Result<PaginatedResponse<TimelineEntry>, AppError> {
    let opts = TimelineOptions {
        cursor: None,
        page_size: MAX_PAGE_SIZE,
        kinds: Some(TICKET_TIMELINE_KINDS.into_iter().collect::<HashSet<_>>()),
        // The ticket alone, as this route has always shown it.
        related: false,
        ..Default::default()
    };
    let page = record_timeline(state, ctx, TICKET_ENTITY, ticket_id, &opts).await?;
    let total = page.items.len() as i64;
    Ok(PaginatedResponse::new(page.items, total, 1, MAX_PAGE_SIZE))
}

/// Read a ticket's timeline
///
/// The ticket's audit events, status changes, communications and linked decisions in one feed, newest
/// first, filtered to what the caller may read. Anyone who may read tickets.
#[utoipa::path(
    get,
    path = "/api/v1/ticket/{id}/timeline",
    tag = "service",
    params(("id" = Uuid, Path, description = "The ticket")),
    responses(
        (status = 200, description = "Assembled, permission-filtered ticket timeline", body = PaginatedResponse<TimelineEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such ticket, or the caller cannot see it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn ticket_timeline(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketRead>>,
    Path(ticket_id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<TimelineEntry>>, AppError> {
    let timeline = build_timeline(&state, &ctx, ticket_id).await?;
    Ok(Json(timeline))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ticket/{id}/timeline", get(ticket_timeline))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `lib.rs::openapi`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(ticket_timeline))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
