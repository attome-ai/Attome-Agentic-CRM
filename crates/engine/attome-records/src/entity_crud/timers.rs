//! M10-T4: a record's pending timers (`GET /api/v1/{entity}/{id}/timers`):
//! what the platform is waiting to do with it and when, for anyone who may
//! read the record. Kinds and times only; a timer's payload stays inside.

use attome_core::EngineState;
use attome_core::timer::{PendingTimer, pending_for_target};
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use uuid::Uuid;

use super::access::require_record_read;
use super::resolve::resolve_entity;

/// The record's pending timers, soonest first (at most 200).
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/timers",
    description = "The pending timers on this record that the caller may see: what each will do and when (M10-T4).",
    tag = "entity",
    operation_id = "list_record_timers",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record's id"),
    ),
    responses(
        (status = 200, description = "The record's pending timers, soonest first", body = PaginatedResponse<PendingTimer>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not read this entity", body = ErrorResponse),
        (status = 404, description = "No such record", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn record_timers(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
) -> Result<Json<PaginatedResponse<PendingTimer>>, AppError> {
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    require_record_read(&state, &ctx, entity_id, &entity_name, record_id).await?;
    let items = pending_for_target(&state.base.db, &entity_name, record_id).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(record_timers), components(schemas(PendingTimer)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
