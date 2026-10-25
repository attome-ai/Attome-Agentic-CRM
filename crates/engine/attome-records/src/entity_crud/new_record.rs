//! `GET /api/v1/{entity}/new` (roadmap A28-T2): the values a new record
//! starts with, so a form shows the defaults before the person saves. The
//! same `apply_defaults` the create path runs, for the calling person, now.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::Value;

use super::resolve::resolve_entity;

/// Defaults for a new record
///
/// A28-T2: the defaults a new record of the entity starts with, by field.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/new",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "Each defaulted field and its starting value", body = HashMap<String, serde_json::Value>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn new_record_defaults(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path(entity): Path<String>,
) -> Result<Json<HashMap<String, Value>>, AppError> {
    let (_, entity_name, attrs, _) = resolve_entity(&state, &entity).await?;
    ctx.require(&entity_name, "read")?;
    let now = attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    let filled = crate::entity_mutation::apply_defaults(
        &attrs,
        &serde_json::Map::new(),
        Some(ctx.user_id),
        now,
    )
    .unwrap_or_default();
    Ok(Json(filled.into_iter().collect()))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(new_record_defaults))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
