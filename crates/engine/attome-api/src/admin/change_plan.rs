//! Y12-T3: `POST /api/v1/admin/entities/{entity_id}/change-plan` classifies
//! proposed structure changes as instant, online or background, each with a
//! time estimate from measured rates (`attome_metadata::provision::change_plan`).
//! It writes nothing. Admin only.

use attome_core::EngineState;
use attome_metadata::provision::{
    RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT,
    change_plan::{self, ChangeClass, StructureChange},
};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The most changes one plan classifies.
const MAX_PLAN_CHANGES: usize = 100;

/// The proposed changes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePlanRequest {
    /// Each `{ "kind": ..., "field": ... }`: `add_field`, `add_choice_value`,
    /// `rename_field` (with `to`), `set_required`, `add_index`,
    /// `set_max_length` (with `max_length`), `change_type` (with `to`),
    /// `backfill`, `delete_field`.
    #[schema(value_type = Vec<Object>)]
    pub changes: Vec<StructureChange>,
}

/// One change's class and estimate.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangePlanEntry {
    pub change: String,
    /// `instant`, `online` or `background`.
    pub class: String,
    pub estimate_secs: u64,
}

/// The plan.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangePlan {
    pub changes: Vec<ChangePlanEntry>,
    /// The sum of the estimates.
    pub total_estimate_secs: u64,
}

fn class_name(class: ChangeClass) -> &'static str {
    match class {
        ChangeClass::Instant => "instant",
        ChangeClass::Online => "online",
        ChangeClass::Background => "background",
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/change-plan",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "classifies proposed structure changes and estimates them; writes nothing"
    )))),
    params(("entity_id" = Uuid, Path)),
    request_body = ChangePlanRequest,
    responses(
        (status = 200, description = "Each change's class and estimate, in request order", body = ChangePlan),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "No changes, too many, or a malformed one", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn plan_changes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<ChangePlanRequest>,
) -> Result<Json<ChangePlan>, AppError> {
    if body.changes.is_empty() || body.changes.len() > MAX_PLAN_CHANGES {
        return Err(AppError::Validation(format!(
            "a change plan takes 1 to {MAX_PLAN_CHANGES} changes"
        )));
    }
    let entity = state
        .entities
        .load()
        .get_by_id(entity_id)
        .map(|meta| meta.logicalname.clone())
        .ok_or(AppError::NotFound)?;
    let items = change_plan::plan_changes(
        &state.base.db,
        &entity,
        RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT,
        &body.changes,
    )
    .await?;
    let total_estimate_secs = items.iter().map(|i| i.estimate_secs).sum();
    Ok(Json(ChangePlan {
        changes: items
            .into_iter()
            .map(|i| ChangePlanEntry {
                change: i.change,
                class: class_name(i.class).to_owned(),
                estimate_secs: i.estimate_secs,
            })
            .collect(),
        total_estimate_secs,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/change-plan",
        post(plan_changes),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(plan_changes))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
