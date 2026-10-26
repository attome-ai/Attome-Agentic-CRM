//! Q14-T4: `GET /api/v1/{entity}/{id}/access/explain`, why a person can or
//! cannot read, change or delete one record. A thin handler over
//! `attome_security::explain`.
//!
//! Asking about someone else needs the Security administration area (Q12).
//! Asking about yourself needs read access to the record: without it the
//! answer is 404, the same as a read, so the explainer never tells anyone a
//! hidden record exists.

use attome_core::EngineState;
use attome_security::RecordAction;
use attome_security::explain::{AccessExplanation, explain};
use attome_server::authz::{AdminArea, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use super::resolve::resolve_entity;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ExplainQuery {
    /// The person to explain for; the caller when omitted. Someone else
    /// needs the Security administration area.
    #[serde(default)]
    pub user: Option<Uuid>,
    /// `read` (default), `update` or `delete`.
    #[serde(default)]
    pub action: Option<String>,
}

/// Explain record access
///
/// Why a person can or cannot read, change or delete a record: every source the record filter applies, in order, with the one that decides marked.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/access/explain",
    tag = "entity",
    operation_id = "explain_record_access",
    description = "Lists the sources of access the record filter applies (administrator, privilege, role level, business unit, ownership, user and team shares, default share, sharing rule, deny) for one person, record and operation, each granting, denying or not applying, with the deciding one marked (Q14-T4). Read only. Another person needs the Security administration area; yourself needs read access to the record.",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ExplainQuery,
    ),
    responses(
        (status = 200, description = "The explanation", body = AccessExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Asking about someone else without the Security administration area", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "Unknown action", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn explain_access(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Query(query): Query<ExplainQuery>,
) -> Result<Json<AccessExplanation>, AppError> {
    let action = match query.action.as_deref().unwrap_or("read") {
        "read" => RecordAction::Read,
        "update" => RecordAction::Update,
        "delete" => RecordAction::Delete,
        _ => {
            return Err(AppError::Validation(
                "action must be read, update or delete".into(),
            ));
        }
    };
    let (entity_id, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    let user = query.user.unwrap_or(ctx.user_id);
    let security_admin = AdminArea::Security.held_by(&ctx);
    if user != ctx.user_id && !security_admin {
        return Err(AppError::Forbidden);
    }
    let target = state.base.security.resolve(user).await?;
    let db = &state.base.db;
    if !security_admin {
        let read = explain(
            db,
            &target,
            entity_id,
            &entity_name,
            record_id,
            RecordAction::Read,
        )
        .await?;
        if !read.allowed {
            return Err(AppError::NotFound);
        }
    }
    Ok(Json(
        explain(db, &target, entity_id, &entity_name, record_id, action).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(explain_access))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
