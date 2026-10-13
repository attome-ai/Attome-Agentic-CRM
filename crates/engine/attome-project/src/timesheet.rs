//! `POST /api/v1/project/timesheet/{id}/submit`, `.../approve`, `.../reject`
//! — the M07 state model + D-195/D-421 four-eyes gate for timesheet
//! approval (M69 master-plan §4: "Timesheet submit/approve/reject as an M07
//! state model + approval plan; period locking after approval").
//!
//! **Submit is not gated.** Moving a timesheet from `draft` to `submitted`
//! is the owner declaring their own hours ready for review — there is no
//! separation-of-duties concern on your *own* submission, so it goes
//! straight through the state model with no `gate()` call. Only
//! `approve`/`reject` (a decision about *someone else's* hours) is gated,
//! same posture `change_request.rs` takes for the same reason — see that
//! module's doc comment for the full account of what the state model and
//! `gate()` each do and do not guarantee, which applies identically here.
//!
//! **One write path (P0 0.7, M07 §4.1).** Every status change here (submit,
//! approve, reject) is written by `entity_crud::update_record_for_with_comment`
//! -> `entity_mutation::update_one` with `{status, …}` — the path a generic
//! `PATCH` and `POST /{entity}/{id}/transition` take — so the state model's
//! `required_privilege` (`project_timesheet.approve` on the decisions),
//! its guard (`current_user != user_id`: nobody decides their own
//! timesheet), the audit event and the change feed apply here too. The
//! approve/reject routes require `.approve` (and `.update`); `gate()` still
//! runs first, and under four-eyes the decision runs as the deciding admin.
//!
//! **Period locking after approval.** Once `status = 'approved'`, this
//! module's own [`do_decide_timesheet`] is the only write path — the state
//! model has no `approved -> *` transition at all (not even back to
//! `draft`), so a `PATCH` at the generic entity endpoint or a repeat call to
//! this route both fail: the former on `check_transition`'s "no transition
//! configured from 'approved'", the latter on this function's own
//! `status == 'submitted'` precondition. That *is* the lock — no separate
//! "locked" flag or migration was needed.

use attome_core::EngineState;
use attome_records::entity_crud::update_record_for_with_comment;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::Utc;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::authorize_timesheet_access;
use crate::auth::{TimesheetApprove, TimesheetUpdate};

const ENTITY: &str = "project_timesheet";

/// Covers `approve`/`reject` only — `submit` is never gated (see this
/// module's doc comment).
pub const ACTION_TIMESHEET_DECIDE: &str = "project_timesheet.decide";

#[derive(Debug, Serialize, ToSchema)]
pub struct TimesheetDecisionResponse {
    pub timesheet_id: Uuid,
    pub status: String,
    pub row_version: i64,
    pub approval_pending: bool,
    pub approval_request_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct TimesheetRow {
    status: String,
}

async fn load_timesheet(state: &EngineState, id: Uuid) -> Result<Option<TimesheetRow>, AppError> {
    sqlx::query_as::<_, TimesheetRow>(
        "SELECT status FROM project_timesheet \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The gated path's entry point (and the historical signature
/// `execute_approved` calls): `actor` is the deciding admin; their security
/// context is resolved here so the state model's privilege and guard are
/// checked against them.
pub async fn do_decide_timesheet(
    state: &EngineState,
    timesheet_id: Uuid,
    from_state: &str,
    to_state: &str,
    actor: Uuid,
) -> Result<TimesheetDecisionResponse, AppError> {
    let ctx = state.base.security.resolve(actor).await?;
    decide_as(state, &ctx, timesheet_id, from_state, to_state).await
}

/// The status change for an authorized `ctx`: refuses (409) unless the
/// timesheet is in `from_state`, then writes `{status: to_state}` (plus
/// `approved_by`/`approved_at` on approval) through the generic update path
/// with the version it read — a concurrent write in between is a 409
/// `version_conflict`, never a silent overwrite.
async fn decide_as(
    state: &EngineState,
    ctx: &SecurityContext,
    timesheet_id: Uuid,
    from_state: &str,
    to_state: &str,
) -> Result<TimesheetDecisionResponse, AppError> {
    let current: Option<(String, i64)> = sqlx::query_as(
        "SELECT status, row_version FROM project_timesheet \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(timesheet_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (status, row_version) = current.ok_or(AppError::NotFound)?;
    if status != from_state {
        return Err(AppError::Conflict(
            "this timesheet is not in the expected state for this action",
        ));
    }

    let mut body = serde_json::json!({ "status": to_state });
    if to_state == "approved" {
        body["approved_by"] = serde_json::json!(ctx.user_id);
        body["approved_at"] = serde_json::json!(Utc::now().to_rfc3339());
    }
    let response = update_record_for_with_comment(
        state,
        ctx,
        ctx.user_id,
        ENTITY,
        timesheet_id,
        row_version,
        body,
        None,
    )
    .await?;

    Ok(TimesheetDecisionResponse {
        timesheet_id,
        status: to_state.to_owned(),
        row_version: response.row_version(),
        approval_pending: false,
        approval_request_id: None,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/project/timesheet/{id}/submit",
    tag = "project",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = TimesheetDecisionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such timesheet, or not visible to this caller", body = ErrorResponse),
        (status = 409, description = "Not in draft status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn submit_timesheet(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TimesheetUpdate>>,
    Path(timesheet_id): Path<Uuid>,
) -> Result<Json<TimesheetDecisionResponse>, AppError> {
    authorize_timesheet_access(&state, &ctx, timesheet_id).await?;
    let response = decide_as(&state, &ctx, timesheet_id, "draft", "submitted").await?;
    Ok(Json(response))
}

async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    timesheet_id: Uuid,
    to_state: &str,
) -> Result<(StatusCode, TimesheetDecisionResponse), AppError> {
    // The transition is a state change on the record, so the generic update
    // privilege applies as on a PATCH (`.approve` is the route's extractor).
    ctx.require(ENTITY, "update")?;
    authorize_timesheet_access(state, ctx, timesheet_id).await?;
    let ts = load_timesheet(state, timesheet_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if ts.status != "submitted" {
        return Err(AppError::Conflict(
            "this timesheet is not submitted and awaiting a decision",
        ));
    }

    let payload = serde_json::json!({
        "timesheet_id": timesheet_id,
        "to_state": to_state,
    });
    if let Some(request) =
        attome_audit::approval::gate(state, ACTION_TIMESHEET_DECIDE, payload, ctx.user_id).await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            TimesheetDecisionResponse {
                timesheet_id,
                status: ts.status,
                row_version: 0,
                approval_pending: true,
                approval_request_id: Some(request.id),
            },
        ));
    }

    let response = decide_as(state, ctx, timesheet_id, "submitted", to_state).await?;
    Ok((StatusCode::OK, response))
}

#[utoipa::path(
    post,
    path = "/api/v1/project/timesheet/{id}/approve",
    tag = "project",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = TimesheetDecisionResponse),
        (status = 202, description = "Four-eyes approval required — request submitted", body = TimesheetDecisionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks project_timesheet.approve or .update", body = ErrorResponse),
        (status = 404, description = "No such timesheet, or not visible to this caller", body = ErrorResponse),
        (status = 409, description = "Not submitted, already decided, or changed concurrently", body = ErrorResponse),
        (status = 422, description = "The transition's guard refused it (the caller owns this timesheet)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn approve_timesheet(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TimesheetApprove>>,
    Path(timesheet_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TimesheetDecisionResponse>), AppError> {
    let (status, response) = decide(&state, &ctx, timesheet_id, "approved").await?;
    Ok((status, Json(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/project/timesheet/{id}/reject",
    tag = "project",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = TimesheetDecisionResponse),
        (status = 202, description = "Four-eyes approval required — request submitted", body = TimesheetDecisionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks project_timesheet.approve or .update", body = ErrorResponse),
        (status = 404, description = "No such timesheet, or not visible to this caller", body = ErrorResponse),
        (status = 409, description = "Not submitted, already decided, or changed concurrently", body = ErrorResponse),
        (status = 422, description = "The transition's guard refused it (the caller owns this timesheet)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn reject_timesheet(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TimesheetApprove>>,
    Path(timesheet_id): Path<Uuid>,
) -> Result<(StatusCode, Json<TimesheetDecisionResponse>), AppError> {
    let (status, response) = decide(&state, &ctx, timesheet_id, "rejected").await?;
    Ok((status, Json(response)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/project/timesheet/{id}/submit",
            post(submit_timesheet),
        )
        .route(
            "/api/v1/project/timesheet/{id}/approve",
            post(approve_timesheet),
        )
        .route(
            "/api/v1/project/timesheet/{id}/reject",
            post(reject_timesheet),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(submit_timesheet, approve_timesheet, reject_timesheet))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
