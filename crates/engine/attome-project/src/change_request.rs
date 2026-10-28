//! `POST /api/v1/project/change-request/{id}/approve` and `.../reject` —
//! the D-195/D-421 four-eyes gate applied to change-request decisions
//! (M69 master-plan §4: "Change request → attome-approval four-eyes plan +
//! M07 state model; auto-baseline and impact application on approval").
//!
//! **Wiring, same three steps every gated flow in this workspace follows**
//! (`attome_audit::approval::gate`'s own module doc): call `gate()` at the top
//! with [`ACTION_CHANGE_REQUEST_DECIDE`] and a payload carrying everything
//! [`do_decide_change_request`] needs; that function is the actual mutation,
//! callable both from here (ungated path) and from
//! `attome-api::approval_admin::execute_approved` (the path a *different*
//! admin's later decision on a gated request takes); one match arm was
//! added there.
//!
//! **What this closes, and what it does not.** `project_change_request
//! .status` now has an M07 state model (`pending -> approved`/`rejected`
//! only), so a raw generic `PATCH` can no longer set an arbitrary status
//! value. When `approval.required_actions` or an `approval_policy`
//! names this action_type, `gate()` additionally enforces separation of
//! duties (`attome_approval::decide_step`: the deciding admin may not be the
//! same identity that called this route) — closing the master-plan's
//! literal complaint, "a requester can approve their own change request",
//! for any deployment that turns gating on for this action.
//!
//! **One write path (P0 0.7, M07 §4.1).** The decision is written through
//! `entity_mutation::update_one` (+ `MutationRing`) with `{status: to_state}`
//! — the same path a generic `PATCH` and `POST /{entity}/{id}/transition`
//! take — so the state model's `required_privilege`
//! (`project_change_request.approve`), its guard
//! (`current_user != requested_by`: nobody decides a change request they
//! requested), the audit event and the change feed all apply here too. The
//! routes themselves require `.approve` (and `.update`), so an `.update`-only
//! holder is refused on this route exactly as on a PATCH. `gate()` still runs
//! first; under four-eyes the decision later runs as the *deciding* admin
//! (`execute_approved` passes their id), and the guard is evaluated against
//! them.
//!
//! **Impact application is atomic with the status write; the baseline
//! capture is not.** The status update (`update_one`, CAS on `row_version`)
//! and the project's
//! `budget_amount`/`target_end_date` adjustment happen in one transaction
//! (below) — a partial application of one without the other is not
//! possible. The automatic baseline snapshot that follows a successful
//! approval is a separate, best-effort call to [`crate::baseline::
//! capture_baseline`] (already its own transaction, already idempotent on
//! `(project_id, label)`): its failure is logged, not fatal, the same
//! posture `attome_audit::approval::gate`'s own doc comment accepts for its
//! non-atomic audit write — a lost automatic snapshot does not un-approve
//! the change request or un-apply its budget/schedule impact, and a PM can
//! always capture a baseline manually afterward (`POST
//! /project/{id}/baseline`).

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_records::entity_crud::{field_changes_from_obj, require_record_access, resolve_entity};
use attome_records::entity_mutation::{MutationMode, update_one};
use attome_records::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::authorize_change_request_access;
use crate::auth::ChangeRequestApprove;

const ENTITY: &str = "project_change_request";

/// Covers both `approve` and `reject` — the payload's `to_state`
/// disambiguates which. One action_type, not two, because they are the same
/// gated *decision*: a deployment that requires four-eyes for one requires
/// it for the other.
pub const ACTION_CHANGE_REQUEST_DECIDE: &str = "project_change_request.decide";

#[derive(Debug, Serialize, ToSchema)]
pub struct ChangeRequestDecisionResponse {
    pub change_request_id: Uuid,
    pub project_id: Uuid,
    pub status: String,
    pub row_version: i64,
    /// `true` when this call only submitted a pending four-eyes approval
    /// request rather than deciding the change request immediately —
    /// mirrors `attome-dashboard::lifecycle::PublishResponse`'s own field.
    pub approval_pending: bool,
    pub approval_request_id: Option<Uuid>,
}

/// Pre-check row for `decide()` below — deliberately just enough to answer
/// "is there anything to gate/decide at all", not the impact fields
/// [`do_decide_change_request`] re-fetches (under `FOR UPDATE`) right before
/// actually applying them.
#[derive(sqlx::FromRow)]
struct ChangeRequestRow {
    project_id: Uuid,
    status: String,
}

async fn load_change_request(
    state: &EngineState,
    id: Uuid,
) -> Result<Option<ChangeRequestRow>, AppError> {
    sqlx::query_as::<_, ChangeRequestRow>(
        "SELECT project_id, status FROM project_change_request \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Applies `impact_budget`/`impact_schedule_days` to the parent project, in
/// the same transaction as the status CAS update — see this module's doc
/// comment for why these two writes are atomic while the baseline capture
/// that follows is not.
async fn apply_impact(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    impact_budget: Option<f64>,
    impact_schedule_days: Option<f64>,
) -> Result<(), AppError> {
    if impact_budget.is_none() && impact_schedule_days.is_none() {
        return Ok(());
    }
    let (budget_amount, target_end_date): (Option<f64>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT budget_amount::double precision, target_end_date \
         FROM attome_project WHERE id = $1",
    )
    .bind(project_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let new_budget = match impact_budget {
        Some(delta) => Some(budget_amount.unwrap_or(0.0) + delta),
        None => budget_amount,
    };
    let new_target_end_date = match impact_schedule_days {
        Some(days) => target_end_date.map(|d| d + Duration::days(days.round() as i64)),
        None => target_end_date,
    };

    sqlx::query(
        "UPDATE attome_project SET budget_amount = $1::numeric, target_end_date = $2, \
             modified_at = NOW() \
         WHERE id = $3",
    )
    .bind(new_budget)
    .bind(new_target_end_date)
    .bind(project_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The gated path's entry point: `execute_approved` calls this once a
/// different admin decides a submitted four-eyes request. `actor` is that
/// deciding admin; their security context is resolved here, so the state
/// model's privilege and guard are checked against *them* — not skipped.
pub async fn do_decide_change_request(
    state: &EngineState,
    change_request_id: Uuid,
    to_state: &str,
    actor: Uuid,
) -> Result<ChangeRequestDecisionResponse, AppError> {
    let ctx = state.base.security.resolve(actor).await?;
    decide_as(state, &ctx, change_request_id, to_state).await
}

/// `(project_id, status, row_version, impact_budget, impact_schedule_days)`.
type DecisionRow = (Uuid, String, i64, Option<f64>, Option<f64>);

/// The actual mutation, for an authorized `ctx` (the route's caller, or the
/// deciding admin on the gated path). Writes `{status: to_state}` through
/// `update_one` — transition check, `required_privilege`, guard, rules,
/// change feed — then applies the impact in the same transaction and commits
/// through `MutationRing` (audit with the `state_transition` marker,
/// invalidation, rw-pin). A decided request is a 409; a concurrent write
/// between the read and the update is a 409 `version_conflict`.
async fn decide_as(
    state: &EngineState,
    ctx: &SecurityContext,
    change_request_id: Uuid,
    to_state: &str,
) -> Result<ChangeRequestDecisionResponse, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, ENTITY).await?;
    require_record_access(
        state,
        ctx,
        entity_id,
        &entity_name,
        change_request_id,
        RecordAction::Update,
    )
    .await?;

    let current: Option<DecisionRow> = sqlx::query_as(
        "SELECT project_id, status, row_version, impact_budget::double precision, \
                impact_schedule_days::double precision \
         FROM project_change_request \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(change_request_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (project_id, status, row_version, impact_budget, impact_schedule_days) =
        current.ok_or(AppError::NotFound)?;
    if status != "pending" {
        return Err(AppError::Conflict(
            "this change request has already been decided",
        ));
    }

    let mut obj = serde_json::Map::new();
    obj.insert(
        "status".to_owned(),
        serde_json::Value::String(to_state.to_owned()),
    );
    let mutation_actor = MutationActor::fetch(state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mutation = update_one(
        &mut tx,
        state,
        ctx,
        &entity_name,
        entity_id,
        change_request_id,
        &attrs,
        &obj,
        ctx.user_id,
        row_version,
        MutationMode::Strict,
    )
    .await?;

    if to_state == "approved" {
        apply_impact(&mut tx, project_id, impact_budget, impact_schedule_days).await?;
    }

    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("change request update returned no row"))?;
    let mut audit = MutationAudit::new();
    audit.changed_fields =
        field_changes_from_obj(&mut tx, state, &attrs, &obj, mutation.old_row.as_ref()).await;
    MutationRing::new(state)
        .commit_mutation(
            tx,
            ctx,
            entity_id,
            &entity_name,
            &attrs,
            &mutation_actor,
            AuditOperation::Update,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            GrantInvalidation::ByRow(Some(&row)),
            audit,
            "change request decision",
            mutation,
        )
        .await?;
    let row_version = row
        .get("row_version")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(row_version + 1);
    let actor = ctx.user_id;

    if to_state == "approved" {
        let label = format!("Change Request {change_request_id} approved");
        match crate::baseline::capture_baseline(
            &state.base.db,
            project_id,
            actor,
            &label,
            "change_request",
        )
        .await
        {
            Ok((response, true)) => {
                attome_audit::write_business_event(
                    state,
                    "project_baseline",
                    response.baseline_id,
                    AuditOperation::Create,
                    "project_baseline_captured",
                    actor,
                    None,
                    None,
                    format!(
                        "baseline '{label}' captured (change_request), {} item(s)",
                        response.item_count
                    ),
                )
                .await;
            }
            Ok((_, false)) => {}
            Err(e) => tracing::error!(
                error = %e,
                change_request_id = %change_request_id,
                project_id = %project_id,
                "change request approved, but the automatic baseline capture failed \
                 (capture one manually via POST /project/{{id}}/baseline)"
            ),
        }
    }

    Ok(ChangeRequestDecisionResponse {
        change_request_id,
        project_id,
        status: to_state.to_owned(),
        row_version,
        approval_pending: false,
        approval_request_id: None,
    })
}

async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    change_request_id: Uuid,
    to_state: &str,
) -> Result<(StatusCode, ChangeRequestDecisionResponse), AppError> {
    // The transition is a state change on the record, so the generic update
    // privilege applies as on a PATCH (`.approve` is the route's extractor).
    ctx.require(ENTITY, "update")?;
    authorize_change_request_access(state, ctx, change_request_id).await?;
    let cr = load_change_request(state, change_request_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if cr.status != "pending" {
        return Err(AppError::Conflict(
            "this change request has already been decided",
        ));
    }

    let payload = serde_json::json!({
        "change_request_id": change_request_id,
        "to_state": to_state,
    });
    if let Some(request) =
        attome_audit::approval::gate(state, ACTION_CHANGE_REQUEST_DECIDE, payload, ctx.user_id)
            .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            ChangeRequestDecisionResponse {
                change_request_id,
                project_id: cr.project_id,
                status: cr.status,
                row_version: 0,
                approval_pending: true,
                approval_request_id: Some(request.id),
            },
        ));
    }

    let response = decide_as(state, ctx, change_request_id, to_state).await?;
    Ok((StatusCode::OK, response))
}

/// Approve a project change request
///
/// Approves the change request through the four-eyes gate: when the approval policy requires it, this
/// submits an approval request a second person decides; otherwise it applies now. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/project/change-request/{id}/approve",
    tag = "project",
    params(("id" = Uuid, Path, description = "The change request")),
    responses(
        (status = 200, description = "Success", body = ChangeRequestDecisionResponse),
        (status = 202, description = "Four-eyes approval required — request submitted", body = ChangeRequestDecisionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks project_change_request.approve or .update", body = ErrorResponse),
        (status = 404, description = "No such change request, or not visible to this caller", body = ErrorResponse),
        (status = 409, description = "Already decided, or changed concurrently", body = ErrorResponse),
        (status = 422, description = "The transition's guard refused it (the caller requested this change request)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn approve_change_request(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ChangeRequestApprove>>,
    Path(change_request_id): Path<Uuid>,
) -> Result<(StatusCode, Json<ChangeRequestDecisionResponse>), AppError> {
    let (status, response) = decide(&state, &ctx, change_request_id, "approved").await?;
    Ok((status, Json(response)))
}

/// Reject a project change request
///
/// Rejects the change request, through the same four-eyes gate as approving. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/project/change-request/{id}/reject",
    tag = "project",
    params(("id" = Uuid, Path, description = "The change request")),
    responses(
        (status = 200, description = "Success", body = ChangeRequestDecisionResponse),
        (status = 202, description = "Four-eyes approval required — request submitted", body = ChangeRequestDecisionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks project_change_request.approve or .update", body = ErrorResponse),
        (status = 404, description = "No such change request, or not visible to this caller", body = ErrorResponse),
        (status = 409, description = "Already decided, or changed concurrently", body = ErrorResponse),
        (status = 422, description = "The transition's guard refused it (the caller requested this change request)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn reject_change_request(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ChangeRequestApprove>>,
    Path(change_request_id): Path<Uuid>,
) -> Result<(StatusCode, Json<ChangeRequestDecisionResponse>), AppError> {
    let (status, response) = decide(&state, &ctx, change_request_id, "rejected").await?;
    Ok((status, Json(response)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/project/change-request/{id}/approve",
            post(approve_change_request),
        )
        .route(
            "/api/v1/project/change-request/{id}/reject",
            post(reject_change_request),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(approve_change_request, reject_change_request))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
