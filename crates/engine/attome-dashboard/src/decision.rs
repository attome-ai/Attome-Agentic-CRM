//! M28 Phase 1 (Decision Intelligence, `document/xrm/module/
//! M28-decision-intelligence/master-plan.md`) — decision records.
//!
//! Ordinary field CRUD on `dashboard_decision`/`dashboard_decision_option`/
//! `dashboard_decision_dependency` goes through the generic entity engine
//! (`/api/v1/dashboard_decision/{id}`, etc. — guidelines §9: no bespoke handler for
//! plain CRUD). This module adds only the one business-action transition the
//! generic engine cannot express: `proposed -> approved`, the human choosing
//! which option to run.
//!
//! **`execute` (`proposed`'s sibling transition, `approved -> executed`) is
//! deliberately NOT here.** It has to call `attome_ai::dispatch`, and this
//! crate cannot depend on `attome-ai`: `attome-api` depends on
//! `attome-dashboard` for real (`approval_admin.rs`'s `do_publish_dashboard`
//! dispatch) and, since M98, also on `attome-ai` for real
//! (`approval_admin.rs`'s `dispatch_approved_agent_action` call) —
//! `attome-dashboard -> attome-ai` would still close a cycle through
//! `attome-api`, even though D-477 (T3-2) removed the older, narrower
//! `attome-ai -> attome-api` edge this comment used to cite directly.
//! `attome-workflow` already sits in the position this module would need (a
//! "sibling" of `attome-ai`, depending on both `attome-api` and
//! `attome-ai` for real, never depended on by `attome-api` in turn) — see
//! its own `Cargo.toml` comment ("both sit above `attome-api`"), which
//! `attome-dashboard` cannot join without breaking the existing
//! `do_publish_dashboard` wiring. So `POST /api/v1/decisions/{id}/execute`
//! lives in `attome_ai::decision` instead — mounted as its own `EngineModel`,
//! gated by this module's own `MODULE_DASHBOARD` bit rather than
//! `MODULE_AI`, and reading/writing `dashboard_decision`/`dashboard_decision_option` by
//! bound SQL the same way `attome_metric::metric` reads tables it does not own
//! the seed of (`sql_query`, `sql_query_version`).
//! See that module's doc comment for the execute side of the flow.
use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_entity_access;
use crate::auth::DecisionUpdate;

/// Thin, `dashboard_decision`-scoped wrapper over the shared
/// `attome_audit::write_business_event` (M26 R-15 dedup — see
/// `attome_dashboard::lifecycle::write_lifecycle_audit`'s own comment).
#[allow(clippy::too_many_arguments)]
async fn write_decision_audit(
    state: &EngineState,
    decision_id: Uuid,
    operation: AuditOperation,
    event_name: &str,
    actor_id: Uuid,
    version_before: Option<i64>,
    version_after: Option<i64>,
    comment: String,
) {
    attome_audit::write_business_event(
        state,
        "dashboard_decision",
        decision_id,
        operation,
        event_name,
        actor_id,
        version_before,
        version_after,
        comment,
    )
    .await;
}

async fn lock_decision(
    tx: &mut Transaction<'_, Postgres>,
    decision_id: Uuid,
) -> Result<(), AppError> {
    // Advisory lock BEFORE reading — same "lock, then act" order as
    // `lifecycle.rs::lock_dashboard`, so two concurrent approvals of the same
    // decision can't both pass the status check below.
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-dashboard/decision:{decision_id}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another request is already changing this decision's state",
        ));
    }
    Ok(())
}

struct DecisionState {
    status: String,
    row_version: i64,
}

async fn load_decision_state(
    tx: &mut Transaction<'_, Postgres>,
    decision_id: Uuid,
) -> Result<DecisionState, AppError> {
    let row: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT status, row_version FROM dashboard_decision \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(decision_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (status, row_version) = row.ok_or(AppError::NotFound)?;
    Ok(DecisionState {
        status: status.unwrap_or_else(|| "proposed".to_string()),
        row_version,
    })
}

/// `pub` (not `pub(crate)`), same reasoning as `lifecycle.rs`'s `do_*`
/// functions: this crate's own tests exercise the transition directly
/// against a live database without a full authenticated HTTP request.
pub async fn do_approve(
    db: &DbPool,
    decision_id: Uuid,
    chosen_option_id: Uuid,
    expected_row_version: i64,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_decision(&mut tx, decision_id).await?;
    let state = load_decision_state(&mut tx, decision_id).await?;
    if state.status != "proposed" {
        return Err(AppError::Conflict(
            "only a proposed decision can be approved",
        ));
    }
    if state.row_version != expected_row_version {
        return Err(AppError::Conflict(
            "row_version does not match the decision's current state — reload and retry",
        ));
    }

    // The chosen option must actually belong to this decision — otherwise a
    // caller could point `chosen_option_ref` at an arbitrary option row from
    // a different decision, which `attome_ai::decision::execute` would then
    // trust for its `action_id`/`args`.
    let option_decision_ref: Option<Uuid> =
        sqlx::query_scalar("SELECT decision_ref FROM dashboard_decision_option WHERE id = $1")
            .bind(chosen_option_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if option_decision_ref != Some(decision_id) {
        return Err(AppError::Validation(
            "chosen_option_id does not belong to this decision".into(),
        ));
    }

    let rows_affected = sqlx::query(
        "UPDATE dashboard_decision SET status = 'approved', chosen_option_ref = $3, \
         modified_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2",
    )
    .bind(decision_id)
    .bind(expected_row_version)
    .bind(chosen_option_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows_affected != 1 {
        return Err(AppError::Conflict(
            "decision row_version changed concurrently — reload and retry",
        ));
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok(expected_row_version + 1)
}

#[derive(Deserialize, ToSchema)]
struct ApproveBody {
    chosen_option_id: Uuid,
    row_version: i64,
}

#[derive(Serialize, ToSchema)]
struct ApproveResponse {
    id: Uuid,
    status: String,
    row_version: i64,
}

/// `POST /api/v1/decisions/{id}/approve` — the human picks which option runs.
/// `dashboard_decision.update`: reuses the entity's own generic update privilege
/// for this bespoke business action, same convention `DashboardUpdate`/
/// `MetricUpdate` already use in this crate.
#[utoipa::path(
    post,
    // Disambiguates from `attome_dashboard::lifecycle`'s own `approve` handler
    // (`/api/v1/attome-dashboard/{id}/approve`) — utoipa derives an
    // operationId from the Rust function name by default, and both are
    // literally named `approve`, which produced a duplicate TypeScript
    // declaration in the generated `api-types.ts` (`generate:api` codegen
    // failure, unrelated to either handler's behavior).
    operation_id = "approve_decision",
    path = "/api/v1/decisions/{id}/approve",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = ApproveBody,
    responses(
        (status = 200, description = "Success", body = ApproveResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such decision", body = ErrorResponse),
        (status = 409, description = "Not proposed, or row_version is stale", body = ErrorResponse),
        (status = 422, description = "chosen_option_id does not belong to this decision", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Approved)])))),
)]
async fn approve(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DecisionUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<ApproveResponse>, AppError> {
    require_entity_access(&state, &ctx, "dashboard_decision", id, RecordAction::Update).await?;
    // Not four-eyes (no attome_approval — a single privileged user still
    // approves in one call, deliberately, per this module's own scope), but
    // the audit trail must still say plainly whether the approver is the
    // same person who proposed the decision, so a reviewer can tell a
    // self-approval from a distinct second reviewer without cross-referencing
    // dashboard_decision.created_by by hand.
    let proposed_by: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by FROM dashboard_decision WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let row_version =
        do_approve(&state.base.db, id, body.chosen_option_id, body.row_version).await?;
    let provenance = match proposed_by {
        Some(proposer) if proposer == ctx.user_id => {
            "self-approval — proposer and approver are the same user".to_string()
        }
        Some(proposer) => format!("proposed by {proposer}, approved by {}", ctx.user_id),
        None => "proposer unknown (created_by not recorded on this row)".to_string(),
    };
    write_decision_audit(
        &state,
        id,
        AuditOperation::Approved,
        "decision.approve",
        ctx.user_id,
        Some(body.row_version),
        Some(row_version),
        format!(
            "decision {id} approved, option {} chosen; {provenance}",
            body.chosen_option_id
        ),
    )
    .await;
    Ok(Json(ApproveResponse {
        id,
        status: "approved".to_string(),
        row_version,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/decisions/{id}/approve", post(approve))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(approve))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
