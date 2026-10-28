//! P-retention-archive-completion §3a/§3e — the propose -> approve -> execute
//! admin surface for partition archive/drop (§3b) and entity-record purge
//! (§3c). A dedicated route (guidelines §9: this isn't CRUD on a registered
//! entity), gated on `system.admin` the same way `s2s_admin`/`erasure_admin`/
//! `rewrap_admin`/`jobs_admin` are. Modeled on F024's staged-import
//! `pending_review -> approving -> approved | rejected` shape
//! (`automation_staged_import`) rather than invented from scratch.
//!
//! Propose (writing `audit_retention_action` rows) always happens on the daily
//! `EngineJob::ProposeRetentionActions` schedule, or on demand via
//! `POST .../retention/propose` here — never automatically approved or
//! executed. `POST .../actions/{id}/approve` is the only path that enqueues
//! `EngineJob::ExecuteRetentionAction`; execution itself is refused by the
//! job handler if `retention.dry_run` is still true or `retention.legal_hold`
//! is set, even for an already-approved row (config can change between
//! approve and execute — see `attome_api::retention::execute_action`).

use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct RetentionActionQuery {
    /// `"proposed" | "approved" | "executing" | "completed" | "failed" | "rejected"`.
    status: Option<String>,
    /// `"partition_archive" | "entity_purge"`.
    action_type: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct RetentionActionSummary {
    id: Uuid,
    action_type: String,
    target: String,
    status: String,
    proposed_at: DateTime<Utc>,
    approved_by: Option<Uuid>,
    approved_at: Option<DateTime<Utc>>,
    executed_at: Option<DateTime<Utc>>,
    failure_reason: Option<String>,
    evidence_ref: Option<String>,
}

/// List retention actions
///
/// The archive and delete actions the retention sweep proposed, optionally by status and type.
/// Compliance administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/retention/actions",
    tag = "admin",
    params(RetentionActionQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RetentionActionSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_actions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Query(query): Query<RetentionActionQuery>,
) -> Result<Json<PaginatedResponse<RetentionActionSummary>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let items: Vec<RetentionActionSummary> = sqlx::query_as(
        "SELECT id, action_type, target, status, proposed_at, approved_by, approved_at, \
                executed_at, failure_reason, evidence_ref \
           FROM audit_retention_action \
          WHERE is_deleted = false \
            AND ($1::text IS NULL OR status = $1) \
            AND ($2::text IS NULL OR action_type = $2) \
          ORDER BY proposed_at DESC \
          LIMIT $3 OFFSET $4",
    )
    .bind(&query.status)
    .bind(&query.action_type)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_action \
          WHERE is_deleted = false \
            AND ($1::text IS NULL OR status = $1) \
            AND ($2::text IS NULL OR action_type = $2)",
    )
    .bind(&query.status)
    .bind(&query.action_type)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Serialize, ToSchema)]
pub struct ActionTransitionResult {
    id: Uuid,
    status: String,
    enqueued: bool,
    /// D-195 — `true` when `approval.required_actions` names
    /// `ACTION_RETENTION_APPROVE`: this call only submitted a four-eyes
    /// approval request, it did not itself transition the action to
    /// `approved` or enqueue execution. Always `false` for `reject_action`'s
    /// response — rejection is never gated (see that handler's doc comment).
    approval_pending: bool,
    approval_request_id: Option<Uuid>,
}

impl std::fmt::Debug for ActionTransitionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionTransitionResult")
            .finish_non_exhaustive()
    }
}

/// D-195 / `document/detailed-plans/P-four-eyes-approval.md` §5 step 9 — the
/// `action_type` string for approving a proposed archive/drop/purge action.
/// Namespaced `"retention.*"` by the same convention as the other wired
/// action_types; `attome_approval` treats it as an opaque string.
pub const ACTION_RETENTION_APPROVE: &str = "retention.approve_action";

/// The real state transition, factored out so `approve_action` (the direct,
/// un-gated path) and `attome-api::approval_admin::execute_approved` (the
/// approved-and-executed path) call the exact same code — one execution path
/// per action. `approver_id` is recorded as `audit_retention_action.
/// approved_by`: under four-eyes gating this is the *deciding* admin (the
/// second, distinct identity that actually authorized the transition), not
/// the admin who originally submitted the request — matching what the
/// column means in the ungated case (the one admin who called this endpoint).
///
/// The `legal_hold`/`dry_run` safety checks live here, not only in the
/// handler below, so a gated call (whose config could differ between submit
/// and decide) is checked at the moment the transition actually happens,
/// exactly like the direct path always was — this is a genuine safety
/// invariant, not merely input validation, so it cannot live in the
/// gate-bypassing fast path alone.
pub async fn do_approve_retention_action(
    state: &EngineState,
    id: Uuid,
    approver_id: Uuid,
) -> Result<ActionTransitionResult, AppError> {
    if state.base.config.retention.legal_hold {
        return Err(AppError::Conflict(
            "retention.legal_hold is set — no archive/drop/purge action may be approved while a deployment-wide legal hold is active",
        ));
    }
    if state.base.config.retention.dry_run {
        return Err(AppError::Conflict(
            "retention.dry_run is still true — flip it to false before approving any retention action",
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-compliance/retention:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another request against this retention action is already in progress",
        ));
    }

    let result = sqlx::query(
        "UPDATE audit_retention_action \
            SET status = 'approved', approved_by = $2, approved_at = NOW(), \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'proposed' AND is_deleted = false",
    )
    .bind(id)
    .bind(approver_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "retention action was not found, already actioned, or rejected",
        ));
    }

    // PLATFORM-REVIEW-2026-08-24 §3.12: the execute job is enqueued in the
    // SAME transaction as the `proposed -> approved` transition, so both
    // become visible at one commit — never an `approved` row with no job
    // (a crash between two separate writes), and never a job for a row the
    // approval never landed on. The dedup key keeps a retried approve from
    // double-queueing the same action (`apalis.push_job_dedup`, D-165).
    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        EngineJob::ExecuteRetentionAction { action_id: id },
        &format!("retention-execute:{id}"),
    )
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Approved,
            approver_id,
            "audit_retention_action",
            Some(id),
        )
        .named("retention_action.approve"),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(ActionTransitionResult {
        id,
        status: "approved".to_string(),
        enqueued: true,
        approval_pending: false,
        approval_request_id: None,
    })
}

/// Approve a retention action
///
/// Approves a proposed archive or delete, which then runs unless a legal hold stops it. When
/// `approval.required_actions` gates it, a second administrator decides (202, `approval_pending`).
/// Compliance administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/retention/actions/{id}/approve",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The retention action")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Approved)])))),
    responses(
        (status = 201, description = "Success", body = ActionTransitionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn approve_action(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<ActionTransitionResult>), AppError> {
    let payload = serde_json::json!({ "action_id": id });
    if let Some(request) =
        attome_audit::approval::gate(&state, ACTION_RETENTION_APPROVE, payload, ctx.user_id).await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(ActionTransitionResult {
                id,
                status: "proposed".to_string(),
                enqueued: false,
                approval_pending: true,
                approval_request_id: Some(request.id),
            }),
        ));
    }

    let result = do_approve_retention_action(&state, id, ctx.user_id).await?;
    Ok((StatusCode::OK, Json(result)))
}

/// Reject a retention action
///
/// The target can be proposed again by the next sweep; refused while a legal hold is set. Compliance
/// administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/retention/actions/{id}/reject",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The retention action")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Rejected)])))),
    responses(
        (status = 200, description = "Success", body = ActionTransitionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn reject_action(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionTransitionResult>, AppError> {
    if state.base.config.retention.legal_hold {
        return Err(AppError::Conflict(
            "retention.legal_hold is set — no retention action's status may change while a deployment-wide legal hold is active",
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE audit_retention_action \
            SET status = 'rejected', updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND status IN ('proposed', 'failed') AND is_deleted = false",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "retention action was not found, or is not in a proposed/failed state",
        ));
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Rejected,
            ctx.user_id,
            "audit_retention_action",
            Some(id),
        )
        .named("retention_action.reject"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(ActionTransitionResult {
        id,
        status: "rejected".to_string(),
        enqueued: false,
        approval_pending: false,
        approval_request_id: None,
    }))
}

#[derive(Serialize, ToSchema)]
struct ProposeTriggered {
    enqueued: bool,
}

/// Propose retention actions now
///
/// Queues the daily retention sweep early; asking again before it runs queues nothing more.
/// Compliance administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/retention/propose",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
    responses(
        (status = 201, description = "Success", body = ProposeTriggered),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn trigger_propose(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
) -> Result<(StatusCode, Json<ProposeTriggered>), AppError> {
    // Deliberately NOT `enqueue_in_tx_dedup` (PLATFORM-REVIEW-2026-08-24
    // §3.12 reviewed this site): this handler writes no state of its own —
    // the enqueue is the only write — so there is nothing for the job row
    // to be atomic with. The sweep job reads whatever is committed when it
    // runs, and the propose step is idempotent (migration 0067's partial
    // unique index) either way.
    attome_jobs::enqueue_dedup(
        &state.base.db,
        EngineJob::ProposeRetentionActions,
        "retention-propose-manual",
    )
    .await
    .map_err(AppError::internal)?;

    // Phase 3.7 coverage: this is a `BusinessEvent`, not the mandatory-writer
    // path, and deliberately not atomic with the enqueue above (same
    // rationale as that enqueue's own comment: there is no state here to be
    // atomic with). It only proves an admin triggered the sweep on demand —
    // `propose_retention_actions` itself (the daily job, and this route's
    // target) writes no per-proposal event yet; that is C15/Phase 9 scope,
    // not this coverage pass.
    attome_audit::write_business_event(
        &state,
        "audit_retention_action",
        Uuid::nil(),
        attome_audit::AuditOperation::Execute,
        "retention_action.propose_triggered",
        ctx.user_id,
        None,
        None,
        "on-demand retention-proposal sweep triggered".to_string(),
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(ProposeTriggered { enqueued: true }),
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/retention/actions", get(list_actions))
        .route(
            "/api/v1/admin/retention/actions/{id}/approve",
            post(approve_action),
        )
        .route(
            "/api/v1/admin/retention/actions/{id}/reject",
            post(reject_action),
        )
        .route("/api/v1/admin/retention/propose", post(trigger_propose))
        .merge(crate::retention_rules::routes())
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_actions, approve_action, reject_action, trigger_propose))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(crate::retention_rules::openapi_fragment());
    doc
}
