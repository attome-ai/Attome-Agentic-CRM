//! D-421 / M10 (Approval & Governance) — admin CRUD for
//! `approval_policy` (migration `0183_xrm_core_approval_policy.sql`).
//! A policy assigns a `attome_approval::ApprovalPlan` to every future
//! `approval_request` whose `action_type` matches
//! (`attome_audit::approval::find_matching_policy`, consulted by `gate()` and
//! the workflow approval node) — this file only ever manages the policy
//! *row*; the resolution/decision machinery it configures lives in
//! `attome-approval`/`attome-audit` (see those crates' own doc comments).
//!
//! Extends D-195's `attome_approval` primitive; never a second approval
//! framework (D-421) — a policy is inert data until `find_matching_policy`
//! hands its `plan` to `attome_approval::submit_with_plan`.

use attome_approval::{ApprovalPlan, OnTimeout};
use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

const POLICY_COLUMNS: &str = "id, name, is_active, action_type, condition, plan, row_version, \
     created_at, updated_at, created_by";

#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: Uuid,
    name: String,
    is_active: bool,
    action_type: String,
    condition: Option<String>,
    plan: Value,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    created_by: Uuid,
}

#[derive(Serialize, ToSchema)]
struct ApprovalPolicyView {
    id: Uuid,
    name: String,
    is_active: bool,
    action_type: String,
    /// M45 expression string, evaluated per-invocation against the gated
    /// action's payload (`attome_audit::approval::condition_permits`) — see
    /// that function's doc comment for the fail-closed semantics.
    condition: Option<String>,
    plan: ApprovalPlan,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    created_by: Uuid,
}

impl TryFrom<PolicyRow> for ApprovalPolicyView {
    type Error = AppError;

    fn try_from(row: PolicyRow) -> Result<Self, AppError> {
        let plan: ApprovalPlan = serde_json::from_value(row.plan)
            .map_err(|e| AppError::internal(format!("corrupt approval_policy.plan: {e}")))?;
        Ok(Self {
            id: row.id,
            name: row.name,
            is_active: row.is_active,
            action_type: row.action_type,
            condition: row.condition,
            plan,
            row_version: row.row_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        })
    }
}

/// BAP-7 / BAP-D3 — structural validation, token validation, and the
/// *static* half of the threshold check.
///
/// The threshold rule is `ApprovalPlan::validate`'s alone (owner ruling
/// 2026-09-25): an `n_of_m` step whose tokens are *all* `user:` is refused
/// when its threshold exceeds the count of *distinct* named users — that
/// population is known now and can never grow. A step holding any `role:`,
/// `team:` or `position:` token is not refused here, whatever its threshold:
/// one such token expands to many people, and the step's real population is
/// only known at decide time, where `ApprovalStep::required_count` refuses a
/// population below the threshold (fail closed, BAP-7).
fn validate_plan(plan: &ApprovalPlan) -> Result<(), AppError> {
    plan.validate()?;
    attome_audit::approval::validate_plan_approvers(plan)?;
    Ok(())
}

/// BAP-12 / BAP-F7 (BAP-D4): a `PRODUCTION_MANDATORY_ACTIONS` type can never
/// be satisfied by an automatic timeout.
///
/// `on_timeout: auto_approve` decides a step with no human behind it (the
/// grant row's `decided_by` is `POLICY_ACTOR_ID`). For the actions whose
/// execution cannot be undone — erasure, DSR erasure, hard entity delete,
/// retention purge, and the two production change-control actions — the
/// production floor's whole point is that a second *person* looked at it
/// before it ran. A policy that put `auto_approve` on one of them would turn
/// that floor into a timer.
///
/// Checked at save time rather than at timeout time deliberately: the
/// operator finds out while editing the policy, and a policy that could never
/// be satisfied the way they intended never becomes active. `escalate` and
/// `auto_reject` stay allowed on these types — neither approves anything.
fn forbid_auto_approve_for_mandatory(
    action_type: &str,
    plan: &ApprovalPlan,
) -> Result<(), AppError> {
    if !crate::approval_admin::PRODUCTION_MANDATORY_ACTIONS.contains(&action_type) {
        return Ok(());
    }
    let offending = plan
        .steps
        .iter()
        .position(|step| step.on_timeout == OnTimeout::AutoApprove);
    if let Some(i) = offending {
        return Err(AppError::Validation(format!(
            "{action_type} is a production-mandatory action: plan step {i} cannot use `on_timeout: auto_approve`, because a mandatory four-eyes action needs at least one human decision. Use `escalate` or `auto_reject` instead."
        )));
    }
    Ok(())
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListQuery {
    /// Only this action type.
    action_type: Option<String>,
    /// One-based — the first page is `page=1` (D-347).
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List approval policies
///
/// `GET /api/v1/admin/approval-policies` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/approval-policies",
    tag = "admin",
    params(ListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ApprovalPolicyView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_policies(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<PaginatedResponse<ApprovalPolicyView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let rows: Vec<PolicyRow> = sqlx::query_as(&format!(
        "SELECT {POLICY_COLUMNS} FROM approval_policy \
         WHERE NOT is_deleted AND ($1::text IS NULL OR action_type = $1) \
         ORDER BY name ASC OFFSET $2 LIMIT $3"
    ))
    .bind(&q.action_type)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_policy \
         WHERE NOT is_deleted AND ($1::text IS NULL OR action_type = $1)",
    )
    .bind(&q.action_type)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct CreatePolicyBody {
    name: String,
    #[serde(default = "default_true")]
    is_active: bool,
    action_type: String,
    condition: Option<String>,
    plan: ApprovalPlan,
}

fn default_true() -> bool {
    true
}

/// Create an approval policy
///
/// `POST /api/v1/admin/approval-policies` — `system.admin` only. `plan` is
/// validated structurally (`ApprovalPlan::validate`) and by approver-token
/// shape (`attome_audit::approval::validate_plan_approvers`) before insert.
/// Rejected with `409` when an active, non-deleted policy already exists
/// for `action_type` — the partial unique index migration `0183` enforces.
/// One row per `action_type` stays the rule even with `condition` now
/// evaluated: there is still at most one candidate policy to check a
/// payload against, never several to pick among (see
/// `find_matching_policy`'s doc comment).
#[utoipa::path(
    post,
    path = "/api/v1/admin/approval-policies",
    tag = "admin",
    request_body = CreatePolicyBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ApprovalPolicyView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "An active policy for this action_type already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Json(body): Json<CreatePolicyBody>,
) -> Result<(StatusCode, Json<ApprovalPolicyView>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name must not be empty".to_string()));
    }
    let action_type = body.action_type.trim();
    if action_type.is_empty() {
        return Err(AppError::Validation(
            "action_type must not be empty".to_string(),
        ));
    }
    validate_plan(&body.plan)?;
    forbid_auto_approve_for_mandatory(action_type, &body.plan)?;
    let plan_json = serde_json::to_value(&body.plan).map_err(AppError::internal)?;
    let id = Uuid::now_v7();
    // D-541 rule 4: approval policy is governance configuration; the event
    // commits with the change (D-062).
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "approval_policy",
            Some(id),
        )
        .named("approval_policy.create"),
    )
    .await?;

    let row: PolicyRow = sqlx::query_as(&format!(
        "INSERT INTO approval_policy \
             (id, name, is_active, action_type, condition, plan, row_version, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, 0, $7) \
         RETURNING {POLICY_COLUMNS}"
    ))
    .bind(id)
    .bind(name)
    .bind(body.is_active)
    .bind(action_type)
    .bind(body.condition.as_deref().map(str::trim))
    .bind(&plan_json)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if attome_db::is_unique_violation(&e) {
            AppError::Conflict("an active policy for this action_type already exists")
        } else {
            AppError::internal(e)
        }
    })?;
    let view: ApprovalPolicyView = row.try_into()?;
    record_policy_version(&mut tx, id, ctx.user_id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(view)))
}

/// Z10-T5: snapshots the policy's plan and condition as its current version,
/// in the policy write's own transaction. Requests keep the plan they were
/// submitted with; this is the history of what the policy said.
async fn record_policy_version(
    tx: &mut SecurityTx<'_>,
    id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO approval_policy_version (policy_id, version, plan, condition, created_by) \
         SELECT id, current_version, plan, condition, $2 FROM approval_policy WHERE id = $1 \
         ON CONFLICT (policy_id, version) DO NOTHING",
    )
    .bind(id)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// One approval policy
///
/// `GET /api/v1/admin/approval-policies/{id}` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/approval-policies/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The approval policy")),
    responses(
        (status = 200, description = "Success", body = ApprovalPolicyView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Policy not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_policy(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalPolicyView>, AppError> {
    let row: PolicyRow = sqlx::query_as(&format!(
        "SELECT {POLICY_COLUMNS} FROM approval_policy WHERE id = $1 AND NOT is_deleted"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row.try_into()?))
}

#[derive(Deserialize, ToSchema)]
struct UpdatePolicyBody {
    name: Option<String>,
    is_active: Option<bool>,
    condition: Option<String>,
    plan: Option<ApprovalPlan>,
    row_version: i64,
}

/// Replace an approval policy
///
/// `PUT /api/v1/admin/approval-policies/{id}` — `system.admin` only.
/// `action_type` is immutable after creation (delete and recreate to
/// retarget a policy) — every field that changes what a policy *governs*
/// staying fixed once requests may already reference `policy_id` keeps
/// those requests' provenance meaningful.
#[utoipa::path(
    put,
    path = "/api/v1/admin/approval-policies/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The approval policy")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    request_body = UpdatePolicyBody,
    responses(
        (status = 200, description = "Success", body = ApprovalPolicyView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Policy not found", body = ErrorResponse),
        (status = 409, description = "row_version is stale", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePolicyBody>,
) -> Result<Json<ApprovalPolicyView>, AppError> {
    if let Some(name) = &body.name
        && name.trim().is_empty()
    {
        return Err(AppError::Validation("name must not be empty".to_string()));
    }
    let plan_json = match &body.plan {
        Some(plan) => {
            validate_plan(plan)?;
            // BAP-12: the action_type is immutable on a policy, so a plan
            // update must be checked against the row's own action_type — not
            // merely against whatever the request body happens to carry.
            // Read only when a plan is actually being replaced.
            let (action_type,): (String,) = sqlx::query_as(
                "SELECT action_type FROM approval_policy WHERE id = $1 AND NOT is_deleted",
            )
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
            forbid_auto_approve_for_mandatory(&action_type, plan)?;
            Some(serde_json::to_value(plan).map_err(AppError::internal)?)
        }
        None => None,
    };
    // D-541 rule 4: approval policy is governance configuration; the event
    // commits with the change (D-062).
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "approval_policy",
            Some(id),
        )
        .named("approval_policy.update"),
    )
    .await?;

    let row: Option<PolicyRow> = sqlx::query_as(&format!(
        "UPDATE approval_policy \
         SET name = COALESCE($3, name), \
             is_active = COALESCE($4, is_active), \
             condition = CASE WHEN $5 THEN $6 ELSE condition END, \
             plan = COALESCE($7, plan), \
             current_version = current_version \
                 + CASE WHEN $5 OR $7::jsonb IS NOT NULL THEN 1 ELSE 0 END, \
             row_version = row_version + 1, \
             updated_at = NOW() \
         WHERE id = $1 AND row_version = $2 AND NOT is_deleted \
         RETURNING {POLICY_COLUMNS}"
    ))
    .bind(id)
    .bind(body.row_version)
    .bind(body.name.as_deref().map(str::trim))
    .bind(body.is_active)
    .bind(body.condition.is_some())
    .bind(body.condition.as_deref().map(str::trim))
    .bind(&plan_json)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let row = match row {
        Some(row) => row,
        None => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM approval_policy WHERE id = $1 AND NOT is_deleted)",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            return Err(if exists {
                AppError::VersionConflict
            } else {
                AppError::NotFound
            });
        }
    };
    let view: ApprovalPolicyView = row.try_into()?;
    // Z10-T5: a changed plan or condition is a new version.
    if body.condition.is_some() || body.plan.is_some() {
        record_policy_version(&mut tx, id, ctx.user_id).await?;
    }
    tx.commit().await?;
    Ok(Json(view))
}

/// Delete an approval policy
///
/// `DELETE /api/v1/admin/approval-policies/{id}` — `system.admin` only.
/// Soft-deletes the policy; already-submitted requests it supplied a plan
/// for are unaffected (their `plan` was copied onto the request at submit
/// time, not referenced live).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/approval-policies/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The approval policy")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Policy not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // D-541 rule 4: approval policy is governance configuration; the event
    // commits with the change (D-062).
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "approval_policy",
            Some(id),
        )
        .named("approval_policy.delete"),
    )
    .await?;
    let result = sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, row_version = row_version + 1, \
             updated_at = NOW() \
         WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/approval-policies",
            get(list_policies).post(create_policy),
        )
        .route(
            "/api/v1/admin/approval-policies/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document (see `approval_admin.rs`'s identical fragment comment).
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_policies, create_policy, get_policy, update_policy, delete_policy))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
