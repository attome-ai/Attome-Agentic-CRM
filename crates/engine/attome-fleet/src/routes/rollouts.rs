//! F4 — publish routes (design §6.4): start a rollout (one set of changesets
//! to many customers, waves by ring), apply a planned target with its
//! `backup_ref`, skip a target, halt / resume / cancel the rollout, and
//! re-arm its steps. The work itself runs in `EngineJob::FleetRolloutStep`
//! jobs ([`crate::publish`]); the console never approves anything — a target
//! in `approval_pending` waits for a human on the customer server, and its
//! view links to the customer's approval page.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{AuditOperation, AuditOutcome};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};

use super::{HumanSession, require_step_up, version_conflict_if_none};
use crate::changesets::{self, ChangesetRef};
use crate::client::{RemoteError, paths};
use crate::core::{RolloutStatus, WaveState};
use crate::error::{ConsoleError, ConsoleResult};
use crate::publish::{
    self, ACTIVE_ROLLOUT_LOCK, PlanSummary, ReleasePlan, TargetStatus, ids_for_phase, read_plan,
    read_refs, read_summary, rollout_status_str,
};
use crate::runtime::FleetState;
use crate::store::{self, ActionWrite, DeploymentRow, RolloutRow, TargetRow, TargetUpdate};

const ROLLOUT_ENTITY: &str = "fleet_rollout";
const TARGET_ENTITY: &str = "fleet_target";
const MAX_CHANGESETS: usize = 200;
const MAX_TARGETS: usize = 100;
const MAX_TITLE: usize = 200;
const MAX_BACKUP_REF: usize = 500;

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct WaveView {
    pub name: String,
    /// `pending`, `in_progress`, `healthy` or `unhealthy`.
    pub state: String,
    pub deployment_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RolloutView {
    pub id: Uuid,
    pub title: String,
    /// `planned`, `in_progress`, `completed`, `halted` or `cancelled`.
    pub status: String,
    pub changesets: Vec<ChangesetRef>,
    pub waves: Vec<WaveView>,
    /// Index of the current wave.
    pub cursor: usize,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TargetView {
    pub id: Uuid,
    pub rollout_id: Uuid,
    pub deployment_id: Uuid,
    pub deployment_label: String,
    pub project_code: String,
    pub environment: String,
    /// Shown before Apply; a warning, not a block (design §6.4).
    pub maintenance_window: Option<String>,
    pub wave: i32,
    /// `pending`, `planned`, `approval_pending`, `applying`, `applied`,
    /// `failed` or `skipped`.
    pub status: String,
    pub plan_summary: Option<PlanSummary>,
    pub backup_ref: Option<String>,
    pub remote_apply_ids: Vec<Uuid>,
    pub remote_approval_id: Option<Uuid>,
    /// The customer's approval page while `approval_pending`: a human
    /// approves there (owner answer Topic 17 Q1); the console never does.
    pub approval_url: Option<String>,
    pub error_code: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RolloutDetail {
    pub rollout: RolloutView,
    pub targets: Vec<TargetView>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StartRolloutBody {
    pub title: String,
    /// Changeset ids from `GET /api/v1/fleet/changesets`; each must verify.
    pub changeset_ids: Vec<Uuid>,
    /// Active deployments with a stored credential; waves follow their rings.
    pub deployment_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApplyTargetBody {
    pub row_version: i64,
    /// The verified backup taken before this apply; required for a `prod`
    /// deployment (422 `backup_ref_required`), as the customer requires it
    /// on its production profile.
    #[serde(default)]
    pub backup_ref: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RowVersionBody {
    pub row_version: i64,
}

/// `POST …/refresh` (202).
#[derive(Debug, Serialize, ToSchema)]
pub struct StepsQueued {
    pub queued: usize,
}

fn wave_state(state: WaveState) -> &'static str {
    match state {
        WaveState::Pending => "pending",
        WaveState::InProgress => "in_progress",
        WaveState::Healthy => "healthy",
        WaveState::Unhealthy => "unhealthy",
    }
}

fn rollout_view(row: &RolloutRow) -> Result<RolloutView, AppError> {
    let plan = read_plan(row)?;
    Ok(RolloutView {
        id: row.id,
        title: row.title.clone(),
        status: row.status.clone(),
        changesets: read_refs(row)?,
        waves: plan
            .waves
            .iter()
            .map(|w| WaveView {
                name: w.name.clone(),
                state: wave_state(w.state).to_owned(),
                deployment_ids: w.deployments.iter().map(|d| d.0).collect(),
            })
            .collect(),
        cursor: plan.cursor,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        row_version: row.row_version,
    })
}

fn target_view(target: &TargetRow, deployment: Option<&DeploymentRow>) -> TargetView {
    let status = target.status.clone();
    let approval_url = match (deployment, target.remote_approval_id) {
        (Some(d), Some(_)) if status == TargetStatus::ApprovalPending.as_str() => {
            Some(format!("{}/xrm/admin/approvals", d.base_url))
        }
        _ => None,
    };
    TargetView {
        id: target.id,
        rollout_id: target.rollout_ref,
        deployment_id: target.deployment_ref,
        deployment_label: deployment.map(|d| d.label.clone()).unwrap_or_default(),
        project_code: deployment
            .map(|d| d.project_code.clone())
            .unwrap_or_default(),
        environment: deployment
            .map(|d| d.environment.clone())
            .unwrap_or_default(),
        maintenance_window: deployment.and_then(|d| d.maintenance_window.clone()),
        wave: target.wave,
        status,
        plan_summary: target
            .plan_summary
            .clone()
            .and_then(|v| serde_json::from_value(v).ok()),
        backup_ref: target.backup_ref.clone(),
        remote_apply_ids: target.remote_apply_ids.clone().unwrap_or_default(),
        remote_approval_id: target.remote_approval_id,
        approval_url,
        error_code: target.error_code.clone(),
        updated_at: target.updated_at,
        row_version: target.row_version,
    }
}

async fn detail(state: &FleetState, rollout_id: Uuid) -> Result<RolloutDetail, AppError> {
    let rollout = store::get_rollout(&state.xrm.base.db, rollout_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let targets = store::targets_of(&state.xrm.base.db, rollout_id).await?;
    let ids: Vec<Uuid> = targets.iter().map(|t| t.deployment_ref).collect();
    let deployments = store::deployments_by_ids(&state.xrm.base.db, &ids).await?;
    Ok(RolloutDetail {
        rollout: rollout_view(&rollout)?,
        targets: targets
            .iter()
            .map(|t| target_view(t, deployments.iter().find(|d| d.id == t.deployment_ref)))
            .collect(),
    })
}

async fn load_pair(
    state: &FleetState,
    rollout_id: Uuid,
    target_id: Uuid,
) -> Result<(RolloutRow, TargetRow), AppError> {
    let rollout = store::get_rollout(&state.xrm.base.db, rollout_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let target = store::get_target(&state.xrm.base.db, target_id)
        .await?
        .filter(|t| t.rollout_ref == rollout_id)
        .ok_or(AppError::NotFound)?;
    Ok((rollout, target))
}

fn local_action(
    actor: Uuid,
    rollout: Uuid,
    deployment: Option<Uuid>,
    action: &'static str,
    detail: Value,
) -> ActionWrite {
    ActionWrite {
        id: Uuid::now_v7(),
        actor_ref: actor,
        deployment_ref: deployment,
        rollout_ref: Some(rollout),
        action,
        remote_method: None,
        remote_path: None,
        remote_status: None,
        outcome: "ok",
        detail,
    }
}

fn rollout_event(actor: Uuid, operation: AuditOperation, id: Uuid, name: &str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        ROLLOUT_ENTITY,
        Some(id),
    )
    .named(name.to_owned())
}

/// Validates a start request against the changeset files and the registry.
pub fn check_start(
    body: &StartRolloutBody,
    files: &[changesets::ChangesetFile],
    deployments: &[DeploymentRow],
) -> Result<Vec<ChangesetRef>, AppError> {
    let title = body.title.trim();
    if title.is_empty() || title.chars().count() > MAX_TITLE {
        return Err(AppError::Validation(format!(
            "title: required, at most {MAX_TITLE} characters"
        )));
    }
    if body.changeset_ids.is_empty() || body.changeset_ids.len() > MAX_CHANGESETS {
        return Err(AppError::Validation(format!(
            "changeset_ids: between 1 and {MAX_CHANGESETS}"
        )));
    }
    if body.deployment_ids.is_empty() || body.deployment_ids.len() > MAX_TARGETS {
        return Err(AppError::Validation(format!(
            "deployment_ids: between 1 and {MAX_TARGETS}"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    if !body.changeset_ids.iter().all(|id| seen.insert(*id))
        || !body.deployment_ids.iter().all(|id| seen.insert(*id))
    {
        return Err(AppError::Validation("an id appears twice".into()));
    }
    let mut refs = Vec::with_capacity(body.changeset_ids.len());
    for id in &body.changeset_ids {
        let file = files.iter().find(|f| f.id == *id).ok_or_else(|| {
            AppError::Validation(format!(
                "changeset_ids: {id} is not under fleet.changesets_dir"
            ))
        })?;
        if !file.checksum_ok {
            return Err(AppError::Validation(format!(
                "changeset_checksum_invalid: {} ({}) does not match its own checksum",
                file.id, file.path
            )));
        }
        refs.push(ChangesetRef::from(file));
    }
    for id in &body.deployment_ids {
        let deployment = deployments.iter().find(|d| d.id == *id).ok_or_else(|| {
            AppError::Validation(format!("deployment_ids: {id} is not registered"))
        })?;
        if !deployment.is_active || !deployment.has_credential() {
            return Err(AppError::Validation(format!(
                "deployment_ids: {} ({}) is inactive or has no rollout credential",
                deployment.label, deployment.project_code
            )));
        }
    }
    Ok(refs)
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/fleet/rollouts",
    tag = "fleet",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Rollouts, newest first", body = PaginatedResponse<RolloutView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn list_rollouts(
    State(state): State<FleetState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
    _session: HumanSession,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<PaginatedResponse<RolloutView>>> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let (rows, total) = store::list_rollouts(&state.xrm.base.db, page_size, offset).await?;
    let items = rows
        .iter()
        .map(rollout_view)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts",
    tag = "fleet",
    request_body = StartRolloutBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Started: the first wave's targets are being planned on each customer", body = RolloutDetail),
        (status = 401, description = "Missing credentials, or `reauth_required` without a fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 409, description = "fleet_rollout_active: another rollout is planned or in progress", body = ErrorResponse),
        (status = 422, description = "An unknown or unverifiable changeset, an unknown, inactive or credential-less deployment, or a bad title", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn start_rollout(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    session: HumanSession,
    Json(body): Json<StartRolloutBody>,
) -> ConsoleResult<(StatusCode, Json<RolloutDetail>)> {
    require_step_up(&state, session, ctx.user_id).await?;
    let files = changesets::list(state.runtime.changesets_dir.clone()).await?;
    let deployments = store::deployments_by_ids(&state.xrm.base.db, &body.deployment_ids).await?;
    let refs = check_start(&body, &files, &deployments)?;
    let plan: ReleasePlan = publish::plan_rollout(body.changeset_ids.clone(), &deployments)
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let plan_value = serde_json::to_value(&plan).map_err(AppError::internal)?;
    let refs_value = serde_json::to_value(&refs).map_err(AppError::internal)?;
    let id = Uuid::now_v7();
    let action = local_action(
        ctx.user_id,
        id,
        None,
        "rollout_start",
        json!({ "changesets": refs.len(), "targets": deployments.len(), "waves": plan.waves.len() }),
    );

    let mut stx = SecurityTx::begin(
        &state.xrm,
        rollout_event(
            ctx.user_id,
            AuditOperation::Create,
            id,
            "fleet.rollout.start",
        ),
    )
    .await?;
    if !crate::try_lock(&mut stx, ACTIVE_ROLLOUT_LOCK).await?
        || store::count_active_rollouts(&mut stx).await? > 0
    {
        return Err(AppError::Conflict(
            "fleet_rollout_active: another rollout is planned or in progress; finish, halt and \
             cancel, or wait for it",
        )
        .into());
    }
    store::insert_rollout(
        &mut stx,
        id,
        body.title.trim(),
        &refs_value,
        &plan_value,
        rollout_status_str(plan.status),
        ctx.user_id,
    )
    .await?;
    for deployment in &deployments {
        let wave = publish::wave_of(&plan, deployment.id).unwrap_or(0);
        let target = store::insert_target(
            &mut stx,
            id,
            deployment.id,
            i32::try_from(wave).unwrap_or(i32::MAX),
            TargetStatus::Pending.as_str(),
        )
        .await?;
        if wave == plan.cursor {
            publish::enqueue_step_in_tx(stx.tx(), target.id).await?;
        }
    }
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok((StatusCode::CREATED, Json(detail(&state, id).await?)))
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/rollouts/{id}",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Rollout id")),
    responses(
        (status = 200, description = "The rollout, its waves and every target", body = RolloutDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn get_rollout(
    State(state): State<FleetState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
) -> ConsoleResult<Json<RolloutDetail>> {
    Ok(Json(detail(&state, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts/{id}/targets/{target_id}/apply",
    tag = "fleet",
    params(
        ("id" = Uuid, Path, description = "Rollout id"),
        ("target_id" = Uuid, Path, description = "Target id")
    ),
    request_body = ApplyTargetBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Sent: approval_pending (a human approves on the customer server) or applying", body = TargetView),
        (status = 401, description = "Missing credentials, or `reauth_required` without a fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout or target", body = ErrorResponse),
        (status = 409, description = "version_conflict, or the rollout is not running, or the target is not planned in the current wave", body = ErrorResponse),
        (status = 422, description = "backup_ref_required for a prod deployment, or a bad backup_ref", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error: the customer refused or failed the apply (the target stays planned)", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn apply_target(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    session: HumanSession,
    Path((id, target_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ApplyTargetBody>,
) -> ConsoleResult<Json<TargetView>> {
    require_step_up(&state, session, ctx.user_id).await?;
    let (rollout, target) = load_pair(&state, id, target_id).await?;
    if rollout.status != "in_progress" {
        return Err(AppError::Conflict(
            "fleet_rollout_not_running: the rollout is not in progress",
        )
        .into());
    }
    let plan = read_plan(&rollout)?;
    if usize::try_from(target.wave).ok() != Some(plan.cursor)
        || TargetStatus::parse(&target.status) != Some(TargetStatus::Planned)
    {
        return Err(AppError::Conflict(
            "fleet_target_not_planned: only a planned target of the current wave can be applied",
        )
        .into());
    }
    if target.row_version != body.row_version {
        return Err(AppError::VersionConflict.into());
    }
    let deployment = store::get_deployment(&state.xrm.base.db, target.deployment_ref)
        .await?
        .ok_or(AppError::NotFound)?;
    let summary = read_summary(&target);
    let apply_ids = ids_for_phase(&summary).to_vec();
    if apply_ids.is_empty() {
        return Err(
            AppError::Conflict("fleet_target_nothing_to_apply: the plan has no rows").into(),
        );
    }
    let backup_ref = body
        .backup_ref
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_owned);
    if backup_ref
        .as_ref()
        .is_some_and(|r| r.chars().count() > MAX_BACKUP_REF)
    {
        return Err(AppError::Validation(format!(
            "backup_ref: at most {MAX_BACKUP_REF} characters"
        ))
        .into());
    }
    if backup_ref.is_none() && deployment.environment == "prod" {
        return Err(AppError::Validation(
            "backup_ref_required: a prod deployment needs the verified backup taken before \
             this apply"
                .into(),
        )
        .into());
    }

    let client = state
        .runtime
        .customer(&state.xrm.base.db, &deployment)
        .await?;
    // Claim the target before calling out, so two concurrent applies cannot
    // both reach the customer: the loser's row_version no longer matches.
    // A refused call puts it back to `planned` below.
    let mut claim = TargetUpdate::from_row(&target);
    claim.status = TargetStatus::Applying.as_str().to_owned();
    claim.error_code = None;
    let mut claim_tx = attome_db::tx::begin(&state.xrm.base.db).await?;
    let claimed = version_conflict_if_none(
        store::update_target(&mut claim_tx, target.id, target.row_version, &claim).await?,
    )?;
    attome_db::tx::commit(claim_tx).await?;

    let action_id = Uuid::now_v7();
    let result = client
        .post(
            paths::APPLY,
            &json!({ "apply_ids": apply_ids, "phase": summary.phase, "backup_ref": backup_ref }),
            None,
            Some(action_id),
        )
        .await;

    let mut update = TargetUpdate::from_row(&target);
    let mut event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        TARGET_ENTITY,
        Some(target.id),
    )
    .named("fleet.rollout.apply")
    .comment(format!(
        "customer {} ({}), phase {}",
        deployment.project_code, deployment.environment, summary.phase
    ));
    let (remote_status, outcome) = match &result {
        Ok(response) => {
            let pending = response.body["approval_pending"].as_bool().unwrap_or(false);
            update.status = if pending {
                TargetStatus::ApprovalPending
            } else {
                TargetStatus::Applying
            }
            .as_str()
            .to_owned();
            update.remote_apply_ids = Some(apply_ids.clone());
            update.remote_approval_id = response.body["approval_request_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok());
            update.backup_ref = backup_ref.clone();
            update.error_code = None;
            (Some(response.status), "ok")
        }
        Err(e) => {
            update.error_code = Some(e.code().to_owned());
            event = event.outcome(AuditOutcome::Failed);
            match e {
                RemoteError::AuthRefused { status } => (Some(*status), "refused"),
                other => (other.status(), "failed"),
            }
        }
    };
    let action = ActionWrite {
        id: action_id,
        actor_ref: ctx.user_id,
        deployment_ref: Some(deployment.id),
        rollout_ref: Some(rollout.id),
        action: "apply",
        remote_method: Some("POST"),
        remote_path: Some(paths::APPLY.to_owned()),
        remote_status,
        outcome,
        detail: json!({ "apply_ids": apply_ids.len(), "phase": summary.phase, "backup_ref": backup_ref.is_some() }),
    };

    let mut stx = SecurityTx::begin(&state.xrm, event).await?;
    let written = version_conflict_if_none(
        store::update_target(&mut stx, target.id, claimed.row_version, &update).await?,
    )?;
    store::insert_action(&mut stx, &action).await?;
    if result.is_ok() {
        publish::enqueue_step_in_tx(stx.tx(), target.id).await?;
    }
    stx.commit().await?;
    if let Err(e) = result {
        return Err(ConsoleError::Remote(e));
    }
    Ok(Json(target_view(&written, Some(&deployment))))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts/{id}/targets/{target_id}/skip",
    tag = "fleet",
    params(
        ("id" = Uuid, Path, description = "Rollout id"),
        ("target_id" = Uuid, Path, description = "Target id")
    ),
    request_body = RowVersionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Skipped: this customer is left out of the rollout; its wave can complete", body = TargetView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout or target", body = ErrorResponse),
        (status = 409, description = "version_conflict, or the target is applying or applied", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn skip_target(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    _session: HumanSession,
    Path((id, target_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RowVersionBody>,
) -> ConsoleResult<Json<TargetView>> {
    let (rollout, target) = load_pair(&state, id, target_id).await?;
    if !matches!(
        TargetStatus::parse(&target.status),
        Some(TargetStatus::Pending | TargetStatus::Planned | TargetStatus::Failed)
    ) {
        return Err(AppError::Conflict(
            "fleet_target_not_skippable: an applying or applied target cannot be skipped",
        )
        .into());
    }
    let mut update = TargetUpdate::from_row(&target);
    update.status = TargetStatus::Skipped.as_str().to_owned();
    let action = local_action(
        ctx.user_id,
        rollout.id,
        Some(target.deployment_ref),
        "skip",
        json!({ "from": target.status }),
    );
    let mut stx = SecurityTx::begin(
        &state.xrm,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            TARGET_ENTITY,
            Some(target.id),
        )
        .named("fleet.rollout.skip"),
    )
    .await?;
    let written = version_conflict_if_none(
        store::update_target(&mut stx, target.id, body.row_version, &update).await?,
    )?;
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    publish::evaluate(&state.xrm, rollout.id).await?;
    let deployment = store::get_deployment(&state.xrm.base.db, target.deployment_ref).await?;
    Ok(Json(target_view(&written, deployment.as_ref())))
}

/// Halt, resume and cancel: one rollout-level transition each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Halt,
    Resume,
    Cancel,
}

/// Applies a transition to a plan and its stored status; `Err` is a 409.
pub fn transition(
    plan: &mut ReleasePlan,
    stored_status: &str,
    which: Transition,
) -> Result<&'static str, &'static str> {
    match which {
        Transition::Halt => {
            if stored_status != "in_progress" {
                return Err("fleet_rollout_not_running: only an in-progress rollout can be halted");
            }
            plan.halt();
            Ok(rollout_status_str(plan.status))
        }
        Transition::Resume => {
            if stored_status != "halted" {
                return Err("fleet_rollout_not_halted: only a halted rollout can be resumed");
            }
            plan.resume()
                .and_then(|()| plan.start_current_wave())
                .map_err(|_| "fleet_rollout_not_resumable: the plan cannot resume")?;
            Ok(rollout_status_str(plan.status))
        }
        Transition::Cancel => {
            if !matches!(stored_status, "planned" | "in_progress" | "halted") {
                return Err(
                    "fleet_rollout_finished: a completed or cancelled rollout stays as it is",
                );
            }
            if plan.status != RolloutStatus::Halted {
                plan.halt();
            }
            Ok("cancelled")
        }
    }
}

async fn change_rollout(
    state: &FleetState,
    user_id: Uuid,
    id: Uuid,
    row_version: i64,
    which: Transition,
) -> ConsoleResult<Json<RolloutDetail>> {
    let (operation, name, action_name) = match which {
        Transition::Halt => (AuditOperation::Update, "fleet.rollout.halt", "rollout_halt"),
        Transition::Resume => (
            AuditOperation::Update,
            "fleet.rollout.resume",
            "rollout_resume",
        ),
        Transition::Cancel => (
            AuditOperation::Cancelled,
            "fleet.rollout.cancel",
            "rollout_cancel",
        ),
    };
    let mut stx =
        SecurityTx::begin(&state.xrm, rollout_event(user_id, operation, id, name)).await?;
    let rollout = store::get_rollout_for_update(&mut stx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if rollout.row_version != row_version {
        return Err(AppError::VersionConflict.into());
    }
    if which == Transition::Resume
        && (!crate::try_lock(&mut stx, ACTIVE_ROLLOUT_LOCK).await?
            || store::count_active_rollouts(&mut stx).await? > 0)
    {
        // One active rollout at a time (design §6.4): a halted one cannot
        // resume while another was started meanwhile.
        return Err(AppError::Conflict(
            "fleet_rollout_active: another rollout is planned or in progress",
        )
        .into());
    }
    let mut plan = read_plan(&rollout)?;
    let status = transition(&mut plan, &rollout.status, which).map_err(AppError::Conflict)?;
    let plan_value = serde_json::to_value(&plan).map_err(AppError::internal)?;
    version_conflict_if_none(
        store::update_rollout(&mut stx, id, row_version, &plan_value, status).await?,
    )?;
    let mut rearmed = 0usize;
    if which == Transition::Resume {
        // Only the halted wave's failed targets go back to pending; applied
        // and skipped ones are left as they are (D-297's fixed behaviour).
        let targets = store::targets_of_locked(&mut stx, id).await?;
        for target in targets.iter().filter(|t| {
            usize::try_from(t.wave).ok() == Some(plan.cursor)
                && matches!(
                    TargetStatus::parse(&t.status),
                    Some(TargetStatus::Failed | TargetStatus::Pending)
                )
        }) {
            let mut update = TargetUpdate::from_row(target);
            update.status = TargetStatus::Pending.as_str().to_owned();
            update.error_code = None;
            update.remote_apply_ids = None;
            update.remote_approval_id = None;
            update.plan_summary = None;
            store::update_target(&mut stx, target.id, target.row_version, &update).await?;
            publish::enqueue_step_in_tx(stx.tx(), target.id).await?;
            rearmed += 1;
        }
    }
    let action = local_action(
        user_id,
        id,
        None,
        action_name,
        json!({ "rearmed": rearmed }),
    );
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok(Json(detail(state, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts/{id}/halt",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Rollout id")),
    request_body = RowVersionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Halted: no new target is planned; applies already sent keep being followed", body = RolloutDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout", body = ErrorResponse),
        (status = 409, description = "version_conflict, or the rollout is not in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn halt_rollout(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
    Json(body): Json<RowVersionBody>,
) -> ConsoleResult<Json<RolloutDetail>> {
    change_rollout(&state, ctx.user_id, id, body.row_version, Transition::Halt).await
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts/{id}/resume",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Rollout id")),
    request_body = RowVersionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Resumed: the halted wave's failed targets are planned again", body = RolloutDetail),
        (status = 401, description = "Missing credentials, or `reauth_required` without a fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout", body = ErrorResponse),
        (status = 409, description = "version_conflict, or the rollout is not halted", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn resume_rollout(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    session: HumanSession,
    Path(id): Path<Uuid>,
    Json(body): Json<RowVersionBody>,
) -> ConsoleResult<Json<RolloutDetail>> {
    require_step_up(&state, session, ctx.user_id).await?;
    change_rollout(
        &state,
        ctx.user_id,
        id,
        body.row_version,
        Transition::Resume,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts/{id}/cancel",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Rollout id")),
    request_body = RowVersionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Cancelled)])))),
    responses(
        (status = 200, description = "Cancelled: the console stops driving it; nothing on a customer is undone, and an approval still pending there is cancelled there", body = RolloutDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout", body = ErrorResponse),
        (status = 409, description = "version_conflict, or the rollout already finished", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn cancel_rollout(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
    Json(body): Json<RowVersionBody>,
) -> ConsoleResult<Json<RolloutDetail>> {
    change_rollout(
        &state,
        ctx.user_id,
        id,
        body.row_version,
        Transition::Cancel,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/rollouts/{id}/refresh",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Rollout id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 202, description = "A step is queued for every target that waits (approval, apply, or an unplanned target of the current wave)", body = StepsQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such rollout", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn refresh_rollout(
    State(state): State<FleetState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
) -> ConsoleResult<(StatusCode, Json<StepsQueued>)> {
    let rollout = store::get_rollout(&state.xrm.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let plan = read_plan(&rollout)?;
    let targets = store::targets_of(&state.xrm.base.db, id).await?;
    let waiting: Vec<&TargetRow> = targets
        .iter()
        .filter(|t| match TargetStatus::parse(&t.status) {
            Some(TargetStatus::ApprovalPending | TargetStatus::Applying) => true,
            Some(TargetStatus::Pending) => usize::try_from(t.wave).ok() == Some(plan.cursor),
            _ => false,
        })
        .collect();
    let action = local_action(
        ctx.user_id,
        id,
        None,
        "rollout_refresh",
        json!({ "targets": waiting.len() }),
    );
    let mut stx = SecurityTx::begin(
        &state.xrm,
        rollout_event(
            ctx.user_id,
            AuditOperation::Update,
            id,
            "fleet.rollout.refresh",
        ),
    )
    .await?;
    let mut queued = 0;
    for target in &waiting {
        if publish::enqueue_step_in_tx(stx.tx(), target.id).await? {
            queued += 1;
        }
    }
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(StepsQueued { queued })))
}

pub fn routes() -> Router<FleetState> {
    Router::new()
        .route(
            "/api/v1/fleet/rollouts",
            get(list_rollouts).post(start_rollout),
        )
        .route("/api/v1/fleet/rollouts/{id}", get(get_rollout))
        .route(
            "/api/v1/fleet/rollouts/{id}/targets/{target_id}/apply",
            post(apply_target),
        )
        .route(
            "/api/v1/fleet/rollouts/{id}/targets/{target_id}/skip",
            post(skip_target),
        )
        .route("/api/v1/fleet/rollouts/{id}/halt", post(halt_rollout))
        .route("/api/v1/fleet/rollouts/{id}/resume", post(resume_rollout))
        .route("/api/v1/fleet/rollouts/{id}/cancel", post(cancel_rollout))
        .route("/api/v1/fleet/rollouts/{id}/refresh", post(refresh_rollout))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_rollouts,
    start_rollout,
    get_rollout,
    apply_target,
    skip_target,
    halt_rollout,
    resume_rollout,
    cancel_rollout,
    refresh_rollout
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changesets::ChangesetFile;

    fn deployment(ring: &str, credential: bool) -> DeploymentRow {
        DeploymentRow {
            id: Uuid::now_v7(),
            project_code: "BMD".into(),
            label: "BMD".into(),
            environment: "prod".into(),
            ring: ring.into(),
            base_url: "https://bmd.example.com".into(),
            s2s_client_id: credential.then(|| "c".to_owned()),
            s2s_key_id: credential.then(|| "k".to_owned()),
            secret_last4: None,
            secret_rotated_at: None,
            maintenance_window: None,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            row_version: 0,
        }
    }

    fn file(id: Uuid, checksum_ok: bool) -> ChangesetFile {
        ChangesetFile {
            id,
            layer: "platform".into(),
            scope: "platform".into(),
            seq: 1,
            name: "cs".into(),
            title: "cs".into(),
            checksum: "sha256:x".into(),
            path: "platform/0001.json".into(),
            checksum_ok,
        }
    }

    #[test]
    fn a_start_needs_verified_changesets_and_credentialed_deployments() {
        let cs = Uuid::now_v7();
        let ok = deployment("canary", true);
        let body = |changesets: Vec<Uuid>, deployments: Vec<Uuid>| StartRolloutBody {
            title: "Release 4.0.2".into(),
            changeset_ids: changesets,
            deployment_ids: deployments,
        };
        let refs = check_start(
            &body(vec![cs], vec![ok.id]),
            &[file(cs, true)],
            std::slice::from_ref(&ok),
        )
        .expect("valid");
        assert_eq!(refs[0].id, cs);
        assert!(
            check_start(
                &body(vec![cs], vec![ok.id]),
                &[file(cs, false)],
                std::slice::from_ref(&ok)
            )
            .is_err()
        );
        assert!(
            check_start(
                &body(vec![Uuid::now_v7()], vec![ok.id]),
                &[file(cs, true)],
                std::slice::from_ref(&ok)
            )
            .is_err()
        );
        let bare = deployment("broad", false);
        assert!(check_start(&body(vec![cs], vec![bare.id]), &[file(cs, true)], &[bare]).is_err());
        assert!(check_start(&body(vec![cs, cs], vec![ok.id]), &[file(cs, true)], &[ok]).is_err());
    }

    #[test]
    fn halt_resume_and_cancel_follow_the_state_machine() {
        let mut plan = publish::plan_rollout(
            vec![Uuid::now_v7()],
            &[deployment("canary", true), deployment("broad", true)],
        )
        .expect("plans");
        assert!(transition(&mut plan, "halted", Transition::Halt).is_err());
        assert_eq!(
            transition(&mut plan, "in_progress", Transition::Halt),
            Ok("halted")
        );
        assert!(transition(&mut plan, "in_progress", Transition::Resume).is_err());
        assert_eq!(
            transition(&mut plan, "halted", Transition::Resume),
            Ok("in_progress")
        );
        assert_eq!(plan.waves[0].state, WaveState::InProgress);
        assert_eq!(
            transition(&mut plan, "in_progress", Transition::Cancel),
            Ok("cancelled")
        );
        assert!(transition(&mut plan, "completed", Transition::Cancel).is_err());
    }

    #[test]
    fn the_approval_link_shows_only_while_an_approval_waits() {
        let d = deployment("canary", true);
        let mut target = TargetRow {
            id: Uuid::now_v7(),
            rollout_ref: Uuid::now_v7(),
            deployment_ref: d.id,
            wave: 0,
            status: TargetStatus::ApprovalPending.as_str().into(),
            remote_apply_ids: Some(vec![Uuid::now_v7()]),
            remote_approval_id: Some(Uuid::now_v7()),
            backup_ref: Some("snap-1".into()),
            plan_summary: None,
            error_code: None,
            updated_at: Utc::now(),
            row_version: 3,
        };
        assert_eq!(
            target_view(&target, Some(&d)).approval_url.as_deref(),
            Some("https://bmd.example.com/xrm/admin/approvals")
        );
        target.status = TargetStatus::Applying.as_str().into();
        assert_eq!(target_view(&target, Some(&d)).approval_url, None);
    }
}
