//! F4 — publish (design §6.4): plan → the developer reviews → apply with a
//! `backup_ref` → a human approves **on the customer server** (the console
//! never approves) → the console follows the customer's ledger → the release
//! report is read by the next sync.
//!
//! A rollout is one set of changesets to many customers, in waves built from
//! the deployments' rings (canary → early → broad) with `core`'s
//! `RolloutPlan` state machine. Each target moves through
//!
//! ```text
//! pending ─plan─► planned ─apply (route, step-up)─► approval_pending ─► applying ─► applied
//!    │               │                                     │                 │
//!    └──► failed ◄───┴──────────── rejected/expired ───────┴──── failed ─────┘
//!                    └─ skip (route) ─► skipped
//! ```
//!
//! as durable `EngineJob::FleetRolloutStep` jobs, never a request-thread
//! loop. A wave is decided when every target in it is `applied`, `failed` or
//! `skipped`: any `failed` halts the rollout (`RolloutPlan::report_wave_health`),
//! a blocked customer never undoes the others, and `resume` re-arms only the
//! halted wave's failed targets (applied ones are not touched, D-297's
//! fixed behaviour). One rollout is active at a time, taken under
//! `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE, hashtext('attome-fleet/rollout:active'))`
//! (D-351); row changes use `row_version`.
//!
//! A changeset with a contract phase is applied twice: the expand rows
//! first; when they succeed the target returns to `planned` with
//! `plan_summary.phase = "contract"` and the developer applies again.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_types::AppError;

use crate::changesets::{self, ChangesetRef};
use crate::client::{CustomerClient, RemoteError, paths};
use crate::core::{DeploymentId, FleetError, RolloutPlan, RolloutStatus, plan_waves_by_groups};
use crate::runtime::FleetRuntime;
use crate::store::{self, ActionWrite, DeploymentRow, RolloutRow, TargetRow, TargetUpdate};

/// The advisory-lock key of "one active rollout" (namespace
/// [`crate::ADVISORY_LOCK_NAMESPACE`]).
pub const ACTIVE_ROLLOUT_LOCK: &str = "attome-fleet/rollout:active";

/// Ring order = wave order (design §6.4).
pub const RINGS: [&str; 3] = ["canary", "early", "broad"];

/// What a console rollout converges to: its changesets (`RolloutPlan<T>`'s
/// target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReleaseTarget {
    pub changeset_ids: Vec<Uuid>,
}

pub type ReleasePlan = RolloutPlan<ReleaseTarget>;

/// `fleet_target.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    Pending,
    Planned,
    ApprovalPending,
    Applying,
    Applied,
    Failed,
    Skipped,
}

impl TargetStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Planned => "planned",
            Self::ApprovalPending => "approval_pending",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Pending,
            Self::Planned,
            Self::ApprovalPending,
            Self::Applying,
            Self::Applied,
            Self::Failed,
            Self::Skipped,
        ]
        .into_iter()
        .find(|s| s.as_str() == value)
    }

    /// The wave can be decided once every target is terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Failed | Self::Skipped)
    }
}

/// `fleet_rollout.status` for a plan status.
pub const fn rollout_status_str(status: RolloutStatus) -> &'static str {
    match status {
        RolloutStatus::Planned => "planned",
        RolloutStatus::InProgress => "in_progress",
        RolloutStatus::Completed => "completed",
        RolloutStatus::Halted => "halted",
        // The console never marks a plan rolled back; a cancelled rollout is
        // the nearest stored state.
        RolloutStatus::RolledBack => "cancelled",
    }
}

/// Builds the waves from the deployments' rings and starts the first wave.
pub fn plan_rollout(
    changeset_ids: Vec<Uuid>,
    deployments: &[DeploymentRow],
) -> Result<ReleasePlan, FleetError> {
    let groups: Vec<(String, Vec<DeploymentId>)> = RINGS
        .iter()
        .map(|ring| {
            (
                (*ring).to_string(),
                deployments
                    .iter()
                    .filter(|d| d.ring == *ring)
                    .map(|d| DeploymentId(d.id))
                    .collect(),
            )
        })
        .collect();
    let mut plan = plan_waves_by_groups(ReleaseTarget { changeset_ids }, groups)?;
    plan.start_current_wave()?;
    Ok(plan)
}

/// The wave index of a deployment in a plan.
pub fn wave_of(plan: &ReleasePlan, deployment_id: Uuid) -> Option<usize> {
    plan.waves
        .iter()
        .position(|w| w.deployments.contains(&DeploymentId(deployment_id)))
}

/// What a set of the customer's ledger rows says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerOutcome {
    Succeeded,
    Failed,
    /// Still running; `queued` once any row left `planned` (the approval was
    /// granted, or there was none).
    Running {
        queued: bool,
    },
}

pub fn ledger_outcome(statuses: &[String]) -> LedgerOutcome {
    if statuses.iter().any(|s| s == "failed") {
        return LedgerOutcome::Failed;
    }
    if !statuses.is_empty() && statuses.iter().all(|s| s == "succeeded" || s == "adopted") {
        return LedgerOutcome::Succeeded;
    }
    LedgerOutcome::Running {
        queued: statuses.iter().any(|s| s != "planned"),
    }
}

/// An approval the customer will never grant.
pub fn approval_closed(status: &str) -> bool {
    matches!(status, "rejected" | "expired" | "cancelled" | "invalidated")
}

/// Whether the current wave can be decided, and how many of it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaveDecision {
    Wait,
    Decide { unhealthy: usize },
}

pub fn wave_decision(statuses: &[TargetStatus]) -> WaveDecision {
    if statuses.iter().any(|s| !s.is_terminal()) {
        return WaveDecision::Wait;
    }
    WaveDecision::Decide {
        unhealthy: statuses
            .iter()
            .filter(|s| **s == TargetStatus::Failed)
            .count(),
    }
}

/// Records the wave's health; when the plan moves on, starts the next wave
/// and returns its index.
pub fn decide_wave(plan: &mut ReleasePlan, unhealthy: usize) -> Result<Option<usize>, FleetError> {
    plan.report_wave_health(unhealthy)?;
    if plan.status == RolloutStatus::InProgress {
        plan.start_current_wave()?;
        return Ok(Some(plan.cursor));
    }
    Ok(None)
}

/// The counts the console keeps of a customer's plan (never record values).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = FleetPlanSummary)]
pub struct PlanSummary {
    pub changesets: usize,
    pub already_applied: usize,
    /// `ref` of every changeset the customer's planner blocked, whether as a
    /// whole (`status = "blocked"`) or in one of its phases (an operation
    /// blocked: the changeset stays `planned`, the phase is not applicable).
    pub blocked: Vec<String>,
    pub applicable: bool,
    /// Operations flagged risky (contract or newly required, design §5.4).
    pub risky_operations: usize,
    pub expand_apply_ids: Vec<Uuid>,
    pub contract_apply_ids: Vec<Uuid>,
    /// `expand` or `contract`: the phase the next apply sends.
    pub phase: String,
}

/// Reads the customer's `ChangesetPlan` (`POST …/changesets/plan`).
pub fn summarize_plan(plan: &Value) -> PlanSummary {
    let ids = |name: &str| -> Vec<Uuid> {
        plan[name]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let changesets = plan["changesets"].as_array().cloned().unwrap_or_default();
    let risky_operations = changesets
        .iter()
        .flat_map(|c| c["phases"].as_array().cloned().unwrap_or_default())
        .flat_map(|p| p["operations"].as_array().cloned().unwrap_or_default())
        .filter(|o| o["risky"].as_bool() == Some(true))
        .count();
    let expand_apply_ids = ids("apply_ids");
    PlanSummary {
        changesets: changesets.len(),
        already_applied: changesets
            .iter()
            .filter(|c| c["status"] == "already_applied")
            .count(),
        blocked: changesets
            .iter()
            .filter(|c| {
                c["status"] == "blocked"
                    || c["phases"].as_array().is_some_and(|phases| {
                        phases
                            .iter()
                            .any(|p| p["applicable"].as_bool() == Some(false))
                    })
            })
            .map(|c| c["ref"].as_str().unwrap_or_default().to_owned())
            .collect(),
        applicable: plan["applicable"].as_bool().unwrap_or(false),
        risky_operations,
        phase: if expand_apply_ids.is_empty() {
            "contract".to_owned()
        } else {
            "expand".to_owned()
        },
        expand_apply_ids,
        contract_apply_ids: ids("contract_apply_ids"),
    }
}

/// The target's state after its plan came back.
pub fn after_plan(summary: &PlanSummary) -> (TargetStatus, Option<&'static str>) {
    if !summary.applicable {
        return (TargetStatus::Failed, Some("plan_blocked"));
    }
    if summary.expand_apply_ids.is_empty() && summary.contract_apply_ids.is_empty() {
        // Everything is already in the customer's ledger.
        return (TargetStatus::Applied, None);
    }
    (TargetStatus::Planned, None)
}

/// The ledger ids the next apply sends, for the summary's phase.
pub fn ids_for_phase(summary: &PlanSummary) -> &[Uuid] {
    if summary.phase == "contract" {
        &summary.contract_apply_ids
    } else {
        &summary.expand_apply_ids
    }
}

pub fn read_summary(target: &TargetRow) -> PlanSummary {
    target
        .plan_summary
        .clone()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub fn read_plan(rollout: &RolloutRow) -> Result<ReleasePlan, AppError> {
    serde_json::from_value(rollout.plan.clone()).map_err(AppError::internal)
}

pub fn read_refs(rollout: &RolloutRow) -> Result<Vec<ChangesetRef>, AppError> {
    serde_json::from_value(rollout.changesets.clone()).map_err(AppError::internal)
}

fn step_job(target_id: Uuid) -> (EngineJob, String) {
    (
        EngineJob::FleetRolloutStep { target_id },
        format!("fleet-rollout-step:{target_id}"),
    )
}

/// Enqueues one target's step (dedup-keyed: a pending step absorbs it).
pub async fn enqueue_step(db: &attome_db::DbPool, target_id: Uuid) -> Result<bool, AppError> {
    let (job, key) = step_job(target_id);
    attome_jobs::enqueue_dedup(db, job, &key)
        .await
        .map_err(AppError::internal)
}

/// [`enqueue_step`] in the caller's transaction.
pub async fn enqueue_step_in_tx(
    tx: &mut attome_db::Tx<'_>,
    target_id: Uuid,
) -> Result<bool, AppError> {
    let (job, key) = step_job(target_id);
    attome_jobs::enqueue_in_tx_dedup(tx, job, &key)
        .await
        .map_err(AppError::internal)
}

/// Writes a target's new state and its action-log row in one transaction.
/// A lost `row_version` race writes nothing (a newer writer decided).
async fn write_target(
    state: &EngineState,
    target: &TargetRow,
    update: &TargetUpdate,
    action: &ActionWrite,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if store::update_target(&mut tx, target.id, target.row_version, update)
        .await?
        .is_none()
    {
        tracing::info!(target_id = %target.id, "fleet step: the target changed meanwhile; nothing written");
        return Ok(());
    }
    store::insert_action(&mut tx, action).await?;
    attome_db::tx::commit(tx).await
}

#[allow(clippy::too_many_arguments)]
fn remote_action(
    id: Uuid,
    rollout: &RolloutRow,
    target: &TargetRow,
    action: &'static str,
    method: &'static str,
    path: &str,
    result: Result<u16, &RemoteError>,
    detail: Value,
) -> ActionWrite {
    let (status, outcome) = match result {
        Ok(status) => (Some(status), "ok"),
        Err(RemoteError::AuthRefused { status }) => (Some(*status), "refused"),
        Err(e) => (e.status(), "failed"),
    };
    ActionWrite {
        id,
        actor_ref: rollout.created_by,
        deployment_ref: Some(target.deployment_ref),
        rollout_ref: Some(rollout.id),
        action,
        remote_method: Some(method),
        remote_path: Some(path.to_owned()),
        remote_status: status,
        outcome,
        detail,
    }
}

/// The `FleetRolloutStep` job body (gate re-checked: fails closed when off).
pub async fn run_step(state: &EngineState, target_id: Uuid) -> Result<(), AppError> {
    crate::gate::require_open(&state.base.config)?;
    let runtime = FleetRuntime::from_config(&state.base.config)?;
    let db = &state.base.db;
    let Some(target) = store::get_target(db, target_id).await? else {
        return Ok(());
    };
    let Some(rollout) = store::get_rollout(db, target.rollout_ref).await? else {
        return Ok(());
    };
    let Some(deployment) = store::get_deployment(db, target.deployment_ref).await? else {
        return Ok(());
    };
    let plan = read_plan(&rollout)?;
    match TargetStatus::parse(&target.status) {
        Some(TargetStatus::Pending)
            if rollout.status == "in_progress" && target.wave as usize == plan.cursor =>
        {
            step_plan(state, &runtime, &rollout, &target, &deployment).await?;
        }
        Some(TargetStatus::ApprovalPending | TargetStatus::Applying) => {
            step_follow(state, &runtime, &rollout, &target, &deployment).await?;
        }
        _ => {}
    }
    evaluate(state, rollout.id).await
}

/// `pending` → plan on the customer.
async fn step_plan(
    state: &EngineState,
    runtime: &FleetRuntime,
    rollout: &RolloutRow,
    target: &TargetRow,
    deployment: &DeploymentRow,
) -> Result<(), AppError> {
    let mut update = TargetUpdate::from_row(target);
    let documents = match changesets::load_documents(
        runtime.changesets_dir.clone(),
        read_refs(rollout)?,
    )
    .await
    {
        Ok(documents) => documents,
        Err(e) => {
            tracing::warn!(target_id = %target.id, error = %e, "fleet step: changesets could not be loaded");
            update.status = TargetStatus::Failed.as_str().to_owned();
            update.error_code = Some("changeset_unreadable".to_owned());
            let action = ActionWrite {
                id: Uuid::now_v7(),
                actor_ref: rollout.created_by,
                deployment_ref: Some(target.deployment_ref),
                rollout_ref: Some(rollout.id),
                action: "plan",
                remote_method: None,
                remote_path: None,
                remote_status: None,
                outcome: "failed",
                detail: json!({"error": "changeset_unreadable"}),
            };
            return write_target(state, target, &update, &action).await;
        }
    };
    let selected: Vec<Value> = documents
        .into_iter()
        .filter(|d| {
            changesets::applies_to(
                d["layer"].as_str().unwrap_or_default(),
                d["scope"].as_str().unwrap_or_default(),
                &deployment.project_code,
            )
        })
        .collect();
    let action_id = Uuid::now_v7();
    if selected.is_empty() {
        update.status = TargetStatus::Applied.as_str().to_owned();
        update.plan_summary = serde_json::to_value(PlanSummary {
            applicable: true,
            ..PlanSummary::default()
        })
        .ok();
        let action = ActionWrite {
            id: action_id,
            actor_ref: rollout.created_by,
            deployment_ref: Some(target.deployment_ref),
            rollout_ref: Some(rollout.id),
            action: "plan",
            remote_method: None,
            remote_path: None,
            remote_status: None,
            outcome: "ok",
            detail: json!({"changesets": 0}),
        };
        return write_target(state, target, &update, &action).await;
    }
    let client = runtime.customer(&state.base.db, deployment).await?;
    let sent = selected.len();
    let result = client
        .post(
            paths::PLAN,
            &json!({ "changesets": selected }),
            None,
            Some(action_id),
        )
        .await;
    let action = match &result {
        Ok(response) => {
            let summary = summarize_plan(&response.body);
            let (status, error) = after_plan(&summary);
            update.status = status.as_str().to_owned();
            update.error_code = error.map(str::to_owned);
            let detail = json!({
                "changesets": sent,
                "already_applied": summary.already_applied,
                "blocked": summary.blocked.len(),
                "risky_operations": summary.risky_operations,
            });
            update.plan_summary = serde_json::to_value(&summary).ok();
            remote_action(
                action_id,
                rollout,
                target,
                "plan",
                "POST",
                paths::PLAN,
                Ok(response.status),
                detail,
            )
        }
        Err(e) => {
            update.status = TargetStatus::Failed.as_str().to_owned();
            update.error_code = Some(e.code().to_owned());
            remote_action(
                action_id,
                rollout,
                target,
                "plan",
                "POST",
                paths::PLAN,
                Err(e),
                json!({"changesets": sent, "error": e.code()}),
            )
        }
    };
    write_target(state, target, &update, &action).await
}

/// `approval_pending` / `applying` → read the customer's ledger rows.
async fn step_follow(
    state: &EngineState,
    runtime: &FleetRuntime,
    rollout: &RolloutRow,
    target: &TargetRow,
    deployment: &DeploymentRow,
) -> Result<(), AppError> {
    let client = runtime.customer(&state.base.db, deployment).await?;
    let action_id = Uuid::now_v7();
    let ids = target.remote_apply_ids.clone().unwrap_or_default();
    let mut statuses = Vec::with_capacity(ids.len());
    for id in &ids {
        match client
            .get(&format!("{}/{id}", paths::LEDGER), Some(action_id))
            .await
        {
            Ok(row) => statuses.push(row["status"].as_str().unwrap_or_default().to_owned()),
            Err(RemoteError::NotFound) => statuses.push("failed".to_owned()),
            // Unreachable now: the next step (poll) asks again.
            Err(e) => {
                tracing::info!(target_id = %target.id, error = %e, "fleet step: ledger unreadable; will retry");
                return Ok(());
            }
        }
    }
    let mut update = TargetUpdate::from_row(target);
    let current = TargetStatus::parse(&target.status);
    let outcome = ledger_outcome(&statuses);

    // A pending approval the customer will never grant fails the target.
    if current == Some(TargetStatus::ApprovalPending)
        && let Some(approval) = target.remote_approval_id
        && let LedgerOutcome::Running { queued: false } = outcome
        && let Ok(request) = approval_status(&client, approval, action_id).await
        && approval_closed(&request)
    {
        update.status = TargetStatus::Failed.as_str().to_owned();
        update.error_code = Some(format!("approval_{request}"));
        let action = follow_action(action_id, rollout, target, json!({"approval": request}));
        return write_target(state, target, &update, &action).await;
    }

    match outcome {
        LedgerOutcome::Running { queued } => {
            if queued && current == Some(TargetStatus::ApprovalPending) {
                update.status = TargetStatus::Applying.as_str().to_owned();
            } else {
                return Ok(());
            }
        }
        LedgerOutcome::Failed => {
            update.status = TargetStatus::Failed.as_str().to_owned();
            update.error_code = Some("apply_failed".to_owned());
        }
        LedgerOutcome::Succeeded => {
            let mut summary = read_summary(target);
            if summary.phase == "expand" && !summary.contract_apply_ids.is_empty() {
                summary.phase = "contract".to_owned();
                update.status = TargetStatus::Planned.as_str().to_owned();
                update.remote_apply_ids = None;
                update.remote_approval_id = None;
                update.plan_summary = serde_json::to_value(&summary).ok();
            } else if client.ready().await.unwrap_or(false) {
                update.status = TargetStatus::Applied.as_str().to_owned();
                update.error_code = None;
            } else {
                update.status = TargetStatus::Failed.as_str().to_owned();
                update.error_code = Some("not_ready_after_apply".to_owned());
            }
        }
    }
    let action = follow_action(
        action_id,
        rollout,
        target,
        json!({"ledger_rows": ids.len(), "status": update.status}),
    );
    write_target(state, target, &update, &action).await
}

fn follow_action(id: Uuid, rollout: &RolloutRow, target: &TargetRow, detail: Value) -> ActionWrite {
    ActionWrite {
        id,
        actor_ref: rollout.created_by,
        deployment_ref: Some(target.deployment_ref),
        rollout_ref: Some(rollout.id),
        action: "follow",
        remote_method: Some("GET"),
        remote_path: Some(paths::LEDGER.to_owned()),
        remote_status: Some(200),
        outcome: "ok",
        detail,
    }
}

async fn approval_status(
    client: &CustomerClient,
    approval: Uuid,
    correlation: Uuid,
) -> Result<String, RemoteError> {
    let body = client
        .get(
            &format!("{}/{approval}", paths::APPROVALS),
            Some(correlation),
        )
        .await?;
    Ok(body["status"].as_str().unwrap_or_default().to_owned())
}

/// Re-evaluates a live rollout's current wave and moves the plan on when
/// every target in it is decided. Idempotent: the steps and the poll both
/// call it; the rollout row lock makes them take turns.
pub async fn evaluate(state: &EngineState, rollout_id: Uuid) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(rollout) = store::get_rollout_for_update(&mut tx, rollout_id).await? else {
        return attome_db::tx::commit(tx).await;
    };
    if rollout.status != "in_progress" {
        return attome_db::tx::commit(tx).await;
    }
    let mut plan = read_plan(&rollout)?;
    let targets = store::targets_of_locked(&mut tx, rollout_id).await?;
    let current: Vec<TargetStatus> = targets
        .iter()
        .filter(|t| t.wave as usize == plan.cursor)
        .filter_map(|t| TargetStatus::parse(&t.status))
        .collect();
    let WaveDecision::Decide { unhealthy } = wave_decision(&current) else {
        return attome_db::tx::commit(tx).await;
    };
    let next = decide_wave(&mut plan, unhealthy).map_err(AppError::internal)?;
    let plan_value = serde_json::to_value(&plan).map_err(AppError::internal)?;
    store::update_rollout(
        &mut tx,
        rollout.id,
        rollout.row_version,
        &plan_value,
        rollout_status_str(plan.status),
    )
    .await?;
    if let Some(wave) = next {
        for target in targets.iter().filter(|t| {
            t.wave as usize == wave && TargetStatus::parse(&t.status) == Some(TargetStatus::Pending)
        }) {
            enqueue_step_in_tx(&mut tx, target.id).await?;
        }
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        %rollout_id,
        unhealthy,
        status = rollout_status_str(plan.status),
        "fleet rollout: wave decided"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::WaveState;
    use chrono::Utc;

    fn deployment(ring: &str) -> DeploymentRow {
        DeploymentRow {
            id: Uuid::now_v7(),
            project_code: "BMD".into(),
            label: "BMD".into(),
            environment: "prod".into(),
            ring: ring.into(),
            base_url: "https://bmd.example.com".into(),
            s2s_client_id: Some("c".into()),
            s2s_key_id: Some("k".into()),
            secret_last4: Some("abcd".into()),
            secret_rotated_at: None,
            maintenance_window: None,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            row_version: 0,
        }
    }

    #[test]
    fn waves_follow_ring_order_and_the_first_one_starts() {
        let broad = deployment("broad");
        let canary = deployment("canary");
        let plan =
            plan_rollout(vec![Uuid::now_v7()], &[broad.clone(), canary.clone()]).expect("plans");
        assert_eq!(plan.waves.len(), 2, "the empty early ring is skipped");
        assert_eq!(plan.waves[0].name, "canary");
        assert_eq!(plan.waves[0].state, WaveState::InProgress);
        assert_eq!(plan.status, RolloutStatus::InProgress);
        assert_eq!(wave_of(&plan, canary.id), Some(0));
        assert_eq!(wave_of(&plan, broad.id), Some(1));
    }

    #[test]
    fn a_wave_waits_until_every_target_is_decided() {
        use TargetStatus::*;
        assert_eq!(wave_decision(&[Applied, Applying]), WaveDecision::Wait);
        assert_eq!(wave_decision(&[Applied, Planned]), WaveDecision::Wait);
        assert_eq!(
            wave_decision(&[Applied, Skipped]),
            WaveDecision::Decide { unhealthy: 0 }
        );
        assert_eq!(
            wave_decision(&[Applied, Failed, Failed]),
            WaveDecision::Decide { unhealthy: 2 }
        );
    }

    #[test]
    fn a_healthy_wave_starts_the_next_and_a_failed_one_halts() {
        let plan_of = || {
            plan_rollout(
                vec![Uuid::now_v7()],
                &[deployment("canary"), deployment("broad")],
            )
            .expect("plans")
        };
        let mut healthy = plan_of();
        assert_eq!(decide_wave(&mut healthy, 0).expect("decides"), Some(1));
        assert_eq!(healthy.waves[1].state, WaveState::InProgress);
        assert_eq!(decide_wave(&mut healthy, 0).expect("decides"), None);
        assert_eq!(healthy.status, RolloutStatus::Completed);
        assert_eq!(rollout_status_str(healthy.status), "completed");

        let mut halted = plan_of();
        assert_eq!(decide_wave(&mut halted, 1).expect("decides"), None);
        assert_eq!(halted.status, RolloutStatus::Halted);
        assert_eq!(halted.cursor, 0, "the halted wave stays current");
        // Resume re-arms only the halted wave; the plan restarts it.
        halted.resume().expect("resumes");
        halted.start_current_wave().expect("restarts");
        assert_eq!(halted.status, RolloutStatus::InProgress);
        assert_eq!(halted.waves[0].state, WaveState::InProgress);
        assert_eq!(halted.waves[1].state, WaveState::Pending);
    }

    #[test]
    fn the_ledger_decides_a_targets_apply() {
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            ledger_outcome(&s(&["succeeded", "adopted"])),
            LedgerOutcome::Succeeded
        );
        assert_eq!(
            ledger_outcome(&s(&["succeeded", "failed"])),
            LedgerOutcome::Failed
        );
        assert_eq!(
            ledger_outcome(&s(&["planned", "planned"])),
            LedgerOutcome::Running { queued: false }
        );
        assert_eq!(
            ledger_outcome(&s(&["queued", "planned"])),
            LedgerOutcome::Running { queued: true }
        );
        assert_eq!(
            ledger_outcome(&[]),
            LedgerOutcome::Running { queued: false }
        );
        assert!(approval_closed("rejected"));
        assert!(!approval_closed("pending"));
    }

    #[test]
    fn a_customer_plan_is_summarized_without_record_values() {
        let expand = Uuid::now_v7();
        let contract = Uuid::now_v7();
        let plan = json!({
            "changesets": [
                {"ref": "platform/1", "status": "already_applied", "phases": []},
                {"ref": "project/bmd/2", "status": "planned", "phases": [
                    {"operations": [{"risky": true}, {"risky": false}]}
                ]},
            ],
            "apply_ids": [expand.to_string()],
            "contract_apply_ids": [contract.to_string()],
            "applicable": true,
        });
        let summary = summarize_plan(&plan);
        assert_eq!(summary.changesets, 2);
        assert_eq!(summary.already_applied, 1);
        assert_eq!(summary.risky_operations, 1);
        assert_eq!(summary.phase, "expand");
        assert_eq!(ids_for_phase(&summary), &[expand]);
        assert_eq!(after_plan(&summary), (TargetStatus::Planned, None));

        let blocked = summarize_plan(
            &json!({"changesets": [{"ref": "x", "status": "blocked"}], "applicable": false}),
        );
        assert_eq!(
            after_plan(&blocked),
            (TargetStatus::Failed, Some("plan_blocked"))
        );
        assert_eq!(blocked.blocked, vec!["x".to_owned()]);

        // FC-D proof: one blocked operation leaves the changeset `planned`
        // and only its phase not applicable; the summary still names it.
        let phase_blocked = summarize_plan(&json!({
            "changesets": [
                {"ref": "product/p/1", "status": "planned", "phases": [
                    {"applicable": false, "operations": [{"action": "blocked", "risky": false}]}
                ]},
                {"ref": "product/p/2", "status": "planned", "phases": [
                    {"applicable": true, "operations": []}
                ]},
            ],
            "apply_ids": [expand.to_string()],
            "applicable": false,
        }));
        assert_eq!(phase_blocked.blocked, vec!["product/p/1".to_owned()]);
        assert_eq!(
            after_plan(&phase_blocked),
            (TargetStatus::Failed, Some("plan_blocked"))
        );
        let nothing = summarize_plan(
            &json!({"changesets": [], "apply_ids": [], "contract_apply_ids": [], "applicable": true}),
        );
        assert_eq!(after_plan(&nothing), (TargetStatus::Applied, None));
    }

    #[test]
    fn target_statuses_round_trip_through_their_column_values() {
        for status in [
            TargetStatus::Pending,
            TargetStatus::Planned,
            TargetStatus::ApprovalPending,
            TargetStatus::Applying,
            TargetStatus::Applied,
            TargetStatus::Failed,
            TargetStatus::Skipped,
        ] {
            assert_eq!(TargetStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(TargetStatus::parse("unknown"), None);
    }

    #[test]
    fn a_release_plan_round_trips_through_its_json_column() {
        let plan = plan_rollout(vec![Uuid::now_v7()], &[deployment("early")]).expect("plans");
        let value = serde_json::to_value(&plan).expect("serializes");
        let back: ReleasePlan = serde_json::from_value(value).expect("deserializes");
        assert_eq!(back.target, plan.target);
        assert_eq!(back.cursor, plan.cursor);
    }
}
