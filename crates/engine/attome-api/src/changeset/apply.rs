//! Apply: run a planned changeset phase through the metadata engine as a
//! durable, resumable job (Solution 7 design §5.3–§5.5).
//!
//! [`run_apply_job`] is the worker entry `EngineJob::ApplyChangesets {
//! apply_ids }` dispatches to (`crates/server/src/jobs.rs`); the boot path
//! runs [`run_one`] inline for a platform changeset. Rows are applied
//! strictly in the order given; a failure stops the run, and the later rows
//! stay `queued` (a retry of the job skips the rows that finished and stops
//! again at the failed one until it is re-queued).
//!
//! **Per row.** Claim (the bundle ledger's CAS + takeover scheme), then:
//!
//! - the checksum refusal again (§5.4): the stored document's recomputed
//!   checksum must equal the row's;
//! - a plan that was not applicable is refused;
//! - a `contract` row is refused until the same changeset's `expand` row is
//!   `succeeded` or `adopted`;
//! - the phase's operations run from `cursor`, in **steps**: one operation,
//!   or a contiguous run of operations on one parent whose children are set
//!   semantics inside the parent's reconcile primitive (a role and its
//!   grants, conditions, entity access and profile links; a profile and its
//!   fields; a state model and its transitions; a calendar and its holidays
//!   and exceptions — [`super::plan::Fold`]). The cursor advances after each
//!   step commits.
//!
//! **Executors** are the existing reconcile primitives, the ones the bundle
//! engine calls (`bundle/apply.rs::run_step`), each its own short
//! transaction holding the metadata write lock and appending the change log;
//! nothing here issues schema statements. Every executor is compare-first,
//! so a resumed run re-applies a step that committed before a crash as
//! `Unchanged`. Created rows take the same deterministic ids
//! (`bundle::derived_id`) the bundle engine gives them, so a changeset and
//! the bundle it was converted from produce the same rows.
//!
//! **Deviation from the design, stated.** §5.3 groups a changeset's
//! non-DDL operations into one transaction per run of transactional ops. The
//! executors reachable from this crate are the reconcile primitives, each
//! with its own transaction (the `*_in_tx` extractions of lanes L3–L5 take a
//! request `Recording` and admin body shapes, not definitions), so a step is
//! the unit of commit here, as it is for the bundle engine. A crash between
//! two steps leaves the earlier steps committed and the cursor on the next
//! one; resume is exact.
//!
//! **Layers.** A platform changeset applies under `ReconcilePolicy::Seed`
//! (the platform-bundle contract, D-478: an omitted `Option` is unmanaged, an
//! admin-customized row is skipped, new rows are stamped `platform`); any
//! other layer under `ReconcilePolicy::Bundle`, which stamps new rows
//! `project` — a `product` changeset's rows are stamped `project` until the
//! primitives take a `Recording::Applying` layer (reported, Phase 1 gap).
//!
//! **Phase 2 field ops** (D-788: `rename_field`, `delete_field`,
//! `change_field_type`, `add_choice_value`, `remove_choice_value`) run through
//! `crate::field_changes` — the admin routes' executors — each its own
//! transaction (a large table's batches run inside this job).
//!
//! **`set_view_columns`** (design §3.7) runs through
//! `crate::view_admin::set_view_columns`: compare-first, `columns` replaces
//! the view's `table_definition` whole.
//!
//! **Not executable in this release** (planned as `op_not_supported`, see
//! [`super::plan::unsupported`]): `data_step`, workflow and case-definition operations
//! (their engines are not dependencies of this crate), role bulk fields,
//! entity default shares, data domains, `publish_rule` and `clear_label`
//! (no reusable executor exists outside their admin handlers).
//!
//! **Doorbell.** One `notify_metadata_change` per run, after the ledger row is
//! terminal, and the configuration hash (D-378) is recomputed on success.
//!
//! **Release report** (Phase 2, design §7.1 post-apply, §10.3). A run — the
//! job's rows, or one boot/replay row — opens its report first
//! (`super::report::begin_run`) and executes inside
//! `attome_core::release_report::scope`; every operation runs in an inner
//! scope naming its `(changeset id, seq)`, so the items an executor writes
//! (conflicts, archived values, adjusted customer objects, breaking changes)
//! land in the run's report as their effects commit. After the last row
//! succeeded the report is marked ready and the administrators are notified
//! once (`super::report::finish_run`). The report never blocks: a failure to
//! open or finish it is logged at `error` and the apply goes on (items then
//! land in a standalone report).

use std::collections::HashMap;
use std::time::Duration;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
    fetch_audit_ctx,
};
use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, Recording};
use attome_core::release_report::{self as rr, ReportCtx};
use attome_db::DbPool;
use attome_metadata::provision::{
    self as provision, AttributeDesc, EntityDesc, ReconcileOutcome, ReconcilePolicy,
};
use attome_security::reconcile as security;
use attome_types::AppError;
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use super::ledger::{self, ApplyPhase, LedgerRow};
use super::plan::{self, DocOp, Document, Fold};
use crate::bundle::model::*;
use crate::bundle::{bundle_hash, derived_id, export_bundle};

/// Y11-T12: a platform or app release that retired, deleted or renamed an
/// item the customer (or another app) customised puts a
/// `customisation_affected` item in the apply run's release report, naming
/// the properties and, for a rename, the new name. The customisation is not
/// moved. Reporting runs after the operation committed; a failure is
/// logged, never a failure of the apply.
async fn report_customisation_impact(
    state: &EngineState,
    layer: Layer,
    removed: &[provision::layer_impact::ObjectKey],
    renamed: &[(
        provision::layer_impact::ObjectKey,
        provision::layer_impact::ObjectKey,
    )],
) {
    if !matches!(layer, Layer::Platform | Layer::Product) {
        return;
    }
    let drafts = match provision::layer_impact::deprecation_impact(&state.base.db, removed, renamed)
        .await
    {
        Ok(impacts) => provision::layer_impact::report_drafts(&impacts),
        Err(error) => {
            tracing::error!(%error, "release report: affected customisations could not be read");
            return;
        }
    };
    if drafts.is_empty() {
        return;
    }
    if let Err(error) = rr::record_drafts(
        &state.base.db,
        attome_core::recovery_archive::ring(state.base.config.as_ref()),
        &drafts,
        "customisations affected by the release",
    )
    .await
    {
        tracing::error!(%error, "release report: affected customisations were not stored");
    }
}

/// Same inline size gate as the bundle engine's index build.
const ATTRIBUTE_INDEX_INLINE_ROW_LIMIT: i64 = 100_000;
/// Bounded retry when a step loses the non-blocking metadata lock.
const LOCK_RETRY_ATTEMPTS: u32 = 5;
const LOCK_RETRY_BACKOFF: Duration = Duration::from_millis(100);
/// `reconcile_attribute`'s size-gate refusal, matched by value.
const SCHEMA_CHANGE_NEEDS_PLAN: &str = "schema change requires async plan";

fn is_lock_busy(err: &AppError) -> bool {
    matches!(err, AppError::Conflict(msg) if msg.contains("already in progress"))
}

/// `bundle/apply.rs`'s bounded lock retry (a macro there for the same
/// higher-ranked `Send` reason, rust-lang #110338).
macro_rules! with_lock_retry {
    ($op:expr) => {{
        let mut attempt: u32 = 0;
        loop {
            let result = $op;
            match &result {
                Err(err) if is_lock_busy(err) && attempt < LOCK_RETRY_ATTEMPTS => {
                    attempt += 1;
                    tracing::debug!(attempt, error = %err, "changeset apply: lock busy, retrying");
                    tokio::time::sleep(LOCK_RETRY_BACKOFF * attempt).await;
                }
                _ => break result,
            }
        }
    }};
}

fn wrote(outcome: ReconcileOutcome) -> bool {
    matches!(
        outcome,
        ReconcileOutcome::Created | ReconcileOutcome::Updated
    )
}

/// What one row's run did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub steps: u32,
    pub written: u32,
    pub unchanged: u32,
}

impl RunSummary {
    fn record(&mut self, outcome: ReconcileOutcome) {
        if wrote(outcome) {
            self.written += 1;
        } else {
            self.unchanged += 1;
        }
    }
}

/// How [`run_one`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// Claimed and applied; the row is `succeeded`.
    Applied(RunSummary),
    /// Not claimable (running elsewhere, finished, or not queued).
    NotClaimed,
}

// ── Worker entry ────────────────────────────────────────────────────────────

/// `EngineJob::ApplyChangesets { apply_ids }`: applies the rows in order,
/// stopping at the first that fails (or that an earlier delivery left
/// failed or unqueued).
pub async fn run_apply_job(state: &EngineState, apply_ids: &[Uuid]) -> Result<(), AppError> {
    let Some(report_id) = open_report(state, apply_ids).await else {
        if run_rows(state, apply_ids).await? {
            super::governance_gate::lapse_certifications(state).await;
        }
        return Ok(());
    };
    let all_done = rr::scope(
        ReportCtx {
            report_id,
            op: None,
        },
        run_rows(state, apply_ids),
    )
    .await?;
    if all_done {
        close_report(state, report_id).await;
        // L3-T5: certifications of entities this changed lapse.
        super::governance_gate::lapse_certifications(state).await;
    }
    Ok(())
}

/// The run's report, or `None` when nothing is left to run (a re-delivered
/// job) or the report could not be opened (logged; the run goes on).
async fn open_report(state: &EngineState, apply_ids: &[Uuid]) -> Option<Uuid> {
    match super::report::begin_run(state, apply_ids).await {
        Ok(report) => report,
        Err(error) => {
            tracing::error!(%error, ?apply_ids,
                "changeset apply: the release report could not be opened; the run goes on and \
                 its items land in a standalone report");
            None
        }
    }
}

/// Post-apply: ready + the one notification. Never fails the apply (its rows
/// are already `succeeded`).
async fn close_report(state: &EngineState, report_id: Uuid) {
    if let Err(error) = super::report::finish_run(state, report_id).await {
        tracing::error!(%error, %report_id,
            "changeset apply succeeded but its release report could not be marked ready; it \
             stays `building` and is still readable");
    }
}

/// The job's rows in order. `Ok(true)` when every row finished, `Ok(false)`
/// when the run stopped at a row claimed elsewhere.
async fn run_rows(state: &EngineState, apply_ids: &[Uuid]) -> Result<bool, AppError> {
    for id in apply_ids {
        let row = ledger::get(&state.base.db, *id)
            .await?
            .ok_or(AppError::NotFound)?;
        match row.status {
            s if s.is_done() => continue,
            ledger::ApplyStatus::Queued
            | ledger::ApplyStatus::Claimed
            | ledger::ApplyStatus::Applying => {}
            ledger::ApplyStatus::Planned | ledger::ApplyStatus::Failed => {
                tracing::warn!(
                    apply_id = %id,
                    status = row.status.as_str(),
                    "changeset apply: the run stops at a row that is not queued"
                );
                return Err(AppError::Conflict(
                    "changeset apply run stopped: a row is failed or no longer queued; later \
                     rows stay queued",
                ));
            }
            _ => {}
        }
        if let RunOutcome::NotClaimed = run_one(state, *id).await? {
            // Held by a live claim elsewhere: the rest of this run waits for
            // that worker (the dedup-keyed job will be delivered again).
            return Ok(false);
        }
    }
    Ok(true)
}

/// Why a run stopped.
struct Failure {
    message: String,
    error: AppError,
    lost_claim: bool,
}

impl From<AppError> for Failure {
    fn from(error: AppError) -> Self {
        Failure {
            message: error.to_string(),
            error,
            lost_claim: false,
        }
    }
}

/// Claims and applies one ledger row. Used by the job and, inline, by boot
/// and the replay tool. Inside a run's report scope (the job) the row writes
/// into that report; called on its own (boot, replay) it is a run of one row
/// with its own report.
pub async fn run_one(state: &EngineState, apply_id: Uuid) -> Result<RunOutcome, AppError> {
    if rr::current().is_some() {
        return run_one_row(state, apply_id).await;
    }
    let Some(report_id) = open_report(state, &[apply_id]).await else {
        return run_one_row(state, apply_id).await;
    };
    let outcome = rr::scope(
        ReportCtx {
            report_id,
            op: None,
        },
        run_one_row(state, apply_id),
    )
    .await?;
    if let RunOutcome::Applied(_) = outcome {
        close_report(state, report_id).await;
    }
    Ok(outcome)
}

/// Runs `f` with the ambient report naming operation `op` (no report: as is).
async fn in_op_scope<F: std::future::Future>(op: (Uuid, i32), f: F) -> F::Output {
    match rr::current() {
        Some(ctx) => {
            rr::scope(
                ReportCtx {
                    op: Some(op),
                    ..ctx
                },
                f,
            )
            .await
        }
        None => f.await,
    }
}

async fn run_one_row(state: &EngineState, apply_id: Uuid) -> Result<RunOutcome, AppError> {
    let worker = format!("pid-{}:{}", std::process::id(), Uuid::now_v7());
    let Some(row) = ledger::claim(&state.base.db, apply_id, &worker).await? else {
        tracing::info!(
            apply_id = %apply_id,
            "changeset apply: row is not claimable (claimed, finished, or not queued)"
        );
        return Ok(RunOutcome::NotClaimed);
    };

    let mut summary = RunSummary::default();
    let result = apply_claimed(state, &row, &mut summary).await;
    let result = match result {
        Ok(()) => {
            ledger::mark_succeeded(&state.base.db, apply_id).await?;
            match export_bundle(&state.base.db).await {
                Ok(bundle) => state
                    .base
                    .configuration_version
                    .store(Some(std::sync::Arc::new(bundle_hash(&bundle)))),
                Err(error) => tracing::warn!(
                    apply_id = %apply_id,
                    %error,
                    "changeset apply succeeded but re-computing the configuration hash failed"
                ),
            }
            tracing::info!(
                apply_id = %apply_id,
                changeset = %row.changeset_ref,
                phase = row.phase.as_str(),
                resumed_from = row.cursor,
                steps = summary.steps,
                written = summary.written,
                unchanged = summary.unchanged,
                "changeset apply succeeded"
            );
            Ok(RunOutcome::Applied(summary))
        }
        Err(failure) => {
            if !failure.lost_claim {
                ledger::mark_failed(&state.base.db, apply_id, &failure.message).await?;
            }
            tracing::warn!(
                apply_id = %apply_id,
                changeset = %row.changeset_ref,
                phase = row.phase.as_str(),
                steps = summary.steps,
                written = summary.written,
                error = %failure.message,
                "changeset apply failed"
            );
            Err(failure.error)
        }
    };
    if result.is_ok() || summary.written > 0 {
        crate::admin::notify_metadata_change(&state.base.redis).await;
    }
    result
}

/// The blocked operations of a stored plan, `seq op: reason`, for the
/// refusal message (so a pack author sees which operation to fix).
fn blocked_reasons(plan: &Value) -> String {
    let mut reasons: Vec<String> = plan
        .get("blocked")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|b| b.as_str().map(str::to_owned))
        .collect();
    for op in plan
        .get("operations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|op| op.get("action").and_then(Value::as_str) == Some("blocked"))
    {
        reasons.push(format!(
            "{} {}: {}",
            op.get("seq").and_then(Value::as_i64).unwrap_or_default(),
            op.get("op").and_then(Value::as_str).unwrap_or_default(),
            op.get("reason")
                .and_then(Value::as_str)
                .unwrap_or("blocked"),
        ));
    }
    reasons.join("; ")
}

/// The checks of a claimed row, then its steps from the cursor.
async fn apply_claimed(
    state: &EngineState,
    row: &LedgerRow,
    summary: &mut RunSummary,
) -> Result<(), Failure> {
    let doc = plan::parse_document(&row.document).map_err(|errs| {
        Failure::from(AppError::Validation(format!(
            "the stored changeset document no longer checks: {}",
            errs.join("; ")
        )))
    })?;
    // §5.4: the claimed row's checksum must be the stored document's.
    if doc.checksum != row.checksum || doc.id != row.changeset_id {
        return Err(AppError::Conflict(ledger::CHANGESET_CHECKSUM_MISMATCH).into());
    }
    if row.plan.get("applicable").and_then(Value::as_bool) != Some(true) {
        return Err(AppError::Validation(format!(
            "the plan of this changeset phase has blocked operations; it cannot be applied: {}",
            blocked_reasons(&row.plan)
        ))
        .into());
    }
    if row.phase == ApplyPhase::Contract && doc.phases().contains(&ApplyPhase::Expand) {
        let mut conn = state
            .base
            .db
            .acquire()
            .await
            .map_err(|e| Failure::from(AppError::internal(e)))?;
        let expand = ledger::find(&mut conn, doc.id, ApplyPhase::Expand).await?;
        if !expand.is_some_and(|e| e.status.is_done()) {
            return Err(AppError::Conflict(
                "a changeset's contract phase applies only after its expand phase succeeded",
            )
            .into());
        }
    }

    let ops = doc.ops_of(row.phase);
    let steps = steps_of(&ops);
    let start = usize::try_from(row.cursor).unwrap_or(0);
    let live = export_bundle(&state.base.db_migrator).await?;
    let mut ctx = Ctx {
        state,
        doc: &doc,
        live,
        overlay: HashMap::new(),
        actor: row.requested_by,
        registry_refreshed: false,
        entity_ids: HashMap::new(),
    };
    let mut applied_count = row.applied_count;
    for step in steps.iter().filter(|s| s.end > start) {
        let before = summary.written;
        if let Err(error) = ctx.run_step(step, &ops, summary).await {
            let first = ops.get(step.start).map_or(0, |o| o.seq);
            let message = format!(
                "operation {first} ({}): {error}",
                ops.get(step.start).map_or("?", |o| o.op.as_str())
            );
            return Err(Failure {
                message,
                error,
                lost_claim: false,
            });
        }
        summary.steps += 1;
        applied_count += i32::try_from(summary.written - before).unwrap_or(i32::MAX);
        let cursor = i32::try_from(step.end).unwrap_or(i32::MAX);
        ledger::advance(&state.base.db, row.id, cursor, applied_count)
            .await
            .map_err(|error| Failure {
                message: error.to_string(),
                lost_claim: matches!(error, AppError::Conflict(_)),
                error,
            })?;
    }
    Ok(())
}

// ── Steps ───────────────────────────────────────────────────────────────────

/// The parent a set-semantics child operation folds into.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Parent {
    Role(String),
    Profile(String),
    /// Q10-T5.
    PermissionSet(String),
    StateModel(String),
    Calendar(String),
}

fn parent_of(op: &DocOp) -> Option<Parent> {
    Some(match op.op {
        Op::UpsertRole
        | Op::GrantRolePrivilege
        | Op::RevokeRolePrivilege
        | Op::AddRoleGrantCondition
        | Op::RemoveRoleGrantCondition
        | Op::SetRoleEntityAccess
        | Op::ClearRoleEntityAccess
        | Op::AssignFieldProfile
        | Op::UnassignFieldProfile => Parent::Role(op.t("role").to_owned()),
        Op::UpsertFieldProfile | Op::SetFieldProfileField => {
            Parent::Profile(op.t("profile").to_owned())
        }
        Op::UpsertPermissionSet
        | Op::SetPermissionSetEntityAccess
        | Op::ClearPermissionSetEntityAccess
        | Op::GrantPermissionSetPrivilege
        | Op::RevokePermissionSetPrivilege => {
            Parent::PermissionSet(op.t("permission_set").to_owned())
        }
        Op::UpsertStateModel | Op::UpsertStateTransition | Op::RetireStateTransition => {
            Parent::StateModel(op.t("entity").to_owned())
        }
        Op::UpsertCalendar
        | Op::AddCalendarHoliday
        | Op::RemoveCalendarHoliday
        | Op::AddCalendarException
        | Op::RemoveCalendarException
        | Op::UpsertCalendarRule
        | Op::RetireCalendarRule
        | Op::UpsertCalendarSeason
        | Op::RetireCalendarSeason => Parent::Calendar(op.t("calendar").to_owned()),
        _ => return None,
    })
}

/// `ops[start..end]`, with the parent they fold into.
#[derive(Debug, PartialEq, Eq)]
struct Step {
    start: usize,
    end: usize,
    parent: Option<Parent>,
}

/// Contiguous runs on one parent become one step; everything else is a step
/// of its own. Deterministic, so a stored cursor always lands on a boundary.
fn steps_of(ops: &[&DocOp]) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let parent = parent_of(op);
        match steps.last_mut() {
            Some(last) if parent.is_some() && last.parent == parent => last.end = i + 1,
            _ => steps.push(Step {
                start: i,
                end: i + 1,
                parent,
            }),
        }
    }
    steps
}

struct Ctx<'a> {
    state: &'a EngineState,
    doc: &'a Document,
    /// Live metadata at the start of this run.
    live: Bundle,
    /// Parents this run already reconciled, by their folded definition.
    overlay: HashMap<Parent, Bundle>,
    actor: Option<Uuid>,
    registry_refreshed: bool,
    entity_ids: HashMap<String, Uuid>,
}

impl Ctx<'_> {
    fn migrator(&self) -> &DbPool {
        &self.state.base.db_migrator
    }

    fn layer(&self) -> Layer {
        self.doc.layer
    }

    /// The platform-bundle contract for the platform layer, the bundle
    /// contract for every other.
    fn policy(&self, is_customized: bool) -> ReconcilePolicy {
        if self.layer() == Layer::Platform {
            ReconcilePolicy::Seed
        } else {
            ReconcilePolicy::Bundle { is_customized }
        }
    }

    /// A removal always runs under the bundle contract: `Seed` never removes.
    fn removal_policy(is_customized: bool) -> ReconcilePolicy {
        ReconcilePolicy::Bundle { is_customized }
    }

    async fn entity_id(&mut self, logicalname: &str) -> Result<Uuid, AppError> {
        if let Some(id) = self.entity_ids.get(logicalname) {
            return Ok(*id);
        }
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(logicalname)
        .fetch_optional(self.migrator())
        .await
        .map_err(AppError::internal)?;
        let id = id.ok_or_else(|| {
            AppError::Validation(format!(
                "entity {logicalname} is not live on this deployment"
            ))
        })?;
        self.entity_ids.insert(logicalname.to_owned(), id);
        Ok(id)
    }

    async fn run_step(
        &mut self,
        step: &Step,
        ops: &[&DocOp],
        summary: &mut RunSummary,
    ) -> Result<(), AppError> {
        let slice = &ops[step.start..step.end];
        match &step.parent {
            Some(parent) => {
                let outcome = self.run_parent(parent, slice).await?;
                summary.record(outcome);
            }
            None => {
                for op in slice {
                    let doc_id = self.doc.id;
                    let outcome = in_op_scope((doc_id, op.seq), self.run_op(op)).await?;
                    summary.record(outcome);
                }
            }
        }
        Ok(())
    }

    /// Folds a run of child operations onto the parent (this run's result,
    /// else live, else the run's own upsert) and reconciles the parent.
    async fn run_parent(
        &mut self,
        parent: &Parent,
        ops: &[&DocOp],
    ) -> Result<ReconcileOutcome, AppError> {
        for op in ops {
            if let Some(reason) = plan::unsupported(op.op) {
                return Err(AppError::Validation(reason.into()));
            }
        }
        let seed = self.overlay.get(parent).cloned().unwrap_or_else(|| {
            Bundle::empty(Requires {
                platform_version: ">=0.0.0".into(),
                schema_version: 0,
                modules: Vec::new(),
                depends_on_bundles: Vec::new(),
            })
        });
        let mut fold = Fold::seeded(&self.live, seed);
        for op in ops {
            fold.apply(op).map_err(AppError::Validation)?;
        }
        let removal = ops.iter().any(|o| o.phase == ApplyPhase::Contract);
        let outcome = match parent {
            Parent::Role(name) => {
                let role = fold
                    .out
                    .roles
                    .iter()
                    .find(|r| &r.name == name)
                    .cloned()
                    .ok_or_else(|| AppError::Validation(format!("role {name} did not fold")))?;
                let pol = if removal {
                    Self::removal_policy(role.is_customized)
                } else {
                    self.policy(role.is_customized)
                };
                let desc = role_desc(&role);
                let db = self.migrator();
                let (role_id, outcome) = with_lock_retry!(
                    security::reconcile_role(
                        db,
                        &desc,
                        pol,
                        Some(derived_id(COMPONENT_ROLE, &role.name))
                    )
                    .await
                )?;
                if wrote(outcome) {
                    security::invalidate_role_holders(db, &self.state.base.security, role_id)
                        .await?;
                }
                outcome
            }
            Parent::Profile(name) => {
                let p = fold
                    .out
                    .field_security_profiles
                    .iter()
                    .find(|p| &p.name == name)
                    .cloned()
                    .ok_or_else(|| AppError::Validation(format!("profile {name} did not fold")))?;
                let pol = if removal {
                    Self::removal_policy(p.is_customized)
                } else {
                    self.policy(p.is_customized)
                };
                let desc = security::FieldSecurityProfileDesc {
                    name: p.name.clone(),
                    description: p.description.clone(),
                    fields: p
                        .fields
                        .iter()
                        .map(|f| security::ProfileFieldDesc {
                            entity: f.entity.clone(),
                            field: f.field.clone(),
                            can_read: f.can_read,
                            can_update: f.can_update,
                        })
                        .collect(),
                };
                let db = self.migrator();
                let (profile_id, outcome) = with_lock_retry!(
                    security::reconcile_field_security_profile(
                        db,
                        &desc,
                        pol,
                        Some(derived_id(COMPONENT_FIELD_SECURITY_PROFILE, &p.name))
                    )
                    .await
                )?;
                if wrote(outcome) {
                    security::invalidate_profile_holders(db, &self.state.base.security, profile_id)
                        .await?;
                }
                outcome
            }
            Parent::PermissionSet(name) => {
                let s = fold
                    .out
                    .permission_sets
                    .iter()
                    .find(|s| &s.name == name)
                    .cloned()
                    .ok_or_else(|| {
                        AppError::Validation(format!("permission set {name} did not fold"))
                    })?;
                let pol = if removal {
                    Self::removal_policy(s.is_customized)
                } else {
                    self.policy(s.is_customized)
                };
                let db = self.migrator();
                let (set_id, outcome) = with_lock_retry!(
                    attome_security::permission_sets::reconcile_permission_set(
                        db,
                        &s.desc(),
                        pol,
                        Some(derived_id(COMPONENT_PERMISSION_SET, &s.name))
                    )
                    .await
                )?;
                if wrote(outcome) {
                    attome_security::permission_sets::invalidate_set_holders(
                        db,
                        &self.state.base.security,
                        set_id,
                    )
                    .await?;
                }
                outcome
            }
            Parent::StateModel(entity) => {
                let m = fold
                    .out
                    .state_models
                    .iter()
                    .find(|m| &m.entity_logicalname == entity)
                    .cloned()
                    .ok_or_else(|| {
                        AppError::Validation(format!("state model of {entity} did not fold"))
                    })?;
                let pol = if removal {
                    Self::removal_policy(false)
                } else {
                    self.policy(false)
                };
                let desc = attome_state::reconcile::StateModelDesc {
                    entity_logicalname: m.entity_logicalname.clone(),
                    locked_states: m.locked_states.clone(),
                    reason_field: m.reason_field.clone(),
                    reasons: m.reasons.clone(),
                    name: m.name.clone(),
                    state_field: m.state_field.clone(),
                    initial_state: m.initial_state.clone(),
                    is_active: m.is_active,
                    transitions: m
                        .transitions
                        .iter()
                        .map(|t| attome_state::reconcile::TransitionDesc {
                            from_state: t.from_state.clone(),
                            to_state: t.to_state.clone(),
                            name: t.name.clone(),
                            required_privilege: t.required_privilege.clone(),
                            guard_expression: t.guard_expression.clone(),
                            entry_actions: t.entry_actions.clone(),
                            exit_actions: t.exit_actions.clone(),
                            display_order: t.display_order,
                            approval_plan: t.approval_plan.clone(),
                            pending_state: t.pending_state.clone(),
                            on_reject_state: t.on_reject_state.clone(),
                            auto_condition: t.auto_condition.clone(),
                        })
                        .collect(),
                };
                let (_, outcome) = with_lock_retry!(
                    attome_state::reconcile::reconcile_state_model(self.state, &desc, pol).await
                )?;
                outcome
            }
            Parent::Calendar(name) => {
                let c = fold
                    .out
                    .calendars
                    .iter()
                    .find(|c| &c.name == name)
                    .cloned()
                    .ok_or_else(|| AppError::Validation(format!("calendar {name} did not fold")))?;
                let pol = if removal {
                    Self::removal_policy(c.is_customized)
                } else {
                    self.policy(c.is_customized)
                };
                let (_, outcome) = with_lock_retry!(
                    crate::calendar_admin::reconcile_calendar(self.state, &c, pol).await
                )?;
                outcome
            }
        };
        self.overlay.insert(parent.clone(), fold.out);
        Ok(outcome)
    }

    /// One operation with no parent to fold into.
    async fn run_op(&mut self, op: &DocOp) -> Result<ReconcileOutcome, AppError> {
        if let Some(reason) = plan::unsupported(op.op) {
            return Err(AppError::Validation(reason.into()));
        }
        let state = self.state;
        let db = &state.base.db_migrator;
        let def_err = AppError::Validation;
        Ok(match op.op {
            Op::CreateEntity | Op::UpdateEntity => {
                let e: EntityDef = op.definition().map_err(def_err)?;
                let desc = EntityDesc {
                    logicalname: e.logicalname.clone(),
                    display_name: e.display_name.clone(),
                    primary_name_attribute: e.primary_name_attribute.clone(),
                    is_append_only: e.is_append_only,
                    is_audited: e.is_audited,
                    category: e.category.clone(),
                };
                let pol = self.policy(e.is_customized);
                let desired_id = derived_id(COMPONENT_ENTITY, &e.logicalname);
                let (id, outcome) = with_lock_retry!(
                    provision::reconcile_entity_with_id(db, &desc, pol, Some(desired_id)).await
                )?;
                self.entity_ids.insert(e.logicalname.clone(), id);
                if wrote(outcome) {
                    // What the admin create does after provisioning.
                    attome_security::entity_privileges::ensure_entity_privileges(
                        db,
                        &e.logicalname,
                        self.layer(),
                    )
                    .await?;
                    let (operation, event) = match outcome {
                        ReconcileOutcome::Created => {
                            (AuditOperation::Create, Some("entity_created"))
                        }
                        _ => (AuditOperation::Update, None),
                    };
                    self.audit(&e.logicalname, id, operation, event).await?;
                }
                // The admin create route also seeds the Active/Inactive list
                // views (L3 finding); a converted platform bundle says
                // `list_views: false` (its views are its own operations).
                let list_views = op
                    .arg("list_views")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if op.op == Op::CreateEntity && outcome == ReconcileOutcome::Created && list_views {
                    provision::ensure_entity_list_views(db, id, &e.logicalname, &e.display_name)
                        .await?;
                }
                // D-787 rule 7: the business key and reference-data flag the
                // definition carries (only those `args.changed` names, §3.9),
                // and the unique index that enforces the key.
                let declared =
                    crate::changeset::business_key::apply_declaration(state, id, op).await?;
                if declared && outcome == ReconcileOutcome::Unchanged {
                    ReconcileOutcome::Updated
                } else {
                    outcome
                }
            }
            Op::RetireEntity => {
                let name = op.t("entity");
                if !self.live.entities.iter().any(|e| e.logicalname == name) {
                    ReconcileOutcome::Unchanged
                } else {
                    let id = self.entity_id(name).await?;
                    let outcome = with_lock_retry!(provision::retire_entity(db, name).await)?;
                    if wrote(outcome) {
                        self.audit(name, id, AuditOperation::SoftDelete, None)
                            .await?;
                        report_customisation_impact(
                            state,
                            self.layer(),
                            &[("entity".to_owned(), name.to_owned())],
                            &[],
                        )
                        .await;
                    }
                    outcome
                }
            }
            Op::ReactivateEntity => {
                with_lock_retry!(provision::reactivate_entity(db, op.t("entity")).await)?
            }
            Op::SetEntityDomain => self.set_entity_domain(op).await?,
            Op::SetEntityMasterData => self.set_entity_master_data(op).await?,
            Op::AddField | Op::UpdateField => {
                let attr: AttributeDef = op.definition().map_err(def_err)?;
                self.apply_attribute(op.t("entity"), &attr).await?
            }
            Op::RetireField => {
                let entity = op.t("entity");
                let field = op.t("field");
                let live_has = self.live.entities.iter().any(|e| {
                    e.logicalname == entity && e.attributes.iter().any(|a| a.logicalname == field)
                });
                if !live_has {
                    ReconcileOutcome::Unchanged
                } else {
                    let entity_id = self.entity_id(entity).await?;
                    let outcome =
                        with_lock_retry!(provision::retire_attribute(db, entity_id, field).await)?;
                    if wrote(outcome) {
                        report_customisation_impact(
                            state,
                            self.layer(),
                            &[("attribute".to_owned(), format!("{entity}.{field}"))],
                            &[],
                        )
                        .await;
                    }
                    outcome
                }
            }
            Op::ReactivateField => {
                let entity_id = self.entity_id(op.t("entity")).await?;
                with_lock_retry!(
                    provision::reactivate_attribute(db, entity_id, op.t("field")).await
                )?
            }
            Op::UpsertRelationship => {
                let r: RelationshipDef = op.definition().map_err(def_err)?;
                self.entity_id(&r.entity_a).await?;
                self.entity_id(&r.entity_b).await?;
                let desc = provision::RelationshipDesc {
                    name: r.name.clone(),
                    entity_a: r.entity_a.clone(),
                    entity_b: r.entity_b.clone(),
                    role_a: r.role_a.clone(),
                    role_b: r.role_b.clone(),
                    cascade: attome_core::RelationshipCascade::from_db_str(&r.cascade),
                    is_active: r.is_active,
                };
                let pol = self.policy(false);
                let (_, outcome) = with_lock_retry!(
                    provision::reconcile_relationship(state, &desc, pol, None).await
                )?;
                outcome
            }
            Op::RetireRelationship => with_lock_retry!(
                provision::retire_relationship_by_name(state, op.t("relationship")).await
            )?,
            Op::SetLabel => {
                let display_name =
                    op.arg("display_name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            AppError::Validation("args.display_name must be a string".into())
                        })?;
                let description = op.arg("description").and_then(Value::as_str);
                let recording = Recording::Applying {
                    layer: self.layer(),
                };
                let mut tx = attome_db::tx::begin(&state.base.db).await?;
                crate::metadata_label_admin::write_label_in_tx(
                    &mut tx,
                    &recording,
                    op.t("object_kind"),
                    op.t("object_key"),
                    op.t("locale"),
                    display_name,
                    description,
                )
                .await?;
                attome_db::tx::commit(tx).await?;
                ReconcileOutcome::Updated
            }
            Op::UpsertQuery => {
                let mut q: QueryDef = op.definition().map_err(def_err)?;
                q.entity = op.query_entity();
                let pol = self.policy(q.is_customized);
                let desc = attome_records::query_admin::QueryDef {
                    entity: q.entity.clone(),
                    name: q.name.clone(),
                    sql: q.sql.clone(),
                    table_definition: q.table_definition.clone(),
                    required_privilege: q.required_privilege.clone(),
                    is_report: q.is_report,
                    entity_mappings: q
                        .entity_mappings
                        .iter()
                        .map(|m| attome_records::query_admin::QueryEntityMapping {
                            entity: m.entity.clone(),
                            id_column: m.id_column.clone(),
                        })
                        .collect(),
                };
                // A platform changeset is code-shipped content: the seed
                // posture skips the EXPLAIN containment lint, as a platform
                // bundle's queries do.
                let trusted = self.layer() == Layer::Platform;
                let actor = self.actor;
                let desired_id = derived_id(COMPONENT_QUERY, &q.key().display());
                let (_, outcome) = with_lock_retry!(
                    attome_records::query_admin::reconcile_query(
                        state,
                        &desc,
                        pol,
                        actor,
                        trusted,
                        Some(desired_id),
                    )
                    .await
                )?;
                outcome
            }
            Op::RetireQuery => {
                let entity = op.query_entity();
                with_lock_retry!(
                    attome_records::query_admin::retire_query(
                        state,
                        entity.as_deref(),
                        op.t("query")
                    )
                    .await
                )?
            }
            Op::UpsertView => {
                let v: ViewDef = op.definition().map_err(def_err)?;
                let pol = self.policy(v.is_customized);
                let desired_id = derived_id(COMPONENT_VIEW, &format!("{}.{}", v.entity, v.name));
                let (_, outcome) = with_lock_retry!(
                    crate::view_admin::reconcile_view(state, &v, pol, Some(desired_id)).await
                )?;
                outcome
            }
            Op::RetireView => with_lock_retry!(
                crate::view_admin::retire_view(state, op.t("entity"), op.t("view")).await
            )?,
            // Design §3.7: `columns` replaces `table_definition` whole. The
            // planner blocks a `sort` (`view_sort_in_query`); refuse it here
            // too rather than apply half the operation.
            Op::SetViewColumns => {
                if let Some(reason) = plan::view_sort_refusal(op) {
                    return Err(AppError::Validation(reason.into()));
                }
                let columns = op.arg("columns").ok_or_else(|| {
                    AppError::Validation("set_view_columns: args.columns is required".into())
                })?;
                let pol = self.policy(false);
                with_lock_retry!(
                    crate::view_admin::set_view_columns(
                        state,
                        op.t("entity"),
                        op.t("view"),
                        columns,
                        pol
                    )
                    .await
                )?
            }
            Op::UpsertRule => {
                let r: RuleDef = op.definition().map_err(def_err)?;
                let pol = self.policy(false);
                let (_, outcome) =
                    with_lock_retry!(crate::rule_admin::reconcile_rule(state, &r, pol).await)?;
                outcome
            }
            Op::RetireRule => with_lock_retry!(
                crate::rule_admin::retire_rule(state, op.t("entity"), op.t("rule")).await
            )?,
            Op::RetireStateModel => with_lock_retry!(
                attome_state::reconcile::retire_state_model(state, op.t("entity")).await
            )?,
            // Q10-T5: retiring a set ends its assignments too.
            Op::RetirePermissionSet => {
                let db = self.migrator();
                let name = op.t("permission_set");
                match attome_security::permission_sets::live_set(db, name).await? {
                    Some((set_id, _, _)) => {
                        let outcome = with_lock_retry!(
                            attome_security::permission_sets::retire_permission_set(db, name).await
                        )?;
                        attome_security::permission_sets::invalidate_set_holders(
                            db,
                            &state.base.security,
                            set_id,
                        )
                        .await?;
                        outcome
                    }
                    None => ReconcileOutcome::Unchanged,
                }
            }
            Op::UpsertSidebarItem => {
                let s: SidebarDef = op.definition().map_err(def_err)?;
                let pol = self.policy(s.is_customized);
                let desired_id = derived_id(COMPONENT_SIDEBAR, &s.path_display());
                let (_, outcome) = with_lock_retry!(
                    crate::sidebar::reconcile_sidebar_item(state, &s, pol, Some(desired_id)).await
                )?;
                outcome
            }
            Op::RetireSidebarItem => {
                let key = op.t("path");
                match self.live.sidebar.iter().find(|s| s.path_display() == key) {
                    None => ReconcileOutcome::Unchanged,
                    Some(item) => {
                        let path = item.path.clone();
                        with_lock_retry!(crate::sidebar::retire_sidebar_item(state, &path).await)?
                    }
                }
            }
            Op::UpsertApp => {
                let a: AppDef = op.definition().map_err(def_err)?;
                let pol = self.policy(false);
                let (_, outcome) =
                    with_lock_retry!(crate::app_admin::reconcile_app(state, &a, pol).await)?;
                outcome
            }
            Op::RetireApp => {
                with_lock_retry!(crate::app_admin::retire_app(state, op.t("app")).await)?
            }
            // B13-T7: brand themes, through the theme store the admin routes use.
            Op::UpsertTheme => {
                let def: crate::settings_admin::ThemeDef = op.definition().map_err(def_err)?;
                with_lock_retry!(crate::settings_admin::reconcile_theme(state, &def).await)?
            }
            Op::PublishTheme => with_lock_retry!(
                crate::settings_admin::publish_theme_scope(state, op.t("theme_scope")).await
            )?,
            Op::RetireTheme => with_lock_retry!(
                crate::settings_admin::retire_theme_scope(state, op.t("theme_scope")).await
            )?,
            Op::RetireCalendar => with_lock_retry!(
                crate::calendar_admin::retire_calendar(state, op.t("calendar")).await
            )?,
            Op::EnsurePrivilege => {
                let p: PrivilegeDef = op.definition().map_err(def_err)?;
                let desc = security::PrivilegeDesc {
                    key: p.key.clone(),
                    name: p.name.clone(),
                    description: p.description.clone(),
                };
                let desired_id = derived_id(COMPONENT_PRIVILEGE, &p.key);
                let (_, outcome) = with_lock_retry!(
                    security::reconcile_privilege(db, &desc, Some(desired_id), self.layer()).await
                )?;
                outcome
            }
            // Phase 2 field ops (D-788): the executors the admin routes use.
            Op::RenameField
            | Op::DeleteField
            | Op::ChangeFieldType
            | Op::AddChoiceValue
            | Op::RemoveChoiceValue => {
                let actor = self.actor.unwrap_or(Uuid::nil());
                let wrote = with_lock_retry!(
                    crate::field_changes::apply_field_op(
                        state,
                        self.layer(),
                        actor,
                        (self.doc.id, op.seq),
                        op.op,
                        op.t("entity"),
                        op.t("field"),
                        op.args.as_ref(),
                    )
                    .await
                )?;
                if wrote {
                    let key = format!("{}.{}", op.t("entity"), op.t("field"));
                    match op.op {
                        Op::RenameField => {
                            let new_name = op
                                .args
                                .as_ref()
                                .and_then(|a| a.get("new_name"))
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            report_customisation_impact(
                                state,
                                self.layer(),
                                &[],
                                &[(
                                    ("attribute".to_owned(), key),
                                    (
                                        "attribute".to_owned(),
                                        format!("{}.{new_name}", op.t("entity")),
                                    ),
                                )],
                            )
                            .await;
                        }
                        Op::DeleteField => {
                            report_customisation_impact(
                                state,
                                self.layer(),
                                &[("attribute".to_owned(), key)],
                                &[],
                            )
                            .await;
                        }
                        _ => {}
                    }
                    ReconcileOutcome::Updated
                } else {
                    ReconcileOutcome::Unchanged
                }
            }
            Op::UpsertRecord => {
                if !self.registry_refreshed {
                    // The record path resolves lookups against the in-memory
                    // registry; entities this boot provisioned are not in it
                    // until the doorbell (the bundle engine's same refresh).
                    let registry =
                        attome_core::meta_registry::build_registry(&state.base.db).await?;
                    state.entities.swap(registry);
                    self.registry_refreshed = true;
                }
                let actor = self.actor.unwrap_or(Uuid::nil());
                let entity = op.t("entity");
                let target_key = crate::changeset::business_key::target_key(op);
                let declared = provision::read_business_key(db, entity)
                    .await?
                    .and_then(|k| k.fields);
                // D-787 rule 7: the declared key only (the plan checked it;
                // re-checked here against the key as it is now).
                match crate::changeset::business_key::match_key(
                    declared.as_deref(),
                    &target_key,
                    self.layer(),
                )
                .map_err(AppError::Conflict)?
                {
                    Some(key_fields) => {
                        let values = op
                            .arg("values")
                            .and_then(Value::as_object)
                            .cloned()
                            .ok_or_else(|| {
                                AppError::Validation(format!(
                                    "operation {}: args.values must be an object",
                                    op.seq
                                ))
                            })?;
                        let changed = crate::changeset::business_key::record_changed(op);
                        crate::bundle::record_sets::apply_upsert_record(
                            state,
                            actor,
                            entity,
                            &key_fields,
                            &target_key,
                            &values,
                            changed.as_deref(),
                            (self.doc.id, op.seq),
                        )
                        .await?
                    }
                    // A platform changeset committed before declarations:
                    // the Phase 1 rule, matched on the op's own key fields.
                    None => {
                        let (key_fields, row) =
                            plan::record_parts(op).map_err(AppError::Validation)?;
                        crate::bundle::apply_record(state, actor, entity, &key_fields, &row).await?
                    }
                }
            }
            // Every child operation belongs to a parent step; reaching here
            // is a step-splitting defect.
            other => {
                return Err(AppError::internal(format!(
                    "changeset apply: operation {} ({}) has no executor",
                    op.seq,
                    other.as_str()
                )));
            }
        })
    }

    /// L1-T1: an entity's master-data settings, through the same function
    /// the entity PATCH uses.
    async fn set_entity_master_data(&mut self, op: &DocOp) -> Result<ReconcileOutcome, AppError> {
        let entity = op.t("entity").to_owned();
        let recording = Recording::Applying {
            layer: self.layer(),
        };
        let actor = self.actor.unwrap_or(Uuid::nil());
        let settings = attome_compliance::governance_admin::MasterData {
            is_master: op
                .arg("is_master")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            hub_style: op
                .arg("hub_style")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        let event = attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            AuditOperation::Update,
            actor,
            "entity_info",
            None,
        )
        .named("changeset.apply.set_entity_master_data");
        let changed = attome_compliance::governance_admin::set_entity_master_data(
            self.state, &recording, &entity, &settings, event,
        )
        .await?;
        Ok(if changed {
            ReconcileOutcome::Updated
        } else {
            ReconcileOutcome::Unchanged
        })
    }

    async fn set_entity_domain(&mut self, op: &DocOp) -> Result<ReconcileOutcome, AppError> {
        let state = self.state;
        let entity = op.t("entity").to_owned();
        let recording = Recording::Applying {
            layer: self.layer(),
        };
        let actor = self.actor.unwrap_or(Uuid::nil());
        let event = || {
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                AuditOperation::Update,
                actor,
                "entity_info",
                None,
            )
            .named("changeset.apply.set_entity_domain")
        };
        match op.arg("domain").and_then(Value::as_str) {
            Some(domain) => {
                let id: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM data_domain WHERE name = $1 AND is_deleted = false \
                     ORDER BY created_at LIMIT 1",
                )
                .bind(domain)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                let id = id.ok_or_else(|| {
                    AppError::Validation(format!("data domain \"{domain}\" does not exist here"))
                })?;
                attome_compliance::governance_admin::set_entity_domain(
                    state,
                    &recording,
                    Some(id),
                    std::slice::from_ref(&entity),
                    event(),
                )
                .await?;
            }
            None => {
                let current: Option<Option<Uuid>> = sqlx::query_scalar(
                    "SELECT domain_ref FROM entity_info WHERE logicalname = $1 \
                     AND (is_active IS NULL OR is_active = true)",
                )
                .bind(&entity)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                if let Some(Some(domain)) = current {
                    attome_compliance::governance_admin::clear_entity_domain(
                        state,
                        &recording,
                        domain,
                        &entity,
                        event(),
                    )
                    .await?;
                }
            }
        }
        Ok(ReconcileOutcome::Updated)
    }

    /// `bundle/apply.rs::apply_attribute`, for one field definition: the
    /// reconcile, the size-gated contract deferral, and the index sync.
    async fn apply_attribute(
        &mut self,
        entity: &str,
        attr: &AttributeDef,
    ) -> Result<ReconcileOutcome, AppError> {
        let entity_id = self.entity_id(entity).await?;
        let db = &self.state.base.db_migrator;
        let had_index: bool = sqlx::query_scalar(
            "SELECT COALESCE(is_sortable, false) OR COALESCE(is_filterable, false) \
                    OR COALESCE(\"type\", 3) = 11 \
             FROM attribute_info \
             WHERE entity_ref = $1 AND logicalname = $2 AND COALESCE(is_active, true) = true",
        )
        .bind(entity_id)
        .bind(&attr.logicalname)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .unwrap_or(false);
        let desc = attribute_desc(attr);
        let pol = self.policy(attr.is_customized);
        let desired_id = derived_id(
            COMPONENT_ATTRIBUTE,
            &format!("{entity}.{}", attr.logicalname),
        );
        let first = with_lock_retry!(
            provision::reconcile_attribute_with_id(db, entity_id, &desc, pol, Some(desired_id))
                .await
        );
        let (attr_id, outcome) = match first {
            Ok(done) => done,
            Err(AppError::Conflict(msg)) if msg == SCHEMA_CHANGE_NEEDS_PLAN => {
                self.defer_contract_change(entity_id, entity, attr, pol)
                    .await?
            }
            Err(e) => return Err(e),
        };
        if wrote(outcome) {
            let (operation, event) = match outcome {
                ReconcileOutcome::Created => (AuditOperation::Create, Some("attribute_created")),
                _ => (AuditOperation::Update, None),
            };
            self.audit(entity, attr_id, operation, event).await?;
        }
        // A7-T3: a lookup is always indexed.
        let wanted = attr.is_sortable
            || attr.is_filterable
            || attr.field_type.eq_ignore_ascii_case("lookup");
        if wrote(outcome) && had_index != wanted {
            let db = &self.state.base.db_migrator;
            if provision::attribute_index_requires_async(
                db,
                entity,
                ATTRIBUTE_INDEX_INLINE_ROW_LIMIT,
            )
            .await?
            {
                attome_jobs::enqueue_dedup(
                    db,
                    attome_core::jobs::EngineJob::BuildAttributeIndex {
                        entity_logicalname: entity.to_owned(),
                        field_logicalname: attr.logicalname.clone(),
                    },
                    &format!("attribute-index:{entity}:{}", attr.logicalname),
                )
                .await
                .map_err(AppError::internal)?;
            } else {
                provision::sync_attribute_index(
                    self.state.base.config.as_ref(),
                    entity,
                    &attr.logicalname,
                    wanted,
                )
                .await?;
            }
        }
        Ok(outcome)
    }

    /// `bundle/apply.rs::defer_contract_change`: everything but the
    /// `is_required`/`max_length` contract now, the contract through
    /// `ApplySchemaChangePlan`.
    async fn defer_contract_change(
        &mut self,
        entity_id: Uuid,
        entity: &str,
        attr: &AttributeDef,
        pol: ReconcilePolicy,
    ) -> Result<(Uuid, ReconcileOutcome), AppError> {
        let db = &self.state.base.db_migrator;
        let previous: Option<(bool, Option<i32>)> = sqlx::query_as(
            "SELECT COALESCE(required, false), max_length FROM attribute_info \
             WHERE entity_ref = $1 AND logicalname = $2 \
             ORDER BY (is_active IS NULL OR is_active = true) DESC, created_at DESC NULLS LAST, \
                      id DESC LIMIT 1",
        )
        .bind(entity_id)
        .bind(&attr.logicalname)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let (previous_required, previous_max_length) = previous.unwrap_or((false, None));
        let mut relaxed = attribute_desc(attr);
        relaxed.is_required = previous_required;
        relaxed.max_length = previous_max_length;
        let desired_id = derived_id(
            COMPONENT_ATTRIBUTE,
            &format!("{entity}.{}", attr.logicalname),
        );
        let (attr_id, outcome) = with_lock_retry!(
            provision::reconcile_attribute_with_id(db, entity_id, &relaxed, pol, Some(desired_id))
                .await
        )?;
        if previous_required == attr.is_required && previous_max_length == attr.max_length {
            return Ok((attr_id, outcome));
        }
        let created_by = self.actor.unwrap_or(Uuid::nil());
        let is_multi = provision::is_multi_valued(&attr.field_type, attr.options.as_ref());
        with_lock_retry!(
            provision::queue_contract_change(
                db,
                provision::SchemaChangePlanRequest {
                    entity_id,
                    attribute_id: attr_id,
                    entity_logicalname: entity,
                    field_logicalname: &attr.logicalname,
                    field_type: &attr.field_type,
                    target_required: attr.is_required,
                    target_max_length: attr.max_length,
                    previous_required,
                    previous_max_length,
                    backfill_default: None,
                    is_multi,
                    created_by,
                },
            )
            .await
        )?;
        tracing::info!(
            entity = %entity,
            field = %attr.logicalname,
            "changeset apply: field contract change crosses the size gate; queued ApplySchemaChangePlan"
        );
        let outcome = match outcome {
            ReconcileOutcome::Created => ReconcileOutcome::Created,
            _ => ReconcileOutcome::Updated,
        };
        Ok((attr_id, outcome))
    }

    /// The `Entity` audit event an equivalent admin write gets, with
    /// `AuditSource::Import`. Not for the platform layer: platform
    /// definitions are the declarative boot seed, which never audited its own
    /// provisioning (`bundle/apply.rs::audit_entity_change` has the reason
    /// this is load-bearing on a fresh database).
    async fn audit(
        &self,
        entity_name: &str,
        record_id: Uuid,
        operation: AuditOperation,
        event_name: Option<&str>,
    ) -> Result<(), AppError> {
        if self.layer() == Layer::Platform {
            return Ok(());
        }
        let actor = self.actor.unwrap_or(Uuid::nil());
        let (user_context, organization_ref) = fetch_audit_ctx(self.state, actor).await;
        let mut tx = attome_db::tx::begin(&self.state.base.db_migrator).await?;
        audit_service(self.state)
            .write_in_tx(
                &mut tx,
                AuditEvent {
                    organization_ref,
                    category: AuditCategory::Entity,
                    entity_name: Some(entity_name.to_owned()),
                    record_id: Some(record_id),
                    operation,
                    version_before: None,
                    version_after: None,
                    user_context,
                    changed_on: Utc::now(),
                    source: AuditSource::Import,
                    request_context: AuditRequestContext::default(),
                    correlation_id: None,
                    batch_id: None,
                    event_name: event_name.map(str::to_owned),
                    event_comment: Some(format!("changeset {}", self.doc.reference())),
                    changed_fields: vec![],
                    snapshot_json: None,
                },
            )
            .await?;
        attome_db::tx::commit(tx).await
    }
}

fn role_desc(r: &RoleDef) -> security::RoleDesc {
    security::RoleDesc {
        name: r.name.clone(),
        description: r.description.clone(),
        access_level: r.access_level,
        position_hierarchy_enabled: r.position_hierarchy_enabled,
        privileges: r
            .privileges
            .iter()
            .map(|g| security::RoleGrantDesc {
                privilege: g.privilege.clone(),
                conditions: g
                    .conditions
                    .iter()
                    .map(|c| security::GrantConditionDesc {
                        field: c.field.clone(),
                        operator: c.operator,
                        value: c.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
        entity_access: r
            .entity_access
            .iter()
            .map(|a| security::RoleEntityAccessDesc {
                entity: a.entity.clone(),
                read_access_level: a.read_access_level,
                write_access_level: a.write_access_level,
                delete_access_level: a.delete_access_level,
                read_owner_visible: a.read_owner_visible,
                write_owner_visible: a.write_owner_visible,
                delete_owner_visible: a.delete_owner_visible,
                operations: a.operations,
            })
            .collect(),
        field_security_profiles: r.field_security_profiles.clone(),
    }
}

fn attribute_desc(a: &AttributeDef) -> AttributeDesc {
    AttributeDesc {
        logicalname: a.logicalname.clone(),
        display_name: a.display_name.clone(),
        field_type: a.field_type.clone(),
        is_required: a.is_required,
        is_sensitive: a.is_sensitive,
        is_write_restricted: Some(a.is_write_restricted),
        is_sortable: a.is_sortable,
        is_filterable: a.is_filterable,
        lookup_entity: a.lookup_entity.clone(),
        options: a.options.clone(),
        max_length: a.max_length,
        on_target_delete: Some(a.on_target_delete.clone()),
        data_classification: Some(a.data_classification.clone()),
        purpose: a.purpose.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn op(seq: i32, name: &str, target: Value) -> DocOp {
        let op = Op::parse(name).expect("op");
        DocOp {
            seq,
            op,
            phase: if op.phase().as_str() == "contract" {
                ApplyPhase::Contract
            } else {
                ApplyPhase::Expand
            },
            target: target.as_object().cloned().unwrap_or_default(),
            args: None,
        }
    }

    #[test]
    fn contiguous_child_operations_fold_into_one_step_per_parent() {
        let ops = [
            op(1, "ensure_privilege", json!({ "privilege": "a.read" })),
            op(2, "upsert_role", json!({ "role": "R" })),
            op(
                3,
                "grant_role_privilege",
                json!({ "role": "R", "privilege": "a.read" }),
            ),
            op(
                4,
                "assign_field_profile",
                json!({ "role": "R", "profile": "P" }),
            ),
            op(5, "upsert_role", json!({ "role": "S" })),
            op(6, "upsert_view", json!({ "entity": "a", "view": "V" })),
            op(7, "upsert_view", json!({ "entity": "a", "view": "W" })),
            op(8, "upsert_state_model", json!({ "entity": "a" })),
            op(
                9,
                "upsert_state_transition",
                json!({ "entity": "a", "transition": "x->y" }),
            ),
        ];
        let refs: Vec<&DocOp> = ops.iter().collect();
        let steps = steps_of(&refs);
        let spans: Vec<(usize, usize)> = steps.iter().map(|s| (s.start, s.end)).collect();
        assert_eq!(spans, [(0, 1), (1, 4), (4, 5), (5, 6), (6, 7), (7, 9)]);
        assert_eq!(steps[1].parent, Some(Parent::Role("R".into())));
        assert_eq!(steps[3].parent, None);
        assert_eq!(steps[5].parent, Some(Parent::StateModel("a".into())));
    }

    #[test]
    fn every_stage_one_op_has_an_executor_or_a_stated_refusal() {
        for op in Op::ALL {
            if op.stage() != 1 || plan::unsupported(*op).is_some() {
                continue;
            }
            let dummy = DocOp {
                seq: 1,
                op: *op,
                phase: ApplyPhase::Expand,
                target: serde_json::Map::new(),
                args: None,
            };
            // A parent-folded op, or one `run_op` matches explicitly.
            let handled_by_run_op = !matches!(
                op,
                Op::GrantRolePrivilege
                    | Op::RevokeRolePrivilege
                    | Op::AddRoleGrantCondition
                    | Op::RemoveRoleGrantCondition
                    | Op::SetRoleEntityAccess
                    | Op::ClearRoleEntityAccess
                    | Op::AssignFieldProfile
                    | Op::UnassignFieldProfile
                    | Op::UpsertRole
                    | Op::UpsertFieldProfile
                    | Op::SetFieldProfileField
                    | Op::UpsertPermissionSet
                    | Op::SetPermissionSetEntityAccess
                    | Op::ClearPermissionSetEntityAccess
                    | Op::GrantPermissionSetPrivilege
                    | Op::RevokePermissionSetPrivilege
                    | Op::UpsertStateModel
                    | Op::UpsertStateTransition
                    | Op::RetireStateTransition
                    | Op::UpsertCalendar
                    | Op::AddCalendarHoliday
                    | Op::RemoveCalendarHoliday
                    | Op::AddCalendarException
                    | Op::RemoveCalendarException
                    | Op::UpsertCalendarRule
                    | Op::RetireCalendarRule
                    | Op::UpsertCalendarSeason
                    | Op::RetireCalendarSeason
            );
            assert_eq!(
                parent_of(&dummy).is_none(),
                handled_by_run_op,
                "{}",
                op.as_str()
            );
        }
    }
}
