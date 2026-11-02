//! Y10-T2: hook stages in the record write pipeline. An engine (and, through
//! `attome-extension`, customer WebAssembly) registers a [`RecordHook`] on
//! the `EngineSystem` builder; the generic create and update paths
//! (`attome_records::entity_mutation`) call every hook of the written
//! entity at each stage, in [`RecordHook::order`] after the built-in rules:
//!
//! - [`HookStage::BeforeValidation`]: before the business rules judge the
//!   values; may change them or reject the save.
//! - [`HookStage::BeforeSave`]: after the rules, just before the row is
//!   written; may change the values or reject the save.
//! - [`HookStage::AfterSave`]: in the transaction, after the row is written;
//!   may reject (the whole write rolls back) but not change values.
//!
//! - [`HookStage::AfterCommit`]: once the write has committed, in a job
//!   ([`AFTER_COMMIT_JOB`]) with the stored row; it cannot undo the write, so
//!   a rejection there is only logged. This is the stage for the network.
//!
//! A rejection answers 422 with the hook's message. An in-transaction hook
//! must not reach the network (the extension runtime refuses its HTTP calls
//! there); work after the commit goes through the `after_commit` job.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::state::EngineState;

/// Where in the write a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookStage {
    BeforeValidation,
    BeforeSave,
    AfterSave,
    AfterCommit,
}

impl HookStage {
    /// Whether a hook at this stage may change the values being written.
    pub fn may_change(self) -> bool {
        matches!(self, Self::BeforeValidation | Self::BeforeSave)
    }
}

/// One write, as a hook sees it.
#[derive(Debug, Clone, Copy)]
pub struct HookEvent<'a> {
    pub entity: &'a str,
    /// `None` on a create before the row exists.
    pub record_id: Option<Uuid>,
    pub is_create: bool,
    /// The values being written: the whole record on a create, the changed
    /// fields on an update; after the save, the stored row.
    pub values: &'a Map<String, Value>,
    /// The row before an update, after the save.
    pub previous: Option<&'a Map<String, Value>>,
    pub actor: Option<Uuid>,
}

/// What a hook decided.
#[derive(Debug, Clone, PartialEq)]
pub enum HookOutcome {
    Continue,
    /// Values to set (a `before` stage only; ignored after the save).
    Change(Map<String, Value>),
    /// Refuse the save with this message (shown to the person).
    Reject(String),
}

/// Y10-T4: a write made by a hook may run hooks of its own; past this
/// depth the write is refused, so two hooks cannot call each other forever.
pub const MAX_HOOK_DEPTH: u32 = 8;

tokio::task_local! {
    /// How many hook calls enclose the current write on this task.
    static HOOK_DEPTH: u32;
}

/// The hook depth of the current task (0 outside any hook).
pub fn current_depth() -> u32 {
    HOOK_DEPTH.try_with(|d| *d).unwrap_or(0)
}

pub type HookFuture<'a> = Pin<Box<dyn Future<Output = Result<HookOutcome, AppError>> + Send + 'a>>;

/// One hook on one entity's writes.
pub trait RecordHook: Send + Sync + 'static {
    /// A stable name, for logs.
    fn name(&self) -> &str;
    /// The entity it watches.
    fn entity(&self) -> &str;
    fn stage(&self) -> HookStage;
    /// Lower runs first; hooks of the same order run in registration order.
    fn order(&self) -> i32 {
        0
    }
    fn run<'a>(&'a self, state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a>;
}

/// Runs every hook of `event.entity` at `stage`, in order. Answers the values
/// as changed by `before` hooks (`None` when no hook changed anything), or a
/// 422 at the first rejection.
pub async fn run_stage(
    state: &EngineState,
    stage: HookStage,
    event: HookEvent<'_>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let mut hooks: Vec<_> = state
        .record_hooks
        .iter()
        .filter(|h| h.stage() == stage && h.entity() == event.entity)
        .collect();
    if hooks.is_empty() {
        return Ok(None);
    }
    hooks.sort_by_key(|h| h.order());
    let depth = current_depth();
    if depth >= MAX_HOOK_DEPTH {
        tracing::warn!(
            entity = event.entity,
            depth,
            "hook-triggered writes nested too deep"
        );
        return Err(AppError::Validation(format!(
            "hooks triggered writes {MAX_HOOK_DEPTH} levels deep; stopped to prevent a loop"
        )));
    }
    let mut changed: Option<Map<String, Value>> = None;
    for hook in hooks {
        let values = changed.as_ref().unwrap_or(event.values);
        let outcome = HOOK_DEPTH
            .scope(depth + 1, hook.run(state, HookEvent { values, ..event }))
            .await?;
        match outcome {
            HookOutcome::Continue => {}
            HookOutcome::Change(set) if stage.may_change() => {
                let mut next = values.clone();
                next.extend(set);
                changed = Some(next);
            }
            HookOutcome::Change(_) => {
                tracing::warn!(
                    hook = hook.name(),
                    entity = event.entity,
                    ?stage,
                    "a hook after the save asked to change values; ignored"
                );
            }
            HookOutcome::Reject(message) if stage == HookStage::AfterCommit => {
                // The write is committed; there is nothing to refuse.
                tracing::warn!(
                    hook = hook.name(),
                    entity = event.entity,
                    %message,
                    "an after-commit hook rejected a committed write; ignored"
                );
            }
            HookOutcome::Reject(message) => {
                tracing::info!(
                    hook = hook.name(),
                    entity = event.entity,
                    ?stage,
                    "write rejected by a hook"
                );
                return Err(AppError::Validation(message));
            }
        }
    }
    Ok(changed)
}

/// Whether `entity` has any hook at `stage`.
pub fn has_hooks(state: &EngineState, entity: &str, stage: HookStage) -> bool {
    state
        .record_hooks
        .iter()
        .any(|h| h.stage() == stage && h.entity() == entity)
}

/// The job that runs [`HookStage::AfterCommit`] hooks. Few attempts: a hook
/// that keeps failing is a defect to read in the dead letters, not to retry.
pub const AFTER_COMMIT_JOB: attome_jobs::JobType = attome_jobs::JobType {
    max_attempts: 3,
    ..attome_jobs::JobType::new("record_hook_after_commit", 1)
};

/// One committed write, carried to the after-commit hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterCommitPayload {
    pub entity: String,
    pub record_id: Uuid,
    pub is_create: bool,
    /// The stored row.
    pub values: Map<String, Value>,
    /// The row before an update.
    pub previous: Option<Map<String, Value>>,
    pub actor: Option<Uuid>,
}

/// Queues the after-commit hooks of a write in its own transaction, so the
/// job exists exactly when the write commits. Nothing is queued when the
/// entity has no such hook.
pub async fn enqueue_after_commit(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    payload: AfterCommitPayload,
) -> Result<(), AppError> {
    if !has_hooks(state, &payload.entity, HookStage::AfterCommit) {
        return Ok(());
    }
    let job = attome_jobs::RegisteredJob {
        name: AFTER_COMMIT_JOB.name.to_owned(),
        version: AFTER_COMMIT_JOB.version,
        payload: serde_json::to_value(&payload).map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_in_tx(tx, crate::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)
}

/// Runs the after-commit hooks of one committed write (the job's body).
pub async fn run_after_commit(
    state: &EngineState,
    payload: &AfterCommitPayload,
) -> Result<(), AppError> {
    run_stage(
        state,
        HookStage::AfterCommit,
        HookEvent {
            entity: &payload.entity,
            record_id: Some(payload.record_id),
            is_create: payload.is_create,
            values: &payload.values,
            previous: payload.previous.as_ref(),
            actor: payload.actor,
        },
    )
    .await
    .map(|_| ())
}
