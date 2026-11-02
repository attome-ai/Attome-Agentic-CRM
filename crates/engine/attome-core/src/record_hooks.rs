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
//! A rejection answers 422 with the hook's message. An in-transaction hook
//! must not reach the network (the extension runtime refuses its HTTP calls
//! there); work after the commit goes through a job (`after_commit`, not run
//! here).

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::state::EngineState;

/// Where in the write a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookStage {
    BeforeValidation,
    BeforeSave,
    AfterSave,
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
            HookOutcome::Change(set) if stage != HookStage::AfterSave => {
                let mut next = values.clone();
                next.extend(set);
                changed = Some(next);
            }
            HookOutcome::Change(_) => {
                tracing::warn!(
                    hook = hook.name(),
                    entity = event.entity,
                    "an after-save hook asked to change values; ignored"
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
