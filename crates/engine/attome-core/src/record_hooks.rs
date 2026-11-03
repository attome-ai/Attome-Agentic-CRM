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
//! Y10-T4: inside a bulk operation or an import ([`in_bulk`]), a write's
//! after-commit payload goes to `record_hook_outbox` (migration 0394) in the
//! write's own transaction instead of one job per write, so it exists
//! exactly when the write commits. [`drain_outbox`] then hands each
//! after-commit hook up to [`BATCH_SIZE`] records of one entity per call
//! ([`RecordHook::run_batch`]): it claims a batch, runs the hooks outside
//! any transaction, and deletes the batch once they ran, so a crash in
//! between delivers the batch again (at least once; a claim older than ten
//! minutes is taken again). The bulk and import workers drain when they
//! finish, and [`OUTBOX_DRAIN_JOB`] drains every minute as the backstop.
//!
//! A rejection answers 422 with the hook's message, in the caller's
//! language when the hook wrote it in more than one ([`HookRejection`]). An in-transaction hook
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
    Reject(HookRejection),
}

/// Y10-T2: why a hook refused a save: the English message, and the same
/// message in each other language the hook wrote it in (`ar`), which the
/// caller reads when that is its language.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HookRejection {
    pub message: String,
    pub translations: std::collections::BTreeMap<String, String>,
}

impl HookRejection {
    /// The 422 the save answers: a plain validation error, or one carrying
    /// its translations.
    pub fn into_error(self) -> AppError {
        if self.translations.is_empty() {
            AppError::Validation(self.message)
        } else {
            AppError::Translated {
                message: self.message,
                translations: self.translations,
            }
        }
    }
}

impl From<&str> for HookRejection {
    fn from(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            translations: Default::default(),
        }
    }
}

impl From<String> for HookRejection {
    fn from(message: String) -> Self {
        Self {
            message,
            translations: Default::default(),
        }
    }
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

/// What a batch call answers: nothing to change (it runs after the commit).
pub type BatchFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>>;

/// Y10-T4: records one after-commit hook call takes in a bulk operation.
pub const BATCH_SIZE: i64 = 500;

/// One hook on one entity's writes.
pub trait RecordHook: Send + Sync + 'static {
    /// A stable name, for logs.
    fn name(&self) -> &str;
    /// The entity it watches.
    fn entity(&self) -> &str;
    /// Whether it runs on `entity`'s writes; by default, its
    /// [`Self::entity`]. A hook serving several entities (the published
    /// extensions) answers from its own list.
    fn watches(&self, entity: &str) -> bool {
        self.entity() == entity
    }
    fn stage(&self) -> HookStage;
    /// Lower runs first; hooks of the same order run in registration order.
    fn order(&self) -> i32 {
        0
    }
    fn run<'a>(&'a self, state: &'a EngineState, event: HookEvent<'a>) -> HookFuture<'a>;
    /// Y10-T4: an after-commit hook's call for a batch of committed writes
    /// of one entity (up to [`BATCH_SIZE`]). By default, [`Self::run`] for
    /// each in turn; a hook that can take them at once overrides it. A
    /// rejection is only logged, as for one write.
    fn run_batch<'a>(
        &'a self,
        state: &'a EngineState,
        events: &'a [HookEvent<'a>],
    ) -> BatchFuture<'a> {
        Box::pin(async move {
            for event in events {
                match self.run(state, *event).await {
                    Ok(HookOutcome::Reject(rejection)) => tracing::warn!(
                        hook = self.name(),
                        entity = event.entity,
                        message = %rejection.message,
                        "an after-commit hook rejected a committed write; ignored"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        hook = self.name(),
                        entity = event.entity,
                        %error,
                        "an after-commit hook failed on one write of a batch"
                    ),
                }
            }
            Ok(())
        })
    }
}

tokio::task_local! {
    /// Set while a bulk operation or an import runs ([`in_bulk`]).
    static IN_BULK: bool;
}

/// Y10-T4: runs `f` as a bulk operation: its writes' after-commit hooks are
/// batched through the outbox.
pub async fn in_bulk<F: Future>(f: F) -> F::Output {
    IN_BULK.scope(true, f).await
}

fn bulk_now() -> bool {
    IN_BULK.try_with(|b| *b).unwrap_or(false)
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
        .filter(|h| h.stage() == stage && h.watches(event.entity))
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
            HookOutcome::Reject(rejection) if stage == HookStage::AfterCommit => {
                // The write is committed; there is nothing to refuse.
                tracing::warn!(
                    hook = hook.name(),
                    entity = event.entity,
                    message = %rejection.message,
                    "an after-commit hook rejected a committed write; ignored"
                );
            }
            HookOutcome::Reject(rejection) => {
                tracing::info!(
                    hook = hook.name(),
                    entity = event.entity,
                    ?stage,
                    "write rejected by a hook"
                );
                return Err(rejection.into_error());
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
        .any(|h| h.stage() == stage && h.watches(entity))
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
    // Y10-T4: in a bulk operation, to the outbox, batched by the drain.
    if bulk_now() {
        sqlx::query("INSERT INTO record_hook_outbox (id, entity, payload) VALUES ($1, $2, $3)")
            .bind(Uuid::now_v7())
            .bind(&payload.entity)
            .bind(serde_json::to_value(&payload).map_err(AppError::internal)?)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
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

/// Y10-T4: the job that drains the outbox, every minute.
pub const OUTBOX_DRAIN_JOB: attome_jobs::JobType =
    attome_jobs::JobType::new("record_hook_outbox_drain", 1);

/// Batches one drain takes before it yields.
const DRAIN_BATCHES: usize = 20;

/// Runs every after-commit hook of `entity` on `payloads` (one batch).
pub async fn run_after_commit_batch(
    state: &EngineState,
    entity: &str,
    payloads: &[AfterCommitPayload],
) {
    let mut hooks: Vec<_> = state
        .record_hooks
        .iter()
        .filter(|h| h.stage() == HookStage::AfterCommit && h.watches(entity))
        .collect();
    hooks.sort_by_key(|h| h.order());
    let events: Vec<HookEvent<'_>> = payloads
        .iter()
        .map(|p| HookEvent {
            entity: &p.entity,
            record_id: Some(p.record_id),
            is_create: p.is_create,
            values: &p.values,
            previous: p.previous.as_ref(),
            actor: p.actor,
        })
        .collect();
    let depth = current_depth();
    for hook in hooks {
        if let Err(error) = HOOK_DEPTH
            .scope(depth + 1, hook.run_batch(state, &events))
            .await
        {
            tracing::warn!(hook = hook.name(), entity, %error, "an after-commit batch failed");
        }
    }
}

/// Y10-T4: delivers the outbox in batches of up to [`BATCH_SIZE`] records of
/// one entity. Returns how many records it delivered.
pub async fn drain_outbox(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let mut delivered = 0;
    for _ in 0..DRAIN_BATCHES {
        let claimed: Vec<(Uuid, String, Value)> = sqlx::query_as(
            "WITH next AS ( \
                 SELECT entity FROM record_hook_outbox \
                  WHERE claimed_at IS NULL OR claimed_at < now() - interval '10 minutes' \
                  ORDER BY created_at LIMIT 1), \
             pick AS ( \
                 SELECT o.id FROM record_hook_outbox o, next \
                  WHERE o.entity = next.entity \
                    AND (o.claimed_at IS NULL OR o.claimed_at < now() - interval '10 minutes') \
                  ORDER BY o.created_at LIMIT $1 FOR UPDATE OF o SKIP LOCKED) \
             UPDATE record_hook_outbox o SET claimed_at = now() FROM pick \
              WHERE o.id = pick.id RETURNING o.id, o.entity, o.payload",
        )
        .bind(BATCH_SIZE)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(entity) = claimed.first().map(|c| c.1.clone()) else {
            break;
        };
        let ids: Vec<Uuid> = claimed.iter().map(|c| c.0).collect();
        let payloads: Vec<AfterCommitPayload> = claimed
            .into_iter()
            .filter_map(|(id, _, payload)| match serde_json::from_value(payload) {
                Ok(payload) => Some(payload),
                Err(error) => {
                    tracing::error!(%id, %error, "an outbox payload does not read; dropped");
                    None
                }
            })
            .collect();
        run_after_commit_batch(state, &entity, &payloads).await;
        sqlx::query("DELETE FROM record_hook_outbox WHERE id = ANY($1)")
            .bind(&ids)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        delivered += payloads.len();
    }
    Ok(delivered)
}
