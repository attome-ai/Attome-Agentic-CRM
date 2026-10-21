//! E8-T1 — the seam through which an engine adds workflow steps and
//! workflow kinds without `attome-workflow` depending on it.
//!
//! A journey (E8) is a workflow whose steps send email, wait for an event
//! or update a list; those steps belong to `attome-marketing`, which
//! `attome-workflow` must not depend on. The same inversion as
//! [`crate::workflow_start`]: the traits live here, the owning engine
//! implements them, the composition root registers each on the
//! `EngineSystem` builder, and the builder freezes them onto
//! [`crate::EngineState::workflow_step_handlers`] and
//! [`crate::EngineState::workflow_kind_guards`]. A duplicate key is a
//! boot-time programming error and panics at build, naming the key.
//!
//! - A [`WorkflowStepHandler`] runs one node of its `key` and answers a
//!   [`StepOutcome`]: done with output, waiting (until a time or an event),
//!   blocked (with whether the instance may go on), or exit.
//! - A [`WorkflowKindGuard`] is asked before each node of an instance of its
//!   `kind` (a journey's exit rules, quiet hours, frequency caps) and may
//!   end the instance with a reason.
//!
//! Neither authorizes: the workflow engine runs instances as their starter
//! and checks the handler's module licence before calling it.

use std::future::Future;
use std::pin::Pin;

use attome_modules::ModuleId;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::EngineState;

/// One node to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepInvocation {
    pub instance_id: Uuid,
    pub node_id: String,
    pub correlation_entity_id: Option<Uuid>,
    /// The node's configuration, as [`WorkflowStepHandler::validate_config`]
    /// accepted it when the definition was published.
    pub config: serde_json::Value,
    /// The instance's data reaching this node.
    pub input: serde_json::Value,
    /// A dry run: describe what would happen, change nothing.
    pub simulate: bool,
    /// E8-T7: the user the run acts as (the flow's run-as identity), for a
    /// step that changes records through access-checked paths. `None` in a
    /// dry run.
    #[serde(default)]
    pub run_as_user: Option<Uuid>,
    /// S9-T5: the step's effect key (`run:node[:round]`), the same on every
    /// replay of this step, for a handler whose target dedupes by key. `None`
    /// in a dry run.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// What a node did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StepOutcome {
    /// Finished; the output joins the instance's data.
    Done(serde_json::Value),
    /// Run again at `resume_at`, or when `wait_event` arrives.
    Waiting {
        resume_at: Option<DateTime<Utc>>,
        wait_event: Option<String>,
    },
    /// Could not run for `reason`; `continue_after` says whether the
    /// instance goes on to the next node.
    Blocked {
        reason: String,
        continue_after: bool,
    },
    /// End the instance.
    Exit { reason: String },
}

/// The boxed future a step returns (no `async_trait` in this workspace).
pub type StepFuture<'a> = Pin<Box<dyn Future<Output = Result<StepOutcome, AppError>> + Send + 'a>>;

/// The boxed future a kind guard returns: `Some(reason)` ends the instance.
pub type GuardFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, AppError>> + Send + 'a>>;

/// One kind of workflow node an engine contributes.
pub trait WorkflowStepHandler: Send + Sync + 'static {
    /// The node type's key, such as `marketing.send_email`.
    fn key(&self) -> &'static str;
    /// The module that must be licensed for the node to run.
    fn module_id(&self) -> ModuleId;
    /// Checks a node's configuration when its definition is saved.
    fn validate_config(&self, config: &serde_json::Value) -> Result<(), String>;
    /// Runs one node.
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a>;
}

/// The rules a kind of workflow applies before every node.
pub trait WorkflowKindGuard: Send + Sync + 'static {
    /// The definition kind it guards, such as `journey`.
    fn kind(&self) -> &'static str;
    fn before_node<'a>(
        &'a self,
        state: &'a EngineState,
        instance_id: Uuid,
        correlation_entity_id: Option<Uuid>,
        node_id: &'a str,
    ) -> GuardFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn outcome_serialises_round_trip() {
        for outcome in [
            StepOutcome::Done(json!({"sent": true})),
            StepOutcome::Waiting {
                resume_at: Some(Utc::now()),
                wait_event: Some("email.opened".into()),
            },
            StepOutcome::Blocked {
                reason: "no consent".into(),
                continue_after: true,
            },
            StepOutcome::Exit {
                reason: "converted".into(),
            },
        ] {
            let text = serde_json::to_string(&outcome).unwrap();
            let back: StepOutcome = serde_json::from_str(&text).unwrap();
            assert_eq!(back, outcome, "{text}");
        }
        let exit = serde_json::to_value(StepOutcome::Exit { reason: "x".into() }).unwrap();
        assert_eq!(exit["outcome"], "exit");
    }
}
