//! C5 — `workflow.start` through the real gate, confirm and approval paths,
//! with a recording `WorkflowStarter` standing in for `attome-workflow` (which
//! this crate cannot depend on — the reverse edge exists). The real starter
//! is proven against the same lifecycle in `attome-workflow`'s
//! `tests/execution.rs`.
//!
//! What is proven:
//! - an agent's `workflow.start` is never executed on dispatch —
//!   `ApprovalRequired`, nothing started;
//! - A-22: propose → human confirm → approval requested with **nothing
//!   started** → a second person approves → started **exactly once**, by the
//!   human the agent acts for;
//! - the admin boundary holds for a direct human invocation and for an agent
//!   of a non-admin;
//! - an unlicensed workflow module, or no registered starter, is absent
//!   (`NotFound`), never a silent success.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test workflow_start -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::sync::{Arc, Mutex};

use attome_ai::confirm::ConfirmOutcome;
use attome_ai::execute::{ActionOutcome, Executors, dispatch};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_core::{EngineState, WorkflowStartFuture, WorkflowStartRequest, WorkflowStarter};
use attome_modules::ModuleSet;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

use common::{Fixture, fixture, seed_user};

/// Records every start it is asked for and returns a fresh instance id.
#[derive(Clone, Default)]
struct RecordingStarter(Arc<Mutex<Vec<WorkflowStartRequest>>>);

impl RecordingStarter {
    fn starts(&self) -> Vec<WorkflowStartRequest> {
        self.0.lock().expect("lock").clone()
    }
}

impl WorkflowStarter for RecordingStarter {
    fn start<'a>(
        &'a self,
        _state: &'a EngineState,
        request: WorkflowStartRequest,
    ) -> WorkflowStartFuture<'a> {
        Box::pin(async move {
            self.0.lock().expect("lock").push(request);
            Ok(Uuid::now_v7())
        })
    }
}

async fn with_starter() -> Option<(Fixture, RecordingStarter)> {
    let mut f = fixture().await?;
    let starter = RecordingStarter::default();
    f.state.workflow_starter = Some(Arc::new(starter.clone()));
    Some((f, starter))
}

fn start_args() -> serde_json::Value {
    json!({"definition_logicalname": "onboard_customer", "context": {"tier": "gold"}})
}

#[tokio::test]
async fn an_agent_workflow_start_requires_approval_and_starts_nothing() {
    let (f, starter) = skip_if_no_db!(with_starter().await);
    let ctx = f.agent_ctx("w-direct").await;
    let outcome = f
        .dispatch(&ctx, "workflow.start", start_args())
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::ApprovalRequired { .. }),
        "{outcome:?}"
    );
    assert!(starter.starts().is_empty());
}

/// **Row A-22, the `Consequential` lifecycle for `workflow.start`.**
#[tokio::test]
async fn a_confirmed_workflow_start_waits_for_approval_then_starts_exactly_once() {
    let (f, starter) = skip_if_no_db!(with_starter().await);
    let hash = f.propose("wf", "workflow.start", start_args()).await;

    let ConfirmOutcome::ApprovalRequested {
        approval_request_id,
    } = f.confirm("wf", &hash).await
    else {
        panic!("confirming a Consequential proposal requests approval");
    };
    assert!(
        starter.starts().is_empty(),
        "nothing started at the confirmation step"
    );

    let approver = seed_user(f.db(), true).await;
    attome_approval::decide(
        f.db(),
        approval_request_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a second person approves");
    let request = attome_ai::approval::approved_payload(f.db(), approval_request_id)
        .await
        .expect("read")
        .expect("approved payload");
    let executed = attome_ai::execute::dispatch_approved_agent_action_under(
        &f.state,
        &request,
        Some(approval_request_id),
    )
    .await
    .expect("execute the approved start");
    assert!(
        matches!(executed, attome_ai::execute::ApprovedExecution::Executed(_)),
        "{executed:?}"
    );

    let starts = starter.starts();
    assert_eq!(starts.len(), 1, "exactly one start");
    assert_eq!(starts[0].definition_logicalname, "onboard_customer");
    assert_eq!(starts[0].started_by, f.owner, "the human, not the agent");
    assert_eq!(starts[0].context, json!({"tier": "gold"}));
}

/// The route is `Authorized<Admin>`, and so is the action: a non-admin is
/// refused whether they invoke it directly or their agent proposes it.
#[tokio::test]
async fn a_non_admin_cannot_start_a_workflow() {
    let (f, starter) = skip_if_no_db!(with_starter().await);
    let plain = seed_user(f.db(), false).await;
    let ctx = f.user_ctx(plain).await;
    let err = f
        .dispatch(&ctx, "workflow.start", start_args())
        .await
        .expect_err("a non-admin's direct invocation");
    assert!(matches!(err, AppError::Forbidden), "{err:?}");
    assert!(starter.starts().is_empty());
}

/// A direct invocation by an administrator keeps its ordinary semantics —
/// the same thing the admin route does, no approval.
#[tokio::test]
async fn an_admin_direct_invocation_starts_once() {
    let (f, starter) = skip_if_no_db!(with_starter().await);
    let ctx = f.user_ctx(f.owner).await;
    let outcome = f
        .dispatch(&ctx, "workflow.start", start_args())
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(starter.starts().len(), 1);
}

/// Unlicensed workflow is absent: the licence is resolved off the
/// descriptor's own module (`MODULE_WORKFLOW`), exactly as `engine::
/// gate_inputs` and the chat/MCP tool lists resolve it.
#[tokio::test]
async fn an_unlicensed_workflow_module_is_absent() {
    let (f, starter) = skip_if_no_db!(with_starter().await);
    let mut bits = [u64::MAX; 4];
    bits[attome_modules::MODULE_WORKFLOW.word] &= !attome_modules::MODULE_WORKFLOW.mask;
    f.state.modules.store(Arc::new(ModuleSet::from_bits(bits)));
    let registry = ActionRegistry::new();
    let descriptor = registry.resolve("workflow.start").expect("registered");
    let inputs = GateInputs {
        licensed: f.state.modules.load().has(descriptor.module),
        ai: &f.state.base.config.inference.ai,
        surface: None,
        external_effects_enabled: false,
    };
    let ctx = f.user_ctx(f.owner).await;
    let err = dispatch(
        &f.state,
        &registry,
        &Executors::new(),
        "workflow.start",
        &ctx,
        &inputs,
        &start_args(),
    )
    .await
    .expect_err("unlicensed");
    assert!(matches!(err, AppError::NotFound), "{err:?}");
    assert!(starter.starts().is_empty());
}

/// No `WorkflowStarter` registered — a bare `EngineState` — is `NotFound`, not
/// a success that started nothing.
#[tokio::test]
async fn no_registered_starter_is_not_found() {
    let f = skip_if_no_db!(fixture().await);
    assert!(f.state.workflow_starter.is_none());
    let ctx = f.user_ctx(f.owner).await;
    let err = f
        .dispatch(&ctx, "workflow.start", start_args())
        .await
        .expect_err("no starter");
    assert!(matches!(err, AppError::NotFound), "{err:?}");
}
