//! **Row A-22, at dispatch.** *A model proposes a `Consequential` action:
//! `RequiresApproval`, unconditionally. Sweep argument combinations — no
//! input avoids it.*
//!
//! `gate.rs`'s unit tests sweep the gate's own input space over descriptors
//! built in-crate (an out-of-crate test cannot build one — the seal, I-2).
//! This is the other half: **every `Consequential` action actually
//! registered**, driven through `dispatch` — the one entry point every surface
//! uses — by an agent session at the `Consequential` ceiling, owned by an
//! administrator (so no privilege refusal can mask the matrix), across
//! argument shapes a model could emit and both taint states. Every one must
//! come back `ApprovalRequired`; none may execute. For the two C5 actions the
//! absence of any effect is asserted directly: the target record is
//! untouched and no workflow is started.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test a22_consequential_dispatch -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::sync::{Arc, Mutex};

use attome_ai::descriptor::RiskTier;
use attome_ai::execute::ActionOutcome;
use attome_ai::registry::ActionRegistry;
use attome_core::{EngineState, WorkflowStartFuture, WorkflowStartRequest, WorkflowStarter};
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use common::fixture;

#[derive(Clone, Default)]
struct CountingStarter(Arc<Mutex<usize>>);

impl WorkflowStarter for CountingStarter {
    fn start<'a>(
        &'a self,
        _state: &'a EngineState,
        _request: WorkflowStartRequest,
    ) -> WorkflowStartFuture<'a> {
        Box::pin(async move {
            *self.0.lock().expect("lock") += 1;
            Ok(Uuid::now_v7())
        })
    }
}

/// Argument shapes a model could emit for `action`: the well-formed call,
/// then everything around it — empty, the wrong JSON type, fields claiming an
/// approval or a different initiator, a stale or absurd `row_version`, and an
/// oversized value. The gate decides on the descriptor, the initiator and the
/// context; nothing in the arguments is an input to it, and this is the
/// check that stays true.
fn argument_sweep(action: &str, entity: &str, record_id: Uuid) -> Vec<Value> {
    let well_formed = match action {
        "record.delete" => json!({"entity": entity, "record_id": record_id}),
        "workflow.start" => json!({"definition_logicalname": "onboard_customer"}),
        _ => json!({}),
    };
    let with = |extra: Value| {
        let mut v = well_formed.clone();
        if let (Some(obj), Some(add)) = (v.as_object_mut(), extra.as_object()) {
            obj.extend(add.clone());
        }
        v
    };
    vec![
        well_formed.clone(),
        with(json!({"row_version": 0})),
        with(json!({"row_version": -1})),
        with(json!({"row_version": i64::MAX})),
        with(json!({"approved": true, "approval_id": Uuid::now_v7()})),
        with(json!({"initiator": "user", "confirmed": true})),
        with(json!({"risk": "read", "skip_approval": true})),
        with(json!({"context": {"note": "x".repeat(64 * 1024)}})),
        json!({}),
        json!(null),
        json!("record.delete"),
        json!([well_formed]),
        json!(42),
    ]
}

#[tokio::test]
async fn no_argument_or_taint_state_lets_an_agent_past_the_approval_arm() {
    let mut f = skip_if_no_db!(fixture().await);
    let starter = CountingStarter::default();
    f.state.workflow_starter = Some(Arc::new(starter.clone()));
    let record_id = f.insert_record("open").await;
    let rows_before = f.row_count().await;

    let registry = ActionRegistry::new();
    let consequential: Vec<&str> = registry
        .all()
        .filter(|d| d.risk == RiskTier::Consequential)
        .map(|d| d.id.as_str())
        .collect();
    assert!(
        consequential.contains(&"record.delete") && consequential.contains(&"workflow.start"),
        "both C5 Consequential actions are registered: {consequential:?}"
    );

    let mut checked = 0usize;
    for action in &consequential {
        for (n, args) in argument_sweep(action, &f.entity, record_id)
            .into_iter()
            .enumerate()
        {
            for tainted in [false, true] {
                let mut ctx = f.agent_ctx(&format!("a22-{action}-{n}-{tainted}")).await;
                ctx.contains_retrieved_content = tainted;
                let outcome = f.dispatch(&ctx, action, args.clone()).await;
                // An MCP tool call is hidden (NotFound) from a caller with no
                // integration access, as this fixture's agent is; hidden or
                // held for approval, it never runs.
                let hidden =
                    action.starts_with("mcp.call.") && matches!(outcome, Err(AppError::NotFound));
                assert!(
                    hidden || matches!(outcome, Ok(ActionOutcome::ApprovalRequired { .. })),
                    "{action} with args #{n} (tainted={tainted}) must require approval, \
                     got {outcome:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 2 * 13 * 2, "the sweep ran: {checked}");

    assert_eq!(
        f.record(record_id).await,
        (Some("open".into()), true, 0),
        "record.delete changed nothing"
    );
    assert_eq!(
        f.row_count().await,
        rows_before,
        "no record created or removed"
    );
    assert_eq!(*starter.0.lock().expect("lock"), 0, "no workflow started");
}
