//! C5 — the two reads: `search.records` (closes G9) and `approval.status`
//! (closes the MCP follow-the-approval gap), through `dispatch` against the
//! same throwaway state `record_write.rs` uses.
//!
//! What is proven:
//! - `search.records` runs the real `execute_search` path for an agent with
//!   no confirmation, even in a tainted context (it is a `Read`), applies the
//!   route's own validation, and hands an aggregation question back to
//!   `query.execute` rather than returning rows;
//! - `approval.status` follows an agent's approval through pending →
//!   approved → executed, and answers `NotFound` for another person's agent
//!   approval, for a non-agent approval the caller requested, and for an id
//!   that does not exist — the three are indistinguishable.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test c5_read_actions -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_ai::execute::ActionOutcome;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{Fixture, fixture, seed_user};

fn completed(outcome: ActionOutcome) -> Value {
    match outcome {
        ActionOutcome::Completed { result, .. } => result,
        other => panic!("expected the read to execute, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// search.records
// ---------------------------------------------------------------------------

/// A read executes for an agent with no confirmation — **in a tainted
/// context too**, since reading is what an agent does after retrieving
/// anything — and the result is the search route's own response shape.
#[tokio::test]
async fn an_agent_search_executes_through_the_search_route_path() {
    let f = skip_if_no_db!(fixture().await);
    let mut ctx = f.agent_ctx("s-1").await;
    ctx.contains_retrieved_content = true;
    let result = completed(
        f.dispatch(&ctx, "search.records", json!({"query": "acme corporation"}))
            .await
            .expect("dispatch"),
    );
    assert!(result["items"].is_array(), "{result}");
    assert_eq!(result["page"], 1);
    assert_eq!(result["page_size"], 10, "a first page, not a dump");
    assert!(result["route"].is_string(), "{result}");
}

/// Rule 4 of the search router reaches the agent: a counting question comes
/// back with a hint to use the query tool and no rows to add up.
#[tokio::test]
async fn a_counting_question_is_handed_to_query_execute() {
    let f = skip_if_no_db!(fixture().await);
    let ctx = f.agent_ctx("s-2").await;
    let result = completed(
        f.dispatch(
            &ctx,
            "search.records",
            json!({"query": "how many open cases"}),
        )
        .await
        .expect("dispatch"),
    );
    assert_eq!(result["route"], "aggregation", "{result}");
    assert_eq!(result["items"], json!([]));
    assert!(result["route_hint"]["tool"].is_string(), "{result}");
}

/// The route's own validation, not a looser copy: an empty query and a page
/// size above the action's cap are refused before any SQL runs.
#[tokio::test]
async fn search_arguments_are_validated_like_the_route() {
    let f = skip_if_no_db!(fixture().await);
    let ctx = f.agent_ctx("s-3").await;
    for args in [
        json!({"query": "   "}),
        json!({"query": "acme", "page_size": 26}),
        json!({"query": "acme", "page": 0}),
        json!({"query": "acme", "entity": "account"}),
    ] {
        let err = f
            .dispatch(&ctx, "search.records", args.clone())
            .await
            .expect_err("must be refused");
        assert!(matches!(err, AppError::Validation(_)), "{args}: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// approval.status
// ---------------------------------------------------------------------------

async fn status_of(f: &Fixture, ctx: &attome_ai::context::ActionContext, id: Uuid) -> Value {
    completed(
        f.dispatch(ctx, "approval.status", json!({"approval_id": id}))
            .await
            .expect("approval.status"),
    )
}

/// **The gap it closes.** An agent's `Consequential` action returns an
/// approval id; the agent can follow it through its whole life.
#[tokio::test]
async fn an_agent_follows_its_approval_from_pending_to_executed() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let ctx = f.agent_ctx("a-1").await;
    let ActionOutcome::ApprovalRequired { approval_id } = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await
        .expect("dispatch")
    else {
        panic!("record.delete requires approval");
    };

    let pending = status_of(&f, &ctx, approval_id).await;
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["action_id"], "record.delete");
    assert_eq!(pending["approval_id"], json!(approval_id));
    assert!(pending["executed_at"].is_null());
    assert!(
        pending.get("args").is_none() && pending.get("payload").is_none(),
        "the status, not the payload: {pending}"
    );

    let approver = seed_user(f.db(), true).await;
    attome_approval::decide(
        f.db(),
        approval_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a second person approves");
    assert_eq!(status_of(&f, &ctx, approval_id).await["status"], "approved");

    let request = attome_ai::approval::approved_payload(f.db(), approval_id)
        .await
        .expect("read")
        .expect("approved payload");
    attome_ai::execute::dispatch_approved_agent_action_under(&f.state, &request, Some(approval_id))
        .await
        .expect("execute");
    // `approval_admin::execute_approved` (attome-api) closes the loop with
    // `mark_executed` after a successful run; this crate's test records it
    // the same way, then reads the status back through the action.
    let current = attome_approval::get(f.db(), approval_id)
        .await
        .expect("read approval");
    attome_approval::mark_executed(f.db(), approval_id, current.row_version)
        .await
        .expect("mark executed");
    let executed = status_of(&f, &ctx, approval_id).await;
    assert_eq!(executed["status"], "executed");
    assert!(executed["executed_at"].is_string(), "{executed}");
}

/// Another person's agent approval, a non-agent approval the caller
/// requested themselves, and an id that does not exist all answer the same
/// `NotFound` — the action cannot be used to learn which ids are real.
#[tokio::test]
async fn approvals_outside_the_callers_own_agent_actions_are_not_found() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let owner_ctx = f.agent_ctx("a-2").await;
    let ActionOutcome::ApprovalRequired { approval_id } = f
        .dispatch(
            &owner_ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await
        .expect("dispatch")
    else {
        panic!("record.delete requires approval");
    };

    let schema_change = attome_approval::submit(
        f.db(),
        "xrm-schema/test-change",
        json!({"note": "not an agent action"}),
        f.owner,
        1,
        chrono::Duration::hours(1),
    )
    .await
    .expect("submit a non-agent approval");

    let someone_else = seed_user(f.db(), false).await;
    let other_ctx = f.user_ctx(someone_else).await;

    for (ctx, approval, what) in [
        (&other_ctx, approval_id, "another person's agent approval"),
        (
            &owner_ctx,
            schema_change.id,
            "a non-agent approval I requested",
        ),
        (&owner_ctx, Uuid::now_v7(), "an id that does not exist"),
    ] {
        let err = f
            .dispatch(ctx, "approval.status", json!({"approval_id": approval}))
            .await
            .expect_err(what);
        assert!(matches!(err, AppError::NotFound), "{what}: {err:?}");
    }
}
