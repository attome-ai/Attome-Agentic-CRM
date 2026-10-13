//! **The negative test TODO-041 exists for**, against a real database.
//!
//! *An agent cannot reach a Consequential action without an approval, through
//! any façade or any argument.* This is the security-critical stage, and the
//! claim being made is a universal one — so the test is written as an
//! exhaustive sweep over the gate's inputs rather than as a handful of cases
//! somebody chose.
//!
//! The exhaustive sweep over the gate's own inputs lives in `gate.rs`'s test
//! module, because `ActionDescriptor` is sealed — an out-of-crate test cannot
//! construct a Consequential descriptor, which is the seal (I-2) working
//! exactly as intended. What lives *here* is the half that needs a database.
//!
//! And the separation-of-duties half is asserted end to end against
//! `attome-approval`: the agent's **owner cannot approve their own agent's
//! action**. That property lives in `attome_approval::decide`'s
//! `approver_id != requested_by` check, and it only holds because
//! `request_approval` records the *human* as requester — a fact that is easy to
//! "simplify" later by recording the agent, which would satisfy dual control on
//! paper with one person and a model they instructed.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test consequential_gate
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::approval::{AgentActionRequest, approved_payload, request_approval};
use attome_ai::descriptor::ActionId;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn agent_request(acting_user_id: Uuid) -> AgentActionRequest {
    AgentActionRequest {
        action_id: "record.delete".into(),
        args: serde_json::json!({ "entity": "account", "id": "abc" }),
        agent_session_id: Uuid::now_v7(),
        acting_user_id,
        agent_rationale: Some("the user asked me to remove the duplicate".into()),
    }
}

/// **The separation-of-duties assertion, end to end.**
///
/// The agent's owner is `requested_by`, so `attome_approval::decide` refuses
/// them. Somebody else has to approve.
#[tokio::test]
async fn the_agents_owner_cannot_approve_their_own_agents_action() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let other_admin = Uuid::now_v7();

    let pending = request_approval(&db, ActionId("record.delete"), &agent_request(owner))
        .await
        .expect("submit");

    // The owner tries. This is the case that matters: the human who started the
    // agent, approving what the agent asked for.
    // `row_version` is the optimistic-concurrency guard: two concurrent
    // decisions on one request cannot both land.
    let self_approval = attome_approval::decide(
        &db,
        pending.approval_id,
        owner,
        attome_approval::Decision::Approve,
        0,
    )
    .await;
    assert!(
        self_approval.is_err(),
        "the agent's owner must not be able to approve their own agent's \
         Consequential action — otherwise dual control is satisfied by one \
         person and a model they instructed"
    );

    // Nothing executes while it is still pending.
    assert!(
        approved_payload(&db, pending.approval_id)
            .await
            .expect("read")
            .is_none(),
        "a pending request must not yield an executable payload"
    );

    // A different admin can.
    attome_approval::decide(
        &db,
        pending.approval_id,
        other_admin,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a distinct approver may approve");

    let payload = approved_payload(&db, pending.approval_id)
        .await
        .expect("read")
        .expect("an approved request yields its payload");
    assert_eq!(payload.acting_user_id, owner, "it still runs as the human");
    assert_eq!(
        payload.args,
        serde_json::json!({ "entity": "account", "id": "abc" }),
        "the arguments are the ones captured at gate time, not re-read from \
         the model"
    );
}

/// A rejected request never yields an executable payload.
#[tokio::test]
async fn a_rejected_request_never_executes() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let pending = request_approval(&db, ActionId("record.delete"), &agent_request(owner))
        .await
        .expect("submit");

    attome_approval::decide(
        &db,
        pending.approval_id,
        Uuid::now_v7(),
        attome_approval::Decision::Reject,
        0,
    )
    .await
    .expect("reject");

    assert!(
        approved_payload(&db, pending.approval_id)
            .await
            .expect("read")
            .is_none(),
        "a rejected request must never yield a payload"
    );
}
