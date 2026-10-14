//! C5 — `record.create`, `record.update`, `record.delete`, `record.restore`,
//! through the real paths: `dispatch` (the gate) and `confirm_tool_call` (the
//! C4 / D-569 confirm path), against a provisioned, writable entity.
//!
//! What is proven:
//! - an agent's proposal of any of the four is never executed autonomously —
//!   `ConfirmationRequired` for the three `Reversible` writes (even in an
//!   untainted context: `agent_must_confirm`), `ApprovalRequired` for delete;
//! - a human confirmation executes the write exactly once; a repeat is
//!   `already_executed`;
//! - a direct human invocation keeps its ordinary semantics;
//! - entity privilege, ledger/append-only refusal, special-category fields,
//!   and `row_version` all hold;
//! - A-22 for `record.delete`: propose → confirm → approval requested with
//!   **no mutation** → approve → **exactly one** delete.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test record_write -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_ai::confirm::{ConfirmOutcome, ConfirmRefusal};
use attome_ai::execute::ActionOutcome;
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

use common::{fixture, fixture_with, seed_user};

// ---------------------------------------------------------------------------
// record.create
// ---------------------------------------------------------------------------

/// **The C5 invariant.** An agent's `record.create` in a perfectly clean,
/// untainted context is still not executed: `agent_must_confirm` is checked
/// by the gate before taint. Nothing is written.
#[tokio::test]
async fn an_agent_create_needs_confirmation_even_in_an_untainted_context() {
    let f = skip_if_no_db!(fixture().await);
    let ctx = f.agent_ctx("c1").await;
    assert!(!ctx.contains_retrieved_content, "precondition: untainted");

    let outcome = f
        .dispatch(
            &ctx,
            "record.create",
            json!({"entity": f.entity, "values": {"status": "new"}}),
        )
        .await
        .expect("dispatch");

    assert!(
        matches!(outcome, ActionOutcome::ConfirmationRequired { .. }),
        "{outcome:?}"
    );
    assert_eq!(f.row_count().await, 0, "nothing written");
}

#[tokio::test]
async fn a_confirmed_create_writes_once_and_a_repeat_is_already_executed() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f
        .propose(
            "c1",
            "record.create",
            json!({"entity": f.entity, "values": {"status": "new"}}),
        )
        .await;

    let ConfirmOutcome::Executed { result } = f.confirm("c1", &hash).await else {
        panic!("a confirmed create executes");
    };
    let id = Uuid::parse_str(result["record_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.record(id).await.0.as_deref(), Some("new"));
    assert_eq!(f.row_count().await, 1);

    assert!(matches!(
        f.confirm("c1", &hash).await,
        ConfirmOutcome::Refused(ConfirmRefusal::AlreadyExecuted { .. })
    ));
    assert_eq!(
        f.row_count().await,
        1,
        "a repeat never creates a second record"
    );
}

/// A direct human invocation keeps its ordinary semantics: a `Reversible`
/// write by the user executes.
#[tokio::test]
async fn a_user_create_executes_normally() {
    let f = skip_if_no_db!(fixture().await);
    let ctx = f.user_ctx(f.owner).await;
    let outcome = f
        .dispatch(
            &ctx,
            "record.create",
            json!({"entity": f.entity, "values": {"status": "mine"}}),
        )
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(f.row_count().await, 1);
}

#[tokio::test]
async fn a_caller_without_the_create_privilege_is_refused() {
    let f = skip_if_no_db!(fixture().await);
    let nobody = seed_user(f.db(), false).await;
    let ctx = f.user_ctx(nobody).await;
    let result = f
        .dispatch(
            &ctx,
            "record.create",
            json!({"entity": f.entity, "values": {"status": "x"}}),
        )
        .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{result:?}"
    );
    assert_eq!(f.row_count().await, 0);
}

#[tokio::test]
async fn a_ledger_entity_cannot_be_created() {
    let f = skip_if_no_db!(fixture().await);
    let ctx = f.user_ctx(f.owner).await;
    let result = f
        .dispatch(
            &ctx,
            "record.create",
            json!({"entity": "audit_header", "values": {}}),
        )
        .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{result:?}"
    );
}

/// A special-category field is refused for the agent by the one shared check,
/// and the proposal is closed — nothing is written.
#[tokio::test]
async fn an_agent_create_touching_a_special_category_field_is_refused() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f
        .propose(
            "sens",
            "record.create",
            json!({"entity": f.entity, "values": {"status": "x", "special_note": "health data"}}),
        )
        .await;
    let outcome = f.confirm("sens", &hash).await;
    assert!(
        matches!(
            outcome,
            ConfirmOutcome::Refused(ConfirmRefusal::ActionFailed { invalidated: true })
        ),
        "{outcome:?}"
    );
    assert_eq!(f.row_count().await, 0);
}

// ---------------------------------------------------------------------------
// record.update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_agent_update_needs_confirmation_and_a_confirmed_one_writes_once() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let args = json!({"entity": f.entity, "record_id": id, "values": {"status": "closed"}, "row_version": 0});

    let ctx = f.agent_ctx("u-direct").await;
    let outcome = f
        .dispatch(&ctx, "record.update", args.clone())
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::ConfirmationRequired { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        f.record(id).await,
        (Some("open".into()), true, 0),
        "nothing written"
    );

    let hash = f.propose("u1", "record.update", args).await;
    assert!(matches!(
        f.confirm("u1", &hash).await,
        ConfirmOutcome::Executed { .. }
    ));
    assert_eq!(
        f.record(id).await,
        (Some("closed".into()), true, 1),
        "exactly one update"
    );
}

/// A stale `row_version` is refused as a conflict, not an overwrite; the
/// arguments cannot change, so the proposal is closed.
#[tokio::test]
async fn a_stale_row_version_is_refused_not_overwritten() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let hash = f
        .propose(
            "stale",
            "record.update",
            json!({"entity": f.entity, "record_id": id, "values": {"status": "closed"}, "row_version": 7}),
        )
        .await;
    let outcome = f.confirm("stale", &hash).await;
    assert!(
        matches!(
            outcome,
            ConfirmOutcome::Refused(ConfirmRefusal::ActionFailed { invalidated: true })
        ),
        "{outcome:?}"
    );
    assert_eq!(f.record(id).await, (Some("open".into()), true, 0));
}

#[tokio::test]
async fn an_agent_update_of_a_special_category_field_is_refused() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let hash = f
        .propose(
            "sens",
            "record.update",
            json!({"entity": f.entity, "record_id": id, "values": {"special_note": "x"}, "row_version": 0}),
        )
        .await;
    assert!(matches!(
        f.confirm("sens", &hash).await,
        ConfirmOutcome::Refused(ConfirmRefusal::ActionFailed { invalidated: true })
    ));
    assert_eq!(f.record(id).await, (Some("open".into()), true, 0));
}

#[tokio::test]
async fn a_caller_without_the_update_privilege_is_refused() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let nobody = seed_user(f.db(), false).await;
    let ctx = f.user_ctx(nobody).await;
    let result = f
        .dispatch(
            &ctx,
            "record.update",
            json!({"entity": f.entity, "record_id": id, "values": {"status": "x"}, "row_version": 0}),
        )
        .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{result:?}"
    );
    assert_eq!(f.record(id).await, (Some("open".into()), true, 0));
}

// ---------------------------------------------------------------------------
// record.delete — including row A-22's lifecycle
// ---------------------------------------------------------------------------

/// An agent's `record.delete` is `Consequential`: four-eyes approval, never an
/// inline execution.
#[tokio::test]
async fn an_agent_delete_requires_approval_and_deletes_nothing() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let ctx = f.agent_ctx("d-direct").await;
    let outcome = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::ApprovalRequired { .. }),
        "{outcome:?}"
    );
    assert_eq!(f.record(id).await, (Some("open".into()), true, 0));
}

/// **Row A-22, the `Consequential` lifecycle for `record.delete`.**
/// propose → human confirm → approval requested, **no business mutation** →
/// a second person approves → executed **exactly once**. Confirming a
/// `Consequential` proposal never executes it (D-569).
#[tokio::test]
async fn a_confirmed_delete_waits_for_approval_then_deletes_exactly_once() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let hash = f
        .propose(
            "del",
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;

    let ConfirmOutcome::ApprovalRequested {
        approval_request_id,
    } = f.confirm("del", &hash).await
    else {
        panic!("confirming a Consequential proposal requests approval");
    };
    assert_eq!(
        f.record(id).await,
        (Some("open".into()), true, 0),
        "no business mutation at the confirmation step"
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
    .expect("execute the approved delete");
    assert!(
        matches!(executed, attome_ai::execute::ApprovedExecution::Executed(_)),
        "{executed:?}"
    );

    let (_, active, version) = f.record(id).await;
    assert!(!active, "deleted after approval");
    assert_eq!(version, 1, "exactly one delete");
}

#[tokio::test]
async fn a_caller_without_the_delete_privilege_is_refused() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let nobody = seed_user(f.db(), false).await;
    let ctx = f.user_ctx(nobody).await;
    let result = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{result:?}"
    );
    assert!(f.record(id).await.1, "the record is still live");
}

#[tokio::test]
async fn an_append_only_entity_cannot_be_deleted() {
    let f = skip_if_no_db!(fixture_with(true).await);
    // An append-only table is never soft-deleted, so it may carry no
    // `is_active`; insert and count without assuming one.
    let table = attome_core::quote_ident(&f.entity);
    let id: Uuid = sqlx::query_scalar(&format!(
        "INSERT INTO {table} (id, status) VALUES ($1, 'open') RETURNING id"
    ))
    .bind(Uuid::now_v7())
    .fetch_one(f.db())
    .await
    .expect("insert append-only row");
    let ctx = f.user_ctx(f.owner).await;
    let result = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{result:?}"
    );
    assert_eq!(f.row_count().await, 1, "the row is untouched");
}

// ---------------------------------------------------------------------------
// record.restore
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_agent_restore_needs_confirmation_and_a_confirmed_one_restores_once() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    // Delete it as the human, directly.
    let user = f.user_ctx(f.owner).await;
    f.dispatch(
        &user,
        "record.delete",
        json!({"entity": f.entity, "record_id": id}),
    )
    .await
    .expect("delete as the user");
    let (_, active, deleted_version) = f.record(id).await;
    assert!(!active);

    let args = json!({"entity": f.entity, "record_id": id});
    let ctx = f.agent_ctx("r-direct").await;
    let outcome = f
        .dispatch(&ctx, "record.restore", args.clone())
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::ConfirmationRequired { .. }),
        "{outcome:?}"
    );
    assert!(!f.record(id).await.1, "still deleted");

    let hash = f.propose("r1", "record.restore", args).await;
    assert!(matches!(
        f.confirm("r1", &hash).await,
        ConfirmOutcome::Executed { .. }
    ));
    let (_, active, version) = f.record(id).await;
    assert!(active, "restored");
    assert_eq!(version, deleted_version + 1, "exactly one restore");
}

#[tokio::test]
async fn a_caller_without_the_update_privilege_cannot_restore() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let user = f.user_ctx(f.owner).await;
    f.dispatch(
        &user,
        "record.delete",
        json!({"entity": f.entity, "record_id": id}),
    )
    .await
    .expect("delete as the user");
    let nobody = seed_user(f.db(), false).await;
    let ctx = f.user_ctx(nobody).await;
    let result = f
        .dispatch(
            &ctx,
            "record.restore",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{result:?}"
    );
    assert!(!f.record(id).await.1, "still deleted");
}
