//! AH8 (V2-D693) — agent autonomy levels and the undo window, end to end
//! through the real `dispatch`, against a throwaway database.
//!
//! `record.delete` is the action under test: `Consequential` and
//! `agent_must_confirm`, so with no level it needs four-eyes approval, and
//! every level above `ask_first` is an administrator's explicit choice.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test agent_autonomy -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::sync::Arc;

use attome_ai::autonomy::AutonomyLevel;
use attome_ai::context::ActionContext;
use attome_ai::execute::ActionOutcome;
use attome_ai::session::AgentSession;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{Fixture, fixture};

const DELETE: &str = "record.delete";

/// A session started from an agent definition, so its autonomy rows apply.
///
/// The executor's audit event reads the definition's model from `ai_agent`
/// and `ai_model`, which the platform bundle provisions and this bare state
/// does not: minimal stand-ins, in the throwaway database only.
async fn definition_session(f: &Fixture, definition: Uuid, tainted: bool) -> AgentSession {
    for ddl in [
        "CREATE TABLE IF NOT EXISTS ai_model (id uuid PRIMARY KEY, provider_model_id text)",
        "CREATE TABLE IF NOT EXISTS ai_agent (id uuid PRIMARY KEY, primary_model_ref uuid)",
    ] {
        sqlx::query(ddl).execute(f.db()).await.expect("stand-in table");
    }
    attome_ai::session::start(
        f.db(),
        &attome_audit::audit_service(&f.state),
        attome_ai::session::SessionStart {
            owner_user_id: f.owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: Some(definition),
            integration_system_id: None,
            tainted,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session")
}

async fn ctx_for(f: &Fixture, session: &AgentSession, key: &str) -> ActionContext {
    let security = Arc::new(
        attome_security::resolve_uncached(f.db(), f.owner)
            .await
            .expect("security"),
    );
    let mut ctx = attome_ai::turn::context_for(security, session);
    ctx.idempotency_key = Some(key.to_owned());
    ctx
}

/// Stores a level the way the admin route does (a throwaway-database write).
async fn set_level(f: &Fixture, definition: Uuid, level: AutonomyLevel, daily_limit: Option<i32>) {
    sqlx::query(
        "INSERT INTO ai_autonomy_level \
           (agent_definition_id, action_id, level, undo_seconds, daily_limit, created_by, updated_by) \
         VALUES ($1, $2, $3, 30, $4, $5, $5) \
         ON CONFLICT (agent_definition_id, action_id) DO UPDATE SET \
           level = EXCLUDED.level, daily_limit = EXCLUDED.daily_limit",
    )
    .bind(definition)
    .bind(DELETE)
    .bind(level.as_i16())
    .bind(daily_limit)
    .bind(f.owner)
    .execute(f.db())
    .await
    .expect("store level");
}

fn delete_args(f: &Fixture, id: Uuid) -> Value {
    json!({ "entity": f.entity, "record_id": id })
}

async fn is_live(f: &Fixture, id: Uuid) -> bool {
    f.record(id).await.1
}

/// Makes a held action due now, so the sweep picks it up.
async fn make_due(f: &Fixture, deferred: Uuid) {
    sqlx::query("UPDATE ai_deferred_action SET run_at = now() - interval '1 second' WHERE id = $1")
        .bind(deferred)
        .execute(f.db())
        .await
        .expect("make due");
}

async fn status_of(f: &Fixture, deferred: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM ai_deferred_action WHERE id = $1")
        .bind(deferred)
        .fetch_one(f.db())
        .await
        .expect("status")
}

#[tokio::test]
async fn with_no_level_a_consequential_agent_action_still_needs_approval() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    let session = definition_session(&f, definition, false).await;
    let id = f.insert_record("open").await;

    let outcome = f
        .dispatch(&ctx_for(&f, &session, "t1").await, DELETE, delete_args(&f, id))
        .await
        .expect("dispatch");
    assert!(matches!(outcome, ActionOutcome::ApprovalRequired { .. }), "{outcome:?}");
    assert!(is_live(&f, id).await, "nothing ran");
}

#[tokio::test]
async fn at_automatic_it_runs_and_a_daily_limit_then_asks() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    set_level(&f, definition, AutonomyLevel::Automatic, Some(1)).await;
    let session = definition_session(&f, definition, false).await;
    let first = f.insert_record("open").await;
    let second = f.insert_record("open").await;

    let outcome = f
        .dispatch(&ctx_for(&f, &session, "t1").await, DELETE, delete_args(&f, first))
        .await
        .expect("dispatch");
    assert!(matches!(outcome, ActionOutcome::Completed { .. }), "{outcome:?}");
    assert!(!is_live(&f, first).await, "the delete ran on its own");

    let over = f
        .dispatch(&ctx_for(&f, &session, "t2").await, DELETE, delete_args(&f, second))
        .await
        .expect("dispatch");
    assert!(
        matches!(over, ActionOutcome::ApprovalRequired { .. }),
        "over its daily limit it asks: {over:?}"
    );
    assert!(is_live(&f, second).await);
}

#[tokio::test]
async fn at_act_with_undo_it_waits_then_runs_and_a_cancelled_one_never_runs() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    set_level(&f, definition, AutonomyLevel::ActWithUndo, None).await;
    let session = definition_session(&f, definition, false).await;
    let kept = f.insert_record("open").await;
    let cancelled = f.insert_record("open").await;

    let ActionOutcome::Scheduled { deferred_action_id: run, .. } = f
        .dispatch(&ctx_for(&f, &session, "t1").await, DELETE, delete_args(&f, kept))
        .await
        .expect("dispatch")
    else {
        panic!("act_with_undo holds the action");
    };
    let ActionOutcome::Scheduled { deferred_action_id: stop, .. } = f
        .dispatch(&ctx_for(&f, &session, "t2").await, DELETE, delete_args(&f, cancelled))
        .await
        .expect("dispatch")
    else {
        panic!("act_with_undo holds the action");
    };
    // A retried tool call returns the same held action.
    let ActionOutcome::Scheduled { deferred_action_id: again, .. } = f
        .dispatch(&ctx_for(&f, &session, "t1").await, DELETE, delete_args(&f, kept))
        .await
        .expect("dispatch")
    else {
        panic!("a retry is held too");
    };
    assert_eq!(again, run, "a retry never holds a second action");
    assert!(is_live(&f, kept).await && is_live(&f, cancelled).await, "nothing ran yet");

    sqlx::query("UPDATE ai_deferred_action SET status = 'cancelled' WHERE id = $1 AND status = 'pending'")
        .bind(stop)
        .execute(f.db())
        .await
        .unwrap();
    make_due(&f, run).await;
    make_due(&f, stop).await;
    attome_ai::deferred::sweep(&f.state).await.expect("sweep");

    assert_eq!(status_of(&f, run).await, "executed");
    assert!(!is_live(&f, kept).await, "the held delete ran after its window");
    assert_eq!(status_of(&f, stop).await, "cancelled");
    assert!(is_live(&f, cancelled).await, "a cancelled action never runs");
}

#[tokio::test]
async fn untrusted_text_lowers_the_level_by_one() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    set_level(&f, definition, AutonomyLevel::ActWithUndo, None).await;
    let tainted = definition_session(&f, definition, true).await;
    let id = f.insert_record("open").await;

    let outcome = f
        .dispatch(&ctx_for(&f, &tainted, "t1").await, DELETE, delete_args(&f, id))
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::ApprovalRequired { .. }),
        "act_with_undo on a tainted context is ask_first: {outcome:?}"
    );
    assert!(is_live(&f, id).await);
}

#[tokio::test]
async fn a_level_lowered_during_the_window_asks_instead_of_running() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    set_level(&f, definition, AutonomyLevel::ActWithUndo, None).await;
    let session = definition_session(&f, definition, false).await;
    let id = f.insert_record("open").await;

    let ActionOutcome::Scheduled { deferred_action_id, .. } = f
        .dispatch(&ctx_for(&f, &session, "t1").await, DELETE, delete_args(&f, id))
        .await
        .expect("dispatch")
    else {
        panic!("held");
    };
    set_level(&f, definition, AutonomyLevel::AskFirst, None).await;
    make_due(&f, deferred_action_id).await;
    attome_ai::deferred::sweep(&f.state).await.expect("sweep");

    assert_eq!(status_of(&f, deferred_action_id).await, "approval_required");
    assert!(is_live(&f, id).await, "nothing ran");
}

#[tokio::test]
async fn a_person_can_hold_their_own_action_for_an_undo_window() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let ctx = f.user_ctx(f.owner).await.with_undo_window(30);

    let ActionOutcome::Scheduled { deferred_action_id, .. } = f
        .dispatch(&ctx, DELETE, delete_args(&f, id))
        .await
        .expect("dispatch")
    else {
        panic!("a requested undo window holds the action");
    };
    assert!(is_live(&f, id).await);
    make_due(&f, deferred_action_id).await;
    attome_ai::deferred::sweep(&f.state).await.expect("sweep");
    assert_eq!(status_of(&f, deferred_action_id).await, "executed");
    assert!(!is_live(&f, id).await);
}

#[tokio::test]
async fn a_row_interrupted_mid_run_ends_failed_and_never_runs_again() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let deferred: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_deferred_action \
           (action_id, args, initiator, acting_user_id, run_at, status, updated_at) \
         VALUES ($1, $2, 'user', $3, now(), 'running', now() - interval '1 hour') RETURNING id",
    )
    .bind(DELETE)
    .bind(delete_args(&f, id))
    .bind(f.owner)
    .fetch_one(f.db())
    .await
    .unwrap();
    attome_ai::deferred::sweep(&f.state).await.expect("sweep");
    assert_eq!(status_of(&f, deferred).await, "failed");
    assert!(is_live(&f, id).await, "an interrupted action is never re-run");
}
