//! AH1-T7 and AH2-T6: undoing what an agent wrote, against a throwaway
//! database.
//!
//! Each agent write goes through the records engine inside
//! `attome_core::agent_scope::scope` (AK3-T1), exactly as an agent action's
//! executor runs, so its audit header carries the session. The planning
//! rules are unit-tested in `undo.rs`; this file proves the whole path:
//! collect, plan, store, apply.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test agent_run_undo -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_core::agent_scope::{AgentScope, scope};
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

use common::{Fixture, fixture};

/// A new session of `definition` (or of no agent), owned by the fixture's
/// owner.
async fn agent_session(f: &Fixture, definition: Option<Uuid>) -> Uuid {
    attome_ai::session::start(
        f.db(),
        &attome_audit::audit_service(&f.state),
        attome_ai::session::SessionStart {
            owner_user_id: f.owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: definition,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session")
    .id
}

async fn owner_ctx(f: &Fixture) -> SecurityContext {
    attome_security::resolve_uncached(f.db(), f.owner)
        .await
        .expect("security")
}

fn as_agent(session: Uuid, action: &str) -> AgentScope {
    AgentScope {
        session_id: session,
        action_id: action.to_owned(),
    }
}

/// Sets `status` on `record` at `version`, as `session`'s agent when given,
/// otherwise as the person.
async fn set_status(f: &Fixture, session: Option<Uuid>, record: Uuid, version: i64, status: &str) {
    let ctx = owner_ctx(f).await;
    let write = attome_records::entity_crud::update_record_for(
        &f.state,
        &ctx,
        f.owner,
        &f.entity,
        record,
        version,
        json!({ "status": status }),
    );
    let written = match session {
        Some(session) => scope(as_agent(session, "record.update"), write).await,
        None => write.await,
    };
    written.expect("update");
}

async fn undo(f: &Fixture, session: Uuid) -> Uuid {
    let ctx = owner_ctx(f).await;
    let run = attome_ai::undo::start_undo(&f.state, &ctx, &[session])
        .await
        .expect("start undo");
    attome_ai::undo::run_undo(&f.state, run)
        .await
        .expect("run undo");
    run
}

/// `(operation, outcome, changed_attributes, detail)` of a run's items, in
/// order.
async fn items(f: &Fixture, run: Uuid) -> Vec<(String, String, Vec<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT operation, outcome, changed_attributes, detail FROM ai_undo_item \
          WHERE undo_run_id = $1 ORDER BY seq",
    )
    .bind(run)
    .fetch_all(f.db())
    .await
    .expect("items")
}

#[tokio::test]
async fn undo_restores_agent_update() {
    let f = skip_if_no_db!(fixture().await);
    let session = agent_session(&f, None).await;
    let record = f.insert_record("open").await;
    set_status(&f, Some(session), record, 0, "closed").await;

    let run = undo(&f, session).await;
    assert_eq!(f.record(record).await.0.as_deref(), Some("open"));
    let items = items(&f, run).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, "restored");
}

#[tokio::test]
async fn undo_skips_attribute_changed_by_person() {
    let f = skip_if_no_db!(fixture().await);
    let session = agent_session(&f, None).await;
    let record = f.insert_record("open").await;
    set_status(&f, Some(session), record, 0, "closed").await;
    set_status(&f, None, record, 1, "reopened").await;

    let run = undo(&f, session).await;
    assert_eq!(
        f.record(record).await.0.as_deref(),
        Some("reopened"),
        "a person's later edit is never overwritten"
    );
    let items = items(&f, run).await;
    assert_eq!(items[0].1, "skipped_changed");
    assert!(items[0].2.contains(&"status".to_owned()), "{items:?}");
}

#[tokio::test]
async fn undo_soft_deletes_agent_created_record() {
    let f = skip_if_no_db!(fixture().await);
    let session = agent_session(&f, None).await;
    let ctx = owner_ctx(&f).await;
    let create = attome_records::entity_crud::create_record_for(
        &f.state,
        &ctx,
        f.owner,
        &f.entity,
        json!({ "status": "new" }),
    );
    let (record, _) = scope(as_agent(session, "record.create"), create)
        .await
        .expect("create");

    undo(&f, session).await;
    assert!(!f.record(record).await.1, "in the bin");
}

#[tokio::test]
async fn undo_restores_agent_deleted_record() {
    let f = skip_if_no_db!(fixture().await);
    let session = agent_session(&f, None).await;
    let record = f.insert_record("open").await;
    let ctx = owner_ctx(&f).await;
    let origin = attome_records::entity_mutation::DeleteOrigin::new(
        attome_records::entity_mutation::DeleteKind::Agent,
    );
    let delete = attome_records::entity_crud::delete_record_for(
        &f.state,
        &ctx,
        f.owner,
        &f.entity,
        record,
        Some(0),
        &origin,
    );
    scope(as_agent(session, "record.delete"), delete)
        .await
        .expect("delete");
    assert!(!f.record(record).await.1);

    undo(&f, session).await;
    assert!(f.record(record).await.1, "the deleted record is back");
}

#[tokio::test]
async fn undo_lists_external_send_as_not_undoable() {
    let f = skip_if_no_db!(fixture().await);
    let session = agent_session(&f, None).await;
    sqlx::query(
        "INSERT INTO action_invocation \
             (action_id, initiator, acting_user_id, outcome, agent_session_id) \
         VALUES ('email.send', 1, $1, 'completed', $2)",
    )
    .bind(f.owner)
    .bind(session)
    .execute(f.db())
    .await
    .expect("an email sent by the agent");

    let run = undo(&f, session).await;
    let items = items(&f, run).await;
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].1, "not_undoable");
    let detail = items[0].3.clone().unwrap_or_default();
    assert!(detail.contains("email.send"), "{detail}");
}

#[tokio::test]
async fn undo_job_resumes_after_partial_run() {
    let f = skip_if_no_db!(fixture().await);
    let session = agent_session(&f, None).await;
    let first = f.insert_record("open").await;
    let second = f.insert_record("open").await;
    set_status(&f, Some(session), first, 0, "closed").await;
    set_status(&f, Some(session), second, 0, "closed").await;

    let ctx = owner_ctx(&f).await;
    let run = attome_ai::undo::start_undo(&f.state, &ctx, &[session])
        .await
        .expect("start undo");
    // A run that stopped after its first item (the newest record, `second`):
    // that item is final, so a rerun must not apply it again.
    sqlx::query(
        "UPDATE ai_undo_item SET outcome = 'restored'           WHERE undo_run_id = $1 AND seq = 0",
    )
    .bind(run)
    .execute(f.db())
    .await
    .expect("mark the first item done");
    attome_ai::undo::run_undo(&f.state, run)
        .await
        .expect("resume");

    assert_eq!(
        f.record(second).await.0.as_deref(),
        Some("closed"),
        "an item already final is not applied again"
    );
    assert_eq!(f.record(first).await.0.as_deref(), Some("open"));
}

#[tokio::test]
async fn rollback_since_revokes_and_undoes_newest_first() {
    let f = skip_if_no_db!(fixture().await);
    let agent = Uuid::now_v7();
    let record = f.insert_record("open").await;

    // Before the cut-off: the first session's change stays.
    let before = agent_session(&f, Some(agent)).await;
    set_status(&f, Some(before), record, 0, "first").await;
    sqlx::query(
        "UPDATE agent_session \
            SET started_at = now() - interval '2 hours', ended_at = now() - interval '90 minutes' \
          WHERE id = $1",
    )
    .bind(before)
    .execute(f.db())
    .await
    .expect("age the first session");
    let since = chrono::Utc::now() - chrono::Duration::hours(1);

    let second = agent_session(&f, Some(agent)).await;
    set_status(&f, Some(second), record, 1, "second").await;
    let third = agent_session(&f, Some(agent)).await;
    set_status(&f, Some(third), record, 2, "third").await;

    let sessions = attome_ai::undo::sessions_of_agent_since(f.db(), agent, since)
        .await
        .expect("sessions");
    assert_eq!(sessions, vec![third, second], "newest first, none before");

    let ctx = owner_ctx(&f).await;
    let run = attome_ai::undo::start_rollback_since(&f.state, &ctx, agent, since)
        .await
        .expect("rollback");
    attome_ai::undo::run_undo(&f.state, run).await.expect("run");

    assert_eq!(
        f.record(record).await.0.as_deref(),
        Some("first"),
        "back to before the second session"
    );
    let revoked = |id: Uuid| {
        let db = f.db().clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT revoked_at IS NOT NULL FROM agent_session WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("session")
        }
    };
    assert!(revoked(second).await && revoked(third).await);
    assert!(!revoked(before).await, "an earlier session stays");
    let scope_row: (String, Option<Uuid>) =
        sqlx::query_as("SELECT scope, agent_ref FROM ai_undo_run WHERE id = $1")
            .bind(run)
            .fetch_one(f.db())
            .await
            .expect("run row");
    assert_eq!(scope_row, ("agent_since".to_owned(), Some(agent)));
}
