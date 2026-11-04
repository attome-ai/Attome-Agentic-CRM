//! AH3-T6: a session bound to an agent principal runs as it, and stops when
//! the principal is paused or revoked.
//!
//! ```powershell
//! cargo test -p attome-ai --test agent_principal_session -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_ai::session::{self, SessionForExecution};
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

use common::fixture;

#[tokio::test]
async fn session_runs_as_agent_principal_and_stops_when_paused() {
    let f = skip_if_no_db!(fixture().await);

    // An agent account sponsored by the session's owner.
    let agent = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, principal_kind) VALUES ($1, $2, 'agent', 2)",
    )
    .bind(agent)
    .bind(format!("agent-{}@internal.attome", agent.simple()))
    .execute(f.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO agent_principal (user_ref, sponsor_user_ref, created_by) VALUES ($1, $2, $2)",
    )
    .bind(agent)
    .bind(f.owner)
    .execute(f.db())
    .await
    .unwrap();

    let started = session::start(
        f.db(),
        &attome_audit::audit_service(&f.state),
        session::SessionStart {
            owner_user_id: f.owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: session::PolicySnapshot::NONE,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        session::acts_as(f.db(), started.id, f.owner).await.unwrap(),
        f.owner,
        "an unbound session acts as its owner"
    );
    session::bind_principal(f.db(), started.id, agent, f.owner)
        .await
        .unwrap();
    assert!(
        session::bind_principal(f.db(), started.id, agent, f.owner)
            .await
            .is_err(),
        "bound once"
    );
    assert_eq!(
        session::acts_as(f.db(), started.id, f.owner).await.unwrap(),
        agent
    );
    let chain: Vec<Uuid> =
        sqlx::query_scalar("SELECT actor_chain FROM agent_session WHERE id = $1")
            .bind(started.id)
            .fetch_one(f.db())
            .await
            .unwrap();
    assert_eq!(chain, vec![f.owner]);

    // It acts with the agent's grants narrowed to the sponsor's (AH3-T5):
    // never admin, never more than the owner.
    let owner = attome_security::resolve_uncached(f.db(), f.owner)
        .await
        .unwrap();
    let as_agent = attome_security::resolve_uncached(f.db(), agent)
        .await
        .unwrap();
    assert_eq!(as_agent.user_id, agent);
    assert!(!as_agent.is_admin);
    assert!(as_agent.privileges.is_subset(&owner.privileges));

    assert!(
        session::load_live(f.db(), started.id)
            .await
            .unwrap()
            .is_some()
    );

    // Paused: not live, and its approvals wait.
    sqlx::query("UPDATE agent_principal SET lifecycle_state = 'paused' WHERE user_ref = $1")
        .bind(agent)
        .execute(f.db())
        .await
        .unwrap();
    assert!(
        session::load_live(f.db(), started.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        session::load_for_execution(f.db(), started.id)
            .await
            .unwrap(),
        SessionForExecution::Paused
    ));
    assert!(
        attome_security::resolve_uncached(f.db(), agent)
            .await
            .is_err(),
        "a paused agent resolves to nothing"
    );

    // Revoked: gone for good.
    sqlx::query("UPDATE agent_principal SET lifecycle_state = 'revoked' WHERE user_ref = $1")
        .bind(agent)
        .execute(f.db())
        .await
        .unwrap();
    assert!(matches!(
        session::load_for_execution(f.db(), started.id)
            .await
            .unwrap(),
        SessionForExecution::Gone
    ));
}

/// An agent account sponsored by `sponsor`, active.
async fn agent_of(db: &attome_db::DbPool, sponsor: Uuid) -> Uuid {
    let agent = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, principal_kind) VALUES ($1, $2, 'agent', 2)",
    )
    .bind(agent)
    .bind(format!("agent-{}@internal.attome", agent.simple()))
    .execute(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO agent_principal (user_ref, sponsor_user_ref, created_by) VALUES ($1, $2, $2)",
    )
    .bind(agent)
    .bind(sponsor)
    .execute(db)
    .await
    .unwrap();
    agent
}

async fn state_of(db: &attome_db::DbPool, agent: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT lifecycle_state, state_reason FROM agent_principal WHERE user_ref = $1")
        .bind(agent)
        .fetch_one(db)
        .await
        .unwrap()
}

#[tokio::test]
async fn sponsor_deactivation_pauses_agent() {
    let f = skip_if_no_db!(fixture().await);
    let sponsor = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, user_name) VALUES ($1, $2, 'sponsor')")
        .bind(sponsor)
        .bind(format!("sponsor-{}@example.invalid", sponsor.simple()))
        .execute(f.db())
        .await
        .unwrap();
    let first = agent_of(f.db(), sponsor).await;
    let second = agent_of(f.db(), sponsor).await;
    assert!(
        attome_security::resolve_uncached(f.db(), first)
            .await
            .is_ok()
    );

    // The deactivation's own transaction pauses what the sponsor sponsors.
    let mut tx = f.db().begin().await.unwrap();
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(sponsor)
        .execute(&mut *tx)
        .await
        .unwrap();
    let paused = attome_security::agent_scope::pause_sponsored(&mut tx, sponsor)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(paused.len(), 2);
    assert_eq!(
        state_of(f.db(), first).await,
        ("paused".to_owned(), Some("sponsor_lost".to_owned()))
    );
    assert!(
        attome_security::resolve_uncached(f.db(), first)
            .await
            .is_err(),
        "the next agent request fails"
    );

    // The daily backstop catches one resumed while the sponsor is gone.
    sqlx::query("UPDATE agent_principal SET lifecycle_state = 'active' WHERE user_ref = $1")
        .bind(second)
        .execute(f.db())
        .await
        .unwrap();
    assert!(
        attome_security::agent_scope::reconcile_sponsors(f.db())
            .await
            .unwrap()
            >= 1
    );
    assert_eq!(state_of(f.db(), second).await.0, "paused");
}
