//! AH5-T6: agents watched against their baseline, against a throwaway
//! database.
//!
//! An `ai_agent` definition with a learned baseline (one write an hour) runs
//! a burst of forty record writes in the current hour: the five-minute check
//! pauses its live session, suspends the agent and notifies its owner. An
//! agent still in its learning week is left alone, and nothing the jobs do
//! sets a stopped agent back to active: only a person's update does.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test agent_behaviour -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_testkit::skip_if_no_db;
use chrono::Utc;
use uuid::Uuid;

use common::{Fixture, fixture};

/// Provisions the `ai_agent` columns the trip reads and adds an active agent
/// owned by the fixture's owner.
async fn agent(f: &Fixture) -> Uuid {
    let entity = attome_metadata::provision::ensure_entity(
        f.db(),
        "ai_agent",
        "AI Agent",
        Some("name"),
        false,
    )
    .await
    .expect("provision ai_agent");
    for name in ["name", "status"] {
        attome_metadata::provision::ensure_attribute(
            f.db(),
            entity,
            name,
            name,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .expect("provision attribute");
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent (id, name, status, owner_ref, is_active, row_version) \
         VALUES ($1, 'watched agent', 'active', $2, true, 0)",
    )
    .bind(id)
    .bind(f.owner)
    .execute(f.db())
    .await
    .expect("an agent");
    id
}

async fn session_of(f: &Fixture, agent: Uuid) -> Uuid {
    attome_ai::session::start(
        f.db(),
        &attome_audit::audit_service(&f.state),
        attome_ai::session::SessionStart {
            owner_user_id: f.owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: Some(agent),
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session")
    .id
}

/// A baseline of about one write an hour at every hour of the day, its
/// activity begun `days_ago` days back.
async fn baseline(f: &Fixture, agent: Uuid, days_ago: i32) {
    sqlx::query(
        "INSERT INTO ai_agent_baseline \
             (agent_ref, first_activity_at, mean_writes_per_hour, stddev_writes_per_hour, \
              mean_deletes_per_hour, stddev_deletes_per_hour, usual_entities, usual_hours) \
         VALUES ($1, now() - make_interval(days => $2), 1, 0.5, 0, 0, $3, \
                 ARRAY(SELECT generate_series(0, 23))::smallint[])",
    )
    .bind(agent)
    .bind(days_ago)
    .bind(vec![f.entity.clone()])
    .execute(f.db())
    .await
    .expect("a baseline");
}

/// `writes` completed record updates by `session` just now.
async fn burst(f: &Fixture, session: Uuid, writes: i32) {
    sqlx::query(
        "INSERT INTO action_invocation \
             (action_id, initiator, acting_user_id, outcome, agent_session_id) \
         SELECT 'record.update', 1, $1, 'completed', $2 FROM generate_series(1, $3)",
    )
    .bind(f.owner)
    .bind(session)
    .bind(writes)
    .execute(f.db())
    .await
    .expect("a burst of writes");
}

async fn status(f: &Fixture, agent: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM ai_agent WHERE id = $1")
        .bind(agent)
        .fetch_one(f.db())
        .await
        .expect("agent status")
}

#[tokio::test]
async fn burst_of_writes_pauses_agent_and_notifies_owner() {
    let f = skip_if_no_db!(fixture().await);
    let agent = agent(&f).await;
    let session = session_of(&f, agent).await;
    baseline(&f, agent, 30).await;
    burst(&f, session, 40).await;

    let stopped = attome_ai::behaviour::run_check(&f.state, Utc::now())
        .await
        .expect("check");
    assert!(stopped >= 1, "the departing agent was stopped");
    assert_eq!(status(&f, agent).await, "suspended");
    let paused: (bool, Option<String>) = sqlx::query_as(
        "SELECT paused_at IS NOT NULL, paused_reason FROM agent_session WHERE id = $1",
    )
    .bind(session)
    .fetch_one(f.db())
    .await
    .expect("session");
    assert_eq!(paused, (true, Some("automatic: volume".to_owned())));
    let notified: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_dispatch \
          WHERE recipient_user_ref = $1 AND subject LIKE '%watched agent%'",
    )
    .bind(f.owner)
    .fetch_one(f.db())
    .await
    .expect("notifications");
    assert!(notified >= 1, "the owner was told");
}

#[tokio::test]
async fn agent_in_learning_period_is_not_tripped() {
    let f = skip_if_no_db!(fixture().await);
    let agent = agent(&f).await;
    let session = session_of(&f, agent).await;
    baseline(&f, agent, 2).await;
    burst(&f, session, 40).await;

    let found = attome_ai::behaviour::check_departures(f.db(), Utc::now())
        .await
        .expect("check");
    assert!(found.iter().all(|d| d.agent_ref != agent), "{found:?}");
    attome_ai::behaviour::run_check(&f.state, Utc::now())
        .await
        .expect("run");
    assert_eq!(status(&f, agent).await, "active");
}

#[tokio::test]
async fn job_actor_cannot_switch_agent_back_on() {
    let f = skip_if_no_db!(fixture().await);
    let agent = agent(&f).await;
    let session = session_of(&f, agent).await;
    baseline(&f, agent, 30).await;
    burst(&f, session, 40).await;
    attome_ai::behaviour::run_check(&f.state, Utc::now())
        .await
        .expect("check");
    assert_eq!(status(&f, agent).await, "suspended");

    // The burst is gone and the jobs run again: nothing they do turns the
    // agent back on, and a second trip finds nothing left to stop.
    sqlx::query("DELETE FROM action_invocation WHERE agent_session_id = $1")
        .bind(session)
        .execute(f.db())
        .await
        .expect("clear the burst");
    attome_ai::behaviour::run_check(&f.state, Utc::now())
        .await
        .expect("check again");
    attome_ai::behaviour::run(&f.state, Utc::now())
        .await
        .expect("hourly run");
    assert_eq!(status(&f, agent).await, "suspended");
    let departure = attome_ai::behaviour::Departure {
        agent_ref: agent,
        kind: attome_ai::behaviour::DepartureKind::Volume,
        observed: 40.0,
        expected: 1.0,
        entity: None,
    };
    let again = attome_ai::behaviour::trip(&f.state, &departure)
        .await
        .expect("trip");
    assert!(!again, "not stopped or alerted twice");
}
