//! AH6 (trial mode) and AH8-T9 (earned autonomy), end to end against a
//! throwaway database: a trial session records instead of acting, the
//! comparison job closes decisions, and strong trial agreement proposes an
//! autonomy raise an administrator accepts.
//!
//! The comparison's same/different rules are unit-tested in `trial.rs`; the
//! go-live threshold in `trial::go_live_refusal`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test agent_trial -- --test-threads=1
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
use attome_ai::execute::ActionOutcome;
use attome_ai::session::AgentSession;
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

use common::{Fixture, fixture};

async fn trial_session(f: &Fixture, definition: Uuid) -> AgentSession {
    let mut session = attome_ai::session::start(
        f.db(),
        &attome_audit::audit_service(&f.state),
        attome_ai::session::SessionStart {
            owner_user_id: f.owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: Some(definition),
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session");
    attome_ai::session::mark_trial(f.db(), &attome_audit::audit_service(&f.state), &mut session)
        .await
        .expect("mark trial");
    session
}

#[tokio::test]
async fn a_trial_session_records_and_does_not_write() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    let session = trial_session(&f, definition).await;
    let loaded = attome_ai::session::load_live(f.db(), session.id)
        .await
        .expect("load")
        .expect("live");
    assert!(loaded.trial, "the flag is read back off the row");

    let id = f.insert_record("open").await;
    let security = Arc::new(
        attome_security::resolve_uncached(f.db(), f.owner)
            .await
            .unwrap(),
    );
    let mut ctx = attome_ai::turn::context_for(security, &loaded);
    ctx.idempotency_key = Some("t1".into());
    let outcome = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({ "entity": f.entity, "record_id": id }),
        )
        .await
        .expect("dispatch");
    let ActionOutcome::Completed { result, .. } = outcome else {
        panic!("a trial write is recorded, not asked or held: {outcome:?}");
    };
    assert_eq!(result["status"], "recorded_in_trial");
    assert!(f.record(id).await.1, "nothing was deleted");

    let (action, target, agent): (String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT action_id, target_record_id, agent_ref FROM ai_trial_decision WHERE agent_session_id = $1",
    )
    .bind(session.id)
    .fetch_one(f.db())
    .await
    .unwrap();
    assert_eq!(action, "record.delete");
    assert_eq!(target, Some(id));
    assert_eq!(agent, Some(definition));
}

#[tokio::test]
async fn the_comparison_closes_decisions_older_than_a_day() {
    let f = skip_if_no_db!(fixture().await);
    let session = trial_session(&f, Uuid::now_v7()).await;
    let old: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_trial_decision (agent_session_id, action_id, args, target_entity, target_record_id, created_at) \
         VALUES ($1, 'record.update', $2, $3, $4, now() - interval '25 hours') RETURNING id",
    )
    .bind(session.id)
    .bind(json!({ "values": { "status": "won" } }))
    .bind(&f.entity)
    .bind(Uuid::now_v7())
    .fetch_one(f.db())
    .await
    .unwrap();
    let fresh: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_trial_decision (agent_session_id, action_id, args) \
         VALUES ($1, 'record.update', '{}') RETURNING id",
    )
    .bind(session.id)
    .fetch_one(f.db())
    .await
    .unwrap();

    attome_ai::trial::compare_due(&f.state)
        .await
        .expect("compare");
    let outcome = |id: Uuid| {
        let db = f.db().clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT human_outcome FROM ai_trial_decision WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&db)
            .await
            .unwrap()
        }
    };
    assert_eq!(
        outcome(old).await.as_deref(),
        Some("none"),
        "no person touched it"
    );
    assert_eq!(outcome(fresh).await, None, "a person still has time");
}

#[tokio::test]
async fn strong_trial_agreement_proposes_a_raise_an_admin_accepts() {
    let f = skip_if_no_db!(fixture().await);
    let definition = Uuid::now_v7();
    let session = trial_session(&f, definition).await;
    sqlx::query(
        "INSERT INTO ai_trial_decision (agent_session_id, agent_ref, action_id, args, human_outcome, compared_at) \
         SELECT $1, $2, 'record.update', '{}', 'same', now() FROM generate_series(1, $3)",
    )
    .bind(session.id)
    .bind(definition)
    .bind(i32::try_from(attome_ai::autonomy::RAISE_MIN_CASES).unwrap())
    .execute(f.db())
    .await
    .unwrap();

    let stats = attome_ai::autonomy::propose_raises(&f.state)
        .await
        .expect("propose");
    assert!(stats.proposed >= 1, "{stats:?}");
    let (proposal, from, to): (Uuid, Option<i16>, i16) = sqlx::query_as(
        "SELECT id, from_level, to_level FROM ai_autonomy_proposal \
         WHERE agent_definition_id = $1 AND action_id = 'record.update' AND status = 'open'",
    )
    .bind(definition)
    .fetch_one(f.db())
    .await
    .unwrap();
    assert_eq!(from, None, "from the built-in rule");
    assert_eq!(
        to,
        AutonomyLevel::ActOnReview.as_i16(),
        "one step above ask first"
    );

    // Proposing again while one is open adds nothing.
    attome_ai::autonomy::propose_raises(&f.state)
        .await
        .expect("propose");
    let open: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_autonomy_proposal WHERE agent_definition_id = $1 AND status = 'open'",
    )
    .bind(definition)
    .fetch_one(f.db())
    .await
    .unwrap();
    assert_eq!(open, 1);

    attome_ai::autonomy::decide_proposal(&f.state, f.owner, proposal, true)
        .await
        .expect("accept");
    let level: i16 = sqlx::query_scalar(
        "SELECT level FROM ai_autonomy_level WHERE agent_definition_id = $1 AND action_id = 'record.update'",
    )
    .bind(definition)
    .fetch_one(f.db())
    .await
    .unwrap();
    assert_eq!(level, AutonomyLevel::ActOnReview.as_i16());
    assert!(
        attome_ai::autonomy::decide_proposal(&f.state, f.owner, proposal, true)
            .await
            .is_err(),
        "a decided proposal cannot be decided again"
    );
}
