//! Agent sessions and invocation idempotency, against a real database
//! (TODO-039, TODO-043).
//!
//! Two negative tests carry this file: **revocation takes effect on the next
//! invocation**, and **a replayed tool call produces exactly one row**. Both are
//! properties nothing else in the system can compensate for — a revoked agent
//! that finishes its loop has already done the damage, and a duplicated
//! `record.create` is visible to the customer.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test agent_session
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::descriptor::{ActionId, RiskTier};
use attome_ai::session::{
    InvocationRecord, SessionStart, load_live, pause, prior_invocation, record_invocation, resume,
    revoke, start,
};
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

async fn open_session(db: &DbPool, owner: Uuid, ceiling: i16) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface) \
         VALUES ($1, $2, 'test') RETURNING id",
    )
    .bind(owner)
    .bind(ceiling)
    .fetch_one(db)
    .await
    .expect("open session")
}

/// **TODO-039's verify line.** Revocation takes effect on the next invocation.
///
/// Checked by reloading the session, not by consulting a cached flag: a cache
/// is exactly the thing that would let a revoked agent finish the loop it was
/// revoked in the middle of.
#[tokio::test]
async fn revocation_takes_effect_on_the_next_invocation() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let session_id = open_session(&db, owner, 1).await;

    let live = load_live(&db, session_id).await.expect("load");
    assert!(live.is_some(), "a fresh session must load");

    assert!(
        revoke(&db, session_id, admin, "operator stopped the agent")
            .await
            .expect("revoke"),
        "the first revocation takes effect"
    );

    assert!(
        load_live(&db, session_id).await.expect("load").is_none(),
        "a revoked session must not load, so the next invocation cannot dispatch"
    );

    // Idempotent: revoking twice is not an error, and the first revocation
    // stands — an auditor's "when was this stopped" must not be overwritten by
    // a second click.
    assert!(
        !revoke(&db, session_id, admin, "again")
            .await
            .expect("revoke"),
        "a second revocation reports that it changed nothing"
    );
    let reason: String =
        sqlx::query_scalar("SELECT revoked_reason FROM agent_session WHERE id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("read reason");
    assert_eq!(
        reason, "operator stopped the agent",
        "the first reason stands"
    );
}

/// An ended session does not load either, and is indistinguishable from a
/// revoked one at this boundary — a caller has no reason to tell them apart,
/// and distinguishing them would invite treating one as recoverable.
#[tokio::test]
async fn an_ended_session_does_not_load() {
    let db = skip_if_no_db!(test_db().await);
    let session_id = open_session(&db, Uuid::now_v7(), 0).await;
    sqlx::query("UPDATE agent_session SET ended_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&db)
        .await
        .expect("end session");
    assert!(load_live(&db, session_id).await.expect("load").is_none());
}

/// **TODO-043's negative test.** A replayed tool call produces exactly one row.
#[tokio::test]
async fn a_replayed_tool_call_records_exactly_one_invocation() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let session_id = open_session(&db, owner, 2).await;
    let tool_call = format!("call_{}", Uuid::now_v7().simple());
    let result = serde_json::json!({ "record_id": "abc" });

    assert!(
        record_invocation(
            &db,
            InvocationRecord {
                session_id: Some(session_id),
                tool_call_id: Some(&tool_call),
                action_id: ActionId("record.create"),
                is_agent: true,
                acting_user_id: owner,
                outcome: "completed",
                result: Some(&result),
            },
        )
        .await
        .expect("first"),
        "the first invocation is recorded"
    );

    // The retry. `ON CONFLICT DO NOTHING` rather than check-then-insert,
    // because check-then-insert has a window and a retrying tool loop is
    // precisely what finds it.
    assert!(
        !record_invocation(
            &db,
            InvocationRecord {
                session_id: Some(session_id),
                tool_call_id: Some(&tool_call),
                action_id: ActionId("record.create"),
                is_agent: true,
                acting_user_id: owner,
                outcome: "completed",
                result: Some(&result),
            },
        )
        .await
        .expect("replay"),
        "the replay must not insert a second row"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation \
          WHERE agent_session_id = $1 AND tool_call_id = $2",
    )
    .bind(session_id)
    .bind(&tool_call)
    .fetch_one(&db)
    .await
    .expect("count");
    assert_eq!(count, 1, "exactly one record, not two");

    // And the replay can read what the first call produced instead of running
    // the action again.
    let prior = prior_invocation(&db, session_id, &tool_call)
        .await
        .expect("prior")
        .expect("a prior invocation exists");
    assert_eq!(prior.outcome, "completed");
    assert_eq!(prior.result, Some(result));
}

/// A `requires_approval` outcome occupies the key even though it has no result.
///
/// Without this, a retry creates a **second approval request** for one intent —
/// and an approver looking at two identical requests cannot tell which is real,
/// or whether approving both does the thing twice.
#[tokio::test]
async fn an_approval_pending_invocation_still_claims_its_key() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let session_id = open_session(&db, owner, 2).await;
    let tool_call = format!("call_{}", Uuid::now_v7().simple());

    record_invocation(
        &db,
        InvocationRecord {
            session_id: Some(session_id),
            tool_call_id: Some(&tool_call),
            action_id: ActionId("record.delete"),
            is_agent: true,
            acting_user_id: owner,
            outcome: "requires_approval",
            result: None,
        },
    )
    .await
    .expect("first");

    assert!(
        !record_invocation(
            &db,
            InvocationRecord {
                session_id: Some(session_id),
                tool_call_id: Some(&tool_call),
                action_id: ActionId("record.delete"),
                is_agent: true,
                acting_user_id: owner,
                outcome: "requires_approval",
                result: None,
            },
        )
        .await
        .expect("replay"),
        "a pending approval must not be duplicated by a retry"
    );

    let prior = prior_invocation(&db, session_id, &tool_call)
        .await
        .expect("prior")
        .expect("exists");
    assert_eq!(prior.outcome, "requires_approval");
    assert!(prior.result.is_none());
}

/// Two *different* tool calls in one session are two invocations. The
/// idempotency key must not be so coarse that it swallows legitimate work — a
/// tool loop making three calls has made three calls.
#[tokio::test]
async fn different_tool_calls_in_one_session_are_distinct() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let session_id = open_session(&db, owner, 1).await;

    for n in 0..3 {
        assert!(
            record_invocation(
                &db,
                InvocationRecord {
                    session_id: Some(session_id),
                    tool_call_id: Some(&format!("call_{n}")),
                    action_id: ActionId("record.get"),
                    is_agent: true,
                    acting_user_id: owner,
                    outcome: "completed",
                    result: None,
                },
            )
            .await
            .expect("insert"),
            "call {n} is its own invocation"
        );
    }

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM action_invocation WHERE agent_session_id = $1")
            .bind(session_id)
            .fetch_one(&db)
            .await
            .expect("count");
    assert_eq!(count, 3);
}

/// A human-initiated invocation carries no tool call id, and several of them
/// coexist.
///
/// The unique index is partial (`WHERE tool_call_id IS NOT NULL`) for exactly
/// this: a plain UNIQUE would risk collapsing every human invocation in a
/// session into one row under NULL semantics.
#[tokio::test]
async fn human_invocations_without_a_tool_call_id_are_not_deduplicated() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();

    for _ in 0..3 {
        assert!(
            record_invocation(
                &db,
                InvocationRecord {
                    session_id: None,
                    tool_call_id: None,
                    action_id: ActionId("record.get"),
                    is_agent: false,
                    acting_user_id: owner,
                    outcome: "completed",
                    result: None,
                },
            )
            .await
            .expect("insert"),
            "a human invocation is never deduplicated by this mechanism"
        );
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation \
          WHERE acting_user_id = $1 AND tool_call_id IS NULL",
    )
    .bind(owner)
    .fetch_one(&db)
    .await
    .expect("count");
    assert_eq!(count, 3);
}

/// M32 Phase 1 (D-450). **`session::start` records which definition opened
/// it, and copies the definition's constraints onto the row verbatim** — the
/// `agent_definition_ref` traceability column (migration `0253`) round-trips,
/// and the ceiling/allow-list `start` was given are exactly what `load_live`
/// reads back. This is the primitive `crate::agent::start_session` and
/// `attome_workflow::AgentStep` both call; this test proves the primitive itself
/// without needing either caller's HTTP/entity-read machinery.
#[tokio::test]
async fn starting_a_session_from_a_definition_records_the_reference_and_constraints() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let definition_id = Uuid::now_v7();

    let session = start(
        &db,
        &attome_audit::AuditService::new(&db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: owner,
            risk_ceiling: RiskTier::Reversible,
            allowed_action_ids: Some(vec!["record.get".to_string()]),
            surface: "test",
            agent_definition_ref: Some(definition_id),
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start");

    assert_eq!(session.owner_user_id, owner);
    assert_eq!(session.risk_ceiling, RiskTier::Reversible);
    assert_eq!(
        session.allowed_action_ids,
        Some(vec!["record.get".to_string()])
    );

    let live = load_live(&db, session.id)
        .await
        .expect("load")
        .expect("a freshly started session must load live");
    assert_eq!(live.risk_ceiling, RiskTier::Reversible);
    assert_eq!(
        live.allowed_action_ids,
        Some(vec!["record.get".to_string()])
    );

    let stored_ref: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_definition_ref FROM agent_session WHERE id = $1")
            .bind(session.id)
            .fetch_one(&db)
            .await
            .expect("read agent_definition_ref");
    assert_eq!(
        stored_ref,
        Some(definition_id),
        "the session must record which definition it came from"
    );
}

/// A session opened directly (not from a definition — e.g. the read-only
/// chatbot) leaves `agent_definition_ref` NULL. This is not a defect this
/// column introduces: most sessions today do not originate from a
/// definition at all, and `start` must not require one.
#[tokio::test]
async fn a_session_opened_without_a_definition_leaves_the_reference_null() {
    let db = skip_if_no_db!(test_db().await);
    let session = start(
        &db,
        &attome_audit::AuditService::new(&db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: RiskTier::Read,
            allowed_action_ids: None,
            surface: "test",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start");

    let stored_ref: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_definition_ref FROM agent_session WHERE id = $1")
            .bind(session.id)
            .fetch_one(&db)
            .await
            .expect("read agent_definition_ref");
    assert_eq!(stored_ref, None);
}

/// **The empty-list-is-not-unrestricted invariant, through the whole
/// `start` -> `load_live` round trip.** `Some(vec![])` must survive storage
/// and reload as `Some(vec![])`, never collapsing to `None`.
#[tokio::test]
async fn an_explicit_empty_action_list_survives_the_round_trip() {
    let db = skip_if_no_db!(test_db().await);
    let session = start(
        &db,
        &attome_audit::AuditService::new(&db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: RiskTier::Consequential,
            allowed_action_ids: Some(vec![]),
            surface: "test",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start");

    let live = load_live(&db, session.id)
        .await
        .expect("load")
        .expect("must load");
    assert_eq!(
        live.allowed_action_ids,
        Some(vec![]),
        "an explicit empty list must not collapse into None (unrestricted)"
    );
    assert!(
        !live.permits(ActionId("record.get")),
        "a session deliberately narrowed to nothing must permit nothing"
    );
}

/// An agent invocation must name its session — enforced by the table, not by a
/// caller remembering. Without a session there is nothing to revoke against and
/// nothing to attribute to.
#[tokio::test]
async fn an_agent_invocation_without_a_session_is_rejected_by_the_database() {
    let db = skip_if_no_db!(test_db().await);
    let err = record_invocation(
        &db,
        InvocationRecord {
            session_id: None,
            tool_call_id: Some("call_x"),
            action_id: ActionId("record.get"),
            is_agent: true,
            acting_user_id: Uuid::now_v7(),
            outcome: "completed",
            result: None,
        },
    )
    .await;
    assert!(
        err.is_err(),
        "the CHECK constraint must refuse an agent invocation with no session"
    );
}

/// M33 Phase 1 (D-460), supervisor `agent.pause`/`agent.resume`. A paused
/// session must be exactly as inert to `load_live` as a revoked one — the
/// whole point of pause joining the same enforcement point revoke already
/// uses, rather than being a second, weaker "is this session okay" check a
/// future caller could forget to consult.
#[tokio::test]
async fn a_paused_session_does_not_load_live_and_resuming_restores_it() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let supervisor = Uuid::now_v7();
    let session_id = open_session(&db, owner, 1).await;

    assert!(load_live(&db, session_id).await.expect("load").is_some());

    assert!(
        pause(&db, session_id, supervisor, "investigating a runaway loop")
            .await
            .expect("pause"),
        "the first pause takes effect"
    );
    assert!(
        load_live(&db, session_id).await.expect("load").is_none(),
        "a paused session must not load live — it must be exactly as inert as a revoked one"
    );

    // Idempotent: pausing twice changes nothing further.
    assert!(
        !pause(&db, session_id, supervisor, "again")
            .await
            .expect("pause"),
        "a second pause reports that it changed nothing"
    );

    assert!(
        resume(&db, session_id).await.expect("resume"),
        "the first resume takes effect"
    );
    assert!(
        load_live(&db, session_id).await.expect("load").is_some(),
        "a resumed session loads live again"
    );

    // Idempotent in the other direction too.
    assert!(
        !resume(&db, session_id).await.expect("resume"),
        "resuming a session that is not paused changes nothing"
    );
}

/// A revoked session cannot be paused, and a revoked session cannot be
/// resumed via `resume` either — kill is permanent, and pause must not be
/// able to paper over that. Matches `session::resume`'s own doc comment.
#[tokio::test]
async fn pause_and_resume_do_not_reanimate_a_killed_session() {
    let db = skip_if_no_db!(test_db().await);
    let owner = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let session_id = open_session(&db, owner, 0).await;

    assert!(
        revoke(&db, session_id, admin, "killed")
            .await
            .expect("revoke")
    );

    assert!(
        !pause(&db, session_id, admin, "too late")
            .await
            .expect("pause"),
        "a killed session cannot be paused"
    );
    assert!(
        !resume(&db, session_id).await.expect("resume"),
        "a killed session cannot be resumed — kill is permanent"
    );
    assert!(load_live(&db, session_id).await.expect("load").is_none());
}

/// M33 Phase 1 (D-460): `tainted` round-trips through `start` -> `load_live`,
/// exactly like `risk_ceiling`/`allowed_action_ids` already do. This is the
/// durable half of "taint does not propagate as trust across a handoff" —
/// `attome_ai::context`'s unit tests cover the gate-decision half against an
/// in-memory `AgentSession`; this proves the session this crate actually
/// starts for a tainted `AgentStep` handoff really does persist `tainted`.
#[tokio::test]
async fn a_session_started_tainted_loads_back_tainted() {
    let db = skip_if_no_db!(test_db().await);

    let clean = start(
        &db,
        &attome_audit::AuditService::new(&db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: RiskTier::Read,
            allowed_action_ids: None,
            surface: "workflow",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start");
    assert!(!clean.tainted);
    let live = load_live(&db, clean.id).await.expect("load").expect("live");
    assert!(
        !live.tainted,
        "an untainted session must load back untainted"
    );

    let handed_off = start(
        &db,
        &attome_audit::AuditService::new(&db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "workflow",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: true,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start");
    assert!(
        handed_off.tainted,
        "start() must return the tainted flag it was given"
    );
    let live = load_live(&db, handed_off.id)
        .await
        .expect("load")
        .expect("live");
    assert!(
        live.tainted,
        "a session started downstream of a tainted handoff must not silently \
         load back clean — that would be taint propagating as trust"
    );
}
