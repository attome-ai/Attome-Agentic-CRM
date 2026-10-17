//! The follow-up agent (roadmap AI4-T5, AI4-T8): running a ledger item, the
//! rule's daily cap, the AI switch, and the approval gate on sending.
//! Needs a test database (`DATABASE_URL`); skips without one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_ai::execute::ActionOutcome;
use attome_ai::followup_run::{RunOutcome, run_item};
use attome_core::EngineState;
use serde_json::{Value, json};
use uuid::Uuid;

/// The rule entity the platform changeset provisions, made here directly
/// (a throwaway database). Idempotent across the tests of one process.
async fn ensure_rule_entity(state: &EngineState) {
    let db = &state.base.db;
    let entity = attome_metadata::provision::ensure_entity(
        db,
        "ai_followup_rule",
        "Follow-up Rule",
        None,
        false,
    )
    .await
    .expect("rule entity");
    for (name, kind) in [
        ("name", "text"),
        ("reason", "text"),
        ("target_entity", "text"),
        ("idle_days", "number"),
        ("mode", "text"),
        ("channel", "text"),
        ("daily_cap", "number"),
    ] {
        attome_metadata::provision::ensure_attribute(
            db, entity, name, name, kind, false, false, false, false, None, None,
        )
        .await
        .expect("rule attribute");
    }
}

async fn rule(state: &EngineState, mode: &str, daily_cap: Option<i64>) -> Uuid {
    ensure_rule_entity(state).await;
    sqlx::query_scalar(
        "INSERT INTO ai_followup_rule (id, name, reason, target_entity, idle_days, mode, \
             channel, daily_cap, is_active) \
         VALUES ($1, 'test', 'stalled_deal', 'opportunity', 7, $2, 'email', $3, true) \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(mode)
    .bind(daily_cap)
    .fetch_one(&state.base.db)
    .await
    .expect("insert rule")
}

async fn item(state: &EngineState, rule: Uuid, owner: Uuid, entity: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO ai_followup_item \
             (rule_ref, entity_logical_name, record_id, owner_user_id, reason, window_start) \
         VALUES ($1, $2, $3, $4, 'stalled_deal', current_date) RETURNING id",
    )
    .bind(rule)
    .bind(entity)
    .bind(Uuid::now_v7())
    .bind(owner)
    .fetch_one(&state.base.db)
    .await
    .expect("insert item")
}

async fn status(state: &EngineState, item: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM ai_followup_item WHERE id = $1")
        .bind(item)
        .fetch_one(&state.base.db)
        .await
        .expect("item status")
}

async fn reminders(state: &EngineState, owner: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM notification_dispatch WHERE recipient_user_ref = $1")
        .bind(owner)
        .fetch_one(&state.base.db)
        .await
        .expect("count dispatches")
}

/// The shipped rule entity carries every field the run and the actions read.
#[test]
fn ai4_rule_entity_is_provisioned() {
    let bundle: Value = serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-ai-followup.json"
    ))
    .expect("bundle parses");
    let entity = bundle["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .find(|e| e["logicalname"] == "ai_followup_rule")
        .expect("ai_followup_rule is declared");
    let fields: Vec<&str> = entity["attributes"]
        .as_array()
        .expect("attributes")
        .iter()
        .filter_map(|a| a["logicalname"].as_str())
        .collect();
    for needed in [
        "reason",
        "target_entity",
        "idle_days",
        "mode",
        "channel",
        "daily_cap",
    ] {
        assert!(fields.contains(&needed), "ai_followup_rule lacks {needed}");
    }
}

// feature: AI4
#[tokio::test]
async fn ai4_run_item_is_idempotent() {
    let Some(f) = common::fixture().await else {
        eprintln!("SKIP: DATABASE_URL not set");
        return;
    };
    let rule = rule(&f.state, "remind_owner", None).await;
    let item = item(&f.state, rule, f.owner, &f.entity).await;
    let before = reminders(&f.state, f.owner).await;

    assert_eq!(
        run_item(&f.state, item).await.expect("first run"),
        RunOutcome::Reminded
    );
    assert_eq!(status(&f.state, item).await, "reminded");
    assert!(matches!(
        run_item(&f.state, item).await.expect("second run"),
        RunOutcome::Skipped(_)
    ));
    assert_eq!(reminders(&f.state, f.owner).await, before + 1);
}

// feature: AI4
// negative: followup.remind_owner
#[tokio::test]
async fn ai4_daily_cap_refuses() {
    let Some(f) = common::fixture().await else {
        eprintln!("SKIP: DATABASE_URL not set");
        return;
    };
    let rule = rule(&f.state, "remind_owner", Some(1)).await;
    let first = item(&f.state, rule, f.owner, &f.entity).await;
    let second = item(&f.state, rule, f.owner, &f.entity).await;

    assert_eq!(
        run_item(&f.state, first).await.unwrap(),
        RunOutcome::Reminded
    );
    assert_eq!(
        run_item(&f.state, second).await.unwrap(),
        RunOutcome::Skipped("daily cap reached")
    );
    assert_eq!(status(&f.state, second).await, "open");
}

// feature: AI4
#[tokio::test]
async fn ai4_kill_switch_skips() {
    let Some(state) = common::test_state_with(|c| c.inference.ai.chat = false).await else {
        eprintln!("SKIP: DATABASE_URL not set");
        return;
    };
    let owner = common::seed_user(&state.base.db, true).await;
    let entity = common::provision_entity(&state, false).await;
    let rule = rule(&state, "remind_owner", None).await;
    let item = item(&state, rule, owner, &entity).await;

    assert_eq!(
        run_item(&state, item).await.unwrap(),
        RunOutcome::Skipped("AI is switched off")
    );
    assert_eq!(status(&state, item).await, "open");
    assert_eq!(reminders(&state, owner).await, 0);
}

// feature: AI4
// negative: followup.send_message
#[tokio::test]
async fn ai4_send_message_needs_approval_for_agent() {
    let Some(f) = common::fixture().await else {
        eprintln!("SKIP: DATABASE_URL not set");
        return;
    };
    let rule = rule(&f.state, "send_message", None).await;
    let item = item(&f.state, rule, f.owner, &f.entity).await;
    let ctx = f.agent_ctx("ai4-send-1").await;

    let outcome = f
        .dispatch(
            &ctx,
            "followup.send_message",
            json!({
                "item_id": item, "channel": "email", "to": ["buyer@example.com"],
                "subject": "Checking in", "body": "Any news on the proposal?"
            }),
        )
        .await
        .expect("dispatch");
    assert!(
        matches!(outcome, ActionOutcome::ApprovalRequired { .. }),
        "an agent's send waits for a person: {outcome:?}"
    );
    // Nothing ran: the item is untouched.
    assert_eq!(status(&f.state, item).await, "open");
}
