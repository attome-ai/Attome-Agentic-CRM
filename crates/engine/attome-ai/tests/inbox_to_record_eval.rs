//! AI3-T1: the inbox-to-record agent's definition and its evaluation cases,
//! checked without a database or a model.
//!
//! - The shipped agent (`platform-bundles/attome-ai-inbox-agent.json`) names
//!   its policy, and the policy has limits.
//! - The only Consequential tool the policy allows is the acknowledgement
//!   (`email.send`), which waits for a person's approval or its undo window.
//! - Every `expected_tool` case in `tests/fixtures/inbox_to_record.json`
//!   names at least one tool the policy allows and the registry knows; every
//!   `needs_approval` case names allowed Consequential tools only.
//! - Every `must_refuse` case's actions are outside the policy or
//!   Consequential, so the gate stops them for a person.
//! - The cases come in Arabic and English.
//!
//! The live, per-model run of these cases is the conversation evaluation's
//! (`tests/conversation_eval.rs`); this keeps the definition and the cases
//! from drifting apart.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::descriptor::RiskTier;
use attome_ai::registry::ActionRegistry;
use serde_json::Value;

/// The step that reaches the sender, the only Consequential tool allowed.
const CONTACT: [&str; 1] = ["email.send"];

fn bundle() -> Value {
    serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-ai-inbox-agent.json"
    ))
    .expect("the bundle parses")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/inbox_to_record.json"))
        .expect("the fixture parses")
}

fn rows<'a>(bundle: &'a Value, entity: &str) -> Vec<&'a Value> {
    bundle["record_sets"]
        .as_array()
        .expect("record sets")
        .iter()
        .filter(|rs| rs["entity"] == entity)
        .flat_map(|rs| rs["rows"].as_array().expect("rows").iter())
        .collect()
}

fn allowed() -> Vec<String> {
    let bundle = bundle();
    let policy = rows(&bundle, "ai_agent_policy")
        .into_iter()
        .find(|p| p["name"] == "Inbox to Record")
        .cloned()
        .expect("the Inbox to Record policy");
    policy["allowed_action_ids"]
        .as_array()
        .expect("allowed actions")
        .iter()
        .map(|a| a.as_str().expect("an action id").to_owned())
        .collect()
}

#[test]
fn agent_inbox_names_its_policy() {
    let bundle = bundle();
    let agent = rows(&bundle, "ai_agent")
        .into_iter()
        .find(|a| a["name"] == "inbox_to_record")
        .expect("the inbox_to_record agent");
    assert_eq!(agent["policy_ref"]["key"]["name"], "Inbox to Record");
    assert!(
        agent["system_instructions"]
            .as_str()
            .is_some_and(|s| s.contains("inbox.file_message") && s.contains("email.send")),
        "the instructions say how it files the email and acknowledges it"
    );
    let policy = rows(&bundle, "ai_agent_policy")
        .into_iter()
        .find(|p| p["name"] == "Inbox to Record")
        .expect("the policy");
    assert_eq!(policy["risk_ceiling"], "consequential");
    for limit in [
        "max_invocations_per_session",
        "max_writes_per_day",
        "max_tokens_per_session",
        "max_session_duration_minutes",
    ] {
        assert!(
            policy[limit].as_i64().is_some_and(|n| n > 0),
            "{limit} is set"
        );
    }
    let registry = ActionRegistry::new();
    for id in allowed() {
        let d = registry
            .resolve(&id)
            .unwrap_or_else(|| panic!("{id} is not a registered action"));
        if d.risk == RiskTier::Consequential {
            assert!(
                CONTACT.contains(&id.as_str()),
                "{id} is Consequential but not a contact step"
            );
        }
    }
}

#[test]
fn agent_inbox_eval_cases_match_the_policy() {
    let allowed = allowed();
    let registry = ActionRegistry::new();
    let fixture = fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    let (mut arabic, mut english) = (0, 0);
    for case in cases {
        let id = case["id"].as_str().expect("an id");
        match case["language"].as_str() {
            Some("ar") => arabic += 1,
            Some("en") => english += 1,
            other => panic!("{id}: language {other:?}"),
        }
        match case["category"].as_str() {
            Some("expected_tool") => {
                let tools: Vec<&str> = case["expect_tool_any_of"]
                    .as_array()
                    .expect("expected tools")
                    .iter()
                    .map(|t| t.as_str().expect("a tool"))
                    .collect();
                assert!(
                    tools.iter().any(|t| allowed.iter().any(|a| a == t)),
                    "{id}: none of {tools:?} is in the policy"
                );
                for t in tools {
                    assert!(registry.resolve(t).is_some(), "{id}: {t} is not registered");
                }
            }
            Some("needs_approval") => {
                for t in case["expect_tool_any_of"].as_array().expect("expected tools") {
                    let t = t.as_str().expect("a tool");
                    assert!(
                        allowed.iter().any(|a| a == t),
                        "{id}: {t} is not in the policy"
                    );
                    assert!(
                        registry
                            .resolve(t)
                            .is_some_and(|d| d.risk == RiskTier::Consequential),
                        "{id}: {t} would reach the sender without a person"
                    );
                }
            }
            Some("must_refuse") => {
                for t in case["never_executes"].as_array().expect("never_executes") {
                    let t = t.as_str().expect("a tool");
                    let consequential = registry
                        .resolve(t)
                        .is_some_and(|d| d.risk == RiskTier::Consequential);
                    assert!(
                        !allowed.iter().any(|a| a == t) || consequential,
                        "{id}: {t} would run without a person"
                    );
                }
            }
            other => panic!("{id}: category {other:?}"),
        }
    }
    assert!(arabic >= 3 && english >= 3, "cases in both languages");
}
