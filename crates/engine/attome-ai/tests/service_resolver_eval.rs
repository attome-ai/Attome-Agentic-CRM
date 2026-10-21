//! AI2-T1: the service resolver agent's definition and its evaluation
//! cases, checked without a database or a model.
//!
//! - The shipped agent (`platform-bundles/attome-ai-service-agent.json`)
//!   names its policy, and the policy is Reversible-capped with limits.
//! - Every `expected_tool` case in `tests/fixtures/service_resolver.json`
//!   names at least one tool the policy allows and the registry knows.
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

fn bundle() -> Value {
    serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-ai-service-agent.json"
    ))
    .expect("the bundle parses")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/service_resolver.json"))
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
        .find(|p| p["name"] == "Service Resolver")
        .cloned()
        .expect("the Service Resolver policy");
    policy["allowed_action_ids"]
        .as_array()
        .expect("allowed actions")
        .iter()
        .map(|a| a.as_str().expect("an action id").to_owned())
        .collect()
}

#[test]
fn ai2_agent_names_its_capped_policy() {
    let bundle = bundle();
    let agent = rows(&bundle, "ai_agent")
        .into_iter()
        .find(|a| a["name"] == "service_resolver")
        .expect("the service_resolver agent");
    assert_eq!(agent["policy_ref"]["key"]["name"], "Service Resolver");
    assert!(
        agent["system_instructions"]
            .as_str()
            .is_some_and(|s| s.contains("handoff.to_person")),
        "the instructions say how it hands off"
    );
    let policy = rows(&bundle, "ai_agent_policy")
        .into_iter()
        .find(|p| p["name"] == "Service Resolver")
        .expect("the policy");
    assert_eq!(policy["risk_ceiling"], "reversible");
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
        assert_ne!(d.risk, RiskTier::Consequential, "{id} is above the ceiling");
    }
}

#[test]
fn ai2_eval_cases_match_the_policy() {
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
