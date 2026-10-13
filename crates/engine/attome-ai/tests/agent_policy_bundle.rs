//! D-505 §2 and §5: the shipped `ai_agent_policy` bundle definition agrees
//! with the code it governs. No database: this parses
//! `platform-bundles/attome-ai-agent.json` exactly as boot applies it.
//!
//! - `allowed_action_ids` offers exactly the registry's actions. The entity
//!   engine therefore rejects an unknown action id when a policy is saved, and
//!   a new action cannot ship without the bundle deciding it is grantable.
//! - The ceiling offers exactly the session tiers.
//! - Every limit is positive (D-512 §2). Only `max_tokens_per_session` has a
//!   code maximum. D-512 §1 forbids inventing one for the other three.
//! - Every governance field, and `ai_agent.policy_ref`, is write-restricted
//!   (D-507) without being made read-sensitive.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;

use attome_ai::agent::parse_risk_ceiling;
use attome_ai::registry::ActionRegistry;
use serde_json::Value;

const BUNDLE: &str = include_str!("../../../../platform-bundles/attome-ai-agent.json");

const POLICY: &str = "ai_agent_policy";

const GOVERNANCE_FIELDS: &[&str] = &[
    "risk_ceiling",
    "allowed_action_ids",
    "knowledge_source_refs",
    // C6/D-556: pack references grant term 5, so they are governance state on
    // the same footing as the explicit allow-list.
    "capability_pack_refs",
    "max_invocations_per_session",
    "max_writes_per_day",
    "max_tokens_per_session",
    "max_session_duration_minutes",
];

const LIMITS: &[&str] = &[
    "max_invocations_per_session",
    "max_writes_per_day",
    "max_tokens_per_session",
    "max_session_duration_minutes",
];

fn bundle() -> Value {
    serde_json::from_str(BUNDLE).expect("attome-ai-agent.json parses")
}

fn attribute<'a>(bundle: &'a Value, entity: &str, field: &str) -> &'a Value {
    let entity_def = bundle["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .find(|e| e["logicalname"] == entity)
        .unwrap_or_else(|| panic!("bundle has no entity {entity}"));
    entity_def["attributes"]
        .as_array()
        .expect("attributes")
        .iter()
        .find(|a| a["logicalname"] == field)
        .unwrap_or_else(|| panic!("bundle has no attribute {entity}.{field}"))
}

fn string_choices(field: &Value) -> BTreeSet<String> {
    field["options"]["choices"]
        .as_array()
        .expect("choices")
        .iter()
        .map(|c| c.as_str().expect("string choice").to_owned())
        .collect()
}

#[test]
fn allowed_action_choices_are_exactly_the_registry() {
    let bundle = bundle();
    let field = attribute(&bundle, POLICY, "allowed_action_ids");
    assert_eq!(field["field_type"], "choice");
    assert_eq!(
        field["options"]["multi"], true,
        "an allow-list is a set of actions, stored as TEXT[] like the session's"
    );

    let offered = string_choices(field);
    let registered: BTreeSet<String> = ActionRegistry::new()
        .all()
        .map(|descriptor| descriptor.id.as_str().to_owned())
        .collect();
    assert_eq!(
        offered, registered,
        "ai_agent_policy.allowed_action_ids must offer exactly the registered actions; \
         update platform-bundles/attome-ai-agent.json when the registry changes"
    );
}

#[test]
fn risk_ceiling_offers_exactly_the_session_tiers() {
    let bundle = bundle();
    let field = attribute(&bundle, POLICY, "risk_ceiling");
    assert_eq!(field["field_type"], "choice");
    assert_eq!(
        field["is_required"], true,
        "a policy always states a ceiling"
    );

    let mut tiers: Vec<String> = string_choices(field)
        .iter()
        .map(|choice| {
            let tier = parse_risk_ceiling(choice)
                .unwrap_or_else(|| panic!("{choice:?} is not a session ceiling"));
            format!("{tier:?}")
        })
        .collect();
    tiers.sort();
    assert_eq!(tiers, ["Consequential", "Read", "Reversible"]);
}

/// D-512 §§1–2: every limit is a positive integer, and only
/// `max_tokens_per_session` has a code maximum (`Budget::PER_SESSION_DEFAULT`).
/// `max_writes_per_day` is a session-wide total, which the per-action
/// `DAILY_WRITE_CAP` does not bound. No maximum is invented for it, for
/// invocations, or for duration.
#[test]
fn limits_are_positive_and_capped_only_where_code_has_a_maximum() {
    let bundle = bundle();
    for limit in LIMITS {
        let field = attribute(&bundle, POLICY, limit);
        assert_eq!(field["field_type"], "number", "{limit}");
        assert_eq!(
            field["options"]["min"].as_f64(),
            Some(1.0),
            "{limit} must be positive (D-512 §2)"
        );
    }
    assert_eq!(
        attribute(&bundle, POLICY, "max_tokens_per_session")["options"]["max"].as_f64(),
        Some(attome_inference::budget::Budget::PER_SESSION_DEFAULT.tokens as f64),
        "max_tokens_per_session is capped by Budget::PER_SESSION_DEFAULT"
    );
    for uncapped in [
        "max_invocations_per_session",
        "max_writes_per_day",
        "max_session_duration_minutes",
    ] {
        assert!(
            attribute(&bundle, POLICY, uncapped)["options"]
                .get("max")
                .is_none(),
            "{uncapped} has no code maximum, and D-512 §1 forbids inventing one"
        );
    }
}

#[test]
fn governance_fields_are_write_restricted_but_stay_readable() {
    let bundle = bundle();
    let fields = GOVERNANCE_FIELDS
        .iter()
        .map(|field| (POLICY, *field))
        .chain([("ai_agent", "policy_ref")]);
    for (entity, field) in fields {
        let definition = attribute(&bundle, entity, field);
        assert_eq!(
            definition["is_write_restricted"], true,
            "{entity}.{field} must be write-restricted (D-505 §5, D-507)"
        );
        assert_ne!(
            definition["is_sensitive"], true,
            "{entity}.{field} must stay readable: an operator reads a ceiling without changing it"
        );
    }
}

/// The entity engine refuses a malformed knowledge scope when a policy is
/// saved. Whether each id names a knowledge source the caller can see is
/// decided at session start, not here.
#[test]
fn knowledge_source_refs_accept_only_a_json_array_of_ids() {
    let bundle = bundle();
    let field = attribute(&bundle, POLICY, "knowledge_source_refs");
    assert_eq!(field["field_type"], "text");
    let options = &field["options"];
    let check = |value: &str| {
        attome_field::validate(
            &attome_core::FieldType::Text,
            &Value::String(value.to_owned()),
            Some(options),
        )
    };

    for accepted in [
        "[]",
        r#"["0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e"]"#,
        r#"[ "0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e", "0190F5C1-8B4F-7C3A-9D2E-1F0A2B3C4D5F" ]"#,
    ] {
        assert!(
            check(accepted).is_ok(),
            "{accepted} is a valid knowledge scope"
        );
    }
    for refused in [
        "null",
        r#""0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e""#,
        r#"["not-a-uuid"]"#,
        r#"["0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e",]"#,
        "[1, 2]",
        r#"["0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e"] trailing"#,
    ] {
        assert!(
            check(refused).is_err(),
            "{refused} must be refused when a policy is saved"
        );
    }
}

/// C6/D-556: the pack reference is the knowledge scope's shape — a JSON
/// array of ids in a text field — so the entity engine refuses a malformed
/// reference when a policy is saved. Whether each id names a pack the caller
/// can read is decided at session start, not here.
#[test]
fn capability_pack_refs_accept_only_a_json_array_of_ids() {
    let bundle = bundle();
    let field = attribute(&bundle, POLICY, "capability_pack_refs");
    assert_eq!(field["field_type"], "text");
    let options = &field["options"];
    let check = |value: &str| {
        attome_field::validate(
            &attome_core::FieldType::Text,
            &Value::String(value.to_owned()),
            Some(options),
        )
    };

    for accepted in [
        "[]",
        r#"["0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e"]"#,
        r#"[ "0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e", "0190F5C1-8B4F-7C3A-9D2E-1F0A2B3C4D5F" ]"#,
    ] {
        assert!(check(accepted).is_ok(), "{accepted} is a valid pack scope");
    }
    for refused in [
        "null",
        r#""0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e""#,
        r#"["not-a-uuid"]"#,
        r#"["0190f5c1-8b4f-7c3a-9d2e-1f0a2b3c4d5e",]"#,
        "[1, 2]",
    ] {
        assert!(
            check(refused).is_err(),
            "{refused} must be refused when a policy is saved"
        );
    }
}

/// C6/D-556: the shipped pack bundle agrees with the code that resolves it.
/// Parsed exactly as boot applies it — no database.
#[test]
fn the_capability_pack_bundle_matches_the_resolver() {
    let bundle: Value = serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-ai-capability-pack.json"
    ))
    .expect("attome-ai-capability-pack.json parses");

    let entity = bundle["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .find(|e| e["logicalname"] == attome_ai::capability_pack::CAPABILITY_PACK_ENTITY)
        .expect("the bundle declares the entity the resolver reads");
    assert_eq!(entity["primary_name_attribute"], "name");

    let field = attribute(
        &bundle,
        attome_ai::capability_pack::CAPABILITY_PACK_ENTITY,
        "action_ids",
    );
    assert_eq!(
        field["logicalname"],
        attome_ai::capability_pack::ACTION_IDS_FIELD
    );
    assert_eq!(field["field_type"], "text");
    assert_eq!(
        field["is_write_restricted"], true,
        "a pack grants capabilities, so it is write-restricted like the policy's own grant field"
    );

    // The shipped pattern accepts the ids the registry actually has, so a pack
    // can never be saved full of ids the resolver would then refuse.
    let options = &field["options"];
    let check = |value: &str| {
        attome_field::validate(
            &attome_core::FieldType::Text,
            &Value::String(value.to_owned()),
            Some(options),
        )
    };
    let every_action: Vec<String> = ActionRegistry::new()
        .all()
        .map(|descriptor| format!("{:?}", descriptor.id.as_str()))
        .collect();
    let all_ids = format!("[{}]", every_action.join(", "));
    assert!(
        check(&all_ids).is_ok(),
        "every registered action id must satisfy the pack field's pattern"
    );
    for refused in [
        "null",
        "record.get",
        "[1]",
        "[\"record.get\",]",
        "[] trailing",
    ] {
        assert!(check(refused).is_err(), "{refused} must be refused");
    }
}

#[test]
fn policy_ref_points_at_the_policy_and_is_not_required() {
    let bundle = bundle();
    let field = attribute(&bundle, "ai_agent", "policy_ref");
    assert_eq!(field["field_type"], "lookup");
    assert_eq!(field["lookup_entity"], POLICY);
    assert_ne!(
        field["is_required"], true,
        "existing agents have no policy; D-505 refuses their sessions at start instead"
    );
}
