//! A1-T13: `model.draft`'s evaluation cases, checked without a model.
//!
//! - Three descriptions, in Arabic and English, each with the entities a good
//!   draft holds; every expected name and alias follows the naming rules the
//!   review applies, so a draft naming them passes it.
//! - `model.draft` and `model.review` are registered read tools: drafting and
//!   reviewing change nothing.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::builder::review::name_ok;
use attome_ai::descriptor::{Effect, RiskTier};
use attome_ai::registry::ActionRegistry;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/builder/draft_model.json"))
        .expect("the fixture parses")
}

#[test]
fn draft_model_cases_are_well_formed() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 3);
    let languages: Vec<&str> = cases
        .iter()
        .map(|c| c["language"].as_str().unwrap())
        .collect();
    assert!(languages.contains(&"ar") && languages.contains(&"en"));
    for case in cases {
        let id = case["id"].as_str().unwrap();
        assert!(
            !case["description"].as_str().unwrap().trim().is_empty(),
            "{id}"
        );
        let expected = case["expected_entities"].as_array().unwrap();
        assert!(expected.len() >= 3, "{id}: at least three entities");
        for entity in expected {
            let name = entity["name"].as_str().unwrap();
            assert!(name_ok(name), "{id}: {name} breaks the naming rules");
            for alias in entity["aliases"].as_array().unwrap() {
                let alias = alias.as_str().unwrap();
                assert!(
                    name_ok(alias),
                    "{id}: alias {alias} breaks the naming rules"
                );
            }
        }
    }
}

#[test]
fn drafting_and_reviewing_are_read_tools() {
    let registry = ActionRegistry::new();
    for id in [
        "model.draft",
        "model.review",
        "model.score",
        "model.from_files",
    ] {
        let descriptor = registry
            .resolve(id)
            .unwrap_or_else(|| panic!("{id} is registered"));
        assert_eq!(descriptor.risk, RiskTier::Read, "{id}");
        assert_eq!(descriptor.effect, Effect::Read, "{id}");
    }
}
