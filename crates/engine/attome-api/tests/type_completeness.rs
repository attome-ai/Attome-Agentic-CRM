//! A2-T6: every field type has every capability the platform needs of it:
//! a column and a cast, a stored code that reads back, write validation (or,
//! for a computed type, a refusal to be written), a rules type or a stated
//! reason for none, an import/export name in the bundle vocabulary, an OData
//! type for export, and a GraphQL type for the API and agent schemas. A new
//! variant that misses one fails here naming the type and the capability.
//! The browser controls are checked by the web app's own specs.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::{ALL_FIELD_TYPES, FieldType};
use serde_json::{Value, json};

/// A value of the type a write accepts; `None` for a computed type.
fn sample(ft: &FieldType) -> Option<Value> {
    Some(match ft {
        FieldType::Text => json!("text"),
        FieldType::Number => json!(1.5),
        FieldType::Currency => json!(12.5),
        FieldType::Date => json!("2026-11-03"),
        FieldType::DateTime => json!("2026-11-03T10:00:00Z"),
        FieldType::Time => json!("10:30"),
        FieldType::Bool => json!(true),
        FieldType::Choice => json!("open"),
        FieldType::Lookup => json!("0190a0c2-0000-7000-8000-000000000001"),
        FieldType::File => json!("files/contract.pdf"),
        FieldType::Image => json!("images/logo.png"),
        FieldType::Icon => json!("las la-file"),
        FieldType::Color => json!("#22c55e"),
        FieldType::RichText => json!("<p>text</p>"),
        FieldType::Geolocation => json!({ "lat": 24.71, "lng": 46.67 }),
        FieldType::Json => json!({ "a": 1 }),
        FieldType::Formula | FieldType::Rollup => return None,
    })
}

/// Types with no rules type, and why: rules never read file content, and a
/// time of day, a point and a JSON document have no expression type yet.
const NO_RULES_TYPE: [FieldType; 5] = [
    FieldType::File,
    FieldType::Image,
    FieldType::Time,
    FieldType::Geolocation,
    FieldType::Json,
];

#[test]
fn every_field_type_has_every_capability() {
    let mut missing: Vec<String> = Vec::new();
    for ft in ALL_FIELD_TYPES {
        let name = ft.as_str();
        let mut lack = |capability: &str| missing.push(format!("{name}: {capability}"));

        if ft.pg_type(false).trim().is_empty() {
            lack("column type");
        }
        if ft.sql_cast(false).trim().is_empty() {
            lack("cast");
        }
        if FieldType::from_int(ft.to_int()) != Some(ft.clone()) {
            lack("stored code that reads back");
        }
        if !FieldType::NAMES.contains(&name)
            || !attome_api::bundle::KNOWN_FIELD_TYPES.contains(&name)
        {
            lack("import/export name");
        }
        match sample(&ft) {
            Some(value) => {
                if let Err(e) = attome_field::validate(&ft, &value, None) {
                    lack(&format!("write validation (refused {value}: {e})"));
                }
            }
            None => {
                if attome_field::validate(&ft, &json!("x"), None).is_ok() {
                    lack("refusing a write to a computed value");
                }
            }
        }
        let rules = attome_core::formula::rules_type(&ft);
        if rules.is_none() && !NO_RULES_TYPE.contains(&ft) {
            lack("rules type");
        }
        if rules.is_some() && NO_RULES_TYPE.contains(&ft) {
            lack("a stale entry in NO_RULES_TYPE (it has a rules type now)");
        }
        if attome_records::odata::csdl::edm_type(ft.clone()).is_empty() {
            lack("OData export type");
        }
        if attome_api::graphql::scalar_of(&ft).is_empty() {
            lack("API and agent schema type");
        }
    }
    assert!(
        missing.is_empty(),
        "field types missing a capability:\n{}",
        missing.join("\n")
    );
    assert_eq!(
        ALL_FIELD_TYPES.len(),
        FieldType::NAMES.len(),
        "every variant is named"
    );
}
