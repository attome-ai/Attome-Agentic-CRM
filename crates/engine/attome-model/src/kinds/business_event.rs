//! The business event kind (roadmap Y7-T5): a named event a builder defines,
//! with typed attributes, that flows and code raise about one record.
//!
//! ```json
//! { "entity": "order",
//!   "attributes": { "carrier": { "type": "text", "required": true },
//!                   "weight_kg": { "type": "number" } },
//!   "description_en": "The order left the warehouse",
//!   "description_ar": "غادر الطلب المستودع" }
//! ```
//!
//! Raising one (`attome_api::business_event::raise_event`, or the
//! `events.raise` flow step) checks the payload against the published
//! definition with [`check_payload`] and writes it to the change feed in the
//! caller's transaction, named by the object's name, so it commits with the
//! write that caused it.

use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const BUSINESS_EVENT: KindName = KindName("business_event");

/// The attribute types an event may carry.
pub const ATTRIBUTE_TYPES: [&str; 5] = ["text", "number", "boolean", "date_time", "uuid"];

/// Most attributes one event declares.
pub const MAX_ATTRIBUTES: usize = 50;

/// Longest description.
const MAX_DESCRIPTION_CHARS: usize = 500;

/// Longest text value in a raised payload.
pub const MAX_TEXT_CHARS: usize = 4000;

/// The business event kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct BusinessEventKind;

fn attribute_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `value` is a valid value of attribute type `kind`.
pub fn value_fits(kind: &str, value: &Value) -> bool {
    match kind {
        "text" => value
            .as_str()
            .is_some_and(|s| s.chars().count() <= MAX_TEXT_CHARS),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "date_time" => value
            .as_str()
            .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
        "uuid" => value
            .as_str()
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok()),
        _ => false,
    }
}

/// Checks a raised payload against its published definition: an object,
/// only declared attributes, each of its type, every required one present.
/// A `null` counts as absent. Answers every problem at once.
pub fn check_payload(definition: &Value, payload: &Value) -> Result<(), Vec<String>> {
    let Some(payload) = payload.as_object() else {
        return Err(vec!["the payload is a JSON object".into()]);
    };
    let empty = Map::new();
    let declared = definition
        .get("attributes")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut problems = Vec::new();
    for (name, value) in payload {
        match declared.get(name) {
            None => problems.push(format!("`{name}` is not an attribute of this event")),
            Some(attr) => {
                let kind = attr["type"].as_str().unwrap_or_default();
                if !value.is_null() && !value_fits(kind, value) {
                    problems.push(format!("`{name}` is not a valid {kind}"));
                }
            }
        }
    }
    for (name, attr) in declared {
        let required = attr.get("required").and_then(Value::as_bool) == Some(true);
        if required && payload.get(name).is_none_or(Value::is_null) {
            problems.push(format!("`{name}` is required"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

impl Kind for BusinessEventKind {
    fn name(&self) -> KindName {
        BUSINESS_EVENT
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "attributes"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string" },
                "attributes": {
                    "type": "object",
                    "maxProperties": MAX_ATTRIBUTES,
                    "additionalProperties": {
                        "type": "object",
                        "required": ["type"],
                        "additionalProperties": false,
                        "properties": {
                            "type": { "enum": ATTRIBUTE_TYPES },
                            "required": { "type": "boolean" }
                        }
                    }
                },
                "description_en": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "description_ar": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a business event is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !["entity", "attributes", "description_en", "description_ar"].contains(&key.as_str())
            {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a business event has no `{key}`"),
                ));
            }
        }
        if doc["entity"].as_str().is_none_or(|e| e.trim().is_empty()) {
            issues.push(Issue::new(
                "/entity",
                "required",
                "entity names the entity whose records the event is about",
            ));
        }
        match doc.get("attributes").and_then(Value::as_object) {
            None => issues.push(Issue::new(
                "/attributes",
                "required",
                "attributes is an object of name to {type, required}",
            )),
            Some(attributes) => {
                if attributes.len() > MAX_ATTRIBUTES {
                    issues.push(Issue::new(
                        "/attributes",
                        "too_many",
                        format!("an event has at most {MAX_ATTRIBUTES} attributes"),
                    ));
                }
                for (name, attr) in attributes {
                    let path = format!("/attributes/{name}");
                    if !attribute_name_ok(name) {
                        issues.push(Issue::new(
                            path.clone(),
                            "invalid_name",
                            "an attribute name is lower case letters, digits and _",
                        ));
                    }
                    let Some(attr) = attr.as_object() else {
                        issues.push(Issue::new(path, "invalid", "an attribute is an object"));
                        continue;
                    };
                    for key in attr.keys() {
                        if key != "type" && key != "required" {
                            issues.push(Issue::new(
                                format!("{path}/{key}"),
                                "unknown_property",
                                format!("an event attribute has no `{key}`"),
                            ));
                        }
                    }
                    if !attr
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|t| ATTRIBUTE_TYPES.contains(&t))
                    {
                        issues.push(Issue::new(
                            format!("{path}/type"),
                            "invalid",
                            "type is text, number, boolean, date_time or uuid",
                        ));
                    }
                    if attr.get("required").is_some_and(|r| !r.is_boolean()) {
                        issues.push(Issue::new(
                            format!("{path}/required"),
                            "invalid",
                            "required is true or false",
                        ));
                    }
                }
            }
        }
        for key in ["description_en", "description_ar"] {
            if doc.get(key).is_some_and(|d| {
                d.as_str()
                    .is_none_or(|d| d.chars().count() > MAX_DESCRIPTION_CHARS)
            }) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a description is text of at most 500 characters",
                ));
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut event = input.doc.clone();
                if let Some(object) = event.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text = crate::canonical::canonicalize(&event).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: BUSINESS_EVENT,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a named business event about one entity's records, with typed attributes (text, number, boolean, date_time, uuid). Flows raise it with the events.raise step and code with raise_event; it lands in the change feed with the write that caused it, for flows and integrations to listen to."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped() -> Value {
        json!({
            "entity": "order",
            "attributes": {
                "carrier": { "type": "text", "required": true },
                "weight_kg": { "type": "number" },
                "shipped_at": { "type": "date_time" }
            }
        })
    }

    #[test]
    fn a_definition_needs_an_entity_and_typed_attributes() {
        let kind = BusinessEventKind;
        assert!(kind.validate_shape(&shipped()).is_ok());
        assert!(kind.validate_shape(&json!({"attributes": {}})).is_err());
        assert!(
            kind.validate_shape(
                &json!({"entity": "order", "attributes": {"x": {"type": "colour"}}})
            )
            .is_err()
        );
        assert!(
            kind.validate_shape(
                &json!({"entity": "order", "attributes": {"Bad Name": {"type": "text"}}})
            )
            .is_err()
        );
        assert!(
            kind.validate_shape(&json!({"entity": "order", "attributes": {}, "extra": 1}))
                .is_err()
        );
    }

    #[test]
    fn a_payload_is_checked_against_its_definition() {
        let def = shipped();
        assert!(
            check_payload(
                &def,
                &json!({"carrier": "Aramex", "weight_kg": 2.5, "shipped_at": "2026-10-25T09:00:00Z"})
            )
            .is_ok()
        );
        let problems = check_payload(
            &def,
            &json!({"weight_kg": "heavy", "colour": "red", "shipped_at": "yesterday"}),
        )
        .unwrap_err();
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("`carrier` is required")));
        assert!(check_payload(&def, &json!([1])).is_err());
        assert!(check_payload(&def, &json!({"carrier": null})).is_err());
    }
}
