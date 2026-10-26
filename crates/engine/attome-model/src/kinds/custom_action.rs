//! The custom action kind (roadmap AE1-T1): an action a builder defines and
//! publishes, offered to people and agents beside the built-in ones.
//!
//! ```json
//! { "description_en": "Book a site survey for a lead",
//!   "description_ar": "حجز معاينة موقع لعميل محتمل",
//!   "input_schema": { "type": "object", "properties": { "lead_id": { "type": "string" } },
//!                     "required": ["lead_id"], "additionalProperties": false },
//!   "output_schema": { "type": "object" },
//!   "risk_tier": "consequential",
//!   "retry_class": "requires_key",
//!   "implementation": { "kind": "flow", "ref": "site_survey_booking" },
//!   "required_privileges": ["lead.update"],
//!   "bulk_allowed": false }
//! ```
//!
//! The action's id is `custom.<object name>`, so a custom action can never
//! take a built-in id. `attome_ai::custom_action` loads the published ones
//! into the action registry as a second source, with the same descriptor
//! type, so the gate, risk tiers, approvals and audit treat them exactly as
//! built-in actions.

use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const CUSTOM_ACTION: KindName = KindName("custom_action");
/// The prefix every custom action id carries.
pub const ID_PREFIX: &str = "custom.";
/// The risk tiers a definition may name.
pub const RISK_TIERS: [&str; 3] = ["read", "reversible", "consequential"];
/// The retry classes a definition may name.
pub const RETRY_CLASSES: [&str; 3] = ["idempotent", "requires_key", "never_retry"];
/// What an action can run.
pub const IMPLEMENTATIONS: [&str; 2] = ["flow", "extension"];
/// Longest description.
pub const MAX_DESCRIPTION_CHARS: usize = 1000;
/// Most privileges one action requires.
pub const MAX_PRIVILEGES: usize = 10;
/// Longest schema, as JSON text.
pub const MAX_SCHEMA_BYTES: usize = 16 * 1024;

const KEYS: [&str; 9] = [
    "description_en",
    "description_ar",
    "input_schema",
    "output_schema",
    "risk_tier",
    "retry_class",
    "implementation",
    "required_privileges",
    "bulk_allowed",
];

/// The custom action kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct CustomActionKind;

/// The action id of the object named `name`.
pub fn action_id(name: &str) -> String {
    format!("{ID_PREFIX}{name}")
}

fn schema_ok(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("object")
        && value.to_string().len() <= MAX_SCHEMA_BYTES
}

impl Kind for CustomActionKind {
    fn name(&self) -> KindName {
        CUSTOM_ACTION
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["description_en", "input_schema", "risk_tier", "implementation"],
            "additionalProperties": false,
            "properties": {
                "description_en": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "description_ar": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "input_schema": { "type": "object" },
                "output_schema": { "type": "object" },
                "risk_tier": { "enum": RISK_TIERS },
                "retry_class": { "enum": RETRY_CLASSES },
                "implementation": {
                    "type": "object",
                    "required": ["kind", "ref"],
                    "additionalProperties": false,
                    "properties": {
                        "kind": { "enum": IMPLEMENTATIONS },
                        "ref": { "type": "string", "minLength": 1, "maxLength": 200 }
                    }
                },
                "required_privileges": {
                    "type": "array", "maxItems": MAX_PRIVILEGES,
                    "items": { "type": "string", "minLength": 1, "maxLength": 200 }
                },
                "bulk_allowed": { "type": "boolean" }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a custom action is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !KEYS.contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a custom action has no `{key}`"),
                ));
            }
        }
        for key in ["description_en", "description_ar"] {
            let required = key == "description_en";
            match doc.get(key) {
                None if required => issues.push(Issue::new(
                    format!("/{key}"),
                    "required",
                    "description_en tells a person and a model what the action does",
                )),
                None => {}
                Some(d) => {
                    if d.as_str().is_none_or(|d| {
                        d.trim().is_empty() || d.chars().count() > MAX_DESCRIPTION_CHARS
                    }) {
                        issues.push(Issue::new(
                            format!("/{key}"),
                            "invalid",
                            "a description is text of 1 to 1,000 characters",
                        ));
                    }
                }
            }
        }
        match doc.get("input_schema") {
            Some(schema) if schema_ok(schema) => {}
            _ => issues.push(Issue::new(
                "/input_schema",
                "invalid",
                "input_schema is a JSON Schema of type object, at most 16 KB",
            )),
        }
        if doc.get("output_schema").is_some_and(|s| !schema_ok(s)) {
            issues.push(Issue::new(
                "/output_schema",
                "invalid",
                "output_schema is a JSON Schema of type object, at most 16 KB",
            ));
        }
        if !doc
            .get("risk_tier")
            .and_then(Value::as_str)
            .is_some_and(|r| RISK_TIERS.contains(&r))
        {
            issues.push(Issue::new(
                "/risk_tier",
                "invalid",
                "risk_tier is read, reversible or consequential",
            ));
        }
        if doc
            .get("retry_class")
            .is_some_and(|r| r.as_str().is_none_or(|r| !RETRY_CLASSES.contains(&r)))
        {
            issues.push(Issue::new(
                "/retry_class",
                "invalid",
                "retry_class is idempotent, requires_key or never_retry",
            ));
        }
        let implementation = doc.get("implementation");
        let kind_ok = implementation
            .and_then(|i| i.get("kind"))
            .and_then(Value::as_str)
            .is_some_and(|k| IMPLEMENTATIONS.contains(&k));
        let ref_ok = implementation
            .and_then(|i| i.get("ref"))
            .and_then(Value::as_str)
            .is_some_and(|r| !r.trim().is_empty() && r.len() <= 200);
        if !kind_ok || !ref_ok {
            issues.push(Issue::new(
                "/implementation",
                "invalid",
                "implementation is {\"kind\": \"flow\" or \"extension\", \"ref\": its name}",
            ));
        }
        if let Some(privileges) = doc.get("required_privileges") {
            let ok = privileges.as_array().is_some_and(|list| {
                list.len() <= MAX_PRIVILEGES
                    && list.iter().all(|p| {
                        p.as_str()
                            .is_some_and(|p| !p.trim().is_empty() && p.len() <= 200)
                    })
            });
            if !ok {
                issues.push(Issue::new(
                    "/required_privileges",
                    "invalid",
                    "required_privileges is a list of at most 10 privilege keys",
                ));
            }
        }
        if doc.get("bulk_allowed").is_some_and(|b| !b.is_boolean()) {
            issues.push(Issue::new(
                "/bulk_allowed",
                "invalid",
                "bulk_allowed is true or false",
            ));
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
                let mut action = input.doc.clone();
                if let Some(object) = action.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                    object.insert("action_id".into(), json!(action_id(&input.name)));
                }
                let text = crate::canonical::canonicalize(&action).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: CUSTOM_ACTION,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a custom action people and agents can run, backed by a published flow: its description in English and Arabic, input schema, risk tier (read, reversible or consequential), retry class and required privileges. Published, it appears as the tool custom.<name> beside the built-in actions, under the same gate and approvals."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn survey() -> Value {
        json!({
            "description_en": "Book a site survey for a lead",
            "input_schema": { "type": "object", "properties": { "lead_id": { "type": "string" } } },
            "risk_tier": "consequential",
            "implementation": { "kind": "flow", "ref": "site_survey_booking" },
            "required_privileges": ["lead.update"]
        })
    }

    #[test]
    fn custom_action_definition_is_checked() {
        let kind = CustomActionKind;
        assert!(kind.validate_shape(&survey()).is_ok());
        let mut bad = survey();
        bad["risk_tier"] = json!("dangerous");
        assert!(kind.validate_shape(&bad).is_err());
        let mut bad = survey();
        bad["implementation"] = json!({ "kind": "script", "ref": "x" });
        assert!(kind.validate_shape(&bad).is_err());
        let mut bad = survey();
        bad["input_schema"] = json!({ "type": "string" });
        assert!(kind.validate_shape(&bad).is_err());
        assert_eq!(action_id("site_survey"), "custom.site_survey");
    }
}
