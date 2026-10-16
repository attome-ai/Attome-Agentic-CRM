//! The environment variable kind (roadmap A30-T1): a named setting that
//! metadata refers to (a service URL, a tenant id, a switch, a secret) whose
//! value differs per environment.
//!
//! ```json
//! { "type": "url", "required": true, "default": "https://erp.test.local",
//!   "description_en": "The ERP's base address", "description_ar": "عنوان نظام ERP" }
//! ```
//!
//! The definition travels with the configuration (changesets, promotion);
//! the value never does: each deployment sets its own through
//! `/api/v1/admin/env-variables` (stored in `environment_variable_value`,
//! a secret encrypted and write-only). A `secret` definition has no default.

use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const ENVIRONMENT_VARIABLE: KindName = KindName("environment_variable");

/// The value types a variable may have.
pub const VALUE_TYPES: [&str; 5] = ["text", "number", "boolean", "url", "secret"];

/// Longest description.
const MAX_DESCRIPTION_CHARS: usize = 500;

/// The environment variable kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvironmentVariableKind;

/// Whether `value` is a valid value of `value_type` (a secret or text is any
/// string; a url starts with http:// or https://).
pub fn value_fits(value_type: &str, value: &Value) -> bool {
    match value_type {
        "text" | "secret" => value.is_string(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "url" => value
            .as_str()
            .is_some_and(|u| u.starts_with("https://") || u.starts_with("http://")),
        _ => false,
    }
}

impl Kind for EnvironmentVariableKind {
    fn name(&self) -> KindName {
        ENVIRONMENT_VARIABLE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["type"],
            "additionalProperties": false,
            "properties": {
                "type": { "enum": VALUE_TYPES },
                "required": { "type": "boolean" },
                "default": {},
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
                "an environment variable is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if ![
                "type",
                "required",
                "default",
                "description_en",
                "description_ar",
            ]
            .contains(&key.as_str())
            {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("an environment variable has no `{key}`"),
                ));
            }
        }
        let value_type = doc["type"].as_str().unwrap_or_default();
        if !VALUE_TYPES.contains(&value_type) {
            issues.push(Issue::new(
                "/type",
                "invalid",
                "type is text, number, boolean, url or secret",
            ));
        }
        if doc.get("required").is_some_and(|r| !r.is_boolean()) {
            issues.push(Issue::new(
                "/required",
                "invalid",
                "required is true or false",
            ));
        }
        if let Some(default) = doc.get("default") {
            if value_type == "secret" {
                issues.push(Issue::new(
                    "/default",
                    "secret_default",
                    "a secret has no default: its value is set on each deployment",
                ));
            } else if !default.is_null() && !value_fits(value_type, default) {
                issues.push(Issue::new(
                    "/default",
                    "invalid",
                    format!("the default is not a valid {value_type}"),
                ));
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
                let mut variable = input.doc.clone();
                if let Some(object) = variable.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text =
                    crate::canonical::canonicalize(&variable).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: ENVIRONMENT_VARIABLE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a setting whose value differs per environment (a service URL, an id, a switch or a secret); rules, flows and templates read it as env.<name>. The definition is configuration; each deployment sets its own value, and an agent never sees a secret's value."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_is_typed_and_a_secret_has_no_default() {
        let kind = EnvironmentVariableKind;
        assert!(
            kind.validate_shape(
                &json!({"type": "url", "required": true, "default": "https://x.test"})
            )
            .is_ok()
        );
        assert!(
            kind.validate_shape(&json!({"type": "url", "default": "ftp://x"}))
                .is_err()
        );
        assert!(kind.validate_shape(&json!({"type": "secret"})).is_ok());
        assert!(
            kind.validate_shape(&json!({"type": "secret", "default": "x"}))
                .is_err()
        );
        assert!(kind.validate_shape(&json!({"type": "colour"})).is_err());
        assert!(
            kind.validate_shape(&json!({"type": "text", "extra": 1}))
                .is_err()
        );
        assert!(value_fits("number", &json!(3.5)));
        assert!(!value_fits("boolean", &json!("yes")));
    }
}
