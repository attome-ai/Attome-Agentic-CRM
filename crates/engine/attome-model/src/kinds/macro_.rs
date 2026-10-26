//! The macro kind (roadmap G6-T2): a named bundle of actions run on one or
//! more records of an entity — set attributes, move the state, assign, add
//! a reply — previewed first, run in bulk, and undoable for a while.
//!
//! ```json
//! { "entity": "ticket",
//!   "description_en": "Close as duplicate",
//!   "description_ar": "إغلاق كمكرر",
//!   "steps": [
//!     { "action": "record.update",
//!       "args": { "entity": "{{entity}}", "record_id": "{{record_id}}",
//!                 "data": { "resolution_code": "duplicate" } } },
//!     { "action": "record.transition",
//!       "args": { "entity": "{{entity}}", "record_id": "{{record_id}}", "to_state": "closed" } }
//!   ],
//!   "undo_minutes": 10 }
//! ```
//!
//! Each step names an action of the AI action registry (a built-in one or a
//! published custom action) and its arguments; `{{entity}}` and
//! `{{record_id}}` in any string are replaced for each record.
//! `attome_ai::macros` loads the published macros and runs them.

use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const MACRO: KindName = KindName("macro");
/// Most steps one macro runs.
pub const MAX_STEPS: usize = 20;
/// The longest undo window, in minutes (the deferred-action limit is a day).
pub const MAX_UNDO_MINUTES: u64 = 1440;
/// Longest description.
pub const MAX_DESCRIPTION_CHARS: usize = 1000;

const KEYS: [&str; 5] = [
    "entity",
    "description_en",
    "description_ar",
    "steps",
    "undo_minutes",
];

/// The macro kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacroKind;

impl Kind for MacroKind {
    fn name(&self) -> KindName {
        MACRO
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "description_en", "steps"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "minLength": 1 },
                "description_en": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "description_ar": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "steps": {
                    "type": "array", "minItems": 1, "maxItems": MAX_STEPS,
                    "items": {
                        "type": "object",
                        "required": ["action"],
                        "additionalProperties": false,
                        "properties": {
                            "action": { "type": "string", "minLength": 1 },
                            "args": { "type": "object" }
                        }
                    }
                },
                "undo_minutes": { "type": "integer", "minimum": 0, "maximum": MAX_UNDO_MINUTES }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a macro is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !KEYS.contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a macro has no `{key}`"),
                ));
            }
        }
        if doc["entity"].as_str().is_none_or(|e| e.trim().is_empty()) {
            issues.push(Issue::new(
                "/entity",
                "required",
                "entity names the records the macro runs on",
            ));
        }
        for key in ["description_en", "description_ar"] {
            let value = doc.get(key);
            let bad = match value {
                None => key == "description_en",
                Some(d) => d.as_str().is_none_or(|d| {
                    d.trim().is_empty() || d.chars().count() > MAX_DESCRIPTION_CHARS
                }),
            };
            if bad {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a description is text of 1 to 1,000 characters",
                ));
            }
        }
        match doc.get("steps").and_then(Value::as_array) {
            Some(steps) if !steps.is_empty() && steps.len() <= MAX_STEPS => {
                for (i, step) in steps.iter().enumerate() {
                    let action_ok = step
                        .get("action")
                        .and_then(Value::as_str)
                        .is_some_and(|a| !a.trim().is_empty());
                    let args_ok = step.get("args").is_none_or(Value::is_object);
                    let keys_ok = step
                        .as_object()
                        .is_some_and(|o| o.keys().all(|k| k == "action" || k == "args"));
                    if !action_ok || !args_ok || !keys_ok {
                        issues.push(Issue::new(
                            format!("/steps/{i}"),
                            "invalid",
                            "a step is {\"action\": an action id, \"args\": an object}",
                        ));
                    }
                }
            }
            _ => issues.push(Issue::new(
                "/steps",
                "invalid",
                "steps lists 1 to 20 actions",
            )),
        }
        if doc
            .get("undo_minutes")
            .is_some_and(|u| u.as_u64().is_none_or(|u| u > MAX_UNDO_MINUTES))
        {
            issues.push(Issue::new(
                "/undo_minutes",
                "invalid",
                "undo_minutes is a whole number from 0 to 1,440",
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
                let mut doc = input.doc.clone();
                if let Some(object) = doc.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text = crate::canonical::canonicalize(&doc).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: MACRO,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a macro: a named list of actions (set attributes, move the state, assign, add a reply) run on records of one entity, with {{entity}} and {{record_id}} filled in per record. People preview it, run it on many records at once, and can undo it within its undo window."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_definition_is_checked() {
        let kind = MacroKind;
        let good = json!({
            "entity": "ticket",
            "description_en": "Close as duplicate",
            "steps": [{ "action": "record.update", "args": { "record_id": "{{record_id}}" } }],
            "undo_minutes": 10
        });
        assert!(kind.validate_shape(&good).is_ok());
        let mut bad = good.clone();
        bad["steps"] = json!([]);
        assert!(kind.validate_shape(&bad).is_err());
        let mut bad = good.clone();
        bad["undo_minutes"] = json!(5000);
        assert!(kind.validate_shape(&bad).is_err());
        let mut bad = good;
        bad["steps"][0]["run"] = json!("x");
        assert!(kind.validate_shape(&bad).is_err());
    }
}
