//! The record type kind (roadmap A27-T1): a kind of record within one entity
//! (a "service" case and a "complaint" case), each with its own labels, form,
//! stage process and default values.
//!
//! ```json
//! { "entity": "<entity id>", "code": "complaint",
//!   "label_en": "Complaint", "label_ar": "شكوى",
//!   "form": "<form id>", "state_model": "<state model id>",
//!   "defaults": { "priority": "high" }, "is_default": false }
//! ```
//!
//! Publishing the first type of an entity gives its table a `record_type`
//! text column (`attome_metadata::provision::record_type`). A record whose
//! `record_type` is empty is of the entity's default type, so existing rows
//! need no rewrite.

use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::form::{ENTITY, FORM};

/// The kind's name.
pub const RECORD_TYPE: KindName = KindName("record_type");

/// The state model adapter kind a type's stage process refers to.
pub const STATE_MODEL: KindName = KindName("state_model");

/// The record attribute that holds a record's type code.
pub const RECORD_TYPE_ATTRIBUTE: &str = "record_type";

const PROPERTIES: [&str; 8] = [
    "entity",
    "code",
    "label_en",
    "label_ar",
    "form",
    "state_model",
    "defaults",
    "is_default",
];

/// Longest label.
const MAX_LABEL_CHARS: usize = 100;

/// The record type kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordTypeKind;

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

/// Whether `code` is a type code: lower-case letters, digits and `_`,
/// starting with a letter, at most 63 characters.
pub fn valid_code(code: &str) -> bool {
    let mut chars = code.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && code.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl Kind for RecordTypeKind {
    fn name(&self) -> KindName {
        RECORD_TYPE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "code", "label_en"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "code": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,62}$" },
                "label_en": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                "label_ar": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                "form": { "type": "string", "format": "uuid" },
                "state_model": { "type": "string", "format": "uuid" },
                "defaults": { "type": "object" },
                "is_default": { "type": "boolean" }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a record type is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !PROPERTIES.contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a record type has no `{key}`"),
                ));
            }
        }
        if uuid_at(&doc["entity"]).is_none() {
            issues.push(Issue::new(
                "/entity",
                "invalid",
                "entity is the id of the entity the type belongs to",
            ));
        }
        if !doc["code"].as_str().is_some_and(valid_code) {
            issues.push(Issue::new(
                "/code",
                "invalid",
                "code is lower-case letters, digits and _, starting with a letter",
            ));
        }
        for (key, required) in [("label_en", true), ("label_ar", false)] {
            match doc.get(key) {
                None if required => issues.push(Issue::new(
                    format!("/{key}"),
                    "required",
                    "a record type has an English label",
                )),
                Some(label)
                    if label.as_str().is_none_or(|l| {
                        l.trim().is_empty() || l.chars().count() > MAX_LABEL_CHARS
                    }) =>
                {
                    issues.push(Issue::new(
                        format!("/{key}"),
                        "invalid",
                        "a label is text of 1 to 100 characters",
                    ));
                }
                _ => {}
            }
        }
        for key in ["form", "state_model"] {
            if doc.get(key).is_some_and(|v| uuid_at(v).is_none()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    format!("{key} is an object id"),
                ));
            }
        }
        if doc.get("defaults").is_some_and(|d| !d.is_object()) {
            issues.push(Issue::new(
                "/defaults",
                "invalid",
                "defaults maps attribute names to values",
            ));
        }
        if let Some(defaults) = doc["defaults"].as_object()
            && defaults.contains_key(RECORD_TYPE_ATTRIBUTE)
        {
            issues.push(Issue::new(
                "/defaults/record_type",
                "invalid",
                "a type's defaults cannot set the type itself",
            ));
        }
        if doc.get("is_default").is_some_and(|d| !d.is_boolean()) {
            issues.push(Issue::new(
                "/is_default",
                "invalid",
                "is_default is true or false",
            ));
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        let mut refs = Vec::new();
        for (key, kind) in [
            ("entity", ENTITY),
            ("form", FORM),
            ("state_model", STATE_MODEL),
        ] {
            if let Some(id) = uuid_at(&doc[key]) {
                refs.push(Reference {
                    target: ObjectRef {
                        kind,
                        id: ObjectId(id),
                    },
                    mode: RefMode::Reads,
                });
            }
        }
        refs
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut record_type = input.doc.clone();
                if let Some(object) = record_type.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                    object
                        .entry("is_default")
                        .or_insert_with(|| Value::Bool(false));
                }
                let text =
                    crate::canonical::canonicalize(&record_type).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: RECORD_TYPE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a kind of record within one entity (for example a complaint case and a service case), with its own labels, form, stage process and default values. A record's type is held in its record_type attribute; an empty one means the entity's default type."
    }
}

/// The entity a record type document belongs to.
pub fn entity_of(doc: &Value) -> Option<Uuid> {
    uuid_at(&doc["entity"])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity() -> String {
        Uuid::now_v7().to_string()
    }

    #[test]
    fn record_type_shape_is_checked() {
        let kind = RecordTypeKind;
        let ok = json!({
            "entity": entity(), "code": "complaint", "label_en": "Complaint",
            "label_ar": "شكوى", "defaults": { "priority": "high" }, "is_default": true
        });
        assert!(kind.validate_shape(&ok).is_ok());
        assert!(
            kind.validate_shape(
                &json!({ "entity": entity(), "code": "Complaint", "label_en": "x" })
            )
            .is_err()
        );
        assert!(
            kind.validate_shape(&json!({ "code": "complaint", "label_en": "x" }))
                .is_err()
        );
        assert!(
            kind.validate_shape(&json!({ "entity": entity(), "code": "complaint" }))
                .is_err()
        );
        assert!(
            kind.validate_shape(&json!({
                "entity": entity(), "code": "complaint", "label_en": "x",
                "defaults": { "record_type": "other" }
            }))
            .is_err()
        );
        assert!(
            kind.validate_shape(&json!({
                "entity": entity(), "code": "complaint", "label_en": "x", "colour": "red"
            }))
            .is_err()
        );
        assert!(valid_code("service_2"));
        assert!(!valid_code("2service"));
        assert!(!valid_code(""));
    }

    #[test]
    fn record_type_refers_to_its_entity_form_and_stages() {
        let (e, f, s) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let refs = RecordTypeKind.references(&json!({
            "entity": e.to_string(), "code": "x", "label_en": "X",
            "form": f.to_string(), "state_model": s.to_string()
        }));
        let targets: Vec<(KindName, Uuid)> = refs
            .iter()
            .map(|r| (r.target.kind, r.target.id.0))
            .collect();
        assert_eq!(targets, vec![(ENTITY, e), (FORM, f), (STATE_MODEL, s)]);
        assert_eq!(entity_of(&json!({ "entity": e.to_string() })), Some(e));
    }
}
