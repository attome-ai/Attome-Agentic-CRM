//! The stage process kind (roadmap M7-T1): the ordered stages a record of
//! one entity moves through, each with the attributes it needs filled,
//! a checklist, and the stages it may move to next.
//!
//! ```json
//! { "entity": "<entity id>",
//!   "stages": [
//!     { "code": "qualify", "label_en": "Qualify", "label_ar": "تأهيل",
//!       "required": ["budget"], "checklist": ["Call the buyer"],
//!       "next": ["propose", "lost"] },
//!     { "code": "propose", "label_en": "Propose", "required": ["amount"],
//!       "next": ["won", "lost"] },
//!     { "code": "won", "label_en": "Won" },
//!     { "code": "lost", "label_en": "Lost" }
//!   ] }
//! ```
//!
//! The first stage is where a new record starts. A stage with no `next`
//! ends the process. Publishing the first process of an entity gives its
//! table a `stage` text attribute and a `stage_entered_at` date that stamps
//! every change of it (`attome_metadata::provision::stage_process`); the
//! record write path refuses a move to a stage not in the current stage's
//! `next`, or into a stage whose `required` attributes are empty, and
//! records every move.

use std::collections::HashSet;

use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::form::ENTITY;
use crate::kinds::record_type::valid_code;

/// The kind's name.
pub const STAGE_PROCESS: KindName = KindName("stage_process");

/// The record attribute that holds a record's current stage code.
pub const STAGE_ATTRIBUTE: &str = "stage";

/// The record attribute that holds when the record entered its stage.
pub const STAGE_ENTERED_ATTRIBUTE: &str = "stage_entered_at";

/// Most stages in one process.
const MAX_STAGES: usize = 50;

/// Most checklist items and required attributes per stage.
const MAX_ITEMS: usize = 50;

/// Longest label or checklist item.
const MAX_TEXT_CHARS: usize = 200;

const STAGE_PROPERTIES: [&str; 6] = [
    "code",
    "label_en",
    "label_ar",
    "required",
    "checklist",
    "next",
];

/// The stage process kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct StageProcessKind;

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

fn strings(value: &Value) -> Option<Vec<&str>> {
    value.as_array()?.iter().map(Value::as_str).collect()
}

fn text_ok(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|t| !t.trim().is_empty() && t.chars().count() <= MAX_TEXT_CHARS)
}

impl Kind for StageProcessKind {
    fn name(&self) -> KindName {
        STAGE_PROCESS
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "stages"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "stages": {
                    "type": "array", "minItems": 1, "maxItems": MAX_STAGES,
                    "items": {
                        "type": "object",
                        "required": ["code", "label_en"],
                        "additionalProperties": false,
                        "properties": {
                            "code": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,62}$" },
                            "label_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                            "label_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                            "required": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_ITEMS },
                            "checklist": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_ITEMS },
                            "next": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_STAGES }
                        }
                    }
                }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a stage process is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !matches!(key.as_str(), "entity" | "stages") {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a stage process has no `{key}`"),
                ));
            }
        }
        if uuid_at(&doc["entity"]).is_none() {
            issues.push(Issue::new(
                "/entity",
                "invalid",
                "entity is the id of the entity whose records move through the stages",
            ));
        }
        let stages = doc["stages"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        if stages.is_empty() || stages.len() > MAX_STAGES {
            issues.push(Issue::new(
                "/stages",
                "invalid",
                "a stage process has 1 to 50 stages",
            ));
        }
        let codes: Vec<&str> = stages.iter().filter_map(|s| s["code"].as_str()).collect();
        let mut seen = HashSet::new();
        for (i, stage) in stages.iter().enumerate() {
            let at = |key: &str| format!("/stages/{i}/{key}");
            let Some(fields) = stage.as_object() else {
                issues.push(Issue::new(
                    format!("/stages/{i}"),
                    "invalid",
                    "a stage is an object",
                ));
                continue;
            };
            for key in fields.keys() {
                if !STAGE_PROPERTIES.contains(&key.as_str()) {
                    issues.push(Issue::new(
                        at(key),
                        "unknown_property",
                        format!("a stage has no `{key}`"),
                    ));
                }
            }
            match stage["code"].as_str() {
                Some(code) if valid_code(code) => {
                    if !seen.insert(code) {
                        issues.push(Issue::new(
                            at("code"),
                            "duplicate",
                            format!("stage `{code}` appears twice"),
                        ));
                    }
                }
                _ => issues.push(Issue::new(
                    at("code"),
                    "invalid",
                    "a stage code is lower-case letters, digits and _, starting with a letter",
                )),
            }
            if !text_ok(&stage["label_en"]) {
                issues.push(Issue::new(
                    at("label_en"),
                    "required",
                    "a stage has an English label of 1 to 200 characters",
                ));
            }
            if stage.get("label_ar").is_some_and(|l| !text_ok(l)) {
                issues.push(Issue::new(
                    at("label_ar"),
                    "invalid",
                    "a label is text of 1 to 200 characters",
                ));
            }
            for key in ["required", "checklist"] {
                if let Some(list) = stage.get(key) {
                    let ok = list
                        .as_array()
                        .is_some_and(|items| items.len() <= MAX_ITEMS && items.iter().all(text_ok));
                    if !ok {
                        issues.push(Issue::new(
                            at(key),
                            "invalid",
                            format!("{key} is a list of at most 50 short texts"),
                        ));
                    }
                }
            }
            if let Some(next) = stage.get("next") {
                match strings(next) {
                    Some(next) => {
                        for target in next {
                            if !codes.contains(&target) {
                                issues.push(Issue::new(
                                    at("next"),
                                    "unknown_reference",
                                    format!("next names `{target}`, which is not a stage"),
                                ));
                            }
                        }
                    }
                    None => issues.push(Issue::new(
                        at("next"),
                        "invalid",
                        "next is a list of stage codes",
                    )),
                }
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        uuid_at(&doc["entity"])
            .map(|id| Reference {
                target: ObjectRef {
                    kind: ENTITY,
                    id: ObjectId(id),
                },
                mode: RefMode::Reads,
            })
            .into_iter()
            .collect()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut process = input.doc.clone();
                if let Some(object) = process.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text =
                    crate::canonical::canonicalize(&process).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: STAGE_PROCESS,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define the ordered stages a record of one entity moves through (for example qualify, propose, won, lost): each stage's required attributes, checklist and the stages it may move to next. A record's current stage is held in its stage attribute; a move to a stage whose required attributes are empty, or that the current stage does not allow, is refused."
    }
}

/// The entity a stage process document belongs to.
pub fn entity_of(doc: &Value) -> Option<Uuid> {
    uuid_at(&doc["entity"])
}

/// Why a stage move is refused, if it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveRefusal {
    /// `to` is not a stage of the process.
    UnknownStage(String),
    /// The current stage does not list `to` among its next stages.
    NotAllowed { from: String, to: String },
    /// The stage's required attributes that the record leaves empty.
    MissingRequired {
        stage: String,
        attributes: Vec<String>,
    },
}

/// The first stage, where a new record starts.
pub fn initial_stage(doc: &Value) -> Option<&str> {
    doc["stages"].as_array()?.first()?["code"].as_str()
}

/// M7-T1: whether a record may move from `from` (its stored stage; `None`
/// for a new record, or one never in a stage) to `to`, given the record as
/// the write leaves it. A new record may start in any stage whose required
/// attributes it fills; a stage it already holds is no move.
pub fn check_move(
    doc: &Value,
    from: Option<&str>,
    to: &str,
    record: &serde_json::Map<String, Value>,
) -> Result<(), MoveRefusal> {
    let stages = doc["stages"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let Some(stage) = stages.iter().find(|s| s["code"].as_str() == Some(to)) else {
        return Err(MoveRefusal::UnknownStage(to.to_owned()));
    };
    if let Some(from) = from.filter(|f| !f.is_empty() && *f != to)
        && let Some(current) = stages.iter().find(|s| s["code"].as_str() == Some(from))
    {
        let allowed = strings(&current["next"]).unwrap_or_default();
        if !allowed.contains(&to) {
            return Err(MoveRefusal::NotAllowed {
                from: from.to_owned(),
                to: to.to_owned(),
            });
        }
    }
    let missing: Vec<String> = strings(&stage["required"])
        .unwrap_or_default()
        .into_iter()
        .filter(|attribute| is_empty(record.get(*attribute)))
        .map(str::to_owned)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(MoveRefusal::MissingRequired {
            stage: to.to_owned(),
            attributes: missing,
        })
    }
}

fn is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> Value {
        json!({
            "entity": Uuid::now_v7().to_string(),
            "stages": [
                { "code": "qualify", "label_en": "Qualify", "required": ["budget"],
                  "checklist": ["Call the buyer"], "next": ["propose", "lost"] },
                { "code": "propose", "label_en": "Propose", "required": ["amount", "close_date"],
                  "next": ["won", "lost"] },
                { "code": "won", "label_en": "Won" },
                { "code": "lost", "label_en": "Lost" }
            ]
        })
    }

    fn record(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn stage_process_shape_is_checked() {
        let kind = StageProcessKind;
        assert!(kind.validate_shape(&process()).is_ok());
        let mut bad = process();
        bad["stages"][0]["next"] = json!(["nowhere"]);
        assert!(kind.validate_shape(&bad).is_err(), "next names a stage");
        let mut dup = process();
        dup["stages"][1]["code"] = json!("qualify");
        assert!(kind.validate_shape(&dup).is_err(), "codes are unique");
        assert!(
            kind.validate_shape(&json!({ "entity": Uuid::now_v7().to_string(), "stages": [] }))
                .is_err()
        );
        assert!(
            kind.validate_shape(&json!({ "stages": [{ "code": "a", "label_en": "A" }] }))
                .is_err()
        );
        assert_eq!(initial_stage(&process()), Some("qualify"));
    }

    #[test]
    fn stage_process_refuses_a_move_with_missing_required_attributes() {
        let doc = process();
        let partial = record(json!({ "budget": 1000, "amount": 900, "close_date": "" }));
        assert_eq!(
            check_move(&doc, Some("qualify"), "propose", &partial),
            Err(MoveRefusal::MissingRequired {
                stage: "propose".into(),
                attributes: vec!["close_date".into()],
            })
        );
        let full = record(json!({ "amount": 900, "close_date": "2026-11-01" }));
        assert_eq!(check_move(&doc, Some("qualify"), "propose", &full), Ok(()));
    }

    #[test]
    fn stage_process_allows_only_the_next_stages() {
        let doc = process();
        let any = record(json!({ "budget": 1 }));
        assert_eq!(
            check_move(&doc, Some("qualify"), "won", &any),
            Err(MoveRefusal::NotAllowed {
                from: "qualify".into(),
                to: "won".into()
            })
        );
        assert_eq!(check_move(&doc, Some("qualify"), "lost", &any), Ok(()));
        assert_eq!(
            check_move(&doc, Some("won"), "qualify", &any),
            Err(MoveRefusal::NotAllowed {
                from: "won".into(),
                to: "qualify".into(),
            }),
            "a final stage has no next"
        );
        assert_eq!(
            check_move(&doc, None, "qualify", &any),
            Ok(()),
            "a new record starts anywhere it qualifies"
        );
        assert_eq!(
            check_move(&doc, Some("qualify"), "nowhere", &any),
            Err(MoveRefusal::UnknownStage("nowhere".into()))
        );
    }
}
