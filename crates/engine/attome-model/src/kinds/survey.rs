//! The survey kind (roadmap G14-T1): questions whose answers land in a typed
//! response entity of their own.
//!
//! ```json
//! { "response_entity": "csat_response", "display_name": "CSAT",
//!   "display_name_ar": "رضا العملاء",
//!   "questions": [
//!     { "key": "score", "label": "How satisfied are you?", "label_ar": "ما مدى رضاك؟",
//!       "type": "rating", "required": true },
//!     { "key": "channel", "label": "How did you reach us?", "type": "choice",
//!       "options": ["phone", "email", "chat"] } ] }
//! ```
//!
//! Each question is one attribute of the response entity ([`QUESTION_TYPES`]
//! say which field type), named by its `key`. Publishing the survey
//! provisions that entity through the normal changeset path:
//! [`changeset_for`] writes an `attome-changeset/v1` document (create the
//! entity, add a field per question, link the response to its respondent
//! and the record it is about, set the Arabic labels) that the publish route
//! applies through the ledger before the survey goes live. The document's id
//! is derived from the survey and its content, so publishing the same survey
//! again applies nothing, and a new question in a later version is a new
//! changeset that only adds its field. A question removed from the survey
//! keeps its column (answers are never dropped by an edit).

use attome_types::AppError;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const SURVEY: KindName = KindName("survey");

/// Question types and the field type each one becomes.
pub const QUESTION_TYPES: [(&str, &str); 8] = [
    ("text", "text"),
    ("long_text", "text"),
    ("number", "number"),
    ("rating", "number"),
    ("bool", "bool"),
    ("date", "date"),
    ("choice", "choice"),
    ("multi_choice", "choice"),
];

/// Most questions in one survey.
pub const MAX_QUESTIONS: usize = 100;
/// Most options in one choice question.
pub const MAX_OPTIONS: usize = 50;
const MAX_LABEL_CHARS: usize = 300;
/// Fields every response entity has besides its questions.
const SYSTEM_FIELDS: [&str; 5] = [
    "respondent_ref",
    "respondent_email",
    "regarding_entity",
    "regarding_id",
    "submitted_at",
];

/// G14-T2: when a survey is sent. A record of `entity` whose `field`
/// becomes `value` gets one survey, emailed to the user or contact its
/// `recipient` lookup names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOn {
    pub entity: String,
    pub field: String,
    pub value: String,
    pub recipient: String,
}

/// The survey's `send_on`, when it has a valid one. Pure.
pub fn send_on_of(doc: &Value) -> Option<SendOn> {
    let s = doc.get("send_on")?;
    let text = |k: &str| s.get(k).and_then(Value::as_str).map(str::trim);
    let (entity, field, recipient) = (text("entity")?, text("field")?, text("recipient")?);
    let value = text("value")?;
    (logical_name_ok(entity)
        && logical_name_ok(field)
        && logical_name_ok(recipient)
        && !value.is_empty())
    .then(|| SendOn {
        entity: entity.to_owned(),
        field: field.to_owned(),
        value: value.to_owned(),
        recipient: recipient.to_owned(),
    })
}

/// The survey kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct SurveyKind;

/// Whether `name` is a usable logical name: lowercase letters, digits and
/// underscores, starting with a letter, at most 60 characters. Pure.
pub fn logical_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 60
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The field type a question type becomes.
pub fn field_type_of(question_type: &str) -> Option<&'static str> {
    QUESTION_TYPES
        .iter()
        .find(|(q, _)| *q == question_type)
        .map(|(_, f)| *f)
}

/// The response entity a survey document names.
pub fn response_entity_of(doc: &Value) -> Option<&str> {
    doc.get("response_entity").and_then(Value::as_str)
}

fn issue(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Issue {
    Issue::new(path, code, message)
}

fn text_ok(v: Option<&Value>, required: bool) -> bool {
    match v {
        None => !required,
        Some(v) => v
            .as_str()
            .is_some_and(|s| !s.trim().is_empty() && s.chars().count() <= MAX_LABEL_CHARS),
    }
}

impl Kind for SurveyKind {
    fn name(&self) -> KindName {
        SURVEY
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        let types: Vec<&str> = QUESTION_TYPES.iter().map(|(q, _)| *q).collect();
        json!({
            "type": "object",
            "required": ["response_entity", "display_name", "questions"],
            "additionalProperties": false,
            "properties": {
                "response_entity": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,59}$" },
                "display_name": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                "display_name_ar": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                "send_on": {
                    "type": "object",
                    "required": ["entity", "field", "value", "recipient"],
                    "additionalProperties": false,
                    "properties": {
                        "entity": { "type": "string" },
                        "field": { "type": "string" },
                        "value": { "type": "string" },
                        "recipient": { "type": "string" }
                    }
                },
                "questions": {
                    "type": "array", "minItems": 1, "maxItems": MAX_QUESTIONS,
                    "items": {
                        "type": "object",
                        "required": ["key", "label", "type"],
                        "additionalProperties": false,
                        "properties": {
                            "key": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,59}$" },
                            "label": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                            "label_ar": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                            "type": { "enum": types },
                            "required": { "type": "boolean" },
                            "options": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_OPTIONS }
                        }
                    }
                }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![issue(
                "",
                "not_an_object",
                "a survey is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if ![
                "response_entity",
                "display_name",
                "display_name_ar",
                "send_on",
                "questions",
            ]
            .contains(&key.as_str())
            {
                issues.push(issue(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a survey has no `{key}`"),
                ));
            }
        }
        if !response_entity_of(doc).is_some_and(logical_name_ok) {
            issues.push(issue(
                "/response_entity",
                "invalid",
                "response_entity is a logical name: lowercase letters, digits and _",
            ));
        }
        if !text_ok(doc.get("display_name"), true) {
            issues.push(issue(
                "/display_name",
                "invalid",
                "display_name is required text",
            ));
        }
        if !text_ok(doc.get("display_name_ar"), false) {
            issues.push(issue(
                "/display_name_ar",
                "invalid",
                "display_name_ar is text",
            ));
        }
        if doc.get("send_on").is_some() && send_on_of(doc).is_none() {
            issues.push(issue(
                "/send_on",
                "invalid",
                "send_on names an entity, a field, the value that sends, and the recipient lookup",
            ));
        }
        let questions = doc.get("questions").and_then(Value::as_array);
        match questions {
            None => issues.push(issue("/questions", "invalid", "questions is a list")),
            Some(q) if q.is_empty() || q.len() > MAX_QUESTIONS => issues.push(issue(
                "/questions",
                "invalid",
                format!("a survey has 1 to {MAX_QUESTIONS} questions"),
            )),
            Some(_) => {}
        }
        let mut seen = Vec::new();
        for (i, q) in questions.into_iter().flatten().enumerate() {
            let at = format!("/questions/{i}");
            let key = q.get("key").and_then(Value::as_str).unwrap_or_default();
            if !logical_name_ok(key) || SYSTEM_FIELDS.contains(&key) {
                issues.push(issue(
                    format!("{at}/key"),
                    "invalid",
                    "a key is a logical name, and not one the response entity already has",
                ));
            } else if seen.contains(&key) {
                issues.push(issue(
                    format!("{at}/key"),
                    "duplicate",
                    format!("`{key}` is used twice"),
                ));
            } else {
                seen.push(key);
            }
            if !text_ok(q.get("label"), true) || !text_ok(q.get("label_ar"), false) {
                issues.push(issue(
                    format!("{at}/label"),
                    "invalid",
                    "a question needs a label",
                ));
            }
            let qtype = q.get("type").and_then(Value::as_str).unwrap_or_default();
            if field_type_of(qtype).is_none() {
                issues.push(issue(
                    format!("{at}/type"),
                    "invalid",
                    "an unknown question type",
                ));
            }
            let options = q.get("options").and_then(Value::as_array);
            let is_choice = matches!(qtype, "choice" | "multi_choice");
            match (is_choice, options) {
                (true, Some(o))
                    if !o.is_empty()
                        && o.len() <= MAX_OPTIONS
                        && o.iter()
                            .all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty())) => {}
                (true, _) => issues.push(issue(
                    format!("{at}/options"),
                    "invalid",
                    format!("a choice question has 1 to {MAX_OPTIONS} options"),
                )),
                (false, Some(_)) => issues.push(issue(
                    format!("{at}/options"),
                    "invalid",
                    "only a choice question has options",
                )),
                (false, None) => {}
            }
            if q.get("required").is_some_and(|r| !r.is_boolean()) {
                issues.push(issue(
                    format!("{at}/required"),
                    "invalid",
                    "required is true or false",
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
                let mut survey = input.doc.clone();
                if let Some(object) = survey.as_object_mut() {
                    object.insert("id".into(), json!(input.id.0.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text = crate::canonical::canonicalize(&survey).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: SURVEY,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a survey: questions (text, number, rating, yes/no, date, choice) whose answers are stored as records of their own response entity, created when the survey is published."
    }
}

/// A UUIDv7-shaped id derived from the survey and its content, so the same
/// survey content always yields the same changeset. Pure.
pub fn changeset_id(survey: Uuid, doc: &Value) -> Uuid {
    let canonical = crate::canonical::canonicalize(doc).unwrap_or_default();
    let digest = Sha256::new()
        .chain_update(survey.as_bytes())
        .chain_update(canonical.as_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn field(
    name: &str,
    display: &str,
    field_type: &str,
    lookup: Option<&str>,
    required: bool,
    choices: Option<(Vec<Value>, bool)>,
) -> Value {
    json!({
        "data_classification": "general",
        "display_name": display,
        "field_type": field_type,
        "is_customized": true,
        "is_filterable": lookup.is_some(),
        "is_required": required,
        "is_sensitive": false,
        "is_sortable": false,
        "logicalname": name,
        "lookup_entity": lookup,
        "max_length": if field_type == "text" { json!(4000) } else { Value::Null },
        "on_target_delete": "orphan",
        "options": choices.map(|(c, multi)| json!({ "choices": c, "multi": multi })),
    })
}

/// The changeset that provisions a survey's response entity, sealed with its
/// checksum. `seq` is the changeset's place in the survey's scope. Pure, and
/// the same for the same input.
pub fn changeset_for(survey: Uuid, doc: &Value, seq: i32) -> Value {
    let entity = response_entity_of(doc).unwrap_or_default();
    let display = doc
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or(entity);
    let mut ops: Vec<Value> = Vec::new();
    let mut push = |op: &str, target: Value, args: Value| {
        let seq = ops.len() + 1;
        ops.push(
            json!({ "args": args, "op": op, "phase": "expand", "seq": seq, "target": target }),
        );
    };
    push(
        "create_entity",
        json!({ "entity": entity }),
        json!({ "definition": {
            "category": "Other",
            "display_name": format!("{display} Response"),
            "is_append_only": false,
            "is_audited": true,
            "is_customized": true,
            "logicalname": entity,
            "primary_name_attribute": "submitted_at",
        }}),
    );
    let mut labels: Vec<(String, String)> = Vec::new();
    if let Some(ar) = doc.get("display_name_ar").and_then(Value::as_str) {
        labels.push((String::new(), ar.to_owned()));
    }
    for (name, display, ftype, lookup) in [
        (
            "respondent_ref",
            "Respondent",
            "lookup",
            Some("user_account"),
        ),
        ("regarding_entity", "About Entity", "text", None),
        ("regarding_id", "About Record", "text", None),
        ("respondent_email", "Respondent Email", "text", None),
        ("submitted_at", "Submitted", "date_time", None),
    ] {
        push(
            "add_field",
            json!({ "entity": entity, "field": name }),
            json!({ "definition": field(name, display, ftype, lookup, false, None) }),
        );
    }
    for q in doc
        .get("questions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let key = q.get("key").and_then(Value::as_str).unwrap_or_default();
        let qtype = q.get("type").and_then(Value::as_str).unwrap_or_default();
        let Some(ftype) = field_type_of(qtype) else {
            continue;
        };
        let label = q.get("label").and_then(Value::as_str).unwrap_or(key);
        let choices = q
            .get("options")
            .and_then(Value::as_array)
            .map(|o| (o.clone(), qtype == "multi_choice"));
        let required = q.get("required").and_then(Value::as_bool).unwrap_or(false);
        push(
            "add_field",
            json!({ "entity": entity, "field": key }),
            json!({ "definition": field(key, label, ftype, None, required, choices) }),
        );
        if let Some(ar) = q.get("label_ar").and_then(Value::as_str) {
            labels.push((key.to_owned(), ar.to_owned()));
        }
    }
    for (key, ar) in labels {
        let (kind, object_key) = if key.is_empty() {
            ("entity", entity.to_owned())
        } else {
            ("attribute", format!("{entity}.{key}"))
        };
        push(
            "set_label",
            json!({ "locale": "ar", "object_key": object_key, "object_kind": kind }),
            json!({ "display_name": ar }),
        );
    }
    let mut out = Map::new();
    out.insert("author".into(), json!("survey"));
    out.insert(
        "checksum".into(),
        json!(format!("sha256:{}", "0".repeat(64))),
    );
    out.insert("closed_at".into(), json!(FIXED_TIME));
    out.insert(
        "description".into(),
        json!(format!(
            "The response entity of the survey {display} (G14-T1)."
        )),
    );
    out.insert("format".into(), json!("attome-changeset/v1"));
    out.insert("id".into(), json!(changeset_id(survey, doc).to_string()));
    out.insert("layer".into(), json!("project"));
    let name: String = format!("survey-{}", entity.replace('_', "-"))
        .chars()
        .take(60)
        .collect();
    out.insert("name".into(), json!(name.trim_end_matches('-')));
    out.insert("opened_at".into(), json!(FIXED_TIME));
    out.insert("operations".into(), Value::Array(ops));
    out.insert(
        "requires".into(),
        json!({ "modules": ["core"], "platform": ">=0.1.0" }),
    );
    out.insert("scope".into(), json!(scope_of(entity)));
    out.insert("seq".into(), json!(seq));
    out.insert(
        "title".into(),
        json!(
            format!("Survey responses: {display}")
                .chars()
                .take(200)
                .collect::<String>()
        ),
    );
    let mut document = Value::Object(out);
    // Sealed here, so the ledger's checksum check passes.
    if let Ok(checksum) = crate::canonical::document_checksum(&document) {
        document["checksum"] = json!(checksum);
    }
    document
}

/// The changeset's open and close time: fixed, since the same id must keep
/// the same checksum (the ledger refuses a changed document under an id it
/// applied).
const FIXED_TIME: &str = "2026-10-21T00:00:00Z";

/// The changeset scope of a survey's response entity. Pure.
pub fn scope_of(entity: &str) -> String {
    format!("survey_{entity}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn survey() -> Value {
        json!({
            "response_entity": "csat_response",
            "display_name": "CSAT",
            "display_name_ar": "رضا العملاء",
            "questions": [
                { "key": "score", "label": "How satisfied are you?", "label_ar": "ما مدى رضاك؟",
                  "type": "rating", "required": true },
                { "key": "channel", "label": "How did you reach us?", "type": "choice",
                  "options": ["phone", "email"] },
                { "key": "comment", "label": "Anything else?", "type": "long_text" }
            ]
        })
    }

    #[test]
    fn a_survey_checks_its_questions() {
        let kind = SurveyKind;
        assert!(kind.validate_shape(&survey()).is_ok());
        let mut bad = survey();
        bad["questions"][1]["options"] = json!([]);
        assert!(kind.validate_shape(&bad).is_err(), "a choice needs options");
        let mut dup = survey();
        dup["questions"][2]["key"] = json!("score");
        assert!(kind.validate_shape(&dup).is_err(), "keys are unique");
        let mut system = survey();
        system["questions"][2]["key"] = json!("submitted_at");
        assert!(kind.validate_shape(&system).is_err(), "not a system field");
        let mut name = survey();
        name["response_entity"] = json!("CSAT Response");
        assert!(kind.validate_shape(&name).is_err());
        assert!(
            kind.validate_shape(
                &json!({"response_entity": "x", "display_name": "X", "questions": []})
            )
            .is_err()
        );
    }

    #[test]
    fn questions_map_to_attributes_of_the_response_entity() {
        let cs = changeset_for(Uuid::from_u128(1), &survey(), 1);
        let ops = cs["operations"].as_array().expect("operations");
        assert_eq!(ops[0]["op"], "create_entity");
        assert_eq!(ops[0]["target"]["entity"], "csat_response");
        let fields: Vec<(&str, &str)> = ops
            .iter()
            .filter(|o| o["op"] == "add_field")
            .map(|o| {
                (
                    o["target"]["field"].as_str().unwrap_or_default(),
                    o["args"]["definition"]["field_type"]
                        .as_str()
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert!(fields.contains(&("score", "number")));
        assert!(fields.contains(&("channel", "choice")));
        assert!(fields.contains(&("comment", "text")));
        assert!(fields.contains(&("respondent_ref", "lookup")));
        let score = ops
            .iter()
            .find(|o| o["target"]["field"] == "score")
            .expect("score");
        assert_eq!(score["args"]["definition"]["is_required"], true);
        let labels = ops.iter().filter(|o| o["op"] == "set_label").count();
        assert_eq!(labels, 2, "the survey's and one question's Arabic labels");
        assert_eq!(cs["scope"], "survey_csat_response");
        assert_eq!(
            crate::canonical::document_checksum(&cs).ok().as_deref(),
            cs["checksum"].as_str(),
            "sealed"
        );
        assert_eq!(cs["layer"], "project");
    }

    #[test]
    fn the_changeset_id_is_stable_for_the_same_content() {
        let a = changeset_id(Uuid::from_u128(1), &survey());
        assert_eq!(a, changeset_id(Uuid::from_u128(1), &survey()));
        assert_eq!(a.get_version_num(), 7);
        let mut changed = survey();
        changed["questions"][2]["label"] = json!("Anything more?");
        assert_ne!(a, changeset_id(Uuid::from_u128(1), &changed));
        assert_ne!(a, changeset_id(Uuid::from_u128(2), &survey()));
    }

    #[test]
    fn send_on_names_the_trigger_and_the_recipient() {
        let mut doc = survey();
        doc["send_on"] = json!({
            "entity": "service_ticket", "field": "status", "value": "closed",
            "recipient": "requester_id"
        });
        assert!(SurveyKind.validate_shape(&doc).is_ok());
        assert_eq!(
            send_on_of(&doc),
            Some(SendOn {
                entity: "service_ticket".into(),
                field: "status".into(),
                value: "closed".into(),
                recipient: "requester_id".into(),
            })
        );
        doc["send_on"]["entity"] = json!("Service Ticket");
        assert!(SurveyKind.validate_shape(&doc).is_err());
        assert_eq!(send_on_of(&survey()), None);
    }
}
