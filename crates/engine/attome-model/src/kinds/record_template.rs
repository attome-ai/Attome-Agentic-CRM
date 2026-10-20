//! The record template kind (roadmap B8-T1): values to fill a new record of
//! one entity with, child records to create with it, and the condition under
//! which it is offered.
//!
//! ```json
//! { "entity": "<entity id>",
//!   "label_en": "Enterprise renewal", "label_ar": "تجديد مؤسسي",
//!   "when": "type == \"renewal\"",
//!   "values": [
//!     { "attribute": "<attribute id>", "fixed": "Net 30" },
//!     { "attribute": "<attribute id>", "expression": "today() + 30" },
//!     { "attribute": "<attribute id>", "prompt": { "label_en": "Seats" } }
//!   ],
//!   "children": [ { "template": "<record_template id>", "link": "<attribute id>" } ] }
//! ```
//!
//! Each value sets one attribute in exactly one way: a fixed value, a rule
//! expression (Z11 text, evaluated when the template is applied), or a prompt
//! the person answers. A child names another template and the lookup on the
//! child's entity that points back at the new record. Publish refuses a
//! template whose entity, attributes or child templates no longer exist
//! (dangling references), and a fixed value that does not fit its
//! attribute's type. A shared template is published like any metadata;
//! a personal one is a person's own saved values and is never published
//! (B8-T2 keeps it with the person).

use std::collections::BTreeSet;

use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::form::{ATTRIBUTE, ENTITY};

/// The kind's name.
pub const RECORD_TEMPLATE: KindName = KindName("record_template");

const MAX_VALUES: usize = 200;
const MAX_CHILDREN: usize = 20;
const MAX_TEXT_CHARS: usize = 500;
const MAX_EXPRESSION_CHARS: usize = 4000;

const KEYS: [&str; 6] = [
    "entity", "label_en", "label_ar", "when", "values", "children",
];
const VALUE_KEYS: [&str; 4] = ["attribute", "fixed", "expression", "prompt"];
const SOURCES: [&str; 3] = ["fixed", "expression", "prompt"];
const PROMPT_KEYS: [&str; 3] = ["label_en", "label_ar", "required"];
const CHILD_KEYS: [&str; 2] = ["template", "link"];

/// Field types a template may not set: they hold files or are computed.
const UNSETTABLE: [&str; 3] = ["file", "image", "formula"];

/// The record template kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordTemplateKind;

fn uuid_at(value: Option<&Value>) -> Option<Uuid> {
    value
        .and_then(Value::as_str)
        .and_then(|text| Uuid::parse_str(text).ok())
}

fn attribute_ref(id: Uuid) -> ObjectRef {
    ObjectRef {
        kind: ATTRIBUTE,
        id: ObjectId(id),
    }
}

/// Whether `value` is a valid fixed value of an attribute of `field_type`.
/// A type this check does not know accepts anything.
pub fn fixed_value_fits(field_type: &str, value: &Value) -> bool {
    if value.is_null() {
        return true;
    }
    match field_type {
        "text" | "rich_text" | "color" | "icon" => value.is_string(),
        "number" | "currency" => value.is_number(),
        "bool" => value.is_boolean(),
        "date" => value.as_str().is_some_and(|s| {
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
                || chrono::DateTime::parse_from_rfc3339(s).is_ok()
        }),
        "choice" => value.is_string() || value.is_number(),
        "lookup" => uuid_at(Some(value)).is_some(),
        other => !UNSETTABLE.contains(&other),
    }
}

fn long_text(value: Option<&Value>, max: usize) -> bool {
    value.is_some_and(|v| v.as_str().is_none_or(|v| v.chars().count() > max))
}

fn unknown_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
    what: &str,
    issues: &mut Vec<Issue>,
) {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            issues.push(Issue::new(
                format!("{path}/{key}"),
                "unknown_property",
                format!("{what} has no `{key}`"),
            ));
        }
    }
}

fn check_value(index: usize, value: &Value, issues: &mut Vec<Issue>) {
    let path = format!("/values/{index}");
    let Some(value) = value.as_object() else {
        issues.push(Issue::new(path, "invalid", "a value is an object"));
        return;
    };
    unknown_keys(value, &VALUE_KEYS, &path, "a value", issues);
    if uuid_at(value.get("attribute")).is_none() {
        issues.push(Issue::new(
            format!("{path}/attribute"),
            "invalid",
            "attribute is the id of the attribute this value sets",
        ));
    }
    let sources = SOURCES.iter().filter(|s| value.contains_key(**s)).count();
    if sources != 1 {
        issues.push(Issue::new(
            path.clone(),
            "one_source",
            "a value has exactly one of fixed, expression or prompt",
        ));
    }
    if let Some(expression) = value.get("expression")
        && expression
            .as_str()
            .is_none_or(|e| e.trim().is_empty() || e.chars().count() > MAX_EXPRESSION_CHARS)
    {
        issues.push(Issue::new(
            format!("{path}/expression"),
            "invalid",
            "an expression is rule text of at most 4000 characters",
        ));
    }
    if let Some(prompt) = value.get("prompt") {
        let Some(prompt) = prompt.as_object() else {
            issues.push(Issue::new(
                format!("{path}/prompt"),
                "invalid",
                "a prompt is an object with its label",
            ));
            return;
        };
        unknown_keys(
            prompt,
            &PROMPT_KEYS,
            &format!("{path}/prompt"),
            "a prompt",
            issues,
        );
        if prompt
            .get("label_en")
            .and_then(Value::as_str)
            .is_none_or(|l| l.trim().is_empty() || l.chars().count() > MAX_TEXT_CHARS)
            || long_text(prompt.get("label_ar"), MAX_TEXT_CHARS)
        {
            issues.push(Issue::new(
                format!("{path}/prompt/label_en"),
                "invalid",
                "a prompt has a label (label_en, and label_ar if given) of at most 500 characters",
            ));
        }
        if prompt.get("required").is_some_and(|r| !r.is_boolean()) {
            issues.push(Issue::new(
                format!("{path}/prompt/required"),
                "invalid",
                "required is true or false",
            ));
        }
    }
}

fn check_child(index: usize, child: &Value, issues: &mut Vec<Issue>) {
    let path = format!("/children/{index}");
    let Some(child) = child.as_object() else {
        issues.push(Issue::new(path, "invalid", "a child is an object"));
        return;
    };
    unknown_keys(child, &CHILD_KEYS, &path, "a child", issues);
    for key in CHILD_KEYS {
        if uuid_at(child.get(key)).is_none() {
            issues.push(Issue::new(
                format!("{path}/{key}"),
                "invalid",
                "a child names its template and the lookup that links it, by id",
            ));
        }
    }
}

impl Kind for RecordTemplateKind {
    fn name(&self) -> KindName {
        RECORD_TEMPLATE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "values"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "label_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "label_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "when": { "type": "string", "maxLength": MAX_EXPRESSION_CHARS },
                "values": {
                    "type": "array",
                    "maxItems": MAX_VALUES,
                    "items": {
                        "type": "object",
                        "required": ["attribute"],
                        "additionalProperties": false,
                        "properties": {
                            "attribute": { "type": "string", "format": "uuid" },
                            "fixed": {},
                            "expression": { "type": "string", "maxLength": MAX_EXPRESSION_CHARS },
                            "prompt": {
                                "type": "object",
                                "required": ["label_en"],
                                "additionalProperties": false,
                                "properties": {
                                    "label_en": { "type": "string" },
                                    "label_ar": { "type": "string" },
                                    "required": { "type": "boolean" }
                                }
                            }
                        }
                    }
                },
                "children": {
                    "type": "array",
                    "maxItems": MAX_CHILDREN,
                    "items": {
                        "type": "object",
                        "required": ["template", "link"],
                        "additionalProperties": false,
                        "properties": {
                            "template": { "type": "string", "format": "uuid" },
                            "link": { "type": "string", "format": "uuid" }
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
                "a record template is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        unknown_keys(object, &KEYS, "", "a record template", &mut issues);
        if uuid_at(object.get("entity")).is_none() {
            issues.push(Issue::new(
                "/entity",
                "invalid",
                "entity is the id of the entity the template creates",
            ));
        }
        for key in ["label_en", "label_ar"] {
            if long_text(object.get(key), MAX_TEXT_CHARS) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a label is text of at most 500 characters",
                ));
            }
        }
        if object.get("when").is_some_and(|w| {
            w.as_str()
                .is_none_or(|w| w.trim().is_empty() || w.chars().count() > MAX_EXPRESSION_CHARS)
        }) {
            issues.push(Issue::new(
                "/when",
                "invalid",
                "when is the rule text that says where the template is offered",
            ));
        }
        match object.get("values").and_then(Value::as_array) {
            None => issues.push(Issue::new("/values", "invalid", "values is a list")),
            Some(values) => {
                if values.len() > MAX_VALUES {
                    issues.push(Issue::new(
                        "/values",
                        "too_many",
                        format!("a template sets at most {MAX_VALUES} values"),
                    ));
                }
                let mut seen = BTreeSet::new();
                for (index, value) in values.iter().enumerate() {
                    check_value(index, value, &mut issues);
                    if let Some(attribute) = uuid_at(value.get("attribute"))
                        && !seen.insert(attribute)
                    {
                        issues.push(Issue::new(
                            format!("/values/{index}/attribute"),
                            "duplicate",
                            "this attribute already has a value in the template",
                        ));
                    }
                }
            }
        }
        if let Some(children) = object.get("children") {
            match children.as_array() {
                None => issues.push(Issue::new("/children", "invalid", "children is a list")),
                Some(children) => {
                    if children.len() > MAX_CHILDREN {
                        issues.push(Issue::new(
                            "/children",
                            "too_many",
                            format!("a template creates at most {MAX_CHILDREN} children"),
                        ));
                    }
                    for (index, child) in children.iter().enumerate() {
                        check_child(index, child, &mut issues);
                    }
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
        let mut refs = Vec::new();
        if let Some(entity) = uuid_at(doc.get("entity")) {
            refs.push(Reference {
                target: ObjectRef {
                    kind: ENTITY,
                    id: ObjectId(entity),
                },
                mode: RefMode::Writes,
            });
        }
        for value in doc["values"].as_array().into_iter().flatten() {
            if let Some(attribute) = uuid_at(value.get("attribute")) {
                refs.push(Reference {
                    target: attribute_ref(attribute),
                    mode: RefMode::Writes,
                });
            }
        }
        for child in doc["children"].as_array().into_iter().flatten() {
            if let Some(template) = uuid_at(child.get("template")) {
                refs.push(Reference {
                    target: ObjectRef {
                        kind: RECORD_TEMPLATE,
                        id: ObjectId(template),
                    },
                    mode: RefMode::Reads,
                });
            }
            if let Some(link) = uuid_at(child.get("link")) {
                refs.push(Reference {
                    target: attribute_ref(link),
                    mode: RefMode::Writes,
                });
            }
        }
        refs
    }

    fn check(&self, doc: &Value, ctx: &dyn ValidationCtx) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (index, value) in doc["values"].as_array().into_iter().flatten().enumerate() {
            let Some(attribute) = uuid_at(value.get("attribute")) else {
                continue;
            };
            let Some(field_type) = ctx.attribute_type(&attribute_ref(attribute)) else {
                continue;
            };
            if UNSETTABLE.contains(&field_type.as_str()) {
                issues.push(Issue::new(
                    format!("/values/{index}/attribute"),
                    "unsettable",
                    format!("a template cannot set a {field_type} attribute"),
                ));
            } else if let Some(fixed) = value.get("fixed")
                && !fixed_value_fits(&field_type, fixed)
            {
                issues.push(Issue::new(
                    format!("/values/{index}/fixed"),
                    "type_mismatch",
                    format!("the value is not a valid {field_type}"),
                ));
            }
        }
        for (index, child) in doc["children"].as_array().into_iter().flatten().enumerate() {
            if let Some(link) = uuid_at(child.get("link"))
                && let Some(field_type) = ctx.attribute_type(&attribute_ref(link))
                && field_type != "lookup"
            {
                issues.push(Issue::new(
                    format!("/children/{index}/link"),
                    "not_a_lookup",
                    "a child is linked through a lookup attribute",
                ));
            }
        }
        issues
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut template = input.doc.clone();
                if let Some(object) = template.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text =
                    crate::canonical::canonicalize(&template).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: RECORD_TEMPLATE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a record template for one entity: the values a new record starts with (fixed, a rule expression, or a question to ask), the child records to create with it, and the condition under which it is offered."
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use std::collections::BTreeMap;

    use super::*;

    const ENTITY_ID: &str = "0190a8a0-0000-7000-8000-0000000000e1";
    const TERMS: &str = "0190a8a0-0000-7000-8000-0000000000a1";
    const DUE: &str = "0190a8a0-0000-7000-8000-0000000000a2";
    const SEATS: &str = "0190a8a0-0000-7000-8000-0000000000a3";
    const PARENT: &str = "0190a8a0-0000-7000-8000-0000000000a4";
    const CHILD: &str = "0190a8a0-0000-7000-8000-0000000000c1";

    struct Model(BTreeMap<Uuid, &'static str>);

    impl ValidationCtx for Model {
        fn exists(&self, _target: &ObjectRef) -> bool {
            true
        }

        fn attribute_type(&self, target: &ObjectRef) -> Option<String> {
            self.0.get(&target.id.0).map(|t| (*t).to_owned())
        }
    }

    fn model() -> Model {
        Model(BTreeMap::from([
            (Uuid::parse_str(TERMS).unwrap(), "text"),
            (Uuid::parse_str(DUE).unwrap(), "date"),
            (Uuid::parse_str(SEATS).unwrap(), "number"),
            (Uuid::parse_str(PARENT).unwrap(), "lookup"),
        ]))
    }

    fn template() -> Value {
        json!({
            "entity": ENTITY_ID,
            "label_en": "Enterprise renewal",
            "when": "type == \"renewal\"",
            "values": [
                { "attribute": TERMS, "fixed": "Net 30" },
                { "attribute": DUE, "expression": "today() + 30" },
                { "attribute": SEATS, "prompt": { "label_en": "Seats", "required": true } }
            ],
            "children": [ { "template": CHILD, "link": PARENT } ]
        })
    }

    fn codes(issues: &[Issue]) -> Vec<&'static str> {
        issues.iter().map(|i| i.code).collect()
    }

    #[test]
    fn record_template_shape_accepts_each_value_source() {
        assert!(RecordTemplateKind.validate_shape(&template()).is_ok());
        assert!(RecordTemplateKind.check(&template(), &model()).is_empty());
    }

    #[test]
    fn record_template_value_needs_exactly_one_source() {
        let mut two = template();
        two["values"][0]["expression"] = json!("'x'");
        let issues = RecordTemplateKind.validate_shape(&two).unwrap_err();
        assert!(codes(&issues).contains(&"one_source"), "{issues:?}");
        let mut none = template();
        none["values"][0].as_object_mut().unwrap().remove("fixed");
        assert!(RecordTemplateKind.validate_shape(&none).is_err());
        let mut twice = template();
        twice["values"][1]["attribute"] = json!(TERMS);
        let issues = RecordTemplateKind.validate_shape(&twice).unwrap_err();
        assert!(codes(&issues).contains(&"duplicate"), "{issues:?}");
    }

    #[test]
    fn record_template_fixed_values_fit_the_model() {
        let mut wrong = template();
        wrong["values"][0] = json!({ "attribute": SEATS, "fixed": "many" });
        wrong["values"][2] = json!({ "attribute": TERMS, "prompt": { "label_en": "Terms" } });
        let issues = RecordTemplateKind.check(&wrong, &model());
        assert_eq!(codes(&issues), vec!["type_mismatch"], "{issues:?}");
        assert!(fixed_value_fits("date", &json!("2027-01-31")));
        assert!(!fixed_value_fits("lookup", &json!("acme")));
        assert!(!fixed_value_fits("file", &json!("x")));
    }

    #[test]
    fn record_template_children_link_through_a_lookup() {
        let mut bad = template();
        bad["children"][0]["link"] = json!(TERMS);
        let issues = RecordTemplateKind.check(&bad, &model());
        assert_eq!(codes(&issues), vec!["not_a_lookup"]);
        let refs = RecordTemplateKind.references(&template());
        assert!(refs.iter().any(|r| r.target.kind == RECORD_TEMPLATE));
        assert_eq!(
            refs.len(),
            6,
            "the entity, three attributes, the child and its link"
        );
    }
}
