//! The form kind (roadmap Y1-T13): the first kind stored natively in the
//! metadata object store.
//!
//! ```json
//! { "entity": "<entity id>",
//!   "sections": [ { "label": "Contact", "fields": ["<attribute id>", ...] } ] }
//! ```
//!
//! A form reads its entity and each attribute it shows; those references go
//! to the `entity` and `attribute` adapter kinds, so a form naming a removed
//! attribute is reported as dangling and cannot be published. Cooking turns
//! a form into its canonical JSON with its id and name, the render plan the
//! client draws (Y14).

use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{
    Artefact, CookInput, Issue, Kind, KindLimits, RefMode, Reference, ValidationCtx,
};

/// The kind's name.
pub const FORM: KindName = KindName("form");
/// The entity adapter kind's name.
pub const ENTITY: KindName = KindName("entity");
/// The attribute adapter kind's name.
pub const ATTRIBUTE: KindName = KindName("attribute");

/// Most fields one form may show.
pub const MAX_FIELDS: usize = 400;

/// The form kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormKind;

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|text| Uuid::parse_str(text).ok())
}

impl Kind for FormKind {
    fn name(&self) -> KindName {
        FORM
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "sections"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "sections": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["label", "fields"],
                        "additionalProperties": false,
                        "properties": {
                            "label": { "type": "string", "minLength": 1 },
                            "fields": { "type": "array", "items": { "type": "string", "format": "uuid" } }
                        }
                    }
                }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let mut issues = Vec::new();
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a form is a JSON object",
            )]);
        };
        for key in object.keys() {
            if key != "entity" && key != "sections" {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a form has no `{key}`"),
                ));
            }
        }
        if uuid_at(&doc["entity"]).is_none() {
            issues.push(Issue::new(
                "/entity",
                "required",
                "a form names its entity by id",
            ));
        }
        match doc["sections"].as_array() {
            None => issues.push(Issue::new(
                "/sections",
                "required",
                "a form has a list of sections",
            )),
            Some(sections) => {
                let mut total = 0usize;
                for (i, section) in sections.iter().enumerate() {
                    let label_ok = section["label"]
                        .as_str()
                        .is_some_and(|l| !l.trim().is_empty());
                    if !label_ok {
                        issues.push(Issue::new(
                            format!("/sections/{i}/label"),
                            "required",
                            "a section has a label",
                        ));
                    }
                    match section["fields"].as_array() {
                        None => issues.push(Issue::new(
                            format!("/sections/{i}/fields"),
                            "required",
                            "a section has a list of fields",
                        )),
                        Some(fields) => {
                            total += fields.len();
                            for (j, field) in fields.iter().enumerate() {
                                if uuid_at(field).is_none() {
                                    issues.push(Issue::new(
                                        format!("/sections/{i}/fields/{j}"),
                                        "not_an_attribute_id",
                                        "a field is an attribute id",
                                    ));
                                }
                            }
                        }
                    }
                }
                if total > MAX_FIELDS {
                    issues.push(Issue::new(
                        "/sections",
                        "limit_exceeded",
                        format!("the form has {total} fields; the limit is {MAX_FIELDS}"),
                    ));
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
        if let Some(entity) = uuid_at(&doc["entity"]) {
            refs.push(Reference {
                target: ObjectRef {
                    kind: ENTITY,
                    id: ObjectId(entity),
                },
                mode: RefMode::Reads,
            });
        }
        for section in doc["sections"].as_array().into_iter().flatten() {
            for field in section["fields"].as_array().into_iter().flatten() {
                if let Some(attribute) = uuid_at(field) {
                    refs.push(Reference {
                        target: ObjectRef {
                            kind: ATTRIBUTE,
                            id: ObjectId(attribute),
                        },
                        mode: RefMode::Reads,
                    });
                }
            }
        }
        refs
    }

    fn check(&self, doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        // One attribute appears at most once on a form.
        let mut seen = std::collections::BTreeSet::new();
        let mut issues = Vec::new();
        for (i, section) in doc["sections"].as_array().into_iter().flatten().enumerate() {
            for (j, field) in section["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                if let Some(id) = field.as_str()
                    && !seen.insert(id.to_owned())
                {
                    issues.push(Issue::new(
                        format!("/sections/{i}/fields/{j}"),
                        "duplicate_field",
                        "this attribute is already on the form",
                    ));
                }
            }
        }
        issues
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let plan = json!({
                    "id": input.id.to_string(),
                    "name": input.name,
                    "entity": input.doc["entity"],
                    "sections": input.doc["sections"],
                });
                let text = crate::canonical::canonicalize(&plan).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: FORM,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn limits(&self) -> KindLimits {
        KindLimits {
            max_doc_bytes: 1024 * 1024,
            max_objects: 10_000,
        }
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit a record form: which entity it shows, its sections and the attributes in each."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(fields: &[Uuid]) -> Value {
        json!({
            "entity": Uuid::now_v7().to_string(),
            "sections": [{ "label": "Main", "fields": fields.iter().map(Uuid::to_string).collect::<Vec<_>>() }]
        })
    }

    #[test]
    fn a_well_formed_form_reads_its_entity_and_attributes() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let doc = form(&[a, b]);
        assert!(FormKind.validate_shape(&doc).is_ok());
        let refs = FormKind.references(&doc);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].target.kind, ENTITY);
        assert!(refs[1..].iter().all(|r| r.target.kind == ATTRIBUTE));
    }

    #[test]
    fn shape_problems_are_named_by_path() {
        let issues = FormKind
            .validate_shape(
                &json!({ "entity": "x", "sections": [{ "label": "", "fields": [1] }], "extra": 1 }),
            )
            .unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        assert!(paths.contains(&"/entity"));
        assert!(paths.contains(&"/sections/0/label"));
        assert!(paths.contains(&"/sections/0/fields/0"));
        assert!(paths.contains(&"/extra"));
    }

    #[test]
    fn a_repeated_attribute_is_an_issue_and_cooking_is_stable() {
        let a = Uuid::now_v7();
        let doc = form(&[a, a]);
        struct AllExist;
        impl ValidationCtx for AllExist {
            fn exists(&self, _target: &ObjectRef) -> bool {
                true
            }
        }
        assert_eq!(FormKind.check(&doc, &AllExist)[0].code, "duplicate_field");
        let input = CookInput {
            id: ObjectId::new(),
            name: "main".into(),
            doc: form(&[a]),
        };
        let one = FormKind.cook(std::slice::from_ref(&input)).unwrap();
        let two = FormKind.cook(&[input]).unwrap();
        assert_eq!(one, two);
    }
}
