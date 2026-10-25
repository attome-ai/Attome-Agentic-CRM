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
//!
//! A12-T1 adds the full layout, every part optional so a form saved before
//! it reads unchanged:
//!
//! ```json
//! { "entity": "<entity id>",
//!   "form_kind": "main",
//!   "tabs": [ { "label": "General", "sections": [
//!       { "label": "Contact", "columns": 2, "fields": ["<attribute id>"],
//!         "related": [ { "entity": "<entity id>", "label": "Cases" } ],
//!         "components": [ { "component": "<component id>" } ] } ] } ],
//!   "targeting": { "roles": ["<role id>"], "record_types": ["<record type id>"],
//!                  "stages": ["qualify"] } }
//! ```
//!
//! A form has `sections` or `tabs` (each with its sections), not both.
//! `form_kind` is `main` (the default), `quick_create`, `quick_view` or
//! `card`; `targeting` narrows who and which records it is for. A related
//! list reads its entity, a component the `component` object, a record type
//! the `record_type` object. [`default_form`] is the form an entity has when
//! none is published.

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

/// The kinds of form (A12-T1).
pub const FORM_KINDS: [&str; 4] = ["main", "quick_create", "quick_view", "card"];

/// The most columns a section lays its fields out in.
pub const MAX_COLUMNS: u64 = 4;

/// The component kind's name (A12-T1: a section may embed components).
const COMPONENT: KindName = KindName("component");
/// The record type kind's name (A12-T1: targeting by record type).
const RECORD_TYPE: KindName = KindName("record_type");

const TOP_KEYS: [&str; 5] = ["entity", "sections", "tabs", "form_kind", "targeting"];
const SECTION_KEYS: [&str; 5] = ["label", "fields", "columns", "related", "components"];
const TARGETING_KEYS: [&str; 3] = ["roles", "record_types", "stages"];

/// Every section of a form with its JSON pointer: the top-level sections,
/// then each tab's (a valid form has only one of the two).
pub fn sections_of(doc: &Value) -> Vec<(String, &Value)> {
    let top = doc["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, s)| (format!("/sections/{i}"), s));
    let tabbed = doc["tabs"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .flat_map(|(t, tab)| {
            tab["sections"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
                .map(move |(i, s)| (format!("/tabs/{t}/sections/{i}"), s))
        });
    top.chain(tabbed).collect()
}

/// The form an entity has when none is published (A12-T1): one main form
/// with one section holding its attributes in order, up to [`MAX_FIELDS`].
/// Pure; always passes [`FormKind`]'s shape check.
pub fn default_form(entity: Uuid, attributes: &[Uuid]) -> Value {
    let mut seen = std::collections::BTreeSet::new();
    let fields: Vec<String> = attributes
        .iter()
        .filter(|a| seen.insert(**a))
        .take(MAX_FIELDS)
        .map(Uuid::to_string)
        .collect();
    json!({
        "entity": entity.to_string(),
        "form_kind": "main",
        "sections": [{ "label": "General", "fields": fields }],
    })
}

fn check_uuid_list(doc: &Value, path: &str, what: &str, issues: &mut Vec<Issue>) {
    match doc {
        Value::Null => {}
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                if uuid_at(item).is_none() {
                    issues.push(Issue::new(
                        format!("{path}/{i}"),
                        "not_an_id",
                        format!("each of {what} is an id"),
                    ));
                }
            }
        }
        _ => issues.push(Issue::new(path, "not_a_list", format!("{what} is a list"))),
    }
}

fn check_section(section: &Value, path: &str, issues: &mut Vec<Issue>) -> usize {
    if let Some(object) = section.as_object() {
        for key in object.keys() {
            if !SECTION_KEYS.contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("{path}/{key}"),
                    "unknown_property",
                    format!("a section has no `{key}`"),
                ));
            }
        }
    }
    let label_ok = section["label"]
        .as_str()
        .is_some_and(|l| !l.trim().is_empty());
    if !label_ok {
        issues.push(Issue::new(
            format!("{path}/label"),
            "required",
            "a section has a label",
        ));
    }
    if !section["columns"].is_null()
        && !section["columns"]
            .as_u64()
            .is_some_and(|c| (1..=MAX_COLUMNS).contains(&c))
    {
        issues.push(Issue::new(
            format!("{path}/columns"),
            "out_of_range",
            format!("a section has 1 to {MAX_COLUMNS} columns"),
        ));
    }
    match &section["related"] {
        Value::Null => {}
        Value::Array(lists) => {
            for (i, list) in lists.iter().enumerate() {
                if uuid_at(&list["entity"]).is_none() {
                    issues.push(Issue::new(
                        format!("{path}/related/{i}/entity"),
                        "required",
                        "a related list names its entity by id",
                    ));
                }
            }
        }
        _ => issues.push(Issue::new(
            format!("{path}/related"),
            "not_a_list",
            "related lists are a list",
        )),
    }
    match &section["components"] {
        Value::Null => {}
        Value::Array(components) => {
            for (i, component) in components.iter().enumerate() {
                if uuid_at(&component["component"]).is_none() {
                    issues.push(Issue::new(
                        format!("{path}/components/{i}/component"),
                        "required",
                        "an embedded component names its component by id",
                    ));
                }
            }
        }
        _ => issues.push(Issue::new(
            format!("{path}/components"),
            "not_a_list",
            "components are a list",
        )),
    }
    match section["fields"].as_array() {
        None => {
            issues.push(Issue::new(
                format!("{path}/fields"),
                "required",
                "a section has a list of fields",
            ));
            0
        }
        Some(fields) => {
            for (j, field) in fields.iter().enumerate() {
                if uuid_at(field).is_none() {
                    issues.push(Issue::new(
                        format!("{path}/fields/{j}"),
                        "not_an_attribute_id",
                        "a field is an attribute id",
                    ));
                }
            }
            fields.len()
        }
    }
}

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
        let ids = json!({ "type": "array", "items": { "type": "string", "format": "uuid" } });
        let section = json!({
            "type": "object",
            "required": ["label", "fields"],
            "additionalProperties": false,
            "properties": {
                "label": { "type": "string", "minLength": 1 },
                "fields": ids,
                "columns": { "type": "integer", "minimum": 1, "maximum": MAX_COLUMNS },
                "related": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["entity"],
                        "properties": {
                            "entity": { "type": "string", "format": "uuid" },
                            "label": { "type": "string" }
                        }
                    }
                },
                "components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["component"],
                        "properties": {
                            "component": { "type": "string", "format": "uuid" },
                            "props": { "type": "object" }
                        }
                    }
                }
            }
        });
        json!({
            "type": "object",
            "required": ["entity"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "form_kind": { "enum": FORM_KINDS },
                "sections": { "type": "array", "items": section },
                "tabs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["label", "sections"],
                        "additionalProperties": false,
                        "properties": {
                            "label": { "type": "string", "minLength": 1 },
                            "sections": { "type": "array", "items": section }
                        }
                    }
                },
                "targeting": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "roles": ids,
                        "record_types": ids,
                        "stages": { "type": "array", "items": { "type": "string" } }
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
            if !TOP_KEYS.contains(&key.as_str()) {
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
        if !doc["form_kind"].is_null()
            && !doc["form_kind"]
                .as_str()
                .is_some_and(|k| FORM_KINDS.contains(&k))
        {
            issues.push(Issue::new(
                "/form_kind",
                "unknown_value",
                format!("form_kind is one of {}", FORM_KINDS.join(", ")),
            ));
        }
        let has_sections = !doc["sections"].is_null();
        let has_tabs = !doc["tabs"].is_null();
        if has_sections == has_tabs {
            issues.push(Issue::new(
                "/sections",
                "required",
                "a form has a list of sections or a list of tabs, not both",
            ));
        }
        if has_sections && !doc["sections"].is_array() {
            issues.push(Issue::new(
                "/sections",
                "not_a_list",
                "a form has a list of sections",
            ));
        }
        match &doc["tabs"] {
            Value::Null => {}
            Value::Array(tabs) => {
                for (t, tab) in tabs.iter().enumerate() {
                    if !tab["label"].as_str().is_some_and(|l| !l.trim().is_empty()) {
                        issues.push(Issue::new(
                            format!("/tabs/{t}/label"),
                            "required",
                            "a tab has a label",
                        ));
                    }
                    if !tab["sections"].is_array() {
                        issues.push(Issue::new(
                            format!("/tabs/{t}/sections"),
                            "required",
                            "a tab has a list of sections",
                        ));
                    }
                }
            }
            _ => issues.push(Issue::new("/tabs", "not_a_list", "tabs are a list")),
        }
        let mut total = 0usize;
        for (path, section) in sections_of(doc) {
            total += check_section(section, &path, &mut issues);
        }
        if total > MAX_FIELDS {
            issues.push(Issue::new(
                if has_tabs { "/tabs" } else { "/sections" },
                "limit_exceeded",
                format!("the form has {total} fields; the limit is {MAX_FIELDS}"),
            ));
        }
        match &doc["targeting"] {
            Value::Null => {}
            Value::Object(targeting) => {
                for key in targeting.keys() {
                    if !TARGETING_KEYS.contains(&key.as_str()) {
                        issues.push(Issue::new(
                            format!("/targeting/{key}"),
                            "unknown_property",
                            format!("targeting has no `{key}`"),
                        ));
                    }
                }
                check_uuid_list(
                    &doc["targeting"]["roles"],
                    "/targeting/roles",
                    "the roles",
                    &mut issues,
                );
                check_uuid_list(
                    &doc["targeting"]["record_types"],
                    "/targeting/record_types",
                    "the record types",
                    &mut issues,
                );
                match &doc["targeting"]["stages"] {
                    Value::Null => {}
                    Value::Array(stages)
                        if stages
                            .iter()
                            .all(|s| s.as_str().is_some_and(|s| !s.trim().is_empty())) => {}
                    _ => issues.push(Issue::new(
                        "/targeting/stages",
                        "not_a_list",
                        "the stages are a list of stage names",
                    )),
                }
            }
            _ => issues.push(Issue::new(
                "/targeting",
                "not_an_object",
                "targeting is an object",
            )),
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
        let mut push = |kind: KindName, id: Option<Uuid>| {
            if let Some(id) = id {
                refs.push(Reference {
                    target: ObjectRef {
                        kind,
                        id: ObjectId(id),
                    },
                    mode: RefMode::Reads,
                });
            }
        };
        for (_, section) in sections_of(doc) {
            for field in section["fields"].as_array().into_iter().flatten() {
                push(ATTRIBUTE, uuid_at(field));
            }
            for list in section["related"].as_array().into_iter().flatten() {
                push(ENTITY, uuid_at(&list["entity"]));
            }
            for component in section["components"].as_array().into_iter().flatten() {
                push(COMPONENT, uuid_at(&component["component"]));
            }
        }
        for record_type in doc["targeting"]["record_types"]
            .as_array()
            .into_iter()
            .flatten()
        {
            push(RECORD_TYPE, uuid_at(record_type));
        }
        refs
    }

    fn check(&self, doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        // One attribute appears at most once on a form.
        let mut seen = std::collections::BTreeSet::new();
        let mut issues = Vec::new();
        for (path, section) in sections_of(doc) {
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
                        format!("{path}/fields/{j}"),
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
                // Every section, tabbed or not, is listed flat in `sections`
                // (what a renderer without tabs draws); `tabs` keeps the
                // grouping as each tab's label and section count.
                let sections: Vec<Value> = sections_of(&input.doc)
                    .into_iter()
                    .map(|(_, s)| s.clone())
                    .collect();
                let tabs: Vec<Value> = input.doc["tabs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|tab| {
                        json!({
                            "label": tab["label"],
                            "sections": tab["sections"].as_array().map_or(0, Vec::len),
                        })
                    })
                    .collect();
                let mut plan = json!({
                    "id": input.id.to_string(),
                    "name": input.name,
                    "entity": input.doc["entity"],
                    "sections": sections,
                    "form_kind": input.doc["form_kind"].as_str().unwrap_or("main"),
                });
                if !tabs.is_empty() {
                    plan["tabs"] = Value::Array(tabs);
                }
                if !input.doc["targeting"].is_null() {
                    plan["targeting"] = input.doc["targeting"].clone();
                }
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
        "Edit a record form: which entity it shows, its kind (main, quick_create, quick_view, card), its tabs and sections with their columns, attributes, related lists and components, and who and which records it is for."
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
    fn form_kind_tabs_targeting_and_default_form() {
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let entity = Uuid::now_v7();
        let component = Uuid::now_v7();
        let record_type = Uuid::now_v7();
        let doc = json!({
            "entity": entity.to_string(),
            "form_kind": "quick_create",
            "tabs": [
                { "label": "General", "sections": [
                    { "label": "Main", "columns": 2, "fields": [a.to_string()],
                      "related": [{ "entity": entity.to_string(), "label": "Children" }],
                      "components": [{ "component": component.to_string() }] } ] },
                { "label": "More", "sections": [{ "label": "Other", "fields": [b.to_string()] }] }
            ],
            "targeting": { "roles": [Uuid::now_v7().to_string()],
                           "record_types": [record_type.to_string()], "stages": ["qualify"] }
        });
        assert!(
            FormKind.validate_shape(&doc).is_ok(),
            "{:?}",
            FormKind.validate_shape(&doc)
        );
        let kinds: Vec<KindName> = FormKind
            .references(&doc)
            .iter()
            .map(|r| r.target.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![ENTITY, ATTRIBUTE, ENTITY, COMPONENT, ATTRIBUTE, RECORD_TYPE]
        );

        let cooked = FormKind
            .cook(&[CookInput {
                id: ObjectId::new(),
                name: "quick".into(),
                doc: doc.clone(),
            }])
            .unwrap();
        let plan: Value = serde_json::from_slice(&cooked[0].payload).unwrap();
        assert_eq!(
            plan["sections"].as_array().unwrap().len(),
            2,
            "tab sections are listed flat"
        );
        assert_eq!(plan["tabs"][1]["sections"], 1);
        assert_eq!(plan["form_kind"], "quick_create");

        // Both sections and tabs, an unknown kind, bad columns and a bad
        // stage list are each named.
        let mut bad = doc.clone();
        bad["sections"] = json!([]);
        bad["form_kind"] = json!("popup");
        bad["tabs"][0]["sections"][0]["columns"] = json!(9);
        bad["targeting"]["stages"] = json!([1]);
        let issues = FormKind.validate_shape(&bad).unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        for expected in [
            "/sections",
            "/form_kind",
            "/tabs/0/sections/0/columns",
            "/targeting/stages",
        ] {
            assert!(paths.contains(&expected), "{expected} in {paths:?}");
        }

        let default = default_form(entity, &[a, b, a, c]);
        assert!(FormKind.validate_shape(&default).is_ok());
        assert_eq!(
            default["sections"][0]["fields"].as_array().unwrap().len(),
            3
        );
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
