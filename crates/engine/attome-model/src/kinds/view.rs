//! The view kind (V2-D1815, before AA4-T8): a published view as a metadata
//! model object, so its definition is versioned, checked and cooked like a
//! form's. The `view` table stays the source the record lists read until
//! reads switch over (expand, then switch, then contract).
//!
//! ```json
//! { "entity": "<entity id>",
//!   "query": "<stored query id>",
//!   "view_kind": "list",
//!   "columns": [ { "attribute": "<attribute id>", "label": "Name", "width": 240 } ],
//!   "is_default": false,
//!   "icon": "las la-table",
//!   "settings": { } }
//! ```
//!
//! `view_kind` is `list` (the default), `kanban`, `calendar`, `timeline` or
//! `chart`, as the `view` table allows; `settings` carries what that kind
//! shows (a kanban's lane field, a chart's measures), as `view_metadata`
//! does today. A view reads its entity, its stored query (the `query`
//! adapter kind, over `sql_query`) and each attribute it shows. Cooking
//! turns a view into its canonical JSON with its id, its name and
//! `column_attributes`, the columns in order: what AA4-T8 builds a view's
//! plan from. The record filter is never part of it.

use std::collections::BTreeSet;

use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::{ATTRIBUTE, ENTITY};

/// The kind's name.
pub const VIEW: KindName = KindName("view");
/// The stored query adapter kind's name (`sql_query`).
pub const QUERY: KindName = KindName("query");

/// The kinds of view the `view` table allows.
pub const VIEW_KINDS: [&str; 5] = ["list", "kanban", "calendar", "timeline", "chart"];

/// Most columns one view shows.
pub const MAX_COLUMNS: usize = 100;
/// Longest column label.
pub const MAX_LABEL_CHARS: usize = 200;
/// Widest column, in pixels.
pub const MAX_WIDTH: u64 = 2000;

/// The view kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct ViewKind;

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

/// The attribute ids a view shows, in column order. Pure.
pub fn column_attributes(doc: &Value) -> Vec<String> {
    doc["columns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["attribute"].as_str().map(str::to_owned))
        .collect()
}

impl Kind for ViewKind {
    fn name(&self) -> KindName {
        VIEW
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "query"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "query": { "type": "string", "format": "uuid" },
                "view_kind": { "type": "string", "enum": VIEW_KINDS },
                "columns": {
                    "type": "array",
                    "maxItems": MAX_COLUMNS,
                    "items": {
                        "type": "object",
                        "required": ["attribute"],
                        "additionalProperties": false,
                        "properties": {
                            "attribute": { "type": "string", "format": "uuid" },
                            "label": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                            "width": { "type": "integer", "minimum": 1, "maximum": MAX_WIDTH }
                        }
                    }
                },
                "is_default": { "type": "boolean" },
                "icon": { "type": "string", "maxLength": 100 },
                "settings": { "type": "object" }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a view is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if ![
                "entity",
                "query",
                "view_kind",
                "columns",
                "is_default",
                "icon",
                "settings",
            ]
            .contains(&key.as_str())
            {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a view has no `{key}`"),
                ));
            }
        }
        for key in ["entity", "query"] {
            if uuid_at(&doc[key]).is_none() {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "required",
                    format!("a view names its {key} by id"),
                ));
            }
        }
        if let Some(kind) = doc.get("view_kind")
            && !kind.as_str().is_some_and(|k| VIEW_KINDS.contains(&k))
        {
            issues.push(Issue::new(
                "/view_kind",
                "invalid",
                format!("a view kind is one of {}", VIEW_KINDS.join(", ")),
            ));
        }
        if let Some(columns) = doc.get("columns") {
            match columns.as_array() {
                None => issues.push(Issue::new("/columns", "invalid", "columns are a list")),
                Some(columns) => {
                    if columns.len() > MAX_COLUMNS {
                        issues.push(Issue::new(
                            "/columns",
                            "too_many",
                            format!("a view shows at most {MAX_COLUMNS} columns"),
                        ));
                    }
                    let mut seen = BTreeSet::new();
                    for (i, column) in columns.iter().enumerate() {
                        let at = |key: &str| format!("/columns/{i}/{key}");
                        if let Some(entry) = column.as_object() {
                            for key in entry.keys() {
                                if !["attribute", "label", "width"].contains(&key.as_str()) {
                                    issues.push(Issue::new(
                                        at(key),
                                        "unknown_property",
                                        format!("a column has no `{key}`"),
                                    ));
                                }
                            }
                        }
                        match uuid_at(&column["attribute"]) {
                            Some(id) if !seen.insert(id) => issues.push(Issue::new(
                                at("attribute"),
                                "duplicate_column",
                                "an attribute is shown once",
                            )),
                            Some(_) => {}
                            None => issues.push(Issue::new(
                                at("attribute"),
                                "required",
                                "a column names its attribute by id",
                            )),
                        }
                        if column.get("label").is_some_and(|l| {
                            l.as_str()
                                .is_none_or(|l| l.chars().count() > MAX_LABEL_CHARS)
                        }) {
                            issues.push(Issue::new(
                                at("label"),
                                "invalid",
                                "a label is text of at most 200 characters",
                            ));
                        }
                        if column
                            .get("width")
                            .is_some_and(|w| w.as_u64().is_none_or(|w| w == 0 || w > MAX_WIDTH))
                        {
                            issues.push(Issue::new(
                                at("width"),
                                "invalid",
                                "a width is 1 to 2000 pixels",
                            ));
                        }
                    }
                }
            }
        }
        if doc.get("is_default").is_some_and(|d| !d.is_boolean()) {
            issues.push(Issue::new(
                "/is_default",
                "invalid",
                "is_default is true or false",
            ));
        }
        if doc
            .get("icon")
            .is_some_and(|i| i.as_str().is_none_or(|i| i.chars().count() > 100))
        {
            issues.push(Issue::new(
                "/icon",
                "invalid",
                "an icon is text of at most 100 characters",
            ));
        }
        if doc.get("settings").is_some_and(|s| !s.is_object()) {
            issues.push(Issue::new("/settings", "invalid", "settings are an object"));
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        let mut refs = Vec::new();
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
        push(ENTITY, uuid_at(&doc["entity"]));
        push(QUERY, uuid_at(&doc["query"]));
        for column in doc["columns"].as_array().into_iter().flatten() {
            push(ATTRIBUTE, uuid_at(&column["attribute"]));
        }
        refs
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut view = input.doc.clone();
                if let Some(object) = view.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                    object.entry("view_kind").or_insert_with(|| json!("list"));
                    object.insert(
                        "column_attributes".into(),
                        json!(column_attributes(&input.doc)),
                    );
                }
                let text = crate::canonical::canonicalize(&view).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: VIEW,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit a view of an entity's records: the stored query it reads, how it shows them (list, kanban, calendar, timeline or chart), its columns in order with labels and widths, and whether it is the entity's default."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> Value {
        json!({
            "entity": Uuid::nil().to_string(),
            "query": Uuid::from_u128(u128::MAX).to_string(),
            "view_kind": "kanban",
            "columns": [
                { "attribute": Uuid::from_u128(1).to_string(), "label": "Name", "width": 240 },
                { "attribute": Uuid::from_u128(2).to_string() }
            ],
            "is_default": true,
            "settings": { "lane": "stage" }
        })
    }

    #[test]
    fn a_view_validates_and_reads_its_entity_query_and_columns() {
        assert!(ViewKind.validate_shape(&view()).is_ok());
        let refs = ViewKind.references(&view());
        let kinds: Vec<&str> = refs.iter().map(|r| r.target.kind.as_str()).collect();
        assert_eq!(kinds, ["entity", "query", "attribute", "attribute"]);
        assert_eq!(
            column_attributes(&view()),
            vec![
                Uuid::from_u128(1).to_string(),
                Uuid::from_u128(2).to_string()
            ]
        );
    }

    #[test]
    fn bad_views_are_named() {
        let doc = json!({
            "entity": "not-an-id",
            "view_kind": "table",
            "columns": [
                { "attribute": Uuid::from_u128(1).to_string(), "width": 0 },
                { "attribute": Uuid::from_u128(1).to_string(), "extra": 1 }
            ],
            "settings": []
        });
        let issues = ViewKind.validate_shape(&doc).unwrap_err();
        let found: Vec<(&str, &str)> = issues.iter().map(|i| (i.path.as_str(), i.code)).collect();
        assert!(found.contains(&("/entity", "required")));
        assert!(found.contains(&("/query", "required")));
        assert!(found.contains(&("/view_kind", "invalid")));
        assert!(found.contains(&("/columns/0/width", "invalid")));
        assert!(found.contains(&("/columns/1/attribute", "duplicate_column")));
        assert!(found.contains(&("/columns/1/extra", "unknown_property")));
        assert!(found.contains(&("/settings", "invalid")));
    }

    #[test]
    fn a_cooked_view_lists_its_columns_and_kind() {
        let artefacts = ViewKind
            .cook(&[CookInput {
                id: ObjectId(Uuid::from_u128(9)),
                name: "Open deals".into(),
                doc: json!({ "entity": Uuid::nil().to_string(), "query": Uuid::from_u128(u128::MAX).to_string(),
                             "columns": [{ "attribute": Uuid::from_u128(1).to_string() }] }),
            }])
            .unwrap();
        let cooked: Value = serde_json::from_slice(&artefacts[0].payload).unwrap();
        assert_eq!(cooked["view_kind"], "list");
        assert_eq!(
            cooked["column_attributes"][0],
            Uuid::from_u128(1).to_string()
        );
        assert_eq!(cooked["name"], "Open deals");
    }
}
