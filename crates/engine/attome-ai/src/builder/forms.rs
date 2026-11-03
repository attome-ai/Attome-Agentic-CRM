//! AD2-T1: the building agent's form skill — a drafted form, by field and
//! entity names, turned into a form document (`attome_model::kinds::form`)
//! by ids, checked by the form kind's own shape rules.
//!
//! A name the entity does not have is left out and reported, never guessed.
//! Visibility rules (A11) are proposals beside the form: a rule is its own
//! object, made in the rule editor. Pure.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// One drafted section, by names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftSection {
    pub label: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub columns: Option<u64>,
    /// Related lists: the entities whose records point at this one.
    #[serde(default)]
    pub related: Vec<String>,
}

/// One drafted tab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftTab {
    pub label: String,
    #[serde(default)]
    pub sections: Vec<DraftSection>,
}

/// A visibility rule the draft proposes: show `field` when `when` holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisibilityProposal {
    pub field: String,
    pub when: Value,
}

/// A drafted form, by names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DraftedForm {
    #[serde(default)]
    pub tabs: Vec<DraftTab>,
    #[serde(default)]
    pub visibility: Vec<VisibilityProposal>,
}

/// The form document for `entity`, with names turned into ids, and the names
/// left out because the entity (or the deployment) has no such field or
/// entity. A field placed twice keeps its first place; an empty tab or
/// section is dropped; columns stay within 1 to the kind's limit. Pure.
pub fn form_document(
    entity: Uuid,
    drafted: &DraftedForm,
    fields: &[(String, Uuid)],
    entities: &[(String, Uuid)],
) -> (Value, Vec<String>) {
    let mut unknown = Vec::new();
    let mut placed = std::collections::HashSet::new();
    let mut tabs = Vec::new();
    for tab in &drafted.tabs {
        let mut sections = Vec::new();
        for section in &tab.sections {
            let mut ids = Vec::new();
            for name in &section.fields {
                match fields.iter().find(|(n, _)| n == name) {
                    Some((_, id)) if placed.insert(*id) => ids.push(id.to_string()),
                    Some(_) => {}
                    None => unknown.push(format!("field {name}")),
                }
            }
            let mut related = Vec::new();
            for name in &section.related {
                match entities.iter().find(|(n, _)| n == name) {
                    Some((_, id)) => {
                        related.push(json!({ "entity": id.to_string(), "label": name }))
                    }
                    None => unknown.push(format!("entity {name}")),
                }
            }
            if ids.is_empty() && related.is_empty() {
                continue;
            }
            let mut out = json!({ "label": non_empty(&section.label, "Details"), "fields": ids });
            if let Some(columns) = section.columns {
                out["columns"] = json!(columns.clamp(1, attome_model::kinds::form::MAX_COLUMNS));
            }
            if !related.is_empty() {
                out["related"] = Value::Array(related);
            }
            sections.push(out);
        }
        if !sections.is_empty() {
            tabs.push(json!({ "label": non_empty(&tab.label, "General"), "sections": sections }));
        }
    }
    if tabs.is_empty() {
        tabs.push(
            json!({ "label": "General", "sections": [{ "label": "Details", "fields": [] }] }),
        );
    }
    (
        json!({ "entity": entity.to_string(), "form_kind": "main", "tabs": tabs }),
        unknown,
    )
}

fn non_empty<'a>(text: &'a str, fallback: &'a str) -> &'a str {
    if text.trim().is_empty() {
        fallback
    } else {
        text.trim()
    }
}

/// The visibility proposals that name a field the entity has. Pure.
pub fn known_visibility(
    drafted: &DraftedForm,
    fields: &[(String, Uuid)],
) -> Vec<VisibilityProposal> {
    drafted
        .visibility
        .iter()
        .filter(|v| fields.iter().any(|(n, _)| n == &v.field))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_model::kind::Kind;

    fn section(label: &str, fields: &[&str], related: &[&str]) -> DraftSection {
        DraftSection {
            label: label.into(),
            fields: fields.iter().map(|f| (*f).into()).collect(),
            columns: Some(9),
            related: related.iter().map(|r| (*r).into()).collect(),
        }
    }

    #[test]
    fn names_become_ids_and_unknown_names_are_reported() {
        let entity = Uuid::now_v7();
        let fields = vec![
            ("title".to_owned(), Uuid::now_v7()),
            ("status".to_owned(), Uuid::now_v7()),
        ];
        let entities = vec![("visit".to_owned(), Uuid::now_v7())];
        let drafted = DraftedForm {
            tabs: vec![
                DraftTab {
                    label: "Main".into(),
                    sections: vec![
                        section(
                            "Basics",
                            &["title", "status", "title", "colour"],
                            &["visit", "ghost"],
                        ),
                        section("Empty", &["nothing"], &[]),
                    ],
                },
                DraftTab {
                    label: String::new(),
                    sections: vec![],
                },
            ],
            visibility: vec![
                VisibilityProposal {
                    field: "status".into(),
                    when: json!({ "field": "title", "op": "is_not_null" }),
                },
                VisibilityProposal {
                    field: "colour".into(),
                    when: json!({}),
                },
            ],
        };
        let (doc, unknown) = form_document(entity, &drafted, &fields, &entities);
        assert!(
            attome_model::kinds::FormKind.validate_shape(&doc).is_ok(),
            "{doc}"
        );
        assert_eq!(
            doc["tabs"].as_array().unwrap().len(),
            1,
            "empty tabs dropped"
        );
        let first = &doc["tabs"][0]["sections"][0];
        assert_eq!(
            first["fields"].as_array().unwrap().len(),
            2,
            "each field once"
        );
        assert_eq!(first["columns"], attome_model::kinds::form::MAX_COLUMNS);
        assert_eq!(first["related"][0]["label"], "visit");
        assert_eq!(
            unknown,
            vec!["field colour", "entity ghost", "field nothing"]
        );
        assert_eq!(known_visibility(&drafted, &fields).len(), 1);
    }
}
