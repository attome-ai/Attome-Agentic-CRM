//! The navigation kind (roadmap A21-T1): an app's menu as metadata.
//!
//! ```json
//! { "groups": [
//!     { "label": "Sales", "items": [
//!         { "label": "Accounts", "kind": "view", "target": "<view id>", "roles": ["<role id>"] },
//!         { "label": "Help", "kind": "url", "url": "https://example.com/help" } ] } ],
//!   "landing": [ { "role": "<role id>", "item": "Sales/Accounts" } ] }
//! ```
//!
//! An item opens a view, form, dashboard, page, report or flow (by id) or a
//! URL. `roles` limits who sees it (empty or absent: everyone who may open
//! the target; visibility never grants access to the target itself).
//! `landing` picks the first screen per role by `<group label>/<item label>`.
//! A form target is a reference, so a menu naming a removed form cannot be
//! published; other targets are checked when their kinds join the model.

use std::collections::BTreeSet;

use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::form::FORM;

/// The kind's name.
pub const NAVIGATION: KindName = KindName("navigation");

/// What an item may open.
pub const ITEM_KINDS: [&str; 7] = ["view", "form", "dashboard", "page", "report", "flow", "url"];
/// Most items in one menu.
pub const MAX_ITEMS: usize = 500;

/// The navigation kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct NavigationKind;

fn label_of(value: &Value) -> Option<&str> {
    value["label"]
        .as_str()
        .map(str::trim)
        .filter(|l| !l.is_empty())
}

fn uuid_of(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|t| Uuid::parse_str(t).ok())
}

impl Kind for NavigationKind {
    fn name(&self) -> KindName {
        NAVIGATION
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["groups"],
            "additionalProperties": false,
            "properties": {
                "groups": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["label", "items"],
                        "properties": {
                            "label": { "type": "string", "minLength": 1 },
                            "items": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["label", "kind"],
                                    "properties": {
                                        "label": { "type": "string", "minLength": 1 },
                                        "kind": { "enum": ITEM_KINDS },
                                        "target": { "type": "string", "format": "uuid" },
                                        "url": { "type": "string" },
                                        "roles": { "type": "array", "items": { "type": "string", "format": "uuid" } },
                                        "badge": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                },
                "landing": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["role", "item"],
                        "properties": {
                            "role": { "type": "string", "format": "uuid" },
                            "item": { "type": "string" }
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
                "a menu is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if key != "groups" && key != "landing" {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a menu has no `{key}`"),
                ));
            }
        }
        let mut paths = BTreeSet::new();
        let mut total = 0usize;
        match doc["groups"].as_array() {
            None => issues.push(Issue::new(
                "/groups",
                "required",
                "a menu has a list of groups",
            )),
            Some(groups) => {
                for (g, group) in groups.iter().enumerate() {
                    let group_label = label_of(group);
                    if group_label.is_none() {
                        issues.push(Issue::new(
                            format!("/groups/{g}/label"),
                            "required",
                            "a group has a label",
                        ));
                    }
                    let Some(items) = group["items"].as_array() else {
                        issues.push(Issue::new(
                            format!("/groups/{g}/items"),
                            "required",
                            "a group has a list of items",
                        ));
                        continue;
                    };
                    total += items.len();
                    for (i, item) in items.iter().enumerate() {
                        let at = format!("/groups/{g}/items/{i}");
                        let Some(label) = label_of(item) else {
                            issues.push(Issue::new(
                                format!("{at}/label"),
                                "required",
                                "an item has a label",
                            ));
                            continue;
                        };
                        if let Some(group_label) = group_label
                            && !paths.insert(format!("{group_label}/{label}"))
                        {
                            issues.push(Issue::new(
                                format!("{at}/label"),
                                "duplicate_item",
                                "this group already has an item with this label",
                            ));
                        }
                        match item["kind"].as_str() {
                            Some("url") => {
                                let ok = item["url"].as_str().is_some_and(|u| {
                                    u.starts_with("https://")
                                        || u.starts_with("http://")
                                        || u.starts_with('/')
                                });
                                if !ok {
                                    issues.push(Issue::new(
                                        format!("{at}/url"),
                                        "invalid",
                                        "a url item has an http(s) or site-relative url",
                                    ));
                                }
                            }
                            Some(kind) if ITEM_KINDS.contains(&kind) => {
                                if uuid_of(&item["target"]).is_none() {
                                    issues.push(Issue::new(
                                        format!("{at}/target"),
                                        "required",
                                        format!("a {kind} item names its target by id"),
                                    ));
                                }
                            }
                            _ => issues.push(Issue::new(
                                format!("{at}/kind"),
                                "invalid",
                                format!("an item opens one of {}", ITEM_KINDS.join(", ")),
                            )),
                        }
                        for (r, role) in item["roles"].as_array().into_iter().flatten().enumerate()
                        {
                            if uuid_of(role).is_none() {
                                issues.push(Issue::new(
                                    format!("{at}/roles/{r}"),
                                    "invalid",
                                    "a role is named by id",
                                ));
                            }
                        }
                    }
                }
            }
        }
        if total > MAX_ITEMS {
            issues.push(Issue::new(
                "/groups",
                "limit_exceeded",
                format!("the menu has {total} items; the limit is {MAX_ITEMS}"),
            ));
        }
        for (l, landing) in doc["landing"].as_array().into_iter().flatten().enumerate() {
            if uuid_of(&landing["role"]).is_none() {
                issues.push(Issue::new(
                    format!("/landing/{l}/role"),
                    "required",
                    "a landing page names its role by id",
                ));
            }
            match landing["item"].as_str() {
                Some(item) if paths.contains(item) => {}
                _ => issues.push(Issue::new(
                    format!("/landing/{l}/item"),
                    "unknown_item",
                    "a landing page is one of this menu's items, as `<group>/<item>`",
                )),
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        doc["groups"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|group| group["items"].as_array().into_iter().flatten())
            .filter(|item| item["kind"] == "form")
            .filter_map(|item| uuid_of(&item["target"]))
            .map(|id| Reference {
                target: ObjectRef {
                    kind: FORM,
                    id: ObjectId(id),
                },
                mode: RefMode::Reads,
            })
            .collect()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut menu = input.doc.clone();
                if let Some(object) = menu.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text = crate::canonical::canonicalize(&menu).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: NAVIGATION,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit an app's menu: groups of items that open views, forms, dashboards, pages, reports, flows or links, who sees each, and each role's landing page."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn menu() -> Value {
        json!({
            "groups": [{ "label": "Sales", "items": [
                { "label": "Accounts", "kind": "form", "target": Uuid::now_v7().to_string() },
                { "label": "Help", "kind": "url", "url": "https://example.com/help" }
            ] }],
            "landing": [{ "role": Uuid::now_v7().to_string(), "item": "Sales/Accounts" }]
        })
    }

    #[test]
    fn a_menu_validates_and_references_its_forms() {
        let doc = menu();
        assert!(NavigationKind.validate_shape(&doc).is_ok());
        let refs = NavigationKind.references(&doc);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target.kind, FORM);
    }

    #[test]
    fn bad_items_and_landings_are_named() {
        let mut doc = menu();
        doc["groups"][0]["items"] = json!([
            { "label": "A", "kind": "view" },
            { "label": "A", "kind": "url", "url": "javascript:alert(1)" },
            { "label": "B", "kind": "spaceship", "target": Uuid::now_v7().to_string() }
        ]);
        doc["landing"] = json!([{ "role": "x", "item": "Nope/Item" }]);
        let issues = NavigationKind.validate_shape(&doc).unwrap_err();
        let found: Vec<(&str, &str)> = issues.iter().map(|i| (i.path.as_str(), i.code)).collect();
        assert!(found.contains(&("/groups/0/items/0/target", "required")));
        assert!(found.contains(&("/groups/0/items/1/label", "duplicate_item")));
        assert!(found.contains(&("/groups/0/items/1/url", "invalid")));
        assert!(found.contains(&("/groups/0/items/2/kind", "invalid")));
        assert!(found.contains(&("/landing/0/role", "required")));
        assert!(found.contains(&("/landing/0/item", "unknown_item")));
    }
}
