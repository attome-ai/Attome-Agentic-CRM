//! The page kind (roadmap T2-T1): a tree of components for an app home, a
//! workspace, a custom page, a record page or a portal page, each component
//! with its props, the data it is bound to and what its events do.
//!
//! ```json
//! { "page_type": "record", "entity": "<entity id>",
//!   "title_en": "Account", "title_ar": "الحساب",
//!   "root": { "id": "main", "type": "container", "children": [
//!     { "id": "contacts", "type": "list",
//!       "binding": { "view": "<view id>" },
//!       "events": [ { "on": "select", "do": "navigate", "target": "/xrm/contact/{id}" } ] },
//!     { "id": "gauge", "type": "custom", "component": "<component id>",
//!       "binding": { "record": "current" } } ] } }
//! ```
//!
//! A binding is one of a view, a stored query (by id), an entity (by
//! logical name, its records as the default list shows them) or a record:
//! the page's own record (`current`, record pages only) or the record a
//! lookup attribute of it points to. On a record page a view or entity
//! binding may add `related_by`, a lookup field of the listed entity that
//! must name the page's record, and an entity binding `where`, up to ten
//! `{ field, op: eq | in, value }` conditions (D1-T2), so a page lists an
//! account's contacts or its open opportunities. A record page with
//! `"default": true` is its entity's record page. An event names when it fires and what it does:
//! start a flow, run an action, or navigate to an app path (never a URL, so
//! a page cannot send someone off the deployment). The entity, the lookup
//! attributes and custom components are references, checked at save and
//! publish; views, queries, flows and actions are checked by id shape here
//! and resolved by the runtime (T2-T2), which shows a missing one as empty.

use std::collections::BTreeSet;

use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::component::COMPONENT;
use crate::kinds::form::{ATTRIBUTE, ENTITY};

/// The kind's name.
pub const PAGE: KindName = KindName("page");

/// Where a page is used.
pub const PAGE_TYPES: [&str; 5] = ["app_home", "workspace", "custom", "record", "portal"];

/// The component palette.
pub const NODE_TYPES: [&str; 12] = [
    "container",
    "tabs",
    "text",
    "list",
    "form",
    "chart",
    "kanban",
    "map",
    "timeline",
    "metric",
    "button",
    "custom",
];

/// T2-T4: who a page is for.
pub const AUDIENCES: [&str; 3] = ["public", "portal", "internal"];

/// What starts an event.
pub const TRIGGERS: [&str; 5] = ["load", "click", "select", "submit", "change"];

/// What an event does.
pub const EVENT_ACTIONS: [&str; 3] = ["start_flow", "run_action", "navigate"];

const MAX_NODES: usize = 500;
const MAX_DEPTH: usize = 12;
const MAX_EVENTS: usize = 10;
const MAX_TEXT_CHARS: usize = 500;

const KEYS: [&str; 10] = [
    "page_type",
    // D1-T2: this record page is its entity's record page.
    "default",
    "entity",
    "title_en",
    "title_ar",
    "root",
    "description_en",
    // T2-T4: who the page is for, and its search-engine title and summary.
    "audience",
    "seo_title",
    "seo_description",
];
const NODE_KEYS: [&str; 7] = [
    "id",
    "type",
    "props",
    "binding",
    "events",
    "children",
    "component",
];
const BINDING_KEYS: [&str; 6] = ["view", "query", "record", "entity", "related_by", "where"];
/// The keys of a binding that name where its rows come from.
const SOURCE_KEYS: [&str; 4] = ["view", "query", "record", "entity"];
/// D1-T2: the most conditions an entity binding's `where` holds.
const MAX_WHERE: usize = 10;

/// A logical name (an entity's or a field's): lowercase letters, digits and
/// `_`, starting with a letter, at most 64 characters.
fn is_logical_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
const EVENT_KEYS: [&str; 3] = ["on", "do", "target"];

/// The page kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageKind;

fn uuid_at(value: Option<&Value>) -> Option<Uuid> {
    value
        .and_then(Value::as_str)
        .and_then(|text| Uuid::parse_str(text).ok())
}

fn is_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Whether `target` is an app path a navigate event may go to: it starts
/// with one `/`, has no scheme, no `\` and no `..` segment.
pub fn is_app_path(target: &str) -> bool {
    target.starts_with('/')
        && !target.starts_with("//")
        && target.len() <= 500
        && !target.contains('\\')
        && !target.contains(':')
        && !target.split('/').any(|s| s == "..")
        && !target.chars().any(char::is_control)
}

fn is_action_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

struct Walk<'a> {
    page_type: &'a str,
    ids: BTreeSet<String>,
    nodes: usize,
    issues: Vec<Issue>,
}

fn unknown_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
    what: &str,
    walk: &mut Walk<'_>,
) {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            walk.issues.push(Issue::new(
                format!("{path}/{key}"),
                "unknown_property",
                format!("{what} has no `{key}`"),
            ));
        }
    }
}

fn check_binding(binding: &Value, path: &str, walk: &mut Walk<'_>) {
    let Some(binding) = binding.as_object() else {
        walk.issues
            .push(Issue::new(path, "invalid", "a binding is an object"));
        return;
    };
    unknown_keys(binding, &BINDING_KEYS, path, "a binding", walk);
    let sources = SOURCE_KEYS
        .iter()
        .filter(|key| binding.contains_key(**key))
        .count();
    if sources != 1 {
        walk.issues.push(Issue::new(
            path,
            "one_source",
            "a binding is exactly one of view, query, entity or record",
        ));
    }
    if let Some(entity) = binding.get("entity")
        && !entity.as_str().is_some_and(is_logical_name)
    {
        walk.issues.push(Issue::new(
            format!("{path}/entity"),
            "invalid",
            "an entity binding names the entity by logical name",
        ));
    }
    if let Some(related) = binding.get("related_by") {
        if !related.as_str().is_some_and(is_logical_name) {
            walk.issues.push(Issue::new(
                format!("{path}/related_by"),
                "invalid",
                "related_by names a lookup field by logical name",
            ));
        }
        if walk.page_type != "record" {
            walk.issues.push(Issue::new(
                format!("{path}/related_by"),
                "no_record",
                "only a record page has a record to relate to",
            ));
        }
        if !binding.contains_key("view") && !binding.contains_key("entity") {
            walk.issues.push(Issue::new(
                format!("{path}/related_by"),
                "invalid",
                "related_by narrows a view or entity binding",
            ));
        }
    }
    if let Some(conditions) = binding.get("where") {
        check_where(
            conditions,
            &format!("{path}/where"),
            binding.contains_key("entity"),
            walk,
        );
    }
    for key in ["view", "query"] {
        if binding.contains_key(key) && uuid_at(binding.get(key)).is_none() {
            walk.issues.push(Issue::new(
                format!("{path}/{key}"),
                "invalid",
                format!("a {key} binding names the {key} by id"),
            ));
        }
    }
    if let Some(record) = binding.get("record") {
        match record.as_str() {
            Some("current") if walk.page_type != "record" => walk.issues.push(Issue::new(
                format!("{path}/record"),
                "no_record",
                "only a record page has a current record",
            )),
            Some("current") => {}
            _ if uuid_at(Some(record)).is_some() && walk.page_type == "record" => {}
            _ => walk.issues.push(Issue::new(
                format!("{path}/record"),
                "invalid",
                "record is `current` or a lookup attribute of the page's record, by id",
            )),
        }
    }
}

fn check_where(conditions: &Value, path: &str, on_entity: bool, walk: &mut Walk<'_>) {
    if !on_entity {
        walk.issues.push(Issue::new(
            path,
            "invalid",
            "where narrows an entity binding",
        ));
    }
    let Some(conditions) = conditions.as_array() else {
        walk.issues
            .push(Issue::new(path, "invalid", "where is a list of conditions"));
        return;
    };
    if conditions.len() > MAX_WHERE {
        walk.issues.push(Issue::new(
            path,
            "too_many",
            format!("where holds at most {MAX_WHERE} conditions"),
        ));
    }
    for (index, condition) in conditions.iter().enumerate() {
        let at = format!("{path}/{index}");
        let field = condition.get("field").and_then(Value::as_str);
        let op = condition.get("op").and_then(Value::as_str);
        let value = condition.get("value");
        let value_ok = match op {
            Some("eq") => value.is_some_and(|v| v.is_string() || v.is_number() || v.is_boolean()),
            Some("in") => value.and_then(Value::as_array).is_some_and(|items| {
                !items.is_empty() && items.len() <= 50 && items.iter().all(Value::is_string)
            }),
            _ => false,
        };
        let keys_ok = condition.as_object().is_some_and(|c| {
            c.keys()
                .all(|k| ["field", "op", "value"].contains(&k.as_str()))
        });
        if !keys_ok || !field.is_some_and(is_logical_name) || !value_ok {
            walk.issues.push(Issue::new(
                at,
                "invalid",
                "a condition is { field, op: eq | in, value }, an in value a list of text",
            ));
        }
    }
}

fn check_event(index: usize, event: &Value, path: &str, walk: &mut Walk<'_>) {
    let path = format!("{path}/events/{index}");
    let Some(event) = event.as_object() else {
        walk.issues
            .push(Issue::new(path, "invalid", "an event is an object"));
        return;
    };
    unknown_keys(event, &EVENT_KEYS, &path, "an event", walk);
    if !event
        .get("on")
        .and_then(Value::as_str)
        .is_some_and(|on| TRIGGERS.contains(&on))
    {
        walk.issues.push(Issue::new(
            format!("{path}/on"),
            "invalid",
            "on is load, click, select, submit or change",
        ));
    }
    let target = event.get("target");
    let target_ok = match event.get("do").and_then(Value::as_str) {
        Some("start_flow") => uuid_at(target).is_some(),
        Some("run_action") => target.and_then(Value::as_str).is_some_and(is_action_id),
        Some("navigate") => target.and_then(Value::as_str).is_some_and(is_app_path),
        _ => {
            walk.issues.push(Issue::new(
                format!("{path}/do"),
                "invalid",
                "do is start_flow, run_action or navigate",
            ));
            return;
        }
    };
    if !target_ok {
        walk.issues.push(Issue::new(
            format!("{path}/target"),
            "invalid",
            "the target is a flow id, an action id, or an app path starting with /",
        ));
    }
}

fn check_node(node: &Value, path: &str, depth: usize, walk: &mut Walk<'_>) {
    walk.nodes += 1;
    if walk.nodes == MAX_NODES + 1 {
        walk.issues.push(Issue::new(
            path,
            "too_many",
            format!("a page has at most {MAX_NODES} components"),
        ));
    }
    if depth > MAX_DEPTH {
        walk.issues.push(Issue::new(
            path,
            "too_deep",
            format!("components nest at most {MAX_DEPTH} levels"),
        ));
        return;
    }
    let Some(node) = node.as_object() else {
        walk.issues
            .push(Issue::new(path, "invalid", "a component is an object"));
        return;
    };
    unknown_keys(node, &NODE_KEYS, path, "a component", walk);
    let id = node.get("id").and_then(Value::as_str).unwrap_or_default();
    if !is_node_id(id) {
        walk.issues.push(Issue::new(
            format!("{path}/id"),
            "invalid",
            "a component id is lower case letters, digits, _ and -",
        ));
    } else if !walk.ids.insert(id.to_owned()) {
        walk.issues.push(Issue::new(
            format!("{path}/id"),
            "duplicate",
            format!("the component id `{id}` is used twice"),
        ));
    }
    let node_type = node.get("type").and_then(Value::as_str).unwrap_or_default();
    if !NODE_TYPES.contains(&node_type) {
        walk.issues.push(Issue::new(
            format!("{path}/type"),
            "invalid",
            "type is a component from the palette",
        ));
    }
    match (node_type, node.get("component")) {
        ("custom", Some(component)) if uuid_at(Some(component)).is_some() => {}
        ("custom", _) => walk.issues.push(Issue::new(
            format!("{path}/component"),
            "missing",
            "a custom component names its component manifest by id",
        )),
        (_, Some(_)) => walk.issues.push(Issue::new(
            format!("{path}/component"),
            "invalid",
            "only a custom component names a component manifest",
        )),
        _ => {}
    }
    if node.get("props").is_some_and(|p| !p.is_object()) {
        walk.issues.push(Issue::new(
            format!("{path}/props"),
            "invalid",
            "props is an object",
        ));
    }
    if let Some(binding) = node.get("binding") {
        check_binding(binding, &format!("{path}/binding"), walk);
    }
    if let Some(events) = node.get("events") {
        match events.as_array() {
            Some(events) if events.len() <= MAX_EVENTS => {
                for (index, event) in events.iter().enumerate() {
                    check_event(index, event, path, walk);
                }
            }
            _ => walk.issues.push(Issue::new(
                format!("{path}/events"),
                "invalid",
                format!("events is a list of at most {MAX_EVENTS}"),
            )),
        }
    }
    if let Some(children) = node.get("children") {
        match children.as_array() {
            Some(children) => {
                for (index, child) in children.iter().enumerate() {
                    check_node(child, &format!("{path}/children/{index}"), depth + 1, walk);
                }
            }
            None => walk.issues.push(Issue::new(
                format!("{path}/children"),
                "invalid",
                "children is a list",
            )),
        }
    }
}

/// Every node of the tree, depth first, bounded by [`MAX_DEPTH`].
fn nodes(root: &Value) -> Vec<&Map<String, Value>> {
    fn walk<'a>(node: &'a Value, depth: usize, out: &mut Vec<&'a Map<String, Value>>) {
        let Some(object) = node.as_object() else {
            return;
        };
        out.push(object);
        if depth >= MAX_DEPTH {
            return;
        }
        for child in object
            .get("children")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(child, depth + 1, out);
        }
    }
    let mut out = Vec::new();
    walk(root, 0, &mut out);
    out
}

impl Kind for PageKind {
    fn name(&self) -> KindName {
        PAGE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["page_type", "root"],
            "additionalProperties": false,
            "properties": {
                "page_type": { "enum": PAGE_TYPES },
                "default": { "type": "boolean" },
                "entity": { "type": "string", "format": "uuid" },
                "title_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "title_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "description_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "audience": { "enum": AUDIENCES },
                "seo_title": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "seo_description": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "root": { "$ref": "#/$defs/node" }
            },
            "$defs": {
                "node": {
                    "type": "object",
                    "required": ["id", "type"],
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string", "pattern": "^[a-z0-9_-]{1,64}$" },
                        "type": { "enum": NODE_TYPES },
                        "component": { "type": "string", "format": "uuid" },
                        "props": { "type": "object" },
                        "binding": { "type": "object" },
                        "events": {
                            "type": "array",
                            "maxItems": MAX_EVENTS,
                            "items": {
                                "type": "object",
                                "required": ["on", "do", "target"],
                                "properties": {
                                    "on": { "enum": TRIGGERS },
                                    "do": { "enum": EVENT_ACTIONS },
                                    "target": { "type": "string" }
                                }
                            }
                        },
                        "children": { "type": "array", "items": { "$ref": "#/$defs/node" } }
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
                "a page is a JSON object",
            )]);
        };
        let page_type = object
            .get("page_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut walk = Walk {
            page_type,
            ids: BTreeSet::new(),
            nodes: 0,
            issues: Vec::new(),
        };
        unknown_keys(object, &KEYS, "", "a page", &mut walk);
        if !PAGE_TYPES.contains(&page_type) {
            walk.issues.push(Issue::new(
                "/page_type",
                "invalid",
                "page_type is app_home, workspace, custom, record or portal",
            ));
        }
        match (page_type, object.get("entity")) {
            ("record", entity) if uuid_at(entity).is_none() => walk.issues.push(Issue::new(
                "/entity",
                "missing",
                "a record page names its entity by id",
            )),
            ("record", _) | (_, None) => {}
            (_, Some(_)) => walk.issues.push(Issue::new(
                "/entity",
                "invalid",
                "only a record page names an entity",
            )),
        }
        match object.get("default") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) if page_type == "record" => {}
            Some(Value::Bool(true)) => walk.issues.push(Issue::new(
                "/default",
                "invalid",
                "only a record page is an entity's default page",
            )),
            Some(_) => walk.issues.push(Issue::new(
                "/default",
                "invalid",
                "default is true or false",
            )),
        }
        if object
            .get("audience")
            .is_some_and(|a| a.as_str().is_none_or(|a| !AUDIENCES.contains(&a)))
        {
            walk.issues.push(Issue::new(
                "/audience",
                "invalid",
                "audience is public, portal or internal",
            ));
        }
        for key in [
            "title_en",
            "title_ar",
            "description_en",
            "seo_title",
            "seo_description",
        ] {
            if object.get(key).is_some_and(|t| {
                t.as_str()
                    .is_none_or(|t| t.chars().count() > MAX_TEXT_CHARS)
            }) {
                walk.issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a title is text of at most 500 characters",
                ));
            }
        }
        match object.get("root") {
            Some(root) => check_node(root, "/root", 0, &mut walk),
            None => walk.issues.push(Issue::new(
                "/root",
                "missing",
                "a page has a root component",
            )),
        }
        if walk.issues.is_empty() {
            Ok(())
        } else {
            Err(walk.issues)
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
                mode: RefMode::Reads,
            });
        }
        let Some(root) = doc.get("root") else {
            return refs;
        };
        for node in nodes(root) {
            if let Some(component) = uuid_at(node.get("component")) {
                refs.push(Reference {
                    target: ObjectRef {
                        kind: COMPONENT,
                        id: ObjectId(component),
                    },
                    mode: RefMode::Reads,
                });
            }
            if let Some(lookup) = uuid_at(node.get("binding").and_then(|b| b.get("record"))) {
                refs.push(Reference {
                    target: ObjectRef {
                        kind: ATTRIBUTE,
                        id: ObjectId(lookup),
                    },
                    mode: RefMode::Reads,
                });
            }
        }
        refs
    }

    fn check(&self, doc: &Value, ctx: &dyn ValidationCtx) -> Vec<Issue> {
        let mut issues = Vec::new();
        let Some(root) = doc.get("root") else {
            return issues;
        };
        for node in nodes(root) {
            let Some(lookup) = uuid_at(node.get("binding").and_then(|b| b.get("record"))) else {
                continue;
            };
            if let Some(field_type) = ctx.attribute_type(&ObjectRef {
                kind: ATTRIBUTE,
                id: ObjectId(lookup),
            }) && field_type != "lookup"
            {
                issues.push(Issue::new(
                    format!(
                        "/root/{}",
                        node.get("id").and_then(Value::as_str).unwrap_or_default()
                    ),
                    "not_a_lookup",
                    "a record binding follows a lookup attribute of the page's record",
                ));
            }
        }
        issues
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut page = input.doc.clone();
                if let Some(object) = page.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text = crate::canonical::canonicalize(&page).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: PAGE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Lay out a page (an app home, a workspace, a custom, record or portal page) as a tree of components from the palette, each bound to a view, a stored query or a record, with events that start a flow, run an action or navigate inside the app."
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;

    const ENTITY_ID: &str = "0190a8a0-0000-7000-8000-0000000000e1";
    const VIEW: &str = "0190a8a0-0000-7000-8000-0000000000f1";
    const FLOW: &str = "0190a8a0-0000-7000-8000-0000000000f2";
    const LOOKUP: &str = "0190a8a0-0000-7000-8000-0000000000a1";
    const GAUGE: &str = "0190a8a0-0000-7000-8000-0000000000c1";

    fn page() -> Value {
        json!({
            "page_type": "record",
            "entity": ENTITY_ID,
            "title_en": "Account",
            "root": {
                "id": "main",
                "type": "container",
                "children": [
                    {
                        "id": "contacts",
                        "type": "list",
                        "binding": { "view": VIEW },
                        "events": [{ "on": "select", "do": "navigate", "target": "/xrm/contact/{id}" }]
                    },
                    {
                        "id": "renew",
                        "type": "button",
                        "props": { "label_en": "Renew" },
                        "binding": { "record": "current" },
                        "events": [{ "on": "click", "do": "start_flow", "target": FLOW }]
                    },
                    {
                        "id": "parent",
                        "type": "custom",
                        "component": GAUGE,
                        "binding": { "record": LOOKUP }
                    }
                ]
            }
        })
    }

    fn codes(doc: &Value) -> Vec<&'static str> {
        PageKind
            .validate_shape(doc)
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.code)
            .collect()
    }

    #[test]
    fn page_kind_accepts_a_bound_tree() {
        assert_eq!(codes(&page()), Vec::<&str>::new());
        let refs = PageKind.references(&page());
        assert_eq!(refs.len(), 3, "the entity, the component and the lookup");
    }

    #[test]
    fn page_kind_checks_bindings() {
        let mut two = page();
        two["root"]["children"][0]["binding"]["query"] = json!(VIEW);
        assert!(codes(&two).contains(&"one_source"));
        let mut home = page();
        home["page_type"] = json!("app_home");
        home.as_object_mut().unwrap().remove("entity");
        assert!(codes(&home).contains(&"no_record"), "{:?}", codes(&home));
        let mut bad_view = page();
        bad_view["root"]["children"][0]["binding"]["view"] = json!("my view");
        assert!(codes(&bad_view).contains(&"invalid"));
    }

    /// D1-T2: an entity binding narrowed to the page's record and by
    /// conditions, and the default record page.
    #[test]
    fn page_kind_takes_related_lists() {
        let mut related = page();
        related["default"] = json!(true);
        related["root"]["children"][0]["binding"] = json!({
            "entity": "opportunity",
            "related_by": "account_ref",
            "where": [{ "field": "stage", "op": "in", "value": ["proposal", "negotiation"] }]
        });
        assert_eq!(codes(&related), Vec::<&str>::new());

        let mut bad = related.clone();
        bad["root"]["children"][0]["binding"]["where"] =
            json!([{ "field": "stage", "op": "like", "value": "x" }]);
        assert!(codes(&bad).contains(&"invalid"));
        let mut bad = related.clone();
        bad["root"]["children"][0]["binding"]["entity"] = json!("Opportunity; drop");
        assert!(codes(&bad).contains(&"invalid"));
        let mut on_query = page();
        on_query["root"]["children"][0]["binding"] =
            json!({ "query": VIEW, "related_by": "account_ref" });
        assert!(codes(&on_query).contains(&"invalid"));

        let mut home = related.clone();
        home["page_type"] = json!("app_home");
        home.as_object_mut().unwrap().remove("entity");
        let home_codes = codes(&home);
        assert!(home_codes.contains(&"no_record"), "{home_codes:?}");
        assert!(home_codes.contains(&"invalid"), "only a record page is a default");
    }

    #[test]
    fn page_kind_checks_events() {
        for target in [
            "https://evil.example",
            "//evil.example",
            "/a/../../b",
            "javascript:alert(1)",
        ] {
            let mut bad = page();
            bad["root"]["children"][0]["events"][0]["target"] = json!(target);
            assert!(codes(&bad).contains(&"invalid"), "{target}");
        }
        let mut flow = page();
        flow["root"]["children"][1]["events"][0]["target"] = json!("not-a-flow");
        assert!(codes(&flow).contains(&"invalid"));
        let mut action = page();
        action["root"]["children"][1]["events"][0] =
            json!({ "on": "click", "do": "run_action", "target": "record.assign" });
        assert!(codes(&action).is_empty());
    }

    #[test]
    fn page_kind_checks_the_tree() {
        let mut duplicate = page();
        duplicate["root"]["children"][1]["id"] = json!("contacts");
        assert!(codes(&duplicate).contains(&"duplicate"));
        let mut custom = page();
        custom["root"]["children"][2]
            .as_object_mut()
            .unwrap()
            .remove("component");
        assert!(codes(&custom).contains(&"missing"));
        let mut deep = json!({ "id": "n0", "type": "container" });
        for i in 1..=14 {
            deep = json!({ "id": format!("n{i}"), "type": "container", "children": [deep] });
        }
        let doc = json!({ "page_type": "custom", "root": deep });
        assert!(codes(&doc).contains(&"too_deep"));
        let mut record_without_entity = page();
        record_without_entity
            .as_object_mut()
            .unwrap()
            .remove("entity");
        assert!(codes(&record_without_entity).contains(&"missing"));
    }

    #[test]
    fn page_kind_record_binding_follows_a_lookup() {
        struct Typed;
        impl ValidationCtx for Typed {
            fn exists(&self, _target: &ObjectRef) -> bool {
                true
            }
            fn attribute_type(&self, _attribute: &ObjectRef) -> Option<String> {
                Some("text".to_owned())
            }
        }
        let issues = PageKind.check(&page(), &Typed);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "not_a_lookup");
    }
}
