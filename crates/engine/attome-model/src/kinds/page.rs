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
//! A binding is one of a view, a stored query (by id) or a record: the
//! page's own record (`current`, record pages only) or the record a lookup
//! attribute of it points to. An event names when it fires and what it does:
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

/// What starts an event.
pub const TRIGGERS: [&str; 5] = ["load", "click", "select", "submit", "change"];

/// What an event does.
pub const EVENT_ACTIONS: [&str; 3] = ["start_flow", "run_action", "navigate"];

const MAX_NODES: usize = 500;
const MAX_DEPTH: usize = 12;
const MAX_EVENTS: usize = 10;
const MAX_TEXT_CHARS: usize = 500;

const KEYS: [&str; 6] = [
    "page_type",
    "entity",
    "title_en",
    "title_ar",
    "root",
    "description_en",
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
const BINDING_KEYS: [&str; 3] = ["view", "query", "record"];
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
    if binding.len() != 1 {
        walk.issues.push(Issue::new(
            path,
            "one_source",
            "a binding is exactly one of view, query or record",
        ));
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
                "entity": { "type": "string", "format": "uuid" },
                "title_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "title_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "description_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
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
        for key in ["title_en", "title_ar", "description_en"] {
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
