//! The component kind (roadmap T3-T3): the manifest of a custom web
//! component a customer wrote against the component SDK, stored with a
//! reference to its module and validated at publish.
//!
//! ```json
//! { "tag": "acme-credit-gauge",
//!   "module": "acme-credit/gauge.js",
//!   "label_en": "Credit gauge", "label_ar": "مؤشر الائتمان",
//!   "properties": [
//!     { "name": "recordId", "type": "record_id", "bind": "record_id" },
//!     { "name": "limit", "type": "number", "bind": "field_value" },
//!     { "name": "warnAt", "type": "number", "default": 0.8 }
//!   ],
//!   "events": [ { "name": "limit-exceeded", "payload": "number" } ] }
//! ```
//!
//! `tag` is the custom element name the host creates (lower case, with a
//! hyphen, never one HTML reserves). `module` names a file inside a published
//! package (`<package>/<path>.js`), never a URL, so a component is loaded
//! only from what was published (T3-T2). A property is set by the builder (a
//! literal, checked against its type) or bound: the host passes the record's
//! id, the bound field's value, the entity's name, the signed-in user's id or
//! the theme. An event is a name the component dispatches, with the type of
//! its `detail`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use attome_types::AppError;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const COMPONENT: KindName = KindName("component");

/// A property's (or an event payload's) type.
pub const VALUE_TYPES: [&str; 7] = [
    "text",
    "number",
    "boolean",
    "date",
    "record_id",
    "user_id",
    "json",
];

/// What the host binds a property to.
pub const BINDINGS: [&str; 5] = [
    "record_id",
    "field_value",
    "entity_name",
    "user_id",
    "theme",
];

/// Custom element names HTML reserves (they contain a hyphen).
const RESERVED_TAGS: [&str; 8] = [
    "annotation-xml",
    "color-profile",
    "font-face",
    "font-face-src",
    "font-face-uri",
    "font-face-format",
    "font-face-name",
    "missing-glyph",
];

const MAX_PROPERTIES: usize = 50;
const MAX_EVENTS: usize = 20;
const MAX_TEXT_CHARS: usize = 500;

const KEYS: [&str; 6] = [
    "tag",
    "module",
    "label_en",
    "label_ar",
    "properties",
    "events",
];
const PROPERTY_KEYS: [&str; 6] = ["name", "type", "bind", "required", "default", "label_en"];
const EVENT_KEYS: [&str; 2] = ["name", "payload"];

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap_or_else(|_| unreachable!()))
}

fn tag_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"^[a-z][a-z0-9]*(-[a-z0-9]+)+$")
}

fn property_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"^[a-z][A-Za-z0-9]{0,63}$")
}

fn event_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
}

fn module_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(
        &RE,
        r"^[a-z0-9][a-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)+\.m?js$",
    )
}

/// Whether `tag` is a custom element name a component may take.
pub fn valid_tag(tag: &str) -> bool {
    tag.len() <= 100 && tag_pattern().is_match(tag) && !RESERVED_TAGS.contains(&tag)
}

/// Whether `module` names a file inside a published package: a package
/// name, a path, `.js` or `.mjs`; never a URL, an absolute path or `..`.
pub fn valid_module(module: &str) -> bool {
    module.len() <= 300
        && module_pattern().is_match(module)
        && !module
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// Whether `value` is a literal of `value_type`.
pub fn value_fits(value_type: &str, value: &Value) -> bool {
    let uuid = |v: &Value| v.as_str().is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
    match value_type {
        "text" => value.is_string(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "date" => value
            .as_str()
            .is_some_and(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()),
        "record_id" | "user_id" => uuid(value),
        "json" => true,
        _ => false,
    }
}

/// The type a binding hands a property, or `None` when any type will do.
fn bound_type(binding: &str) -> Option<&'static str> {
    match binding {
        "record_id" => Some("record_id"),
        "user_id" => Some("user_id"),
        "entity_name" => Some("text"),
        "theme" => Some("json"),
        _ => None,
    }
}

fn text_of<'a>(object: &'a Map<String, Value>, key: &str) -> &'a str {
    object.get(key).and_then(Value::as_str).unwrap_or_default()
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

fn check_property(
    index: usize,
    value: &Value,
    names: &mut BTreeSet<String>,
    issues: &mut Vec<Issue>,
) {
    let path = format!("/properties/{index}");
    let Some(property) = value.as_object() else {
        issues.push(Issue::new(path, "invalid", "a property is an object"));
        return;
    };
    unknown_keys(property, &PROPERTY_KEYS, &path, "a property", issues);
    let name = text_of(property, "name");
    if !property_pattern().is_match(name) {
        issues.push(Issue::new(
            format!("{path}/name"),
            "invalid",
            "a property name is camelCase letters and digits",
        ));
    } else if !names.insert(name.to_owned()) {
        issues.push(Issue::new(
            format!("{path}/name"),
            "duplicate",
            format!("`{name}` is declared twice"),
        ));
    }
    let value_type = text_of(property, "type");
    if !VALUE_TYPES.contains(&value_type) {
        issues.push(Issue::new(
            format!("{path}/type"),
            "invalid",
            "type is text, number, boolean, date, record_id, user_id or json",
        ));
    }
    if property.get("required").is_some_and(|r| !r.is_boolean()) {
        issues.push(Issue::new(
            format!("{path}/required"),
            "invalid",
            "required is true or false",
        ));
    }
    if property.get("label_en").is_some_and(|l| {
        l.as_str()
            .is_none_or(|l| l.chars().count() > MAX_TEXT_CHARS)
    }) {
        issues.push(Issue::new(
            format!("{path}/label_en"),
            "invalid",
            "a label is text of at most 500 characters",
        ));
    }
    match property.get("bind") {
        Some(bind) => {
            let binding = bind.as_str().unwrap_or_default();
            if !BINDINGS.contains(&binding) {
                issues.push(Issue::new(
                    format!("{path}/bind"),
                    "invalid",
                    "bind is record_id, field_value, entity_name, user_id or theme",
                ));
            } else if let Some(expected) = bound_type(binding)
                && expected != value_type
            {
                issues.push(Issue::new(
                    format!("{path}/type"),
                    "binding_type",
                    format!("a property bound to {binding} has type {expected}"),
                ));
            }
            if property.contains_key("default") {
                issues.push(Issue::new(
                    format!("{path}/default"),
                    "bound_default",
                    "a bound property takes its value from the host and has no default",
                ));
            }
        }
        None => {
            if let Some(default) = property.get("default")
                && VALUE_TYPES.contains(&value_type)
                && !value_fits(value_type, default)
            {
                issues.push(Issue::new(
                    format!("{path}/default"),
                    "invalid",
                    format!("the default is not a valid {value_type}"),
                ));
            }
        }
    }
}

fn check_event(index: usize, value: &Value, names: &mut BTreeSet<String>, issues: &mut Vec<Issue>) {
    let path = format!("/events/{index}");
    let Some(event) = value.as_object() else {
        issues.push(Issue::new(path, "invalid", "an event is an object"));
        return;
    };
    unknown_keys(event, &EVENT_KEYS, &path, "an event", issues);
    let name = text_of(event, "name");
    if name.len() > 64 || !event_pattern().is_match(name) {
        issues.push(Issue::new(
            format!("{path}/name"),
            "invalid",
            "an event name is lower case words joined by hyphens",
        ));
    } else if !names.insert(name.to_owned()) {
        issues.push(Issue::new(
            format!("{path}/name"),
            "duplicate",
            format!("the event `{name}` is declared twice"),
        ));
    }
    if let Some(payload) = event.get("payload")
        && !payload.as_str().is_some_and(|p| VALUE_TYPES.contains(&p))
    {
        issues.push(Issue::new(
            format!("{path}/payload"),
            "invalid",
            "payload is the type of the event's detail",
        ));
    }
}

/// Checks one item of a manifest list, collecting names and issues.
type Check = fn(usize, &Value, &mut BTreeSet<String>, &mut Vec<Issue>);

/// The component kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct ComponentKind;

impl Kind for ComponentKind {
    fn name(&self) -> KindName {
        COMPONENT
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["tag", "module"],
            "additionalProperties": false,
            "properties": {
                "tag": { "type": "string", "pattern": "^[a-z][a-z0-9]*(-[a-z0-9]+)+$" },
                "module": { "type": "string" },
                "label_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "label_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "properties": {
                    "type": "array",
                    "maxItems": MAX_PROPERTIES,
                    "items": {
                        "type": "object",
                        "required": ["name", "type"],
                        "additionalProperties": false,
                        "properties": {
                            "name": { "type": "string" },
                            "type": { "enum": VALUE_TYPES },
                            "bind": { "enum": BINDINGS },
                            "required": { "type": "boolean" },
                            "default": {},
                            "label_en": { "type": "string", "maxLength": MAX_TEXT_CHARS }
                        }
                    }
                },
                "events": {
                    "type": "array",
                    "maxItems": MAX_EVENTS,
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "additionalProperties": false,
                        "properties": {
                            "name": { "type": "string" },
                            "payload": { "enum": VALUE_TYPES }
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
                "a component manifest is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        unknown_keys(object, &KEYS, "", "a component", &mut issues);
        if !valid_tag(text_of(object, "tag")) {
            issues.push(Issue::new(
                "/tag",
                "invalid",
                "tag is a custom element name: lower case, with a hyphen, not one HTML reserves",
            ));
        }
        if !valid_module(text_of(object, "module")) {
            issues.push(Issue::new(
                "/module",
                "invalid",
                "module is a .js file inside a published package (<package>/<path>.js), never a URL",
            ));
        }
        for key in ["label_en", "label_ar"] {
            if object.get(key).is_some_and(|l| {
                l.as_str()
                    .is_none_or(|l| l.chars().count() > MAX_TEXT_CHARS)
            }) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a label is text of at most 500 characters",
                ));
            }
        }
        for (key, max, check) in [
            ("properties", MAX_PROPERTIES, check_property as Check),
            ("events", MAX_EVENTS, check_event as Check),
        ] {
            let Some(value) = object.get(key) else {
                continue;
            };
            let Some(list) = value.as_array() else {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    format!("{key} is a list"),
                ));
                continue;
            };
            if list.len() > max {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "too_many",
                    format!("a component has at most {max} {key}"),
                ));
            }
            let mut names = BTreeSet::new();
            for (index, item) in list.iter().enumerate() {
                check(index, item, &mut names, &mut issues);
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
                let mut manifest = input.doc.clone();
                if let Some(object) = manifest.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text =
                    crate::canonical::canonicalize(&manifest).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: COMPONENT,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Describe a custom web component: its element tag, the published module that defines it, its typed properties (set by the builder, or bound by the host to the record id, a field's value, the entity name, the user or the theme) and the events it dispatches."
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;

    fn manifest() -> Value {
        json!({
            "tag": "acme-credit-gauge",
            "module": "acme-credit/gauge.js",
            "label_en": "Credit gauge",
            "properties": [
                { "name": "recordId", "type": "record_id", "bind": "record_id" },
                { "name": "limit", "type": "number", "bind": "field_value" },
                { "name": "warnAt", "type": "number", "default": 0.8, "required": false }
            ],
            "events": [ { "name": "limit-exceeded", "payload": "number" } ]
        })
    }

    fn codes(doc: &Value) -> Vec<&'static str> {
        ComponentKind
            .validate_shape(doc)
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.code)
            .collect()
    }

    #[test]
    fn component_kind_accepts_a_valid_manifest() {
        assert!(ComponentKind.validate_shape(&manifest()).is_ok());
        assert!(
            ComponentKind
                .validate_shape(&json!({"tag": "x-y", "module": "pkg/a/b.mjs"}))
                .is_ok()
        );
    }

    #[test]
    fn component_kind_checks_tag_and_module() {
        for tag in ["gauge", "Acme-Gauge", "font-face", "acme-", "1a-b"] {
            assert!(!valid_tag(tag), "{tag}");
        }
        assert!(valid_tag("acme-credit-gauge"));
        for module in [
            "https://cdn.example.com/a.js",
            "/abs/a.js",
            "pkg/../other/a.js",
            "pkg/a.css",
            "a.js",
            "pkg/./a.js",
        ] {
            assert!(!valid_module(module), "{module}");
        }
        assert!(valid_module("acme-credit/dist/gauge.js"));
    }

    #[test]
    fn component_kind_checks_property_types_and_bindings() {
        let mut bad_default = manifest();
        bad_default["properties"][2]["default"] = json!("high");
        assert!(codes(&bad_default).contains(&"invalid"));

        let mut bound_default = manifest();
        bound_default["properties"][0]["default"] = json!("0190a8a0-0000-7000-8000-000000000001");
        assert!(codes(&bound_default).contains(&"bound_default"));

        let mut wrong_type = manifest();
        wrong_type["properties"][0]["type"] = json!("text");
        assert!(codes(&wrong_type).contains(&"binding_type"));

        let mut duplicate = manifest();
        duplicate["properties"][1]["name"] = json!("recordId");
        assert!(codes(&duplicate).contains(&"duplicate"));

        let mut unknown = manifest();
        unknown["properties"][1]["onClick"] = json!("alert(1)");
        assert!(codes(&unknown).contains(&"unknown_property"));
    }

    #[test]
    fn component_kind_checks_events() {
        let mut bad = manifest();
        bad["events"][0]["name"] = json!("LimitExceeded");
        assert!(codes(&bad).contains(&"invalid"));
        let mut payload = manifest();
        payload["events"][0]["payload"] = json!("blob");
        assert!(codes(&payload).contains(&"invalid"));
        let mut twice = manifest();
        twice["events"] = json!([{ "name": "changed" }, { "name": "changed" }]);
        assert!(codes(&twice).contains(&"duplicate"));
    }

    #[test]
    fn component_kind_literal_types() {
        assert!(value_fits("date", &json!("2027-01-31")));
        assert!(!value_fits("date", &json!("31/01/2027")));
        assert!(value_fits("json", &json!({"a": [1]})));
        assert!(!value_fits("boolean", &json!("true")));
    }
}
