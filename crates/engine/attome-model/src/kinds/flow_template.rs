//! The flow template kind (roadmap M6-T1): a saved, parameterised workflow
//! graph that is instantiated into a draft flow once its parameters are
//! given.
//!
//! ```json
//! { "description_en": "Approve large invoices", "description_ar": "اعتماد الفواتير الكبيرة",
//!   "parameters": [
//!     { "name": "entity", "type": "entity" },
//!     { "name": "amount", "type": "attribute", "of": "entity" },
//!     { "name": "approvers", "type": "users" }
//!   ],
//!   "graph": { "trigger": { "entity": "{{entity}}" },
//!              "nodes": [{ "type": "approval", "approvers": "{{approvers}}",
//!                          "condition": "{{amount}} > 10000" }] } }
//! ```
//!
//! A string that is exactly `{{name}}` is replaced by the argument whatever
//! its JSON type (so a `users` list drops in as a list); `{{name}}` inside a
//! longer string is replaced by the text of a string argument. Every
//! placeholder must name a declared parameter, and [`instantiate`] refuses
//! arguments of the wrong type, missing or unknown ones, and any placeholder
//! left over. The graph it returns is saved as a new flow's draft version,
//! where the workflow engine validates it like any draft before publish.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use attome_types::AppError;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const FLOW_TEMPLATE: KindName = KindName("flow_template");

/// The parameter types: an entity's logical name, an attribute's logical
/// name, one user id, a list of user ids, text, or a number.
pub const PARAMETER_TYPES: [&str; 6] = ["entity", "attribute", "user", "users", "text", "number"];

/// Most parameters one template declares.
const MAX_PARAMETERS: usize = 50;

/// Longest description or label.
const MAX_TEXT_CHARS: usize = 500;

const KEYS: [&str; 4] = ["description_en", "description_ar", "parameters", "graph"];
const PARAMETER_KEYS: [&str; 6] = ["name", "type", "of", "label_en", "label_ar", "default"];

fn placeholder() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\{\{\s*([a-z][a-z0-9_]{0,62})\s*\}\}").unwrap_or_else(|_| unreachable!())
    })
}

fn identifier() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_]{0,62}$").unwrap_or_else(|_| unreachable!()))
}

/// The flow template kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowTemplateKind;

/// Whether `value` is a valid argument of `parameter_type`.
pub fn argument_fits(parameter_type: &str, value: &Value) -> bool {
    let is_user = |v: &Value| v.as_str().is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
    match parameter_type {
        "entity" | "attribute" => value.as_str().is_some_and(|s| identifier().is_match(s)),
        "user" => is_user(value),
        "users" => value
            .as_array()
            .is_some_and(|users| !users.is_empty() && users.iter().all(is_user)),
        "text" => value.is_string(),
        "number" => value.is_number(),
        _ => false,
    }
}

fn scan(text: &str, found: &mut BTreeSet<String>) {
    for capture in placeholder().captures_iter(text) {
        found.insert(capture[1].to_owned());
    }
}

/// Every placeholder name used anywhere in `graph`, keys included.
fn placeholders_in(graph: &Value, found: &mut BTreeSet<String>) {
    match graph {
        Value::String(text) => scan(text, found),
        Value::Array(items) => items.iter().for_each(|item| placeholders_in(item, found)),
        Value::Object(map) => {
            for (key, value) in map {
                scan(key, found);
                placeholders_in(value, found);
            }
        }
        _ => {}
    }
}

fn text_of<'a>(parameter: &'a Map<String, Value>, key: &str) -> &'a str {
    parameter
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The parameter declarations of a shape-valid template.
fn parameters(doc: &Value) -> Vec<&Map<String, Value>> {
    doc.get("parameters")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

/// Replaces the placeholders in `value` with `args`.
fn substitute(value: &Value, args: &Map<String, Value>) -> Value {
    let replace_text = |text: &str| {
        placeholder()
            .replace_all(text, |capture: &regex::Captures<'_>| {
                match args.get(&capture[1]) {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => capture[0].to_owned(),
                }
            })
            .into_owned()
    };
    match value {
        Value::String(text) => {
            if let Some(capture) = placeholder().captures(text)
                && capture[0].len() == text.len()
                && let Some(arg) = args.get(&capture[1])
            {
                return arg.clone();
            }
            Value::String(replace_text(text))
        }
        Value::Array(items) => Value::Array(items.iter().map(|i| substitute(i, args)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (replace_text(key), substitute(value, args)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The draft flow graph `doc` makes with `args`, one argument per parameter
/// (a parameter with a `default` may be left out). Every issue is reported at
/// once, at `/args/<name>` for an argument.
pub fn instantiate(doc: &Value, args: &Map<String, Value>) -> Result<Value, Vec<Issue>> {
    FlowTemplateKind.validate_shape(doc)?;
    let mut issues = Vec::new();
    let mut resolved = Map::new();
    for parameter in parameters(doc) {
        let name = text_of(parameter, "name");
        let parameter_type = text_of(parameter, "type");
        match args.get(name).or_else(|| parameter.get("default")) {
            None => issues.push(Issue::new(
                format!("/args/{name}"),
                "missing",
                format!("the template needs `{name}`"),
            )),
            Some(value) if !argument_fits(parameter_type, value) => issues.push(Issue::new(
                format!("/args/{name}"),
                "invalid",
                format!("`{name}` is not a valid {parameter_type}"),
            )),
            Some(value) => {
                resolved.insert(name.to_owned(), value.clone());
            }
        }
    }
    let declared: BTreeSet<&str> = parameters(doc)
        .into_iter()
        .map(|p| text_of(p, "name"))
        .collect();
    for name in args.keys() {
        if !declared.contains(name.as_str()) {
            issues.push(Issue::new(
                format!("/args/{name}"),
                "unknown_parameter",
                format!("the template has no parameter `{name}`"),
            ));
        }
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    let graph = substitute(&doc["graph"], &resolved);
    let mut left = BTreeSet::new();
    placeholders_in(&graph, &mut left);
    if !left.is_empty() {
        return Err(left
            .into_iter()
            .map(|name| {
                Issue::new(
                    "/graph",
                    "unresolved_placeholder",
                    format!("`{{{{{name}}}}}` is still in the instantiated graph"),
                )
            })
            .collect());
    }
    Ok(graph)
}

impl Kind for FlowTemplateKind {
    fn name(&self) -> KindName {
        FLOW_TEMPLATE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["parameters", "graph"],
            "additionalProperties": false,
            "properties": {
                "description_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "description_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                "parameters": {
                    "type": "array",
                    "maxItems": MAX_PARAMETERS,
                    "items": {
                        "type": "object",
                        "required": ["name", "type"],
                        "additionalProperties": false,
                        "properties": {
                            "name": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,62}$" },
                            "type": { "enum": PARAMETER_TYPES },
                            "of": { "type": "string" },
                            "label_en": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                            "label_ar": { "type": "string", "maxLength": MAX_TEXT_CHARS },
                            "default": {}
                        }
                    }
                },
                "graph": { "type": "object" }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a flow template is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !KEYS.contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a flow template has no `{key}`"),
                ));
            }
        }
        for key in ["description_en", "description_ar"] {
            if doc.get(key).is_some_and(|d| {
                d.as_str()
                    .is_none_or(|d| d.chars().count() > MAX_TEXT_CHARS)
            }) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a description is text of at most 500 characters",
                ));
            }
        }
        if !doc.get("graph").is_some_and(Value::is_object) {
            issues.push(Issue::new(
                "/graph",
                "invalid",
                "graph is the flow's graph, a JSON object",
            ));
        }
        let Some(list) = doc.get("parameters").and_then(Value::as_array) else {
            issues.push(Issue::new("/parameters", "invalid", "parameters is a list"));
            return Err(issues);
        };
        if list.len() > MAX_PARAMETERS {
            issues.push(Issue::new(
                "/parameters",
                "too_many",
                format!("a template has at most {MAX_PARAMETERS} parameters"),
            ));
        }
        let mut names: BTreeSet<&str> = BTreeSet::new();
        let mut types: Vec<(&str, &str)> = Vec::new();
        for (index, parameter) in list.iter().enumerate() {
            let path = format!("/parameters/{index}");
            let Some(parameter) = parameter.as_object() else {
                issues.push(Issue::new(path, "invalid", "a parameter is an object"));
                continue;
            };
            for key in parameter.keys() {
                if !PARAMETER_KEYS.contains(&key.as_str()) {
                    issues.push(Issue::new(
                        format!("{path}/{key}"),
                        "unknown_property",
                        format!("a parameter has no `{key}`"),
                    ));
                }
            }
            let name = parameter
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !identifier().is_match(name) {
                issues.push(Issue::new(
                    format!("{path}/name"),
                    "invalid",
                    "a parameter name is lower case letters, digits and _",
                ));
            } else if !names.insert(name) {
                issues.push(Issue::new(
                    format!("{path}/name"),
                    "duplicate",
                    format!("`{name}` is declared twice"),
                ));
            }
            let parameter_type = parameter
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !PARAMETER_TYPES.contains(&parameter_type) {
                issues.push(Issue::new(
                    format!("{path}/type"),
                    "invalid",
                    "type is entity, attribute, user, users, text or number",
                ));
            }
            if let Some(default) = parameter.get("default")
                && !argument_fits(parameter_type, default)
            {
                issues.push(Issue::new(
                    format!("{path}/default"),
                    "invalid",
                    format!("the default is not a valid {parameter_type}"),
                ));
            }
            for key in ["label_en", "label_ar"] {
                if parameter.get(key).is_some_and(|l| {
                    l.as_str()
                        .is_none_or(|l| l.chars().count() > MAX_TEXT_CHARS)
                }) {
                    issues.push(Issue::new(
                        format!("{path}/{key}"),
                        "invalid",
                        "a label is text of at most 500 characters",
                    ));
                }
            }
            types.push((name, parameter_type));
        }
        // An attribute parameter names the entity parameter it belongs to.
        for (index, parameter) in list.iter().enumerate() {
            let Some(parameter) = parameter.as_object() else {
                continue;
            };
            let parameter_type = parameter.get("type").and_then(Value::as_str);
            match (parameter_type, parameter.get("of")) {
                (Some("attribute"), Some(of)) => {
                    let of = of.as_str().unwrap_or_default();
                    if !types.iter().any(|(n, t)| *n == of && *t == "entity") {
                        issues.push(Issue::new(
                            format!("/parameters/{index}/of"),
                            "invalid",
                            "of names an entity parameter of this template",
                        ));
                    }
                }
                (Some("attribute"), None) => issues.push(Issue::new(
                    format!("/parameters/{index}/of"),
                    "missing",
                    "an attribute parameter names its entity parameter in `of`",
                )),
                (_, Some(_)) => issues.push(Issue::new(
                    format!("/parameters/{index}/of"),
                    "invalid",
                    "only an attribute parameter has `of`",
                )),
                _ => {}
            }
        }
        if let Some(graph) = doc.get("graph") {
            let mut used = BTreeSet::new();
            placeholders_in(graph, &mut used);
            for name in used {
                if !names.contains(name.as_str()) {
                    issues.push(Issue::new(
                        "/graph",
                        "unknown_parameter",
                        format!("the graph uses `{name}`, which is not a parameter"),
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

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        // The entities and attributes are parameters, bound only when the
        // template is instantiated.
        Vec::new()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
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
                    kind: FLOW_TEMPLATE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a reusable flow: a workflow graph with typed parameters (an entity, its attributes, users, text or numbers) written as {{name}} placeholders. Instantiating it with arguments produces a new flow's draft, which is reviewed and published like any flow."
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "test helpers: a failed setup step should panic with its message"
    )]

    use super::*;

    const ALICE: &str = "0190a8a0-0000-7000-8000-000000000001";
    const BOB: &str = "0190a8a0-0000-7000-8000-000000000002";

    fn template() -> Value {
        json!({
            "description_en": "Approve large invoices",
            "parameters": [
                { "name": "entity", "type": "entity", "label_en": "Invoices" },
                { "name": "amount", "type": "attribute", "of": "entity" },
                { "name": "approvers", "type": "users" },
                { "name": "limit", "type": "number", "default": 10000 }
            ],
            "graph": {
                "trigger": { "entity": "{{entity}}", "on": "create" },
                "nodes": [{
                    "type": "approval",
                    "approvers": "{{approvers}}",
                    "condition": "{{amount}} > {{ limit }}",
                    "threshold": "{{limit}}"
                }]
            }
        })
    }

    fn args(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn flow_template_shape_declares_every_placeholder() {
        let kind = FlowTemplateKind;
        assert!(kind.validate_shape(&template()).is_ok());

        let mut undeclared = template();
        undeclared["graph"]["nodes"][0]["note"] = json!("for {{team}}");
        let issues = kind.validate_shape(&undeclared).unwrap_err();
        assert!(
            issues.iter().any(|i| i.code == "unknown_parameter"),
            "{issues:?}"
        );

        let mut duplicate = template();
        duplicate["parameters"][1]["name"] = json!("entity");
        duplicate["parameters"][1]["type"] = json!("entity");
        duplicate["parameters"][1]
            .as_object_mut()
            .unwrap()
            .remove("of");
        let issues = kind.validate_shape(&duplicate).unwrap_err();
        assert!(issues.iter().any(|i| i.code == "duplicate"), "{issues:?}");
    }

    #[test]
    fn flow_template_attribute_parameters_name_their_entity() {
        let kind = FlowTemplateKind;
        let mut orphan = template();
        orphan["parameters"][1]["of"] = json!("approvers");
        assert!(kind.validate_shape(&orphan).is_err());
        let mut missing = template();
        missing["parameters"][1]
            .as_object_mut()
            .unwrap()
            .remove("of");
        assert!(kind.validate_shape(&missing).is_err());
        let mut stray = template();
        stray["parameters"][2]["of"] = json!("entity");
        assert!(kind.validate_shape(&stray).is_err());
        let mut bad_type = template();
        bad_type["parameters"][0]["type"] = json!("colour");
        assert!(kind.validate_shape(&bad_type).is_err());
        let mut bad_default = template();
        bad_default["parameters"][3]["default"] = json!("ten");
        assert!(kind.validate_shape(&bad_default).is_err());
    }

    #[test]
    fn flow_template_instantiates_a_draft_graph() {
        let graph = instantiate(
            &template(),
            &args(json!({
                "entity": "invoice",
                "amount": "total_amount",
                "approvers": [ALICE, BOB]
            })),
        )
        .unwrap();
        assert_eq!(graph["trigger"]["entity"], json!("invoice"));
        assert_eq!(graph["nodes"][0]["approvers"], json!([ALICE, BOB]));
        assert_eq!(
            graph["nodes"][0]["condition"],
            json!("total_amount > 10000"),
            "inside text, placeholders are replaced by the arguments' text"
        );
        assert_eq!(
            graph["nodes"][0]["threshold"],
            json!(10000),
            "a whole-string placeholder keeps the argument's JSON type"
        );
    }

    #[test]
    fn flow_template_refuses_wrong_missing_and_unknown_arguments() {
        let issues = instantiate(
            &template(),
            &args(json!({
                "entity": "Invoice Table",
                "approvers": ["not-a-user"],
                "colour": "red"
            })),
        )
        .unwrap_err();
        let at = |path: &str, code: &str| issues.iter().any(|i| i.path == path && i.code == code);
        assert!(at("/args/entity", "invalid"), "{issues:?}");
        assert!(at("/args/amount", "missing"), "{issues:?}");
        assert!(at("/args/approvers", "invalid"), "{issues:?}");
        assert!(at("/args/colour", "unknown_parameter"), "{issues:?}");
        assert!(
            !issues.iter().any(|i| i.path == "/args/limit"),
            "a parameter with a default may be left out"
        );
    }

    #[test]
    fn flow_template_argument_types() {
        assert!(argument_fits("user", &json!(ALICE)));
        assert!(!argument_fits("users", &json!([])));
        assert!(argument_fits("users", &json!([ALICE])));
        assert!(argument_fits("attribute", &json!("total_amount")));
        assert!(!argument_fits("entity", &json!("drop table")));
        assert!(argument_fits("text", &json!("any text")));
        assert!(!argument_fits("number", &json!("3")));
    }
}
