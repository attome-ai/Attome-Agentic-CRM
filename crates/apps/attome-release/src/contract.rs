//! The contract-diff step (roadmap AC4-T4): compares this commit's
//! `openapi.json` with the one at the previous release tag and fails on a
//! breaking change the changelog does not announce.
//!
//! `/api/v1` is not additive-only (guidelines §12): a breaking change may
//! ship, but only in one change that names it under `### Breaking` in the
//! `[Unreleased]` section of `CHANGELOG.md`. Breaking means:
//! - an operation (method and path) removed;
//! - a response status removed from an operation;
//! - a request-body property newly required;
//! - a property removed from a success response;
//! - a request or success-response property whose `type` changed.
//!
//! Additions (a new path, a new optional property, a new status) are not
//! breaking. Schemas are compared after resolving `$ref`s into
//! `components.schemas`, one level deep, which is how every route here
//! declares its bodies.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// One breaking change, with the path it concerns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Breaking {
    pub method: String,
    pub path: String,
    pub what: String,
}

impl Breaking {
    fn new(method: &str, path: &str, what: impl Into<String>) -> Self {
        Self {
            method: method.to_uppercase(),
            path: path.to_owned(),
            what: what.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({ "method": self.method, "path": self.path, "change": self.what })
    }
}

const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

/// Every operation in a document, keyed by `(method, path)`.
fn operations(doc: &Value) -> BTreeMap<(String, String), &Value> {
    let mut out = BTreeMap::new();
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (path, item) in paths {
            for method in METHODS {
                if let Some(op) = item.get(method) {
                    out.insert((method.to_owned(), path.clone()), op);
                }
            }
        }
    }
    out
}

/// `schema` with a top-level `$ref` into `components.schemas` resolved.
fn resolve<'a>(doc: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => reference
            .strip_prefix("#/components/schemas/")
            .and_then(|name| doc.pointer(&format!("/components/schemas/{name}")))
            .unwrap_or(schema),
        None => schema,
    }
}

/// The JSON body schema of a request or response object, resolved.
fn json_body<'a>(doc: &'a Value, holder: &'a Value) -> Option<&'a Value> {
    holder
        .pointer("/content/application~1json/schema")
        .map(|schema| resolve(doc, schema))
}

fn properties(schema: &Value) -> BTreeMap<&str, &Value> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| props.iter().map(|(k, v)| (k.as_str(), v)).collect())
        .unwrap_or_default()
}

fn required(schema: &Value) -> BTreeSet<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn type_of<'a>(doc: &'a Value, property: &'a Value) -> Option<&'a str> {
    resolve(doc, property).get("type").and_then(Value::as_str)
}

/// The breaking changes from `old` to `new`, sorted.
pub fn breaking_changes(old: &Value, new: &Value) -> Vec<Breaking> {
    let mut out = Vec::new();
    let new_ops = operations(new);
    for ((method, path), old_op) in operations(old) {
        let Some(new_op) = new_ops.get(&(method.clone(), path.clone())) else {
            out.push(Breaking::new(&method, &path, "operation removed"));
            continue;
        };

        // Response statuses, and the success responses' properties.
        if let Some(old_responses) = old_op.get("responses").and_then(Value::as_object) {
            for (status, old_response) in old_responses {
                let Some(new_response) = new_op.pointer(&format!("/responses/{status}")) else {
                    out.push(Breaking::new(
                        &method,
                        &path,
                        format!("response {status} removed"),
                    ));
                    continue;
                };
                if !status.starts_with('2') {
                    continue;
                }
                let (Some(old_body), Some(new_body)) =
                    (json_body(old, old_response), json_body(new, new_response))
                else {
                    continue;
                };
                let new_props = properties(new_body);
                for (name, old_prop) in properties(old_body) {
                    match new_props.get(name) {
                        None => out.push(Breaking::new(
                            &method,
                            &path,
                            format!("response {status} property `{name}` removed"),
                        )),
                        Some(new_prop) => {
                            if let (Some(was), Some(now)) =
                                (type_of(old, old_prop), type_of(new, new_prop))
                                && was != now
                            {
                                out.push(Breaking::new(
                                    &method,
                                    &path,
                                    format!(
                                        "response {status} property `{name}` changed type from {was} to {now}"
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Request body: newly required properties and changed types.
        let old_request = old_op
            .get("requestBody")
            .and_then(|body| json_body(old, body));
        let new_request = new_op
            .get("requestBody")
            .and_then(|body| json_body(new, body));
        if let Some(new_request) = new_request {
            let was_required = old_request.map(required).unwrap_or_default();
            for name in required(new_request) {
                if !was_required.contains(name) {
                    out.push(Breaking::new(
                        &method,
                        &path,
                        format!("request property `{name}` newly required"),
                    ));
                }
            }
            if let Some(old_request) = old_request {
                let new_props = properties(new_request);
                for (name, old_prop) in properties(old_request) {
                    if let Some(new_prop) = new_props.get(name)
                        && let (Some(was), Some(now)) =
                            (type_of(old, old_prop), type_of(new, new_prop))
                        && was != now
                    {
                        out.push(Breaking::new(
                            &method,
                            &path,
                            format!("request property `{name}` changed type from {was} to {now}"),
                        ));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The `### Breaking` part of the `[Unreleased]` section of a changelog, or
/// an empty string.
fn unreleased_breaking(changelog: &str) -> String {
    let mut in_unreleased = false;
    let mut in_breaking = false;
    let mut text = String::new();
    for line in changelog.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            in_unreleased = trimmed.to_ascii_lowercase().contains("[unreleased]");
            in_breaking = false;
            continue;
        }
        if !in_unreleased {
            continue;
        }
        if trimmed.starts_with("### ") {
            in_breaking = trimmed.eq_ignore_ascii_case("### breaking");
            continue;
        }
        if in_breaking {
            text.push_str(line);
            text.push('\n');
        }
    }
    text
}

/// The breaking changes the changelog's `[Unreleased]` → `### Breaking`
/// section does not name (by path).
pub fn unannounced<'a>(changes: &'a [Breaking], changelog: &str) -> Vec<&'a Breaking> {
    let announced = unreleased_breaking(changelog);
    changes
        .iter()
        .filter(|change| !announced.contains(&change.path))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(paths: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "paths": paths,
            "components": { "schemas": {
                "Thing": {
                    "type": "object",
                    "required": ["name"],
                    "properties": { "name": { "type": "string" }, "size": { "type": "integer" } }
                },
                "ThingStrict": {
                    "type": "object",
                    "required": ["name", "size"],
                    "properties": { "name": { "type": "string" }, "size": { "type": "integer" } }
                },
                "ThingSmall": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } }
                }
            } }
        })
    }

    fn body(schema: &str) -> Value {
        json!({ "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{schema}") } } } })
    }

    fn op(request: Option<&str>, ok: &str, statuses: &[&str]) -> Value {
        let mut responses = serde_json::Map::new();
        responses.insert("200".into(), body(ok));
        for status in statuses {
            responses.insert((*status).into(), json!({ "description": "error" }));
        }
        let mut op = json!({ "responses": responses });
        if let Some(request) = request {
            op["requestBody"] = body(request);
        }
        op
    }

    #[test]
    fn removed_operation_is_breaking() {
        let old = doc(json!({ "/api/v1/things": { "get": op(None, "Thing", &[]) } }));
        let new = doc(json!({}));
        let changes = breaking_changes(&old, &new);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "/api/v1/things");
        assert_eq!(changes[0].what, "operation removed");
    }

    #[test]
    fn newly_required_property_is_breaking() {
        let old = doc(json!({ "/api/v1/things": { "post": op(Some("Thing"), "Thing", &[]) } }));
        let new =
            doc(json!({ "/api/v1/things": { "post": op(Some("ThingStrict"), "Thing", &[]) } }));
        let changes = breaking_changes(&old, &new);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(changes[0].what.contains("`size` newly required"));
    }

    #[test]
    fn removed_response_status_is_breaking() {
        let old = doc(json!({ "/api/v1/things": { "get": op(None, "Thing", &["404"]) } }));
        let new = doc(json!({ "/api/v1/things": { "get": op(None, "Thing", &[]) } }));
        let changes = breaking_changes(&old, &new);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].what, "response 404 removed");
    }

    #[test]
    fn removed_response_property_is_breaking() {
        let old = doc(json!({ "/api/v1/things": { "get": op(None, "Thing", &[]) } }));
        let new = doc(json!({ "/api/v1/things": { "get": op(None, "ThingSmall", &[]) } }));
        let changes = breaking_changes(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].what.contains("`size` removed"));
    }

    #[test]
    fn additive_path_is_not_breaking() {
        let old = doc(json!({ "/api/v1/things": { "get": op(None, "Thing", &[]) } }));
        let new = doc(json!({
            "/api/v1/things": { "get": op(None, "Thing", &["404"]) },
            "/api/v1/more": { "get": op(None, "ThingSmall", &[]) }
        }));
        assert!(breaking_changes(&old, &new).is_empty());
    }

    #[test]
    fn breaking_without_changelog_heading_fails() {
        let old = doc(json!({ "/api/v1/things": { "get": op(None, "Thing", &[]) } }));
        let new = doc(json!({}));
        let changes = breaking_changes(&old, &new);
        let silent = "# Changelog\n\n## [Unreleased]\n\n### Added\n- /api/v1/things moved\n";
        assert_eq!(
            unannounced(&changes, silent).len(),
            1,
            "an Added line is not an announcement"
        );
        let announced = "# Changelog\n\n## [Unreleased]\n\n### Breaking\n- `GET /api/v1/things` is removed.\n\n## [0.1.0]\n";
        assert!(unannounced(&changes, announced).is_empty());
        let old_release =
            "# Changelog\n\n## [Unreleased]\n\n## [0.1.0]\n\n### Breaking\n- /api/v1/things\n";
        assert_eq!(
            unannounced(&changes, old_release).len(),
            1,
            "only [Unreleased] counts"
        );
    }
}
