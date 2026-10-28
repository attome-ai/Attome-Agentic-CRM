//! S2-T3: the house lint over the API document, with a shrink-only baseline.
//!
//! Every operation in `attome::openapi::document()` (the document
//! `attome serve --print-openapi` prints, built without a database or a
//! configuration) is checked against the rules below; each finding is the
//! string `RULE METHOD PATH`. `openapi_lint_baseline.json` lists today's
//! findings: a finding not in it fails (fix the operation, or, for a rule no
//! route can meet yet, add the line), and a baseline line that is no longer
//! a finding fails too, so the list only shrinks.
//!
//! ```text
//! cargo test -p attome --test openapi_lint
//! cargo test -p attome --test openapi_lint -- --ignored write_baseline   # rewrite the baseline
//! ```
//!
//! Rules: `security-declared` (a `security` key), `summary` and
//! `description` (non-empty), `param-description` (every inline parameter
//! has one), `error-shape` (every 4xx/5xx response references
//! `ErrorResponse`), `one-based-page` (a `page` query parameter has
//! `minimum: 1`), `operation-id-unique` (present and unique),
//! `mutating-has-audit` (POST/PUT/PATCH/DELETE carries `x-audit` or
//! `x-audit-exempt`) and `policy-extensions` (`x-risk`, `x-privilege`,
//! `x-rate-class`, `x-idempotent` and `x-cache` all present).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use serde_json::Value;

const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];
const POLICY_EXTENSIONS: &[&str] = &[
    "x-risk",
    "x-privilege",
    "x-rate-class",
    "x-idempotent",
    "x-cache",
];
const ERROR_REF: &str = "#/components/schemas/ErrorResponse";

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/openapi_lint_baseline.json")
}

fn document() -> Value {
    serde_json::to_value(&*attome::openapi::document()).expect("the document serialises")
}

fn non_empty(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

/// Every `(METHOD, path, operation)`.
fn operations(document: &Value) -> Vec<(String, String, &Value)> {
    let mut out = Vec::new();
    let Some(paths) = document["paths"].as_object() else {
        return out;
    };
    for (path, item) in paths {
        for method in METHODS {
            if let Some(op) = item.get(*method)
                && op.get("responses").is_some()
            {
                out.push((method.to_ascii_uppercase(), path.clone(), op));
            }
        }
    }
    out
}

fn inline_params(op: &Value) -> Vec<&Value> {
    op.get("parameters")
        .and_then(Value::as_array)
        .map(|params| {
            params
                .iter()
                .filter(|p| p.is_object() && p.get("$ref").is_none())
                .collect()
        })
        .unwrap_or_default()
}

fn security_declared(op: &Value) -> bool {
    op.get("security").is_some()
}

fn summary(op: &Value) -> bool {
    non_empty(op.get("summary"))
}

fn description(op: &Value) -> bool {
    non_empty(op.get("description"))
}

fn param_description(op: &Value) -> bool {
    inline_params(op)
        .iter()
        .all(|p| non_empty(p.get("description")))
}

fn error_shape(op: &Value) -> bool {
    op["responses"].as_object().is_none_or(|responses| {
        responses
            .iter()
            .filter(|(code, _)| code.starts_with('4') || code.starts_with('5'))
            .all(|(_, response)| response.to_string().contains(ERROR_REF))
    })
}

fn one_based_page(op: &Value) -> bool {
    inline_params(op)
        .iter()
        .filter(|p| {
            p.get("name") == Some(&Value::from("page"))
                && p.get("in") == Some(&Value::from("query"))
        })
        .all(|p| p["schema"]["minimum"].as_f64() == Some(1.0))
}

fn mutating_has_audit(method: &str, op: &Value) -> bool {
    !matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
        || op.get("x-audit").is_some()
        || op.get("x-audit-exempt").is_some()
}

fn policy_extensions(op: &Value) -> bool {
    POLICY_EXTENSIONS.iter().all(|key| op.get(*key).is_some())
}

/// Every finding in `document`, as `RULE METHOD PATH`.
fn findings(document: &Value) -> BTreeSet<String> {
    let ops = operations(document);
    let mut ids: HashMap<&str, usize> = HashMap::new();
    for (_, _, op) in &ops {
        if let Some(id) = op.get("operationId").and_then(Value::as_str) {
            *ids.entry(id).or_default() += 1;
        }
    }
    let mut out = BTreeSet::new();
    for (method, path, op) in &ops {
        let mut add = |rule: &str, ok: bool| {
            if !ok {
                out.insert(format!("{rule} {method} {path}"));
            }
        };
        add("security-declared", security_declared(op));
        add("summary", summary(op));
        add("description", description(op));
        add("param-description", param_description(op));
        add("error-shape", error_shape(op));
        add("one-based-page", one_based_page(op));
        let unique = op
            .get("operationId")
            .and_then(Value::as_str)
            .is_some_and(|id| ids.get(id) == Some(&1));
        add("operation-id-unique", unique);
        add("mutating-has-audit", mutating_has_audit(method, op));
        add("policy-extensions", policy_extensions(op));
    }
    out
}

fn baseline() -> BTreeSet<String> {
    let text = std::fs::read_to_string(baseline_path()).expect("the lint baseline is readable");
    serde_json::from_str::<Vec<String>>(&text)
        .expect("the lint baseline is a JSON array of strings")
        .into_iter()
        .collect()
}

#[test]
fn no_new_lint_findings() {
    let baseline = baseline();
    let new: Vec<String> = findings(&document())
        .into_iter()
        .filter(|f| !baseline.contains(f))
        .collect();
    for finding in &new {
        println!("new lint finding: {finding}");
    }
    assert!(
        new.is_empty(),
        "{} new OpenAPI lint finding(s), listed above: fix the operation (see this file's doc)",
        new.len()
    );
}

#[test]
fn baseline_has_no_fixed_entries() {
    let current = findings(&document());
    let fixed: Vec<String> = baseline()
        .into_iter()
        .filter(|f| !current.contains(f))
        .collect();
    for entry in &fixed {
        println!("fixed, delete from the baseline: {entry}");
    }
    assert!(
        fixed.is_empty(),
        "{} baseline entr(y/ies) no longer found, listed above: delete them so the baseline only shrinks",
        fixed.len()
    );
}

/// S2-T6: every operation has a summary, a description and a description on
/// each inline parameter; none may be added to the baseline again.
#[test]
fn no_description_entries_in_baseline() {
    let open: Vec<String> = baseline()
        .into_iter()
        .filter(|f| {
            f.starts_with("summary ")
                || f.starts_with("description ")
                || f.starts_with("param-description ")
        })
        .collect();
    assert!(
        open.is_empty(),
        "S2-T6 documented every operation: {open:?}"
    );
}

#[test]
fn security_declared_has_no_baseline_entries() {
    let open: Vec<String> = baseline()
        .into_iter()
        .filter(|f| f.starts_with("security-declared "))
        .collect();
    assert!(
        open.is_empty(),
        "S2-T2 declared security on every operation: {open:?}"
    );
}

#[test]
fn rules_flag_what_they_describe() {
    let document = serde_json::json!({ "paths": {
        "/ok": { "get": {
            "summary": "s", "description": "d", "operationId": "ok", "security": [],
            "parameters": [{ "name": "page", "in": "query", "description": "p", "schema": { "minimum": 1 } }],
            "responses": { "404": { "content": { "application/json": { "schema": { "$ref": ERROR_REF } } } } },
            "x-risk": "read", "x-privilege": "x", "x-rate-class": "read", "x-idempotent": true, "x-cache": "private"
        } },
        "/bad": { "post": {
            "operationId": "ok",
            "parameters": [{ "name": "page", "in": "query", "schema": { "minimum": 0 } }],
            "responses": { "500": {} }
        } }
    } });
    let found = findings(&document);
    for rule in [
        "security-declared",
        "summary",
        "description",
        "param-description",
        "error-shape",
        "one-based-page",
        "mutating-has-audit",
        "policy-extensions",
    ] {
        assert!(
            found.contains(&format!("{rule} POST /bad")),
            "{rule}: {found:?}"
        );
        assert!(
            !found.contains(&format!("{rule} GET /ok")),
            "{rule}: {found:?}"
        );
    }
    assert!(
        found.contains("operation-id-unique GET /ok"),
        "a shared id flags both"
    );
    assert!(found.contains("operation-id-unique POST /bad"));
}

/// Rewrites the baseline from today's findings (run with `--ignored`).
#[test]
#[ignore = "rewrites tests/openapi_lint_baseline.json"]
fn write_baseline() {
    let all: Vec<String> = findings(&document()).into_iter().collect();
    let text = serde_json::to_string_pretty(&all).expect("serialises") + "\n";
    std::fs::write(baseline_path(), text).expect("write the baseline");
}

/// S2-T12: the document's top-level `webhooks` describes the delivery a
/// subscription receives: a body schema that exists, the signature header
/// and the retry rules.
#[test]
fn webhooks_section_references_existing_schema() {
    let document = document();
    let post = &document["webhooks"]["entityChanged"]["post"];
    assert!(post.is_object(), "webhooks.entityChanged.post is missing");
    let reference = post["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        .as_str()
        .expect("the body references a schema");
    let name = reference
        .strip_prefix("#/components/schemas/")
        .expect("a components schema reference");
    assert!(
        document["components"]["schemas"][name].is_object(),
        "{reference} is not in components.schemas"
    );
    let parameters = post["parameters"].as_array().expect("header parameters");
    assert!(
        parameters.iter().any(|p| p["in"] == "header"
            && p["name"] == attome_events::crypto::SIGNATURE_HEADER
            && p["description"]
                .as_str()
                .is_some_and(|d| d.contains("HMAC-SHA256"))),
        "the signature header and its algorithm are described"
    );
    let description = post["description"].as_str().unwrap_or_default();
    assert!(description.contains("retried") && description.contains("max_attempts"));
}

/// S2-T13: every step of the published Arazzo workflows
/// (`docs/api/arazzo/*.arazzo.json`) names an operation the API document has,
/// and every workflow has a step.
#[test]
fn arazzo_steps_reference_existing_operations() {
    let document = document();
    let operations: BTreeSet<String> = document["paths"]
        .as_object()
        .into_iter()
        .flat_map(|paths| paths.values())
        .filter_map(Value::as_object)
        .flat_map(|ops| ops.values())
        .filter_map(|op| op["operationId"].as_str().map(str::to_owned))
        .collect();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docs/api/arazzo");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(".arazzo.json"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 3, "three published workflows: {files:?}");
    for file in files {
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let workflows = doc["workflows"].as_array().expect("workflows");
        assert!(!workflows.is_empty(), "{}", file.display());
        for workflow in workflows {
            let steps = workflow["steps"].as_array().expect("steps");
            assert!(
                !steps.is_empty(),
                "{} has an empty workflow",
                file.display()
            );
            for step in steps {
                let id = step["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{}: a step names no operationId", file.display()));
                assert!(
                    operations.contains(id),
                    "{}: step {} names {id}, which the API document does not have",
                    file.display(),
                    step["stepId"]
                );
            }
        }
    }
}

/// S2-T9: every operation names the licence module whose gate it sits
/// behind, as a key of `attome_modules::MODULE_MAP`, so the document can be
/// split and filtered by licence.
#[test]
fn every_operation_has_x_module() {
    let document = document();
    let modules: BTreeSet<&str> = attome_modules::MODULE_MAP
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let mut missing = Vec::new();
    let mut unknown = Vec::new();
    for (path, item) in document["paths"].as_object().expect("paths") {
        for (method, operation) in item.as_object().expect("path item") {
            if !operation.is_object() || operation.get("responses").is_none() {
                continue;
            }
            match operation["x-module"].as_str() {
                None => missing.push(format!("{} {path}", method.to_uppercase())),
                Some(module) if !modules.contains(module) => {
                    unknown.push(format!("{} {path}: {module}", method.to_uppercase()));
                }
                Some(_) => {}
            }
        }
    }
    assert!(
        missing.is_empty(),
        "operations without x-module (tag the fragment with attome_server::openapi::tag_module): {missing:?}"
    );
    assert!(
        unknown.is_empty(),
        "x-module is not a MODULE_MAP key: {unknown:?}"
    );
}
