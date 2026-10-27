//! Z11-T13: the browser's answer is the server's. Twenty fixed expressions go
//! through this crate's JSON entry points (what the WebAssembly build runs)
//! and straight through `attome-rules` (what the server runs), on the same
//! record, and must agree on the value or the error code.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a failed setup step should panic with its message"
)]

use attome_rules::{Budgets, Context, LanguageVersion, Schema, Type, Value};
use chrono::{TimeZone, Utc};
use serde_json::{Value as Json, json};

const EXPRESSIONS: [&str; 20] = [
    "amount > 100",
    "amount * 2 + 1",
    "round(amount / 3, 2)",
    "name",
    "upper(name)",
    "len(name) > 3",
    "contains(name, 'cm')",
    "if(amount > 100, 'large', 'small')",
    "status = 'open'",
    "status = 'open' and amount > 50",
    "not active",
    "active or amount < 0",
    "due_date > now()",
    "coalesce(notes, 'none')",
    "amount / 0",
    "concat(name, ' / ', status)",
    "all(lines, l => l.qty > 0)",
    "count(lines)",
    "any(lines, l => l.qty > 2)",
    "missing_field + 1",
];

fn schema() -> Schema {
    Schema::new()
        .with_field("amount", Type::Number)
        .with_field("name", Type::Text)
        .with_field("notes", Type::Text)
        .with_field("status", Type::Choice)
        .with_field("active", Type::Bool)
        .with_field("due_date", Type::Date)
        .with_related_list("lines", vec![("qty".to_owned(), Type::Number)])
}

fn context() -> Context {
    Context::new(Utc.with_ymd_and_hms(2026, 10, 28, 9, 0, 0).unwrap())
        .with_field("amount", Value::Number(150.0))
        .with_field("name", Value::Text("Acme".into()))
        .with_field("notes", Value::Null)
        .with_field("status", Value::Choice("open".into()))
        .with_field("active", Value::Bool(true))
        .with_field(
            "due_date",
            Value::Date(Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap()),
        )
        .with_related_list(
            "lines",
            vec![
                vec![("qty".to_owned(), Value::Number(1.0))],
                vec![("qty".to_owned(), Value::Number(3.0))],
            ],
        )
}

const SCHEMA_JSON: &str = r#"{
    "fields": {"amount": "number", "name": "text", "notes": "text", "status": "choice",
               "active": "bool", "due_date": "date"},
    "related_lists": {"lines": {"qty": "number"}}
}"#;

const CONTEXT_JSON: &str = r#"{
    "now": "2026-10-28T09:00:00Z",
    "fields": {"amount": 150, "name": "Acme", "notes": null, "status": "open",
               "active": true, "due_date": "2026-12-01"},
    "related_lists": {"lines": [{"qty": 1}, {"qty": 3}]}
}"#;

/// What the server answers: the value as JSON, or the error code.
fn server(src: &str) -> Result<Json, String> {
    let compiled = attome_rules::compile_diagnostic(
        src,
        &schema(),
        LanguageVersion::LATEST,
        Budgets::default(),
    )
    .map_err(|d| d.error.code().to_owned())?;
    let value = compiled.eval(&context()).map_err(|e| e.code().to_owned())?;
    Ok(match value {
        Value::Number(n) => json!(n),
        Value::Bool(b) => json!(b),
        Value::Text(s) | Value::Choice(s) => json!(s),
        Value::Null => Json::Null,
        Value::Date(d) => json!(d.to_rfc3339()),
        other => json!(other.to_string()),
    })
}

/// What the browser answers.
fn browser(src: &str) -> Result<Json, String> {
    let answer = attome_rules_wasm::evaluate_value(src, SCHEMA_JSON, CONTEXT_JSON, "v2");
    if answer["ok"] == json!(true) {
        Ok(answer["value"].clone())
    } else {
        Err(answer["diagnostics"][0]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }
}

#[test]
fn the_browser_answers_as_the_server_does() {
    for src in EXPRESSIONS {
        assert_eq!(browser(src), server(src), "{src}");
    }
    // The set covers values and errors both.
    assert!(EXPRESSIONS.iter().any(|s| server(s).is_err()));
    assert!(EXPRESSIONS.iter().any(|s| server(s).is_ok()));
}

#[test]
fn validate_points_at_the_unknown_field() {
    let answer = attome_rules_wasm::validate_value("amount + missing", SCHEMA_JSON, "v2");
    assert_eq!(answer["ok"], json!(false));
    let d = &answer["diagnostics"][0];
    assert_eq!(d["code"], json!("rules.field.unknown"));
    assert_eq!(
        (d["start"].clone(), d["end"].clone()),
        (json!(9), json!(16))
    );
    let ok = attome_rules_wasm::validate_value("amount > 100", SCHEMA_JSON, "v2");
    assert_eq!(ok["result_type"], json!("bool"));
}

#[test]
fn a_bad_context_is_a_diagnostic_not_a_panic() {
    let answer = attome_rules_wasm::evaluate_value("amount", SCHEMA_JSON, "{}", "v2");
    assert_eq!(
        answer["diagnostics"][0]["code"],
        json!("rules.input.context")
    );
    let answer = attome_rules_wasm::evaluate_value("amount", "not json", CONTEXT_JSON, "v2");
    assert_eq!(
        answer["diagnostics"][0]["code"],
        json!("rules.input.schema")
    );
}
