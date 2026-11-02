//! Z13-T9: the browser's render is the server's: the same template through
//! this crate's JSON entry point and straight through `attome_html::tmpl`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a failed setup step should panic with its message"
)]

use attome_html::tmpl::{Output, RenderContext, Template};
use attome_html_wasm::render_value;
use attome_rules::{Context, Schema, Type, Value};
use chrono::{TimeZone, Utc};
use serde_json::json;

const TEMPLATE: &str =
    "<h1>{{ name }}</h1>{% if total > 100 %}<p>{{ total | number(2) }}</p>{% else %}small{% end %}";

fn server(output: Output, locale: &str) -> String {
    let schema = Schema::new()
        .with_field("name", Type::Text)
        .with_field("total", Type::Number);
    let now = Utc.with_ymd_and_hms(2026, 11, 2, 9, 0, 0).unwrap();
    let values = Context::new(now)
        .with_field("name", Value::Text("<Acme>".into()))
        .with_field("total", Value::Number(1250.5));
    Template::compile(TEMPLATE, &schema)
        .unwrap()
        .render(&RenderContext::new(values, locale, output))
        .unwrap()
}

fn browser(output: &str, locale: &str) -> serde_json::Value {
    render_value(
        TEMPLATE,
        &json!({ "fields": { "name": "text", "total": "number" } }).to_string(),
        &json!({
            "now": "2026-11-02T09:00:00Z",
            "fields": { "name": "<Acme>", "total": 1250.5 },
        })
        .to_string(),
        locale,
        output,
    )
}

#[test]
fn preview_equals_the_server_render() {
    for locale in ["en", "ar-SA"] {
        assert_eq!(
            browser("html", locale)["output"],
            json!(server(Output::Html, locale))
        );
        assert_eq!(
            browser("text", locale)["output"],
            json!(server(Output::Text, locale))
        );
    }
}

#[test]
fn a_template_error_is_an_answer() {
    let got = render_value(
        "{{ missing }}",
        r#"{"fields": {}}"#,
        r#"{"now": "2026-11-02T09:00:00Z"}"#,
        "en",
        "html",
    );
    assert_eq!(got["ok"], false);
    assert!(got["diagnostics"][0]["code"].is_string());
}
