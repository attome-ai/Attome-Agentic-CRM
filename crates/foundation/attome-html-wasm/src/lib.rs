//! Z13-T9: the template renderer for the browser. [`render`] takes the same
//! JSON as `attome-rules-wasm` (a schema and a context, see that crate) and
//! runs the server's `attome_html::tmpl`, so a preview shows what the server
//! will render, without a round trip. `scripts/build-html-wasm.ps1` builds this
//! crate to WebAssembly.
//!
//! The answer is `{"ok": true, "output": "..."}`, or `{"ok": false,
//! "diagnostics": [{code, message, start, end}]}` with the template error's
//! code. There is no clock on wasm32, so the iteration and output limits alone
//! bound a render there.

use attome_html::tmpl::{Output, RenderContext, Template};
use attome_rules_wasm::{failure, parse_context, parse_schema};
use serde_json::{Value as Json, json};
use wasm_bindgen::prelude::wasm_bindgen;

/// Renders `template` against `schema_json` on `context_json`, for `locale`;
/// `output` is `text`, anything else HTML.
#[wasm_bindgen]
#[must_use]
pub fn render(
    template: &str,
    schema_json: &str,
    context_json: &str,
    locale: &str,
    output: &str,
) -> String {
    render_value(template, schema_json, context_json, locale, output).to_string()
}

/// [`render`] as a JSON value.
#[must_use]
pub fn render_value(
    template: &str,
    schema_json: &str,
    context_json: &str,
    locale: &str,
    output: &str,
) -> Json {
    let schema = match parse_schema(schema_json) {
        Ok(schema) => schema,
        Err(message) => return failure("rules.input.schema", &message),
    };
    let values = match parse_context(context_json, &schema) {
        Ok(values) => values,
        Err(message) => return failure("rules.input.context", &message),
    };
    let compiled = match Template::compile(template, &schema.schema) {
        Ok(compiled) => compiled,
        Err(e) => return failure(e.code(), &e.to_string()),
    };
    let kind = if output == "text" {
        Output::Text
    } else {
        Output::Html
    };
    match compiled.render(&RenderContext::new(values, locale, kind)) {
        Ok(output) => json!({ "ok": true, "output": output }),
        Err(e) => failure(e.code(), &e.to_string()),
    }
}
