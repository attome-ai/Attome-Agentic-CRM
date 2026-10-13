//! Regression proof for `attome_docgen::merge`'s security property, referenced
//! by that module's own doc comment (M57 Phase 1, D-463): a merge field
//! naming an attribute the caller cannot see must render as an empty
//! string, never the real value or a masked placeholder that leaks its
//! presence.
//!
//! `MergeContext::data` is exactly what `merge::build_context` produces from
//! `entity_crud::read_record`'s already-permission-filtered
//! `EntityRecordResponse::data()` — a hidden attribute simply has no key in
//! that map (guidelines: the column is never selected, not
//! selected-then-masked). These tests construct that same shape directly
//! (no DB needed — the security projection itself is proven generically by
//! `attome-api`'s own field-security suite; this file proves what
//! `render_template` does with whatever context it is handed, which is the
//! actual code path a hidden field goes through).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_docgen::merge::{MergeContext, referenced_fields, render_template};
use serde_json::json;
use uuid::Uuid;

fn ctx(data: serde_json::Map<String, serde_json::Value>) -> MergeContext {
    MergeContext {
        entity: "test_entity".to_string(),
        record_id: Uuid::now_v7(),
        data,
    }
}

#[test]
fn a_field_absent_from_the_context_renders_as_empty_string() {
    // `salary` is deliberately never inserted — this is exactly the shape a
    // hidden/unauthorized attribute takes once `entity_crud::read_record`
    // has already filtered it out upstream.
    let mut data = serde_json::Map::new();
    data.insert("name".to_string(), json!("Ada Lovelace"));
    let context = ctx(data);

    let out = render_template("Name: {{ name }}, Salary: {{ salary }}", &context)
        .expect("plain substitution never fails");

    assert_eq!(out, "Name: Ada Lovelace, Salary: ");
    assert!(
        !out.contains("salary"),
        "the field name itself must not leak into rendered output either"
    );
}

#[test]
fn an_explicit_null_value_renders_identically_to_an_absent_field() {
    // A caller cannot distinguish "this field is genuinely null" from "this
    // field is hidden from me" by inspecting rendered output — both are
    // empty. Proves the two cases are handled by the same code path.
    let mut data = serde_json::Map::new();
    data.insert("middle_name".to_string(), serde_json::Value::Null);
    let context = ctx(data);

    let out = render_template("[{{ middle_name }}]", &context).unwrap();
    assert_eq!(out, "[]");
}

#[test]
fn a_visible_field_substitutes_its_html_escaped_value() {
    let mut data = serde_json::Map::new();
    data.insert("company".to_string(), json!("Ada & Sons <Ltd>"));
    let context = ctx(data);

    let out = render_template("{{ company }}", &context).unwrap();
    assert_eq!(out, "Ada &amp; Sons &lt;Ltd&gt;");
}

#[test]
fn a_true_conditional_keeps_its_inner_content() {
    let mut data = serde_json::Map::new();
    data.insert("status".to_string(), json!("approved"));
    data.insert("amount".to_string(), json!(500));
    let context = ctx(data);

    let out = render_template(
        "{% if status == \"approved\" %}Approved: {{ amount }}{% endif %}",
        &context,
    )
    .unwrap();
    assert_eq!(out, "Approved: 500");
}

#[test]
fn a_false_conditional_drops_its_inner_content_entirely() {
    let mut data = serde_json::Map::new();
    data.insert("status".to_string(), json!("draft"));
    data.insert("amount".to_string(), json!(500));
    let context = ctx(data);

    let out = render_template(
        "before {% if status == \"approved\" %}Approved: {{ amount }}{% endif %} after",
        &context,
    )
    .unwrap();
    assert_eq!(out, "before  after");
    assert!(
        !out.contains("500"),
        "the hidden branch's merge fields must never be substituted or leak into output"
    );
}

#[test]
fn a_conditional_over_a_hidden_field_fails_closed_rather_than_leaking_the_block() {
    // `is_confidential` is absent (hidden), same as the field-visibility
    // tests above. `rules_context` builds its `attome-rules` schema only from
    // the fields actually present in the merge context, so a conditional
    // naming a field the caller cannot see (or that does not exist) is an
    // "unknown field" compile error, not a silent false — render_template
    // therefore returns Err here rather than substituting anything. Either
    // way the security property holds: the conditional's block can never be
    // included in output the caller cannot otherwise justify, whether by
    // rendering empty or by failing the whole render outright (which is
    // what `render::process` does with this Err — it marks the render
    // `failed` and never uploads a document).
    let data = serde_json::Map::new();
    let context = ctx(data);

    let err = render_template(
        "{% if is_confidential == true %}SECRET{% endif %}",
        &context,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("is_confidential"),
        "error should name the offending field: {err}"
    );
}

#[test]
fn an_unmatched_if_block_is_a_validation_error_not_silent_partial_output() {
    let context = ctx(serde_json::Map::new());
    let err = render_template("{% if true %}unterminated", &context).unwrap_err();
    assert!(
        err.to_string().contains("unmatched"),
        "error should name the actual problem: {err}"
    );
}

#[test]
fn referenced_fields_lists_every_merge_tag_exactly_once() {
    let fields = referenced_fields("{{ name }} - {{ name }} - {{ status }}");
    let mut names: Vec<&str> = fields.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(names, vec!["name", "status"]);
}
