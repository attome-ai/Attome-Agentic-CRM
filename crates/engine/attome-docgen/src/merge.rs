//! Merge-context builder and template renderer — the security-critical half
//! of this crate.
//!
//! [`build_context`] is the whole security property: it reads the source
//! record through `attome_records::entity_crud::read_record`, the exact same
//! function every other read path (the generic `GET /api/v1/{entity}/{id}`,
//! `attome-ai`'s `record.get`) uses for record-level *and* field-level
//! authorization. `EntityRecordResponse::data()` already excludes any
//! attribute the caller's `SecurityContext` cannot read (`ctx
//! .has_field_read_grant`, applied at the SQL projection in
//! `read_record_projection` — the column is never selected at all, not
//! selected-then-masked). A merge field naming a hidden attribute therefore
//! finds no key in `data()` and renders as an empty string — it can never
//! see the real value, because the real value was never fetched. See
//! `tests/hidden_field_renders_empty.rs` for the regression proof.
//!
//! [`render_template`] is this crate's own small, bounded template
//! language: `{{ field }}` substitution (HTML-escaped) and single-level
//! `{% if expr %}...{% endif %}` conditional sections, where `expr` is a
//! `attome-rules` (M45) boolean expression evaluated against the same
//! permission-filtered context — never a second templating/expression
//! engine (D-463). Nested conditionals are not supported in Phase 1
//! (documented limitation, not a silent truncation: an unmatched `{% if %}`
//! /`{% endif %}` is a validation error, not partial output).

use std::borrow::Cow;
use std::collections::HashMap;

use attome_core::EngineState;
use attome_rules::{Context as RulesContext, Schema, Type, Value as RulesValue, compile};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::Utc;
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use uuid::Uuid;

/// Hard ceiling on how many `{% if %}` blocks one render evaluates —
/// protects the worker from a pathological template (guidelines §10: bounded
/// work, never an unbounded loop on a background thread). Templates are
/// admin-authored, not attacker-authored, but this costs nothing and matches
/// `attome-rules`' own budget-everything posture.
const MAX_CONDITIONAL_BLOCKS: usize = 500;

#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
static IF_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\{%\s*if\s+(.+?)\s*%\}(.*?)\{%\s*endif\s*%\}").expect("static regex")
});

/// Whether a `{{ ... }}` body is a merge field: `[A-Za-z_][A-Za-z0-9_]*`.
/// Anything else between braces is not a merge field and is left verbatim.
fn is_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The record fields a caller may see, already filtered by
/// [`build_context`] — nothing downstream of this struct ever has a chance
/// to leak an unauthorized value, because unauthorized values are never in
/// `data`.
pub struct MergeContext {
    pub entity: String,
    pub record_id: Uuid,
    pub data: serde_json::Map<String, Value>,
}

impl std::fmt::Debug for MergeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergeContext").finish_non_exhaustive()
    }
}

/// Builds the merge context for `entity`/`record_id` under `ctx` — the one
/// place this crate reads record data. `ctx` must already be the resolved
/// `SecurityContext` for the render's `requested_by` user (never the
/// enqueuing caller's own context and never a superuser one), same
/// discipline `attome-report::run::process` documents for its own
/// `resolve_uncached` call.
pub async fn build_context(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record_id: Uuid,
) -> Result<MergeContext, AppError> {
    // D-589: document generation is a bulk surface.
    let record =
        attome_records::entity_crud::read_record_bulk(state, ctx, entity, record_id).await?;
    let mut data = match record.data() {
        Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    // B13-T10: the deployment's brand, for `{{ brand_app_name }}`,
    // `{{ brand_logo_url }}` and `{{ brand_primary }}`. A record field of
    // the same name wins.
    let brand =
        attome_core::theme_store::email_brand(&state.base.db, &state.base.config.frontend_url())
            .await;
    for (key, value) in [
        ("brand_app_name", brand.app_name),
        ("brand_logo_url", brand.logo_url),
        ("brand_primary", brand.primary),
    ] {
        data.entry(key)
            .or_insert_with(|| value.map_or(Value::Null, Value::String));
    }
    Ok(MergeContext {
        entity: entity.to_string(),
        record_id,
        data,
    })
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => {
            if *b {
                "Yes".to_string()
            } else {
                "No".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(display_value)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(_) => String::new(),
    }
}

fn json_to_rules_value(value: &Value) -> RulesValue {
    match value {
        Value::Null => RulesValue::Null,
        Value::Bool(b) => RulesValue::Bool(*b),
        Value::Number(n) => RulesValue::Number(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => RulesValue::Text(s.clone()),
        Value::Array(items) => RulesValue::List(items.iter().map(json_to_rules_value).collect()),
        Value::Object(_) => RulesValue::Null,
    }
}

/// Builds a `attome-rules` `Schema`/`Context` pair off the merge context's
/// current field set. Every field is declared `Type::Null` in the schema —
/// `attome-rules`' own unification rule ("`Null` unifies with anything")
/// means this still type-checks `amount > 100`/`status == "approved"`-shaped
/// expressions without this crate having to know or guess each field's XRM
/// field type.
fn rules_context(ctx: &MergeContext) -> (Schema, RulesContext) {
    let mut schema = Schema::new();
    let mut rc = RulesContext::new(Utc::now());
    for (key, value) in &ctx.data {
        schema = schema.with_field(key.clone(), Type::Null);
        rc = rc.with_field(key.clone(), json_to_rules_value(value));
    }
    (schema, rc)
}

/// Evaluates every `{% if expr %}...{% endif %}` block against `ctx`,
/// keeping the block's inner content (recursively merge-substituted) when
/// `expr` evaluates truthy and dropping it otherwise. Single-level only —
/// see this module's doc comment.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
fn eval_conditionals(body: &str, ctx: &MergeContext) -> Result<String, AppError> {
    if body.matches("{% endif %}").count() != body.matches("{% if ").count() {
        return Err(AppError::Validation(
            "template has an unmatched {% if %}/{% endif %} block".into(),
        ));
    }

    let (schema, rc) = rules_context(ctx);
    let mut text = body.to_string();
    let mut iterations = 0usize;
    while let Some(caps) = IF_BLOCK_RE.captures(&text) {
        iterations += 1;
        if iterations > MAX_CONDITIONAL_BLOCKS {
            return Err(AppError::Validation(format!(
                "template exceeds the {MAX_CONDITIONAL_BLOCKS}-conditional-block limit"
            )));
        }
        let whole = caps.get(0).expect("group 0 always matches").as_str();
        let expr_src = caps.get(1).expect("group 1").as_str();
        let inner = caps.get(2).expect("group 2").as_str();

        let compiled = compile(expr_src, &schema).map_err(|e| {
            AppError::Validation(format!("invalid {{% if %}} expression '{expr_src}': {e}"))
        })?;
        let result = compiled
            .eval(&rc)
            .map_err(|e| AppError::Validation(format!("{{% if %}} evaluation failed: {e}")))?;
        let keep = matches!(result, RulesValue::Bool(true));

        let replacement = if keep { inner } else { "" };
        text = text.replacen(whole, replacement, 1);
    }
    Ok(text)
}

/// Substitutes `{{ field }}` through the platform's one placeholder merge
/// (`attome_html::merge_placeholders`). This caller's unknown-name rule: a
/// well-formed field name that is not in the context renders **empty**; a
/// `{{ ... }}` whose body is not a field name is not a merge field and stays
/// verbatim.
fn substitute_fields(body: &str, ctx: &MergeContext) -> String {
    attome_html::merge_placeholders(body, |field| {
        if !is_field_name(field) {
            return None;
        }
        Some(Cow::Owned(match ctx.data.get(field) {
            // Missing key covers BOTH "field is genuinely null" and "field
            // exists but this caller cannot read it" — see this module's
            // top doc comment. Both render empty, which is the whole
            // point: there is no way, from here, to distinguish the two.
            Some(value) => attome_html::escape_html(&display_value(value)),
            None => String::new(),
        }))
    })
}

/// Renders `body` against `ctx`: conditional sections first, then merge-field
/// substitution over whatever text remains.
pub fn render_template(body: &str, ctx: &MergeContext) -> Result<String, AppError> {
    let with_conditionals = eval_conditionals(body, ctx)?;
    Ok(substitute_fields(&with_conditionals, ctx))
}

/// Which merge field names appear in `body` — used by the admin editor's
/// live preview and by tests; not needed for rendering itself (unresolved
/// fields already default to empty).
pub fn referenced_fields(body: &str) -> HashMap<String, ()> {
    let mut fields = HashMap::new();
    // The same scan `substitute_fields` does, so the two cannot disagree on
    // what counts as a merge field.
    attome_html::merge_placeholders(body, |field| {
        if !is_field_name(field) {
            return None;
        }
        fields.insert(field.to_owned(), ());
        Some(Cow::Borrowed(""))
    });
    fields
}
