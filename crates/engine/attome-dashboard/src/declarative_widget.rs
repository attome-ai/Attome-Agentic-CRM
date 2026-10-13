//! M67 Phase 1 — `declarative_widget`: a JSON-schema-driven widget type that
//! covers most "custom widget" requests with **zero customer code
//! execution** (`document/xrm/module/M67-component-platform/master-plan.md`
//! Step 1 — Step 2's sandboxed-component model is explicitly out of scope
//! and needs its own decision entry before design).
//!
//! A widget's `config` (`dashboard_widget.config`, plain `text` — see
//! `seed.rs`'s doc comment) references a stored query by id (`query_ref`,
//! same "client-owned reference, unvalidated existence, checked again at
//! execution time" convention `dashboard_widget.query_id`/`group_id`
//! already use — see this file's [`validate_config`] doc) and declares how
//! to render that query's result set: which columns, how each is formatted,
//! which rows get a conditional color, which cells link out, and which
//! platform-registered actions (`attome-ai`'s closed registry, invariant
//! I-2) a viewer may invoke.
//!
//! ## Why this shape and not "a config blob nobody checks"
//!
//! Every other widget's `config` is deliberately unvalidated at write time
//! (`widget_registry.rs`'s own doc comment: "this platform has no
//! JSON-schema-validation dependency"). `declarative_widget` is the one type
//! where that posture is not good enough — its whole reason to exist is to
//! be the *safe* alternative to Step 2's customer code, and "safe" has to be
//! demonstrated, not asserted. [`validate_config`] is a real, hand-rolled,
//! unit-tested structural validator (deny-unknown-fields, bounded array/
//! string sizes, closed enums, a scheme allow-list on every link, a hex-only
//! allow-list on every color) — not a generic JSON-schema library dependency
//! (none exists in this workspace and adding one for a single widget type
//! would be a needless new dependency for a shape this small to hand-check).
//!
//! ## What this does NOT validate, and why that is still safe
//!
//! `query_ref` and every `actions[]` entry are checked for **shape** only
//! (a well-formed UUID; a well-formed `"{domain}.{verb}"` action id) — never
//! for **existence**. This matches the established convention for every
//! other client-owned reference on this entity (`query_id`/`group_id`, see
//! `seed.rs`'s widget doc comment: "unvalidated at write time... still runs
//! under its own security at execution time regardless of what this column
//! claims"). `query_exec.rs` now lives in `attome-records` (D-477), which
//! this crate already depends on for other writes (see `layout.rs`), so
//! resolving `query_ref` here is no longer structurally blocked — it stays
//! unvalidated at write time by the same deliberate convention every other
//! client-owned reference on this entity uses, not because the crate cannot
//! reach it. `attome-ai`'s registry is still out of reach: it sits above
//! `attome-api`, which depends on both `attome-dashboard` and (since M98)
//! `attome-ai` for real, so `attome-dashboard -> attome-ai` would still close
//! a cycle through `attome-api` (see `decision.rs`'s doc comment for the
//! identical reasoning). So this crate cannot resolve that one reference.
//! That is not a gap: a `query_ref` naming a query the viewer may not run
//! still gets rejected by
//! `query_exec.rs`'s own privilege/RLS checks when the widget actually
//! fetches data, and an `actions[]` entry naming an unknown or unlicensed
//! action still resolves to nothing (`ActionRegistry::resolve`) when a
//! viewer tries to invoke it — the real enforcement point for both was
//! always downstream of this widget's config, never this validator.
//!
//! ## The security property this module does NOT own
//!
//! Schema validation proves the *shape* of a config is sane. It does
//! nothing about what a malicious *string value* inside an otherwise
//! well-shaped config (a label, a format pattern, an unresolved link
//! target) does once rendered — that guarantee belongs to the Angular
//! renderer (`angular/projects/xrm/dashboard`), which must never interpret
//! any config string as HTML/script. See that component's spec file for the
//! injection proof; this module's own tests only prove malformed *shapes*
//! are rejected (including some that are shape-invalid *because* they are
//! injection attempts, e.g. a `javascript:` link scheme — a second,
//! independent layer, not a substitute for the renderer's own discipline).
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Hard ceilings — a config this large would render a widget nobody could
/// use anyway, and bounding it keeps [`validate_config`] itself O(small).
const MAX_COLUMNS: usize = 50;
const MAX_ACTIONS: usize = 20;
const MAX_CONDITIONAL_COLORS_PER_COLUMN: usize = 10;
const MAX_LABEL_LEN: usize = 200;
const MAX_FIELD_LEN: usize = 128;
const MAX_LINK_LEN: usize = 2000;
const MAX_PATTERN_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclarativeWidgetConfig {
    /// A `sql_query` id (UUID string) — same client-owned-reference
    /// convention as `dashboard_widget.query_id` (see this module's doc
    /// comment). Shape-checked here (must parse as a UUID); existence and
    /// the viewer's privilege to run it are re-checked at execution time by
    /// `query_exec.rs` (`attome-records`, D-477) — deliberately left
    /// unvalidated here at write time, per this module's doc comment.
    pub query_ref: String,
    #[serde(default)]
    pub columns: Vec<ColumnSpec>,
    /// `attome-ai` action ids (`"{domain}.{verb}"`) this widget may offer as
    /// row/toolbar buttons. Shape-checked only — see this module's doc
    /// comment for why resolving them against the live registry happens at
    /// invocation time, not here.
    #[serde(default)]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ColumnSpec {
    /// The query result column this display column reads. Same identifier
    /// shape as `attribute_info.logicalname`.
    pub field: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_ar: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ColumnFormat>,
    #[serde(default)]
    pub conditional_colors: Vec<ConditionalColor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<LinkSpec>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ColumnFormat {
    Text,
    Number {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decimals: Option<u8>,
    },
    Date {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
    },
    Currency {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        currency_code: Option<String>,
    },
    Badge,
}

/// A single (condition -> color) rule, evaluated top-to-bottom by the
/// renderer; the first match wins. Deliberately a **structured** predicate
/// (field/operator/value), never a free-form expression string to
/// parse/eval — the same "declarative JSON, not a mini-language" boundary
/// this whole widget type exists to hold (see this module's doc comment).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalColor {
    pub when: Condition,
    /// `#RGB`/`#RRGGBB`/`#RRGGBBAA` only — see [`validate_hex_color`]. No CSS
    /// function syntax, no named colors: a smaller allow-list than the
    /// renderer's sanitizing `[style.*]` binding would already require, kept
    /// here too as an independent, defense-in-depth check.
    pub color: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    pub operator: ConditionOperator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    IsEmpty,
    IsNotEmpty,
}

impl ConditionOperator {
    fn requires_value(self) -> bool {
        !matches!(self, Self::IsEmpty | Self::IsNotEmpty)
    }
}

/// A cell can link out two ways: to an admin-chosen external URL template
/// (scheme allow-listed — see [`validate_link_target`]), or to an
/// `attome-ai` action id, resolved and re-authorized at invocation time
/// (see this module's doc comment) rather than here. Deliberately no
/// "internal record" kind that would bake a route shape into this crate —
/// the host application composes that from `entity`/`id` columns already
/// present in the query result, same as any other list.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LinkSpec {
    /// `target` may contain `{field}` placeholders the renderer substitutes
    /// from the row — substitution happens at render time (as text, into an
    /// Angular `[href]`/`[routerLink]` binding, never `[innerHTML]`), not here.
    External {
        target: String,
    },
    Action {
        action_id: String,
    },
}

// ── Validation ───────────────────────────────────────────────────────────

/// Validates a widget's raw JSON `config` against `declarative_widget`'s
/// schema, returning the typed, validated config or a list of actionable
/// field errors (guidelines §6: identify actionable client input). Called
/// by [`validate_config_route`] — see this module's doc comment for what is
/// and is not covered.
pub fn validate_config(raw: &serde_json::Value) -> Result<DeclarativeWidgetConfig, Vec<String>> {
    let config: DeclarativeWidgetConfig = serde_json::from_value(raw.clone()).map_err(|e| {
        vec![format!(
            "config does not match the declarative_widget schema: {e}"
        )]
    })?;

    let mut errors = Vec::new();

    if uuid::Uuid::parse_str(&config.query_ref).is_err() {
        errors.push("query_ref must be a valid UUID naming a stored query".to_string());
    }

    if config.columns.is_empty() {
        errors.push("columns must declare at least one column".to_string());
    }
    if config.columns.len() > MAX_COLUMNS {
        errors.push(format!("columns must not exceed {MAX_COLUMNS} entries"));
    }
    for (i, column) in config.columns.iter().enumerate() {
        validate_column(i, column, &mut errors);
    }

    if config.actions.len() > MAX_ACTIONS {
        errors.push(format!("actions must not exceed {MAX_ACTIONS} entries"));
    }
    for (i, action_id) in config.actions.iter().enumerate() {
        if !is_valid_action_id(action_id) {
            errors.push(format!(
                "actions[{i}] ({action_id:?}) must look like \"domain.verb\" (lowercase snake_case each side)"
            ));
        }
    }

    if errors.is_empty() {
        Ok(config)
    } else {
        Err(errors)
    }
}

fn validate_column(index: usize, column: &ColumnSpec, errors: &mut Vec<String>) {
    let prefix = format!("columns[{index}]");
    if column.field.is_empty()
        || column.field.len() > MAX_FIELD_LEN
        || !is_safe_identifier(&column.field)
    {
        errors.push(format!(
            "{prefix}.field must be a non-empty identifier up to {MAX_FIELD_LEN} chars"
        ));
    }
    if column.label.is_empty() || column.label.chars().count() > MAX_LABEL_LEN {
        errors.push(format!(
            "{prefix}.label must be 1-{MAX_LABEL_LEN} characters"
        ));
    }
    if let Some(label_ar) = &column.label_ar
        && label_ar.chars().count() > MAX_LABEL_LEN
    {
        errors.push(format!(
            "{prefix}.label_ar must be at most {MAX_LABEL_LEN} characters"
        ));
    }
    if let Some(format) = &column.format {
        validate_format(&prefix, format, errors);
    }
    if column.conditional_colors.len() > MAX_CONDITIONAL_COLORS_PER_COLUMN {
        errors.push(format!(
            "{prefix}.conditional_colors must not exceed {MAX_CONDITIONAL_COLORS_PER_COLUMN} entries"
        ));
    }
    for (j, rule) in column.conditional_colors.iter().enumerate() {
        validate_conditional_color(&format!("{prefix}.conditional_colors[{j}]"), rule, errors);
    }
    if let Some(link) = &column.link {
        validate_link(&prefix, link, errors);
    }
}

fn validate_format(prefix: &str, format: &ColumnFormat, errors: &mut Vec<String>) {
    match format {
        ColumnFormat::Text | ColumnFormat::Badge | ColumnFormat::Number { .. } => {}
        ColumnFormat::Date { pattern } => {
            if let Some(pattern) = pattern
                && (pattern.is_empty()
                    || pattern.len() > MAX_PATTERN_LEN
                    || !pattern.chars().all(|c| {
                        c.is_ascii_alphabetic() || c.is_ascii_whitespace() || "-/,:.".contains(c)
                    }))
            {
                errors.push(format!(
                    "{prefix}.format.pattern must be a short date-format token string"
                ));
            }
        }
        ColumnFormat::Currency { currency_code } => {
            if let Some(code) = currency_code
                && (code.len() != 3 || !code.chars().all(|c| c.is_ascii_uppercase()))
            {
                errors.push(format!(
                    "{prefix}.format.currency_code must be a 3-letter uppercase ISO code"
                ));
            }
        }
    }
}

fn validate_conditional_color(prefix: &str, rule: &ConditionalColor, errors: &mut Vec<String>) {
    if rule.when.field.is_empty()
        || rule.when.field.len() > MAX_FIELD_LEN
        || !is_safe_identifier(&rule.when.field)
    {
        errors.push(format!("{prefix}.when.field must be a valid identifier"));
    }
    if rule.when.operator.requires_value() && rule.when.value.is_none() {
        errors.push(format!(
            "{prefix}.when.value is required for operator {:?}",
            rule.when.operator
        ));
    }
    if !validate_hex_color(&rule.color) {
        errors.push(format!(
            "{prefix}.color must be #RGB, #RRGGBB, or #RRGGBBAA hex"
        ));
    }
}

fn validate_link(prefix: &str, link: &LinkSpec, errors: &mut Vec<String>) {
    match link {
        LinkSpec::External { target } => {
            if !validate_link_target(target) {
                errors.push(format!(
                    "{prefix}.link.target must be an http(s) URL or a site-relative path, at most {MAX_LINK_LEN} chars, with no javascript:/data:/vbscript: scheme"
                ));
            }
        }
        LinkSpec::Action { action_id } => {
            if !is_valid_action_id(action_id) {
                errors.push(format!(
                    "{prefix}.link.action_id must look like \"domain.verb\""
                ));
            }
        }
    }
}

/// A query-result column identifier: this platform's own attribute
/// logicalname shape (`^[a-z][a-z0-9_]*$`), matching
/// `attribute_info.logicalname` convention elsewhere in this
/// workspace. The shared `attome_db::ident` validator (CLEANUP-REVIEW 3.4);
/// no length cap here (`is_valid_action_id` caps the whole id).
fn is_safe_identifier(value: &str) -> bool {
    attome_db::ident::is_logical_name(value)
}

/// `"{domain}.{verb}"`, each side lowercase snake_case — matches
/// `attome-ai`'s own `ActionId` convention (`descriptor.rs`: `"record.get"`,
/// `"query.execute"`).
fn is_valid_action_id(value: &str) -> bool {
    let Some((domain, verb)) = value.split_once('.') else {
        return false;
    };
    !domain.is_empty()
        && !verb.is_empty()
        && value.len() <= MAX_FIELD_LEN
        && is_safe_identifier(domain)
        && is_safe_identifier(verb)
        && !verb.contains('.')
}

/// `#RGB` / `#RRGGBB` / `#RRGGBBAA` only — deliberately rejects CSS function
/// syntax (`expr(...)`, `url(...)`), named colors, and anything with a `;`
/// or whitespace that could widen a `style` attribute if a future renderer
/// ever concatenated this into a `style` string instead of using Angular's
/// sanitizing `[style.*]` property binding (which this platform's renderer
/// uses — see the Angular component's spec).
fn validate_hex_color(value: &str) -> bool {
    let hex = match value.strip_prefix('#') {
        Some(hex) => hex,
        None => return false,
    };
    matches!(hex.len(), 3 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// `http://`/`https://` absolute, or a site-relative path starting with `/`
/// (never `//`, which a browser resolves as protocol-relative to an
/// attacker-controlled host). Rejects `javascript:`, `data:`, `vbscript:`,
/// `file:`, and any other scheme — independent of whatever sanitization the
/// Angular renderer's `[href]` binding also applies.
fn validate_link_target(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_LINK_LEN {
        return false;
    }
    if value.chars().any(|c| c.is_control()) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return true;
    }
    if value.starts_with('/') && !value.starts_with("//") {
        return true;
    }
    false
}

// ── HTTP surface ─────────────────────────────────────────────────────────

use attome_core::EngineState;
use attome_types::ErrorResponse;
use axum::{Json, Router, http::StatusCode, routing::post};

use attome_server::authz::{Authorized, Privilege};

use crate::auth::WidgetUpdate;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateConfigBody {
    /// The raw `dashboard_widget.config` payload a client is about to save.
    pub config: serde_json::Value,
    /// The widget type the config is for. Omitted means `declarative_widget`,
    /// this route's original contract. For any other type the route checks
    /// that the type is renderable and validates `config.data` (a structured
    /// definition) and `config.bindings` (dashboard 10/10 Phase 2.1).
    #[serde(default)]
    pub widget_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// `POST /api/v1/attome-dashboard/widget/validate-config` — the "reject
/// malformed configs at write time, not render time" surface for
/// `declarative_widget` (see this module's doc comment). Generic entity CRUD
/// has no per-field business-validation hook (`widget_registry.rs`'s doc
/// comment: `config` is an unvalidated client-owned blob on every
/// widget-carrying entity), so — same shape as `query_admin.rs`'s
/// publish-time `EXPLAIN` lint being "the friendly error, the missing grant
/// is the actual guarantee" — this is the sanctioned pre-save check the
/// widget config editor calls before writing through
/// `/api/v1/dashboard_widget`. Same authorization as this crate's other
/// bespoke widget business actions (`widget_actions.rs`): a caller who may
/// update a widget may check whether a config they intend to save is valid.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/widget/validate-config",
    tag = "dashboard",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "pure pre-save config validation; persists nothing",
    )))),
    request_body = ValidateConfigBody,
    responses(
        (status = 200, description = "Validation result (see `valid`/`errors`)", body = ValidateConfigResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn validate_config_route(
    axum::extract::State(state): axum::extract::State<attome_core::EngineState>,
    _ctx: Authorized<Privilege<WidgetUpdate>>,
    Json(body): Json<ValidateConfigBody>,
) -> (StatusCode, Json<ValidateConfigResponse>) {
    if let Some(widget_type) = body
        .widget_type
        .as_deref()
        .filter(|t| *t != "declarative_widget")
    {
        let mut errors = Vec::new();
        match crate::widget_registry::registry().get(widget_type) {
            None => errors.push(format!("unknown widget_type {widget_type}")),
            Some(descriptor)
                if descriptor.render_kind == crate::widget_registry::RenderKind::Unsupported =>
            {
                errors.push(format!(
                    "widget_type {widget_type} has no renderer and cannot be added"
                ));
            }
            Some(_) => {}
        }
        match body.config.as_object() {
            Some(config) => errors.extend(crate::execution::validate_widget_config(
                config,
                &state.entities.load(),
            )),
            None => errors.push("config must be a JSON object".to_string()),
        }
        return (
            StatusCode::OK,
            Json(ValidateConfigResponse {
                valid: errors.is_empty(),
                errors,
            }),
        );
    }
    match validate_config(&body.config) {
        Ok(_) => (
            StatusCode::OK,
            Json(ValidateConfigResponse {
                valid: true,
                errors: Vec::new(),
            }),
        ),
        Err(errors) => (
            StatusCode::OK,
            Json(ValidateConfigResponse {
                valid: false,
                errors,
            }),
        ),
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/attome-dashboard/widget/validate-config",
        post(validate_config_route),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(validate_config_route))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Descriptive schema/default-config for the widget registry ─────────────

/// Descriptive only — see `widget_registry.rs`'s doc comment for why
/// `WidgetDescriptor::schema` is not an enforced validator; the real
/// enforcement is [`validate_config`] via the HTTP route above.
pub fn schema_hint() -> serde_json::Value {
    serde_json::json!({
        "query_ref": "uuid (references a stored query)",
        "columns": [{
            "field": "string", "label": "string", "label_ar": "string?",
            "format": { "kind": "text|number|date|currency|badge" },
            "conditional_colors": [{ "when": { "field": "string", "operator": "eq|ne|gt|gte|lt|lte|contains|is_empty|is_not_empty", "value": "any?" }, "color": "#hex" }],
            "link": { "kind": "external", "target": "http(s) url or /relative path" }
        }],
        "actions": ["string (attome-ai id, \"domain.verb\")"]
    })
}

pub fn default_config() -> serde_json::Value {
    serde_json::json!({ "query_ref": "", "columns": [], "actions": [] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_config() -> serde_json::Value {
        json!({
            "query_ref": "018f1c2e-6b7a-7c3d-8b1a-000000000001",
            "columns": [
                {
                    "field": "amount",
                    "label": "Amount",
                    "label_ar": "المبلغ",
                    "format": { "kind": "currency", "currency_code": "SAR" },
                    "conditional_colors": [
                        { "when": { "field": "amount", "operator": "gt", "value": 1000 }, "color": "#22c55e" }
                    ],
                    "link": { "kind": "external", "target": "https://example.com/{id}" }
                },
                {
                    "field": "status",
                    "label": "Status",
                    "format": { "kind": "badge" },
                    "link": { "kind": "action", "action_id": "record.get" }
                }
            ],
            "actions": ["record.get", "record.summarize"]
        })
    }

    #[test]
    fn a_well_formed_config_validates() {
        let result = validate_config(&valid_config());
        assert!(result.is_ok(), "unexpected errors: {result:?}");
    }

    #[test]
    fn missing_query_ref_is_rejected() {
        let mut config = valid_config();
        config.as_object_mut().unwrap().remove("query_ref");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn a_non_uuid_query_ref_is_rejected() {
        let mut config = valid_config();
        config["query_ref"] = json!("not-a-uuid");
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("query_ref")));
    }

    #[test]
    fn zero_columns_is_rejected() {
        let mut config = valid_config();
        config["columns"] = json!([]);
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("columns")));
    }

    #[test]
    fn too_many_columns_is_rejected() {
        let mut config = valid_config();
        let column = json!({ "field": "x", "label": "X" });
        config["columns"] = json!(std::iter::repeat_n(column, MAX_COLUMNS + 1).collect::<Vec<_>>());
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("50")));
    }

    #[test]
    fn an_unknown_top_level_field_is_rejected() {
        let mut config = valid_config();
        config
            .as_object_mut()
            .unwrap()
            .insert("extra_evil_field".to_string(), json!("nope"));
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn a_javascript_scheme_link_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["link"] =
            json!({ "kind": "external", "target": "javascript:alert(1)" });
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("link.target")));
    }

    #[test]
    fn a_data_scheme_link_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["link"] =
            json!({ "kind": "external", "target": "data:text/html,<script>alert(1)</script>" });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn a_protocol_relative_link_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["link"] =
            json!({ "kind": "external", "target": "//evil.example.com" });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn a_relative_path_link_is_accepted() {
        let mut config = valid_config();
        config["columns"][0]["link"] = json!({ "kind": "external", "target": "/xrm/invoice/123" });
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn a_non_hex_color_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["conditional_colors"][0]["color"] = json!("red");
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("color")));
    }

    #[test]
    fn a_css_expression_color_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["conditional_colors"][0]["color"] = json!("expression(alert(1))");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn a_malformed_action_id_is_rejected() {
        let mut config = valid_config();
        config["actions"] = json!(["not_dotted", "Bad.Case", "record."]);
        let errors = validate_config(&config).unwrap_err();
        assert_eq!(errors.len(), 3);
    }

    #[test]
    fn too_many_actions_is_rejected() {
        let mut config = valid_config();
        config["actions"] =
            json!(std::iter::repeat_n("record.get", MAX_ACTIONS + 1).collect::<Vec<_>>());
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("20")));
    }

    #[test]
    fn an_unsafe_field_identifier_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["field"] = json!("amount; DROP TABLE x");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn a_condition_missing_a_required_value_is_rejected() {
        let mut config = valid_config();
        config["columns"][0]["conditional_colors"][0]["when"] =
            json!({ "field": "amount", "operator": "gt" });
        let errors = validate_config(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("when.value")));
    }

    #[test]
    fn is_empty_operator_does_not_require_a_value() {
        let mut config = valid_config();
        config["columns"][0]["conditional_colors"][0]["when"] =
            json!({ "field": "amount", "operator": "is_empty" });
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn default_config_is_itself_schema_shaped_but_incomplete() {
        // The seed default is intentionally an empty shell (no columns yet) —
        // it must round-trip through serde into the typed struct even though
        // it fails validate_config's "at least one column" rule.
        let raw = default_config();
        let typed: Result<DeclarativeWidgetConfig, _> = serde_json::from_value(raw.clone());
        assert!(typed.is_ok(), "default_config must deserialize");
        assert!(
            validate_config(&raw).is_err(),
            "empty columns must fail validation"
        );
    }

    /// CLEANUP-REVIEW 3.4: accept/reject set unchanged by the move to
    /// `attome_db::ident` — first char a letter, no leading underscore, no length cap.
    #[test]
    fn safe_identifier_accept_reject_set() {
        for ok in ["name", "a", "created_on", "x9_", "a__b"] {
            assert!(is_safe_identifier(ok), "{ok}");
        }
        for bad in [
            "", "_a", "_", "Name", "1a", "a-b", "a b", "a.b", "a\"b", "é",
        ] {
            assert!(!is_safe_identifier(bad), "{bad:?}");
        }
        assert!(is_safe_identifier(&"a".repeat(500)));
    }
}
