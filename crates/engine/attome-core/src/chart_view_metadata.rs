//! D-528: moved here from `attome-server` (dashboard 10/10 Phase 2.1) so the
//! dashboard crate's structured data definition ([`crate::data_definition`])
//! can share its enums without an `attome-server` edge.
//!
//! `kind = "chart"` (D-429 follow-up, migration `0447_view_kind_chart.sql`) —
//! the typed, hand-validated `view.view_metadata` schema for a chart
//! view. Same discipline `attome-dashboard::declarative_widget` already
//! established for a widget's `config`: deny-unknown-fields structs, bounded
//! arrays/strings, closed enums, hex-only colors, a hand-rolled validator
//! (this workspace has no JSON-schema-validation dependency) — not because
//! `view_metadata` was previously validated this strictly (kanban/calendar's
//! `view_admin.rs::validate_view_kind_metadata` checks are a few
//! `non_empty_string` calls), but because a chart's settings are wide enough
//! (multiple Y series, per-series aggregation/color, calculation modifiers)
//! that the same "closed enum + bounded array, not a free-form blob" posture
//! declarative_widget uses is worth reusing here too.
//!
//! ## What this does NOT do
//!
//! Same posture as every other view kind (D-429's ruling): this is
//! presentation metadata only. `x_field`/`y_fields[].field`/`group_by_field`
//! are checked for **shape** (a safe identifier), never for **existence**
//! against the view's actual bound query columns — that happens naturally
//! when the dashboard widget viewer tries to read a bucket key from a
//! `query/execute` result that doesn't have it (missing key -> empty/zero,
//! never a crash). No new enforcement point is added; rendering still runs
//! entirely over the same already-privilege-checked feed every other kind
//! uses (D-429).
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

const MAX_FIELD_LEN: usize = 128;
const MAX_LABEL_LEN: usize = 200;
const MAX_Y_FIELDS: usize = 8;
const MIN_MOVING_AVERAGE_WINDOW: u32 = 2;
const MAX_MOVING_AVERAGE_WINDOW: u32 = 90;
const MIN_LIMIT: u32 = 1;
const MAX_LIMIT: u32 = 366;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChartViewMetadata {
    /// Defaults to `Line` — a freshly created chart view (`view_metadata:
    /// {}`, before an admin has configured anything yet) must itself pass
    /// this validator, same as any other write; see [`validate`]'s doc
    /// comment for why `x_field`/`y_fields` are similarly draft-friendly.
    #[serde(default)]
    pub chart_type: ChartType,
    /// The category/date/lookup column the view's own bound query returns —
    /// same identifier shape as `attribute_info.logicalname`. Shape-
    /// checked only, see this module's doc comment. Empty is valid (not yet
    /// configured); the dashboard viewer's own settings-driven renderer
    /// already treats a missing `x_field` as "fall back to the legacy
    /// heuristic", never a broken chart.
    #[serde(default)]
    pub x_field: String,
    /// Only meaningful when `x_field` resolves to a date/timestamp column at
    /// render time — advisory, not type-checked against the actual column
    /// here (same "kind-specific settings are advisory" posture D-429 uses
    /// for kanban/calendar).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_bucket: Option<DateBucket>,
    #[serde(default)]
    pub y_fields: Vec<ChartSeries>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<ChartSort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// When `limit` truncates the bucket set, fold the remainder into a
    /// trailing "Other" bucket instead of silently dropping it. No effect
    /// without `limit`.
    #[serde(default)]
    pub other_bucket: bool,
    /// Meaningful only for `chart_type` in `{bar, column, area}` — advisory,
    /// same reasoning as `x_bucket`.
    #[serde(default)]
    pub stacked: bool,
    #[serde(default)]
    pub cumulative: bool,
    #[serde(default)]
    pub percent_of_total: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moving_average_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ChartThreshold>,
    #[serde(default = "default_true")]
    pub show_legend: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_format: Option<ChartNumberFormat>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChartType {
    #[default]
    Line,
    Area,
    Bar,
    Column,
    Donut,
    Pie,
    Funnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DateBucket {
    Day,
    Week,
    Month,
    Quarter,
    Year,
    /// AG1-T4: an Umm al-Qura month (`hijri_month`).
    HijriMonth,
    /// AG1-T4: an Umm al-Qura year (`hijri_year`).
    HijriYear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChartSort {
    XAsc,
    XDesc,
    ValueAsc,
    ValueDesc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Aggregation {
    Sum,
    Avg,
    Count,
    CountDistinct,
    Min,
    Max,
    Median,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChartSeries {
    pub field: String,
    pub aggregation: Aggregation,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_ar: Option<String>,
    /// `#RGB`/`#RRGGBB`/`#RRGGBBAA` only — same allow-list and reasoning as
    /// `declarative_widget::ConditionalColor::color`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChartThreshold {
    pub value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChartNumberFormat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_suffix: Option<String>,
}

/// Validates a `kind = "chart"` view's raw `view_metadata` JSON, returning
/// the typed, validated metadata or a list of actionable field errors
/// (guidelines §6). Called by `view_admin.rs::validate_view_kind_metadata`
/// on EVERY create/update of a `kind = chart` view — unlike
/// `declarative_widget`'s own validator (opt-in, called only by that
/// widget's dedicated `/validate-config` route), there is no way to persist
/// a `kind = chart` view that fails this check. That matters for the
/// "create first, configure through the Chart Settings panel afterward" UX
/// this schema exists to support (`chart_view_metadata`'s own module doc):
/// a brand-new view's `view_metadata` starts as `{}`, which must itself
/// validate. `x_field` empty and `y_fields` empty are therefore both
/// accepted as "not configured yet" rather than errors — the dashboard
/// viewer's settings-driven renderer already treats either as "fall back to
/// the legacy heuristic" (never a broken chart), so storing that
/// intermediate state is genuinely valid, not merely tolerated. Anything
/// that IS present is still checked for shape.
pub fn validate(raw: &serde_json::Value) -> Result<ChartViewMetadata, Vec<String>> {
    let config: ChartViewMetadata = serde_json::from_value(raw.clone()).map_err(|e| {
        vec![format!(
            "view_metadata does not match the chart schema: {e}"
        )]
    })?;

    let mut errors = Vec::new();

    if !config.x_field.is_empty()
        && (!is_safe_identifier(&config.x_field) || config.x_field.len() > MAX_FIELD_LEN)
    {
        errors.push("x_field must be a valid identifier when present".to_string());
    }

    if config.y_fields.len() > MAX_Y_FIELDS {
        errors.push(format!("y_fields must not exceed {MAX_Y_FIELDS} entries"));
    }
    for (i, series) in config.y_fields.iter().enumerate() {
        validate_series(i, series, &mut errors);
    }

    if let Some(field) = &config.group_by_field
        && (!is_safe_identifier(field) || field.len() > MAX_FIELD_LEN)
    {
        errors.push("group_by_field must be a non-empty identifier when present".to_string());
    }

    if let Some(limit) = config.limit
        && !(MIN_LIMIT..=MAX_LIMIT).contains(&limit)
    {
        errors.push(format!("limit must be between {MIN_LIMIT} and {MAX_LIMIT}"));
    }

    if let Some(window) = config.moving_average_window
        && !(MIN_MOVING_AVERAGE_WINDOW..=MAX_MOVING_AVERAGE_WINDOW).contains(&window)
    {
        errors.push(format!(
            "moving_average_window must be between {MIN_MOVING_AVERAGE_WINDOW} and {MAX_MOVING_AVERAGE_WINDOW}"
        ));
    }

    if let Some(threshold) = &config.threshold
        && let Some(label) = &threshold.label
        && label.chars().count() > MAX_LABEL_LEN
    {
        errors.push(format!(
            "threshold.label must be at most {MAX_LABEL_LEN} characters"
        ));
    }

    if let Some(format) = &config.number_format {
        validate_number_format(format, &mut errors);
    }

    if errors.is_empty() {
        Ok(config)
    } else {
        Err(errors)
    }
}

fn validate_series(index: usize, series: &ChartSeries, errors: &mut Vec<String>) {
    let prefix = format!("y_fields[{index}]");
    if !is_safe_identifier(&series.field) || series.field.len() > MAX_FIELD_LEN {
        errors.push(format!("{prefix}.field must be a non-empty identifier"));
    }
    if series.label.is_empty() || series.label.chars().count() > MAX_LABEL_LEN {
        errors.push(format!(
            "{prefix}.label must be 1-{MAX_LABEL_LEN} characters"
        ));
    }
    if let Some(label_ar) = &series.label_ar
        && label_ar.chars().count() > MAX_LABEL_LEN
    {
        errors.push(format!(
            "{prefix}.label_ar must be at most {MAX_LABEL_LEN} characters"
        ));
    }
    if let Some(color) = &series.color
        && !validate_hex_color(color)
    {
        errors.push(format!(
            "{prefix}.color must be #RGB, #RRGGBB, or #RRGGBBAA hex"
        ));
    }
}

fn validate_number_format(format: &ChartNumberFormat, errors: &mut Vec<String>) {
    if let Some(code) = &format.currency_code
        && (code.len() != 3 || !code.chars().all(|c| c.is_ascii_uppercase()))
    {
        errors
            .push("number_format.currency_code must be a 3-letter uppercase ISO code".to_string());
    }
    if let Some(suffix) = &format.unit_suffix
        && suffix.chars().count() > 8
    {
        errors.push("number_format.unit_suffix must be at most 8 characters".to_string());
    }
}

/// Same identifier shape `declarative_widget::is_safe_identifier` uses —
/// `attribute_info.logicalname` convention, from the shared
/// `attome_db::ident` validator (CLEANUP-REVIEW 3.4). No length cap here.
fn is_safe_identifier(value: &str) -> bool {
    attome_db::ident::is_logical_name(value)
}

/// Identical allow-list to `declarative_widget::validate_hex_color`.
fn validate_hex_color(value: &str) -> bool {
    let hex = match value.strip_prefix('#') {
        Some(hex) => hex,
        None => return false,
    };
    matches!(hex.len(), 3 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_config() -> serde_json::Value {
        json!({
            "chart_type": "line",
            "x_field": "created_on",
            "x_bucket": "month",
            "y_fields": [
                { "field": "amount", "aggregation": "sum", "label": "Amount", "color": "#22c55e" }
            ],
            "group_by_field": "status",
            "sort": "x_asc",
            "limit": 12,
            "other_bucket": true,
            "cumulative": false,
            "percent_of_total": false,
            "moving_average_window": 3,
            "threshold": { "value": 1000.0, "label": "Target" },
            "show_legend": true
        })
    }

    #[test]
    fn a_well_formed_config_validates() {
        let result = validate(&valid_config());
        assert!(result.is_ok(), "unexpected errors: {result:?}");
    }

    #[test]
    fn a_minimal_config_validates() {
        let config = json!({
            "chart_type": "bar",
            "x_field": "status",
            "y_fields": [{ "field": "id", "aggregation": "count", "label": "Count" }]
        });
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn missing_x_field_is_accepted_as_not_yet_configured() {
        // A freshly created `kind = chart` view starts as `view_metadata: {}`
        // (`WidgetInspectorComponent`'s "Create Chart" flow) and must itself
        // validate — see `validate`'s own doc comment for why `x_field`
        // empty means "not configured yet", not an error.
        let mut config = valid_config();
        config.as_object_mut().unwrap().remove("x_field");
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn zero_y_fields_is_accepted_as_not_yet_configured() {
        let mut config = valid_config();
        config["y_fields"] = json!([]);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn a_completely_empty_config_validates() {
        // The exact shape a brand-new `kind = chart` view is created with.
        assert!(validate(&json!({})).is_ok());
    }

    #[test]
    fn too_many_y_fields_is_rejected() {
        let mut config = valid_config();
        let series = json!({ "field": "amount", "aggregation": "sum", "label": "Amount" });
        config["y_fields"] =
            json!(std::iter::repeat_n(series, MAX_Y_FIELDS + 1).collect::<Vec<_>>());
        let errors = validate(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("y_fields")));
    }

    #[test]
    fn an_unknown_chart_type_is_rejected() {
        let mut config = valid_config();
        config["chart_type"] = json!("waffle");
        assert!(validate(&config).is_err());
    }

    #[test]
    fn an_unknown_aggregation_is_rejected() {
        let mut config = valid_config();
        config["y_fields"][0]["aggregation"] = json!("mode");
        assert!(validate(&config).is_err());
    }

    #[test]
    fn an_unsafe_field_identifier_is_rejected() {
        let mut config = valid_config();
        config["x_field"] = json!("amount; DROP TABLE x");
        assert!(validate(&config).is_err());
    }

    #[test]
    fn a_non_hex_series_color_is_rejected() {
        let mut config = valid_config();
        config["y_fields"][0]["color"] = json!("red");
        let errors = validate(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("color")));
    }

    #[test]
    fn moving_average_window_out_of_bounds_is_rejected() {
        let mut config = valid_config();
        config["moving_average_window"] = json!(1);
        let errors = validate(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("moving_average_window")));
    }

    #[test]
    fn limit_out_of_bounds_is_rejected() {
        let mut config = valid_config();
        config["limit"] = json!(0);
        let errors = validate(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("limit")));
    }

    #[test]
    fn an_unknown_top_level_field_is_rejected() {
        let mut config = valid_config();
        config
            .as_object_mut()
            .unwrap()
            .insert("extra_evil_field".to_string(), json!("nope"));
        assert!(validate(&config).is_err());
    }

    #[test]
    fn bad_currency_code_is_rejected() {
        let mut config = valid_config();
        config["number_format"] = json!({ "currency_code": "usd" });
        let errors = validate(&config).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("currency_code")));
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
