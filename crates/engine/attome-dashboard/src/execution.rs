//! Dashboard 10/10 Phase 2.3 — the widget execution context (D-522).
//!
//! One server function resolves everything a widget's number depends on, and
//! the client supplies values only, never definitions (D-522 decision 7):
//!
//! 1. record Read on the dashboard (`require_dashboard_access`);
//! 2. the definition from the live published snapshot, or — only when the
//!    caller asks for a preview and holds record Update — from the draft;
//! 3. parameter values validated against the parameter declarations *in that
//!    definition* (type, date format); an unknown name is a 422;
//! 4. cross-filter values accepted only for variables the widget listens to;
//! 5. built-ins from the server's own `SecurityContext`;
//! 6. the timezone: page `settings.timezone` → the user's
//!    `user_account.timezone` → UTC; an invalid IANA id counts as unset;
//! 7. bindings compiled into `Filter` values, each tagged with its origin.
//!
//! Everything here except [`load_definition`] and [`resolve_timezone`] is pure,
//! so the rules are unit tested directly.
use std::collections::BTreeMap;

use attome_core::data_definition::{Binding, BindingOp, BindingSource, Presentation};
use attome_core::{EngineState, Filter};
use attome_search::{BucketKey, StructuredBucket};
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_dashboard_access;

/// The widget types whose data is a governed metric snapshot (Class B).
pub const KPI_WIDGET_TYPES: &[&str] = &["scorecard", "trendline"];

/// Upper bound on one text/choice parameter value.
const MAX_PARAMETER_TEXT: usize = 500;

/// What a viewer may send to a data route: values, never definitions.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WidgetInputs {
    /// Values for declared dashboard parameters, by name. A `date_range`
    /// parameter takes `{ "start": "YYYY-MM-DD", "end": "YYYY-MM-DD" }`; every
    /// other type takes a string (a number may also be a JSON number). `null`
    /// or an omitted name falls back to the declared default.
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    /// Cross-filter variable values by name. Only variables the widget listens
    /// to apply; the rest are ignored, so one page-wide map serves every widget.
    #[serde(default)]
    pub cross_filters: BTreeMap<String, Value>,
    /// Execute the editor's draft instead of the published version. Needs
    /// record Update on the dashboard; without it the dashboard reads as
    /// missing (404).
    #[serde(default)]
    pub preview: bool,
    /// Row page size for a query-backed (Class C) widget, 1–200.
    #[serde(default)]
    pub page_size: Option<i64>,
}

/// Where the executed definition came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionSource {
    /// The live immutable version.
    Published,
    /// The editor's working copy (preview).
    Draft,
}

/// A dashboard definition loaded once per request and shared by every widget
/// the request executes.
pub struct DashboardDefinition {
    pub dashboard_id: Uuid,
    pub source: DefinitionSource,
    pub version_number: Option<i64>,
    pub snapshot: Value,
}

impl std::fmt::Debug for DashboardDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DashboardDefinition")
            .finish_non_exhaustive()
    }
}

/// Steps 1 and 2. A dashboard with nothing published is a 404 for a viewer.
pub async fn load_definition(
    state: &EngineState,
    ctx: &SecurityContext,
    dashboard_id: Uuid,
    preview: bool,
) -> Result<DashboardDefinition, AppError> {
    require_dashboard_access(state, ctx, dashboard_id, RecordAction::Read).await?;
    if preview {
        require_dashboard_access(state, ctx, dashboard_id, RecordAction::Update)
            .await
            .map_err(|error| match error {
                AppError::Forbidden => AppError::NotFound,
                other => other,
            })?;
        let snapshot = crate::lifecycle::do_load_draft(&state.base.db, dashboard_id).await?;
        return Ok(DashboardDefinition {
            dashboard_id,
            source: DefinitionSource::Draft,
            version_number: None,
            snapshot,
        });
    }
    let published = crate::lifecycle::do_load_published(&state.base.db, dashboard_id).await?;
    let source = match published.state.as_str() {
        "published" => DefinitionSource::Published,
        _ => return Err(AppError::NotFound),
    };
    Ok(DashboardDefinition {
        dashboard_id,
        source,
        version_number: published.version_number,
        snapshot: published.snapshot.ok_or(AppError::NotFound)?,
    })
}

// ── Snapshot navigation ─────────────────────────────────────────────────────

/// Every widget JSON object under `page`'s section tree, in tree order.
pub fn collect_widgets<'a>(page: &'a Value, out: &mut Vec<&'a Value>) {
    fn walk<'a>(sections: &'a [Value], out: &mut Vec<&'a Value>) {
        for section in sections {
            if let Some(widgets) = section.get("widgets").and_then(Value::as_array) {
                out.extend(widgets.iter());
            }
            if let Some(children) = section.get("children").and_then(Value::as_array) {
                walk(children, out);
            }
        }
    }
    if let Some(sections) = page.get("sections").and_then(Value::as_array) {
        walk(sections, out);
    }
}

fn pages(snapshot: &Value) -> &[Value] {
    snapshot
        .get("pages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn id_of(value: &Value) -> Option<&str> {
    value.get("id").and_then(Value::as_str)
}

/// `(page, widget)` for `widget_id` in the snapshot.
pub fn find_widget(snapshot: &Value, widget_id: Uuid) -> Option<(&Value, &Value)> {
    let wanted = widget_id.to_string();
    for page in pages(snapshot) {
        let mut widgets = Vec::new();
        collect_widgets(page, &mut widgets);
        if let Some(widget) = widgets.into_iter().find(|w| id_of(w) == Some(&wanted)) {
            return Some((page, widget));
        }
    }
    None
}

/// `(page, widgets)` for `page_id` in the snapshot.
pub fn find_page(snapshot: &Value, page_id: Uuid) -> Option<(&Value, Vec<&Value>)> {
    let wanted = page_id.to_string();
    let page = pages(snapshot).iter().find(|p| id_of(p) == Some(&wanted))?;
    let mut widgets = Vec::new();
    collect_widgets(page, &mut widgets);
    Some((page, widgets))
}

/// A JSON-in-text column (`config`, `settings`) as an object; malformed or
/// absent reads as `{}`. Already-parsed objects pass through.
pub fn json_text_object(raw: Option<&Value>) -> serde_json::Map<String, Value> {
    match raw {
        Some(Value::Object(map)) => map.clone(),
        Some(Value::String(text)) => serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default(),
        _ => serde_json::Map::new(),
    }
}

/// A widget's parsed `config`.
pub fn widget_config(widget: &Value) -> serde_json::Map<String, Value> {
    json_text_object(widget.get("config"))
}

/// A widget's `listens` variable names (a JSON array in a text column).
pub fn listened_variables(widget: &Value) -> Vec<String> {
    let parsed = match widget.get("listens") {
        Some(Value::String(text)) => serde_json::from_str::<Value>(text).ok(),
        Some(value @ Value::Array(_)) => Some(value.clone()),
        _ => None,
    };
    parsed
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned))
        .collect()
}

/// The metric ids a KPI widget renders: `config.metric_refs` (scorecard) or
/// `config.metric_ref` (trendline). Empty for any other widget.
pub fn kpi_metric_refs(widget: &Value) -> Vec<Uuid> {
    let widget_type = widget.get("widget_type").and_then(Value::as_str);
    if !widget_type.is_some_and(|t| KPI_WIDGET_TYPES.contains(&t)) {
        return Vec::new();
    }
    let config = widget_config(widget);
    let mut refs: Vec<Uuid> = config
        .get("metric_refs")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect()
        })
        .unwrap_or_default();
    if let Some(single) = config
        .get("metric_ref")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        && !refs.contains(&single)
    {
        refs.push(single);
    }
    refs
}

// ── Write-time validation (Phase 2.1) ───────────────────────────────────────

/// The structural checks every save of a widget `config` must pass: a present
/// `data` is a valid structured definition against its source entity, and a
/// present `bindings` list is well formed. Empty when valid. Whether a binding
/// names a declared parameter is checked at publish (Phase 3.5), since a
/// parameter may be created after the widget.
pub fn validate_widget_config(
    config: &serde_json::Map<String, Value>,
    entities: &attome_core::EntityMetaRegistry,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(data) = config.get("data").filter(|d| !d.is_null()) {
        match data.get("source").and_then(Value::as_str) {
            Some(source) => match entities.get(source) {
                Some(meta) => {
                    if let Err(found) =
                        attome_core::data_definition::DataDefinition::parse(data, meta)
                    {
                        errors.extend(found.into_iter().map(|e| format!("data: {e}")));
                    }
                }
                None => errors.push(format!("data.source: unknown entity {source}")),
            },
            None => errors.push("data.source is required".to_string()),
        }
    }
    if let Some(bindings) = config.get("bindings").filter(|b| !b.is_null())
        && let Err(e) = serde_json::from_value::<Vec<Binding>>(bindings.clone())
    {
        errors.push(format!("bindings: {e}"));
    }
    errors
}

/// `EngineModel::record_validators` entry for `dashboard_widget`: runs
/// [`validate_widget_config`] on a submitted `config`. A config that is not a
/// JSON object keeps today's lenient behaviour (widget types without a schema
/// store free-form text); only the structured keys are enforced.
pub fn validate_widget_record(
    obj: &serde_json::Map<String, Value>,
    entities: &attome_core::EntityMetaRegistry,
) -> Result<(), String> {
    let Some(raw) = obj.get("config").filter(|c| !c.is_null()) else {
        return Ok(());
    };
    let config = json_text_object(Some(raw));
    let errors = validate_widget_config(&config, entities);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("config: {}", errors.join("; ")))
    }
}

// ── Classification (decision 5) ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Class A: `config.data`, aggregated live over one entity.
    Structured,
    /// Class B: a governed metric snapshot, computed by the platform service.
    Kpi,
    /// Class C: a stored query or view; the rows shown are the result.
    Query,
    /// Text, image, divider: no data.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Drillability {
    /// The records behind any value can be listed exactly.
    Exact,
    /// Explainable, not drillable (governed KPI).
    ExplainOnly,
    /// No aggregate to drill.
    None,
}

/// Server-computed classification of one snapshot widget.
pub fn classify(widget: &Value) -> (DataClass, Drillability) {
    let config = widget_config(widget);
    if config.get("data").is_some_and(|d| !d.is_null()) {
        return (DataClass::Structured, Drillability::Exact);
    }
    if !kpi_metric_refs(widget).is_empty() {
        return (DataClass::Kpi, Drillability::ExplainOnly);
    }
    let text = |key: &str| {
        widget
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
    };
    let declarative_query = widget.get("widget_type").and_then(Value::as_str)
        == Some("declarative_widget")
        && config
            .get("query_ref")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty());
    if text("query_id") || text("view_id") || declarative_query {
        return (DataClass::Query, Drillability::None);
    }
    (DataClass::None, Drillability::None)
}

// ── Parameters ───────────────────────────────────────────────────────────────

/// One declared parameter as the snapshot carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterDecl {
    pub name: String,
    pub parameter_type: String,
    pub default_value: Option<String>,
}

/// The parameters that apply on `page_id`: dashboard-wide ones plus that
/// page's own.
pub fn declared_parameters(snapshot: &Value, page_id: Option<&str>) -> Vec<ParameterDecl> {
    snapshot
        .get("parameters")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|row| match row.get("page_id").and_then(Value::as_str) {
            None => true,
            Some(own) => Some(own) == page_id,
        })
        .filter_map(|row| {
            Some(ParameterDecl {
                name: row.get("name")?.as_str()?.to_owned(),
                parameter_type: row
                    .get("parameter_type")
                    .and_then(Value::as_str)
                    .unwrap_or("text")
                    .to_owned(),
                default_value: row
                    .get("default_value")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect()
}

/// A validated parameter value.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParameterValue {
    Scalar { value: String },
    DateRange { start: NaiveDate, end: NaiveDate },
}

fn parse_parameter(decl: &ParameterDecl, raw: &Value) -> Result<Option<ParameterValue>, String> {
    if raw.is_null() {
        return Ok(None);
    }
    let name = &decl.name;
    match decl.parameter_type.as_str() {
        "date_range" => {
            let object = match raw {
                Value::Object(map) => map.clone(),
                Value::String(text) => serde_json::from_str::<Value>(text)
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .ok_or_else(|| format!("parameter {name} must be a date range"))?,
                _ => return Err(format!("parameter {name} must be a date range")),
            };
            let date = |key: &str| {
                object
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
                    .ok_or_else(|| format!("parameter {name}.{key} must be a YYYY-MM-DD date"))
            };
            let (start, end) = (date("start")?, date("end")?);
            if start > end {
                return Err(format!("parameter {name} starts after it ends"));
            }
            Ok(Some(ParameterValue::DateRange { start, end }))
        }
        "number" => {
            let text = match raw {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.trim().to_owned(),
                _ => return Err(format!("parameter {name} must be a number")),
            };
            if text.is_empty() {
                return Ok(None);
            }
            text.parse::<f64>()
                .ok()
                .filter(|n| n.is_finite())
                .ok_or_else(|| format!("parameter {name} must be a number"))?;
            Ok(Some(ParameterValue::Scalar { value: text }))
        }
        "entity_lookup" => {
            let text = raw
                .as_str()
                .ok_or_else(|| format!("parameter {name} must be a record id"))?;
            if text.is_empty() {
                return Ok(None);
            }
            Uuid::parse_str(text).map_err(|_| format!("parameter {name} must be a record id"))?;
            Ok(Some(ParameterValue::Scalar {
                value: text.to_owned(),
            }))
        }
        _ => {
            let text = raw
                .as_str()
                .ok_or_else(|| format!("parameter {name} must be a string"))?;
            if text.chars().count() > MAX_PARAMETER_TEXT {
                return Err(format!(
                    "parameter {name} must be at most {MAX_PARAMETER_TEXT} characters"
                ));
            }
            if text.is_empty() {
                return Ok(None);
            }
            Ok(Some(ParameterValue::Scalar {
                value: text.to_owned(),
            }))
        }
    }
}

/// Step 3. Unknown names and malformed values are 422s; an omitted value
/// falls back to the declared default, and a default that does not parse is
/// treated as unset (it was accepted as free text when it was saved).
pub fn resolve_parameters(
    decls: &[ParameterDecl],
    inputs: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, ParameterValue>, AppError> {
    for name in inputs.keys() {
        if !decls.iter().any(|d| &d.name == name) {
            return Err(AppError::Validation(format!("unknown parameter: {name}")));
        }
    }
    let mut resolved = BTreeMap::new();
    for decl in decls {
        let value = match inputs.get(&decl.name) {
            Some(raw) if !raw.is_null() => {
                parse_parameter(decl, raw).map_err(AppError::Validation)?
            }
            _ => decl.default_value.as_ref().and_then(|default| {
                parse_parameter(decl, &Value::String(default.clone()))
                    .ok()
                    .flatten()
            }),
        };
        if let Some(value) = value {
            resolved.insert(decl.name.clone(), value);
        }
    }
    Ok(resolved)
}

/// Step 4. Only listened variables with a non-empty string value apply.
pub fn resolve_cross_filters(
    listens: &[String],
    inputs: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, String>, AppError> {
    let mut resolved = BTreeMap::new();
    for name in listens {
        match inputs.get(name) {
            None | Some(Value::Null) => {}
            Some(Value::String(value)) if value.is_empty() => {}
            Some(Value::String(value)) => {
                if value.chars().count() > MAX_PARAMETER_TEXT {
                    return Err(AppError::Validation(format!(
                        "cross filter {name} must be at most {MAX_PARAMETER_TEXT} characters"
                    )));
                }
                resolved.insert(name.clone(), value.clone());
            }
            Some(_) => {
                return Err(AppError::Validation(format!(
                    "cross filter {name} must be a string"
                )));
            }
        }
    }
    Ok(resolved)
}

// ── Timezone (decision 10) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimezoneSource {
    Page,
    User,
    Utc,
}

fn parse_tz(value: Option<&str>) -> Option<chrono_tz::Tz> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<chrono_tz::Tz>().ok())
}

/// Pure half of step 6: page setting, then user setting, then UTC.
pub fn choose_timezone(
    page_setting: Option<&str>,
    user_setting: Option<&str>,
) -> (chrono_tz::Tz, TimezoneSource) {
    if let Some(tz) = parse_tz(page_setting) {
        return (tz, TimezoneSource::Page);
    }
    if let Some(tz) = parse_tz(user_setting) {
        return (tz, TimezoneSource::User);
    }
    (chrono_tz::UTC, TimezoneSource::Utc)
}

/// Step 6 for `page` (a snapshot page object) and the caller.
pub async fn resolve_timezone(
    state: &EngineState,
    ctx: &SecurityContext,
    page: &Value,
) -> Result<(chrono_tz::Tz, TimezoneSource), AppError> {
    let settings = json_text_object(page.get("settings"));
    let page_setting = settings.get("timezone").and_then(Value::as_str);
    if parse_tz(page_setting).is_some() {
        return Ok(choose_timezone(page_setting, None));
    }
    let user_setting: Option<Option<String>> =
        sqlx::query_scalar("SELECT timezone FROM user_account WHERE id = $1")
            .bind(ctx.user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(choose_timezone(None, user_setting.flatten().as_deref()))
}

// ── Bindings (step 7) ───────────────────────────────────────────────────────

/// Where an applied filter came from — carried to the response so the
/// explanation (Phase 3.2) and the records drill use the same list.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilterOrigin {
    Definition,
    Parameter { name: String },
    Variable { name: String },
    Builtin { name: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AppliedFilter {
    pub filter: Filter,
    pub origin: FilterOrigin,
}

/// The instant local midnight of `date` falls on in `tz` (the earliest
/// instant when a DST change makes midnight ambiguous, the first instant after
/// the gap when it does not exist).
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn local_midnight_utc(date: NaiveDate, tz: chrono_tz::Tz) -> DateTime<Utc> {
    let midnight = date.and_hms_opt(0, 0, 0).expect("midnight is valid");
    match tz.from_local_datetime(&midnight) {
        chrono::LocalResult::Single(t) => t.with_timezone(&Utc),
        chrono::LocalResult::Ambiguous(earliest, _) => earliest.with_timezone(&Utc),
        chrono::LocalResult::None => {
            let mut probe = midnight;
            loop {
                probe += chrono::Duration::minutes(15);
                if let Some(t) = tz.from_local_datetime(&probe).earliest() {
                    break t.with_timezone(&Utc);
                }
            }
        }
    }
}

fn scalar_filter(field: &str, op: BindingOp, value: String) -> Filter {
    let value = if op == BindingOp::In {
        Value::Array(vec![Value::String(value)])
    } else {
        Value::String(value)
    };
    Filter {
        field: field.to_owned(),
        op: op.filter_op().to_owned(),
        value: Some(value),
    }
}

/// Compiles bindings into filters. A binding whose source has no value is
/// skipped — an unset parameter narrows nothing.
pub fn compile_bindings(
    bindings: &[Binding],
    parameters: &BTreeMap<String, ParameterValue>,
    variables: &BTreeMap<String, String>,
    builtins: &serde_json::Map<String, Value>,
    tz: chrono_tz::Tz,
) -> Result<Vec<AppliedFilter>, AppError> {
    let mut out = Vec::new();
    for binding in bindings {
        let field = binding.field.as_str();
        match binding.source {
            BindingSource::Parameter => {
                let origin = FilterOrigin::Parameter {
                    name: binding.name.clone(),
                };
                match (parameters.get(&binding.name), binding.op) {
                    (None, _) => {}
                    (Some(ParameterValue::DateRange { start, end }), BindingOp::Range) => {
                        let from = local_midnight_utc(*start, tz);
                        let to = local_midnight_utc(*end + chrono::Duration::days(1), tz);
                        for (op, instant) in [("gte", from), ("lt", to)] {
                            out.push(AppliedFilter {
                                filter: Filter {
                                    field: field.to_owned(),
                                    op: op.to_owned(),
                                    value: Some(Value::String(instant.to_rfc3339())),
                                },
                                origin: origin.clone(),
                            });
                        }
                    }
                    (Some(ParameterValue::DateRange { .. }), _) => {
                        return Err(AppError::Validation(format!(
                            "parameter {} is a date range and needs a range binding",
                            binding.name
                        )));
                    }
                    (Some(ParameterValue::Scalar { .. }), BindingOp::Range) => {
                        return Err(AppError::Validation(format!(
                            "parameter {} is not a date range",
                            binding.name
                        )));
                    }
                    (Some(ParameterValue::Scalar { value }), op) => out.push(AppliedFilter {
                        filter: scalar_filter(field, op, value.clone()),
                        origin,
                    }),
                }
            }
            BindingSource::Variable => {
                if let Some(value) = variables.get(&binding.name) {
                    out.push(AppliedFilter {
                        filter: scalar_filter(field, binding.op, value.clone()),
                        origin: FilterOrigin::Variable {
                            name: binding.name.clone(),
                        },
                    });
                }
            }
            BindingSource::Builtin => {
                let origin = FilterOrigin::Builtin {
                    name: binding.name.clone(),
                };
                match builtins.get(&binding.name) {
                    None | Some(Value::Null) => {}
                    Some(Value::Array(items)) => {
                        let values: Vec<Value> = items
                            .iter()
                            .map(|v| match v {
                                Value::String(s) => Value::String(s.clone()),
                                other => Value::String(other.to_string()),
                            })
                            .collect();
                        // An empty membership list matches nothing: a caller
                        // on no team sees no team-scoped rows.
                        let filter = if values.is_empty() {
                            Filter {
                                field: "id".to_owned(),
                                op: "is_null".to_owned(),
                                value: None,
                            }
                        } else {
                            Filter {
                                field: field.to_owned(),
                                op: "in".to_owned(),
                                value: Some(Value::Array(values)),
                            }
                        };
                        out.push(AppliedFilter { filter, origin });
                    }
                    Some(Value::String(value)) => out.push(AppliedFilter {
                        filter: scalar_filter(field, binding.op, value.clone()),
                        origin,
                    }),
                    Some(other) => out.push(AppliedFilter {
                        filter: scalar_filter(field, binding.op, other.to_string()),
                        origin,
                    }),
                }
            }
        }
    }
    Ok(out)
}

/// Canonical SHA-256 over the inputs a widget response depends on.
pub fn fingerprint(parts: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(parts.to_string().as_bytes()))
}

// ── Presentation (applied over computed buckets) ────────────────────────────

fn series_identity(bucket: &StructuredBucket) -> String {
    bucket
        .series_key
        .as_ref()
        .map(|k| serde_json::to_string(k).unwrap_or_default())
        .unwrap_or_default()
}

fn key_identity(key: &BucketKey) -> String {
    serde_json::to_string(key).unwrap_or_default()
}

/// Applies `percent_of_total`, then `cumulative`, then the moving average, per
/// measure and per series, in bucket order. Returns the raw values (one row
/// per bucket) when anything was rewritten, so drill parity can still be
/// checked against the counted numbers.
pub fn apply_presentation(
    buckets: &mut [StructuredBucket],
    other: Option<&mut StructuredBucket>,
    presentation: &Presentation,
) -> Option<Vec<Vec<Option<f64>>>> {
    if !presentation.rewrites_values() {
        return None;
    }
    let raw: Vec<Vec<Option<f64>>> = buckets.iter().map(|b| b.values.clone()).collect();
    let measures = buckets.first().map_or(0, |b| b.values.len());
    let has_series = buckets.iter().any(|b| b.series_key.is_some());
    let mut other = other;

    if presentation.percent_of_total {
        for m in 0..measures {
            if has_series {
                let mut totals: BTreeMap<String, f64> = BTreeMap::new();
                for b in buckets.iter() {
                    *totals.entry(key_identity(&b.key)).or_default() += b.values[m].unwrap_or(0.0);
                }
                for b in buckets.iter_mut() {
                    let total = totals.get(&key_identity(&b.key)).copied().unwrap_or(0.0);
                    b.values[m] = b.values[m].map(|v| percent(v, total));
                }
            } else {
                let total: f64 = buckets
                    .iter()
                    .map(|b| b.values[m].unwrap_or(0.0))
                    .chain(other.as_ref().map(|o| o.values[m].unwrap_or(0.0)))
                    .sum();
                for b in buckets.iter_mut() {
                    b.values[m] = b.values[m].map(|v| percent(v, total));
                }
                if let Some(o) = other.as_mut() {
                    o.values[m] = o.values[m].map(|v| percent(v, total));
                }
            }
        }
    }
    let mut series_order: Vec<String> = Vec::new();
    for b in buckets.iter() {
        let id = series_identity(b);
        if !series_order.contains(&id) {
            series_order.push(id);
        }
    }
    for series in &series_order {
        let indexes: Vec<usize> = (0..buckets.len())
            .filter(|&i| &series_identity(&buckets[i]) == series)
            .collect();
        for m in 0..measures {
            if presentation.cumulative {
                let mut running = 0.0;
                for &i in &indexes {
                    if let Some(v) = buckets[i].values[m] {
                        running += v;
                        buckets[i].values[m] = Some(running);
                    }
                }
            }
            if let Some(window) = presentation.moving_average_window {
                let window = window.max(1) as usize;
                let source: Vec<Option<f64>> =
                    indexes.iter().map(|&i| buckets[i].values[m]).collect();
                for (position, &i) in indexes.iter().enumerate() {
                    let from = (position + 1).saturating_sub(window);
                    let present: Vec<f64> =
                        source[from..=position].iter().flatten().copied().collect();
                    buckets[i].values[m] = if present.is_empty() {
                        None
                    } else {
                        Some(present.iter().sum::<f64>() / present.len() as f64)
                    };
                }
            }
        }
    }
    Some(raw)
}

fn percent(value: f64, total: f64) -> f64 {
    if total == 0.0 {
        0.0
    } else {
        value / total * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decl(name: &str, parameter_type: &str, default_value: Option<&str>) -> ParameterDecl {
        ParameterDecl {
            name: name.into(),
            parameter_type: parameter_type.into(),
            default_value: default_value.map(str::to_owned),
        }
    }

    #[test]
    fn unknown_parameters_are_refused() {
        let err = resolve_parameters(
            &[decl("region", "text", None)],
            &BTreeMap::from([("status".to_string(), json!("open"))]),
        )
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(m) if m.contains("unknown parameter")));
    }

    #[test]
    fn parameter_types_are_validated_and_defaults_apply() {
        let decls = [
            decl("amount", "number", Some("10")),
            decl("owner", "entity_lookup", None),
            decl(
                "period",
                "date_range",
                Some(r#"{"start":"2026-01-01","end":"2026-01-31"}"#),
            ),
            decl("broken_default", "number", Some("not a number")),
        ];
        let resolved = resolve_parameters(&decls, &BTreeMap::new()).unwrap();
        assert_eq!(
            resolved["amount"],
            ParameterValue::Scalar { value: "10".into() }
        );
        assert!(matches!(
            resolved["period"],
            ParameterValue::DateRange { .. }
        ));
        assert!(!resolved.contains_key("broken_default"));
        assert!(!resolved.contains_key("owner"));

        for (name, bad) in [
            ("amount", json!("ten")),
            ("owner", json!("not-a-uuid")),
            (
                "period",
                json!({"start": "2026-02-01", "end": "2026-01-01"}),
            ),
            (
                "period",
                json!({"start": "01/02/2026", "end": "2026-01-01"}),
            ),
        ] {
            let inputs = BTreeMap::from([(name.to_string(), bad)]);
            assert!(resolve_parameters(&decls, &inputs).is_err(), "{name}");
        }
    }

    #[test]
    fn cross_filters_apply_only_to_listened_variables() {
        let inputs = BTreeMap::from([
            ("region".to_string(), json!("GCC")),
            ("status".to_string(), json!("open")),
        ]);
        let resolved = resolve_cross_filters(&["region".to_string()], &inputs).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["region"], "GCC");
        assert!(
            resolve_cross_filters(
                &["region".to_string()],
                &BTreeMap::from([("region".to_string(), json!(5))])
            )
            .is_err()
        );
    }

    #[test]
    fn timezone_precedence_is_page_then_user_then_utc() {
        assert_eq!(
            choose_timezone(Some("Asia/Bahrain"), Some("Europe/London")),
            (chrono_tz::Asia::Bahrain, TimezoneSource::Page)
        );
        assert_eq!(
            choose_timezone(Some("Not/AZone"), Some("Europe/London")),
            (chrono_tz::Europe::London, TimezoneSource::User)
        );
        assert_eq!(
            choose_timezone(None, Some("")),
            (chrono_tz::UTC, TimezoneSource::Utc)
        );
    }

    fn binding(source: BindingSource, name: &str, field: &str, op: BindingOp) -> Binding {
        Binding {
            source,
            name: name.into(),
            field: field.into(),
            op,
        }
    }

    #[test]
    fn a_date_range_binds_as_a_half_open_local_day_range() {
        let parameters = BTreeMap::from([(
            "period".to_string(),
            ParameterValue::DateRange {
                start: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
                end: NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
            },
        )]);
        let filters = compile_bindings(
            &[binding(
                BindingSource::Parameter,
                "period",
                "closed_on",
                BindingOp::Range,
            )],
            &parameters,
            &BTreeMap::new(),
            &serde_json::Map::new(),
            chrono_tz::Asia::Bahrain,
        )
        .unwrap();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].filter.op, "gte");
        assert_eq!(
            filters[0].filter.value,
            Some(json!("2026-02-28T21:00:00+00:00"))
        );
        assert_eq!(filters[1].filter.op, "lt");
        assert_eq!(
            filters[1].filter.value,
            Some(json!("2026-03-31T21:00:00+00:00"))
        );
    }

    #[test]
    fn unset_sources_are_skipped_and_builtins_resolve_server_side() {
        let user = Uuid::now_v7();
        let team = Uuid::now_v7();
        let builtins = serde_json::Map::from_iter([
            ("@current_user".to_string(), json!(user.to_string())),
            ("@current_user_team".to_string(), json!([team])),
        ]);
        let filters = compile_bindings(
            &[
                binding(BindingSource::Parameter, "missing", "name", BindingOp::Eq),
                binding(BindingSource::Variable, "region", "region", BindingOp::Eq),
                binding(
                    BindingSource::Builtin,
                    "@current_user",
                    "owner_ref",
                    BindingOp::Eq,
                ),
                binding(
                    BindingSource::Builtin,
                    "@current_user_team",
                    "owner_ref",
                    BindingOp::In,
                ),
            ],
            &BTreeMap::new(),
            &BTreeMap::from([("region".to_string(), "GCC".to_string())]),
            &builtins,
            chrono_tz::UTC,
        )
        .unwrap();
        assert_eq!(filters.len(), 3);
        assert_eq!(filters[1].filter.value, Some(json!(user.to_string())));
        assert_eq!(filters[2].filter.op, "in");
        assert_eq!(filters[2].filter.value, Some(json!([team.to_string()])));
    }

    #[test]
    fn an_empty_membership_builtin_matches_nothing() {
        let builtins = serde_json::Map::from_iter([("@current_user_team".to_string(), json!([]))]);
        let filters = compile_bindings(
            &[binding(
                BindingSource::Builtin,
                "@current_user_team",
                "owner_ref",
                BindingOp::In,
            )],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &builtins,
            chrono_tz::UTC,
        )
        .unwrap();
        assert_eq!(filters[0].filter.field, "id");
        assert_eq!(filters[0].filter.op, "is_null");
    }

    #[test]
    fn a_scalar_parameter_cannot_feed_a_range_binding() {
        let parameters = BTreeMap::from([(
            "p".to_string(),
            ParameterValue::Scalar { value: "x".into() },
        )]);
        assert!(
            compile_bindings(
                &[binding(
                    BindingSource::Parameter,
                    "p",
                    "closed_on",
                    BindingOp::Range
                )],
                &parameters,
                &BTreeMap::new(),
                &serde_json::Map::new(),
                chrono_tz::UTC,
            )
            .is_err()
        );
    }

    #[test]
    fn local_midnight_handles_a_dst_gap() {
        // America/Santiago skips 00:00-01:00 on 2026-09-06.
        let tz: chrono_tz::Tz = "America/Santiago".parse().unwrap();
        let instant = local_midnight_utc(NaiveDate::from_ymd_opt(2026, 9, 6).unwrap(), tz);
        assert_eq!(
            instant.with_timezone(&tz).format("%H:%M").to_string(),
            "01:00"
        );
    }

    #[test]
    fn classification_follows_the_data_source() {
        assert_eq!(
            classify(
                &json!({"widget_type": "bar_chart", "config": r#"{"data": {"source": "x"}}"#})
            ),
            (DataClass::Structured, Drillability::Exact)
        );
        assert_eq!(
            classify(
                &json!({"widget_type": "scorecard", "config": format!(r#"{{"metric_refs": ["{}"]}}"#, Uuid::nil())})
            ),
            (DataClass::Kpi, Drillability::ExplainOnly)
        );
        assert_eq!(
            classify(
                &json!({"widget_type": "entity_data_grid", "query_id": Uuid::nil().to_string()})
            ),
            (DataClass::Query, Drillability::None)
        );
        assert_eq!(
            classify(&json!({"widget_type": "rich_text", "config": "{}"})),
            (DataClass::None, Drillability::None)
        );
    }

    fn bucket(value: &str, series: Option<&str>, values: Vec<Option<f64>>) -> StructuredBucket {
        StructuredBucket {
            key: BucketKey::Value {
                value: value.into(),
            },
            series_key: series.map(|s| BucketKey::Value { value: s.into() }),
            label: Some(value.into()),
            series_label: series.map(Into::into),
            values,
        }
    }

    #[test]
    fn presentation_applies_percent_then_cumulative_per_series() {
        let mut buckets = vec![
            bucket("a", None, vec![Some(1.0)]),
            bucket("b", None, vec![Some(3.0)]),
        ];
        let presentation = Presentation {
            percent_of_total: true,
            cumulative: true,
            ..Presentation::default()
        };
        let raw = apply_presentation(&mut buckets, None, &presentation).unwrap();
        assert_eq!(raw, vec![vec![Some(1.0)], vec![Some(3.0)]]);
        assert_eq!(buckets[0].values, vec![Some(25.0)]);
        assert_eq!(buckets[1].values, vec![Some(100.0)]);

        let mut series = vec![
            bucket("jan", Some("x"), vec![Some(2.0)]),
            bucket("jan", Some("y"), vec![Some(2.0)]),
            bucket("feb", Some("x"), vec![Some(4.0)]),
        ];
        let presentation = Presentation {
            moving_average_window: Some(2),
            ..Presentation::default()
        };
        apply_presentation(&mut series, None, &presentation).unwrap();
        assert_eq!(series[2].values, vec![Some(3.0)]);
        assert_eq!(series[1].values, vec![Some(2.0)]);
    }

    #[test]
    fn presentation_without_modifiers_returns_no_raw_values() {
        let mut buckets = vec![bucket("a", None, vec![Some(1.0)])];
        assert!(apply_presentation(&mut buckets, None, &Presentation::default()).is_none());
    }
}
