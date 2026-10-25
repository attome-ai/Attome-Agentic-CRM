//! Dashboard-owned widget data (D-522 decision 7, D-523, D-543).
//!
//! A viewer names a dashboard and a widget and sends values — parameter values,
//! cross-filter values, whether it wants the editor's draft — and never a
//! definition. [`crate::execution`] resolves the definition and the execution
//! context; this module dispatches on the widget's server-computed class:
//!
//! - **Class A (`structured`)** — `config.data` aggregated by
//!   `attome_search::run_structured_aggregate` in-process, under
//!   `MODULE_DASHBOARD` (D-523), over every matching live row, with the
//!   caller's record scope.
//! - **Class B (`kpi`)** — governed metric snapshots. On a published render
//!   only snapshots computed from the metric definition captured at publish are
//!   shown (E-02); a metric edited since reports `definition_changed`.
//! - **Class C (`query`)** — the stored query or view, pinned and captured at
//!   publish (D-543), with the widget's `config.bindings` compiled to filters.
//!
//! An edit to the draft never changes a non-preview response; the records, their
//! `is_active` and the caller's grants still do (D-543 rule 2). No result is
//! cached (D-522 decision 20).
use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_core::data_definition::{Binding, DataDefinition, Grouping, Measure};
use attome_records::query_exec::{
    ExecResponse, ExecuteQueryRequest, PublishedDefinition, execute_stored_query,
    execute_stored_query_with_definition,
};
use attome_search::StructuredBucket;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, NaiveDate, Utc};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::DashboardRead;
use crate::execution::{
    AppliedFilter, DashboardDefinition, DataClass, DefinitionSource, Drillability, FilterOrigin,
    TimezoneSource, WidgetInputs, apply_presentation, classify, compile_bindings,
    declared_parameters, find_page, find_widget, fingerprint, kpi_metric_refs, listened_variables,
    load_definition, resolve_cross_filters, resolve_parameters, resolve_timezone, widget_config,
};
use crate::widget_registry::{RenderKind, registry};

/// D-522 — at most this many widgets of one page execute at once.
const PAGE_CONCURRENCY: usize = 4;
/// Snapshots a trendline shows.
const TRENDLINE_POINTS: i64 = 12;

#[derive(Serialize, ToSchema)]
pub struct StructuredData {
    pub measures: Vec<Measure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Grouping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series: Option<String>,
    pub buckets: Vec<StructuredBucket>,
    /// The values before cumulative / percent / moving-average rewrote them,
    /// one row per bucket; absent when nothing was rewritten.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_values: Option<Vec<Vec<Option<f64>>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<StructuredBucket>,
    /// Groups past the limit exist; with `other` they are folded, not dropped.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl std::fmt::Debug for StructuredData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructuredData").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KpiStatus {
    /// A snapshot computed from the executed definition exists.
    Ok,
    /// No snapshot computed from the executed definition yet.
    NoSnapshot,
    /// The metric was edited after publish; republish to adopt it.
    DefinitionChanged,
    /// The metric no longer exists or is inactive.
    Missing,
}

#[derive(Serialize, ToSchema)]
pub struct KpiPoint {
    pub snapshot_id: Uuid,
    pub period_start: NaiveDate,
    pub actual: Option<f64>,
    pub status: String,
    pub computed_at: DateTime<Utc>,
    pub source_version: Option<String>,
}

impl std::fmt::Debug for KpiPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KpiPoint").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct KpiMetric {
    pub metric_id: Uuid,
    pub name: Option<String>,
    pub key: Option<String>,
    pub unit: Option<String>,
    pub period: Option<String>,
    pub direction: Option<String>,
    pub status: KpiStatus,
    /// The latest point; `null` unless `status` is `ok`.
    pub current: Option<KpiPoint>,
    /// Newest first; a trendline's series, empty for a scorecard.
    pub history: Vec<KpiPoint>,
    /// The query version a published query-backed metric is held to.
    pub pinned_query_version_id: Option<Uuid>,
    pub snapshot_id_at_publish: Option<Uuid>,
}

impl std::fmt::Debug for KpiMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KpiMetric").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct KpiData {
    pub metrics: Vec<KpiMetric>,
    /// Always true: governed KPIs are computed by the platform service account
    /// for a fixed scope, never filtered to the viewer (D-522 decision 5).
    pub service_scoped: bool,
}

impl std::fmt::Debug for KpiData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KpiData").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct WidgetDataResponse {
    pub widget_id: Uuid,
    pub widget_type: String,
    pub render_kind: RenderKind,
    pub data_class: DataClass,
    pub drillability: Drillability,
    pub definition_source: DefinitionSource,
    pub published_version_number: Option<i64>,
    pub as_of: DateTime<Utc>,
    pub timezone: String,
    pub timezone_source: TimezoneSource,
    /// Stable for identical definitions and inputs.
    pub definition_fingerprint: String,
    /// Every filter the number was computed with, and where each came from.
    pub applied_filters: Vec<AppliedFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<StructuredData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kpi: Option<KpiData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<ExecResponse>,
}

impl std::fmt::Debug for WidgetDataResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetDataResponse").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct WidgetError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Debug for WidgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetError").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct PageWidgetResult {
    pub widget_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<WidgetDataResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WidgetError>,
}

impl std::fmt::Debug for PageWidgetResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageWidgetResult").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct PageDataResponse {
    pub page_id: Uuid,
    pub definition_source: DefinitionSource,
    pub published_version_number: Option<i64>,
    /// One entry per widget on the page, in layout order.
    pub widgets: Vec<PageWidgetResult>,
}

impl std::fmt::Debug for PageDataResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageDataResponse").finish_non_exhaustive()
    }
}

fn widget_error(error: &AppError) -> WidgetError {
    let (status, code, message) = match error {
        AppError::NotFound => (404, "not_found", "not found".to_owned()),
        AppError::Forbidden => (403, "forbidden", "forbidden".to_owned()),
        AppError::Validation(message) => (422, "validation_error", message.clone()),
        AppError::Conflict(message) => (409, "conflict", (*message).to_owned()),
        AppError::FeatureHidden(module) => (
            403,
            "feature_hidden",
            format!("module '{module}' is not included in your license"),
        ),
        _ => (500, "internal_error", "internal error".to_owned()),
    };
    WidgetError {
        status,
        code: code.to_owned(),
        message,
    }
}

/// Everything one widget's data depends on, resolved once from the executed
/// definition and the caller's inputs (D-522 decision 6). The data, records and
/// explain routes all start here, so a number, its records and its explanation
/// can never be computed under different parameters, filters or timezones.
pub struct WidgetContext<'a> {
    pub page: &'a Value,
    pub widget: &'a Value,
    pub widget_id: Uuid,
    pub widget_type: String,
    pub data_class: DataClass,
    pub drillability: Drillability,
    pub parameters: BTreeMap<String, crate::execution::ParameterValue>,
    pub variables: BTreeMap<String, String>,
    pub builtins: serde_json::Map<String, Value>,
    pub tz: chrono_tz::Tz,
    pub timezone_source: TimezoneSource,
    pub config: serde_json::Map<String, Value>,
}

impl std::fmt::Debug for WidgetContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetContext").finish_non_exhaustive()
    }
}

/// Resolves a [`WidgetContext`]: parameters against the executed definition's
/// declarations, listened cross-filters, server built-ins and the timezone.
pub async fn resolve_widget_context<'a>(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &DashboardDefinition,
    page: &'a Value,
    widget: &'a Value,
    parameters: &BTreeMap<String, Value>,
    cross_filters: &BTreeMap<String, Value>,
) -> Result<WidgetContext<'a>, AppError> {
    let widget_id = widget
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("snapshot widget without an id"))?;
    let widget_type = widget
        .get("widget_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let (data_class, mut drillability) = classify(widget);
    let config = widget_config(widget);
    // P7-T1: a query or view widget drills exactly when its stored query
    // reads one entity (its rows are records); otherwise its rows are the
    // result.
    if data_class == DataClass::Query
        && query_reads_one_entity(state, definition, widget, &config).await
    {
        drillability = Drillability::Exact;
    }
    let page_id = page.get("id").and_then(Value::as_str);
    let parameters = resolve_parameters(
        &declared_parameters(&definition.snapshot, page_id),
        parameters,
    )?;
    let variables = resolve_cross_filters(&listened_variables(widget), cross_filters)?;
    let (tz, timezone_source) = resolve_timezone(state, ctx, page).await?;
    let builtins =
        crate::context::resolve_builtin_variables(ctx, &crate::context::EmbedContext::default());
    Ok(WidgetContext {
        page,
        widget,
        widget_id,
        widget_type,
        data_class,
        drillability,
        parameters,
        variables,
        builtins,
        tz,
        timezone_source,
        config,
    })
}

/// P7-T1: whether the stored query a query widget runs is over one entity.
/// Unknown (no query, a lookup failure) is `false`: not drillable.
async fn query_reads_one_entity(
    state: &EngineState,
    definition: &DashboardDefinition,
    widget: &Value,
    config: &serde_json::Map<String, Value>,
) -> bool {
    let id = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .and_then(|s| Uuid::parse_str(s).ok())
    };
    let (query_id, view_id) = match definition.source {
        DefinitionSource::Published => {
            let widget_id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
            let dependency = definition
                .snapshot
                .get("dependencies")
                .and_then(Value::as_array)
                .and_then(|deps| {
                    deps.iter()
                        .find(|dep| dep.get("widget_id").and_then(Value::as_str) == Some(widget_id))
                });
            (dependency.and_then(|d| id(d.get("query_id"))), None)
        }
        DefinitionSource::Draft => (
            id(widget.get("query_id")).or_else(|| id(config.get("query_ref"))),
            id(widget.get("view_id")),
        ),
    };
    let found: Result<Option<bool>, sqlx::Error> = match (view_id, query_id) {
        (Some(view), _) => {
            sqlx::query_scalar(
                "SELECT q.entity_logical_name IS NOT NULL FROM view v \
                   JOIN sql_query q ON q.id = v.sql_query_ref WHERE v.id = $1",
            )
            .bind(view)
            .fetch_optional(&state.base.db)
            .await
        }
        (None, Some(query)) => {
            sqlx::query_scalar(
                "SELECT entity_logical_name IS NOT NULL FROM sql_query WHERE id = $1",
            )
            .bind(query)
            .fetch_optional(&state.base.db)
            .await
        }
        (None, None) => Ok(None),
    };
    matches!(found, Ok(Some(true)))
}

/// A Class A widget's validated definition and its compiled bindings.
pub struct StructuredPlan {
    pub data: DataDefinition,
    pub bound: Vec<AppliedFilter>,
}

impl std::fmt::Debug for StructuredPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructuredPlan").finish_non_exhaustive()
    }
}

impl StructuredPlan {
    /// The bindings as filters, for the executor.
    pub fn extra_filters(&self) -> Vec<attome_core::Filter> {
        self.bound
            .iter()
            .map(|applied| applied.filter.clone())
            .collect()
    }

    /// Every filter the number is computed with: the definition's own, then
    /// the bindings, each with its origin.
    pub fn applied_filters(&self) -> Vec<AppliedFilter> {
        self.data
            .filters
            .iter()
            .map(|filter| AppliedFilter {
                filter: filter.clone(),
                origin: FilterOrigin::Definition,
            })
            .chain(self.bound.iter().cloned())
            .collect()
    }
}

/// Parses and validates `config.data` against the live metadata and compiles
/// its bindings. 422 for anything that cannot execute.
pub fn structured_plan(
    state: &EngineState,
    wc: &WidgetContext<'_>,
) -> Result<StructuredPlan, AppError> {
    let raw = wc.config.get("data").cloned().unwrap_or(Value::Null);
    let data: DataDefinition = serde_json::from_value(raw)
        .map_err(|e| AppError::Validation(format!("widget data definition is malformed: {e}")))?;
    {
        let registry = state.entities.load();
        let meta = registry.get(&data.source).ok_or_else(|| {
            AppError::Validation(format!("unknown source entity: {}", data.source))
        })?;
        data.validate_against(meta)
            .map_err(|errors| AppError::Validation(errors.join("; ")))?;
        check_choice_values(&data.bindings, &wc.parameters, &wc.variables, meta)?;
    }
    let bound = compile_bindings(
        &data.bindings,
        &wc.parameters,
        &wc.variables,
        &wc.builtins,
        wc.tz,
    )?;
    Ok(StructuredPlan { data, bound })
}

/// The Class C widget's `config.bindings` compiled to filters.
pub(crate) fn query_bindings(wc: &WidgetContext<'_>) -> Result<Vec<AppliedFilter>, AppError> {
    let bindings: Vec<Binding> = match wc.config.get("bindings") {
        Some(raw) => serde_json::from_value(raw.clone())
            .map_err(|e| AppError::Validation(format!("widget bindings are malformed: {e}")))?,
        None => Vec::new(),
    };
    compile_bindings(
        &bindings,
        &wc.parameters,
        &wc.variables,
        &wc.builtins,
        wc.tz,
    )
}

/// Stable for an identical definition and identical resolved inputs.
pub fn definition_fingerprint(
    definition: &DashboardDefinition,
    wc: &WidgetContext<'_>,
    applied_filters: &[AppliedFilter],
) -> String {
    fingerprint(&serde_json::json!({
        "publication": definition.snapshot.get("publication_fingerprint"),
        "widget": wc.widget,
        "parameters": wc.parameters,
        "variables": wc.variables,
        "filters": applied_filters,
        "timezone": wc.tz.name(),
        "source": definition.source,
    }))
}

/// Executes one widget of an already-loaded definition.
pub async fn execute_widget(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &DashboardDefinition,
    page: &Value,
    widget: &Value,
    inputs: &WidgetInputs,
) -> Result<WidgetDataResponse, AppError> {
    let wc = resolve_widget_context(
        state,
        ctx,
        definition,
        page,
        widget,
        &inputs.parameters,
        &inputs.cross_filters,
    )
    .await?;

    let mut response = WidgetDataResponse {
        widget_id: wc.widget_id,
        widget_type: wc.widget_type.clone(),
        render_kind: registry().render_kind(&wc.widget_type),
        data_class: wc.data_class,
        drillability: wc.drillability,
        definition_source: definition.source,
        published_version_number: definition.version_number,
        as_of: Utc::now(),
        timezone: wc.tz.name().to_owned(),
        timezone_source: wc.timezone_source,
        definition_fingerprint: String::new(),
        applied_filters: Vec::new(),
        structured: None,
        kpi: None,
        query: None,
    };

    match wc.data_class {
        DataClass::Structured => {
            let plan = structured_plan(state, &wc)?;
            let mut aggregate = attome_search::run_structured_aggregate(
                state,
                ctx,
                &plan.data,
                &plan.extra_filters(),
                wc.tz,
            )
            .await?;
            let raw_values = apply_presentation(
                &mut aggregate.buckets,
                aggregate.other.as_mut(),
                &plan.data.presentation,
            );
            response.as_of = aggregate.as_of;
            response.applied_filters = plan.applied_filters();
            response.structured = Some(StructuredData {
                measures: plan.data.measures.clone(),
                group: plan.data.group.clone(),
                series: plan.data.series.clone(),
                buckets: aggregate.buckets,
                raw_values,
                other: aggregate.other,
                truncated: aggregate.truncated,
                threshold: plan.data.presentation.threshold,
            });
        }
        DataClass::Kpi => {
            ctx.require_key("dashboard_metric_definition.read")?;
            response.kpi = Some(kpi_data(state, definition, widget, &wc.widget_type).await?);
        }
        DataClass::Query => {
            let bound = query_bindings(&wc)?;
            let filters: Vec<_> = bound.iter().map(|applied| applied.filter.clone()).collect();
            let page_size = inputs
                .page_size
                .unwrap_or(attome_types::DEFAULT_PAGE_SIZE)
                .clamp(1, attome_types::MAX_PAGE_SIZE);
            response.query = Some(
                query_data(
                    state, ctx, definition, widget, &wc.config, page_size, filters,
                )
                .await?,
            );
            response.applied_filters = bound;
        }
        DataClass::None => {}
    }

    response.definition_fingerprint =
        definition_fingerprint(definition, &wc, &response.applied_filters);
    Ok(response)
}

/// A binding to a single-select choice field must carry one of its choices —
/// the closed set the metadata declares (dashboard parameters carry no choice
/// list of their own).
fn check_choice_values(
    bindings: &[Binding],
    parameters: &BTreeMap<String, crate::execution::ParameterValue>,
    variables: &BTreeMap<String, String>,
    meta: &attome_core::EntityMeta,
) -> Result<(), AppError> {
    use attome_core::data_definition::BindingSource;
    for binding in bindings {
        let value = match binding.source {
            BindingSource::Parameter => match parameters.get(&binding.name) {
                Some(crate::execution::ParameterValue::Scalar { value }) => value,
                _ => continue,
            },
            BindingSource::Variable => match variables.get(&binding.name) {
                Some(value) => value,
                None => continue,
            },
            BindingSource::Builtin => continue,
        };
        let Some(attr) = meta.attrs.iter().find(|a| a.logicalname == binding.field) else {
            continue;
        };
        if attome_core::FieldType::from_int(attr.field_type_int)
            != Some(attome_core::FieldType::Choice)
            || attome_core::is_multi_choice_attr(attr)
        {
            continue;
        }
        let choices: Vec<&str> = attr
            .options
            .as_ref()
            .and_then(|o| o.get("choices"))
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !choices.is_empty() && !choices.contains(&value.as_str()) {
            return Err(AppError::Validation(format!(
                "{} is not a valid choice for {}",
                binding.name, binding.field
            )));
        }
    }
    Ok(())
}

async fn query_data(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &DashboardDefinition,
    widget: &Value,
    config: &serde_json::Map<String, Value>,
    page_size: i64,
    filters: Vec<attome_core::Filter>,
) -> Result<ExecResponse, AppError> {
    let (request, captured) = query_request(definition, widget, config, page_size, filters)?;
    run_query(state, ctx, request, captured).await
}

/// The stored-query request a query widget runs, and the definition a
/// published widget captured at publish (P7-T1: the value and drill routes
/// build it here, so both run the same query).
pub(crate) fn query_request(
    definition: &DashboardDefinition,
    widget: &Value,
    config: &serde_json::Map<String, Value>,
    page_size: i64,
    filters: Vec<attome_core::Filter>,
) -> Result<(ExecuteQueryRequest, Option<PublishedDefinition>), AppError> {
    let uuid_field = |key: &str| {
        widget
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .and_then(|v| Uuid::parse_str(v).ok())
    };
    let declarative_query = config
        .get("query_ref")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok());
    match definition.source {
        DefinitionSource::Published => {
            let widget_id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
            let dependency = definition
                .snapshot
                .get("dependencies")
                .and_then(Value::as_array)
                .and_then(|deps| {
                    deps.iter()
                        .find(|dep| dep.get("widget_id").and_then(Value::as_str) == Some(widget_id))
                })
                .ok_or_else(|| {
                    AppError::Validation(
                        "this widget has no data source in the published version of this \
                         dashboard; republish it"
                            .into(),
                    )
                })?;
            let uuid = |key: &str| {
                dependency
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
            };
            let query_id = uuid("query_id").ok_or_else(|| {
                AppError::Validation("this widget was published without a stored query".into())
            })?;
            let view = dependency.get("view");
            let captured = PublishedDefinition {
                column_definition: dependency
                    .get("column_definition")
                    .filter(|value| !value.is_null())
                    .cloned(),
                view_kind: view
                    .and_then(|v| v.get("kind"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                view_metadata: view
                    .and_then(|v| v.get("view_metadata"))
                    .filter(|value| !value.is_null())
                    .cloned(),
            };
            let request = ExecuteQueryRequest::for_published_widget(
                query_id,
                uuid("query_version_id"),
                page_size,
                filters,
            );
            Ok((request, Some(captured)))
        }
        DefinitionSource::Draft => {
            let request = ExecuteQueryRequest::for_draft_widget(
                uuid_field("view_id"),
                uuid_field("query_id").or(declarative_query),
                page_size,
                filters,
            )
            .ok_or_else(|| AppError::Validation("this widget has no data source".into()))?;
            Ok((request, None))
        }
    }
}

/// Runs a query widget's request, with its captured definition when published.
pub(crate) async fn run_query(
    state: &EngineState,
    ctx: &SecurityContext,
    request: ExecuteQueryRequest,
    captured: Option<PublishedDefinition>,
) -> Result<ExecResponse, AppError> {
    match captured {
        Some(captured) => {
            execute_stored_query_with_definition(state, ctx, request, Some(captured)).await
        }
        None => execute_stored_query(state, ctx, request).await,
    }
}

#[derive(sqlx::FromRow)]
struct LiveMetricRow {
    name: Option<String>,
    key: Option<String>,
    unit: Option<String>,
    source_kind: Option<String>,
    query_ref: Option<String>,
    formula: Option<String>,
    period: Option<String>,
    direction: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PointRow {
    id: Uuid,
    period_start: NaiveDate,
    actual: Option<f64>,
    status: String,
    computed_at: DateTime<Utc>,
    source_version: Option<String>,
}

pub(crate) async fn kpi_data(
    state: &EngineState,
    definition: &DashboardDefinition,
    widget: &Value,
    widget_type: &str,
) -> Result<KpiData, AppError> {
    let db = &state.base.db;
    let widget_id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
    let captured: Vec<&Value> = definition
        .snapshot
        .get("metric_dependencies")
        .and_then(Value::as_array)
        .map(|deps| {
            deps.iter()
                .filter(|dep| dep.get("widget_id").and_then(Value::as_str) == Some(widget_id))
                .collect()
        })
        .unwrap_or_default();
    let published = definition.source == DefinitionSource::Published;
    let points = if widget_type == "trendline" {
        TRENDLINE_POINTS
    } else {
        1
    };

    let mut metrics = Vec::new();
    for metric_id in kpi_metric_refs(widget) {
        let live: Option<LiveMetricRow> = sqlx::query_as(
            "SELECT name, key, unit, source_kind, query_ref, formula, period, direction \
             FROM dashboard_metric_definition \
             WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(metric_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let capture = captured.iter().find(|dep| {
            dep.get("metric_id").and_then(Value::as_str) == Some(&metric_id.to_string())
        });
        let mut metric = KpiMetric {
            metric_id,
            name: None,
            key: None,
            unit: None,
            period: None,
            direction: None,
            status: KpiStatus::Missing,
            current: None,
            history: Vec::new(),
            pinned_query_version_id: None,
            snapshot_id_at_publish: capture
                .and_then(|c| c.get("snapshot_id_at_publish"))
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok()),
        };
        let Some(live) = live else {
            metrics.push(metric);
            continue;
        };
        metric.name = live.name.clone();
        metric.key = live.key.clone();
        metric.unit = live.unit.clone();
        metric.period = live.period.clone();
        metric.direction = live.direction.clone();

        let mut source_version: Option<String> = None;
        if published {
            let Some(capture) = capture else {
                // Published before format 4 captured metric definitions.
                metric.status = KpiStatus::DefinitionChanged;
                metrics.push(metric);
                continue;
            };
            let captured_definition = capture.get("definition").cloned().unwrap_or(Value::Null);
            let text = |key: &str| {
                captured_definition
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            let unchanged = text("source_kind") == live.source_kind
                && text("query_ref") == live.query_ref
                && text("formula") == live.formula
                && text("period") == live.period
                && text("direction") == live.direction;
            if !unchanged {
                metric.status = KpiStatus::DefinitionChanged;
                metrics.push(metric);
                continue;
            }
            metric.pinned_query_version_id = capture
                .get("query_version_id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok());
            source_version = metric.pinned_query_version_id.map(|id| id.to_string());
        }

        let rows: Vec<PointRow> = sqlx::query_as(
            "SELECT DISTINCT ON (period_start) id, period_start, actual::double precision AS actual, \
                    status, computed_at, source_version \
             FROM metric_snapshot \
             WHERE metric_ref = $1 AND ($2::text IS NULL OR source_version = $2) \
               AND status <> 'failed' AND dimension_attribute IS NULL \
             ORDER BY period_start DESC, computed_at DESC, id DESC \
             LIMIT $3",
        )
        .bind(metric_id)
        .bind(source_version)
        .bind(points)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let mut history: Vec<KpiPoint> = rows
            .into_iter()
            .map(|row| KpiPoint {
                snapshot_id: row.id,
                period_start: row.period_start,
                actual: row.actual,
                status: row.status,
                computed_at: row.computed_at,
                source_version: row.source_version,
            })
            .collect();
        if history.is_empty() {
            metric.status = KpiStatus::NoSnapshot;
        } else {
            metric.status = KpiStatus::Ok;
            let current = history.remove(0);
            if widget_type == "trendline" {
                history.insert(
                    0,
                    KpiPoint {
                        snapshot_id: current.snapshot_id,
                        period_start: current.period_start,
                        actual: current.actual,
                        status: current.status.clone(),
                        computed_at: current.computed_at,
                        source_version: current.source_version.clone(),
                    },
                );
            }
            metric.current = Some(current);
        }
        metric.history = history;
        metrics.push(metric);
    }
    Ok(KpiData {
        metrics,
        service_scoped: true,
    })
}

/// One page widget, with its failure contained to its own entry.
async fn run_page_widget(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &DashboardDefinition,
    page: &Value,
    widget: Value,
    inputs: &WidgetInputs,
    index: usize,
) -> (usize, PageWidgetResult) {
    let widget_id = widget
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_default();
    let result = match execute_widget(state, ctx, definition, page, &widget, inputs).await {
        Ok(data) => PageWidgetResult {
            widget_id,
            data: Some(data),
            error: None,
        },
        Err(error) => {
            if !matches!(
                error,
                AppError::Validation(_) | AppError::Forbidden | AppError::NotFound
            ) {
                tracing::error!(
                    dashboard_id = %definition.dashboard_id,
                    widget_id = %widget_id,
                    error = %error,
                    "dashboard page data: widget execution failed"
                );
            }
            PageWidgetResult {
                widget_id,
                data: None,
                error: Some(widget_error(&error)),
            }
        }
    };
    (index, result)
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/widgets/{widget_id}/data",
    tag = "dashboard",
    extensions(("x-audit-exempt" = json!({"reason": "read_only", "via": null, "note": "Dashboard 10/10 Phase 2.3: executes a widget definition over the caller's record scope and writes nothing."}))),
    params(("id" = Uuid, Path), ("widget_id" = Uuid, Path)),
    request_body = WidgetInputs,
    responses(
        (status = 200, description = "The widget's data, executed server-side from the published definition (or the draft for a preview)", body = WidgetDataResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, nothing is published, the widget is not in the executed definition, or a preview without record Update", body = ErrorResponse),
        (status = 422, description = "An unknown parameter, a malformed value, or a widget whose definition cannot execute", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn widget_data(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    Path((dashboard_id, widget_id)): Path<(Uuid, Uuid)>,
    Json(inputs): Json<WidgetInputs>,
) -> Result<Json<WidgetDataResponse>, AppError> {
    let definition = load_definition(&state, &ctx, dashboard_id, inputs.preview).await?;
    let (page, widget) = find_widget(&definition.snapshot, widget_id).ok_or(AppError::NotFound)?;
    let response = execute_widget(&state, &ctx, &definition, page, widget, &inputs).await?;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/pages/{page_id}/data",
    tag = "dashboard",
    extensions(("x-audit-exempt" = json!({"reason": "read_only", "via": null, "note": "Dashboard 10/10 Phase 2.3: executes every widget of one page over the caller's record scope and writes nothing."}))),
    params(("id" = Uuid, Path), ("page_id" = Uuid, Path)),
    request_body = WidgetInputs,
    responses(
        (status = 200, description = "Every widget on the page, executed with at most four at a time; a widget that fails carries its own error", body = PageDataResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard or page in the executed definition", body = ErrorResponse),
        (status = 422, description = "An unknown parameter or a malformed value", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn page_data(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    Path((dashboard_id, page_id)): Path<(Uuid, Uuid)>,
    Json(inputs): Json<WidgetInputs>,
) -> Result<Json<PageDataResponse>, AppError> {
    Ok(Json(
        run_page(&state, &ctx, dashboard_id, page_id, inputs).await?,
    ))
}

/// Executes every widget of one page as `ctx`; the page data route and the
/// embed route (P8-T1) both answer with it.
pub(crate) async fn run_page(
    state: &EngineState,
    ctx: &SecurityContext,
    dashboard_id: Uuid,
    page_id: Uuid,
    inputs: WidgetInputs,
) -> Result<PageDataResponse, AppError> {
    let definition = load_definition(state, ctx, dashboard_id, inputs.preview).await?;
    let (page, widgets) = find_page(&definition.snapshot, page_id).ok_or(AppError::NotFound)?;
    // A request-level input error (an unknown parameter) is the caller's
    // mistake, not one widget's: refuse the whole request.
    resolve_parameters(
        &declared_parameters(&definition.snapshot, page.get("id").and_then(Value::as_str)),
        &inputs.parameters,
    )?;
    let page = page.clone();
    let widgets: Vec<Value> = widgets.into_iter().cloned().collect();
    let pending: Vec<_> = widgets
        .into_iter()
        .enumerate()
        .map(|(index, widget)| {
            run_page_widget(state, ctx, &definition, &page, widget, &inputs, index)
        })
        .collect();
    let results: Vec<(usize, PageWidgetResult)> = futures_util::stream::iter(pending)
        .buffer_unordered(PAGE_CONCURRENCY)
        .collect()
        .await;
    let mut results = results;
    results.sort_by_key(|(index, _)| *index);
    Ok(PageDataResponse {
        page_id,
        definition_source: definition.source,
        published_version_number: definition.version_number,
        widgets: results.into_iter().map(|(_, result)| result).collect(),
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/attome-dashboard/{id}/widgets/{widget_id}/data",
            post(widget_data),
        )
        .route(
            "/api/v1/attome-dashboard/{id}/pages/{page_id}/data",
            post(page_data),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(widget_data, page_data))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
