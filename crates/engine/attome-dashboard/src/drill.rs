//! Dashboard 10/10 Phase 3.1 — the records behind a number, and Phase 3.2 —
//! how the number was calculated.
//!
//! Both routes resolve the same [`crate::widget_data::WidgetContext`] and the
//! same structured plan the data route used, so the explanation's filters are
//! exactly the filters the records were listed with, and a bucket's records
//! total is exactly its value on static data (the parity contract D-522 names).
use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_core::chart_view_metadata::ChartViewMetadata;
use attome_core::chart_view_metadata::DateBucket;
use attome_core::data_definition::{MeasureFn, Presentation};
use attome_search::{BucketKey, DrillTarget, RecordColumn, StructuredRecords};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::DashboardRead;
use crate::execution::{
    AppliedFilter, DataClass, DefinitionSource, Drillability, FilterOrigin, TimezoneSource,
    WidgetInputs, find_widget, load_definition,
};
use crate::widget_data::{
    KpiMetric, WidgetContext, definition_fingerprint, kpi_data, query_bindings, query_request,
    resolve_widget_context, run_query, structured_plan,
};

/// What a viewer may send to the records route: the data route's values plus
/// which bucket to list.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WidgetRecordsInputs {
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    #[serde(default)]
    pub cross_filters: BTreeMap<String, Value>,
    #[serde(default)]
    pub preview: bool,
    /// A bucket key exactly as the data route returned it; omitted lists every
    /// row the (ungrouped) number covers.
    #[serde(default)]
    pub bucket_key: Option<BucketKey>,
    #[serde(default)]
    pub series_key: Option<BucketKey>,
    /// Keyset cursor: the `next_cursor` of the previous page.
    #[serde(default)]
    pub after_id: Option<Uuid>,
    /// 1-200, default 50.
    #[serde(default)]
    pub page_size: Option<i64>,
}

/// P7-T2: a drilled KPI's snapshot next to the records listed now.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MetricParity {
    pub metric_id: Uuid,
    /// The period the records were listed for: the metric's current one.
    pub period_start: chrono::NaiveDate,
    /// The latest snapshot of that period; absent before one is computed.
    pub snapshot_value: Option<f64>,
    pub snapshot_computed_at: Option<DateTime<Utc>>,
    /// How many records the caller may read match the definition now.
    pub listed_total: i64,
    /// Whether the metric counts records, so the snapshot and the listed
    /// total are the same measure and can be compared.
    pub counts_records: bool,
    /// Whether the records as they were when the snapshot was taken can be
    /// listed; never yet.
    pub as_of_available: bool,
    pub as_of_unavailable_reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct WidgetRecordsResponse {
    pub widget_id: Uuid,
    pub drillability: Drillability,
    pub definition_source: DefinitionSource,
    pub published_version_number: Option<i64>,
    /// Equal to the data route's fingerprint for the same inputs.
    pub definition_fingerprint: String,
    pub timezone: String,
    pub timezone_source: TimezoneSource,
    /// The same filters the number was computed with, and their origins.
    pub applied_filters: Vec<AppliedFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_key: Option<BucketKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series_key: Option<BucketKey>,
    pub records: StructuredRecords,
    /// P7-T2: for a KPI widget, the snapshot and the records listed now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric_parity: Option<MetricParity>,
    /// P7-T3: for a KPI widget, whether the caller's read scope on the
    /// metric's entity is narrower than the whole entity the metric was
    /// computed over, so the number counts records this list leaves out.
    /// Only the flag: how many are hidden is never counted or returned.
    pub some_records_hidden: bool,
    /// P7-T4: whether the listed total equals the widget's number, and why
    /// not.
    pub parity: Parity,
}

/// P7-T4: why a drill's listed total and the widget's number differ, or
/// that they agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParityReason {
    /// The records listed are exactly the ones the number counts.
    Equal,
    /// The number was computed earlier (a metric snapshot, or the records
    /// changed between the two reads).
    DataChangedSinceComputed,
    /// An amount was converted at another date's rate.
    CurrencyConvertedAtOtherDate,
    /// The number is a fraction within half of the listed total.
    Rounding,
    /// The number is not a count of these records (a sum, an average, a
    /// stored query's own figure), so the two cannot be compared.
    NotComparable,
}

/// P7-T4: a drill's listed total beside the widget's number.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Parity {
    /// The widget's number for the drilled bucket; absent when there is none
    /// to compare.
    pub value: Option<f64>,
    pub listed_total: i64,
    pub matches: bool,
    pub reason: ParityReason,
}

/// P7-T4: the parity of `listed_total` against `value`, a count of the same
/// records when `comparable`. A difference is a change since the number was
/// computed, unless it is a fraction within half of the total. Pure.
pub fn parity_of(value: Option<f64>, listed_total: i64, comparable: bool) -> Parity {
    let reason = match value {
        _ if !comparable => ParityReason::NotComparable,
        None => ParityReason::NotComparable,
        #[allow(
            clippy::cast_precision_loss,
            reason = "record counts are far below 2^52"
        )]
        Some(v) if v == listed_total as f64 => ParityReason::Equal,
        #[allow(
            clippy::cast_precision_loss,
            reason = "record counts are far below 2^52"
        )]
        Some(v) if v.fract() != 0.0 && (v - listed_total as f64).abs() < 0.5 => {
            ParityReason::Rounding
        }
        Some(_) => ParityReason::DataChangedSinceComputed,
    };
    Parity {
        value,
        listed_total,
        matches: reason == ParityReason::Equal,
        reason,
    }
}

/// P7-T3: the widget config flag that shows a widget's totals and never its
/// records. The explanation stays available.
pub const AGGREGATE_ONLY: &str = "aggregate_only";

/// Whether a widget's config asks for totals only. Pure.
pub fn is_aggregate_only(config: &serde_json::Map<String, Value>) -> bool {
    config.get(AGGREGATE_ONLY).and_then(Value::as_bool) == Some(true)
}

impl std::fmt::Debug for WidgetRecordsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetRecordsResponse")
            .finish_non_exhaustive()
    }
}

/// List the records behind a widget value
///
/// The records the caller may see that make up a widget's value, for drilling in. Writes nothing.
/// Anyone who may read the dashboard.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/widgets/{widget_id}/records",
    tag = "dashboard",
    extensions(("x-audit-exempt" = json!({"reason": "read_only", "via": null, "note": "Dashboard 10/10 Phase 3.1: lists the records behind a widget value over the caller's record scope and writes nothing."}))),
    params(("id" = Uuid, Path, description = "The dashboard"), ("widget_id" = Uuid, Path, description = "The widget")),
    request_body = WidgetRecordsInputs,
    responses(
        (status = 200, description = "The exact records behind the widget's value or bucket, with an exact total", body = WidgetRecordsResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, nothing is published, or the widget is not in the executed definition", body = ErrorResponse),
        (status = 422, description = "The widget is not exactly drillable, the key does not apply, or the count exceeds the cost ceiling", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn widget_records(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    Path((dashboard_id, widget_id)): Path<(Uuid, Uuid)>,
    Json(inputs): Json<WidgetRecordsInputs>,
) -> Result<Json<WidgetRecordsResponse>, AppError> {
    let definition = load_definition(&state, &ctx, dashboard_id, inputs.preview).await?;
    let (page, widget) = find_widget(&definition.snapshot, widget_id).ok_or(AppError::NotFound)?;
    let wc = resolve_widget_context(
        &state,
        &ctx,
        &definition,
        page,
        widget,
        &inputs.parameters,
        &inputs.cross_filters,
    )
    .await?;
    if is_aggregate_only(&wc.config) {
        return Err(AppError::FieldValidation(vec![attome_types::FieldError {
            field: AGGREGATE_ONLY.to_owned(),
            code: AGGREGATE_ONLY.to_owned(),
            message: "this widget shows totals only; its records cannot be listed (its \
                      explanation can be read)"
                .to_owned(),
        }]));
    }
    if wc.drillability != Drillability::Exact {
        return Err(AppError::Validation(format!(
            "this widget's data is not exactly drillable (drillability: {})",
            match wc.drillability {
                Drillability::ExplainOnly => "explain_only; a governed KPI can only be explained",
                _ => "none; the rows shown are the result",
            }
        )));
    }
    // P7-T1: a query or view widget over one entity drills through its own
    // stored query, filtered by the clicked bucket.
    if wc.data_class == DataClass::Query {
        let (records, applied_filters) =
            query_records(&state, &ctx, &definition, &wc, &inputs).await?;
        return Ok(Json(WidgetRecordsResponse {
            widget_id: wc.widget_id,
            drillability: wc.drillability,
            definition_source: definition.source,
            published_version_number: definition.version_number,
            definition_fingerprint: definition_fingerprint(&definition, &wc, &applied_filters),
            timezone: wc.tz.name().to_owned(),
            timezone_source: wc.timezone_source,
            applied_filters,
            bucket_key: inputs.bucket_key,
            series_key: inputs.series_key,
            parity: parity_of(None, records.total, false),
            records,
            metric_parity: None,
            some_records_hidden: false,
        }));
    }
    // P7-T2: a builder metric's KPI lists the records its definition counts
    // now, as the viewer, next to the snapshot.
    if wc.data_class == DataClass::Kpi {
        let (records, applied_filters, parity, some_records_hidden) =
            metric_records(&state, &ctx, &wc, &inputs).await?;
        return Ok(Json(WidgetRecordsResponse {
            widget_id: wc.widget_id,
            drillability: wc.drillability,
            definition_source: definition.source,
            published_version_number: definition.version_number,
            definition_fingerprint: definition_fingerprint(&definition, &wc, &applied_filters),
            timezone: wc.tz.name().to_owned(),
            timezone_source: wc.timezone_source,
            applied_filters,
            bucket_key: inputs.bucket_key,
            series_key: inputs.series_key,
            parity: parity_of(parity.snapshot_value, records.total, parity.counts_records),
            records,
            metric_parity: Some(parity),
            some_records_hidden,
        }));
    }
    let plan = structured_plan(&state, &wc)?;
    let records = attome_search::run_structured_records(
        &state,
        &ctx,
        &plan.data,
        &plan.extra_filters(),
        wc.tz,
        &DrillTarget {
            bucket_key: inputs.bucket_key.clone(),
            series_key: inputs.series_key.clone(),
        },
        inputs.after_id,
        inputs.page_size.unwrap_or(attome_types::DEFAULT_PAGE_SIZE),
    )
    .await?;
    let applied_filters = plan.applied_filters();
    // P7-T4: the same aggregate the data route returns, for this bucket.
    let counts = plan
        .data
        .measures
        .first()
        .is_some_and(|m| m.aggregation == MeasureFn::Count);
    let value = if counts {
        let aggregate = attome_search::run_structured_aggregate(
            &state,
            &ctx,
            &plan.data,
            &plan.extra_filters(),
            wc.tz,
        )
        .await?;
        bucket_value(
            &aggregate,
            inputs.bucket_key.as_ref(),
            inputs.series_key.as_ref(),
        )
    } else {
        None
    };
    let parity = parity_of(value, records.total, counts);
    Ok(Json(WidgetRecordsResponse {
        widget_id: wc.widget_id,
        drillability: wc.drillability,
        definition_source: definition.source,
        published_version_number: definition.version_number,
        definition_fingerprint: definition_fingerprint(&definition, &wc, &applied_filters),
        timezone: wc.tz.name().to_owned(),
        timezone_source: wc.timezone_source,
        applied_filters,
        bucket_key: inputs.bucket_key,
        series_key: inputs.series_key,
        records,
        metric_parity: None,
        some_records_hidden: false,
        parity,
    }))
}

/// P7-T4: the first measure of the bucket a drill names (the whole number
/// when it names none; the Other bucket for `Other`). Pure.
pub fn bucket_value(
    aggregate: &attome_search::StructuredAggregate,
    bucket_key: Option<&BucketKey>,
    series_key: Option<&BucketKey>,
) -> Option<f64> {
    if matches!(bucket_key, Some(BucketKey::Other)) {
        return aggregate
            .other
            .as_ref()
            .and_then(|b| b.values.first().copied().flatten());
    }
    let key = bucket_key.cloned().unwrap_or(BucketKey::Total);
    aggregate
        .buckets
        .iter()
        .find(|b| b.key == key && b.series_key.as_ref() == series_key)
        .and_then(|b| b.values.first().copied().flatten())
}

/// P7-T2: the records behind a builder metric's KPI: the metric's spec as a
/// structured definition over its current period, run as the viewer (record
/// and attribute security apply, never the metric principal's scope), with
/// the latest snapshot of that period beside the exact total, and (P7-T3)
/// whether the viewer's scope is narrower than the metric's.
async fn metric_records(
    state: &EngineState,
    ctx: &SecurityContext,
    wc: &WidgetContext<'_>,
    inputs: &WidgetRecordsInputs,
) -> Result<(StructuredRecords, Vec<AppliedFilter>, MetricParity, bool), AppError> {
    let refs = crate::execution::kpi_metric_refs(wc.widget);
    let [metric_id] = refs.as_slice() else {
        return Err(AppError::Validation(
            "only a widget showing one metric can be drilled".into(),
        ));
    };
    let db = &state.base.db;
    let spec = attome_metric::builder::current_spec(db, *metric_id)
        .await?
        .ok_or_else(|| {
            AppError::Validation(
                "this metric is not built from its parts; it can only be explained".into(),
            )
        })?;
    let metric = attome_metric::metric::fetch_metric(db, *metric_id).await?;
    let (start, end) = attome_metric::metric::period_bounds(
        &metric.period,
        attome_metric::metric::PeriodCalendar::default(),
        Utc::now(),
    )?;
    let snapshot = attome_metric::metric::latest_snapshot(db, *metric_id, start).await?;
    let data = attome_metric::builder::spec_definition(&spec, start, end)?;
    let records = attome_search::run_structured_records(
        state,
        ctx,
        &data,
        &[],
        wc.tz,
        &DrillTarget {
            bucket_key: inputs.bucket_key.clone(),
            series_key: inputs.series_key.clone(),
        },
        inputs.after_id,
        inputs.page_size.unwrap_or(attome_types::DEFAULT_PAGE_SIZE),
    )
    .await?;
    let applied_filters = data
        .filters
        .iter()
        .map(|filter| AppliedFilter {
            filter: filter.clone(),
            origin: FilterOrigin::Definition,
        })
        .collect();
    let parity = MetricParity {
        metric_id: *metric_id,
        period_start: start,
        snapshot_value: snapshot.as_ref().and_then(|s| s.actual),
        snapshot_computed_at: snapshot.as_ref().map(|s| s.computed_at),
        listed_total: records.total,
        counts_records: spec.aggregate == "count",
        as_of_available: false,
        as_of_unavailable_reason: Some("record history (A1) is not enabled".to_owned()),
    };
    let hidden = narrower_than_whole_entity(state, ctx, &spec.entity_logicalname).await?;
    Ok((records, applied_filters, parity, hidden))
}

/// P7-T3: whether `ctx` reads less than every record of `entity`. A builder
/// metric is computed over the whole entity (the metric principal's read),
/// so the comparison is of scope kinds: anything below `Global` (own, team,
/// business unit, shares) may leave records out. Nothing is counted.
async fn narrower_than_whole_entity(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
) -> Result<bool, AppError> {
    if ctx.is_admin {
        return Ok(false);
    }
    let (entity_id, entity_name, _, _) =
        attome_records::entity_crud::resolve_entity(state, entity).await?;
    let (level, _) = attome_records::entity_crud::resolve_record_access_inputs(
        state,
        ctx,
        entity_id,
        &entity_name,
        attome_security::RecordAction::Read,
    )
    .await?;
    Ok(level < AccessLevel::Global)
}

/// The filters that select one bucket of a chart over a query's rows: the
/// category (`x_field`) for `bucket_key` and the series (`group_by_field`)
/// for `series_key`. `Total` selects everything. Pure.
pub fn bucket_filters(
    chart: Option<&ChartViewMetadata>,
    bucket_key: Option<&BucketKey>,
    series_key: Option<&BucketKey>,
) -> Result<Vec<attome_core::Filter>, AppError> {
    let mut out = Vec::new();
    for (key, field) in [
        (
            bucket_key,
            chart.map(|c| c.x_field.as_str()).filter(|f| !f.is_empty()),
        ),
        (series_key, chart.and_then(|c| c.group_by_field.as_deref())),
    ] {
        match (key, field) {
            (None | Some(BucketKey::Total), _) => {}
            (Some(key), Some(field)) => out.extend(attome_search::key_filters(field, key)?),
            (Some(_), None) => {
                return Err(AppError::Validation(
                    "this widget's query is not grouped by that key".into(),
                ));
            }
        }
    }
    Ok(out)
}

/// P7-T1: the records behind a query widget's value or bucket (D-522): the
/// widget's own request (same query, version, bindings, security) with the
/// bucket's grouping values added as bound filters, paged by keyset, with
/// the exact total of the same request. Only a query over one entity drills.
async fn query_records(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &crate::execution::DashboardDefinition,
    wc: &WidgetContext<'_>,
    inputs: &WidgetRecordsInputs,
) -> Result<(StructuredRecords, Vec<AppliedFilter>), AppError> {
    let bound = query_bindings(wc)?;
    let mut filters: Vec<attome_core::Filter> =
        bound.iter().map(|applied| applied.filter.clone()).collect();

    // What the query is: its entity, and the chart's grouping.
    let (probe, captured) = query_request(definition, wc.widget, &wc.config, 1, filters.clone())?;
    let probe = run_query(state, ctx, probe.drill_page(None), captured).await?;
    let entity = probe
        .entity_logical_name()
        .map(str::to_owned)
        .ok_or_else(|| {
            AppError::Validation(
                "this widget's query reads more than one entity; its rows are the result".into(),
            )
        })?;
    let chart: Option<ChartViewMetadata> = probe
        .view_metadata()
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    filters.extend(bucket_filters(
        chart.as_ref(),
        inputs.bucket_key.as_ref(),
        inputs.series_key.as_ref(),
    )?);

    let (count, captured) = query_request(definition, wc.widget, &wc.config, 1, filters.clone())?;
    let counted = run_query(state, ctx, count.drill_count(), captured).await?;
    let (total, estimated) = counted.total();
    if estimated {
        return Err(AppError::Validation(
            "too many records to count exactly; narrow the dashboard's filters".into(),
        ));
    }

    let page_size = inputs
        .page_size
        .unwrap_or(attome_types::DEFAULT_PAGE_SIZE)
        .clamp(1, attome_types::MAX_PAGE_SIZE);
    let (rows, captured) = query_request(
        definition,
        wc.widget,
        &wc.config,
        page_size,
        filters.clone(),
    )?;
    let page = run_query(state, ctx, rows.drill_page(inputs.after_id), captured).await?;
    let columns = page
        .column_types()
        .into_iter()
        .map(|(name, data_type)| RecordColumn { name, data_type })
        .collect();
    let (rows, next_cursor) = page.into_rows();
    Ok((
        StructuredRecords {
            entity_logical_name: entity,
            columns,
            rows,
            total: total.unwrap_or(0),
            as_of: Utc::now(),
            next_cursor,
            drill_filters: Some(filters),
        },
        bound,
    ))
}

// ── Explanation (Phase 3.2) ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ExplainedFilter {
    pub field: String,
    pub field_display_name: Option<String>,
    pub op: String,
    #[schema(value_type = Object)]
    pub value: Option<Value>,
    /// A readable value where one is safe to show: a built-in `@current_user`
    /// shows only the caller's own user name.
    pub value_display: Option<String>,
    pub origin: FilterOrigin,
}

impl std::fmt::Debug for ExplainedFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplainedFilter").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ExplainedMeasure {
    pub aggregation: MeasureFn,
    pub field: Option<String>,
    pub field_display_name: Option<String>,
    pub label: Option<String>,
    /// The formal form, e.g. `SUM(amount)` or `COUNT(*)`.
    pub expression: String,
}

impl std::fmt::Debug for ExplainedMeasure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplainedMeasure").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct StructuredExplanation {
    pub entity_logical_name: String,
    pub entity_display_name: Option<String>,
    pub measures: Vec<ExplainedMeasure>,
    pub group_field: Option<String>,
    pub group_field_display_name: Option<String>,
    pub bucket: Option<DateBucket>,
    pub series_field: Option<String>,
    pub series_field_display_name: Option<String>,
    /// Inactive records never count (`is_active` NULL or true).
    pub live_rows_only: bool,
    /// The caller's read depth on the entity: `global`, `business_unit`,
    /// `team` or `none` (own and shared records only).
    pub access_level: String,
    pub caller_is_admin: bool,
    pub presentation: Presentation,
}

impl std::fmt::Debug for StructuredExplanation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructuredExplanation")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct MetricTarget {
    pub target_value: Option<f64>,
    pub threshold_warn: Option<f64>,
    pub threshold_crit: Option<f64>,
}

impl std::fmt::Debug for MetricTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricTarget").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ExplainedMetric {
    pub metric: KpiMetric,
    pub source_kind: Option<String>,
    pub query_ref: Option<String>,
    pub query_name: Option<String>,
    pub formula: Option<String>,
    pub target: Option<MetricTarget>,
    pub lineage: Option<attome_metric::lineage::MetricLineageNode>,
}

impl std::fmt::Debug for ExplainedMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplainedMetric").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct KpiExplanation {
    /// Always true: computed by the platform service account for a fixed scope,
    /// never filtered to the viewer, and never drillable to records.
    pub service_scoped: bool,
    pub metrics: Vec<ExplainedMetric>,
}

impl std::fmt::Debug for KpiExplanation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KpiExplanation").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct QueryExplanation {
    pub query_id: Option<Uuid>,
    pub query_name: Option<String>,
    pub required_privilege: Option<String>,
    pub view_id: Option<Uuid>,
    pub pinned_query_version_id: Option<Uuid>,
    /// True when the rows shown are the result (a query over more than one
    /// entity); false when its buckets drill to records (P7-T1).
    pub rows_are_the_result: bool,
}

impl std::fmt::Debug for QueryExplanation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryExplanation").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct WidgetExplanation {
    pub widget_id: Uuid,
    pub widget_type: String,
    pub data_class: DataClass,
    pub drillability: Drillability,
    pub definition_source: DefinitionSource,
    pub published_version_number: Option<i64>,
    pub publication_fingerprint: Option<String>,
    pub definition_fingerprint: String,
    pub as_of: DateTime<Utc>,
    pub timezone: String,
    pub timezone_source: TimezoneSource,
    pub filters: Vec<ExplainedFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<StructuredExplanation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kpi: Option<KpiExplanation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<QueryExplanation>,
}

impl std::fmt::Debug for WidgetExplanation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WidgetExplanation").finish_non_exhaustive()
    }
}

async fn display_names(
    state: &EngineState,
    entity: &str,
) -> Result<(Option<String>, BTreeMap<String, String>), AppError> {
    let entity_name: Option<Option<String>> = sqlx::query_scalar(
        "SELECT name FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT a.logicalname, a.name FROM attribute_info a \
         JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND (a.is_active IS NULL OR a.is_active = true) \
           AND (e.is_active IS NULL OR e.is_active = true)",
    )
    .bind(entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok((
        entity_name.flatten(),
        rows.into_iter()
            .filter_map(|(logical, name)| name.map(|n| (logical, n)))
            .collect(),
    ))
}

fn access_level_name(level: AccessLevel) -> &'static str {
    match level {
        AccessLevel::Global => "global",
        AccessLevel::BusinessUnit => "business_unit",
        AccessLevel::Team => "team",
        AccessLevel::None => "none",
    }
}

async fn caller_user_name(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Option<String>, AppError> {
    let name: Option<Option<String>> =
        sqlx::query_scalar("SELECT user_name FROM user_account WHERE id = $1")
            .bind(ctx.user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(name.flatten())
}

async fn explain_filters(
    state: &EngineState,
    ctx: &SecurityContext,
    applied: &[AppliedFilter],
    names: &BTreeMap<String, String>,
) -> Result<Vec<ExplainedFilter>, AppError> {
    let mut out = Vec::with_capacity(applied.len());
    for applied in applied {
        let value_display = match &applied.origin {
            FilterOrigin::Builtin { name } if name == "@current_user" => {
                caller_user_name(state, ctx).await?
            }
            _ => applied.filter.value.as_ref().map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Array(items) => items
                    .iter()
                    .map(|i| {
                        i.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| i.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            }),
        };
        out.push(ExplainedFilter {
            field: applied.filter.field.clone(),
            field_display_name: names.get(&applied.filter.field).cloned(),
            op: applied.filter.op.clone(),
            value: applied.filter.value.clone(),
            value_display,
            origin: applied.origin.clone(),
        });
    }
    Ok(out)
}

/// Explain a widget's value
///
/// How the widget's value is calculated, from the same resolved context as its data. Writes nothing.
/// Anyone who may read the dashboard.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/widgets/{widget_id}/explain",
    tag = "dashboard",
    extensions(("x-audit-exempt" = json!({"reason": "read_only", "via": null, "note": "Dashboard 10/10 Phase 3.2: explains how a widget value is calculated from the same resolved context and writes nothing."}))),
    params(("id" = Uuid, Path, description = "The dashboard"), ("widget_id" = Uuid, Path, description = "The widget")),
    request_body = WidgetInputs,
    responses(
        (status = 200, description = "How the widget's number is calculated, from the same context the data route uses", body = WidgetExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, nothing is published, or the widget is not in the executed definition", body = ErrorResponse),
        (status = 422, description = "An unknown parameter, a malformed value, or a definition that cannot execute", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn widget_explain(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    Path((dashboard_id, widget_id)): Path<(Uuid, Uuid)>,
    Json(inputs): Json<WidgetInputs>,
) -> Result<Json<WidgetExplanation>, AppError> {
    let definition = load_definition(&state, &ctx, dashboard_id, inputs.preview).await?;
    let (page, widget) = find_widget(&definition.snapshot, widget_id).ok_or(AppError::NotFound)?;
    let wc = resolve_widget_context(
        &state,
        &ctx,
        &definition,
        page,
        widget,
        &inputs.parameters,
        &inputs.cross_filters,
    )
    .await?;

    let mut explanation = WidgetExplanation {
        widget_id: wc.widget_id,
        widget_type: wc.widget_type.clone(),
        data_class: wc.data_class,
        drillability: wc.drillability,
        definition_source: definition.source,
        published_version_number: definition.version_number,
        publication_fingerprint: definition
            .snapshot
            .get("publication_fingerprint")
            .and_then(Value::as_str)
            .map(str::to_owned),
        definition_fingerprint: String::new(),
        as_of: Utc::now(),
        timezone: wc.tz.name().to_owned(),
        timezone_source: wc.timezone_source,
        filters: Vec::new(),
        structured: None,
        kpi: None,
        query: None,
    };
    let mut applied = Vec::new();

    match wc.data_class {
        DataClass::Structured => {
            let plan = structured_plan(&state, &wc)?;
            applied = plan.applied_filters();
            let (entity_display_name, names) = display_names(&state, &plan.data.source).await?;
            let entity_id = crate::access::entity_id(&state, &plan.data.source)
                .map_err(|_| AppError::Validation("unknown source entity".into()))?;
            let level = attome_security::resolve_entity_access_level(
                &state.base.db,
                ctx.user_id,
                entity_id,
                &plan.data.source,
                attome_security::RecordAction::Read,
            )
            .await?;
            let measures = plan
                .data
                .measures
                .iter()
                .map(|m| ExplainedMeasure {
                    aggregation: m.aggregation,
                    field: m.field.clone(),
                    field_display_name: m.field.as_ref().and_then(|f| names.get(f).cloned()),
                    label: m.label.clone(),
                    expression: match (&m.field, m.aggregation) {
                        (_, MeasureFn::Count) => "COUNT(*)".to_owned(),
                        (Some(field), MeasureFn::CountDistinct) => {
                            format!("COUNT(DISTINCT {field})")
                        }
                        (Some(field), MeasureFn::Median) => format!("MEDIAN({field})"),
                        (Some(field), agg) => format!("{}({field})", agg.as_str().to_uppercase()),
                        (None, agg) => agg.as_str().to_uppercase(),
                    },
                })
                .collect();
            explanation.filters = explain_filters(&state, &ctx, &applied, &names).await?;
            explanation.structured = Some(StructuredExplanation {
                entity_logical_name: plan.data.source.clone(),
                entity_display_name,
                measures,
                group_field: plan.data.group.as_ref().map(|g| g.field.clone()),
                group_field_display_name: plan
                    .data
                    .group
                    .as_ref()
                    .and_then(|g| names.get(&g.field).cloned()),
                bucket: plan.data.group.as_ref().and_then(|g| g.bucket),
                series_field: plan.data.series.clone(),
                series_field_display_name: plan
                    .data
                    .series
                    .as_ref()
                    .and_then(|s| names.get(s).cloned()),
                live_rows_only: true,
                access_level: if ctx.is_admin {
                    "global".to_owned()
                } else {
                    access_level_name(level).to_owned()
                },
                caller_is_admin: ctx.is_admin,
                presentation: plan.data.presentation.clone(),
            });
        }
        DataClass::Kpi => {
            ctx.require_key("dashboard_metric_definition.read")?;
            let kpi = kpi_data(&state, &definition, widget, &wc.widget_type).await?;
            let mut metrics = Vec::with_capacity(kpi.metrics.len());
            for metric in kpi.metrics {
                metrics.push(explain_metric(&state, &definition, widget, metric).await?);
            }
            explanation.kpi = Some(KpiExplanation {
                service_scoped: true,
                metrics,
            });
        }
        DataClass::Query => {
            let mut query = explain_query(&state, &definition, widget).await?;
            query.rows_are_the_result = wc.drillability != Drillability::Exact;
            explanation.query = Some(query);
        }
        DataClass::None => {}
    }
    explanation.definition_fingerprint = definition_fingerprint(&definition, &wc, &applied);
    Ok(Json(explanation))
}

async fn explain_metric(
    state: &EngineState,
    definition: &crate::execution::DashboardDefinition,
    widget: &Value,
    metric: KpiMetric,
) -> Result<ExplainedMetric, AppError> {
    let db = &state.base.db;
    // Published: the captured definition is what the number means; the draft
    // follows the live metric.
    let widget_id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
    let captured = (definition.source == DefinitionSource::Published)
        .then(|| {
            definition
                .snapshot
                .get("metric_dependencies")
                .and_then(Value::as_array)
                .and_then(|deps| {
                    deps.iter().find(|dep| {
                        dep.get("widget_id").and_then(Value::as_str) == Some(widget_id)
                            && dep.get("metric_id").and_then(Value::as_str)
                                == Some(&metric.metric_id.to_string())
                    })
                })
                .and_then(|dep| dep.get("definition").cloned())
        })
        .flatten();
    let live: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT source_kind, query_ref, formula FROM dashboard_metric_definition \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(metric.metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let text = |key: &str| {
        captured
            .as_ref()
            .and_then(|c| c.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let (source_kind, query_ref, formula) = match &captured {
        Some(_) => (text("source_kind"), text("query_ref"), text("formula")),
        None => live.clone().unwrap_or((None, None, None)),
    };
    let query_name: Option<String> =
        match query_ref.as_deref().and_then(|r| Uuid::parse_str(r).ok()) {
            Some(query_id) => {
                sqlx::query_scalar::<_, Option<String>>("SELECT name FROM sql_query WHERE id = $1")
                    .bind(query_id)
                    .fetch_optional(db)
                    .await
                    .map_err(AppError::internal)?
                    .flatten()
            }
            None => None,
        };
    let target = match &metric.current {
        Some(point) => sqlx::query_as::<_, (Option<f64>, Option<f64>, Option<f64>)>(
            "SELECT target_value::double precision, threshold_warn::double precision, \
                    threshold_crit::double precision \
             FROM dashboard_metric_target \
             WHERE metric_ref = $1 AND period_start = $2 AND (is_active IS NULL OR is_active = true) \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(metric.metric_id)
        .bind(point.period_start)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .map(|(target_value, threshold_warn, threshold_crit)| MetricTarget {
            target_value,
            threshold_warn,
            threshold_crit,
        }),
        None => None,
    };
    let lineage = if live.is_some() {
        let period = metric.current.as_ref().map(|p| p.period_start);
        Some(
            attome_metric::lineage::do_metric_lineage(db, metric.metric_id, period)
                .await?
                .root,
        )
    } else {
        None
    };
    Ok(ExplainedMetric {
        metric,
        source_kind,
        query_ref,
        query_name,
        formula,
        target,
        lineage,
    })
}

async fn explain_query(
    state: &EngineState,
    definition: &crate::execution::DashboardDefinition,
    widget: &Value,
) -> Result<QueryExplanation, AppError> {
    let uuid = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .and_then(|v| Uuid::parse_str(v).ok())
    };
    let widget_id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
    let dependency = definition
        .snapshot
        .get("dependencies")
        .and_then(Value::as_array)
        .and_then(|deps| {
            deps.iter()
                .find(|dep| dep.get("widget_id").and_then(Value::as_str) == Some(widget_id))
        });
    let config = crate::execution::widget_config(widget);
    let query_id = dependency
        .and_then(|d| uuid(d.get("query_id")))
        .or_else(|| uuid(widget.get("query_id")))
        .or_else(|| uuid(config.get("query_ref")));
    let (query_name, required_privilege) = match query_id {
        Some(id) => sqlx::query_as::<_, (Option<String>, Option<String>)>(
            "SELECT name, required_privilege FROM sql_query WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .unwrap_or((None, None)),
        None => (None, None),
    };
    Ok(QueryExplanation {
        query_id,
        query_name,
        required_privilege,
        view_id: uuid(widget.get("view_id")),
        pinned_query_version_id: dependency.and_then(|d| uuid(d.get("query_version_id"))),
        rows_are_the_result: true,
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/attome-dashboard/{id}/widgets/{widget_id}/records",
            post(widget_records),
        )
        .route(
            "/api/v1/attome-dashboard/{id}/widgets/{widget_id}/explain",
            post(widget_explain),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(widget_records, widget_explain))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod query_drill_tests {
    use super::*;

    #[test]
    fn parity_names_why_the_total_differs() {
        assert_eq!(parity_of(Some(3.0), 3, true).reason, ParityReason::Equal);
        assert!(parity_of(Some(3.0), 3, true).matches);
        assert_eq!(
            parity_of(Some(4.0), 3, true).reason,
            ParityReason::DataChangedSinceComputed
        );
        assert_eq!(parity_of(Some(3.4), 3, true).reason, ParityReason::Rounding);
        assert_eq!(
            parity_of(Some(3.0), 3, false).reason,
            ParityReason::NotComparable
        );
        assert_eq!(parity_of(None, 3, true).reason, ParityReason::NotComparable);
        assert!(!parity_of(Some(3.4), 3, true).matches);
    }

    fn chart(x: &str, series: Option<&str>) -> ChartViewMetadata {
        let mut v = serde_json::json!({
            "chart_type": "bar",
            "x_field": x,
            "y_fields": [{"field": "id", "aggregation": "count", "label": "Deals"}],
        });
        if let Some(series) = series {
            v["group_by_field"] = serde_json::json!(series);
        }
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn a_bucket_drills_by_its_grouping_values() {
        let c = chart("stage", Some("owner_name"));
        let won = BucketKey::Value {
            value: "won".into(),
        };
        let filters = bucket_filters(Some(&c), Some(&won), None).unwrap();
        assert_eq!(filters.len(), 1);
        assert_eq!(
            (filters[0].field.as_str(), filters[0].op.as_str()),
            ("stage", "eq")
        );
        let both = bucket_filters(Some(&c), Some(&won), Some(&BucketKey::Null)).unwrap();
        assert_eq!(both.len(), 2);
        assert_eq!(both[1].field, "owner_name");
        assert!(
            bucket_filters(Some(&c), Some(&BucketKey::Total), None)
                .unwrap()
                .is_empty()
        );
        assert!(bucket_filters(None, None, None).unwrap().is_empty());
        assert!(
            bucket_filters(None, Some(&won), None).is_err(),
            "no grouping to drill by"
        );
        assert!(bucket_filters(Some(&chart("stage", None)), None, Some(&won)).is_err());
    }
}
