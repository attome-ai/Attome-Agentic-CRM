//! Generic aggregation — `GROUP BY` with `COUNT`/`SUM`/`AVG`/`MIN`/`MAX` over
//! one entity's own physical table, validated against its metadata exactly
//! like `attome-api::query_exec`'s WHERE-loop (identifiers/casts only from
//! `EntityMeta`, every value bound — guidelines §4, never interpolated SQL).
//! Built for the dashboard module's chart/metric widgets:
//! `document/XRM_Implementation_Plan.txt` names "Search Engine's
//! aggregation" as the Reporting Engine's own stated prerequisite, and
//! nothing in the platform had it before this.
//!
//! Lives in `attome-search`, not `attome-report`, per that plan's own engine
//! placement — so this public `POST /api/v1/search/aggregate` route is
//! license-gated by `MODULE_SEARCH`. It is not the dashboard entitlement:
//! D-523 entitles dashboard widget aggregation by `MODULE_DASHBOARD`, through
//! the dashboard module's own data routes calling [`run_structured_aggregate`]
//! in-process. The `MODULE_REPORT` gate this comment used to cite belonged to
//! the Report-hosted dashboards D-479 sunset.
//!
//! ## One scope for every read (dashboard 10/10 Phase 2.2)
//!
//! [`AggregateScope`] is the only place that decides which rows a number
//! covers: entity read privilege, the field whitelist (sensitive fields
//! without a grant are absent), compiled filters, the live-row predicate
//! (`attome_core::live_row_predicate` — NULL `is_active` counts as live) and
//! the record-level RLS predicate. The public route, the structured dashboard
//! aggregation and the records twin all start from it, which is what makes
//! "the records behind a number are the rows the number counted" structural
//! rather than a convention. Inactive rows no longer count on the public
//! route either — a behavior change for totals that used to include them.
use attome_core::chart_view_metadata::DateBucket;
use attome_core::data_definition::{
    DataDefinition, MAX_GROUP_LIMIT, MeasureFn, SortOrder, date_trunc_unit, system_column_type,
};
use attome_core::filter::{FieldCastError, FilterSchema};
use attome_core::{EngineState, Filter, parameter_cast, quote_ident, text_array_literal};
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::{Json, Router, extract::State, routing::post};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use utoipa::ToSchema;
use uuid::Uuid;

/// Mirrors `attome-api::entity_crud::access::POLYMORPHIC_AUDIT_ENTITIES`,
/// which is `pub(crate)` there — `attome-search` does not (and should not)
/// depend on `attome-api` for one four-entry array. Aggregating an audit
/// ledger isn't a dashboard use case, and these rows have no meaningful
/// row-level RLS of their own (`query_exec.rs`'s single-entity branch has to
/// special-case them for exactly that reason); refusing them outright here
/// is the simplest correct answer rather than reimplementing that
/// special-casing a second time. If the upstream list ever changes, this one
/// needs updating too — a known, accepted duplication of four string
/// literals, not a shared source of truth.
const POLYMORPHIC_AUDIT_ENTITIES: &[&str] = &[
    "audit_header",
    "audit_snapshot",
    "audit_detail",
    "attome_document",
];

/// Past this many groups, a chart/list widget isn't rendering "results," it's
/// rendering noise — matches the platform-wide `MAX_PAGE_SIZE` ceiling for UI
/// consistency (`attome_types::MAX_PAGE_SIZE` is also 200).
pub const MAX_GROUP_BUCKETS: i64 = 200;

/// Same non-report cost ceiling `query_exec.rs` applies to a non-`is_report`
/// stored query — an aggregate widget has no "report" tier of its own.
const AGGREGATE_COST_CEILING: f64 = 100_000.0;

/// Heavier than `query/execute`'s 500ms fast-read default (`GROUP BY` costs
/// more per row than a keyset page), lighter than its 5s `is_report` tier
/// (this endpoint has a hard bucket-count + cost ceiling that report SQL
/// does not).
const AGGREGATE_STATEMENT_TIMEOUT_MS: i64 = 2000;

// ── Request/response ─────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct AggregateRequest {
    /// Entity UUID (`entity_info.id`) — same dual resolution as
    /// `query/execute`'s `ExecuteQueryRequest`.
    entity_logical_name: Option<Uuid>,
    /// Fallback: entity logicalname string.
    entity: Option<String>,
    /// Field to bucket on. `None` runs the metric over every row the
    /// filters/RLS admit as a single ungrouped total (e.g. a Metric widget's
    /// "Total Revenue" — `SUM(amount)` with no `GROUP BY`) — the response
    /// carries exactly one bucket with `label: null`.
    group_by: Option<String>,
    /// Required unless `metric_fn == "count"`.
    metric_field: Option<String>,
    /// One of: `count`, `sum`, `avg`, `min`, `max`.
    #[schema(example = "sum")]
    metric_fn: String,
    #[serde(default)]
    filters: Vec<Filter>,
    /// `"value_desc"` (default), `"value_asc"`, `"label_asc"`, `"label_desc"`.
    /// Ties break on the label, so equal values never swap between runs.
    #[serde(default = "value_desc")]
    #[schema(default = "value_desc", example = "value_desc")]
    order: String,
}

impl std::fmt::Debug for AggregateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregateRequest").finish_non_exhaustive()
    }
}
fn value_desc() -> String {
    "value_desc".to_owned()
}

#[derive(Serialize, ToSchema)]
pub struct AggregateBucket {
    /// `null` for rows whose `group_by` field is itself NULL. Always a
    /// display string (or null) — the group_by column is cast to `text` in
    /// SQL rather than decoded per its native type, since a bucket label is
    /// for display, not further computation.
    label: Option<String>,
    value: f64,
}

impl std::fmt::Debug for AggregateBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregateBucket").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct AggregateResponse {
    entity_logical_name: String,
    group_by: Option<String>,
    metric_fn: String,
    buckets: Vec<AggregateBucket>,
    bucket_count: i64,
    /// Honest-cap contract mirroring `attome-search::routes`'s `Total::AtLeast`
    /// reasoning: `true` means real groups exist past [`MAX_GROUP_BUCKETS`],
    /// not that the count happens to equal the cap.
    truncated: bool,
}

impl std::fmt::Debug for AggregateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregateResponse").finish_non_exhaustive()
    }
}

// ── Entity resolution ─────────────────────────────────────────────────────────

async fn resolve_entity(
    db: &DbPool,
    entity_logical_name: Option<Uuid>,
    entity: Option<&str>,
) -> Result<(Uuid, String), AppError> {
    if let Some(id) = entity_logical_name {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, logicalname FROM entity_info \
             WHERE id = $1 AND (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        return row.ok_or(AppError::NotFound);
    }
    if let Some(name) = entity {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, logicalname FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(name)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        return row.ok_or(AppError::NotFound);
    }
    Err(AppError::Validation(
        "entity_logical_name or entity is required".into(),
    ))
}

/// `field_type_int -> data_type` string, by storage type
/// (`FieldType::storage`, U9). Currency reads as `number` here (this
/// endpoint only needs "numeric or not"); `query_exec.rs` keeps
/// `currency` distinct for grid rendering. Test-only: the whitelist uses
/// [`data_type_of_attr`], which also sees a formula's options.
#[cfg(test)]
fn data_type_of(field_type_int: i32) -> &'static str {
    let ft =
        attome_core::FieldType::from_int(field_type_int).unwrap_or(attome_core::FieldType::Text);
    data_type_of_storage(&ft.storage(None))
}

/// [`data_type_of`] by storage type (U9): a formula aggregates as its
/// result type — a `number` formula is summable — a rich-text field as
/// text, an image as a file (never a group key).
fn data_type_of_attr(attr: &attome_core::AttrInfo) -> &'static str {
    data_type_of_storage(&attr.storage_type())
}

fn data_type_of_storage(ft: &attome_core::FieldType) -> &'static str {
    use attome_core::FieldType;
    match ft {
        FieldType::Number | FieldType::Currency => "number",
        FieldType::Date => "date",
        FieldType::Bool => "bool",
        FieldType::Choice => "choice",
        FieldType::Lookup => "lookup",
        FieldType::File | FieldType::Image => "file",
        FieldType::Text
        | FieldType::Icon
        | FieldType::Color
        | FieldType::RichText
        | FieldType::Formula => "text",
    }
}

struct Whitelist {
    /// logicalname -> data_type, sensitive-without-grant fields excluded;
    /// the system columns every provisioned table carries are included.
    fields: HashMap<String, &'static str>,
    multi_choice: HashSet<String>,
}

/// C-15 (M01 §7): this endpoint's own [`attome_core::filter::FilterSchema`]
/// adapter over the whitelist just above — the filter -> WHERE fragment
/// itself is `attome_core::filter::compile` now, shared with
/// `query_exec.rs`, `data_export.rs`, and `legal_matter_admin.rs`.
impl FilterSchema for Whitelist {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        let data_type = self.fields.get(field).ok_or(FieldCastError::Unknown)?;
        parameter_cast(data_type).ok_or(FieldCastError::UnsupportedType)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.multi_choice.contains(field)
    }
}

fn build_whitelist(meta: &attome_core::EntityMeta, ctx: &SecurityContext) -> Whitelist {
    let sensitive: HashSet<String> = meta
        .attrs
        .iter()
        // D-589: aggregates are a bulk surface.
        .filter(|attr| {
            !attome_security::field_gate::readable(
                ctx,
                &meta.logicalname,
                attr,
                meta.primary_name_attribute.as_deref(),
                attome_security::field_gate::Surface::Bulk,
            )
        })
        .map(|attr| attr.logicalname.clone())
        .collect();
    let multi_choice: HashSet<String> = meta
        .attrs
        .iter()
        .filter(|attr| {
            matches!(attr.field_type_int, 7 | 8)
                && attr
                    .options
                    .as_ref()
                    .and_then(|o| o.get("multi"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
        .map(|attr| attr.logicalname.clone())
        .collect();
    let mut fields: HashMap<String, &'static str> = meta
        .attrs
        .iter()
        .filter(|attr| !sensitive.contains(&attr.logicalname))
        .map(|attr| (attr.logicalname.clone(), data_type_of_attr(attr)))
        .collect();
    for column in attome_core::ALL_SYSTEM_COLS {
        if let Some(field_type) = system_column_type(column) {
            fields
                .entry((*column).to_owned())
                .or_insert_with(|| field_type.as_str());
        }
    }
    Whitelist {
        fields,
        multi_choice,
    }
}

/// The exact "which rows to show, and did we cut real data" logic
/// `run_aggregate` applies to its query result — pulled out so it can be
/// unit tested against a small `cap` instead of the real
/// [`MAX_GROUP_BUCKETS`] (200 rows is an expensive fixture for a unit test
/// whose only job is to get an off-by-one boundary right).
fn split_at_cap<T>(mut rows: Vec<T>, cap: i64) -> (Vec<T>, bool) {
    let truncated = rows.len() as i64 > cap;
    rows.truncate(cap.max(0) as usize);
    (rows, truncated)
}

async fn run_live_explain<'e, E>(executor: E, sql: &str, params: &[String]) -> Result<f64, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let explain_sql = format!("EXPLAIN (FORMAT JSON) {sql}");
    let mut explain = sqlx::query_scalar::<_, Value>(&explain_sql);
    for param in params {
        explain = explain.bind(param);
    }
    let plan = explain
        .fetch_one(executor)
        .await
        .map_err(AppError::internal)?;
    plan.pointer("/0/Plan/Total Cost")
        .and_then(Value::as_f64)
        .ok_or_else(|| AppError::internal("PostgreSQL returned an invalid query plan"))
}

// ── The shared scope ─────────────────────────────────────────────────────────

/// Which rows of one entity a caller may count, list or export, as a bound
/// `WHERE` clause over alias `t`. See the module doc comment.
pub struct AggregateScope {
    pub entity_id: Uuid,
    pub logicalname: String,
    pub is_append_only: bool,
    pub primary_name_attribute: Option<String>,
    whitelist: Whitelist,
    conds: Vec<String>,
    params: Vec<String>,
}

impl std::fmt::Debug for AggregateScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregateScope").finish_non_exhaustive()
    }
}

impl AggregateScope {
    /// Entity read privilege, audit-ledger refusal, whitelist, `filters`, the
    /// live-row predicate and RLS, in that order. `NotFound` for an entity the
    /// registry does not know.
    pub async fn build(
        state: &EngineState,
        ctx: &SecurityContext,
        entity_logicalname: &str,
        filters: &[Filter],
    ) -> Result<Self, AppError> {
        ctx.require(entity_logicalname, "read")?;
        // U1: a polymorphic child is readable only with its parent record, a
        // per-row predicate aggregation does not replicate.
        if POLYMORPHIC_AUDIT_ENTITIES.contains(&entity_logicalname)
            || (crate::corpus::POLYMORPHIC_CHILD_ENTITIES.contains(&entity_logicalname)
                && !ctx.is_admin)
        {
            return Err(AppError::Validation(
                "aggregation is not available for this entity".into(),
            ));
        }
        let (entity_id, is_append_only, primary_name_attribute, whitelist) = {
            let registry = state.entities.load();
            let meta = registry.get(entity_logicalname).ok_or(AppError::NotFound)?;
            (
                meta.entity_id,
                meta.is_append_only,
                meta.primary_name_attribute.clone(),
                build_whitelist(meta, ctx),
            )
        };
        let mut scope = Self {
            entity_id,
            logicalname: entity_logicalname.to_owned(),
            is_append_only,
            primary_name_attribute,
            whitelist,
            conds: Vec::new(),
            params: Vec::new(),
        };
        for filter in filters {
            scope.push_filter(filter)?;
        }
        if let Some(live) = attome_core::live_row_predicate("t", is_append_only) {
            scope.conds.push(live);
        }
        let access_level = attome_security::resolve_entity_access_level(
            &state.base.db,
            ctx.user_id,
            entity_id,
            entity_logicalname,
            attome_security::RecordAction::Read,
        )
        .await?;
        if let Some(pred) = attome_security::rls_predicate(
            ctx,
            entity_id,
            "t",
            access_level,
            attome_security::RecordAction::Read.share_capability(),
            scope.params.len() + 1,
        ) {
            scope
                .conds
                .push(pred.sql.trim_start_matches("AND ").to_owned());
            scope.params.extend(pred.binds.to_text_params());
        }
        Ok(scope)
    }

    /// Adds one more filter (a resolved dashboard binding, a drill predicate).
    pub fn push_filter(&mut self, filter: &Filter) -> Result<(), AppError> {
        let (cond, binds) =
            attome_core::filter::compile(filter, &self.whitelist, self.params.len() + 1)?;
        self.conds.push(cond);
        self.params.extend(binds);
        Ok(())
    }

    /// The whitelisted data type of `field` (`number`, `date`, `choice`, …),
    /// or `None` when the field is unknown or hidden from this caller.
    pub fn data_type(&self, field: &str) -> Option<&'static str> {
        self.whitelist.fields.get(field).copied()
    }

    pub fn is_multi_choice(&self, field: &str) -> bool {
        self.whitelist.multi_choice.contains(field)
    }

    fn require_field(&self, field: &str, what: &str) -> Result<&'static str, AppError> {
        self.data_type(field)
            .ok_or_else(|| AppError::Validation(format!("unknown {what} field: {field}")))
    }

    /// Binds one more text parameter and returns its placeholder number.
    fn bind(&mut self, value: String) -> usize {
        self.params.push(value);
        self.params.len()
    }

    fn where_sql(&self, extra: &[String]) -> String {
        let all: Vec<&str> = self
            .conds
            .iter()
            .chain(extra.iter())
            .map(String::as_str)
            .collect();
        if all.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", all.join(" AND "))
        }
    }
}

/// Opens the bounded read transaction every aggregate statement runs in.
async fn begin_bounded(db: &DbPool) -> Result<attome_db::Tx<'_>, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(&format!(
        "SET LOCAL statement_timeout = {AGGREGATE_STATEMENT_TIMEOUT_MS}"
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(tx)
}

async fn enforce_cost_ceiling(
    tx: &mut attome_db::Tx<'_>,
    sql: &str,
    params: &[String],
) -> Result<(), AppError> {
    let total_cost = run_live_explain(&mut **tx, sql, params).await?;
    if total_cost > AGGREGATE_COST_CEILING {
        return Err(AppError::Validation(format!(
            "aggregate plan cost {total_cost:.2} exceeds the allowed limit {AGGREGATE_COST_CEILING:.0}"
        )));
    }
    Ok(())
}

// ── Public route ─────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/search/aggregate",
    tag = "search",
    request_body = AggregateRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "computes grouped metric buckets over a read privilege check; persists nothing",
    )))),
    responses(
        (status = 200, description = "Grouped metric buckets", body = AggregateResponse),
        (status = 422, description = "Invalid entity, group_by, metric, or filter"),
    ),
)]
/// Bare `RecordScoped`, and one of only two routes entitled to it (D-353,
/// counted by `route_authz.rs`'s ratchet): the entity is not a path segment
/// but a body field (`entity` / `entity_logical_name`), and it is resolved
/// against the database — `resolve_entity` accepts either an id or a
/// logicalname — so there is nothing for `RecordScoped<Read>` to read off the
/// matched route. `run_aggregate` makes the `ctx.require(&logicalname,
/// "read")` call itself, immediately after that resolution.
async fn aggregate(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Json(body): Json<AggregateRequest>,
) -> Result<Json<AggregateResponse>, AppError> {
    run_aggregate(&state, &ctx, body).await.map(Json)
}

/// Running an aggregation, with every transport concern removed — `pub` so
/// integration tests (and any future in-process caller, same reasoning as
/// `query_exec::execute_stored_query`) exercise the real code path rather
/// than a re-implementation of it.
pub async fn run_aggregate(
    state: &EngineState,
    ctx: &SecurityContext,
    body: AggregateRequest,
) -> Result<AggregateResponse, AppError> {
    let db = state.base.readonly_query_pool(ctx.user_id).await;
    let (_entity_id, logicalname) =
        resolve_entity(db, body.entity_logical_name, body.entity.as_deref()).await?;

    if !matches!(
        body.metric_fn.as_str(),
        "count" | "sum" | "avg" | "min" | "max"
    ) {
        ctx.require(&logicalname, "read")?;
        return Err(AppError::Validation(format!(
            "unsupported metric_fn: {}",
            body.metric_fn
        )));
    }
    if body.metric_fn != "count" && body.metric_field.is_none() {
        ctx.require(&logicalname, "read")?;
        return Err(AppError::Validation(
            "metric_field is required unless metric_fn is \"count\"".into(),
        ));
    }

    let scope = AggregateScope::build(state, ctx, &logicalname, &body.filters).await?;

    if let Some(group_by) = &body.group_by {
        if scope.is_multi_choice(group_by) {
            return Err(AppError::Validation(
                "group_by does not support multi-select Choice fields".into(),
            ));
        }
        if scope.data_type(group_by).is_none() {
            return Err(AppError::Validation(format!(
                "unknown group_by field: {group_by}"
            )));
        }
    }

    let metric_expr = match body.metric_fn.as_str() {
        "count" => "COUNT(*)::float8".to_owned(),
        fn_name => {
            let field = body.metric_field.as_ref().expect("checked above");
            let data_type = scope
                .data_type(field)
                .ok_or_else(|| AppError::Validation(format!("unknown field: {field}")))?;
            if parameter_cast(data_type) != Some("numeric") {
                return Err(AppError::Validation(format!(
                    "metric_field must be numeric for {fn_name}: {field}"
                )));
            }
            format!(
                "{}(t.{})::float8",
                fn_name.to_uppercase(),
                quote_ident(field)
            )
        }
    };

    let where_sql = scope.where_sql(&[]);
    let dir = match body.order.as_str() {
        "value_asc" => "value ASC NULLS LAST, label ASC NULLS FIRST",
        "label_asc" => "label ASC NULLS FIRST",
        "label_desc" => "label DESC NULLS LAST",
        _ => "value DESC NULLS LAST, label ASC NULLS FIRST",
    };

    let table = quote_ident(&logicalname);
    let sql = match &body.group_by {
        Some(group_by) => {
            let group_by_sql = quote_ident(group_by);
            format!(
                "SELECT t.{group_by_sql}::text AS label, {metric_expr} AS value \
                 FROM {table} t {where_sql} \
                 GROUP BY 1 ORDER BY {dir} LIMIT {}",
                MAX_GROUP_BUCKETS + 1
            )
        }
        // No GROUP BY at all — a single ungrouped total, capped to exactly
        // one row so the same `split_at_cap`/`truncated` machinery below
        // stays correct without a special case (a real aggregate never
        // produces a second row here, so `truncated` is always `false`).
        None => {
            format!("SELECT NULL::text AS label, {metric_expr} AS value FROM {table} t {where_sql}")
        }
    };

    let mut tx = begin_bounded(db).await?;
    enforce_cost_ceiling(&mut tx, &sql, &scope.params).await?;

    let mut q = sqlx::query_as::<_, (Option<String>, Option<f64>)>(&sql);
    for param in &scope.params {
        q = q.bind(param);
    }
    let rows = q.fetch_all(&mut *tx).await.map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;

    let (rows, truncated) = split_at_cap(rows, MAX_GROUP_BUCKETS);
    let buckets: Vec<AggregateBucket> = rows
        .into_iter()
        .map(|(label, value)| AggregateBucket {
            label,
            value: value.unwrap_or(0.0),
        })
        .collect();
    let bucket_count = buckets.len() as i64;

    Ok(AggregateResponse {
        entity_logical_name: logicalname,
        group_by: body.group_by,
        metric_fn: body.metric_fn,
        buckets,
        bucket_count,
        truncated,
    })
}

// ── Structured aggregation (dashboard Class A, D-522) ────────────────────────

/// A bucket's identity: the stored value, never a display string, so a drill
/// predicate can be rebuilt from it exactly (D-522 decision 11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BucketKey {
    /// The single bucket of an ungrouped definition.
    Total,
    /// A group whose stored value is not NULL, as PostgreSQL renders it as text.
    Value { value: String },
    /// The group of rows whose field is NULL.
    Null,
    /// A time bucket: `start ≤ t < end`, both UTC instants computed in the
    /// resolved timezone.
    Range {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    /// Everything past `presentation.limit`, when `other_bucket` is set.
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StructuredBucket {
    pub key: BucketKey,
    /// `Value`/`Null` only; present when the definition has a series.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_key: Option<BucketKey>,
    /// A display label derived from the key: the value itself, a lookup
    /// value's target record name when the caller may read it, or the bucket
    /// start in the resolved timezone. `null` for NULL, Total and Other — the
    /// client localizes those.
    pub label: Option<String>,
    /// The series value's display label, on the same rules as `label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_label: Option<String>,
    /// One value per measure, in definition order. `null` when the measure has
    /// no value for the group (an average over no numeric values).
    pub values: Vec<Option<f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StructuredAggregate {
    pub entity_logical_name: String,
    pub buckets: Vec<StructuredBucket>,
    /// The Other bucket, when requested and groups past the limit exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<StructuredBucket>,
    /// `true` when groups past the limit exist. With an Other bucket those
    /// groups are folded into it rather than dropped.
    pub truncated: bool,
    /// The database transaction time the statement ran at.
    pub as_of: DateTime<Utc>,
    /// The IANA timezone time buckets were computed in.
    pub timezone: String,
}

/// The complement of `top` over `field`: every row whose stored value is not
/// one of the returned group keys, including NULL rows unless the NULL group
/// was itself returned (`NOT IN` never matches NULL, so the plain form would
/// silently drop them). Shared by the Other bucket and its records drill.
pub fn other_complement_filter_sql(
    field: &str,
    top: &[BucketKey],
    placeholder: usize,
) -> (String, Option<String>) {
    let column = format!("t.{}", quote_ident(field));
    let null_returned = top.iter().any(|key| matches!(key, BucketKey::Null));
    let values: Vec<&str> = top
        .iter()
        .filter_map(|key| match key {
            BucketKey::Value { value } => Some(value.as_str()),
            _ => None,
        })
        .collect();
    if values.is_empty() {
        let sql = if null_returned {
            format!("{column} IS NOT NULL")
        } else {
            "TRUE".to_owned()
        };
        return (sql, None);
    }
    let not_in = format!("NOT ({column}::text = ANY(${placeholder}::text[]))");
    let sql = if null_returned {
        format!("({column} IS NOT NULL AND {not_in})")
    } else {
        format!("({column} IS NULL OR {not_in})")
    };
    (sql, Some(text_array_literal(&values)))
}

fn measure_sql(scope: &AggregateScope, definition: &DataDefinition) -> Result<String, AppError> {
    let mut parts = Vec::with_capacity(definition.measures.len());
    for (i, measure) in definition.measures.iter().enumerate() {
        let expr = match (&measure.field, measure.aggregation) {
            (_, MeasureFn::Count) => "COUNT(*)".to_owned(),
            (Some(field), aggregation) => {
                let data_type = scope.require_field(field, "measure")?;
                if scope.is_multi_choice(field) {
                    return Err(AppError::Validation(format!(
                        "measure field {field} is a multi-select field"
                    )));
                }
                if aggregation.needs_numeric_field() && parameter_cast(data_type) != Some("numeric")
                {
                    return Err(AppError::Validation(format!(
                        "measure field {field} must be numeric for {}",
                        aggregation.as_str()
                    )));
                }
                let column = format!("t.{}", quote_ident(field));
                match aggregation {
                    MeasureFn::CountDistinct => format!("COUNT(DISTINCT {column})"),
                    MeasureFn::Sum => format!("SUM({column})"),
                    MeasureFn::Avg => format!("AVG({column})"),
                    MeasureFn::Min => format!("MIN({column})"),
                    MeasureFn::Max => format!("MAX({column})"),
                    MeasureFn::Median => {
                        format!("percentile_cont(0.5) WITHIN GROUP (ORDER BY {column})")
                    }
                    MeasureFn::Count => unreachable!("matched above"),
                }
            }
            (None, aggregation) => {
                return Err(AppError::Validation(format!(
                    "measure {} needs a field",
                    aggregation.as_str()
                )));
            }
        };
        parts.push(format!("({expr})::float8 AS m{i}"));
    }
    Ok(parts.join(", "))
}

fn interval_for(bucket: DateBucket) -> &'static str {
    match bucket {
        DateBucket::Day => "1 day",
        DateBucket::Week => "7 days",
        DateBucket::Month => "1 month",
        DateBucket::Quarter => "3 months",
        DateBucket::Year => "1 year",
    }
}

/// The display label of a time bucket starting at `start`, in `tz`.
pub fn range_label(start: DateTime<Utc>, bucket: DateBucket, tz: chrono_tz::Tz) -> String {
    let local = start.with_timezone(&tz);
    match bucket {
        DateBucket::Day => local.format("%Y-%m-%d").to_string(),
        DateBucket::Week => {
            let week = local.iso_week();
            format!("{}-W{:02}", week.year(), week.week())
        }
        DateBucket::Month => local.format("%Y-%m").to_string(),
        DateBucket::Quarter => format!("{}-Q{}", local.year(), (local.month() - 1) / 3 + 1),
        DateBucket::Year => local.format("%Y").to_string(),
    }
}

fn value_key(value: Option<String>) -> BucketKey {
    match value {
        Some(value) => BucketKey::Value { value },
        None => BucketKey::Null,
    }
}

/// Executes a validated [`DataDefinition`] over the caller's scope: every
/// measure in one statement, an optional field or time-bucket group and
/// series, deterministic ordering (`measure, typed key, series key`), the
/// group cap, and an Other bucket computed over the exact complement.
/// `extra_filters` are the dashboard's resolved bindings. Presentation
/// modifiers that rewrite values (cumulative, percent, moving average) are the
/// caller's to apply over the returned buckets.
pub async fn run_structured_aggregate(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &DataDefinition,
    extra_filters: &[Filter],
    tz: chrono_tz::Tz,
) -> Result<StructuredAggregate, AppError> {
    definition
        .validate_shape()
        .map_err(|errors| AppError::Validation(errors.join("; ")))?;
    let db = state.base.readonly_query_pool(ctx.user_id).await;
    let mut filters = definition.filters.clone();
    filters.extend(extra_filters.iter().cloned());
    let mut scope = AggregateScope::build(state, ctx, &definition.source, &filters).await?;

    let measures = measure_sql(&scope, definition)?;
    let table = quote_ident(&scope.logicalname);
    let mut select = Vec::new();
    let mut group_by: Vec<String> = Vec::new();
    let mut key_order = String::new();
    let bucket = definition.group.as_ref().and_then(|g| g.bucket);

    if let Some(group) = &definition.group {
        scope.require_field(&group.field, "group")?;
        if scope.is_multi_choice(&group.field) {
            return Err(AppError::Validation(
                "group does not support multi-select Choice fields".into(),
            ));
        }
        let column = format!("t.{}", quote_ident(&group.field));
        match group.bucket {
            Some(bucket) => {
                if scope.data_type(&group.field) != Some("date") {
                    return Err(AppError::Validation(
                        "a time bucket needs a date field".into(),
                    ));
                }
                let tz_param = scope.bind(tz.name().to_owned());
                let unit = date_trunc_unit(bucket);
                let local = format!("date_trunc('{unit}', {column} AT TIME ZONE ${tz_param})");
                select.push(format!("({local} AT TIME ZONE ${tz_param}) AS g_start"));
                select.push(format!(
                    "(({local} + interval '{}') AT TIME ZONE ${tz_param}) AS g_end",
                    interval_for(bucket)
                ));
                select.push("NULL::text AS g".to_owned());
                group_by.extend(["1".to_owned(), "2".to_owned()]);
                key_order = "g_start".to_owned();
            }
            None => {
                select.push("NULL::timestamptz AS g_start".to_owned());
                select.push("NULL::timestamptz AS g_end".to_owned());
                select.push(format!("{column}::text AS g"));
                select.push(format!("{column} AS g_typed"));
                group_by.extend(["3".to_owned(), "4".to_owned()]);
                key_order = "g_typed".to_owned();
            }
        }
    }
    if let Some(series) = &definition.series {
        scope.require_field(series, "series")?;
        if scope.is_multi_choice(series) {
            return Err(AppError::Validation(
                "series does not support multi-select Choice fields".into(),
            ));
        }
        let column = format!("t.{}", quote_ident(series));
        select.push(format!("{column}::text AS s"));
        select.push(format!("{column} AS s_typed"));
        let n = select.len();
        group_by.push((n - 1).to_string());
        group_by.push(n.to_string());
    }
    select.push(measures);

    let limit = definition
        .presentation
        .limit
        .unwrap_or(MAX_GROUP_LIMIT)
        .min(MAX_GROUP_LIMIT) as i64;
    let where_sql = scope.where_sql(&[]);
    let sql = if definition.group.is_some() {
        let series_order = if definition.series.is_some() {
            ", s_typed ASC NULLS FIRST"
        } else {
            ""
        };
        let sort = definition.presentation.sort.unwrap_or(if bucket.is_some() {
            SortOrder::KeyAsc
        } else {
            SortOrder::ValueDesc
        });
        let order = match sort {
            SortOrder::ValueDesc => {
                format!("m0 DESC NULLS LAST, {key_order} ASC NULLS FIRST{series_order}")
            }
            SortOrder::ValueAsc => {
                format!("m0 ASC NULLS LAST, {key_order} ASC NULLS FIRST{series_order}")
            }
            SortOrder::KeyAsc => format!("{key_order} ASC NULLS FIRST{series_order}"),
            SortOrder::KeyDesc => format!("{key_order} DESC NULLS LAST{series_order}"),
        };
        format!(
            "SELECT {} FROM {table} t {where_sql} GROUP BY {} ORDER BY {order} LIMIT {}",
            select.join(", "),
            group_by.join(", "),
            limit + 1
        )
    } else {
        format!("SELECT {} FROM {table} t {where_sql}", select.join(", "))
    };

    let mut tx = begin_bounded(db).await?;
    let as_of: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    enforce_cost_ceiling(&mut tx, &sql, &scope.params).await?;
    let mut query = sqlx::query(&sql);
    for param in &scope.params {
        query = query.bind(param);
    }
    let rows = query
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    let measure_count = definition.measures.len();
    let values_of = |row: &sqlx::postgres::PgRow| -> Result<Vec<Option<f64>>, AppError> {
        (0..measure_count)
            .map(|i| {
                row.try_get::<Option<f64>, _>(format!("m{i}").as_str())
                    .map_err(AppError::internal)
            })
            .collect()
    };

    let (rows, truncated) = split_at_cap(rows, limit);
    let mut buckets = Vec::with_capacity(rows.len());
    for row in &rows {
        let key = match (&definition.group, bucket) {
            (None, _) => BucketKey::Total,
            (Some(_), Some(_)) => {
                let start: Option<DateTime<Utc>> =
                    row.try_get("g_start").map_err(AppError::internal)?;
                let end: Option<DateTime<Utc>> =
                    row.try_get("g_end").map_err(AppError::internal)?;
                match (start, end) {
                    (Some(start), Some(end)) => BucketKey::Range { start, end },
                    _ => BucketKey::Null,
                }
            }
            (Some(_), None) => value_key(
                row.try_get::<Option<String>, _>("g")
                    .map_err(AppError::internal)?,
            ),
        };
        let label = match (&key, bucket) {
            (BucketKey::Value { value }, _) => Some(value.clone()),
            (BucketKey::Range { start, .. }, Some(bucket)) => Some(range_label(*start, bucket, tz)),
            _ => None,
        };
        let series_key = if definition.series.is_some() {
            Some(value_key(
                row.try_get::<Option<String>, _>("s")
                    .map_err(AppError::internal)?,
            ))
        } else {
            None
        };
        let series_label = match &series_key {
            Some(BucketKey::Value { value }) => Some(value.clone()),
            _ => None,
        };
        buckets.push(StructuredBucket {
            key,
            series_key,
            label,
            series_label,
            values: values_of(row)?,
        });
    }

    let mut other = None;
    if truncated
        && definition.presentation.other_bucket
        && let Some(group) = &definition.group
    {
        let top: Vec<BucketKey> = buckets.iter().map(|b| b.key.clone()).collect();
        let placeholder = scope.params.len() + 1;
        let (complement, bind) = other_complement_filter_sql(&group.field, &top, placeholder);
        if let Some(bind) = bind {
            scope.bind(bind);
        }
        let measures = measure_sql(&scope, definition)?;
        let other_sql = format!(
            "SELECT {measures} FROM {table} t {}",
            scope.where_sql(&[complement])
        );
        enforce_cost_ceiling(&mut tx, &other_sql, &scope.params).await?;
        let mut query = sqlx::query(&other_sql);
        for param in &scope.params {
            query = query.bind(param);
        }
        let row = query
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        other = Some(StructuredBucket {
            key: BucketKey::Other,
            series_key: None,
            label: None,
            series_label: None,
            values: values_of(&row)?,
        });
    }
    tx.commit().await.map_err(AppError::internal)?;

    if let Some(group) = definition.group.as_ref().filter(|g| g.bucket.is_none()) {
        let values = buckets.iter().filter_map(|b| match &b.key {
            BucketKey::Value { value } => Some(value.as_str()),
            _ => None,
        });
        let names =
            lookup_display_names(state, ctx, db, &scope.logicalname, &group.field, values).await?;
        for b in &mut buckets {
            if let BucketKey::Value { value } = &b.key
                && let Some(name) = names.get(value)
            {
                b.label = Some(name.clone());
            }
        }
    }
    if let Some(series) = &definition.series {
        let values = buckets.iter().filter_map(|b| match &b.series_key {
            Some(BucketKey::Value { value }) => Some(value.as_str()),
            _ => None,
        });
        let names =
            lookup_display_names(state, ctx, db, &scope.logicalname, series, values).await?;
        for b in &mut buckets {
            if let Some(BucketKey::Value { value }) = &b.series_key
                && let Some(name) = names.get(value)
            {
                b.series_label = Some(name.clone());
            }
        }
    }

    Ok(StructuredAggregate {
        entity_logical_name: scope.logicalname,
        buckets,
        other,
        truncated,
        as_of,
        timezone: tz.name().to_owned(),
    })
}

/// Display names for the values of a lookup `field` (Dashboard 10/10
/// Phase 4): each target record's primary name, read under the caller's own
/// scope on the *target* entity — its read privilege, field whitelist, live
/// rows and RLS. A value the caller may not read, a target without a primary
/// name, or a field that is not a lookup gets no entry, so its label stays
/// the stored id; a name never reaches a caller who could not open the
/// record.
async fn lookup_display_names<'a>(
    state: &EngineState,
    ctx: &SecurityContext,
    db: &DbPool,
    source: &str,
    field: &str,
    values: impl Iterator<Item = &'a str>,
) -> Result<HashMap<String, String>, AppError> {
    let ids: Vec<String> = values
        .filter_map(|v| Uuid::parse_str(v).ok())
        .map(|id| id.to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let target = {
        let registry = state.entities.load();
        registry
            .get(source)
            .and_then(|meta| meta.attrs.iter().find(|a| a.logicalname == field))
            .and_then(|attr| attr.lookup_entity_ref)
            .and_then(|target_id| registry.get_by_id(target_id))
            .map(|meta| meta.logicalname.clone())
    };
    let Some(target) = target else {
        return Ok(HashMap::new());
    };
    let mut scope = match AggregateScope::build(state, ctx, &target, &[]).await {
        Ok(scope) => scope,
        Err(AppError::Forbidden | AppError::NotFound | AppError::Validation(_)) => {
            return Ok(HashMap::new());
        }
        Err(e) => return Err(e),
    };
    let Some(primary) = scope
        .primary_name_attribute
        .clone()
        .filter(|name| scope.data_type(name).is_some())
    else {
        return Ok(HashMap::new());
    };
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let ids_param = scope.bind(text_array_literal(&id_refs));
    let sql = format!(
        "SELECT t.id::text AS id, t.{}::text AS name FROM {} t {}",
        quote_ident(&primary),
        quote_ident(&scope.logicalname),
        scope.where_sql(&[format!("t.id = ANY(${ids_param}::uuid[])")])
    );
    let mut query = sqlx::query_as::<_, (String, Option<String>)>(&sql);
    for param in &scope.params {
        query = query.bind(param);
    }
    let rows = query.fetch_all(db).await.map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, name)| name.filter(|n| !n.trim().is_empty()).map(|n| (id, n)))
        .collect())
}

// ── Records behind a number (dashboard 10/10 Phase 3.1) ─────────────────────

/// Which part of a structured aggregate to list: a group (and series) key as
/// the aggregate returned it. Omitted keys mean "every row the number covers".
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DrillTarget {
    #[serde(default)]
    pub bucket_key: Option<BucketKey>,
    #[serde(default)]
    pub series_key: Option<BucketKey>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecordColumn {
    pub name: String,
    /// The whitelisted data type (`number`, `date`, `choice`, `lookup`, ...).
    pub data_type: String,
}

/// A drill-through result set: column metadata, rows, the read instant and the
/// filters that reproduce it, keyset-paged by `next_cursor`. Like
/// `query/execute`'s tabular shape it is a documented exception to
/// `CursorPage<T>` (guidelines §12): the metadata around the rows is part of
/// the contract, so it is not a plain item list.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StructuredRecords {
    pub entity_logical_name: String,
    pub columns: Vec<RecordColumn>,
    /// One JSON object per record, keyed by column name.
    #[schema(value_type = Vec<Object>)]
    pub rows: Vec<Value>,
    /// Exact: a count over the same scope and drill predicate as the rows,
    /// never an estimate.
    pub total: i64,
    pub as_of: DateTime<Utc>,
    /// Pass back as `after_id` for the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
    /// The definition, binding and bucket predicates as concrete filters, so an
    /// export reproduces exactly these rows. Absent for the Other bucket, whose
    /// NULL-aware complement no filter list can express.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drill_filters: Option<Vec<Filter>>,
}

/// A value, NULL or range key as concrete filters on `field`.
pub fn key_filters(field: &str, key: &BucketKey) -> Result<Vec<Filter>, AppError> {
    let filter = |op: &str, value: Option<Value>| Filter {
        field: field.to_owned(),
        op: op.to_owned(),
        value,
    };
    match key {
        BucketKey::Value { value } => Ok(vec![filter("eq", Some(Value::String(value.clone())))]),
        BucketKey::Null => Ok(vec![filter("is_null", None)]),
        BucketKey::Range { start, end } => Ok(vec![
            filter("gte", Some(Value::String(start.to_rfc3339()))),
            filter("lt", Some(Value::String(end.to_rfc3339()))),
        ]),
        BucketKey::Other | BucketKey::Total => Err(AppError::Validation(
            "this key cannot be expressed as filters".into(),
        )),
    }
}

/// Lists the exact records behind a structured aggregate's value, or behind
/// one of its buckets, built from the same [`AggregateScope`] (privilege,
/// whitelist, definition filters, bindings, live rows, RLS) plus the bucket
/// predicate (D-522 decision 11): a value key is typed equality on the stored
/// value, NULL is `is_null`, a time range is `gte start` and `lt end`, and
/// Other is the NULL-aware complement of the top groups the aggregate itself
/// returns for the same inputs. Keyset-paginated on `id`; `total` is an exact
/// count under the same timeout and cost ceiling (a count that exceeds the
/// ceiling is a 422, never an estimate).
#[allow(clippy::too_many_arguments)]
pub async fn run_structured_records(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &DataDefinition,
    extra_filters: &[Filter],
    tz: chrono_tz::Tz,
    drill: &DrillTarget,
    after_id: Option<Uuid>,
    page_size: i64,
) -> Result<StructuredRecords, AppError> {
    definition
        .validate_shape()
        .map_err(|errors| AppError::Validation(errors.join("; ")))?;
    let page_size = page_size.clamp(1, MAX_GROUP_BUCKETS);

    // `Some` = the drill is expressible as filters; `None` = the Other bucket.
    let mut drill_filters: Option<Vec<Filter>> = Some(Vec::new());
    let mut other_top: Option<Vec<BucketKey>> = None;
    if let Some(key) = &drill.bucket_key {
        match (&definition.group, key) {
            (None, BucketKey::Total) => {}
            (None, _) => {
                return Err(AppError::Validation(
                    "this definition has no group; its only key is total".into(),
                ));
            }
            (Some(_), BucketKey::Total) => {
                return Err(AppError::Validation(
                    "a grouped definition has no total key; omit bucket_key".into(),
                ));
            }
            (Some(group), BucketKey::Range { .. }) if group.bucket.is_none() => {
                return Err(AppError::Validation(format!(
                    "group {} has no time bucket; a range key does not apply",
                    group.field
                )));
            }
            (Some(group), BucketKey::Value { .. }) if group.bucket.is_some() => {
                return Err(AppError::Validation(format!(
                    "group {} is time-bucketed; use its range key",
                    group.field
                )));
            }
            (Some(_), BucketKey::Other) => {
                if !definition.presentation.other_bucket {
                    return Err(AppError::Validation(
                        "this definition has no Other bucket".into(),
                    ));
                }
                let aggregate =
                    run_structured_aggregate(state, ctx, definition, extra_filters, tz).await?;
                if aggregate.other.is_none() {
                    return Err(AppError::Validation(
                        "no groups fall into the Other bucket".into(),
                    ));
                }
                other_top = Some(aggregate.buckets.iter().map(|b| b.key.clone()).collect());
                drill_filters = None;
            }
            (Some(group), key) => drill_filters
                .as_mut()
                .expect("expressible so far")
                .extend(key_filters(&group.field, key)?),
        }
    }
    if let Some(key) = &drill.series_key {
        let Some(series) = &definition.series else {
            return Err(AppError::Validation(
                "this definition has no series; omit series_key".into(),
            ));
        };
        if !matches!(key, BucketKey::Value { .. } | BucketKey::Null) {
            return Err(AppError::Validation(
                "a series key is a value or null".into(),
            ));
        }
        // A series never coexists with an Other bucket (shape validation), so
        // the drill is still expressible here.
        if let Some(list) = drill_filters.as_mut() {
            list.extend(key_filters(series, key)?);
        }
    }

    let mut filters = definition.filters.clone();
    filters.extend(extra_filters.iter().cloned());
    if let Some(list) = &drill_filters {
        filters.extend(list.iter().cloned());
    }
    let mut scope = AggregateScope::build(state, ctx, &definition.source, &filters).await?;
    let mut extra_conds = Vec::new();
    if let (Some(top), Some(group)) = (&other_top, &definition.group) {
        let placeholder = scope.params.len() + 1;
        let (sql, bind) = other_complement_filter_sql(&group.field, top, placeholder);
        if let Some(bind) = bind {
            scope.bind(bind);
        }
        extra_conds.push(sql);
    }

    let mut names: Vec<String> = vec!["id".to_owned()];
    let mut add = |name: &str| {
        if !names.iter().any(|c| c == name) {
            names.push(name.to_owned());
        }
    };
    if let Some(primary) = &scope.primary_name_attribute {
        add(primary);
    }
    if let Some(group) = &definition.group {
        add(&group.field);
    }
    if let Some(series) = &definition.series {
        add(series);
    }
    for measure in &definition.measures {
        if let Some(field) = &measure.field {
            add(field);
        }
    }
    add("created_at");
    let columns: Vec<RecordColumn> = names
        .into_iter()
        .filter_map(|name| {
            scope.data_type(&name).map(|data_type| RecordColumn {
                data_type: data_type.to_owned(),
                name,
            })
        })
        .collect();

    let table = quote_ident(&scope.logicalname);
    let count_sql = format!(
        "SELECT COUNT(*) FROM {table} t {}",
        scope.where_sql(&extra_conds)
    );
    let count_params = scope.params.clone();

    let mut page_conds = extra_conds;
    if let Some(after) = after_id {
        let placeholder = scope.bind(after.to_string());
        page_conds.push(format!("t.id > ${placeholder}::uuid"));
    }
    let projection = columns
        .iter()
        .map(|c| format!("t.{}", quote_ident(&c.name)))
        .collect::<Vec<_>>()
        .join(", ");
    let rows_sql = format!(
        "SELECT row_to_json(r) FROM (SELECT {projection} FROM {table} t {} \
         ORDER BY t.id LIMIT {}) r",
        scope.where_sql(&page_conds),
        page_size + 1
    );

    let db = state.base.readonly_query_pool(ctx.user_id).await;
    let mut tx = begin_bounded(db).await?;
    let as_of: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    enforce_cost_ceiling(&mut tx, &count_sql, &count_params).await?;
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for param in &count_params {
        count = count.bind(param);
    }
    let total = count
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    enforce_cost_ceiling(&mut tx, &rows_sql, &scope.params).await?;
    let mut rows_query = sqlx::query_scalar::<_, Value>(&rows_sql);
    for param in &scope.params {
        rows_query = rows_query.bind(param);
    }
    let rows = rows_query
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;

    let (rows, more) = split_at_cap(rows, page_size);
    let next_cursor = if more {
        rows.last()
            .and_then(|row| row.get("id"))
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
    } else {
        None
    };

    Ok(StructuredRecords {
        entity_logical_name: scope.logicalname,
        columns,
        rows,
        total,
        as_of,
        next_cursor,
        drill_filters: drill_filters.map(|_| filters),
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/search/aggregate", post(aggregate))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged in `engine.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(aggregate))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_type_of_covers_every_known_field_type() {
        assert_eq!(data_type_of(1), "number");
        assert_eq!(data_type_of(5), "date");
        assert_eq!(data_type_of(6), "bool");
        assert_eq!(data_type_of(7), "choice");
        assert_eq!(data_type_of(11), "lookup");
        assert_eq!(data_type_of(12), "file");
        assert_eq!(data_type_of(999), "text");
    }

    #[test]
    fn a_number_formula_aggregates_as_a_number() {
        let attr = attome_core::AttrInfo {
            logicalname: "total".into(),
            field_type_int: 16,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            options: Some(serde_json::json!({"expression": "a", "result_type": "number"})),
        };
        assert_eq!(data_type_of_attr(&attr), "number");
        assert_eq!(data_type_of(17), "text");
        assert_eq!(data_type_of(18), "file");
    }

    /// The exact bucket-count boundary a caller relies on to distinguish
    /// "these are all the groups" from "there are more than we're showing" —
    /// wrong-by-one here is a dashboard silently under- or over-claiming
    /// completeness.
    #[test]
    fn split_at_cap_is_not_truncated_exactly_at_the_boundary() {
        let (rows, truncated) = split_at_cap(vec![1, 2], 2);
        assert_eq!(rows, vec![1, 2]);
        assert!(!truncated);
    }

    #[test]
    fn split_at_cap_truncates_and_flags_exactly_one_row_past_the_boundary() {
        let (rows, truncated) = split_at_cap(vec![1, 2, 3], 2);
        assert_eq!(rows, vec![1, 2]);
        assert!(truncated);
    }

    #[test]
    fn split_at_cap_handles_fewer_rows_than_the_cap() {
        let (rows, truncated) = split_at_cap(vec![1], 200);
        assert_eq!(rows, vec![1]);
        assert!(!truncated);
    }

    #[test]
    fn other_complement_keeps_null_rows_unless_the_null_group_was_returned() {
        let top = vec![
            BucketKey::Value {
                value: "open".into(),
            },
            BucketKey::Value {
                value: "won".into(),
            },
        ];
        let (sql, bind) = other_complement_filter_sql("status", &top, 3);
        assert_eq!(
            sql,
            "(t.\"status\" IS NULL OR NOT (t.\"status\"::text = ANY($3::text[])))"
        );
        assert_eq!(bind.as_deref(), Some(r#"{"open","won"}"#));

        let mut with_null = top.clone();
        with_null.push(BucketKey::Null);
        let (sql, _) = other_complement_filter_sql("status", &with_null, 1);
        assert!(
            sql.starts_with("(t.\"status\" IS NOT NULL AND NOT"),
            "{sql}"
        );

        let (sql, bind) = other_complement_filter_sql("status", &[BucketKey::Null], 1);
        assert_eq!(sql, "t.\"status\" IS NOT NULL");
        assert!(bind.is_none());
    }

    #[test]
    fn range_labels_use_the_local_start() {
        let tz: chrono_tz::Tz = "Asia/Bahrain".parse().unwrap();
        // 2026-02-28T21:00Z is 2026-03-01T00:00 in Bahrain (UTC+3).
        let start = "2026-02-28T21:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(range_label(start, DateBucket::Month, tz), "2026-03");
        assert_eq!(range_label(start, DateBucket::Day, tz), "2026-03-01");
        assert_eq!(range_label(start, DateBucket::Quarter, tz), "2026-Q1");
        assert_eq!(range_label(start, DateBucket::Year, tz), "2026");
        assert_eq!(range_label(start, DateBucket::Week, tz), "2026-W09");
    }

    #[test]
    fn bucket_keys_serialize_with_a_kind_tag() {
        let key = BucketKey::Value { value: "a".into() };
        assert_eq!(
            serde_json::to_value(&key).unwrap(),
            serde_json::json!({"kind": "value", "value": "a"})
        );
        assert_eq!(
            serde_json::to_value(BucketKey::Null).unwrap(),
            serde_json::json!({"kind": "null"})
        );
    }
}
