//! P9-T3: the metric builder. A builder describes a metric as an entity, an
//! aggregate over one of its attributes, the date that places a record in a
//! period, filters and dimensions; [`upsert_builder_query`] turns it into a
//! stored query (through `attome_records::query_admin`'s create and
//! republish, so the publish lint, versioning and audit apply) and points the
//! metric at it (`source_kind = query`, `query_ref`, through the record
//! engine with the metric's row version).
//!
//! **The SQL** ([`spec_sql`]) answers one row, or one per dimension member,
//! with the aggregate as `value`, the column every query metric is read by.
//! The period is the metric's own (`day`, `week`, `month`, `quarter`,
//! `year`), relative to the moment the query runs: the date attribute falls
//! in `[date_trunc(period, now()), date_trunc(period, now()) + 1 period)`, so
//! a snapshot taken during a period measures that period. Identifiers are
//! quoted with `quote_ident`; filter values are typed from the attribute's
//! storage type and written as literals (a stored query carries no
//! parameters): numbers as numbers, dates and lookups parsed first, text
//! quoted with doubled quotes. Only live rows count.
//!
//! The query names no single entity (as every query metric's), so it runs as
//! an aggregate under the principal's whole-entity read; its relations are
//! still checked at publish.
//!
//! **What may be built** ([`validate_spec`]): attributes of the entity (and,
//! for the date, its `created_at` or `modified_at`); a numeric measure for
//! `sum`, `avg`, `median`, `min` and `max`; at most three dimensions; no
//! sensitive attribute anywhere, since the metric runs under its service
//! principal and its value is shown to everyone who may read the metric.

use attome_core::{AttrInfo, EngineState, EntityMeta, EntityMetaRegistry, FieldType, quote_ident};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The aggregates a builder may use.
pub const AGGREGATES: &[&str] = &["count", "sum", "avg", "median", "min", "max"];

/// The filter operators a builder may use.
pub const OPERATORS: &[&str] = &[
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "is_null",
    "is_not_null",
];

/// The most dimensions, filters and `in` values one builder holds.
const MAX_DIMENSIONS: usize = 3;
const MAX_FILTERS: usize = 10;
const MAX_IN_VALUES: usize = 100;

/// The system date columns a builder may window by.
const SYSTEM_DATES: &[&str] = &["created_at", "modified_at"];

/// The stored query's name for a metric, which marks it as the builder's.
pub fn builder_query_name(metric_id: Uuid) -> String {
    format!("Metric builder {metric_id}")
}

/// A metric described by its parts.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricSpec {
    pub entity_logicalname: String,
    /// `count`, `sum`, `avg`, `median`, `min` or `max`.
    pub aggregate: String,
    /// The attribute aggregated; optional for `count` (every record).
    #[serde(default)]
    pub measure_attribute: Option<String>,
    /// The date that places a record in a period: a date or date-time
    /// attribute, or `created_at` / `modified_at`.
    pub date_attribute: String,
    #[serde(default)]
    pub filters: Vec<SpecFilter>,
    /// Attributes the value is broken down by, at most three.
    #[serde(default)]
    pub dimension_attributes: Vec<String>,
}

/// One filter of a builder.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SpecFilter {
    pub attribute: String,
    /// `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `is_null` or `is_not_null`.
    pub op: String,
    /// A scalar; a list for `in`; none for `is_null` and `is_not_null`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub value: Option<Value>,
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::Validation(message.into())
}

/// The attribute `name` of `entity`, refusing a sensitive one.
fn attribute<'a>(entity: &'a EntityMeta, name: &str) -> Result<&'a AttrInfo, AppError> {
    let attr = entity
        .attrs
        .iter()
        .find(|a| a.logicalname == name)
        .ok_or_else(|| {
            invalid(format!(
                "{name:?} is not an attribute of {}",
                entity.logicalname
            ))
        })?;
    if attr.is_read_gated() {
        return Err(invalid(format!(
            "{name:?} is sensitive; a metric is shown to everyone who may read it"
        )));
    }
    Ok(attr)
}

fn is_numeric(attr: &AttrInfo) -> bool {
    matches!(attr.storage_type(), FieldType::Number | FieldType::Currency)
}

/// Checks `spec` against the live metadata: 422 naming what is wrong.
pub fn validate_spec(spec: &MetricSpec, registry: &EntityMetaRegistry) -> Result<(), AppError> {
    let entity = registry
        .get(&spec.entity_logicalname)
        .ok_or_else(|| invalid(format!("{:?} is not an entity", spec.entity_logicalname)))?;
    if !AGGREGATES.contains(&spec.aggregate.as_str()) {
        return Err(invalid(format!(
            "aggregate must be one of {}",
            AGGREGATES.join(", ")
        )));
    }
    match (&spec.measure_attribute, spec.aggregate.as_str()) {
        (None, "count") => {}
        (None, aggregate) => {
            return Err(invalid(format!("{aggregate} needs a measure_attribute")));
        }
        (Some(measure), aggregate) => {
            let attr = attribute(entity, measure)?;
            if aggregate != "count" && !is_numeric(attr) {
                return Err(invalid(format!(
                    "{aggregate} needs a numeric measure; {measure:?} is not a number"
                )));
            }
        }
    }
    if !SYSTEM_DATES.contains(&spec.date_attribute.as_str()) {
        let date = attribute(entity, &spec.date_attribute)?;
        if !matches!(date.storage_type(), FieldType::Date | FieldType::DateTime) {
            return Err(invalid(format!("{:?} is not a date", spec.date_attribute)));
        }
    }
    if spec.dimension_attributes.len() > MAX_DIMENSIONS {
        return Err(invalid(format!("at most {MAX_DIMENSIONS} dimensions")));
    }
    for dimension in &spec.dimension_attributes {
        attribute(entity, dimension)?;
    }
    if spec.filters.len() > MAX_FILTERS {
        return Err(invalid(format!("at most {MAX_FILTERS} filters")));
    }
    for filter in &spec.filters {
        filter_sql(entity, filter)?;
    }
    Ok(())
}

/// `value` as a SQL literal of `attr`'s storage type.
fn literal(attr: &AttrInfo, value: &Value) -> Result<String, AppError> {
    let wrong = || {
        invalid(format!(
            "{value} is not a valid value for {:?}",
            attr.logicalname
        ))
    };
    match attr.storage_type() {
        FieldType::Number | FieldType::Currency => value
            .as_f64()
            .filter(|n| n.is_finite())
            .map(|n| format!("{n}"))
            .ok_or_else(wrong),
        FieldType::Bool => value.as_bool().map(|b| b.to_string()).ok_or_else(wrong),
        FieldType::Date => value
            .as_str()
            .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
            .map(|d| format!("DATE '{d}'"))
            .ok_or_else(wrong),
        FieldType::DateTime => value
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| format!("TIMESTAMPTZ '{}'", d.to_rfc3339()))
            .ok_or_else(wrong),
        FieldType::Lookup => value
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .map(|id| format!("'{id}'::uuid"))
            .ok_or_else(wrong),
        _ => {
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return Err(wrong()),
            };
            if text.contains('\0') || text.chars().count() > 1_000 {
                return Err(wrong());
            }
            Ok(format!("'{}'", text.replace('\'', "''")))
        }
    }
}

/// One filter as a condition on `t`.
fn filter_sql(entity: &EntityMeta, filter: &SpecFilter) -> Result<String, AppError> {
    let attr = attribute(entity, &filter.attribute)?;
    let column = format!("t.{}", quote_ident(&attr.logicalname));
    let op = filter.op.as_str();
    if !OPERATORS.contains(&op) {
        return Err(invalid(format!(
            "filter op must be one of {}",
            OPERATORS.join(", ")
        )));
    }
    if matches!(op, "is_null" | "is_not_null") {
        if filter.value.is_some() {
            return Err(invalid(format!("{op} takes no value")));
        }
        let not = if op == "is_null" { "" } else { " NOT" };
        return Ok(format!("{column} IS{not} NULL"));
    }
    let value = filter
        .value
        .as_ref()
        .ok_or_else(|| invalid(format!("{op} needs a value")))?;
    if op == "in" {
        let items = value
            .as_array()
            .filter(|items| !items.is_empty() && items.len() <= MAX_IN_VALUES)
            .ok_or_else(|| invalid(format!("in takes a list of 1 to {MAX_IN_VALUES} values")))?;
        let literals = items
            .iter()
            .map(|v| literal(attr, v))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(format!("{column} IN ({})", literals.join(", ")));
    }
    let symbol = match op {
        "eq" => "=",
        "neq" => "<>",
        "gt" => ">",
        "gte" => ">=",
        "lt" => "<",
        _ => "<=",
    };
    Ok(format!("{column} {symbol} {}", literal(attr, value)?))
}

/// The aggregate expression, as `float8`.
fn aggregate_sql(spec: &MetricSpec) -> String {
    let measure = spec
        .measure_attribute
        .as_deref()
        .map(|m| format!("t.{}", quote_ident(m)));
    match (spec.aggregate.as_str(), measure) {
        ("count", None) => "count(*)::float8".to_owned(),
        ("count", Some(m)) => format!("count({m})::float8"),
        ("sum", Some(m)) => format!("coalesce(sum({m}), 0)::float8"),
        ("median", Some(m)) => {
            format!("(percentile_cont(0.5) WITHIN GROUP (ORDER BY {m}))::float8")
        }
        (aggregate, Some(m)) => format!("{aggregate}({m})::float8"),
        (_, None) => "count(*)::float8".to_owned(),
    }
}

/// The stored query for `spec` over `entity`, windowed by `period`. `spec`
/// must have passed [`validate_spec`].
pub fn spec_sql(spec: &MetricSpec, entity: &EntityMeta, period: &str) -> Result<String, AppError> {
    let unit = match period {
        "day" | "week" | "month" | "quarter" | "year" => period,
        other => {
            return Err(invalid(format!(
                "a builder metric needs a calendar period, not {other:?}"
            )));
        }
    };
    let date = format!("t.{}", quote_ident(&spec.date_attribute));
    let mut conditions: Vec<String> = attome_core::live_row_predicate("t", entity.is_append_only)
        .into_iter()
        .collect();
    conditions.push(format!("{date} >= date_trunc('{unit}', now())"));
    conditions.push(format!(
        "{date} < date_trunc('{unit}', now()) + interval '1 {unit}'"
    ));
    for filter in &spec.filters {
        conditions.push(filter_sql(entity, filter)?);
    }
    let dimensions: Vec<String> = spec
        .dimension_attributes
        .iter()
        .map(|d| format!("t.{}", quote_ident(d)))
        .collect();
    let mut select = vec![format!("{} AS value", aggregate_sql(spec))];
    select.extend(
        spec.dimension_attributes
            .iter()
            .zip(&dimensions)
            .map(|(name, column)| format!("{column}::text AS {}", quote_ident(name))),
    );
    let mut sql = format!(
        "SELECT {} FROM {} t WHERE {}",
        select.join(", "),
        quote_ident(&entity.logicalname),
        conditions.join(" AND ")
    );
    if !dimensions.is_empty() {
        sql.push_str(&format!(" GROUP BY {}", dimensions.join(", ")));
    }
    Ok(sql)
}

/// P7-T2: keeps the spec a builder metric was last built from. The stored
/// query holds only the aggregate, so the spec is what lets a drill list the
/// records behind the value. One row per metric, replaced on every build.
pub async fn store_spec(
    db: &attome_db::DbPool,
    metric_id: Uuid,
    spec: &MetricSpec,
    actor: Uuid,
) -> Result<(), AppError> {
    let spec = serde_json::to_value(spec).map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO metric_builder_spec (metric_ref, spec, updated_by) VALUES ($1, $2, $3) \
         ON CONFLICT (metric_ref) DO UPDATE \
            SET spec = EXCLUDED.spec, updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(metric_id)
    .bind(spec)
    .bind(actor)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// P7-T2: the spec of a builder metric whose value still comes from the
/// builder's own query; `None` for any other metric, or once someone pointed
/// it at a different query.
pub async fn current_spec(
    db: &attome_db::DbPool,
    metric_id: Uuid,
) -> Result<Option<MetricSpec>, AppError> {
    let spec: Option<Value> = sqlx::query_scalar(
        "SELECT s.spec FROM metric_builder_spec s \
           JOIN dashboard_metric_definition m ON m.id = s.metric_ref \
           JOIN sql_query q ON q.id::text = m.query_ref \
          WHERE s.metric_ref = $1 AND m.source_kind = 'query' \
            AND q.name = $2 AND q.is_active = true",
    )
    .bind(metric_id)
    .bind(builder_query_name(metric_id))
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(spec.and_then(|spec| serde_json::from_value(spec).ok()))
}

/// P7-T2: the records `spec` counts in the period `[start, end)`, as a
/// structured data definition over its entity: its filters plus the date
/// window, measured by its aggregate. Pure.
pub fn spec_definition(
    spec: &MetricSpec,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<attome_core::data_definition::DataDefinition, AppError> {
    let mut filters: Vec<Value> = spec
        .filters
        .iter()
        .map(|f| json!({ "field": f.attribute, "op": f.op, "value": f.value }))
        .collect();
    filters.push(json!({ "field": spec.date_attribute, "op": "gte", "value": start.to_string() }));
    filters.push(json!({ "field": spec.date_attribute, "op": "lt", "value": end.to_string() }));
    let mut measure = json!({ "aggregation": spec.aggregate });
    if let Some(field) = &spec.measure_attribute {
        measure["field"] = json!(field);
    }
    serde_json::from_value(json!({
        "source": spec.entity_logicalname,
        "measures": [measure],
        "filters": filters,
    }))
    .map_err(|e| invalid(format!("the metric's builder spec cannot be listed: {e}")))
}

/// Creates or republishes the metric's builder query from `spec` and points
/// the metric at it, as `ctx` (who holds the metric's update privilege).
/// Answers the stored query's id.
pub async fn upsert_builder_query(
    state: &EngineState,
    ctx: &SecurityContext,
    metric_id: Uuid,
    spec: &MetricSpec,
) -> Result<Uuid, AppError> {
    let metric = crate::metric::fetch_metric(&state.base.db, metric_id).await?;
    let sql = {
        let registry = state.entities.load();
        validate_spec(spec, &registry)?;
        let entity = registry
            .get(&spec.entity_logicalname)
            .ok_or_else(|| invalid("no such entity"))?;
        spec_sql(spec, entity, &metric.period)?
    };
    let name = builder_query_name(metric_id);
    // The metric's current query, when the builder made it.
    let existing: Option<Uuid> = match metric.query_ref.as_deref().map(Uuid::parse_str) {
        Some(Ok(query_id)) => sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM sql_query WHERE id = $1 AND name = $2 AND is_active = true",
        )
        .bind(query_id)
        .bind(&name)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        _ => None,
    };
    let query_id = match existing {
        Some(query_id) => {
            let body = serde_json::from_value(json!({
                "sql_query": sql,
                "required_privilege": crate::principal::METRIC_SNAPSHOT_PRIVILEGE,
            }))
            .map_err(AppError::internal)?;
            attome_records::query_admin::do_update_query(state, query_id, ctx.user_id, body, None)
                .await?;
            query_id
        }
        None => {
            let body = serde_json::from_value(json!({
                "name": name,
                "sql_query": sql,
                "required_privilege": crate::principal::METRIC_SNAPSHOT_PRIVILEGE,
                "is_report": true,
            }))
            .map_err(AppError::internal)?;
            let (_, detail) =
                attome_records::query_admin::do_create_query(state, ctx.user_id, body).await?;
            serde_json::to_value(&detail)
                .ok()
                .and_then(|d| d.get("id").and_then(Value::as_str).map(str::to_owned))
                .and_then(|id| Uuid::parse_str(&id).ok())
                .ok_or_else(|| AppError::internal("the created query has no id"))?
        }
    };
    if metric.source_kind != "query" || metric.query_ref.as_deref() != Some(&query_id.to_string()) {
        let row_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM dashboard_metric_definition WHERE id = $1")
                .bind(metric_id)
                .fetch_one(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            "dashboard_metric_definition",
            metric_id,
            row_version,
            json!({ "source_kind": "query", "query_ref": query_id.to_string() }),
        )
        .await?;
    }
    store_spec(&state.base.db, metric_id, spec, ctx.user_id).await?;
    Ok(query_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_lists_its_records_over_the_period() {
        let spec = MetricSpec {
            entity_logicalname: "deal".into(),
            aggregate: "sum".into(),
            measure_attribute: Some("amount".into()),
            date_attribute: "closed_on".into(),
            filters: vec![SpecFilter {
                attribute: "status".into(),
                op: "eq".into(),
                value: Some(json!("won")),
            }],
            dimension_attributes: vec![],
        };
        let day = |d: &str| NaiveDate::parse_from_str(d, "%Y-%m-%d").unwrap();
        let definition = spec_definition(&spec, day("2026-10-01"), day("2026-11-01")).unwrap();
        assert_eq!(definition.source, "deal");
        assert_eq!(definition.measures.len(), 1);
        let filters: Vec<(String, String, Option<Value>)> = definition
            .filters
            .iter()
            .map(|f| (f.field.clone(), f.op.clone(), f.value.clone()))
            .collect();
        assert_eq!(
            filters,
            vec![
                ("status".into(), "eq".into(), Some(json!("won"))),
                ("closed_on".into(), "gte".into(), Some(json!("2026-10-01"))),
                ("closed_on".into(), "lt".into(), Some(json!("2026-11-01"))),
            ]
        );
    }

    fn attr(name: &str, field_type: i32, sensitive: bool) -> AttrInfo {
        serde_json::from_value(json!({
            "logicalname": name,
            "field_type_int": field_type,
            "is_sensitive": sensitive,
            "is_sortable": true,
            "is_filterable": true,
        }))
        .unwrap()
    }

    // `FieldType::from_int`: 1 is a number, 5 a date, 0 text.
    const NUMBER: i32 = 1;
    const DATE: i32 = 5;
    const TEXT: i32 = 0;

    fn deal() -> EntityMeta {
        EntityMeta {
            entity_id: Uuid::nil(),
            logicalname: "deal".into(),
            attrs: vec![
                attr("amount", NUMBER, false),
                attr("region", TEXT, false),
                attr("closed_on", DATE, false),
                attr("salary", NUMBER, true),
                attr("Odd \"name", TEXT, false),
            ],
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    fn spec(aggregate: &str, measure: Option<&str>) -> MetricSpec {
        MetricSpec {
            entity_logicalname: "deal".into(),
            aggregate: aggregate.into(),
            measure_attribute: measure.map(str::to_owned),
            date_attribute: "closed_on".into(),
            filters: Vec::new(),
            dimension_attributes: Vec::new(),
        }
    }

    #[test]
    fn spec_sql_quotes_identifiers() {
        let mut s = spec("sum", Some("amount"));
        s.dimension_attributes = vec!["Odd \"name".into()];
        s.filters = vec![
            SpecFilter {
                attribute: "region".into(),
                op: "eq".into(),
                value: Some(json!("O'Neil")),
            },
            SpecFilter {
                attribute: "amount".into(),
                op: "gte".into(),
                value: Some(json!(100)),
            },
        ];
        let sql = spec_sql(&s, &deal(), "month").unwrap();
        assert!(sql.starts_with("SELECT coalesce(sum(t.\"amount\"), 0)::float8 AS value, t.\"Odd \"\"name\"::text AS \"Odd \"\"name\" FROM \"deal\" t WHERE"), "{sql}");
        assert!(
            sql.contains("t.\"closed_on\" >= date_trunc('month', now())"),
            "{sql}"
        );
        assert!(sql.contains("t.\"region\" = 'O''Neil'"), "{sql}");
        assert!(sql.contains("t.\"amount\" >= 100"), "{sql}");
        assert!(sql.ends_with("GROUP BY t.\"Odd \"\"name\""), "{sql}");
        assert!(spec_sql(&s, &deal(), "fortnight").is_err());
    }

    #[test]
    fn sum_over_text_attribute_is_rejected() {
        let registry = EntityMetaRegistry::from_entities(vec![deal()]);
        assert!(matches!(
            validate_spec(&spec("sum", Some("region")), &registry),
            Err(AppError::Validation(_))
        ));
        assert!(validate_spec(&spec("sum", Some("amount")), &registry).is_ok());
        assert!(validate_spec(&spec("count", None), &registry).is_ok());
        assert!(
            validate_spec(&spec("avg", None), &registry).is_err(),
            "avg needs a measure"
        );
        assert!(
            validate_spec(&spec("sum", Some("salary")), &registry).is_err(),
            "sensitive"
        );
        let mut by_text_date = spec("count", None);
        by_text_date.date_attribute = "region".into();
        assert!(validate_spec(&by_text_date, &registry).is_err());
        let mut by_created = spec("count", None);
        by_created.date_attribute = "created_at".into();
        assert!(validate_spec(&by_created, &registry).is_ok());
        let mut bad_value = spec("count", None);
        bad_value.filters = vec![SpecFilter {
            attribute: "amount".into(),
            op: "gt".into(),
            value: Some(json!("1; DROP TABLE deal")),
        }];
        assert!(validate_spec(&bad_value, &registry).is_err());
    }
}
