//! `query.plan` (roadmap N5-T1): turns a question the model has read into a
//! validated query model, before anything runs.
//!
//! The model never writes SQL (I-9). It states the question as a query model
//! (one entity, typed filters, an order, a row limit) and this action checks
//! it against the deployment's metadata: the entity exists and the caller
//! may read it, every named field exists on it and is readable by the caller
//! (a sensitive field needs its read grant), each operator suits the field's
//! type, and each value parses as that type (a choice value must be one of
//! its choices). A model that fails comes back as data, with every issue by
//! path, so the model can correct it; nothing is raised as an error.
//!
//! A valid model comes back normalised with a plain description for the
//! person to confirm and the exact `query.execute` arguments that run it.
//! Running stays on the stored-query path (`query.execute` with the entity's
//! default view), which owns the privilege gate, record-level scoping, the
//! read-only pool, the column whitelist and the statement timeout; this
//! action only reads metadata.

use std::future::Future;
use std::pin::Pin;

use attome_core::{AttrInfo, EngineState, EntityMeta, FieldType, Filter};
use attome_modules::MODULE_CORE;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const QUERY_PLAN: &str = "query.plan";
/// Rows a planned query returns when the model names no limit.
pub const DEFAULT_LIMIT: i64 = 50;
/// The most rows one page of `query.execute` returns.
pub const MAX_LIMIT: i64 = 200;
/// The most filters one planned query may carry.
pub const MAX_FILTERS: usize = 20;

const QUERY_PLAN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string", "description": "The person's question, as asked." },
    "entity": { "type": "string", "description": "Logical name of the entity the question is about." },
    "filters": {
      "type": "array",
      "description": "Conditions every row must meet. Values are strings; in, contains_any and contains_all take an array of strings; is_null and is_not_null take none.",
      "items": {
        "type": "object",
        "properties": {
          "field": { "type": "string" },
          "op": { "type": "string", "enum": ["eq", "neq", "gt", "gte", "lt", "lte", "contains", "starts_with", "ends_with", "in", "contains_any", "contains_all", "is_null", "is_not_null"] },
          "value": {}
        },
        "required": ["field", "op"],
        "additionalProperties": false
      }
    },
    "order_by": { "type": "string", "description": "Field to sort by." },
    "order_dir": { "type": "string", "enum": ["asc", "desc"] },
    "limit": { "type": "integer", "minimum": 1, "maximum": 200 }
  },
  "required": ["entity"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        QUERY_PLAN,
        "Turn a question about records into a checked query before running it: \
         name the entity, the filters (field, op, value), the order and a row \
         limit. Returns either the issues to fix or a description to show the \
         person and the query.execute arguments that run it. Use record.schema \
         to see an entity's fields.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[],
    )
    .input_schema(QUERY_PLAN_SCHEMA)
}

/// The query model a question becomes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryModel {
    #[serde(default)]
    pub question: Option<String>,
    pub entity: String,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub order_by: Option<String>,
    #[serde(default)]
    pub order_dir: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// One thing wrong with a query model, by JSON path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanIssue {
    pub path: String,
    pub message: String,
}

impl PlanIssue {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// A query model that passed every check.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedQuery {
    pub entity: String,
    pub filters: Vec<Filter>,
    pub order_by: Option<String>,
    pub order_dir: &'static str,
    pub limit: i64,
}

impl PlannedQuery {
    /// The `query.execute` arguments that run this query.
    pub fn execute_args(&self) -> Value {
        let mut args = json!({
            "entity": self.entity,
            "filters": self.filters,
            "order_dir": self.order_dir,
            "page_size": self.limit,
        });
        if let Some(order_by) = &self.order_by {
            args["order_by"] = json!(order_by);
        }
        args
    }

    /// What the query does, in words a person confirms.
    pub fn describe(&self) -> String {
        let mut text = format!("Up to {} {} records", self.limit, self.entity);
        if !self.filters.is_empty() {
            let conditions: Vec<String> = self.filters.iter().map(describe_filter).collect();
            text.push_str(" where ");
            text.push_str(&conditions.join(" and "));
        }
        if let Some(order_by) = &self.order_by {
            let dir = if self.order_dir == "desc" {
                "highest first"
            } else {
                "lowest first"
            };
            text.push_str(&format!(", sorted by {order_by}, {dir}"));
        }
        text.push('.');
        text
    }
}

fn describe_filter(filter: &Filter) -> String {
    let value = match &filter.value {
        Some(Value::String(s)) => format!("\"{s}\""),
        Some(Value::Array(items)) => {
            let items: Vec<String> = items
                .iter()
                .map(|v| format!("\"{}\"", v.as_str().unwrap_or_default()))
                .collect();
            format!("[{}]", items.join(", "))
        }
        _ => String::new(),
    };
    let op = match filter.op.as_str() {
        "eq" => "is",
        "neq" => "is not",
        "gt" => "is more than",
        "gte" => "is at least",
        "lt" => "is less than",
        "lte" => "is at most",
        "contains" => "contains",
        "starts_with" => "starts with",
        "ends_with" => "ends with",
        "in" => "is one of",
        "contains_any" => "has any of",
        "contains_all" => "has all of",
        "is_null" => "is empty",
        "is_not_null" => "is not empty",
        other => other,
    };
    if value.is_empty() {
        format!("{} {op}", filter.field)
    } else {
        format!("{} {op} {value}", filter.field)
    }
}

/// How a field's values are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Text,
    Number,
    Date,
    Bool,
    Choice,
    MultiChoice,
    Id,
    /// Only emptiness can be asked of it (files, images).
    Presence,
}

fn shape_of(attr: &AttrInfo) -> Option<Shape> {
    Some(match attr.field_type() {
        FieldType::Text | FieldType::RichText | FieldType::Icon | FieldType::Color => Shape::Text,
        FieldType::Number | FieldType::Currency => Shape::Number,
        FieldType::Date | FieldType::DateTime => Shape::Date,
        FieldType::Bool => Shape::Bool,
        FieldType::Choice if is_multi(attr) => Shape::MultiChoice,
        FieldType::Choice => Shape::Choice,
        FieldType::Lookup => Shape::Id,
        FieldType::File | FieldType::Image => Shape::Presence,
        // A formula is computed on read, not a stored column.
        FieldType::Formula => return None,
    })
}

fn is_multi(attr: &AttrInfo) -> bool {
    attr.options
        .as_ref()
        .and_then(|o| o.get("multi"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn choices(attr: &AttrInfo) -> Vec<String> {
    attr.options
        .as_ref()
        .and_then(|o| o.get("choices"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn ops_for(shape: Shape) -> &'static [&'static str] {
    match shape {
        Shape::Text => &[
            "eq",
            "neq",
            "contains",
            "starts_with",
            "ends_with",
            "in",
            "is_null",
            "is_not_null",
        ],
        Shape::Number | Shape::Date => &[
            "eq",
            "neq",
            "gt",
            "gte",
            "lt",
            "lte",
            "in",
            "is_null",
            "is_not_null",
        ],
        Shape::Bool => &["eq", "neq", "is_null", "is_not_null"],
        Shape::Choice | Shape::Id => &["eq", "neq", "in", "is_null", "is_not_null"],
        Shape::MultiChoice => &[
            "contains",
            "contains_any",
            "contains_all",
            "is_null",
            "is_not_null",
        ],
        Shape::Presence => &["is_null", "is_not_null"],
    }
}

/// Whether `value` is a valid single value of a field shaped `shape`.
fn scalar_ok(shape: Shape, attr: &AttrInfo, value: &str) -> Result<(), String> {
    match shape {
        Shape::Number => value
            .trim()
            .parse::<f64>()
            .map(|_| ())
            .map_err(|_| format!("\"{value}\" is not a number")),
        Shape::Date => {
            let day = value.get(..10).unwrap_or(value);
            chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
                .map(|_| ())
                .map_err(|_| format!("\"{value}\" is not a date (YYYY-MM-DD)"))
        }
        Shape::Bool => match value {
            "true" | "false" => Ok(()),
            _ => Err(format!("\"{value}\" is not true or false")),
        },
        Shape::Id => uuid::Uuid::parse_str(value)
            .map(|_| ())
            .map_err(|_| format!("\"{value}\" is not a record id")),
        Shape::Choice | Shape::MultiChoice => {
            let allowed = choices(attr);
            if allowed.is_empty() || allowed.iter().any(|c| c == value) {
                Ok(())
            } else {
                Err(format!(
                    "\"{value}\" is not one of the choices: {}",
                    allowed.join(", ")
                ))
            }
        }
        Shape::Text | Shape::Presence => Ok(()),
    }
}

fn check_filter(
    path: &str,
    filter: &Filter,
    attr: &AttrInfo,
    shape: Shape,
    issues: &mut Vec<PlanIssue>,
) {
    let allowed = ops_for(shape);
    if !allowed.contains(&filter.op.as_str()) {
        issues.push(PlanIssue::new(
            format!("{path}/op"),
            format!(
                "{} cannot be used on {}; use one of: {}",
                filter.op,
                filter.field,
                allowed.join(", ")
            ),
        ));
        return;
    }
    let value_path = format!("{path}/value");
    match filter.op.as_str() {
        "is_null" | "is_not_null" => {
            if filter.value.as_ref().is_some_and(|v| !v.is_null()) {
                issues.push(PlanIssue::new(value_path, "takes no value"));
            }
        }
        "in" | "contains_any" | "contains_all" => {
            let strings: Option<Vec<&str>> = filter
                .value
                .as_ref()
                .and_then(Value::as_array)
                .and_then(|items| items.iter().map(Value::as_str).collect());
            match strings {
                Some(values) if !values.is_empty() => {
                    for (i, value) in values.iter().enumerate() {
                        if let Err(message) = scalar_ok(shape, attr, value) {
                            issues.push(PlanIssue::new(format!("{value_path}/{i}"), message));
                        }
                    }
                }
                _ => issues.push(PlanIssue::new(
                    value_path,
                    "needs a non-empty array of strings",
                )),
            }
        }
        _ => match filter.value.as_ref().and_then(Value::as_str) {
            Some(value) => {
                if let Err(message) = scalar_ok(shape, attr, value) {
                    issues.push(PlanIssue::new(value_path, message));
                }
            }
            None => issues.push(PlanIssue::new(value_path, "needs a string value")),
        },
    }
}

/// Checks `model` against `meta`. `readable` says whether the caller may read
/// a field (a sensitive field needs its read grant). The entity-level read
/// privilege is the caller's to check before this.
pub fn plan(
    model: &QueryModel,
    meta: &EntityMeta,
    readable: impl Fn(&AttrInfo) -> bool,
) -> Result<PlannedQuery, Vec<PlanIssue>> {
    let mut issues = Vec::new();
    // A field the caller cannot read is reported as unknown, so a plan never
    // confirms that a hidden field exists.
    let field = |name: &str| {
        meta.attrs
            .iter()
            .find(|a| a.logicalname == name)
            .filter(|a| readable(a))
    };
    if model.filters.len() > MAX_FILTERS {
        issues.push(PlanIssue::new(
            "/filters",
            format!("at most {MAX_FILTERS} filters"),
        ));
    }
    let mut filters = Vec::with_capacity(model.filters.len());
    for (i, filter) in model.filters.iter().enumerate() {
        let path = format!("/filters/{i}");
        let name = filter.field.trim();
        let Some(attr) = field(name) else {
            issues.push(PlanIssue::new(
                format!("{path}/field"),
                format!("{} has no field {name}", meta.logicalname),
            ));
            continue;
        };
        let Some(shape) = shape_of(attr) else {
            issues.push(PlanIssue::new(
                format!("{path}/field"),
                format!("{name} is computed and cannot be filtered"),
            ));
            continue;
        };
        let normalised = Filter {
            field: name.to_owned(),
            op: filter.op.trim().to_owned(),
            value: match filter.op.trim() {
                "is_null" | "is_not_null" => None,
                _ => filter.value.clone(),
            },
        };
        check_filter(&path, &normalised, attr, shape, &mut issues);
        filters.push(normalised);
    }
    let order_by = match model.order_by.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(name) => match field(name) {
            Some(attr) if shape_of(attr).is_some_and(|s| s != Shape::Presence) => {
                Some(name.to_owned())
            }
            Some(_) => {
                issues.push(PlanIssue::new(
                    "/order_by",
                    format!("{name} cannot be sorted"),
                ));
                None
            }
            None => {
                issues.push(PlanIssue::new(
                    "/order_by",
                    format!("{} has no field {name}", meta.logicalname),
                ));
                None
            }
        },
    };
    let order_dir = match model.order_dir.as_deref().map(str::trim) {
        None | Some("") | Some("asc") => "asc",
        Some("desc") => "desc",
        Some(other) => {
            issues.push(PlanIssue::new(
                "/order_dir",
                format!("{other} is not asc or desc"),
            ));
            "asc"
        }
    };
    let limit = model.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        issues.push(PlanIssue::new(
            "/limit",
            format!("must be between 1 and {MAX_LIMIT}"),
        ));
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(PlannedQuery {
        entity: meta.logicalname.clone(),
        filters,
        order_by,
        order_dir,
        limit,
    })
}

pub(crate) struct QueryPlan;

impl Action for QueryPlan {
    fn id(&self) -> ActionId {
        ActionId(QUERY_PLAN)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let model: QueryModel = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid query.plan arguments: {e}")))?;
            let entity = model.entity.trim();
            if entity.is_empty() {
                return Err(AppError::Validation("entity is required".into()));
            }
            ctx.security.require(entity, "read")?;
            let registry = state.entities.load();
            let meta = registry.get(entity).ok_or(AppError::NotFound)?;
            // D-589: the plan feeds query.execute, a bulk surface, so a field
            // is offered only when the bulk gate admits it.
            let readable = |attr: &AttrInfo| {
                attome_security::field_gate::readable(
                    &ctx.security,
                    entity,
                    attr,
                    meta.primary_name_attribute.as_deref(),
                    attome_security::field_gate::Surface::Bulk,
                )
            };
            Ok(ActionResult::plain(match plan(&model, meta, readable) {
                Ok(planned) => json!({
                    "valid": true,
                    "question": model.question,
                    "description": planned.describe(),
                    "run": { "action": crate::actions::read::QUERY_EXECUTE, "args": planned.execute_args() },
                }),
                Err(issues) => json!({
                    "valid": false,
                    "issues": issues
                        .iter()
                        .map(|i| json!({ "path": i.path, "message": i.message }))
                        .collect::<Vec<_>>(),
                }),
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str, field_type_int: i32, sensitive: bool, options: Value) -> AttrInfo {
        serde_json::from_value(json!({
            "logicalname": name, "field_type_int": field_type_int, "is_required": false,
            "is_sensitive": sensitive, "is_sortable": true, "is_filterable": true,
            "options": options
        }))
        .unwrap()
    }

    fn meta() -> EntityMeta {
        let ty = |t: FieldType| t.to_int();
        serde_json::from_value(json!({
            "entity_id": uuid::Uuid::now_v7(),
            "logicalname": "deal",
            "is_append_only": false,
            "attrs": [
                attr("name", ty(FieldType::Text), false, Value::Null),
                attr("amount", ty(FieldType::Currency), false, Value::Null),
                attr("close_date", ty(FieldType::Date), false, Value::Null),
                attr("stage", ty(FieldType::Choice), false, json!({ "choices": ["open", "won", "lost"], "multi": false })),
                attr("national_id", ty(FieldType::Text), true, Value::Null),
            ],
        }))
        .unwrap()
    }

    fn model(value: Value) -> QueryModel {
        serde_json::from_value(value).unwrap()
    }

    fn open(attr: &AttrInfo) -> bool {
        !attr.is_sensitive
    }

    #[test]
    fn nl_query_a_valid_model_becomes_execute_args_and_a_description() {
        let planned = plan(
            &model(json!({
                "entity": "deal",
                "filters": [
                    { "field": "stage", "op": "eq", "value": "won" },
                    { "field": "amount", "op": "gte", "value": "10000" },
                    { "field": "close_date", "op": "gte", "value": "2026-01-01" }
                ],
                "order_by": "amount", "order_dir": "desc", "limit": 10
            })),
            &meta(),
            open,
        )
        .unwrap();
        let args = planned.execute_args();
        assert_eq!(args["entity"], "deal");
        assert_eq!(args["page_size"], 10);
        assert_eq!(args["order_by"], "amount");
        assert_eq!(args["filters"].as_array().unwrap().len(), 3);
        assert_eq!(
            planned.describe(),
            "Up to 10 deal records where stage is \"won\" and amount is at least \"10000\" \
             and close_date is at least \"2026-01-01\", sorted by amount, highest first."
        );
    }

    #[test]
    fn nl_query_every_issue_is_reported_by_path() {
        let issues = plan(
            &model(json!({
                "entity": "deal",
                "filters": [
                    { "field": "nope", "op": "eq", "value": "x" },
                    { "field": "stage", "op": "eq", "value": "pending" },
                    { "field": "amount", "op": "contains", "value": "1" },
                    { "field": "close_date", "op": "lt", "value": "yesterday" },
                    { "field": "stage", "op": "in", "value": [] }
                ],
                "order_dir": "sideways", "limit": 500
            })),
            &meta(),
            open,
        )
        .unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/filters/0/field",
                "/filters/1/value",
                "/filters/2/op",
                "/filters/3/value",
                "/filters/4/value",
                "/order_dir",
                "/limit",
            ]
        );
    }

    #[test]
    fn nl_query_a_sensitive_field_without_its_grant_is_unknown() {
        let query = model(json!({
            "entity": "deal",
            "filters": [{ "field": "national_id", "op": "eq", "value": "1" }]
        }));
        let issues = plan(&query, &meta(), open).unwrap_err();
        assert_eq!(issues[0].message, "deal has no field national_id");
        assert!(plan(&query, &meta(), |_| true).is_ok());
    }

    #[test]
    fn nl_query_emptiness_takes_no_value_and_defaults_apply() {
        let planned = plan(
            &model(json!({
                "entity": "deal",
                "filters": [{ "field": "close_date", "op": "is_null" }]
            })),
            &meta(),
            open,
        )
        .unwrap();
        assert_eq!(planned.limit, DEFAULT_LIMIT);
        assert_eq!(planned.order_dir, "asc");
        assert_eq!(planned.filters[0].value, None);
        assert_eq!(
            planned.describe(),
            "Up to 50 deal records where close_date is empty."
        );
    }
}
