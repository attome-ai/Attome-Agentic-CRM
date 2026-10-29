//! `view.plan` (roadmap A13-T5): a view from plain language. The model
//! reads the person's sentence ("deals closing this month over 50k") and
//! states it as a query model with a name and columns, as for `query.plan`;
//! this action checks it the same way ([`super::nl_query::plan`]) and
//! answers the personal view it would save, with a description for the
//! person to confirm. It saves nothing: after the person agrees, the view is
//! saved through `POST /api/v1/views` (a personal view on the entity's
//! default query, D-429), which checks it again.
//!
//! Filters may use the dynamic values (`@me`, `@my_team`, `@my_unit`,
//! `@today`, `@this_month`, `@last_n_days(n)`), which the view keeps as
//! written and expands for whoever runs it (A13-T1).

use std::future::Future;
use std::pin::Pin;

use attome_core::{AttrInfo, EngineState, EntityMeta};
use attome_modules::MODULE_CORE;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::nl_query::{PlannedQuery, QueryModel, plan};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const VIEW_PLAN: &str = "view.plan";
/// The most columns a planned view lists.
pub const MAX_COLUMNS: usize = 30;

const VIEW_PLAN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string", "description": "The person's sentence, as said." },
    "name": { "type": "string", "description": "The view's name, short." },
    "entity": { "type": "string", "description": "Logical name of the entity the view lists." },
    "columns": { "type": "array", "items": { "type": "string" }, "description": "Fields to show, in order; a related field through a lookup is lookup.field." },
    "filters": {
      "type": "array",
      "description": "Conditions every row must meet. Values are strings; a date may be @today, @this_month or @last_n_days(n), a person @me, a team @my_team, a unit @my_unit.",
      "items": {
        "type": "object",
        "properties": {
          "field": { "type": "string" },
          "op": { "type": "string" },
          "value": {}
        },
        "required": ["field", "op"],
        "additionalProperties": false
      }
    }
  },
  "required": ["name", "entity"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        VIEW_PLAN,
        "Turn a sentence describing a list of records into a personal view to \
         save: name it, name the entity, the columns and the filters (dynamic \
         values such as @this_month or @me allowed). Returns the \
         issues to fix, or a description to show the person and the view body; \
         save it with POST /api/v1/views only after the person agrees.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[],
    )
    .input_schema(VIEW_PLAN_SCHEMA)
}

/// One problem with a view model, by JSON path.
fn issue(path: &str, message: impl Into<String>) -> Value {
    json!({ "path": path, "message": message.into() })
}

/// The columns, checked: each a field the caller may read, or a path whose
/// first step is a lookup the caller may read (the rest is checked when the
/// view runs). Pure.
fn check_columns(
    columns: &[String],
    meta: &EntityMeta,
    readable: impl Fn(&AttrInfo) -> bool,
) -> Result<Vec<String>, Vec<Value>> {
    let mut issues = Vec::new();
    if columns.len() > MAX_COLUMNS {
        issues.push(issue("/columns", format!("at most {MAX_COLUMNS} columns")));
    }
    let mut out = Vec::with_capacity(columns.len());
    for (i, column) in columns.iter().enumerate() {
        let name = column.trim();
        let (first, related) = match name.split_once('.') {
            Some((first, _)) => (first, true),
            None => (name, false),
        };
        let ok = meta.attrs.iter().any(|a| {
            a.logicalname == first
                && readable(a)
                && (!related || a.field_type() == attome_core::FieldType::Lookup)
        });
        if ok {
            if !out.iter().any(|c| c == name) {
                out.push(name.to_owned());
            }
        } else {
            issues.push(issue(
                &format!("/columns/{i}"),
                format!("{} has no field {name}", meta.logicalname),
            ));
        }
    }
    if issues.is_empty() {
        Ok(out)
    } else {
        Err(issues)
    }
}

/// The `POST /api/v1/views` body the plan becomes. Pure.
pub fn view_body(planned: &PlannedQuery, name: &str, columns: &[String], query: Uuid) -> Value {
    let mut metadata = Map::new();
    metadata.insert("filters".into(), json!(planned.filters));
    json!({
        "name": name.trim(),
        "entity": planned.entity,
        "sql_query_ref": query,
        "kind": "list",
        "table_definition": columns.iter().map(|c| json!({ "name": c })).collect::<Vec<_>>(),
        "view_metadata": Value::Object(metadata),
    })
}

/// The arguments with the view's own keys taken out, as a `query.plan`
/// model.
fn split_args(args: &Value) -> Result<(String, Vec<String>, QueryModel), AppError> {
    let invalid = |e: String| AppError::Validation(format!("invalid view.plan arguments: {e}"));
    let mut rest = args
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("an object is required".into()))?;
    let name = rest
        .remove("name")
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| invalid("name is required".into()))?;
    let columns: Vec<String> = match rest.remove("columns") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => serde_json::from_value(v).map_err(|e| invalid(e.to_string()))?,
    };
    let model: QueryModel =
        serde_json::from_value(Value::Object(rest)).map_err(|e| invalid(e.to_string()))?;
    Ok((name, columns, model))
}

pub(crate) struct ViewPlan;

impl Action for ViewPlan {
    fn id(&self) -> ActionId {
        ActionId(VIEW_PLAN)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let (name, columns, mut model) = split_args(args)?;
            // A view keeps no order of its own: the list it opens sorts.
            model.order_by = None;
            model.order_dir = None;
            let entity = model.entity.trim().to_owned();
            if entity.is_empty() {
                return Err(AppError::Validation("entity is required".into()));
            }
            ctx.security.require(&entity, "read")?;
            let (planned, columns) = {
                let registry = state.entities.load();
                let meta = registry.get(&entity).ok_or(AppError::NotFound)?;
                let readable = |attr: &AttrInfo| {
                    attome_security::field_gate::readable(
                        &ctx.security,
                        &entity,
                        attr,
                        meta.primary_name_attribute.as_deref(),
                        attome_security::field_gate::Surface::Bulk,
                    )
                };
                let planned = plan(&model, meta, readable);
                let checked = check_columns(&columns, meta, readable);
                match (planned, checked) {
                    (Ok(planned), Ok(columns)) => (planned, columns),
                    (planned, checked) => {
                        let mut issues: Vec<Value> = planned
                            .err()
                            .unwrap_or_default()
                            .iter()
                            .map(|i| issue(&i.path, i.message.clone()))
                            .collect();
                        issues.extend(checked.err().unwrap_or_default());
                        return Ok(ActionResult::plain(json!({
                            "valid": false,
                            "issues": issues,
                        })));
                    }
                }
            };
            // A personal view runs the entity's default query (D-429).
            let query: Option<Uuid> = sqlx::query_scalar(
                "SELECT v.sql_query_ref FROM view v \
                 JOIN entity_info e ON e.id = v.entity_logical_name \
                 JOIN sql_query q ON q.id = v.sql_query_ref \
                 WHERE e.logicalname = $1 AND v.is_default = true AND v.is_active = true \
                   AND q.is_active = true \
                 LIMIT 1",
            )
            .bind(&entity)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let Some(query) = query else {
                return Ok(ActionResult::plain(json!({
                    "valid": false,
                    "issues": [issue("/entity", format!("{entity} has no default list to build a view on"))],
                })));
            };
            let mut description = format!("A view \"{}\": {}", name.trim(), planned.describe());
            if !columns.is_empty() {
                description.push_str(&format!(" Columns: {}.", columns.join(", ")));
            }
            Ok(ActionResult::plain(json!({
                "valid": true,
                "question": model.question,
                "description": description,
                "view": view_body(&planned, &name, &columns, query),
                "save": { "method": "POST", "path": "/api/v1/views" },
                "confirm": "Show the description and save the view only after the person agrees.",
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        serde_json::from_value(json!({
            "logicalname": name, "field_type_int": field_type_int, "is_required": false,
            "is_sensitive": false, "is_sortable": true, "is_filterable": true,
        }))
        .unwrap()
    }

    fn deals() -> EntityMeta {
        EntityMeta {
            entity_id: Uuid::now_v7(),
            logicalname: "opportunity".into(),
            attrs: vec![
                attr("name", 3),
                attr("amount", 2),
                attr("close_date", 5),
                attr("owner_user", 11),
                attr("account_ref", 11),
            ],
            is_append_only: false,
            primary_name_attribute: Some("name".into()),
        }
    }

    /// What a model answers for "deals closing this month over 50k".
    fn sentence() -> Value {
        json!({
            "question": "deals closing this month over 50k",
            "name": "Big deals this month",
            "entity": "opportunity",
            "columns": ["name", "amount", "close_date", "account_ref.name"],
            "filters": [
                { "field": "close_date", "op": "eq", "value": "@this_month" },
                { "field": "amount", "op": "gt", "value": "50000" },
            ],
        })
    }

    #[test]
    fn nl_view_turns_a_sentence_into_a_view_body() {
        let (name, columns, model) = split_args(&sentence()).unwrap();
        let meta = deals();
        let planned = plan(&model, &meta, |_| true).expect("a valid plan");
        let columns = check_columns(&columns, &meta, |_| true).expect("valid columns");
        let query = Uuid::now_v7();
        let body = view_body(&planned, &name, &columns, query);
        assert_eq!(body["name"], "Big deals this month");
        assert_eq!(body["entity"], "opportunity");
        assert_eq!(body["kind"], "list");
        assert_eq!(body["sql_query_ref"], json!(query));
        assert_eq!(body["table_definition"][3]["name"], "account_ref.name");
        let filters = &body["view_metadata"]["filters"];
        assert_eq!(filters[0]["value"], "@this_month", "kept as written");
        assert_eq!(filters[1]["op"], "gt");
    }

    #[test]
    fn nl_view_reports_unknown_columns_and_needs_a_name() {
        let meta = deals();
        let issues = check_columns(
            &["name".into(), "missing".into(), "amount.x".into()],
            &meta,
            |_| true,
        )
        .unwrap_err();
        assert_eq!(issues.len(), 2, "{issues:?}");
        assert_eq!(issues[0]["path"], "/columns/1");
        // A field the caller may not read is unknown too.
        assert!(check_columns(&["amount".into()], &meta, |a| a.logicalname != "amount").is_err());
        let mut no_name = sentence();
        no_name.as_object_mut().unwrap().remove("name");
        assert!(split_args(&no_name).is_err());
    }
}
