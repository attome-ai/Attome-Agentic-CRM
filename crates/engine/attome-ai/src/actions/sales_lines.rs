//! Opportunity line actions (roadmap D6-T12).
//!
//! `sales.opportunity_line.add`, `.update` and `.remove` call the same
//! functions as the line routes (`attome_sales::opportunity_lines`), so an
//! agent's change is priced, locked, version-checked and audited exactly
//! like a person's, as the calling user; each is a write that an agent must
//! have confirmed. `sales.products.suggest` reads which products were most
//! often won together with the deal's products in the last 24 months and
//! returns them as a draft list; it writes nothing.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const LINE_ADD: &str = "sales.opportunity_line.add";
pub const LINE_UPDATE: &str = "sales.opportunity_line.update";
pub const LINE_REMOVE: &str = "sales.opportunity_line.remove";
pub const PRODUCTS_SUGGEST: &str = "sales.products.suggest";

/// Products one suggestion lists.
pub const MAX_SUGGESTIONS: i64 = 10;

/// The line fields the add and update schemas share, as a literal.
macro_rules! line_fields {
    () => {
        r#"
    "quantity": { "type": "string", "description": "Decimal text; 1 when absent." },
    "sales_price": { "type": "string" },
    "discount_percent": { "type": "string" },
    "discount_amount": { "type": "string" },
    "line_kind": { "type": "string", "enum": ["one_time", "recurring"] },
    "recurrence": { "type": "string", "enum": ["monthly", "yearly"] },
    "term_months": { "type": "integer" },
    "description": { "type": "string" }"#
    };
}

const ADD_SCHEMA: &str = concat!(
    r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" },
    "row_version": { "type": "integer", "description": "The deal's current row_version (record.get)." },
    "product_ref": { "type": "string", "format": "uuid", "description": "A product on the deal's price list." },"#,
    line_fields!(),
    r#"
  },
  "required": ["opportunity_id", "row_version", "product_ref"],
  "additionalProperties": false
}"#
);

const UPDATE_SCHEMA: &str = concat!(
    r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" },
    "row_version": { "type": "integer" },
    "line_id": { "type": "string", "format": "uuid" },"#,
    line_fields!(),
    r#"
  },
  "required": ["opportunity_id", "row_version", "line_id"],
  "additionalProperties": false
}"#
);

const REMOVE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" },
    "row_version": { "type": "integer" },
    "line_id": { "type": "string", "format": "uuid" }
  },
  "required": ["opportunity_id", "row_version", "line_id"],
  "additionalProperties": false
}"#;

const SUGGEST_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" }
  },
  "required": ["opportunity_id"],
  "additionalProperties": false
}"#;

fn write(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Reversible,
        Effect::Write,
        RetryClass::RequiresKey,
        MODULE_SALES,
        &[],
    )
    .input_schema(schema)
    .agent_must_confirm()
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        write(
            LINE_ADD,
            "Add a product line to a deal. The product must be on the deal's price list; \
             its list price comes from the price list. The whole deal is repriced. Give the \
             deal's current row_version.",
            ADD_SCHEMA,
        ),
        write(
            LINE_UPDATE,
            "Change a deal line's quantity, price, discount or term; the deal is repriced. \
             Give the deal's current row_version.",
            UPDATE_SCHEMA,
        ),
        ActionDescriptor::new(
            LINE_REMOVE,
            "Remove a line from a deal; the deal is repriced and the line's splits removed. \
             Give the deal's current row_version.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_SALES,
            &[],
        )
        .input_schema(REMOVE_SCHEMA)
        .agent_must_confirm(),
        ActionDescriptor::new(
            PRODUCTS_SUGGEST,
            "Suggest products for a deal: those most often won together with its current \
             products in the last 24 months. A draft list only; nothing is added.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_SALES,
            &[],
        )
        .input_schema(SUGGEST_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(LineAdd),
        Box::new(LineUpdate),
        Box::new(LineRemove),
        Box::new(ProductsSuggest),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

fn version_arg(args: &Value) -> Result<i64, AppError> {
    args["row_version"]
        .as_i64()
        .ok_or_else(|| AppError::Validation("row_version is required".into()))
}

fn result(
    changed: attome_sales::opportunity_lines::SalesLinesChanged,
) -> Result<ActionResult, AppError> {
    Ok(ActionResult::plain(
        serde_json::to_value(changed).map_err(AppError::internal)?,
    ))
}

struct LineAdd;

impl Action for LineAdd {
    fn id(&self) -> ActionId {
        ActionId(LINE_ADD)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("opportunity", "update")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let version = version_arg(args)?;
            let body: attome_sales::opportunity_lines::SalesLineBody =
                serde_json::from_value(args.clone())
                    .map_err(|e| AppError::Validation(format!("bad line: {e}")))?;
            result(
                attome_sales::opportunity_lines::add_line(
                    state,
                    &ctx.security,
                    opportunity,
                    version,
                    &body,
                )
                .await?,
            )
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(
            json!({ "action": LINE_ADD, "opportunity_id": args["opportunity_id"],
                     "product_ref": args["product_ref"], "quantity": args["quantity"] }),
        )
    }
}

struct LineUpdate;

impl Action for LineUpdate {
    fn id(&self) -> ActionId {
        ActionId(LINE_UPDATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("opportunity", "update")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let line = uuid_arg(args, "line_id")?;
            let version = version_arg(args)?;
            let body: attome_sales::opportunity_lines::SalesLinePatch =
                serde_json::from_value(args.clone())
                    .map_err(|e| AppError::Validation(format!("bad change: {e}")))?;
            result(
                attome_sales::opportunity_lines::change_line(
                    state,
                    &ctx.security,
                    opportunity,
                    line,
                    version,
                    &body,
                )
                .await?,
            )
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({ "action": LINE_UPDATE, "change": args }))
    }
}

struct LineRemove;

impl Action for LineRemove {
    fn id(&self) -> ActionId {
        ActionId(LINE_REMOVE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("opportunity", "update")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let line = uuid_arg(args, "line_id")?;
            let version = version_arg(args)?;
            result(
                attome_sales::opportunity_lines::remove_line(
                    state,
                    &ctx.security,
                    opportunity,
                    line,
                    version,
                )
                .await?,
            )
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(
            json!({ "action": LINE_REMOVE, "opportunity_id": args["opportunity_id"],
                     "line_id": args["line_id"] }),
        )
    }
}

struct ProductsSuggest;

impl Action for ProductsSuggest {
    fn id(&self) -> ActionId {
        ActionId(PRODUCTS_SUGGEST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("product", "read")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let entity = state
                .entities
                .load()
                .get("opportunity")
                .map(|m| m.entity_id)
                .ok_or(AppError::NotFound)?;
            attome_records::entity_crud::require_record_access(
                state,
                &ctx.security,
                entity,
                "opportunity",
                opportunity,
                RecordAction::Read,
            )
            .await?;
            let rows: Vec<(Uuid, Option<String>, i64)> = sqlx::query_as(
                "WITH mine AS ( \
                     SELECT DISTINCT product_ref FROM opportunity_line \
                     WHERE opportunity_ref = $1 AND product_ref IS NOT NULL \
                       AND (is_active IS NULL OR is_active = true)), \
                 won AS ( \
                     SELECT DISTINCT l.opportunity_ref FROM opportunity_line l \
                     JOIN opportunity o ON o.id = l.opportunity_ref \
                     WHERE l.product_ref IN (SELECT product_ref FROM mine) \
                       AND o.stage = 'closed_won' AND o.id <> $1 \
                       AND COALESCE(o.close_date::date, o.created_at::date) >= now()::date - 730 \
                       AND (l.is_active IS NULL OR l.is_active = true)) \
                 SELECT p.id, p.name, COUNT(DISTINCT l.opportunity_ref) AS deals \
                 FROM opportunity_line l JOIN product p ON p.id = l.product_ref \
                 WHERE l.opportunity_ref IN (SELECT opportunity_ref FROM won) \
                   AND l.product_ref NOT IN (SELECT product_ref FROM mine) \
                   AND (l.is_active IS NULL OR l.is_active = true) \
                   AND (p.is_active IS NULL OR p.is_active = true) \
                 GROUP BY p.id, p.name ORDER BY deals DESC, p.name LIMIT $2",
            )
            .bind(opportunity)
            .bind(MAX_SUGGESTIONS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(ActionResult::plain(json!({
                "draft": true,
                "detail": "Suggestions only; nothing was added to the deal.",
                "products": rows.into_iter().map(|(id, name, deals)| json!({
                    "product_id": id,
                    "name": name,
                    "won_together_on_deals": deals,
                })).collect::<Vec<_>>(),
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_writes_need_confirmation_and_suggest_is_read_only() {
        let all = descriptors();
        for id in [LINE_ADD, LINE_UPDATE, LINE_REMOVE] {
            let d = all.iter().find(|d| d.id.as_str() == id);
            assert!(
                d.is_some_and(|d| d.effect == Effect::Write),
                "{id} is a write"
            );
        }
        let suggest = all.iter().find(|d| d.id.as_str() == PRODUCTS_SUGGEST);
        assert!(suggest.is_some_and(|d| d.effect == Effect::Read && d.risk == RiskTier::Read));
    }

    #[test]
    fn the_input_schemas_are_json() {
        for schema in [ADD_SCHEMA, UPDATE_SCHEMA] {
            assert!(serde_json::from_str::<Value>(schema).is_ok(), "{schema}");
        }
        assert!(serde_json::from_str::<Value>(REMOVE_SCHEMA).is_ok());
    }
}
