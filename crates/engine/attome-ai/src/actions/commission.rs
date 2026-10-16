//! Commission actions (roadmap F10-T14). Both read only; no action approves
//! payouts, adjusts amounts or changes plans.
//!
//! - `commission.explain_line` returns a statement line's stored
//!   explanation, read through the same record read as `record.get`, so the
//!   commission roles' record rules decide whose lines the caller sees and
//!   the amount field's grant decides whether the amount shows. It never
//!   recalculates.
//! - `commission.draft_plan_from_policy` checks a plan the model drafted
//!   from a policy document (read with `document.extract` or the knowledge
//!   actions first): every component's rate table must parse and compile.
//!   It returns the normalised `comp_plan` draft, or what is wrong with it,
//!   and writes nothing; a person creates the plan.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_COMMISSION;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EXPLAIN_LINE: &str = "commission.explain_line";
pub const DRAFT_PLAN: &str = "commission.draft_plan_from_policy";

/// Components one draft may carry.
pub const MAX_COMPONENTS: usize = 50;

const EXPLAIN_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "statement_line_id": { "type": "string", "format": "uuid", "description": "The comp_statement_line to explain." }
  },
  "required": ["statement_line_id"],
  "additionalProperties": false
}"#;

const DRAFT_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "name": { "type": "string", "description": "The plan's name." },
    "source_document": { "type": "string", "description": "Which policy document the draft comes from, for the person reviewing it." },
    "components": {
      "type": "array",
      "maxItems": 50,
      "items": {
        "type": "object",
        "properties": {
          "kind": { "type": "string", "description": "What the component pays on, e.g. revenue, margin, new_logo." },
          "measure": { "type": "string" },
          "tier_mode": { "type": "string", "enum": ["retroactive", "marginal"] },
          "rate_table": {
            "type": "array",
            "description": "Bands by attainment percent: from (inclusive), to (exclusive, omit for the top band), rate (percent of the credit).",
            "items": {
              "type": "object",
              "properties": { "from": { "type": "number" }, "to": { "type": "number" }, "rate": { "type": "number" } },
              "required": ["from", "rate"]
            }
          },
          "cap_per_deal": { "type": "number" },
          "cap_per_period": { "type": "number" },
          "gate_attainment_percent": { "type": "number" },
          "floor_margin_percent": { "type": "number" }
        },
        "required": ["kind", "rate_table"]
      }
    }
  },
  "required": ["name", "components"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            EXPLAIN_LINE,
            "Explain one commission statement line you may read: the stored steps \
             (attainment, band, rate, caps) that produced its amount. Reads the \
             stored explanation; never recalculates.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_COMMISSION,
            &[],
        )
        .input_schema(EXPLAIN_INPUT),
        ActionDescriptor::new(
            DRAFT_PLAN,
            "Check a commission plan you drafted from a policy document: give its \
             components with rate tables, and get back the normalised comp_plan \
             draft or what is wrong with it. Writes nothing; a person creates the \
             plan from the draft.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_COMMISSION,
            &[],
        )
        .input_schema(DRAFT_INPUT),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ExplainLine), Box::new(DraftPlan)]
}

struct ExplainLine;

impl Action for ExplainLine {
    fn id(&self) -> ActionId {
        ActionId(EXPLAIN_LINE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let line = args["statement_line_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("statement_line_id must be a UUID".into()))?;
            // Over MCP, the line's entity must be admitted for read, as for
            // `record.get`; refused darkly otherwise.
            if let Some(admission) = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?
                && !admission.admits("comp_statement_line")
            {
                return Err(AppError::NotFound);
            }
            let record = attome_records::entity_crud::read_record_bulk(
                state,
                &ctx.security,
                "comp_statement_line",
                line,
            )
            .await?;
            let value = serde_json::to_value(record)
                .map_err(|e| AppError::internal(format!("record serialization failed: {e}")))?;
            Ok(ActionResult::plain(explain(line, &value["data"])))
        })
    }
}

/// The answer for one line from its record's data.
pub fn explain(line: Uuid, data: &Value) -> Value {
    let steps = match &data["explanation"] {
        Value::String(text) => serde_json::from_str(text).unwrap_or(Value::String(text.clone())),
        other => other.clone(),
    };
    json!({
        "statement_line_id": line,
        "amount": data.get("amount").cloned().unwrap_or(Value::Null),
        "component_id": data.get("component_ref").cloned().unwrap_or(Value::Null),
        "credit_id": data.get("credit_ref").cloned().unwrap_or(Value::Null),
        "steps": steps,
    })
}

struct DraftPlan;

impl Action for DraftPlan {
    fn id(&self) -> ActionId {
        ActionId(DRAFT_PLAN)
    }

    fn execute<'a>(
        &'a self,
        _state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move { Ok(ActionResult::plain(check_draft(args)?)) })
    }
}

fn number(value: &Value) -> Option<rust_decimal::Decimal> {
    match value {
        Value::Number(n) => n.to_string().parse().ok(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Normalises and compiles a drafted plan: the draft and the problems
/// found (empty when it compiles).
pub fn check_draft(args: &Value) -> Result<Value, AppError> {
    let name = args["name"]
        .as_str()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| AppError::Validation("name is required".into()))?;
    let components = args["components"]
        .as_array()
        .ok_or_else(|| AppError::Validation("components must be a list".into()))?;
    if components.is_empty() || components.len() > MAX_COMPONENTS {
        return Err(AppError::Validation(format!(
            "components: 1 to {MAX_COMPONENTS}"
        )));
    }
    let mut problems = Vec::new();
    let mut drafted = Vec::new();
    for (i, c) in components.iter().enumerate() {
        let table = c["rate_table"].to_string();
        let mode = match c["tier_mode"].as_str() {
            Some("marginal") => attome_commission::rules::TierMode::Marginal,
            _ => attome_commission::rules::TierMode::Retroactive,
        };
        match attome_commission::run::parse_rate_table(&table) {
            Err(e) => problems.push(format!("component {i}: {e}")),
            Ok(bands) => {
                let component = attome_commission::rules::Component {
                    id: Uuid::nil(),
                    bands,
                    mode,
                    gate_pct: number(&c["gate_attainment_percent"]),
                    margin_floor_pct: number(&c["floor_margin_percent"]),
                    cap_per_deal: number(&c["cap_per_deal"]),
                    cap_per_period: number(&c["cap_per_period"]),
                    minor_units: 2,
                };
                if let Err(e) = attome_commission::rules::compile(&component) {
                    problems.push(format!("component {i}: {e:?}"));
                }
            }
        }
        drafted.push(json!({
            "kind": c["kind"],
            "measure": c.get("measure").cloned().unwrap_or(Value::Null),
            "tier_mode": if mode == attome_commission::rules::TierMode::Marginal { "marginal" } else { "retroactive" },
            "rate_table": table,
            "cap_per_deal": c.get("cap_per_deal").cloned().unwrap_or(Value::Null),
            "cap_per_period": c.get("cap_per_period").cloned().unwrap_or(Value::Null),
            "gate_attainment_percent": c.get("gate_attainment_percent").cloned().unwrap_or(Value::Null),
            "floor_margin_percent": c.get("floor_margin_percent").cloned().unwrap_or(Value::Null),
        }));
    }
    Ok(json!({
        "comp_plan": {
            "name": name,
            "source_document": args.get("source_document").cloned().unwrap_or(Value::Null),
            "components": drafted,
        },
        "compiles": problems.is_empty(),
        "problems": problems,
        "detail": "A draft only; nothing was written. A person creates the plan and its version.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_explanation_is_the_stored_steps() {
        let line = Uuid::from_u128(7);
        let out = explain(
            line,
            &json!({ "amount": "12.50", "explanation": "[{\"key\":\"band\",\"values\":{\"rate\":\"5\"}}]" }),
        );
        assert_eq!(out["amount"], "12.50");
        assert_eq!(out["steps"][0]["key"], "band");
        let hidden = explain(line, &json!({ "explanation": "[]" }));
        assert!(
            hidden["amount"].is_null(),
            "an amount the caller cannot see stays absent"
        );
    }

    #[test]
    fn a_draft_that_compiles_has_no_problems_and_one_that_overlaps_does() {
        let good = check_draft(&json!({
            "name": "FY27 AE plan",
            "components": [{ "kind": "revenue", "rate_table": [
                { "from": 0, "to": 100, "rate": 5 }, { "from": 100, "rate": 8 }
            ]}]
        }))
        .unwrap_or_default();
        assert_eq!(good["compiles"], true);
        assert_eq!(
            good["comp_plan"]["components"][0]["tier_mode"],
            "retroactive"
        );
        let bad = check_draft(&json!({
            "name": "Overlap",
            "components": [{ "kind": "revenue", "tier_mode": "marginal", "rate_table": [
                { "from": 0, "to": 120, "rate": 5 }, { "from": 100, "rate": 8 }
            ]}]
        }))
        .unwrap_or_default();
        assert_eq!(bad["compiles"], false);
        assert!(check_draft(&json!({ "name": "x", "components": [] })).is_err());
    }
}
