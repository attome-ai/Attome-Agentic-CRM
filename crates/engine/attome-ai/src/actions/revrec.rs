//! Revenue recognition actions (roadmap F11-T12).
//!
//! - `revrec.explain_period(schedule_line_id)`: why an amount of revenue
//!   falls in a period: the line, its obligation's pattern and dates, the
//!   standalone selling price method and version it was allocated with, and
//!   the product's revenue rule.
//! - `revrec.propose_revenue_rule(product_id)`: a draft revenue rule (the
//!   pattern and why) for a person to create. Nothing is saved.
//! - `revrec.draft_disclosure(fiscal_period)`: a draft revenue disclosure
//!   paragraph from the period's recognised, deferred and remaining figures.
//!   Nothing is saved.
//!
//! None writes: closes, changes and rules stay with people through the
//! ledger routes.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_modules::MODULE_LEDGER;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const EXPLAIN_PERIOD: &str = "revrec.explain_period";
pub const PROPOSE_RULE: &str = "revrec.propose_revenue_rule";
pub const DRAFT_DISCLOSURE: &str = "revrec.draft_disclosure";
/// Bumped whenever a prompt changes in a way that could move output.
pub const PROPOSE_PROMPT_VERSION: &str = "revrec.propose_revenue_rule/v1";
pub const DISCLOSURE_PROMPT_VERSION: &str = "revrec.draft_disclosure/v1";
/// The revenue patterns a rule may name.
pub const PATTERNS: [&str; 5] = [
    "point_in_time",
    "ratable",
    "milestone",
    "usage",
    "percent_complete",
];

const LINE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "schedule_line_id": { "type": "string", "format": "uuid" } },
  "required": ["schedule_line_id"],
  "additionalProperties": false
}"#;

const PRODUCT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "product_id": { "type": "string", "format": "uuid" } },
  "required": ["product_id"],
  "additionalProperties": false
}"#;

const PERIOD_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "fiscal_period": { "type": "string", "pattern": "^[0-9]{4}-[0-9]{2}$" } },
  "required": ["fiscal_period"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_LEDGER,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            EXPLAIN_PERIOD,
            "Explain why an amount of revenue falls in a period: the schedule line, its \
             obligation's recognition pattern and dates, the standalone selling price method and \
             version it was allocated with, and the product's revenue rule.",
            LINE_SCHEMA,
        ),
        read(
            PROPOSE_RULE,
            "Draft a revenue recognition rule for a product (the pattern and why) for a person to \
             create. Nothing is saved.",
            PRODUCT_SCHEMA,
        ),
        read(
            DRAFT_DISCLOSURE,
            "Draft a revenue disclosure paragraph for a period from its recognised, deferred and \
             remaining figures. Nothing is saved.",
            PERIOD_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(ExplainPeriod),
        Box::new(ProposeRule),
        Box::new(DraftDisclosure),
    ]
}

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>>;

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

/// What explains a line, as read.
#[derive(Debug, Clone, Default, PartialEq, sqlx::FromRow)]
pub struct LineFacts {
    pub fiscal_period: Option<String>,
    pub amount: Option<f64>,
    pub line_status: Option<String>,
    pub pattern: Option<String>,
    pub start_on: Option<String>,
    pub end_on: Option<String>,
    pub allocated_amount: Option<f64>,
    pub ssp_method: Option<String>,
    pub ssp_version: Option<f64>,
    pub rule_name: Option<String>,
    pub rule_pattern: Option<String>,
}

/// The explanation of a line from its facts, citing the pattern, the
/// allocation and the rule. Pure.
pub fn explain(facts: &LineFacts) -> Value {
    let period = facts.fiscal_period.as_deref().unwrap_or("?");
    let pattern = facts.pattern.as_deref().unwrap_or("unknown");
    let why = match pattern {
        "ratable" => format!(
            "The obligation is recognised evenly from {} to {}, so {period} takes its share.",
            facts.start_on.as_deref().unwrap_or("its start"),
            facts.end_on.as_deref().unwrap_or("its end")
        ),
        "point_in_time" => {
            format!("The obligation is recognised when it is delivered, in {period}.")
        }
        "milestone" => format!("A milestone of the obligation falls in {period}."),
        "usage" => format!("The usage measured in {period} is recognised there."),
        "percent_complete" => {
            format!("The work completed in {period} is recognised there.")
        }
        _ => format!("The schedule places this amount in {period}."),
    };
    json!({
        "fiscal_period": facts.fiscal_period,
        "amount": facts.amount,
        "status": facts.line_status,
        "pattern": facts.pattern,
        "why": why,
        "allocation": {
            "allocated_amount": facts.allocated_amount,
            "ssp_method": facts.ssp_method,
            "ssp_version": facts.ssp_version,
        },
        "rule": { "name": facts.rule_name, "pattern": facts.rule_pattern },
    })
}

struct ExplainPeriod;

impl Action for ExplainPeriod {
    fn id(&self) -> ActionId {
        ActionId(EXPLAIN_PERIOD)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let line = uuid_arg(args, "schedule_line_id")?;
            ctx.security.require("revenue_schedule_line", "read")?;
            ctx.security.require("performance_obligation", "read")?;
            let facts: Option<LineFacts> = sqlx::query_as(
                "SELECT s.fiscal_period, s.amount_contract_ccy::float8 AS amount, \
                        s.status::text AS line_status, o.pattern::text AS pattern, \
                        o.start_on::date::text AS start_on, o.end_on::date::text AS end_on, \
                        o.allocated_amount::float8 AS allocated_amount, \
                        to_jsonb(o) ->> 'ssp_method' AS ssp_method, \
                        (to_jsonb(o) ->> 'ssp_version')::float8 AS ssp_version, \
                        r.name AS rule_name, r.pattern::text AS rule_pattern \
                   FROM revenue_schedule_line s \
                   JOIN performance_obligation o ON o.id = s.obligation_ref \
                   LEFT JOIN product p ON p.id = o.product_ref \
                   LEFT JOIN revenue_rule r ON r.id = p.revenue_rule_ref \
                  WHERE s.id = $1 AND (s.is_active IS NULL OR s.is_active = true)",
            )
            .bind(line)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let facts = facts.ok_or(AppError::NotFound)?;
            Ok(ActionResult::plain(explain(&facts)))
        })
    }
}

/// The drafting instructions for a rule.
pub fn propose_system_prompt() -> String {
    format!(
        "You help an accountant set up revenue recognition under IFRS 15. From the product's \
         facts, propose one recognition pattern from this list: {}. Explain why in two or three \
         sentences in plain words, naming what the customer receives and when. Answer with JSON \
         only: {{\"pattern\": \"...\", \"name\": \"...\", \"reason\": \"...\"}}.",
        PATTERNS.join(", ")
    )
}

/// The drafting instructions for a disclosure.
pub fn disclosure_system_prompt() -> String {
    "You draft the revenue note of a company's monthly management report. From the figures \
     given, write one short paragraph stating revenue recognised in the period, the deferred \
     balance, unbilled revenue, and the remaining performance obligations, in the figures' \
     currency as given. State only the figures given; add no estimate, forecast or opinion. \
     Answer with the paragraph only."
        .to_owned()
}

/// A proposed rule from the model's reply, refused unless its pattern is
/// one of [`PATTERNS`]. Pure.
pub fn parse_proposal(reply: &str) -> Result<Value, AppError> {
    let start = reply.find('{');
    let end = reply.rfind('}');
    let value: Value = match (start, end) {
        (Some(s), Some(e)) if s < e => serde_json::from_str(&reply[s..=e])
            .map_err(|_| AppError::Validation("the proposal could not be read".into()))?,
        _ => {
            return Err(AppError::Validation(
                "the proposal could not be read".into(),
            ));
        }
    };
    let pattern = value["pattern"].as_str().unwrap_or_default();
    if !PATTERNS.contains(&pattern) {
        return Err(AppError::Validation(format!(
            "the proposal names no known pattern ({pattern})"
        )));
    }
    Ok(json!({
        "pattern": pattern,
        "name": value["name"].as_str().unwrap_or_default(),
        "reason": value["reason"].as_str().unwrap_or_default(),
    }))
}

async fn generate(
    state: &EngineState,
    ctx: &ActionContext,
    action: &'static str,
    system: String,
    facts: String,
) -> Result<(String, String), AppError> {
    let client = crate::inference_client::client_for(state, action).await?;
    let mut request = GenerationRequest::new(crate::prompt::assemble(&[
        Segment::trusted(system),
        Segment::untrusted("facts", facts),
    ]));
    request.temperature = 0.2;
    crate::model_registry::require_approved_model(&state.base.db, client.model_id(), action)
        .await?;
    let grant = crate::budget_guard::admit(
        state,
        ctx,
        attome_inference::budget::Priority::Chat,
        action,
        &mut request,
    )
    .await?;
    let generated = client.generate(request).await.map_err(|e| {
        tracing::warn!(error = %e, action, "revenue draft failed");
        AppError::internal("revenue draft failed")
    })?;
    grant.settle(state, &generated.usage).await;
    Ok((generated.text, generated.usage.model_id))
}

struct ProposeRule;

impl Action for ProposeRule {
    fn id(&self) -> ActionId {
        ActionId(PROPOSE_RULE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let product = uuid_arg(args, "product_id")?;
            let record =
                attome_records::entity_crud::read_record(state, &ctx.security, "product", product)
                    .await?;
            let data = record.data();
            let facts = json!({
                "name": data.get("name"),
                "description": data.get("description"),
                "fulfilment_kind": data.get("fulfilment_kind"),
                "revenue_rule": data.get("revenue_rule"),
            })
            .to_string();
            let (reply, model) =
                generate(state, ctx, PROPOSE_RULE, propose_system_prompt(), facts).await?;
            let mut proposal = parse_proposal(&reply)?;
            proposal["product_id"] = json!(product);
            proposal["saved"] = json!(false);
            Ok(ActionResult {
                value: proposal,
                provenance: Some(Provenance {
                    model_id: model,
                    prompt_version: PROPOSE_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

struct DraftDisclosure;

impl Action for DraftDisclosure {
    fn id(&self) -> ActionId {
        ActionId(DRAFT_DISCLOSURE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let period = args["fiscal_period"]
                .as_str()
                .map(str::trim)
                .filter(|p| p.len() == 7)
                .ok_or_else(|| AppError::Validation("fiscal_period is YYYY-MM".into()))?
                .to_owned();
            ctx.security.require("revenue_schedule_line", "read")?;
            ctx.security.require("revenue_balance_snapshot", "read")?;
            let figures: (Option<f64>, Option<f64>, Option<f64>, Option<f64>) = sqlx::query_as(
                "SELECT \
                    (SELECT sum(amount_contract_ccy)::float8 FROM revenue_schedule_line \
                      WHERE fiscal_period = $1 AND status::text IN ('recognised', 'locked') \
                        AND (is_active IS NULL OR is_active = true)), \
                    (SELECT sum(deferred)::float8 FROM revenue_balance_snapshot \
                      WHERE fiscal_period = $1 AND (is_active IS NULL OR is_active = true)), \
                    (SELECT sum(unbilled)::float8 FROM revenue_balance_snapshot \
                      WHERE fiscal_period = $1 AND (is_active IS NULL OR is_active = true)), \
                    (SELECT sum(amount_contract_ccy)::float8 FROM revenue_schedule_line \
                      WHERE fiscal_period > $1 AND status::text = 'planned' \
                        AND (is_active IS NULL OR is_active = true))",
            )
            .bind(&period)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let facts = json!({
                "period": period,
                "recognised": figures.0.unwrap_or(0.0),
                "deferred": figures.1.unwrap_or(0.0),
                "unbilled": figures.2.unwrap_or(0.0),
                "remaining_obligations": figures.3.unwrap_or(0.0),
            });
            let (text, model) = generate(
                state,
                ctx,
                DRAFT_DISCLOSURE,
                disclosure_system_prompt(),
                facts.to_string(),
            )
            .await?;
            Ok(ActionResult {
                value: json!({
                    "fiscal_period": period,
                    "figures": facts,
                    "draft": text.trim(),
                    "saved": false,
                }),
                provenance: Some(Provenance {
                    model_id: model,
                    prompt_version: DISCLOSURE_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_cites_rule_and_ssp_version() {
        let facts = LineFacts {
            fiscal_period: Some("2027-02".into()),
            amount: Some(100.0),
            line_status: Some("planned".into()),
            pattern: Some("ratable".into()),
            start_on: Some("2027-01-01".into()),
            end_on: Some("2027-12-31".into()),
            allocated_amount: Some(1200.0),
            ssp_method: Some("median_standalone".into()),
            ssp_version: Some(3.0),
            rule_name: Some("Subscriptions".into()),
            rule_pattern: Some("ratable".into()),
        };
        let out = explain(&facts);
        assert_eq!(out["rule"]["name"], "Subscriptions");
        assert_eq!(out["allocation"]["ssp_version"], 3.0);
        assert!(out["why"].as_str().unwrap().contains("2027-01-01"));
    }

    #[test]
    fn a_proposal_names_a_known_pattern() {
        let ok =
            parse_proposal("{\"pattern\": \"ratable\", \"name\": \"SaaS\", \"reason\": \"r\"}")
                .unwrap();
        assert_eq!(ok["pattern"], "ratable");
        assert!(parse_proposal("{\"pattern\": \"whenever\"}").is_err());
        assert!(parse_proposal("nothing").is_err());
    }
}
