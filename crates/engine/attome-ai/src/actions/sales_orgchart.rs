//! Org chart actions (roadmap D23-T10). None changes a contact.
//!
//! - `sales.orgchart.read` answers an account's chart (D23-T5) as the
//!   acting person may read it.
//! - `sales.committee.read` answers a deal's buying committee (D23-T7):
//!   roles, and influence and attitude only through the Deal Attitude
//!   profile.
//! - `sales.coverage.gaps` answers just the deal's coverage gaps.
//! - `sales.orgchart.propose` queues proposals for an account's unplaced
//!   people, written as open drafts a person accepts or rejects; it never
//!   sets a manager. Reversible, confirmed first.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SALES_ORGCHART_READ: &str = "sales.orgchart.read";
pub const SALES_COMMITTEE_READ: &str = "sales.committee.read";
pub const SALES_COVERAGE_GAPS: &str = "sales.coverage.gaps";
pub const SALES_ORGCHART_PROPOSE: &str = "sales.orgchart.propose";

const ACCOUNT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "account_id": { "type": "string", "format": "uuid" },
    "group": { "type": "boolean", "description": "The whole group of companies" }
  },
  "required": ["account_id"],
  "additionalProperties": false
}"#;

const PROPOSE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "account_id": { "type": "string", "format": "uuid" }
  },
  "required": ["account_id"],
  "additionalProperties": false
}"#;

const DEAL_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" }
  },
  "required": ["opportunity_id"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_SALES,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            SALES_ORGCHART_READ,
            "Read an account's org chart: its people by who they report to, the unplaced ones, \
             and the companies in its group when asked.",
            ACCOUNT_SCHEMA,
        ),
        read(
            SALES_COMMITTEE_READ,
            "Read a deal's buying committee: each contact's role, influence and attitude (where \
             the reader may see them), who influences whom, and the coverage gaps.",
            DEAL_SCHEMA,
        ),
        read(
            SALES_COVERAGE_GAPS,
            "List a deal's coverage gaps: the roles its stage requires that no contact holds, \
             and high-influence contacts nobody has met in 180 days.",
            DEAL_SCHEMA,
        ),
        ActionDescriptor::new(
            SALES_ORGCHART_PROPOSE,
            "Propose who an account's unplaced people report to, from their titles and \
             departments, as drafts a person accepts or rejects. Sets no manager.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_SALES,
            &[],
        )
        .input_schema(PROPOSE_SCHEMA)
        .agent_must_confirm(),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(OrgChart(SALES_ORGCHART_READ)),
        Box::new(OrgChart(SALES_COMMITTEE_READ)),
        Box::new(OrgChart(SALES_COVERAGE_GAPS)),
        Box::new(OrgChart(SALES_ORGCHART_PROPOSE)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be an id")))
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, AppError> {
    serde_json::to_value(value).map_err(AppError::internal)
}

struct OrgChart(&'static str);

impl Action for OrgChart {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let security = &ctx.security;
            match self.0 {
                SALES_ORGCHART_READ => {
                    let account = uuid_arg(args, "account_id")?;
                    let group = args.get("group").and_then(Value::as_bool) == Some(true);
                    let chart = attome_sales::orgchart::chart::account_chart(
                        state,
                        security,
                        account,
                        group,
                        &HashSet::new(),
                        None,
                    )
                    .await?;
                    Ok(ActionResult::plain(to_value(&chart)?))
                }
                SALES_COMMITTEE_READ => {
                    let deal = uuid_arg(args, "opportunity_id")?;
                    let map =
                        attome_sales::orgchart::committee::deal_map(state, security, deal).await?;
                    Ok(ActionResult::plain(to_value(&map)?))
                }
                SALES_COVERAGE_GAPS => {
                    let deal = uuid_arg(args, "opportunity_id")?;
                    let map =
                        attome_sales::orgchart::committee::deal_map(state, security, deal).await?;
                    Ok(ActionResult::plain(json!({
                        "opportunity_id": deal,
                        "required_roles": map.required_roles,
                        "gaps": map.gaps,
                    })))
                }
                SALES_ORGCHART_PROPOSE => {
                    let account = uuid_arg(args, "account_id")?;
                    attome_sales::orgchart::drafts::queue_propose(state, security, account).await?;
                    Ok(ActionResult::plain(json!({
                        "account_id": account,
                        "queued": true,
                        "next": "Open drafts appear in Org Chart Drafts for a person to accept or reject; no manager is set until then.",
                    })))
                }
                _ => Err(AppError::NotFound),
            }
        })
    }
}
