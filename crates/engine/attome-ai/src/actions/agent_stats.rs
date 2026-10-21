//! `agent.performance` (roadmap AI8-T5): the agent performance summary the
//! admin route serves (`agent_stats_routes::performance`), as a read-only
//! action, so the operations agent — and an MCP client, which lists the
//! registered read actions — can answer "how is the follow-up agent doing".
//! Administrators only, as on the route. Sums and rates only: no message
//! text and no record values.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::agent_stats_routes::{PerformanceRange, performance};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const AGENT_PERFORMANCE: &str = "agent.performance";

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "agent_id": { "type": "string", "format": "uuid", "description": "One agent; omit for every agent." },
    "from": { "type": "string", "format": "date", "description": "First day (YYYY-MM-DD)." },
    "to": { "type": "string", "format": "date", "description": "Last day (YYYY-MM-DD)." }
  },
  "required": ["from", "to"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        AGENT_PERFORMANCE,
        "How agents are doing over a date range: tasks done, resolution, accuracy, hand-off \
         rate, tokens, cost per task and an estimate of time saved. Administrators only. \
         Writes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(INPUT)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![descriptor()]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(AgentPerformanceAction)]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    agent_id: Option<Uuid>,
    from: NaiveDate,
    to: NaiveDate,
}

struct AgentPerformanceAction;

impl Action for AgentPerformanceAction {
    fn id(&self) -> ActionId {
        ActionId(AGENT_PERFORMANCE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // The route's own gate: administrators only.
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid agent.performance arguments: {e}"))
            })?;
            let range = PerformanceRange {
                from: args.from,
                to: args.to,
            };
            let agents = performance(&state.base.db, &range, args.agent_id).await?;
            Ok(ActionResult::plain(json!({
                "from": range.from,
                "to": range.to,
                "agents": agents,
                "note": "time_saved_seconds is an estimate per task source; cost is in millionths of the price list's currency, and null cost_unit means some tokens had no price",
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_performance_is_read_tier() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.retry, RetryClass::Idempotent);
    }
}
