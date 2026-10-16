//! `ops.slo_health` (roadmap AA13-T10): each SLO class's status and the
//! share of its 30-day error budget left, from the server's own metrics
//! store (`attome_server::slo`), so an operations agent can see whether the
//! deployment meets its objectives. Administrators only; reads, changes
//! nothing.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_SLO_HEALTH: &str = "ops.slo_health";

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        OPS_SLO_HEALTH,
        "List each service-level class (sign-in, record read and write, search, …) with its \
         status (ok, at_risk, exhausted or unmeasured) and the share of its 30-day error \
         budget left (1 = untouched, below 0 = over budget).",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#)
}

pub(crate) struct OpsSloHealth;

impl Action for OpsSloHealth {
    fn id(&self) -> ActionId {
        ActionId(OPS_SLO_HEALTH)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let mut classes = Vec::new();
            for class in &attome_server::slo::catalogue().classes {
                let budget = attome_server::slo::budget(&state.base.db, class)
                    .await
                    .map_err(AppError::internal)?;
                classes.push(class_row(&class.id, budget.as_ref()));
            }
            Ok(ActionResult::plain(json!({ "classes": classes })))
        })
    }
}

/// One class as the tool reports it.
fn class_row(id: &str, budget: Option<&attome_server::slo::Budget>) -> Value {
    json!({
        "id": id,
        "status": budget.map_or("unmeasured", attome_server::slo::status),
        "budget_remaining": budget.map(|b| b.remaining_ratio),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slo_health_is_for_administrators_and_reads_only() {
        let d = descriptor();
        assert_eq!(d.required_privileges, &["system.admin"]);
        let row = class_row(
            "S1",
            Some(&attome_server::slo::budget_of(995.0, 5.0, 0.001)),
        );
        assert_eq!(row["status"], "exhausted");
        assert_eq!(class_row("S12", None)["status"], "unmeasured");
        assert!(class_row("S12", None)["budget_remaining"].is_null());
    }
}
