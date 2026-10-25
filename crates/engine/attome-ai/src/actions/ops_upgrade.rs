//! AB8-T9: an operations agent reads the latest platform upgrade, its
//! pre-upgrade check report and how it ended. Reading only: starting,
//! verifying or rolling back an upgrade stays with people (the upgrade
//! routes need `ops.upgrade.run` and a fresh step-up).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_OPS;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_UPGRADE_STATUS: &str = "ops.upgrade_status";

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        OPS_UPGRADE_STATUS,
        "Read the latest platform upgrade: the versions, when it started and finished, its \
         status (started, verified, failed or rolled back), the safety point to go back to \
         and the pre-upgrade check report.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_OPS,
        &["ops.read"],
    )
    .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#)
}

pub(crate) struct OpsUpgradeStatus;

impl Action for OpsUpgradeStatus {
    fn id(&self) -> ActionId {
        ActionId(OPS_UPGRADE_STATUS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let latest = attome_ops::upgrades::latest(&state.base.db).await?;
            Ok(ActionResult::plain(json!({
                "upgrade": serde_json::to_value(latest).map_err(AppError::internal)?,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_tool_is_read_tier() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.required_privileges, &["ops.read"]);
        // No action may start, verify or roll back an upgrade.
        let writes: Vec<&str> = crate::actions::all()
            .into_iter()
            .filter(|a| a.id.0.starts_with("ops.upgrade") && a.risk != RiskTier::Read)
            .map(|a| a.id.0)
            .collect();
        assert!(writes.is_empty(), "{writes:?}");
    }
}
