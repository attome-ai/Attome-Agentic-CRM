//! AB3-T11: an operations agent reads how ready the deployment is to
//! recover. Reads only: no tool declares a disaster, asks for or approves a
//! recovery action, or starts a recovery.
//!
//! - `ops.recovery_readiness` (Read, `ops.read`) — this profile's recovery
//!   targets per scenario and whether a fresh drill proved each (AB3-T1).
//! - `ops.live_rpo` (Read, `ops.read`) — the live recovery point per source
//!   against its target (AB3-T2).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_OPS;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_RECOVERY_READINESS: &str = "ops.recovery_readiness";
pub const OPS_LIVE_RPO: &str = "ops.live_rpo";

pub fn descriptors() -> Vec<ActionDescriptor> {
    let empty = r#"{"type": "object", "properties": {}, "additionalProperties": false}"#;
    vec![
        ActionDescriptor::new(
            OPS_RECOVERY_READINESS,
            "Read this deployment's recovery targets: per disaster scenario the data loss and \
             downtime allowed, the drill kind that proves it, whether a fresh drill proved it \
             and what that drill measured.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(empty),
        ActionDescriptor::new(
            OPS_LIVE_RPO,
            "Read the live recovery point: how many seconds of data a disaster now would lose, \
             from WAL archiving, the read replica and the newest backup, each against its target \
             (ok, over or off).",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(empty),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(OpsRecoveryReadiness), Box::new(OpsLiveRpo)]
}

pub(crate) struct OpsRecoveryReadiness;

impl Action for OpsRecoveryReadiness {
    fn id(&self) -> ActionId {
        ActionId(OPS_RECOVERY_READINESS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let profile = state.base.config.ops.profile.clone();
            let targets =
                attome_ops::recovery_targets::list_with_proof(&state.base.db, &profile).await?;
            Ok(ActionResult::plain(json!({
                "profile": profile,
                "targets": serde_json::to_value(targets).map_err(AppError::internal)?,
            })))
        })
    }
}

pub(crate) struct OpsLiveRpo;

impl Action for OpsLiveRpo {
    fn id(&self) -> ActionId {
        ActionId(OPS_LIVE_RPO)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let sources = attome_ops::live_rpo::current(state).await?;
            Ok(ActionResult::plain(json!({
                "sources": serde_json::to_value(sources).map_err(AppError::internal)?,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_tools_are_read_tier() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
            assert_eq!(d.required_privileges, &["ops.read"]);
        }
        // No action may declare a disaster, ask for or approve a recovery.
        let writes: Vec<&str> = crate::actions::all()
            .into_iter()
            .filter(|a| {
                (a.id.0.starts_with("ops.recover")
                    || a.id.0.starts_with("ops.disaster")
                    || a.id.0.starts_with("ops.dr"))
                    && a.risk != RiskTier::Read
            })
            .map(|a| a.id.0)
            .collect();
        assert!(writes.is_empty(), "{writes:?}");
    }
}
