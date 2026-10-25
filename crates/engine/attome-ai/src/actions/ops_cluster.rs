//! AB2-T12: an operations agent reads the database cluster and proposes a
//! switchover; it never moves the leader itself.
//!
//! - `ops.cluster_status` (Read, `ops.read`) — the cluster's members, lag,
//!   synchronous standby and last failover, as `GET /api/v1/ops/cluster`
//!   answers it.
//! - `ops.propose_switchover` (Reversible, `ops.cluster.switchover`) — its
//!   only effect is the pending `ops.switchover` approval request (the
//!   requester can recall it). That request is itself the approval tier: a
//!   person in the Operations role other than the requester decides it, its
//!   step needs a person (no agent), and only then does the ops engine call
//!   Patroni. Making this action Consequential too would put a second
//!   approval in front of the first, so it is not.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_OPS;
use attome_ops::switchover::SwitchoverRequest;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_CLUSTER_STATUS: &str = "ops.cluster_status";
pub const OPS_PROPOSE_SWITCHOVER: &str = "ops.propose_switchover";

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            OPS_CLUSTER_STATUS,
            "Read the database cluster: single server or high availability, the leader, each \
             member's role, state and replication lag, the synchronous standby and the last \
             failover or switchover.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#),
        ActionDescriptor::new(
            OPS_PROPOSE_SWITCHOVER,
            "Propose a planned switchover of the database leader, optionally to a named member, \
             with the reason. This only creates an approval request: a second person in the \
             Operations role must approve it before anything changes.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_OPS,
            &["ops.cluster.switchover"],
        )
        .input_schema(
            r#"{"type": "object", "required": ["reason"], "properties": {"candidate": {"type": "string", "minLength": 1, "maxLength": 128}, "reason": {"type": "string", "minLength": 10, "maxLength": 500}}, "additionalProperties": false}"#,
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(OpsClusterStatus), Box::new(OpsProposeSwitchover)]
}

/// A proposal's request from the action's arguments. Pure.
pub fn switchover_request(args: &Value) -> Result<SwitchoverRequest, AppError> {
    let reason = args["reason"]
        .as_str()
        .ok_or_else(|| AppError::Validation("reason is required".into()))?;
    let request = SwitchoverRequest {
        candidate: args["candidate"].as_str().map(str::to_owned),
        reason: reason.to_owned(),
    };
    attome_ops::switchover::check_request(&request)?;
    Ok(request)
}

pub(crate) struct OpsClusterStatus;

impl Action for OpsClusterStatus {
    fn id(&self) -> ActionId {
        ActionId(OPS_CLUSTER_STATUS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let status = attome_ops::status::cluster_status(state).await?;
            Ok(ActionResult::plain(
                serde_json::to_value(status).map_err(AppError::internal)?,
            ))
        })
    }
}

pub(crate) struct OpsProposeSwitchover;

impl Action for OpsProposeSwitchover {
    fn id(&self) -> ActionId {
        ActionId(OPS_PROPOSE_SWITCHOVER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let request = switchover_request(args)?;
            let approval =
                attome_ops::switchover::submit(state, ctx.security.user_id, &request).await?;
            Ok(ActionResult::plain(json!({
                "approval_id": approval.id,
                "status": approval.status.to_string(),
                "note": "A second person in the Operations role must approve the switchover.",
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> ActionDescriptor {
        descriptors().into_iter().find(|d| d.id.0 == id).unwrap()
    }

    #[test]
    fn cluster_status_hidden_without_ops_read() {
        let status = descriptor(OPS_CLUSTER_STATUS);
        assert_eq!(status.required_privileges, &["ops.read"]);
        assert_eq!(status.risk, RiskTier::Read);
        assert_eq!(status.module, MODULE_OPS);
    }

    #[test]
    fn propose_switchover_returns_approval_id() {
        // The proposal only ever asks: its one effect is the approval, under
        // the switchover privilege, and its arguments are the route's.
        let propose = descriptor(OPS_PROPOSE_SWITCHOVER);
        assert_eq!(propose.required_privileges, &["ops.cluster.switchover"]);
        assert_eq!(propose.risk, RiskTier::Reversible);
        let ok =
            switchover_request(&json!({"candidate": "db2", "reason": "planned kernel patching"}))
                .unwrap();
        assert_eq!(ok.candidate.as_deref(), Some("db2"));
        assert!(switchover_request(&json!({"reason": "short"})).is_err());
        assert!(switchover_request(&json!({})).is_err());
    }
}
