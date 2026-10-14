//! `system.status` (roadmap AB5-T10): which services this node can use right
//! now, so an agent can tell an outage from its own mistake.
//!
//! Each service the platform gates work on (object storage, email, the two
//! job queues) with its state and, while it is down, for how long and whether
//! a call that needs it is worth retrying. A refused MCP call carries the
//! same `degraded` and `retryable` fields (`mcp::refusal_payload`). Names and
//! states only: no addresses, latencies or error text, which stay on the
//! administrators' `/health/dependencies`. Reads, changes nothing.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_server::{Capability, CapabilityRegistry, CapabilityState};
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SYSTEM_STATUS: &str = "system.status";

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        SYSTEM_STATUS,
        "List the services this system depends on and which are down right now. \
         Call it when a tool fails with `degraded`; when a service is down with \
         `retryable: false`, stop and tell the person instead of retrying.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[],
    )
    .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#)
}

pub(crate) struct SystemStatus;

impl Action for SystemStatus {
    fn id(&self) -> ActionId {
        ActionId(SYSTEM_STATUS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ActionResult::plain(status_body(
                &state.base.capabilities,
                state
                    .base
                    .audit_ingest_backlog_exceeded
                    .load(Ordering::Relaxed),
                state.base.metadata_lagging.load(Ordering::Relaxed),
            )))
        })
    }
}

/// The tool's answer from the node's own readings.
fn status_body(
    registry: &CapabilityRegistry,
    writes_paused: bool,
    metadata_lagging: bool,
) -> Value {
    let services: Vec<Value> = Capability::ALL
        .iter()
        .map(|c| {
            let state = registry.state(*c);
            let mut row = json!({
                "service": c.as_str(),
                "state": match state {
                    CapabilityState::Available | CapabilityState::Unknown => "up",
                    CapabilityState::Unavailable => "down",
                    CapabilityState::Disabled => "off",
                },
            });
            if let Some(secs) = registry.down_for_secs(*c) {
                row["down_for_secs"] = json!(secs);
                row["retryable"] = json!(registry.agent_should_retry(*c));
            }
            row
        })
        .collect();
    let degraded: Vec<&str> = Capability::ALL
        .iter()
        .filter(|c| registry.state(**c) == CapabilityState::Unavailable)
        .map(|c| c.as_str())
        .collect();
    json!({
        "degraded": degraded,
        "services": services,
        // The audit backlog breaker refuses every write while it is tripped.
        "writes_paused": writes_paused,
        // This node's metadata is behind another node's last change.
        "metadata_lagging": metadata_lagging,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_server::ProbeOutcome;

    #[test]
    fn status_action_lists_down_capability() {
        let registry = CapabilityRegistry::new(2, true);
        for c in Capability::ALL {
            registry.record(c, ProbeOutcome::Reachable);
        }
        registry.record(Capability::Email, ProbeOutcome::Unreachable);
        let body = status_body(&registry, false, false);
        assert_eq!(
            body["degraded"],
            json!([]),
            "one failed probe is not an outage"
        );

        registry.record(Capability::Email, ProbeOutcome::Unreachable);
        let body = status_body(&registry, true, false);
        assert_eq!(body["degraded"], json!(["email"]));
        assert_eq!(body["writes_paused"], json!(true));
        let email = body["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["service"] == "email")
            .unwrap();
        assert_eq!(email["state"], "down");
        assert!(email["down_for_secs"].as_u64().unwrap() < 5);
        assert_eq!(
            email["retryable"],
            json!(true),
            "a fresh outage is worth one retry"
        );
        let storage = &body["services"][0];
        assert_eq!(storage["state"], "up");
        assert!(storage.get("retryable").is_none());

        registry.record(Capability::Email, ProbeOutcome::Reachable);
        assert_eq!(status_body(&registry, false, false)["degraded"], json!([]));
    }
}
