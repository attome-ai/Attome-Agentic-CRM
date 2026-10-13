//! `agent.pause` / `agent.resume` / `agent.kill` — supervisor actions over a
//! live [`crate::session::AgentSession`] (M33 Phase 1, D-460).
//!
//! ## Additive to the kill-switch, never a replacement
//!
//! `AiEnablement`'s global/per-surface kill-switch (TODO-055) stays the one
//! authority over whether AI runs on a deployment at all — these three
//! actions do not bypass it (they are ordinary `MODULE_AI` actions and are
//! gated by it exactly like `record.classify`, through the same
//! `/api/v1/actions/{id}/invoke` -> `gate::evaluate` path everything else
//! uses). What they add is a finer-grained control an operator can reach for
//! **without** disabling AI for the whole deployment: stop, freeze, or
//! unfreeze one runaway agent session.
//!
//! ## Admin-tier, and `Consequential` on purpose
//!
//! Controlling another session's execution state is not a `Reversible`
//! action an agent should ever be trusted to auto-execute on itself or on a
//! sibling session — even a well-behaved agent invoking `agent.resume` on a
//! session a human just paused would defeat the pause. `RiskTier::Consequential`
//! makes that structurally impossible for an agent initiator (`gate.rs`'s
//! `(Consequential, Agent) => RequiresApproval` arm, never `Execute`); a human
//! supervisor holding `ai_agent.supervise` still executes immediately
//! (`(Consequential, User) => Execute`), which is the whole point of a
//! dashboard control.
//!
//! ## Idempotent by construction
//!
//! Pausing/resuming/killing an already-paused/live/dead session no-ops
//! (`changed: false` in the result) rather than erroring — see
//! `session::pause`/`session::resume`/`session::revoke`'s own doc comments.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_server::authz::PrivilegeKey;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const AGENT_PAUSE: &str = "agent.pause";
pub const AGENT_RESUME: &str = "agent.resume";
pub const AGENT_KILL: &str = "agent.kill";

/// `ai_agent.supervise` — the admin-tier privilege gating all three
/// supervisor actions AND the read-only sessions dashboard
/// (`crate::session_admin`). One privilege for both, deliberately: a
/// deployment that lets someone SEE the live-sessions dashboard already lets
/// them act on it, the same "reuse the same privilege for read and act"
/// convention `agent.rs`'s own `AgentUpdate` establishes for starting
/// sessions.
#[derive(Debug)]
pub struct AgentSupervise;

impl PrivilegeKey for AgentSupervise {
    const KEY: &'static str = "ai_agent.supervise";
}

#[derive(Deserialize)]
struct SupervisionArgs {
    session_id: Uuid,
    #[serde(default)]
    reason: Option<String>,
}

/// M101 slice 3 — the argument contract, mirroring ``SupervisionArgs``.
/// See `descriptor::UNDECLARED_SCHEMA` for why every action carries one, and
/// `lib.rs`'s `schemas_are_wellformed_and_describe_an_object` for what keeps
/// it honest.
const SUPERVISION_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "session_id": {
      "type": "string",
      "format": "uuid",
      "description": "The agent session to pause, resume, or kill."
    },
    "reason": {
      "type": "string",
      "description": "Operator note recorded against the supervision event."
    }
  },
  "required": ["session_id"],
  "additionalProperties": false
}"#;

fn descriptor(id: &'static str, description: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        description,
        RiskTier::Consequential,
        Effect::Write,
        RetryClass::Idempotent,
        attome_modules::MODULE_AI,
        &[AgentSupervise::KEY],
    )
    .input_schema(SUPERVISION_SCHEMA)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        descriptor(
            AGENT_PAUSE,
            "Pause a live agent session, freezing it without ending it. \
             Resumable via agent.resume.",
        ),
        descriptor(
            AGENT_RESUME,
            "Resume a paused agent session. Has no effect on a session that \
             is not currently paused.",
        ),
        descriptor(
            AGENT_KILL,
            "Permanently revoke an agent session (TODO-039). Not resumable — \
             a killed session must be started fresh.",
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(AgentPause),
        Box::new(AgentResume),
        Box::new(AgentKill),
    ]
}

#[derive(Debug)]
pub struct AgentPause;

impl Action for AgentPause {
    fn id(&self) -> ActionId {
        ActionId(AGENT_PAUSE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SupervisionArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))?;
            let reason = args
                .reason
                .unwrap_or_else(|| "paused by supervisor".to_owned());
            let changed = crate::session::pause(
                &state.base.db,
                args.session_id,
                ctx.security.user_id,
                &reason,
            )
            .await?;
            tracing::info!(
                session_id = %args.session_id,
                actor = %ctx.security.user_id,
                changed,
                "agent.pause invoked"
            );
            Ok(ActionResult::plain(serde_json::json!({
                "session_id": args.session_id,
                "changed": changed,
            })))
        })
    }
}

#[derive(Debug)]
pub struct AgentResume;

impl Action for AgentResume {
    fn id(&self) -> ActionId {
        ActionId(AGENT_RESUME)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SupervisionArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))?;
            let changed = crate::session::resume(&state.base.db, args.session_id).await?;
            tracing::info!(
                session_id = %args.session_id,
                actor = %ctx.security.user_id,
                changed,
                "agent.resume invoked"
            );
            Ok(ActionResult::plain(serde_json::json!({
                "session_id": args.session_id,
                "changed": changed,
            })))
        })
    }
}

#[derive(Debug)]
pub struct AgentKill;

impl Action for AgentKill {
    fn id(&self) -> ActionId {
        ActionId(AGENT_KILL)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SupervisionArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))?;
            let reason = args
                .reason
                .unwrap_or_else(|| "killed by supervisor".to_owned());
            // The existing TODO-039 primitive (`session::revoke`) had zero
            // callers before this action — this is the first one, not a
            // second kill mechanism (guidelines §13).
            let changed = crate::session::revoke(
                &state.base.db,
                args.session_id,
                ctx.security.user_id,
                &reason,
            )
            .await?;
            tracing::info!(
                session_id = %args.session_id,
                actor = %ctx.security.user_id,
                changed,
                "agent.kill invoked"
            );
            Ok(ActionResult::plain(serde_json::json!({
                "session_id": args.session_id,
                "changed": changed,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supervisor_action_is_consequential_write_and_admin_gated() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Consequential, "{}", d.id);
            assert_eq!(d.effect, Effect::Write, "{}", d.id);
            assert_eq!(d.required_privileges.len(), 1, "{}", d.id);
            assert_eq!(d.required_privileges[0], AgentSupervise::KEY, "{}", d.id);
            assert_eq!(
                (d.module.word, d.module.mask),
                (
                    attome_modules::MODULE_AI.word,
                    attome_modules::MODULE_AI.mask
                ),
                "{}",
                d.id
            );
        }
    }

    /// **The negative test the whole descriptor choice exists for.** An
    /// agent — even one whose session's own `allowed_action_ids` lists
    /// `agent.kill` — can never auto-execute it; a human must approve.
    /// Otherwise a compromised or merely over-eager agent could kill (or
    /// resume) sessions unattended, including possibly its own supervisor's
    /// controls.
    #[test]
    fn an_agent_can_never_auto_execute_a_supervisor_action() {
        use crate::context::ActionContext;
        use crate::context::tests::security_context_with;
        use crate::gate::{self, GateDecision};
        use attome_config::AiEnablement;

        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        // Even an admin-privileged agent session must not auto-execute.
        let security = security_context_with(true, &[AgentSupervise::KEY]);
        let ctx = ActionContext::agent(security, RiskTier::Consequential);
        let inputs = gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };

        for d in descriptors() {
            assert_eq!(
                gate::evaluate(&d, &ctx, &inputs),
                Ok(GateDecision::RequiresApproval),
                "{} must require approval for an agent initiator",
                d.id
            );
        }
    }

    /// A human supervisor holding the privilege executes immediately — the
    /// dashboard control is not itself blocked by four-eyes.
    #[test]
    fn a_privileged_human_executes_a_supervisor_action_immediately() {
        use crate::context::ActionContext;
        use crate::context::tests::security_context_with;
        use crate::gate::{self, GateDecision};
        use attome_config::AiEnablement;

        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        let security = security_context_with(false, &[AgentSupervise::KEY]);
        let ctx = ActionContext::user(security);
        let inputs = gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };

        for d in descriptors() {
            assert_eq!(gate::evaluate(&d, &ctx, &inputs), Ok(GateDecision::Execute));
        }
    }

    /// A human WITHOUT the privilege — and not an admin — is refused, exactly
    /// like any other admin-tier action.
    #[test]
    fn a_human_without_the_privilege_is_forbidden() {
        use crate::context::ActionContext;
        use crate::context::tests::security_context;
        use crate::gate::{self, GateRefusal};
        use attome_config::AiEnablement;

        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        let ctx = ActionContext::user(security_context());
        let inputs = gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };

        for d in descriptors() {
            assert_eq!(
                gate::evaluate(&d, &ctx, &inputs),
                Err(GateRefusal::Forbidden)
            );
        }
    }
}
