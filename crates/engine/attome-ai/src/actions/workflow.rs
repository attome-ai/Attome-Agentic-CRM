//! C5 — starting a workflow (`workflow.start`) and following an approval
//! (`approval.status`).
//!
//! ## `workflow.start`: one start path, reached through the foundation seam
//!
//! `attome-workflow` depends on `attome-ai`, so this crate cannot call it. The
//! executor goes through `attome_core::WorkflowStarter`, which the
//! composition root fills with `attome_workflow::instance_admin::
//! PublishedWorkflowStarter` — the function `POST /api/v1/workflow/instances`
//! itself calls. The published/active/not-deleted definition check is that
//! function's, not a copy.
//!
//! It keeps the HTTP route's boundaries:
//!
//! - **Admin only.** The route is `Authorized<Admin>`; the descriptor requires
//!   `system.admin`, which `gate::admissible` checks on every surface and again
//!   when an approved request executes. The executor checks `is_admin` once
//!   more, so the boundary does not depend on the descriptor alone.
//! - **Licensed as workflow.** The descriptor's module is `MODULE_WORKFLOW`, the
//!   module gating the workflow routes, so an unlicensed deployment refuses it
//!   as absent everywhere.
//! - **Consequential.** A workflow's own steps may send email or call an
//!   external system, and the assistant cannot see how far that reaches. An
//!   agent proposes it; a second person approves it through `attome-approval`
//!   (`gate::evaluate`'s approval arm). `agent_must_confirm` does not replace
//!   that.
//!
//! No starter registered (a bare `EngineState`) is `NotFound`: the action is
//! absent, never a silent success that started nothing.
//!
//! `approval.status` closes the MCP gap `02-capability-model.md` names: an
//! agent whose `Consequential` action returned `approval_required` held an
//! approval id and had no tool to ask what became of it.
//!
//! ## Scoped to the caller's own agent approvals
//!
//! `attome_approval` holds every approval on the platform — schema changes,
//! role grants, other people's agent actions. This action answers for one
//! only when **both** hold:
//!
//! - its `action_type` is an agent action (`approval::ACTION_TYPE_PREFIX`), and
//! - it was requested by the caller: `requested_by` is the acting human
//!   `approval::request_approval` recorded, so a caller sees exactly the
//!   approvals their own agents raised.
//!
//! Anything else is `NotFound`, the same answer as an id that does not exist,
//! so the action cannot be used to probe which approval ids are real. The
//! result carries the status and its timestamps, not the payload: the caller
//! already knows what it asked for, and an approval's arguments are not this
//! action's to re-publish.

use std::future::Future;
use std::pin::Pin;

use attome_approval::ApprovalStatus;
use attome_core::EngineState;
use attome_core::WorkflowStartRequest;
use attome_modules::{MODULE_AI, MODULE_WORKFLOW};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::ACTION_TYPE_PREFIX;
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// The action ids.
pub const WORKFLOW_START: &str = "workflow.start";
pub const APPROVAL_STATUS: &str = "approval.status";

const WORKFLOW_START_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "definition_logicalname": {
      "type": "string",
      "description": "The logical name of the workflow to start. Only its published, active version runs."
    },
    "correlation_entity_id": {
      "type": "string",
      "format": "uuid",
      "description": "Optional. The record the workflow run is about."
    },
    "context": {
      "type": "object",
      "description": "Optional. Input values the workflow's own trigger expects."
    }
  },
  "required": ["definition_logicalname"],
  "additionalProperties": false
}"#;

const APPROVAL_STATUS_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "approval_id": {
      "type": "string",
      "format": "uuid",
      "description": "The approval_id an earlier action returned with approval_required."
    }
  },
  "required": ["approval_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            WORKFLOW_START,
            "Start a published workflow by its logical name, optionally for \
             one record. Only an administrator can, and a second person \
             approves it before it runs. Do NOT use this to change a record \
             directly (use record.update) or to check on a workflow already \
             running.",
            RiskTier::Consequential,
            Effect::Write,
            // A retry without a key would start a second instance.
            RetryClass::RequiresKey,
            MODULE_WORKFLOW,
            &["system.admin"],
        )
        .input_schema(WORKFLOW_START_SCHEMA),
        ActionDescriptor::new(
            APPROVAL_STATUS,
            "Check what happened to an approval request one of your earlier \
             actions raised: pending, approved, rejected, expired, executed, \
             cancelled or invalidated. Use the approval_id that action \
             returned. Do NOT use this to approve or reject anything — a \
             person decides — and do NOT poll it in a loop; ask once when \
             the user wants to know.",
            RiskTier::Read,
            Effect::Read,
            // Reading a status twice is harmless, but its answer changes over
            // time; `cacheable` stays off (the default) for that reason.
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(APPROVAL_STATUS_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(WorkflowStart), Box::new(ApprovalStatusAction)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartArgs {
    definition_logicalname: String,
    #[serde(default)]
    correlation_entity_id: Option<Uuid>,
    #[serde(default)]
    context: Option<serde_json::Map<String, Value>>,
}

fn parse_start(args: &Value) -> Result<StartArgs, AppError> {
    let args: StartArgs = serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid workflow.start arguments: {e}")))?;
    if args.definition_logicalname.trim().is_empty() {
        return Err(AppError::Validation(
            "definition_logicalname must not be empty".into(),
        ));
    }
    Ok(args)
}

pub(crate) struct WorkflowStart;

impl Action for WorkflowStart {
    fn id(&self) -> ActionId {
        ActionId(WORKFLOW_START)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args = parse_start(args)?;
            // The route's `Authorized<Admin>`, held here too (module doc).
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let Some(starter) = state.workflow_starter.as_ref() else {
                return Err(AppError::NotFound);
            };
            let instance_id = starter
                .start(
                    state,
                    WorkflowStartRequest {
                        definition_logicalname: args.definition_logicalname.clone(),
                        started_by: ctx.security.user_id,
                        correlation_entity_id: args.correlation_entity_id,
                        context: Value::Object(args.context.unwrap_or_default()),
                    },
                )
                .await?;
            Ok(ActionResult::plain(json!({
                "definition_logicalname": args.definition_logicalname,
                "instance_id": instance_id,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let args = parse_start(args).ok()?;
        Some(json!({
            "action": WORKFLOW_START,
            "definition_logicalname": args.definition_logicalname,
            "correlation_entity_id": args.correlation_entity_id,
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    approval_id: Uuid,
}

/// `ApprovalStatus::as_str` is private to `attome-approval`; this is the same
/// vocabulary, spelled out so a new variant is a compile error here.
fn status_name(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Rejected => "rejected",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Executed => "executed",
        ApprovalStatus::Cancelled => "cancelled",
        ApprovalStatus::Invalidated => "invalidated",
        ApprovalStatus::Executing => "executing",
    }
}

/// Whether `caller` may see this approval through `approval.status` — see the
/// module doc. One function so the unit tests pin the rule itself.
fn visible_to(action_type: &str, requested_by: Uuid, caller: Uuid) -> bool {
    action_type
        .strip_prefix(ACTION_TYPE_PREFIX)
        .is_some_and(|rest| rest.starts_with(':'))
        && requested_by == caller
}

pub(crate) struct ApprovalStatusAction;

impl Action for ApprovalStatusAction {
    fn id(&self) -> ActionId {
        ActionId(APPROVAL_STATUS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: StatusArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid approval.status arguments: {e}"))
            })?;
            let request = attome_approval::get(&state.base.db, args.approval_id).await?;
            if !visible_to(
                &request.action_type,
                request.requested_by,
                ctx.security.user_id,
            ) {
                return Err(AppError::NotFound);
            }
            let action_id = request
                .payload
                .get("action_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Ok(ActionResult::plain(json!({
                "approval_id": request.id,
                "action_id": action_id,
                "status": status_name(request.status),
                "requested_at": request.requested_at,
                "expires_at": request.expires_at,
                "executed_at": request.executed_at,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> ActionDescriptor {
        descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == id)
            .expect("registered")
    }

    /// Consequential, admin-only, licensed as workflow: the route's own
    /// boundaries, plus four-eyes approval for an agent.
    #[test]
    fn workflow_start_keeps_the_routes_boundaries() {
        let d = descriptor(WORKFLOW_START);
        assert_eq!(d.risk, RiskTier::Consequential);
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.retry, RetryClass::RequiresKey);
        assert_eq!(d.module, MODULE_WORKFLOW);
        assert_eq!(d.required_privileges, &["system.admin"]);
    }

    #[test]
    fn workflow_start_arguments_are_strict() {
        assert!(parse_start(&json!({ "definition_logicalname": "onboard" })).is_ok());
        assert!(parse_start(&json!({ "definition_logicalname": "  " })).is_err());
        assert!(
            parse_start(&json!({ "definition_logicalname": "onboard", "version": 3 })).is_err(),
            "the published version runs; a model cannot pick another"
        );
        assert!(
            parse_start(&json!({ "definition_logicalname": "onboard", "context": "x" })).is_err(),
            "context is an object"
        );
    }

    #[test]
    fn it_is_an_idempotent_read() {
        let d = descriptor(APPROVAL_STATUS);
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.retry, RetryClass::Idempotent);
        assert!(!d.cacheable, "a status changes over time");
    }

    #[test]
    fn only_the_callers_own_agent_approvals_are_visible() {
        let me = Uuid::now_v7();
        let someone = Uuid::now_v7();
        assert!(visible_to("attome-ai/invoke:record.delete", me, me));
        assert!(
            !visible_to("attome-ai/invoke:record.delete", someone, me),
            "another person's agent approval"
        );
        assert!(
            !visible_to("xrm-schema/alter_field", me, me),
            "an approval that is not an agent action, even one I requested"
        );
        assert!(
            !visible_to("attome-ai/invokeX:record.delete", me, me),
            "a prefix look-alike"
        );
    }

    #[test]
    fn unknown_arguments_are_refused() {
        let parsed: Result<StatusArgs, _> =
            serde_json::from_value(json!({ "approval_id": Uuid::now_v7(), "decision": "approve" }));
        assert!(parsed.is_err());
    }
}
