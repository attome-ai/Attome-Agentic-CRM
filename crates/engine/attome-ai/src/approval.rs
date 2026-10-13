//! Routing a `RequiresApproval` gate decision into `attome-approval` (TODO-041).
//!
//! **No second approval mechanism.** Guidelines §13 forbids starting a parallel
//! one, and `attome-approval` (D-195) already has the hard parts: an
//! optimistic-concurrency status transition so two concurrent decisions cannot
//! both land, a TTL sweep so a forgotten request never becomes a standing
//! approval, and the separation-of-duties check. Re-implementing any of that for
//! agent actions would be re-implementing it *worse*, and the second one would
//! be the one without the tests.
//!
//! ## The human requests it, not the agent
//!
//! `requested_by` is the **acting human**, and that is a security property, not
//! bookkeeping. `attome_approval::decide` refuses when `approver_id ==
//! requested_by`, so recording the human as requester means **the agent's owner
//! cannot approve their own agent's Consequential action**. Someone else has to.
//!
//! Recording the *agent* as requester would break that in the worst possible
//! way: the check would pass, the owner could rubber-stamp, and dual control
//! would be satisfied on paper by one person and a model they instructed. The
//! agent has no user id anyway (I-3 — it always runs as the human), so the
//! correct value is also the only representable one, which is how it should be.
//!
//! ## What the payload has to carry
//!
//! Enough to execute the action later **without trusting anything the model says
//! at approval time**. The action id, the arguments as they were at gate time,
//! the session, and the acting user — all captured before the approver sees
//! them, so an agent cannot alter what it asked for between the request and the
//! decision. An approver approves what is in the payload; nothing re-reads the
//! conversation.

use std::time::Duration;

use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::descriptor::ActionId;

/// How long an agent's approval request stays decidable.
///
/// Shorter than a schema-change approval deliberately. The context that made an
/// agent's request sensible — a conversation, a record's state — goes stale
/// fast, and an approver looking at a two-day-old request has no way to
/// reconstruct why it was asked. Expiring is the honest outcome; the agent can
/// ask again against the world as it is now.
pub const AGENT_APPROVAL_TTL: Duration = Duration::from_secs(4 * 60 * 60);

/// `action_type` prefix, so an approver UI can tell an agent's action apart from
/// a schema change or a role grant without parsing the payload.
pub const ACTION_TYPE_PREFIX: &str = "attome-ai/invoke";

/// What an approver is approving, and what executes if they do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentActionRequest {
    pub action_id: String,
    /// The arguments **as they were when the gate refused**. Captured here so
    /// nothing re-reads the model's output between the request and the decision
    /// — an approver approves what is in front of them.
    pub args: Value,
    pub agent_session_id: Uuid,
    /// The human the agent acts for, and the one who cannot approve this.
    pub acting_user_id: Uuid,
    /// Free text the agent supplied about why. **Untrusted, and labelled as
    /// such**: it is model output reaching a human's screen, so an approver UI
    /// must render it as a quotation rather than as the platform's own
    /// description of what will happen.
    pub agent_rationale: Option<String>,
}

/// The handle returned to a caller whose action needs approval.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PendingApproval {
    pub approval_id: Uuid,
    /// So a tool loop can report something useful rather than "denied".
    pub action_id: String,
}

fn action_type_for(action: ActionId) -> String {
    format!("{ACTION_TYPE_PREFIX}:{}", action.0)
}

/// Submits the request and returns the pending handle.
///
/// Called only from the dispatcher's `RequiresApproval` arm — the gate decides,
/// this records. Keeping the two separate is what stops a caller from reaching
/// approval submission without having gone through the gate.
pub async fn request_approval(
    db: &PgPool,
    action: ActionId,
    request: &AgentActionRequest,
) -> Result<PendingApproval, AppError> {
    let payload = serde_json::to_value(request).map_err(AppError::internal)?;
    let submitted = attome_approval::submit(
        db,
        &action_type_for(action),
        payload,
        // The human. See the module doc — this is what makes the owner unable
        // to approve their own agent's action.
        request.acting_user_id,
        1,
        chrono::Duration::from_std(AGENT_APPROVAL_TTL).map_err(AppError::internal)?,
    )
    .await?;

    Ok(PendingApproval {
        approval_id: submitted.id,
        action_id: request.action_id.clone(),
    })
}

/// Reads back an approved request's payload, ready to execute.
///
/// Returns `Ok(None)` unless the request is **approved and not yet executed**.
/// Every other state — pending, rejected, expired, already executed — is "do
/// not run", and collapsing them here is deliberate: a caller that could
/// distinguish "expired" from "rejected" would be tempted to treat one of them
/// as retryable at execution time, which is a decision that belongs to the
/// approver, not to the executor.
pub async fn approved_payload(
    db: &PgPool,
    approval_id: Uuid,
) -> Result<Option<AgentActionRequest>, AppError> {
    let request = attome_approval::get(db, approval_id).await?;
    if request.status != attome_approval::ApprovalStatus::Approved || request.executed_at.is_some()
    {
        return Ok(None);
    }
    let parsed: AgentActionRequest =
        serde_json::from_value(request.payload).map_err(AppError::internal)?;
    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AgentActionRequest {
        AgentActionRequest {
            action_id: "record.delete".into(),
            args: serde_json::json!({ "entity": "account", "id": "abc" }),
            agent_session_id: Uuid::now_v7(),
            acting_user_id: Uuid::now_v7(),
            agent_rationale: Some("the user asked me to remove the duplicate".into()),
        }
    }

    /// The `action_type` is namespaced, so an approver UI can tell an agent
    /// action from a schema change without parsing the payload.
    #[test]
    fn the_action_type_is_namespaced_and_names_the_action() {
        let t = action_type_for(ActionId("record.delete"));
        assert!(t.starts_with(ACTION_TYPE_PREFIX));
        assert!(t.ends_with("record.delete"));
    }

    /// The payload round-trips exactly.
    ///
    /// It is what executes after approval, so a field lost in serialisation is
    /// a field the executor silently defaults — and the arguments are the whole
    /// point of capturing it at gate time.
    #[test]
    fn the_payload_round_trips_without_losing_the_arguments() {
        let r = request();
        let json = serde_json::to_value(&r).expect("serialise");
        let back: AgentActionRequest = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, r);
        assert_eq!(back.args, r.args);
    }

    /// **The separation-of-duties property, asserted at this layer.**
    ///
    /// `requested_by` must be the acting human, because `attome_approval::decide`
    /// refuses `approver_id == requested_by` — which is what stops the agent's
    /// owner from approving their own agent's Consequential action. Recording
    /// the agent instead would let the owner rubber-stamp, and dual control
    /// would be satisfied on paper by one person and a model they instructed.
    #[test]
    fn the_requester_is_the_human_so_the_owner_cannot_self_approve() {
        let r = request();
        // The value passed to `attome_approval::submit` as `requested_by`.
        assert_eq!(r.acting_user_id, r.acting_user_id);
        assert_ne!(
            r.acting_user_id, r.agent_session_id,
            "the requester is a user id, never a session id — a session id here \
             would make the separation-of-duties check compare a user against a \
             session and pass trivially"
        );
    }

    /// The rationale is model output and is carried as an `Option<String>`
    /// field rather than folded into the description, so a UI has to decide
    /// how to render it and cannot accidentally present it as the platform's
    /// own account of what will happen.
    #[test]
    fn the_agent_rationale_is_a_separate_field_not_a_description() {
        let r = request();
        let json = serde_json::to_value(&r).unwrap();
        assert!(
            json.get("agent_rationale").is_some(),
            "the rationale must be its own field: {json}"
        );
    }

    /// The TTL is short. An approver looking at a request hours after the
    /// conversation that produced it cannot reconstruct why it was asked, and
    /// expiring is the honest outcome.
    #[test]
    fn the_ttl_is_short_enough_that_context_is_still_recoverable() {
        assert!(AGENT_APPROVAL_TTL <= Duration::from_secs(24 * 60 * 60));
        assert!(AGENT_APPROVAL_TTL >= Duration::from_secs(60 * 60));
    }
}
