//! AI7-T4: a person hands a ticket back to the agent (job `ai_handback`,
//! queued by `attome_service::handoff::return_to_agent` in the same
//! transaction as the return).
//!
//! [`run`] loads the hand-off; anything but `returned` is left alone. When
//! the agent session that handed it off is still live (not ended, revoked,
//! paused or expired), the person's note is its next user turn, in that
//! session's newest conversation, as the session's owner. Otherwise a new
//! session of the same agent starts for the person who returned it — never
//! a revoked or paused one resumed — and its first turn carries the ticket,
//! the original summary and reasoning, and the note. A new session that is
//! not left waiting on a confirmation or an approval is ended after its
//! turn.
//!
//! **Idempotent.** The turn's text names the hand-off (`[hand-back {id}]`),
//! and a new session's conversation is titled after it: a retried job finds
//! either and does nothing.

use std::sync::Arc;

use attome_core::EngineState;
use attome_service::handoff::{HandBack, Handoff};
use attome_types::AppError;
use uuid::Uuid;

use crate::descriptor::RiskTier;

/// Model steps a hand-back turn may take.
pub const STEP_BUDGET: usize = 8;

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandBackOutcome {
    /// Nothing to do: why.
    Skipped(&'static str),
    /// The live session took the note as its next turn.
    Resumed { conversation_id: Uuid },
    /// A new session ran the hand-back's first turn.
    Started { conversation_id: Uuid },
}

/// The marker a hand-back's turn carries. Pure.
pub fn marker(handoff: Uuid) -> String {
    format!("[hand-back {handoff}]")
}

/// The turn the agent receives. Pure.
pub fn task_text(handoff: &Handoff, note: &str) -> String {
    format!(
        "{marker}\nA person handed ticket {ticket} back to you.\n\
         Your summary when you handed it off: {summary}\n\
         Your reasoning: {reasoning}\n\
         Their note: {note}\n\
         Continue the ticket from their note. Read the ticket before you act.",
        marker = marker(handoff.id),
        ticket = handoff.ticket_id,
        summary = handoff.summary.trim(),
        reasoning = handoff.reasoning.trim(),
        note = note.trim(),
    )
}

/// Runs one hand-back. See the module doc.
pub async fn run(state: &EngineState, job: &HandBack) -> Result<HandBackOutcome, AppError> {
    let db = &state.base.db;
    let handoff = match attome_service::handoff::get_handoff(db, job.handoff_id).await {
        Ok(handoff) => handoff,
        Err(AppError::NotFound) => return Ok(HandBackOutcome::Skipped("no such hand-off")),
        Err(e) => return Err(e),
    };
    if handoff.status != "returned" {
        return Ok(HandBackOutcome::Skipped("not returned"));
    }
    let text = task_text(&handoff, &job.note);

    // The live session, resumed.
    if let Some(session_id) = handoff.agent_session_ref
        && let Some(session) = crate::session::load_live(db, session_id).await?
    {
        let conversation: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ai_conversation WHERE agent_session_id = $1 \
              ORDER BY started_at DESC, id DESC LIMIT 1",
        )
        .bind(session.id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let conversation = match conversation {
            Some(id) => id,
            None => {
                crate::conversation::create(
                    db,
                    crate::conversation::NewConversation {
                        agent_session_id: session.id,
                        owner_user_id: session.owner_user_id,
                        agent_definition_ref: None,
                        surface: crate::conversation::Surface::Internal,
                        title: Some(format!("Hand-back {}", handoff.id)),
                    },
                )
                .await?
                .id
            }
        };
        let done: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM ai_message \
              WHERE conversation_id = $1 AND role = 'user' AND strpos(content, $2) > 0)",
        )
        .bind(conversation)
        .bind(marker(handoff.id))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if done {
            return Ok(HandBackOutcome::Skipped("already handed back"));
        }
        let security = state.base.security.resolve(session.owner_user_id).await?;
        crate::turn::run(
            state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &crate::turn::TurnInputs {
                session: &session,
                security,
                conversation_id: conversation,
                step_budget: Some(STEP_BUDGET),
            },
            &text,
        )
        .await?;
        return Ok(HandBackOutcome::Resumed {
            conversation_id: conversation,
        });
    }

    // A new session of the same agent, for the person who returned it.
    let title = format!("Hand-back {}", handoff.id);
    let started: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ai_conversation WHERE title = $1)")
            .bind(&title)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if started {
        return Ok(HandBackOutcome::Skipped("already handed back"));
    }
    if handoff.from_kind != "agent" {
        return Ok(HandBackOutcome::Skipped("not an agent's hand-off"));
    }
    let person = job.returned_by;
    let security = Arc::new(attome_security::resolve_uncached(db, person).await?);
    let constraints = crate::agent::SessionConstraints {
        risk_ceiling: RiskTier::Reversible,
        allowed_action_ids: None,
    };
    let is_definition: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ai_agent WHERE id = $1 \
           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(handoff.from_ref)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    // The ticket's text reaches the model: the session is tainted.
    let session = if is_definition {
        crate::agent::start_session(
            state,
            &security,
            handoff.from_ref,
            "handoff",
            constraints,
            true,
        )
        .await?
    } else {
        crate::agent::start_session_from_object(
            state,
            &security,
            handoff.from_ref,
            "handoff",
            constraints,
            true,
        )
        .await?
    };
    let ran = async {
        let conversation = crate::conversation::create(
            db,
            crate::conversation::NewConversation {
                agent_session_id: session.id,
                owner_user_id: person,
                agent_definition_ref: is_definition.then_some(handoff.from_ref),
                surface: crate::conversation::Surface::Internal,
                title: Some(title.clone()),
            },
        )
        .await?;
        let outcome = crate::turn::run(
            state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &crate::turn::TurnInputs {
                session: &session,
                security: security.clone(),
                conversation_id: conversation.id,
                step_budget: Some(STEP_BUDGET),
            },
            &text,
        )
        .await?;
        let waiting = matches!(
            outcome.terminal_state,
            crate::conversation::TerminalState::AwaitingConfirmation
                | crate::conversation::TerminalState::AwaitingApproval
        );
        Ok::<_, AppError>((conversation.id, waiting))
    }
    .await;
    // A session waiting on a confirmation or an approval stays live for it.
    if !matches!(ran, Ok((_, true)))
        && let Err(error) =
            crate::session::revoke(db, session.id, person, "hand-back turn finished").await
    {
        tracing::warn!(%error, session = %session.id, "hand-back session not ended");
    }
    let (conversation_id, _) = ran?;
    Ok(HandBackOutcome::Started { conversation_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff() -> Handoff {
        Handoff {
            id: Uuid::from_u128(7),
            ticket_id: Uuid::from_u128(9),
            from_kind: "agent".into(),
            from_ref: Uuid::from_u128(1),
            to_kind: "user".into(),
            to_ref: Uuid::from_u128(2),
            summary: " Refund over the limit ".into(),
            reasoning: "Needs a supervisor".into(),
            agent_session_ref: None,
            status: "returned".into(),
            created_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).expect("a time"),
            accepted_at: None,
            returned_at: None,
            row_version: 3,
        }
    }

    #[test]
    fn the_turn_carries_the_ticket_summary_reasoning_and_note() {
        let text = task_text(&handoff(), " Approved: refund the full amount ");
        assert!(text.starts_with(&marker(Uuid::from_u128(7))));
        assert!(text.contains(&Uuid::from_u128(9).to_string()));
        assert!(text.contains("Your summary when you handed it off: Refund over the limit\n"));
        assert!(text.contains("Your reasoning: Needs a supervisor"));
        assert!(text.contains("Their note: Approved: refund the full amount\n"));
    }
}
