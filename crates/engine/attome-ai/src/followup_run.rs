//! One follow-up item, run (roadmap AI4-T5): what the `AiFollowupItem` job
//! does with a stall the scan recorded.
//!
//! - Only an `open` item that no run has claimed is run, so a retried or
//!   duplicated job does nothing the second time.
//! - Nothing runs while AI is switched off (the deployment's or the
//!   runtime switch, for the chat surface); the item stays `open`.
//! - A rule in `remind_owner` mode reminds the owner directly
//!   ([`crate::actions::followup::remind`]): a notification to the owner
//!   about their own record needs no agent.
//! - A rule in `draft_message` or `send_message` mode starts a session of
//!   the `followup_agent` definition for the record's owner, limited to
//!   reading the record, filing an email draft and the two follow-up
//!   actions, and runs one turn asking it to follow the item up. Its writes
//!   go through the gate like any agent's: a draft or reminder waits for the
//!   owner's confirmation in that conversation, and a message waits for a
//!   person's approval. When the definition cannot start a session (it ships
//!   as a draft until an administrator activates it), the owner is
//!   reminded instead.
//! - A collections item (AI5-T5: `invoice_due`, `invoice_overdue`,
//!   `renewal_due`) is sent its reminder directly as the owner
//!   ([`crate::actions::collections::send_reminder`]) while its rule is
//!   active and has reminders left: an administrator who activated the rule
//!   authorised exactly that, so it needs no approval each time. A reminder
//!   that cannot be sent (no customer email, a channel not sent yet) reminds
//!   the owner instead.

use std::sync::Arc;

use attome_config::AiSurface;
use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

use crate::actions::followup::{REMIND_OWNER, SEND_MESSAGE};
use crate::context::ActionContext;
use crate::descriptor::RiskTier;

/// The agent definition that runs follow-ups (`platform-bundles/attome-ai-followup.json`).
pub const FOLLOWUP_AGENT: &str = "followup_agent";

/// Model steps one follow-up turn may take.
pub const STEP_BUDGET: usize = 6;

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Nothing to do: why.
    Skipped(&'static str),
    /// The owner was reminded directly.
    Reminded,
    /// The agent ran one turn in this conversation.
    AgentRan { conversation_id: Uuid },
    /// A collections reminder was sent to the customer.
    Sent,
}

/// The actions a follow-up session may use.
pub fn allowed_actions() -> Vec<String> {
    [
        "record.get",
        crate::actions::draft_email::EMAIL_DRAFT,
        REMIND_OWNER,
        SEND_MESSAGE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The task the agent is given for one item.
pub fn task_text(
    item: Uuid,
    entity: &str,
    record: Uuid,
    reason: &str,
    mode: &str,
    channel: &str,
) -> String {
    let what = match reason {
        "stalled_deal" => "has had no activity for a while",
        "overdue_task" => "is past its due date and still open",
        "unanswered_customer" => "has a customer message nobody has answered",
        _ => "needs a follow-up",
    };
    let step = if mode == "send_message" {
        format!(
            "Draft a short, polite follow-up message in the customer's language and send it \
             with followup.send_message (item_id {item}, channel {channel}); a person approves \
             it before it goes out."
        )
    } else {
        format!(
            "Draft a short, polite follow-up message in the customer's language and file it \
             with email.draft on the record, then remind the owner with \
             followup.remind_owner (item_id {item})."
        )
    };
    format!(
        "Follow-up item {item}: the {entity} record {record} {what}. Read it with record.get \
         first and use only facts from it. {step}"
    )
}

type ItemRow = (
    String,
    Uuid,
    Uuid,
    String,
    Option<Uuid>,
    String,
    Option<String>,
    Option<String>,
);

/// Items one scan hands to runs at most.
pub const ITEMS_PER_SCAN: i64 = 200;

/// The open items no run has claimed yet, oldest first.
pub async fn open_items(db: &attome_db::DbPool) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM ai_followup_item \
         WHERE status = 'open' AND agent_session_ref IS NULL \
         ORDER BY created_at, id LIMIT $1",
    )
    .bind(ITEMS_PER_SCAN)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Runs one follow-up item. See the module doc.
pub async fn run_item(state: &EngineState, item_id: Uuid) -> Result<RunOutcome, AppError> {
    let db = &state.base.db;
    let row: Option<ItemRow> = sqlx::query_as(
        "SELECT i.entity_logical_name, i.record_id, i.owner_user_id, i.status, \
                i.agent_session_ref, i.reason, r.mode, r.channel \
         FROM ai_followup_item i LEFT JOIN ai_followup_rule r ON r.id = i.rule_ref \
         WHERE i.id = $1",
    )
    .bind(item_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((entity, record, owner, status, claimed, reason, mode, channel)) = row else {
        return Ok(RunOutcome::Skipped("no such item"));
    };
    if status != "open" || claimed.is_some() {
        return Ok(RunOutcome::Skipped("already handled"));
    }
    // The snapshot is per process and fails closed until read.
    attome_core::ai_runtime_switch::refresh(db).await;
    if !attome_core::ai_runtime_switch::allows(&state.base.config.inference.ai, AiSurface::Chat) {
        tracing::info!(item = %item_id, "follow-up skipped: AI is switched off");
        return Ok(RunOutcome::Skipped("AI is switched off"));
    }
    let mode = mode.unwrap_or_else(|| "remind_owner".to_owned());
    let channel = channel.unwrap_or_else(|| "email".to_owned());
    let security = Arc::new(attome_security::resolve_uncached(db, owner).await?);
    if crate::actions::collections::is_collections_reason(&reason) {
        return run_collections(state, &security, item_id, &entity, record).await;
    }
    if mode == "remind_owner" {
        return remind_owner(state, &security, item_id).await;
    }

    let definition: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ai_agent WHERE name = $1 \
           AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT 1",
    )
    .bind(FOLLOWUP_AGENT)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(definition) = definition else {
        return remind_owner(state, &security, item_id).await;
    };
    let session = match crate::agent::start_session(
        state,
        &security,
        definition,
        "followup",
        crate::agent::SessionConstraints {
            risk_ceiling: RiskTier::Consequential,
            allowed_action_ids: Some(allowed_actions()),
        },
        // The record's text reaches the model: treat the session as tainted.
        true,
    )
    .await
    {
        Ok(session) => session,
        Err(AppError::Validation(why)) => {
            tracing::info!(item = %item_id, %why, "follow-up agent cannot start; reminding the owner");
            return remind_owner(state, &security, item_id).await;
        }
        Err(e) => return Err(e),
    };
    // Claim the item for this session; a second run finds it claimed.
    let claimed = sqlx::query(
        "UPDATE ai_followup_item SET agent_session_ref = $2, updated_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND status = 'open' AND agent_session_ref IS NULL",
    )
    .bind(item_id)
    .bind(session.id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    let ran = if claimed == 0 {
        Ok(None)
    } else {
        async {
            let conversation = crate::conversation::create(
                db,
                crate::conversation::NewConversation {
                    agent_session_id: session.id,
                    owner_user_id: owner,
                    agent_definition_ref: Some(definition),
                    surface: crate::conversation::Surface::Internal,
                    title: Some(format!("Follow-up: {entity}")),
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
                &task_text(item_id, &entity, record, &reason, &mode, &channel),
            )
            .await?;
            let waiting = matches!(
                outcome.terminal_state,
                crate::conversation::TerminalState::AwaitingConfirmation
                    | crate::conversation::TerminalState::AwaitingApproval
            );
            Ok::<_, AppError>(Some((conversation.id, waiting)))
        }
        .await
    };
    // A session waiting on the owner's confirmation or a person's approval
    // stays live for it; every other one is ended now.
    if !matches!(ran, Ok(Some((_, true))))
        && let Err(error) =
            crate::session::revoke(db, session.id, owner, "follow-up run finished").await
    {
        tracing::warn!(%error, session = %session.id, "follow-up session not ended");
    }
    match ran? {
        Some((conversation_id, _)) => Ok(RunOutcome::AgentRan { conversation_id }),
        None => Ok(RunOutcome::Skipped("already handled")),
    }
}

/// Sends a collections item's reminder as its owner, within its rule.
async fn run_collections(
    state: &EngineState,
    security: &Arc<attome_server::security::SecurityContext>,
    item_id: Uuid,
    entity: &str,
    record: Uuid,
) -> Result<RunOutcome, AppError> {
    let ctx = ActionContext::user(security.clone());
    let item = match crate::actions::collections::load_item(state, &ctx, item_id).await {
        Ok(item) => item,
        Err(AppError::NotFound | AppError::Conflict(_)) => {
            return Ok(RunOutcome::Skipped("already handled"));
        }
        Err(e) => return Err(e),
    };
    if !item.rule_active {
        return Ok(RunOutcome::Skipped("the collection rule is off"));
    }
    if let Some(max) = item.max_reminders {
        let sent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ai_followup_item \
              WHERE rule_ref = $1 AND entity_logical_name = $2 AND record_id = $3 \
                AND status = 'sent'",
        )
        .bind(item.rule_id)
        .bind(entity)
        .bind(record)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if sent >= max {
            return Ok(RunOutcome::Skipped("the rule's reminders are used up"));
        }
    }
    match crate::actions::collections::send_reminder(state, &ctx, item_id).await {
        Ok(_) => Ok(RunOutcome::Sent),
        Err(AppError::Validation(why)) => {
            tracing::info!(item = %item_id, %why, "collections reminder not sent; reminding the owner");
            remind_owner(state, security, item_id).await
        }
        Err(AppError::Conflict(_)) => Ok(RunOutcome::Skipped("already handled")),
        Err(e) => Err(e),
    }
}

async fn remind_owner(
    state: &EngineState,
    security: &Arc<attome_server::security::SecurityContext>,
    item_id: Uuid,
) -> Result<RunOutcome, AppError> {
    let ctx = ActionContext::user(security.clone());
    match crate::actions::followup::remind(state, &ctx, item_id, None).await {
        Ok(_) => Ok(RunOutcome::Reminded),
        // Over the rule's cap the item stays open for a later run.
        Err(AppError::TooManyRequests { .. }) => Ok(RunOutcome::Skipped("daily cap reached")),
        Err(AppError::Conflict(_)) => Ok(RunOutcome::Skipped("already handled")),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_may_only_read_draft_remind_and_send() {
        let allowed = allowed_actions();
        assert_eq!(allowed.len(), 4);
        for id in ["record.get", "email.draft", REMIND_OWNER, SEND_MESSAGE] {
            assert!(allowed.iter().any(|a| a == id), "{id}");
        }
        // Every one is a registered action, and none changes or deletes records.
        let registered = crate::actions::all();
        for id in &allowed {
            assert!(
                registered.iter().any(|d| d.id.as_str() == id),
                "{id} is registered"
            );
            assert!(!id.starts_with("record.delete") && id != "record.update");
        }
    }

    #[test]
    fn the_task_names_the_item_and_the_way_to_act() {
        let item = Uuid::nil();
        let record = Uuid::max();
        let send = task_text(
            item,
            "opportunity",
            record,
            "stalled_deal",
            "send_message",
            "email",
        );
        assert!(send.contains("followup.send_message"));
        assert!(send.contains(&item.to_string()));
        assert!(send.contains("no activity"));
        let draft = task_text(
            item,
            "task",
            record,
            "overdue_task",
            "draft_message",
            "email",
        );
        assert!(draft.contains("email.draft"));
        assert!(draft.contains("followup.remind_owner"));
        assert!(!draft.contains("followup.send_message"));
    }
}
