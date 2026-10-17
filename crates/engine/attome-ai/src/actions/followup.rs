//! Follow-up actions (roadmap AI4-T4), the only two things the follow-up
//! agent may do with an item of the follow-up ledger (`ai_followup_item`).
//!
//! - `followup.remind_owner` (Reversible): an in-app notification to the
//!   record's owner, written with the item's move to `reminded` in one
//!   transaction (`attome_notification::dispatch::create_dispatch_in_tx`).
//! - `followup.send_message` (Consequential): a message to the customer
//!   through the same writer as the compose route
//!   (`attome_notification::communication::write_communication`), so an
//!   email's `SendEmail` job is enqueued in the message's own transaction;
//!   the item then moves to `sent`. Consequential, so an agent's call stops
//!   at the gate for a person's approval; the detector never sends.
//!
//! Both act only on an item the caller owns (the agent runs for the record
//! owner), only while it is still `open`, `reminded` or `drafted`, and only
//! under the rule's `daily_cap`: the items of the rule reminded or sent since
//! midnight UTC. Over the cap the action is refused with `429`, never a
//! `500`. An agent session's own write caps apply too. Each completed action
//! records an `agent_task` outcome linked to the agent session.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const REMIND_OWNER: &str = "followup.remind_owner";
pub const SEND_MESSAGE: &str = "followup.send_message";

/// The outcome kind both actions record.
pub const OUTCOME_KIND: &str = "agent_task";

/// Per-minute cap on either action inside one agent session.
pub const PER_MINUTE_CAP: i32 = 10;

/// Statuses an item can still be acted on from.
const ACTIONABLE: &str = "('open', 'reminded', 'drafted')";

const REMIND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "item_id": { "type": "string", "format": "uuid", "description": "The ai_followup_item." },
    "note": { "type": "string", "maxLength": 1000, "description": "What to tell the owner." }
  },
  "required": ["item_id"],
  "additionalProperties": false
}"#;

const SEND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "item_id": { "type": "string", "format": "uuid", "description": "The ai_followup_item." },
    "channel": { "type": "string", "enum": ["email", "internal"] },
    "to": { "type": "array", "items": { "type": "string" }, "maxItems": 10,
            "description": "Email addresses, for channel email." },
    "subject": { "type": "string", "maxLength": 300 },
    "body": { "type": "string", "maxLength": 20000, "description": "The drafted message." }
  },
  "required": ["item_id", "channel", "subject", "body"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            REMIND_OWNER,
            "Remind the owner of a stalled record (a follow-up item) with an in-app \
             notification, and mark the item reminded.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(REMIND_SCHEMA)
        .outcome_kind(OUTCOME_KIND),
        ActionDescriptor::new(
            SEND_MESSAGE,
            "Send the drafted follow-up message for a follow-up item, by email or as an \
             internal message, and mark the item sent. A person approves it first.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(SEND_SCHEMA)
        .outcome_kind(OUTCOME_KIND),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(RemindOwner), Box::new(SendMessage)]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

fn text_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, AppError> {
    args[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation(format!("{key} is required")))
}

/// One ledger item with its rule's cap.
#[derive(Debug, Clone)]
struct Item {
    rule_ref: Uuid,
    entity: String,
    record_id: Uuid,
    owner: Uuid,
    reason: String,
    status: String,
    daily_cap: Option<i64>,
}

type ItemRow = (Uuid, String, Uuid, Uuid, String, String, Option<i64>);

async fn load_item(state: &EngineState, ctx: &ActionContext, id: Uuid) -> Result<Item, AppError> {
    let row: Option<ItemRow> = sqlx::query_as(
        "SELECT i.rule_ref, i.entity_logical_name, i.record_id, i.owner_user_id, i.reason, \
                i.status, r.daily_cap::bigint \
         FROM ai_followup_item i LEFT JOIN ai_followup_rule r ON r.id = i.rule_ref \
         WHERE i.id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((rule_ref, entity, record_id, owner, reason, status, daily_cap)) = row else {
        return Err(AppError::NotFound);
    };
    // Only the owner's own items (the agent runs for the owner).
    if owner != ctx.security.user_id && !ctx.security.is_admin {
        return Err(AppError::NotFound);
    }
    if !matches!(status.as_str(), "open" | "reminded" | "drafted") {
        return Err(AppError::Conflict("the follow-up is already closed"));
    }
    Ok(Item {
        rule_ref,
        entity,
        record_id,
        owner,
        reason,
        status,
        daily_cap,
    })
}

/// Whether the rule's cap allows one more reminder or message today.
pub fn under_cap(done_today: i64, daily_cap: Option<i64>) -> bool {
    daily_cap.is_none_or(|cap| done_today < cap)
}

async fn enforce_caps(
    state: &EngineState,
    ctx: &ActionContext,
    action_id: &str,
    item: &Item,
) -> Result<(), AppError> {
    let done_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_followup_item \
         WHERE rule_ref = $1 AND status IN ('reminded', 'sent') \
           AND updated_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",
    )
    .bind(item.rule_ref)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !under_cap(done_today, item.daily_cap) {
        tracing::info!(
            rule = %item.rule_ref,
            action_id,
            done_today,
            "follow-up rule's daily cap reached"
        );
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    if let Some(session) = ctx.agent_session_id {
        let cap = item.daily_cap.unwrap_or(i64::MAX);
        crate::write_guard::enforce_write_caps(state, session, action_id, cap, PER_MINUTE_CAP)
            .await?;
    }
    Ok(())
}

/// Records the completed action in the outcome ledger. Best-effort: the
/// action already happened, so a failed ledger write is logged, not raised.
async fn record_outcome(
    state: &EngineState,
    ctx: &ActionContext,
    action_id: &str,
    item_id: Uuid,
    item: &Item,
) {
    let rule = item.rule_ref.to_string();
    let proposal = crate::outcome::OutcomeProposal {
        kind: OUTCOME_KIND,
        entity_logicalname: Some(&item.entity),
        regarding_entity: Some("ai_followup_item"),
        regarding_id: Some(item_id),
        model_id: None,
        prompt_version: None,
        rule_ref: Some(&rule),
        proposed_by: Some(ctx.security.user_id),
        organization_ref: None,
        expected_value: Some(json!({ "reason": item.reason, "action": action_id })),
    };
    if let Err(e) = crate::outcome::record_proposed(
        &state.base.db,
        Uuid::now_v7(),
        action_id,
        &proposal,
        ctx.agent_session_id,
    )
    .await
    {
        tracing::warn!(item = %item_id, error = %e, "follow-up outcome not recorded");
    }
}

/// Moves an actionable item to `status`; zero rows means someone else
/// closed it first.
async fn mark(
    tx: &mut attome_db::Tx<'_>,
    item_id: Uuid,
    status: &str,
    session: Option<Uuid>,
) -> Result<(), AppError> {
    let moved = sqlx::query(&format!(
        "UPDATE ai_followup_item SET status = $2, updated_at = now(), \
             row_version = row_version + 1, \
             agent_session_ref = COALESCE($3, agent_session_ref) \
         WHERE id = $1 AND status IN {ACTIONABLE}"
    ))
    .bind(item_id)
    .bind(status)
    .bind(session)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if moved == 0 {
        return Err(AppError::Conflict("the follow-up is already closed"));
    }
    Ok(())
}

struct RemindOwner;

impl Action for RemindOwner {
    fn id(&self) -> ActionId {
        ActionId(REMIND_OWNER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let item_id = uuid_arg(args, "item_id")?;
            let note = args["note"].as_str();
            Ok(ActionResult::plain(
                remind(state, ctx, item_id, note).await?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({ "action": REMIND_OWNER, "item_id": args["item_id"], "note": args["note"] }))
    }
}

/// Reminds the item's owner and marks it reminded: the body of
/// `followup.remind_owner`, also called by the follow-up run for a rule whose
/// mode is `remind_owner` (a notification to the owner about their own
/// record, which needs no agent).
pub async fn remind(
    state: &EngineState,
    ctx: &ActionContext,
    item_id: Uuid,
    note: Option<&str>,
) -> Result<Value, AppError> {
    let item = load_item(state, ctx, item_id).await?;
    enforce_caps(state, ctx, REMIND_OWNER, &item).await?;
    let note = note.map(str::trim).unwrap_or_default();
    let body = if note.is_empty() {
        format!("This {} needs a follow-up ({}).", item.entity, item.reason)
    } else {
        note.to_owned()
    };
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_owned(),
        recipient_user_ref: Some(item.owner),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned()]),
        subject: Some(format!("Follow up: {}", item.entity)),
        body_html: None,
        body_text: Some(body),
        route: Some(format!("/{}/{}", item.entity, item.record_id)),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let dispatch = attome_notification::dispatch::create_dispatch_in_tx(
        &mut tx,
        &state.base.config.notification,
        req,
        Some("ai.followup"),
    )
    .await?;
    mark(&mut tx, item_id, "reminded", ctx.agent_session_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    record_outcome(state, ctx, REMIND_OWNER, item_id, &item).await;
    Ok(json!({
        "item_id": item_id,
        "status": "reminded",
        "dispatch_id": dispatch,
    }))
}

struct SendMessage;

impl Action for SendMessage {
    fn id(&self) -> ActionId {
        ActionId(SEND_MESSAGE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let item_id = uuid_arg(args, "item_id")?;
            let channel = text_arg(args, "channel")?;
            let subject = text_arg(args, "subject")?;
            let body = text_arg(args, "body")?;
            let to: Vec<String> = args["to"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let item = load_item(state, ctx, item_id).await?;
            // Writing a message about a record is an update of the record,
            // as on the compose route.
            ctx.security.require(&item.entity, "update")?;
            let entity_id = state
                .entities
                .load()
                .get(&item.entity)
                .map(|m| m.entity_id)
                .ok_or(AppError::NotFound)?;
            attome_records::entity_crud::require_record_access(
                state,
                &ctx.security,
                entity_id,
                &item.entity,
                item.record_id,
                RecordAction::Update,
            )
            .await?;
            let (to, recipients) = attome_notification::communication::validate_recipients(
                channel,
                &to,
                &[item.owner],
            )?;
            enforce_caps(state, ctx, SEND_MESSAGE, &item).await?;
            let sent = attome_notification::communication::write_communication(
                state,
                &ctx.security,
                ctx.security.user_id,
                &item.entity,
                item.record_id,
                channel,
                "outbound",
                &to,
                &recipients,
                subject,
                body,
                None,
                None,
                None,
                None,
            )
            .await?;
            if channel == "internal" {
                attome_notification::communication::notify_internal_recipients(
                    state,
                    &recipients,
                    &item.entity,
                    item.record_id,
                    subject,
                )
                .await;
            }
            // The message is durable; a follow-up already closed meanwhile
            // only means it is not marked again.
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            match mark(&mut tx, item_id, "sent", ctx.agent_session_id).await {
                Ok(()) => tx.commit().await.map_err(AppError::internal)?,
                Err(AppError::Conflict(_)) => {
                    tracing::info!(item = %item_id, "follow-up closed before it was marked sent");
                }
                Err(e) => return Err(e),
            }
            record_outcome(state, ctx, SEND_MESSAGE, item_id, &item).await;
            Ok(ActionResult::plain(json!({
                "item_id": item_id,
                "status": "sent",
                "communication_id": sent.id,
                "previous_status": item.status,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({
            "action": SEND_MESSAGE,
            "item_id": args["item_id"],
            "channel": args["channel"],
            "to": args["to"],
            "subject": args["subject"],
            "body": args["body"],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> ActionDescriptor {
        descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == id)
            .expect("described")
    }

    #[test]
    fn send_message_is_consequential() {
        let d = descriptor(SEND_MESSAGE);
        assert!(matches!(d.risk, RiskTier::Consequential));
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.outcome_kind, Some(OUTCOME_KIND));
    }

    #[test]
    fn remind_owner_is_reversible() {
        let d = descriptor(REMIND_OWNER);
        assert!(matches!(d.risk, RiskTier::Reversible));
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.outcome_kind, Some(OUTCOME_KIND));
    }

    #[test]
    fn the_rule_cap_counts_what_was_done_today() {
        assert!(under_cap(0, Some(1)));
        assert!(!under_cap(1, Some(1)));
        assert!(!under_cap(0, Some(0)));
        assert!(under_cap(1_000, None));
    }

    #[test]
    fn schemas_parse() {
        for schema in [REMIND_SCHEMA, SEND_SCHEMA] {
            assert!(serde_json::from_str::<Value>(schema).is_ok());
        }
    }
}
