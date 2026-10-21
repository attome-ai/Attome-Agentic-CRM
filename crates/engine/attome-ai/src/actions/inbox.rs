//! `inbox.file_message` (roadmap AI3-T1): places an inbound email on the
//! record the inbox agent made or found for it.
//!
//! Inbound mail arrives as a `communication` on one record (J2-T2's routing:
//! a case, a lead or the sender's contact). When the inbox agent decides the
//! message is about another record too, such as the order or the lead it
//! created from the message, this action adds that record through
//! `communication_link`, the table mail capture (D15-T2) already uses for a
//! message on several records; the record timeline reads both. The message
//! and its attachments then show on that record. Nothing is copied or
//! moved, so filing it again is a no-op and the original placement stays.
//!
//! Reversible: it changes no record, and a wrong link is removed by deleting
//! the row. The caller must be able to read the message and update the
//! target record; only inbound email is filed. An agent session's write
//! caps apply, and each filing records an `agent_task` outcome under rule
//! `ai.inbox`.

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

pub const FILE_MESSAGE: &str = "inbox.file_message";

/// The outcome kind the action records.
pub const OUTCOME_KIND: &str = "agent_task";
/// Per-minute cap inside one agent session.
pub const PER_MINUTE_CAP: i32 = 30;
/// Per-day cap inside one agent session.
pub const PER_DAY_CAP: i64 = 500;

const FILE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "communication_id": { "type": "string", "format": "uuid", "description": "The inbound email (a communication)." },
    "entity": { "type": "string", "maxLength": 100, "description": "Logical name of the record to file it on." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record to file it on." }
  },
  "required": ["communication_id", "entity", "record_id"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        FILE_MESSAGE,
        "File an inbound email, with its attachments, on another record, such as the \
         lead, case or order made from it. The email stays where it was too.",
        RiskTier::Reversible,
        Effect::Write,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(FILE_SCHEMA)
    .outcome_kind(OUTCOME_KIND)
}

#[derive(Debug)]
pub(crate) struct FileMessage;

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

/// Whether a message can be filed: inbound email only. Pure.
pub fn fileable(channel: Option<&str>, direction: Option<&str>) -> bool {
    channel == Some("email") && direction == Some("inbound")
}

/// Files the message on the record: the body of `inbox.file_message`.
pub async fn file_message(
    state: &EngineState,
    ctx: &ActionContext,
    communication_id: Uuid,
    entity: &str,
    record_id: Uuid,
) -> Result<Value, AppError> {
    let message = attome_records::entity_crud::read_record_bulk(
        state,
        &ctx.security,
        "communication",
        communication_id,
    )
    .await?;
    let data = message.data();
    let field = |key: &str| data.get(key).and_then(Value::as_str);
    if !fileable(field("channel"), field("direction")) {
        return Err(AppError::Validation("only an inbound email can be filed".into()));
    }
    if field("entity_name") == Some(entity) && field("record_id") == Some(&record_id.to_string()) {
        return Ok(json!({ "communication_id": communication_id, "filed": false }));
    }
    ctx.security.require(entity, "update")?;
    let entity_id = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        &ctx.security,
        entity_id,
        entity,
        record_id,
        RecordAction::Update,
    )
    .await?;
    if let Some(session) = ctx.agent_session_id {
        crate::write_guard::enforce_write_caps(
            state,
            session,
            FILE_MESSAGE,
            PER_DAY_CAP,
            PER_MINUTE_CAP,
        )
        .await?;
    }
    let added = sqlx::query(
        "INSERT INTO communication_link (communication_id, entity_name, record_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(communication_id)
    .bind(entity)
    .bind(record_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if added > 0 {
        record_outcome(state, ctx, communication_id, entity, record_id).await;
    }
    Ok(json!({
        "communication_id": communication_id,
        "entity": entity,
        "record_id": record_id,
        "filed": added > 0,
    }))
}

/// Records the filing in the outcome ledger; a failure is logged.
async fn record_outcome(
    state: &EngineState,
    ctx: &ActionContext,
    communication_id: Uuid,
    entity: &str,
    record_id: Uuid,
) {
    let proposal = crate::outcome::OutcomeProposal {
        kind: OUTCOME_KIND,
        entity_logicalname: Some(entity),
        regarding_entity: Some("communication"),
        regarding_id: Some(communication_id),
        model_id: None,
        prompt_version: None,
        rule_ref: Some("ai.inbox"),
        proposed_by: Some(ctx.security.user_id),
        organization_ref: None,
        expected_value: Some(json!({ "action": "file", "record_id": record_id })),
    };
    if let Err(error) = crate::outcome::record_proposed(
        &state.base.db,
        Uuid::now_v7(),
        FILE_MESSAGE,
        &proposal,
        ctx.agent_session_id,
    )
    .await
    {
        tracing::warn!(communication = %communication_id, %error, "inbox outcome not recorded");
    }
}

impl Action for FileMessage {
    fn id(&self) -> ActionId {
        ActionId(FILE_MESSAGE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let communication_id = uuid_arg(args, "communication_id")?;
            let record_id = uuid_arg(args, "record_id")?;
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            Ok(ActionResult::plain(
                file_message(state, ctx, communication_id, entity, record_id).await?,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_inbox_filing_is_reversible() {
        let d = descriptor();
        assert!(matches!(d.risk, RiskTier::Reversible));
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.outcome_kind, Some(OUTCOME_KIND));
        assert!(serde_json::from_str::<Value>(FILE_SCHEMA).is_ok());
    }

    #[test]
    fn agent_inbox_files_inbound_email_only() {
        assert!(fileable(Some("email"), Some("inbound")));
        assert!(!fileable(Some("email"), Some("outbound")));
        assert!(!fileable(Some("sms"), Some("inbound")));
        assert!(!fileable(None, None));
    }
}
