//! `email.draft` (roadmap N3-T1): files an email the model wrote as a draft
//! on a record's communications, for a person to review and send.
//!
//! The model writes the subject and body in the conversation, from the
//! record, its thread and any knowledge it read; this action only files the
//! result, like `article.draft`. The communication is created with status
//! `draft` and direction `outbound`; nothing is sent, and no argument can
//! make it anything but a draft. Sending is a separate, human step.
//!
//! The caller needs create on `communication` and read on the record it is
//! filed against (the engine's own create path checks lookups and field
//! rules). `Reversible`: a draft nobody sent is easy to delete; for an agent
//! it degrades to a person's confirmation like every other write.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EMAIL_DRAFT: &str = "email.draft";
/// The communication entity a draft is filed in.
pub const COMMUNICATION_ENTITY: &str = "communication";
/// The only status this action writes.
pub const DRAFT_STATUS: &str = "draft";
/// Longest subject.
pub const MAX_SUBJECT_CHARS: usize = 300;
/// Longest body.
pub const MAX_BODY_CHARS: usize = 50_000;

const EMAIL_DRAFT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Logical name of the record the email is about." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record the email is about." },
    "to": { "type": "string", "description": "Recipient addresses, comma separated." },
    "subject": { "type": "string", "description": "Subject line." },
    "body": { "type": "string", "description": "The email text, in the language the recipient uses." },
    "in_reply_to": { "type": "string", "format": "uuid", "description": "Optional: the communication this replies to." }
  },
  "required": ["entity", "record_id", "to", "subject", "body"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        EMAIL_DRAFT,
        "File an email you wrote as a DRAFT on a record, for a person to review \
         and send. Nothing is sent. Write the subject and body yourself, in the \
         recipient's language, from the record and its thread.",
        RiskTier::Reversible,
        Effect::Write,
        // A replayed call would file a second draft.
        RetryClass::RequiresKey,
        attome_modules::MODULE_AI,
        &[],
    )
    .input_schema(EMAIL_DRAFT_SCHEMA)
    .agent_must_confirm()
}

fn text_arg<'v>(args: &'v Value, key: &str, max: usize) -> Result<&'v str, AppError> {
    let value = args[key]
        .as_str()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Validation(format!("{key} is required")))?;
    if value.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{key} is longer than {max} characters"
        )));
    }
    Ok(value)
}

/// The communication record a draft becomes.
pub fn draft_values(args: &Value) -> Result<Map<String, Value>, AppError> {
    let entity = text_arg(args, "entity", 100)?;
    let record_id = args["record_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("record_id must be a UUID".into()))?;
    let to = text_arg(args, "to", 2_000)?;
    let subject = text_arg(args, "subject", MAX_SUBJECT_CHARS)?;
    let body = text_arg(args, "body", MAX_BODY_CHARS)?;
    let mut values = Map::new();
    values.insert("entity_name".into(), json!(entity));
    values.insert("record_id".into(), json!(record_id.to_string()));
    values.insert("channel".into(), json!("email"));
    values.insert("direction".into(), json!("outbound"));
    values.insert("status".into(), json!(DRAFT_STATUS));
    values.insert("to_addresses".into(), json!(to));
    values.insert("subject".into(), json!(subject));
    values.insert("body".into(), json!(body));
    if let Some(reply) = args["in_reply_to"].as_str() {
        let reply = Uuid::parse_str(reply)
            .map_err(|_| AppError::Validation("in_reply_to must be a UUID".into()))?;
        values.insert("in_reply_to".into(), json!(reply.to_string()));
    }
    Ok(values)
}

#[derive(Debug)]
pub(crate) struct EmailDraft;

impl Action for EmailDraft {
    fn id(&self) -> ActionId {
        ActionId(EMAIL_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let values = draft_values(args)?;
            let entity = values["entity_name"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            ctx.security.require(COMMUNICATION_ENTITY, "create")?;
            ctx.security.require(&entity, "read")?;
            let (draft_id, _) = attome_records::entity_crud::create_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                COMMUNICATION_ENTITY,
                Value::Object(values),
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "communication_id": draft_id,
                "status": DRAFT_STATUS,
                "detail": "Filed as a draft. Nothing was sent; a person reviews and sends it.",
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let values = draft_values(args).ok()?;
        Some(json!({
            "action": EMAIL_DRAFT,
            "to": values["to_addresses"],
            "subject": values["subject"],
            "body": values["body"],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_is_always_an_outbound_email_draft() {
        let values = draft_values(&json!({
            "entity": "contact", "record_id": Uuid::now_v7().to_string(),
            "to": "ada@example.com", "subject": "Your order", "body": "Hello Ada",
            "status": "sent"
        }))
        .unwrap();
        assert_eq!(values["status"], "draft", "no argument changes the status");
        assert_eq!(values["channel"], "email");
        assert_eq!(values["direction"], "outbound");
        assert!(draft_values(&json!({ "entity": "contact" })).is_err());
        let long = draft_values(&json!({
            "entity": "contact", "record_id": Uuid::now_v7().to_string(),
            "to": "a@b.c", "subject": "x".repeat(MAX_SUBJECT_CHARS + 1), "body": "b"
        }));
        assert!(long.is_err());
    }
}
