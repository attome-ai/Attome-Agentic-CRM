//! `email.send` (roadmap AH8, V2-D693): sends an email about a record.
//!
//! The send is the platform's own compose path,
//! `attome_notification::communication::write_communication`: the outbound
//! `communication` row, its `queued` event and the durable `SendEmail` job in
//! one transaction, with the suppression list, threading and audit that path
//! already has. Nothing here talks to a mail server.
//!
//! `Consequential`: an email that has left cannot be called back. So for an
//! agent it needs approval unless an administrator set its autonomy level
//! higher, and **the undo window is its undo**: at level `act_with_undo`, or
//! when the caller passes `_undo_window_seconds`, it waits in
//! `ai_deferred_action` and the person can cancel it before it leaves. That
//! gives both kinds of send from one action: now, or with undo.
//!
//! `email.draft` stays the action for "write it, a person sends it".

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::actions::draft_email::{COMMUNICATION_ENTITY, MAX_BODY_CHARS, MAX_SUBJECT_CHARS};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EMAIL_SEND: &str = "email.send";
/// Most recipients one send takes.
pub const MAX_RECIPIENTS: usize = 20;

const EMAIL_SEND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Logical name of the record the email is about." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record the email is about." },
    "to": { "type": "array", "items": { "type": "string" }, "description": "Recipient email addresses." },
    "subject": { "type": "string", "description": "Subject line." },
    "body": { "type": "string", "description": "The email text, in the language the recipient uses." },
    "_undo_window_seconds": { "type": "integer", "minimum": 30, "maximum": 86400, "description": "Optional: hold the email this many seconds so the person can cancel it before it is sent." }
  },
  "required": ["entity", "record_id", "to", "subject", "body"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        EMAIL_SEND,
        "Send an email about a record to the addresses given. It leaves the \
         platform and cannot be called back once sent, so use it only when \
         the user wants the email sent, not drafted (use email.draft for a \
         draft). Pass _undo_window_seconds to hold it so the person can \
         cancel it first. Depending on your autonomy level it may wait for \
         approval or for its undo window; the result says which.",
        RiskTier::Consequential,
        Effect::Write,
        // A replayed call would send the email twice.
        RetryClass::RequiresKey,
        attome_modules::MODULE_AI,
        &[],
    )
    .input_schema(EMAIL_SEND_SCHEMA)
}

/// The parsed, checked arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct SendArgs {
    pub entity: String,
    pub record_id: Uuid,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

fn text(args: &Value, key: &str, max: usize) -> Result<String, AppError> {
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
    Ok(value.to_owned())
}

pub fn parse_args(args: &Value) -> Result<SendArgs, AppError> {
    let entity = text(args, "entity", 100)?;
    let record_id = args["record_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("record_id must be a UUID".into()))?;
    let to: Vec<String> = match &args["to"] {
        Value::Array(items) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| AppError::Validation("to must list addresses".into()))
            })
            .collect::<Result<_, _>>()?,
        Value::String(s) => s.split(',').map(str::to_owned).collect(),
        _ => return Err(AppError::Validation("to is required".into())),
    };
    let (to, _) = attome_notification::communication::validate_recipients("email", &to, &[])?;
    if to.len() > MAX_RECIPIENTS {
        return Err(AppError::Validation(format!(
            "at most {MAX_RECIPIENTS} recipients"
        )));
    }
    Ok(SendArgs {
        entity,
        record_id,
        to,
        subject: text(args, "subject", MAX_SUBJECT_CHARS)?,
        body: text(args, "body", MAX_BODY_CHARS)?,
    })
}

#[derive(Debug)]
pub(crate) struct EmailSend;

impl Action for EmailSend {
    fn id(&self) -> ActionId {
        ActionId(EMAIL_SEND)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let send = parse_args(args)?;
            ctx.security.require(COMMUNICATION_ENTITY, "create")?;
            ctx.security.require(&send.entity, "update")?;
            // Record-level access, as the compose route requires: the caller
            // must reach this record, not only hold the entity privilege.
            attome_records::entity_crud::read_record_bulk(
                state,
                &ctx.security,
                &send.entity,
                send.record_id,
            )
            .await?;
            let sent = attome_notification::communication::write_communication(
                state,
                &ctx.security,
                ctx.security.user_id,
                &send.entity,
                send.record_id,
                "email",
                "outbound",
                &send.to,
                &[],
                &send.subject,
                &send.body,
                None,
                None,
                None,
                None,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "communication": sent,
                "status": "queued",
                "detail": "Queued for sending; the communication's events show delivery.",
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let send = parse_args(args).ok()?;
        Some(json!({
            "action": EMAIL_SEND,
            "to": send.to,
            "subject": send.subject,
            "body": send.body,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Value {
        json!({
            "entity": "contact", "record_id": Uuid::now_v7().to_string(),
            "to": ["ada@example.com"], "subject": "Your order", "body": "Hello Ada"
        })
    }

    #[test]
    fn a_send_is_consequential_and_needs_a_key() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Consequential);
        assert_eq!(d.retry, RetryClass::RequiresKey);
        assert!(!d.agent_must_confirm && !d.autonomy_locked);
    }

    #[test]
    fn arguments_parse_and_recipients_are_checked() {
        let parsed = parse_args(&args()).unwrap();
        assert_eq!(parsed.to, vec!["ada@example.com".to_owned()]);
        let mut bad = args();
        bad["to"] = json!(["not-an-address"]);
        assert!(parse_args(&bad).is_err());
        let mut none = args();
        none["to"] = json!([]);
        assert!(parse_args(&none).is_err());
        let mut many = args();
        many["to"] = json!(
            (0..=MAX_RECIPIENTS)
                .map(|i| format!("p{i}@example.com"))
                .collect::<Vec<_>>()
        );
        assert!(parse_args(&many).is_err());
        let mut comma = args();
        comma["to"] = json!("a@example.com, b@example.com");
        assert_eq!(parse_args(&comma).unwrap().to.len(), 2);
    }
}
