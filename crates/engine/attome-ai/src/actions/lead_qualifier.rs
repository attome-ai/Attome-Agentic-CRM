//! Lead qualification actions (roadmap AI1-T1), the two steps of the lead
//! qualifier agent that reach the prospect. Reading, updating and assigning
//! the lead are the generic `record.get`, `record.update` and
//! `record.assign`; research is `search.records` and `record.summarize`
//! until enrichment (L9) ships.
//!
//! - `lead.send_message` (Consequential): an email to the lead through the
//!   compose writer (`attome_notification::communication::write_communication`),
//!   the one `followup.send_message` uses, so the message is a
//!   `communication` on the lead.
//! - `lead.book_meeting` (Consequential): a meeting on a booking page
//!   (D20-T2, `attome_sales::booking::book`) at one of its offered times, in
//!   the lead's name and email. The booking engine gives it to a free team
//!   member round robin, attaches it to the lead by its email and sends the
//!   lead the confirmation with the reschedule and cancel link.
//!
//! Both are Consequential, so an agent's call waits for a person's approval,
//! and both refuse unless the lead holds a grant in force for
//! [`OUTREACH_PURPOSE`] on email in the consent ledger (E27,
//! `attome_core::consent_rules::gate`); no grant, a withdrawal or an
//! account opt-out refuses, never sends. Both act only on a lead the caller
//! may update, apply an agent session's write caps, and record an
//! `agent_task` outcome tied to the session (rule `ai.lead`).
//!
//! Only email is sent today: the compose writer sends email and internal
//! messages, so WhatsApp waits for the omnichannel sender.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_core::consent_rules::Decision;
use attome_modules::MODULE_AI;
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SEND_MESSAGE: &str = "lead.send_message";
pub const BOOK_MEETING: &str = "lead.book_meeting";

/// The consent purpose a lead must have granted before the agent contacts
/// them. A deployment records it on the lead (`consent_event`) from its
/// forms or by hand.
pub const OUTREACH_PURPOSE: &str = "sales_outreach";
/// The outcome kind both actions record.
pub const OUTCOME_KIND: &str = "agent_task";
/// Per-minute cap on either action inside one agent session.
pub const PER_MINUTE_CAP: i32 = 10;
/// Per-day cap on either action inside one agent session.
pub const PER_DAY_CAP: i64 = 100;

const SEND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "lead_id": { "type": "string", "format": "uuid", "description": "The lead." },
    "subject": { "type": "string", "maxLength": 300 },
    "body": { "type": "string", "maxLength": 20000, "description": "The message, in the lead's language." }
  },
  "required": ["lead_id", "subject", "body"],
  "additionalProperties": false
}"#;

const BOOK_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "lead_id": { "type": "string", "format": "uuid", "description": "The lead." },
    "page": { "type": "string", "maxLength": 200, "description": "The booking page's slug." },
    "start": { "type": "string", "format": "date-time", "description": "One of the page's offered start times (UTC)." },
    "notes": { "type": "string", "maxLength": 2000, "description": "What the meeting is about." }
  },
  "required": ["lead_id", "page", "start"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            SEND_MESSAGE,
            "Email a lead, for example to ask qualifying questions, when the lead has \
             consented to sales outreach. A person approves it first.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(SEND_SCHEMA)
        .outcome_kind(OUTCOME_KIND),
        ActionDescriptor::new(
            BOOK_MEETING,
            "Book a meeting for a lead on a booking page at one of its offered times; the \
             lead gets the confirmation. Needs the lead's consent to sales outreach. A \
             person approves it first.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(BOOK_SCHEMA)
        .outcome_kind(OUTCOME_KIND),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(SendMessage), Box::new(BookMeeting)]
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

/// Why a consent decision refuses contact, or `None` when it allows it.
/// Pure.
pub fn refusal(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::Allowed | Decision::Bypassed => None,
        Decision::NoConsent => Some("the lead has not consented to sales outreach"),
        Decision::Withdrawn => Some("the lead withdrew consent to sales outreach"),
        Decision::AccountOptOut => Some("the lead's account opted out of sales outreach"),
    }
}

/// The lead the action is about.
struct Lead {
    name: String,
    email: String,
}

/// Loads the lead the caller may update and checks its outreach consent.
async fn contactable_lead(
    state: &EngineState,
    ctx: &ActionContext,
    lead_id: Uuid,
) -> Result<Lead, AppError> {
    // A message about a record is an update of the record, as on the
    // compose route.
    ctx.security.require("lead", "update")?;
    let entity_id = state
        .entities
        .load()
        .get("lead")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        &ctx.security,
        entity_id,
        "lead",
        lead_id,
        RecordAction::Update,
    )
    .await?;
    let row =
        attome_records::entity_crud::read_record_bulk(state, &ctx.security, "lead", lead_id)
            .await?;
    let data = row.data();
    let text = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let email = text("email")
        .ok_or_else(|| AppError::Validation("the lead has no email address".into()))?;
    let decision = outreach_decision(state, lead_id).await?;
    if let Some(reason) = refusal(decision) {
        tracing::info!(lead = %lead_id, ?decision, "lead outreach refused by consent");
        return Err(AppError::Validation(reason.into()));
    }
    Ok(Lead {
        name: text("name").unwrap_or_else(|| email.clone()),
        email,
    })
}

/// The consent ledger's decision for emailing the lead. A lead has no
/// account until it converts, so only its own rows count.
async fn outreach_decision(state: &EngineState, lead_id: Uuid) -> Result<Decision, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::consent_rules::gate(
        &mut conn,
        ("lead", lead_id),
        None,
        OUTREACH_PURPOSE,
        "email",
        None,
    )
    .await
}

async fn session_caps(
    state: &EngineState,
    ctx: &ActionContext,
    action_id: &str,
) -> Result<(), AppError> {
    if let Some(session) = ctx.agent_session_id {
        crate::write_guard::enforce_write_caps(
            state,
            session,
            action_id,
            PER_DAY_CAP,
            PER_MINUTE_CAP,
        )
        .await?;
    }
    Ok(())
}

/// Records the action in the outcome ledger; a failure is logged.
async fn record_outcome(
    state: &EngineState,
    ctx: &ActionContext,
    action_id: &str,
    lead_id: Uuid,
    expected: Value,
) {
    let proposal = crate::outcome::OutcomeProposal {
        kind: OUTCOME_KIND,
        entity_logicalname: Some("lead"),
        regarding_entity: Some("lead"),
        regarding_id: Some(lead_id),
        model_id: None,
        prompt_version: None,
        rule_ref: Some("ai.lead"),
        proposed_by: Some(ctx.security.user_id),
        organization_ref: None,
        expected_value: Some(expected),
    };
    if let Err(error) = crate::outcome::record_proposed(
        &state.base.db,
        Uuid::now_v7(),
        action_id,
        &proposal,
        ctx.agent_session_id,
    )
    .await
    {
        tracing::warn!(lead = %lead_id, %error, "lead outcome not recorded");
    }
}

/// Emails the lead: the body of `lead.send_message`.
pub async fn send_message(
    state: &EngineState,
    ctx: &ActionContext,
    lead_id: Uuid,
    subject: &str,
    body: &str,
) -> Result<Value, AppError> {
    let lead = contactable_lead(state, ctx, lead_id).await?;
    let (to, recipients) =
        attome_notification::communication::validate_recipients("email", &[lead.email], &[])?;
    session_caps(state, ctx, SEND_MESSAGE).await?;
    let sent = attome_notification::communication::write_communication(
        state,
        &ctx.security,
        ctx.security.user_id,
        "lead",
        lead_id,
        "email",
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
    record_outcome(state, ctx, SEND_MESSAGE, lead_id, json!({ "action": "message" })).await;
    Ok(json!({ "lead_id": lead_id, "communication_id": sent.id }))
}

/// Books a meeting for the lead: the body of `lead.book_meeting`.
pub async fn book_meeting(
    state: &EngineState,
    ctx: &ActionContext,
    lead_id: Uuid,
    page: &str,
    start: chrono::DateTime<chrono::Utc>,
    notes: Option<&str>,
) -> Result<Value, AppError> {
    let lead = contactable_lead(state, ctx, lead_id).await?;
    session_caps(state, ctx, BOOK_MEETING).await?;
    let booked = attome_sales::booking::book(
        state,
        page,
        &attome_sales::booking::BookRequest {
            start,
            name: lead.name,
            email: lead.email,
            phone: None,
            notes: notes.map(str::to_owned),
            captcha_token: None,
        },
    )
    .await?;
    record_outcome(
        state,
        ctx,
        BOOK_MEETING,
        lead_id,
        json!({ "action": "meeting", "booking_id": booked.booking_id }),
    )
    .await;
    Ok(json!({
        "lead_id": lead_id,
        "booking_id": booked.booking_id,
        "start": booked.start,
        "end": booked.end,
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
            let lead_id = uuid_arg(args, "lead_id")?;
            let subject = text_arg(args, "subject")?;
            let body = text_arg(args, "body")?;
            Ok(ActionResult::plain(
                send_message(state, ctx, lead_id, subject, body).await?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({
            "action": SEND_MESSAGE,
            "lead_id": args["lead_id"],
            "subject": args["subject"],
            "body": args["body"],
        }))
    }
}

struct BookMeeting;

impl Action for BookMeeting {
    fn id(&self) -> ActionId {
        ActionId(BOOK_MEETING)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let lead_id = uuid_arg(args, "lead_id")?;
            let page = text_arg(args, "page")?;
            let start = chrono::DateTime::parse_from_rfc3339(text_arg(args, "start")?)
                .map_err(|_| AppError::Validation("start must be an RFC 3339 time".into()))?
                .with_timezone(&chrono::Utc);
            let notes = args["notes"].as_str();
            Ok(ActionResult::plain(
                book_meeting(state, ctx, lead_id, page, start, notes).await?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({
            "action": BOOK_MEETING,
            "lead_id": args["lead_id"],
            "page": args["page"],
            "start": args["start"],
            "notes": args["notes"],
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
    fn agent_lead_qualifier_contact_is_consequential() {
        for id in [SEND_MESSAGE, BOOK_MEETING] {
            let d = descriptor(id);
            assert!(matches!(d.risk, RiskTier::Consequential), "{id}");
            assert_eq!(d.effect, Effect::Write);
            assert_eq!(d.outcome_kind, Some(OUTCOME_KIND));
        }
    }

    #[test]
    fn agent_lead_qualifier_contact_needs_consent() {
        assert_eq!(refusal(Decision::Allowed), None);
        assert!(refusal(Decision::NoConsent).is_some(), "nothing fails closed");
        assert!(refusal(Decision::Withdrawn).is_some());
        assert!(refusal(Decision::AccountOptOut).is_some());
    }

    #[test]
    fn agent_lead_qualifier_schemas_parse() {
        for schema in [SEND_SCHEMA, BOOK_SCHEMA] {
            assert!(serde_json::from_str::<Value>(schema).is_ok());
        }
    }
}
