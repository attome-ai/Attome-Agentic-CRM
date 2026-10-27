//! J5-T2: WhatsApp conversations.
//!
//! The WhatsApp Cloud API posts to `POST /api/v1/whatsapp/{key}`, where
//! `key` is the WhatsApp system's `inbound_key` (an integration system whose
//! config has `"social": "whatsapp"`); `GET` answers Meta's subscription
//! check with the system's `verify_token`. Each POST's `X-Hub-Signature-256`
//! is checked against the system's `app_secret` before anything is read, as
//! for Messenger (J8-T1). The routes are public, rate-limited and licensed
//! with the omnichannel module, and answer an unknown key, an unlicensed
//! deployment and a bad signature alike.
//!
//! **Conversation.** The sender's number (E.164) is matched to a contact,
//! lead or account by any phone field ([`crate::sms_inbound::find_sender`]).
//! A number no record holds becomes a lead or a contact named by the number,
//! per the system's `unknown_sender` (`lead`, the default, `contact`, or
//! `none`, which keeps the message on the system's own record). Each message
//! is an inbound `whatsapp` communication on that record, threaded with the
//! person's earlier WhatsApp messages, through the M52 writer as the
//! system's service principal, so it is on the timeline. With a `queue_id`
//! the conversation is routed by the unified router (J10-T1): the record
//! gets a waiting `chat` queue item in that queue unless one is open there.
//!
//! **Opt-in.** A message that is only a stop word withdraws the person's
//! WhatsApp consent for every consent-based purpose, as for texts (J4-T2).
//! [`template_allowed`] is the gate a marketing template passes before it is
//! sent (E27): utility and authentication templates are transactional.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_integration::connector::adapters::social::{self, meta};
use attome_integration::connector::adapters::whatsapp::{self, Inbound};
use attome_integration::system::IntegrationSystem;
use attome_modules::MODULE_OMNICHANNEL;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

/// What a number no record holds becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSender {
    Lead,
    Contact,
    /// Kept on the system's own record for an agent.
    Keep,
}

/// The system's `unknown_sender`: `lead` (the default), `contact` or `none`.
/// Pure.
pub fn unknown_sender(config: &Value) -> UnknownSender {
    match config.get("unknown_sender").and_then(Value::as_str) {
        Some("contact") => UnknownSender::Contact,
        Some("none") => UnknownSender::Keep,
        _ => UnknownSender::Lead,
    }
}

/// A number as E.164: `+` and 8 to 15 digits, from what WhatsApp sends
/// (international digits) or a formatted number. Pure.
pub fn e164(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.strip_prefix("00").unwrap_or(&digits);
    (8..=15)
        .contains(&digits.len())
        .then(|| format!("+{digits}"))
}

/// The record an unknown number becomes: its entity and fields. Pure.
pub fn new_party(unknown: UnknownSender, phone: &str) -> Option<(&'static str, Value)> {
    match unknown {
        UnknownSender::Lead => Some(("lead", json!({ "name": phone, "phone": phone }))),
        UnknownSender::Contact => Some(("contact", json!({ "full_name": phone, "phone": phone }))),
        UnknownSender::Keep => None,
    }
}

/// A message as it goes on the timeline: its text, else its kind. Pure.
pub fn message_text(message: &Inbound) -> String {
    match message.text.as_deref().map(str::trim) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => format!("[{}]", message.kind),
    }
}

/// Whether a template of `category` may go to a person whose consent is
/// `consented`: marketing needs it, utility and authentication do not. Pure.
pub fn template_allowed(category: &str, consented: bool) -> bool {
    !category.eq_ignore_ascii_case("marketing") || consented
}

/// E27: the gate a WhatsApp template passes for `person`, under the
/// consent `purpose`.
pub async fn template_gate(
    state: &EngineState,
    person: (&str, Uuid),
    category: &str,
    purpose: &str,
) -> Result<bool, AppError> {
    if template_allowed(category, false) {
        return Ok(true);
    }
    let decision =
        attome_compliance::consent::gate(&state.base.db, person, None, purpose, "whatsapp", None)
            .await?;
    Ok(template_allowed(category, decision.allowed()))
}

fn licensed(state: &EngineState) -> Result<(), AppError> {
    state
        .modules
        .load()
        .require(MODULE_OMNICHANNEL)
        .map_err(|_| AppError::NotFound)
}

async fn thread_of(state: &EngineState, entity: &str, id: Uuid) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT thread_id FROM communication \
          WHERE entity_name = $1 AND record_id = $2 AND channel = 'whatsapp' \
            AND is_active IS NOT FALSE \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity)
    .bind(id.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The sender's record, made from the number when none holds it and the
/// system says so.
async fn party_of(
    state: &EngineState,
    ctx: &SecurityContext,
    principal: Uuid,
    system: &IntegrationSystem,
    phone: &str,
) -> Result<(String, Uuid), AppError> {
    if let Some(found) = crate::sms_inbound::find_sender(state, phone).await? {
        return Ok(found);
    }
    let unknown = unknown_sender(&social::config(system));
    if let Some((entity, body)) = new_party(unknown, phone)
        && state.entities.load().get(entity).is_some()
    {
        match attome_records::entity_crud::create_record_for(state, ctx, principal, entity, body)
            .await
        {
            Ok((id, _)) => return Ok((entity.to_owned(), id)),
            Err(error) => {
                tracing::warn!(system = %system.id, entity, %error, "whatsapp: the sender's record was not created");
            }
        }
    }
    Ok(("integration_system".to_owned(), system.id))
}

/// J10-T1: a waiting chat queue item for the record in the system's queue,
/// unless one is open there.
async fn route(
    state: &EngineState,
    ctx: &SecurityContext,
    principal: Uuid,
    system: &IntegrationSystem,
    party: (&str, Uuid),
) -> Result<(), AppError> {
    let Some(queue) = social::config(system)
        .get("queue_id")
        .and_then(Value::as_str)
        .and_then(|q| Uuid::parse_str(q).ok())
    else {
        return Ok(());
    };
    let provisioned: bool = sqlx::query_scalar("SELECT to_regclass('queue_item') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !provisioned {
        return Ok(());
    }
    let open: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM queue_item \
                        WHERE queue_ref = $1 AND record_entity = $2 AND record_id = $3 \
                          AND status <> 'done' AND is_active IS NOT FALSE)",
    )
    .bind(queue)
    .bind(party.0)
    .bind(party.1.to_string())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if open {
        return Ok(());
    }
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        principal,
        "queue_item",
        json!({
            "queue_ref": queue,
            "record_entity": party.0,
            "record_id": party.1.to_string(),
            "priority": "medium",
            "status": "waiting",
            "channel": "chat",
            "entered_at": Utc::now().to_rfc3339(),
        }),
    )
    .await?;
    Ok(())
}

/// Withdraws the person's WhatsApp consent for every consent-based purpose.
async fn opt_out(
    state: &EngineState,
    person: (&str, Uuid),
    message: &Inbound,
) -> Result<usize, AppError> {
    let purposes: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM audit_consent_purpose \
          WHERE (is_active IS NULL OR is_active = true) AND lawful_basis = 'consent'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for purpose in &purposes {
        attome_compliance::consent::record(
            &mut tx,
            &attome_compliance::consent::ConsentChange {
                subject_entity: person.0.to_owned(),
                subject_id: person.1,
                purpose_key: purpose.clone(),
                channel: "whatsapp".into(),
                grant: false,
                source: "whatsapp_stop".into(),
                proof: json!({
                    "from": message.from,
                    "body": message.text,
                    "provider_message_id": message.id,
                }),
                occurred_at: Utc::now(),
                recorded_by: None,
            },
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(purposes.len())
}

/// One inbound message: on the sender's record, routed, and a STOP honoured.
async fn record_inbound(
    state: &EngineState,
    system: &IntegrationSystem,
    message: &Inbound,
) -> Result<(), AppError> {
    let principal = attome_integration::system::service_principal_id(system)?;
    let ctx = state.base.security.resolve(principal).await?;
    ctx.require("communication", "create")?;
    let phone = e164(&message.from).unwrap_or_else(|| message.from.clone());
    let (entity, record) = party_of(state, &ctx, principal, system, &phone).await?;
    let thread = thread_of(state, &entity, record).await?;
    let text = message_text(message);
    attome_notification::communication::write_communication(
        state,
        &ctx,
        principal,
        &entity,
        record,
        "whatsapp",
        "inbound",
        std::slice::from_ref(&phone),
        &[],
        "WhatsApp",
        &text,
        None,
        thread,
        None,
        None,
    )
    .await?;
    if entity != "integration_system" {
        if let Err(error) = route(state, &ctx, principal, system, (&entity, record)).await {
            tracing::warn!(system = %system.id, %error, "whatsapp: the conversation was not routed");
        }
        if attome_integration::sms::is_stop(&text) {
            let withdrawn = opt_out(state, (&entity, record), message).await?;
            tracing::info!(%record, entity = %entity, withdrawn, "whatsapp: opted out");
        }
    }
    Ok(())
}

/// WhatsApp's subscription check
///
/// Meta's subscription check for a WhatsApp system.
#[utoipa::path(
    get,
    path = "/api/v1/whatsapp/{key}",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The WhatsApp system's inbound key")),
    responses(
        (status = 200, description = "The challenge, echoed", body = String),
        (status = 404, description = "Not licensed, no such system, or the wrong verify token", body = ErrorResponse),
    ),
)]
async fn whatsapp_verify(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<String, AppError> {
    licensed(&state)?;
    let system = social::system_by_key(&state, "whatsapp", &key)
        .await?
        .ok_or(AppError::NotFound)?;
    let token = social::config(&system)
        .get("verify_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    meta::verify_challenge(&params, &token).ok_or(AppError::NotFound)
}

/// WhatsApp's webhook events
///
/// The WhatsApp Cloud API's signed events: each message becomes part of the
/// sender's conversation.
#[utoipa::path(
    post,
    path = "/api/v1/whatsapp/{key}",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The WhatsApp system's inbound key")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Received"),
        (status = 404, description = "Not licensed, no such system, or a bad signature", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn whatsapp_events(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    licensed(&state)?;
    let system = social::system_by_key(&state, "whatsapp", &key)
        .await?
        .ok_or(AppError::NotFound)?;
    let app_secret = social::sealed_secret(&state, &system, "app_secret").await?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());
    if !app_secret.with_value(|secret| meta::signature_ok(secret, &body, signature)) {
        return Err(AppError::NotFound);
    }
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::Validation("not a WhatsApp webhook".into()))?;
    let (messages, _statuses) = whatsapp::parse_webhook(&payload);
    for message in &messages {
        // One failure does not lose the rest; Meta retries the whole batch
        // only on a non-2xx, which would duplicate the ones written.
        if let Err(error) = record_inbound(&state, &system, message).await {
            tracing::warn!(system = %system.id, %error, "whatsapp: message not recorded");
        }
    }
    Ok(StatusCode::OK)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/whatsapp/{key}",
        get(whatsapp_verify).post(whatsapp_events),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(whatsapp_verify, whatsapp_events))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatsapp_conversation_numbers_and_unknown_senders() {
        assert_eq!(e164("966501234567").as_deref(), Some("+966501234567"));
        assert_eq!(e164("+966 50 123 4567").as_deref(), Some("+966501234567"));
        assert_eq!(e164("00966501234567").as_deref(), Some("+966501234567"));
        assert_eq!(e164("12345"), None);
        assert_eq!(unknown_sender(&json!({})), UnknownSender::Lead);
        assert_eq!(
            unknown_sender(&json!({ "unknown_sender": "contact" })),
            UnknownSender::Contact
        );
        assert_eq!(
            unknown_sender(&json!({ "unknown_sender": "none" })),
            UnknownSender::Keep
        );
        assert_eq!(
            new_party(UnknownSender::Contact, "+966501234567"),
            Some((
                "contact",
                json!({ "full_name": "+966501234567", "phone": "+966501234567" })
            ))
        );
        assert_eq!(new_party(UnknownSender::Keep, "+1"), None);
    }

    #[test]
    fn whatsapp_conversation_text_and_template_consent() {
        let mut message = Inbound {
            id: "wamid.1".into(),
            from: "966501234567".into(),
            at: None,
            kind: "image".into(),
            text: None,
            reply_id: None,
            media_id: Some("m1".into()),
        };
        assert_eq!(message_text(&message), "[image]");
        message.text = Some(" مرحبا ".into());
        assert_eq!(message_text(&message), "مرحبا");
        assert!(template_allowed("UTILITY", false));
        assert!(template_allowed("authentication", false));
        assert!(!template_allowed("MARKETING", false));
        assert!(template_allowed("marketing", true));
    }
}
