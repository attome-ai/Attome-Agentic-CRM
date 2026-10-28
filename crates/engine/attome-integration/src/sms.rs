//! SMS sending and delivery receipts (roadmap J4-T1).
//!
//! **Providers** are `integration_system` rows whose `config` names
//! `"sms": "twilio" | "unifonic"` and `"senders"`, a sender id per
//! recipient country (`{"SA": "Attome", "*": "+15550001111"}`); Twilio also
//! needs `account_sid`. The secret (Twilio's auth token, Unifonic's AppSid)
//! is that system's envelope-encrypted credential.
//!
//! **Ledger.** Every message is a `sms_delivery` row with its segment count
//! and encoding (GSM-7 or UCS-2), written before the provider is called and
//! updated with the provider's message id and, later, its receipts.
//!
//! **Receipts.** Each message's callback URL carries a token signed for its
//! ledger row (`POST /api/v1/sms/receipts/{token}`), so a receipt can only
//! move the message it was issued for, and a state never goes back
//! (delivered stays delivered when a late "sent" arrives).

use std::sync::OnceLock;
use std::time::Duration;

use attome_audit::security::{ExemptReason, x_audit_exempt};
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::connector::adapters::sms::{DeliveryStatus, SendAnswer, e164, segments, sender_for};
use crate::connector::adapters::{sms_twilio, sms_unifonic};

/// The signing domain of receipt tokens.
pub const RECEIPT_DOMAIN: &str = "attome-sms-receipt";
/// How long a receipt token is valid.
const RECEIPT_DAYS: i64 = 14;
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
/// Longest message sent (ten UCS-2 parts).
pub const MAX_BODY_CHARS: usize = 670;

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("sms"), |b| {
            b.timeout(SEND_TIMEOUT)
        })
    })
}

struct Provider {
    kind: String,
    config: Value,
    secret: String,
}

async fn provider(state: &EngineState) -> Result<Option<Provider>, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'sms' END \
                IN ('twilio', 'unifonic') \
          ORDER BY created_at, id LIMIT 1",
    )
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((config, credential_ref)) = row else {
        return Ok(None);
    };
    let config: Value = config
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(Value::Null);
    let Some(secret) = crate::credential::resolve_value(
        &state.base.db,
        &crate::credential::ring(state),
        credential_ref.as_deref(),
    )
    .await?
    else {
        tracing::warn!("sms: provider configured without a credential");
        return Ok(None);
    };
    let kind = config
        .get("sms")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(Some(Provider {
        kind,
        config,
        secret,
    }))
}

fn signing_secret(state: &EngineState) -> Option<String> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
}

/// The callback URL a message's receipts go to.
fn receipt_url(state: &EngineState, delivery_id: Uuid) -> Option<String> {
    let secret = signing_secret(state)?;
    let expires = (Utc::now() + chrono::Duration::days(RECEIPT_DAYS)).timestamp();
    let token =
        attome_auth::signed_link::sign(&secret, RECEIPT_DOMAIN, &delivery_id.to_string(), expires)?;
    Some(format!(
        "{}/api/v1/sms/receipts/{token}",
        state.base.config.frontend_url().trim_end_matches('/')
    ))
}

/// What a send did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// The provider took it; the ledger row.
    Accepted(Uuid),
    /// No provider is configured, or the number is not international.
    Skipped,
}

/// Sends `body` to `to` (E.164) through the configured provider, recording
/// it in the ledger. A provider refusal is an error (the ledger row says
/// `failed` with its code), so a notification dispatch retries it.
pub async fn send(
    state: &EngineState,
    to: &str,
    body: &str,
    recipient_user_ref: Option<Uuid>,
) -> Result<Sent, AppError> {
    let Some(to) = e164(to) else {
        return Ok(Sent::Skipped);
    };
    let body: String = body.trim().chars().take(MAX_BODY_CHARS).collect();
    if body.is_empty() {
        return Ok(Sent::Skipped);
    }
    let Some(p) = provider(state).await? else {
        return Ok(Sent::Skipped);
    };
    let sender = sender_for(p.config.get("senders").unwrap_or(&Value::Null), &to)
        .ok_or_else(|| AppError::Validation("sms: no sender id for this country".into()))?;
    let (encoding, parts) = segments(&body);
    let delivery_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sms_delivery (provider, recipient, recipient_user_ref, sender, segments, encoding) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&p.kind)
    .bind(&to)
    .bind(recipient_user_ref)
    .bind(&sender)
    .bind(i32::try_from(parts).unwrap_or(i32::MAX))
    .bind(encoding.as_str())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let callback = receipt_url(state, delivery_id).unwrap_or_default();
    let request = match p.kind.as_str() {
        "twilio" => {
            let sid = p
                .config
                .get("account_sid")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("sms: twilio needs account_sid".into()))?;
            client()
                .post(sms_twilio::send_url(sid))
                .basic_auth(sid, Some(&p.secret))
                .form(&sms_twilio::send_form(&to, &sender, &body, &callback))
        }
        _ => {
            let digits = sms_unifonic::recipient(&to);
            client()
                .post(sms_unifonic::SEND_URL)
                .form(&sms_unifonic::send_form(&p.secret, &sender, &body, &digits))
        }
    };
    let (status, text) = match request.send().await {
        Ok(res) => {
            let status = res.status().as_u16();
            (status, res.text().await.unwrap_or_default())
        }
        Err(e) => {
            record(
                state,
                delivery_id,
                None,
                DeliveryStatus::Failed,
                Some("network"),
            )
            .await?;
            return Err(AppError::internal(e));
        }
    };
    let answer = if p.kind == "twilio" {
        sms_twilio::parse_send(status, &text)
    } else {
        sms_unifonic::parse_send(status, &text)
    };
    match answer {
        SendAnswer::Accepted {
            provider_message_id,
        } => {
            record(
                state,
                delivery_id,
                Some(&provider_message_id),
                DeliveryStatus::Sent,
                None,
            )
            .await?;
            Ok(Sent::Accepted(delivery_id))
        }
        SendAnswer::Refused { code } => {
            record(
                state,
                delivery_id,
                None,
                DeliveryStatus::Failed,
                Some(&code),
            )
            .await?;
            Err(AppError::internal(format!(
                "sms: the provider refused the message ({code})"
            )))
        }
    }
}

/// Moves a ledger row forward (never back).
async fn record(
    state: &EngineState,
    delivery_id: Uuid,
    provider_message_id: Option<&str>,
    status: DeliveryStatus,
    error_code: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE sms_delivery \
            SET provider_message_id = coalesce($2, provider_message_id), \
                status = CASE WHEN (CASE status WHEN 'queued' THEN 0 WHEN 'sent' THEN 1 ELSE 2 END) \
                                   <= $4 THEN $3 ELSE status END, \
                error_code = coalesce($5, error_code), \
                updated_at = now() \
          WHERE id = $1",
    )
    .bind(delivery_id)
    .bind(provider_message_id)
    .bind(status.as_str())
    .bind(i32::from(status.rank()))
    .bind(error_code)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Sends to a user's phone (`user_account.phone`); a user without one, or
/// without a provider configured, is skipped.
pub async fn send_to_user(
    state: &EngineState,
    user: Option<Uuid>,
    body: &str,
) -> Result<(), AppError> {
    let Some(user) = user else {
        return Ok(());
    };
    let phone: Option<Option<String>> =
        sqlx::query_scalar("SELECT phone FROM user_account WHERE id = $1 AND is_active")
            .bind(user)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match phone.flatten() {
        Some(phone) => send(state, &phone, body, Some(user)).await.map(|_| ()),
        None => Ok(()),
    }
}

// ── J4-T2: inbound messages ─────────────────────────────────────────────────

/// A message a person sent to the deployment's number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSms {
    /// The sender, E.164.
    pub from: String,
    pub body: String,
    pub provider_message_id: Option<String>,
}

/// Reads an inbound message: a Twilio form (`From`, `Body`, `MessageSid`)
/// or a Unifonic JSON body (`from`/`sender`, `body`/`message`/`text`,
/// `messageId`). Pure.
pub fn parse_inbound(body: &[u8]) -> Option<InboundSms> {
    let (from, text, id) = if let Ok(json) = serde_json::from_slice::<Value>(body) {
        let field = |names: &[&str]| {
            names
                .iter()
                .find_map(|n| json.get(*n))
                .map(|v| v.to_string().trim_matches('"').to_owned())
        };
        (
            field(&["from", "sender", "From"]),
            field(&["body", "message", "text", "Body"]),
            field(&["messageId", "MessageID", "message_id"]),
        )
    } else {
        let form: Vec<(String, String)> = url::form_urlencoded::parse(body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        (get("From"), get("Body"), get("MessageSid"))
    };
    let from = e164(&from?)?;
    let body = text?.trim().to_owned();
    (!body.is_empty()).then_some(InboundSms {
        from,
        body,
        provider_message_id: id.filter(|i| !i.is_empty() && i != "null"),
    })
}

/// Whether a message asks to stop all texts: the carriers' keywords, and
/// their Arabic equivalents, as the whole message. Pure.
pub fn is_stop(body: &str) -> bool {
    let word = body
        .trim()
        .trim_matches(|c: char| c.is_ascii_punctuation())
        .to_uppercase();
    matches!(
        word.as_str(),
        "STOP"
            | "STOPALL"
            | "UNSUBSCRIBE"
            | "CANCEL"
            | "END"
            | "QUIT"
            | "OPTOUT"
            | "الغاء"
            | "إلغاء"
            | "ايقاف"
            | "إيقاف"
            | "توقف"
    )
}

/// The SMS system an inbound webhook belongs to, when its key is that
/// system's `inbound_key`; the comparison is of SHA-256 digests, so its time
/// says nothing about the key.
pub async fn inbound_system(
    state: &EngineState,
    key: &str,
) -> Result<Option<crate::system::IntegrationSystem>, AppError> {
    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, config FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'sms' END \
                IN ('twilio', 'unifonic')",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    use sha2::{Digest, Sha256};
    let presented = Sha256::digest(key.as_bytes());
    for (id, config) in rows {
        let expected = config
            .and_then(|c| serde_json::from_str::<Value>(&c).ok())
            .and_then(|c| {
                c.get("inbound_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .filter(|k| k.len() >= 16);
        if let Some(expected) = expected
            && Sha256::digest(expected.as_bytes()) == presented
        {
            return crate::system::load(&state.base.db, id).await;
        }
    }
    Ok(None)
}

/// Reads a receipt body: a Twilio form or a Unifonic JSON webhook.
pub fn parse_receipt_body(body: &[u8]) -> Option<(String, DeliveryStatus, Option<String>)> {
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        return sms_unifonic::parse_receipt(&json);
    }
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    sms_twilio::parse_receipt(&form)
}

/// Receive an SMS delivery receipt
///
/// A provider's delivery receipt for one message; the token names the message, and a bad or expired
/// one, or a receipt for another provider message, is 404. No session.
#[utoipa::path(
    post,
    path = "/api/v1/sms/receipts/{token}",
    tag = "integration",
    params(("token" = String, Path, description = "The receipt token sent with the message")),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::Telemetry,
        None,
        "a provider's delivery receipt moving one SMS ledger row forward; no business or security effect"
    )))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 404, description = "No such message", body = ErrorResponse),
        (status = 422, description = "Not a receipt this route reads", body = ErrorResponse),
    ),
)]
async fn receipt(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let secret = signing_secret(&state).ok_or(AppError::NotFound)?;
    let delivery_id =
        attome_auth::signed_link::verify(&secret, RECEIPT_DOMAIN, &token, Utc::now().timestamp())
            .and_then(|claim| Uuid::parse_str(&claim).ok())
            .ok_or(AppError::NotFound)?;
    let (message_id, status, error) = parse_receipt_body(&body)
        .ok_or_else(|| AppError::Validation("not a delivery receipt".into()))?;
    let known: Option<Option<String>> =
        sqlx::query_scalar("SELECT provider_message_id FROM sms_delivery WHERE id = $1")
            .bind(delivery_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match known {
        Some(Some(id)) if id != message_id => return Err(AppError::NotFound),
        None => return Err(AppError::NotFound),
        _ => {}
    }
    record(
        &state,
        delivery_id,
        Some(&message_id),
        status,
        error.as_deref(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The receipt route: public (the token is the authority), mounted with the
/// other public routes.
pub fn public_routes() -> Router<EngineState> {
    Router::new().route("/api/v1/sms/receipts/{token}", post(receipt))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(receipt))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_receipts_are_read_from_either_provider() {
        let twilio = b"MessageSid=SM9&MessageStatus=delivered&To=%2B966551234567";
        assert_eq!(
            parse_receipt_body(twilio),
            Some(("SM9".into(), DeliveryStatus::Delivered, None))
        );
        let unifonic = br#"{"messageId": 12, "status": "Delivered"}"#;
        assert_eq!(
            parse_receipt_body(unifonic),
            Some(("12".into(), DeliveryStatus::Delivered, None))
        );
        assert_eq!(parse_receipt_body(b"nothing=here"), None);
    }

    #[test]
    fn sms_inbound_is_read_and_stop_is_recognised() {
        let twilio = b"From=%2B966551234567&To=%2B15550001111&Body=STOP&MessageSid=SM5";
        assert_eq!(
            parse_inbound(twilio),
            Some(InboundSms {
                from: "+966551234567".into(),
                body: "STOP".into(),
                provider_message_id: Some("SM5".into()),
            })
        );
        let unifonic = r#"{"from": "+966551234567", "message": "متى يصل الطلب؟", "messageId": 9}"#;
        assert_eq!(
            parse_inbound(unifonic.as_bytes()).map(|m| m.body),
            Some("متى يصل الطلب؟".into())
        );
        assert_eq!(
            parse_inbound(b"From=0551234567&Body=hi"),
            None,
            "a local number"
        );
        assert_eq!(parse_inbound(b"From=%2B966551234567&Body=%20"), None);
        assert!(is_stop(" stop "));
        assert!(is_stop("Stop!"));
        assert!(is_stop("الغاء"));
        assert!(is_stop("إيقاف"));
        assert!(!is_stop("please stop calling me at work"));
    }
}
