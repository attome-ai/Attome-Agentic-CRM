//! Z8-T5: `POST /api/v1/email/webhooks/{provider}` — bounces, complaints
//! and unsubscribes reported by the sending provider.
//!
//! Public (bypass-listed by its exact paths): the provider's own signature
//! is the credential, and an unsigned or wrongly signed call is 401 with no
//! detail.
//!
//! - `ses`: Amazon SNS posts SES notifications from a topic named in
//!   `email.feedback.ses_topic_arns`. The signing certificate must be an
//!   `https://sns.<region>.amazonaws.com/….pem` address and is cached for an
//!   hour per node (a copy of a public certificate, rebuilt on a miss). A
//!   `SubscriptionConfirmation` is confirmed by fetching its `SubscribeURL`
//!   (an SNS address only).
//! - `sendgrid`: the signed event webhook, checked against
//!   `email.feedback.sendgrid_public_key`, its timestamp within ten minutes.
//!
//! Events become suppressions through `attome_email::feedback::apply`; a
//! provider not configured answers 404.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_core::EngineState;
use attome_email::feedback;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde_json::Value;

/// How long a fetched SNS certificate is reused.
const CERT_TTL: Duration = Duration::from_secs(3600);
/// How far a SendGrid timestamp may be from now.
const SENDGRID_WINDOW_SECS: i64 = 600;
/// How old an SNS message may be.
const SNS_WINDOW_SECS: i64 = 3600;
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

static CERTS: LazyLock<Mutex<HashMap<String, (Instant, String)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn client() -> &'static attome_outbound::http::Outbound {
    static CLIENT: std::sync::OnceLock<attome_outbound::http::Outbound> =
        std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(
            attome_outbound::http::Purpose::public("email-feedback").no_redirects(),
            |b| b.timeout(CALL_TIMEOUT),
        )
    })
}

/// Whether `url` is an SNS endpoint (the subscription confirmation link).
/// Pure.
fn sns_endpoint_ok(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest
        .split(['/', '?'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    host.strip_prefix("sns.")
        .and_then(|h| {
            h.strip_suffix(".amazonaws.com")
                .or_else(|| h.strip_suffix(".amazonaws.com.cn"))
        })
        .is_some_and(|region| {
            !region.is_empty()
                && region
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

async fn certificate(url: &str) -> Result<String, AppError> {
    if let Some((at, pem)) = CERTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(url)
        && at.elapsed() < CERT_TTL
    {
        return Ok(pem.clone());
    }
    let res = client()
        .get(url)
        .send()
        .await
        .map_err(|_| AppError::Unauthorized)?;
    if !res.status().is_success() {
        return Err(AppError::Unauthorized);
    }
    let pem = res.text().await.map_err(|_| AppError::Unauthorized)?;
    CERTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(url.to_owned(), (Instant::now(), pem.clone()));
    Ok(pem)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

async fn ses(state: &EngineState, body: &[u8]) -> Result<Vec<feedback::Feedback>, AppError> {
    let topics = &state.base.config.email.feedback.ses_topic_arns;
    if topics.is_empty() {
        return Err(AppError::NotFound);
    }
    let msg: Value = serde_json::from_slice(body).map_err(|_| AppError::Unauthorized)?;
    let topic = msg["TopicArn"].as_str().unwrap_or_default();
    if !topics.iter().any(|t| t == topic) {
        return Err(AppError::Unauthorized);
    }
    let fresh = msg["Timestamp"]
        .as_str()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .is_some_and(|t| (chrono::Utc::now().timestamp() - t.timestamp()).abs() <= SNS_WINDOW_SECS);
    let cert_url = msg["SigningCertURL"].as_str().unwrap_or_default();
    if !fresh || !feedback::sns_cert_url_ok(cert_url) {
        return Err(AppError::Unauthorized);
    }
    let pem = certificate(cert_url).await?;
    if !feedback::verify_sns(&msg, &pem) {
        return Err(AppError::Unauthorized);
    }
    match msg["Type"].as_str() {
        Some("SubscriptionConfirmation") => {
            let url = msg["SubscribeURL"].as_str().unwrap_or_default();
            if sns_endpoint_ok(url) {
                let confirmed = client().get(url).send().await;
                if confirmed.is_err() {
                    tracing::warn!(%topic, "email feedback: the SNS subscription was not confirmed");
                }
            }
            Ok(Vec::new())
        }
        Some("Notification") => Ok(feedback::parse_ses(
            msg["Message"].as_str().unwrap_or_default(),
        )),
        _ => Ok(Vec::new()),
    }
}

fn sendgrid(
    state: &EngineState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Vec<feedback::Feedback>, AppError> {
    let Some(key) = state
        .base
        .config
        .email
        .feedback
        .sendgrid_public_key
        .as_deref()
    else {
        return Err(AppError::NotFound);
    };
    let signature = header(headers, "x-twilio-email-event-webhook-signature").unwrap_or_default();
    let timestamp = header(headers, "x-twilio-email-event-webhook-timestamp").unwrap_or_default();
    let fresh = timestamp
        .parse::<i64>()
        .is_ok_and(|t| (chrono::Utc::now().timestamp() - t).abs() <= SENDGRID_WINDOW_SECS);
    if !fresh || !feedback::verify_sendgrid(key, signature, timestamp, body) {
        return Err(AppError::Unauthorized);
    }
    Ok(feedback::parse_sendgrid(body))
}

/// Receive provider email events
///
/// Z8-T5: bounces, complaints and unsubscribes from Amazon SES (through
/// SNS) or SendGrid's signed event webhook. Public: the provider's
/// signature is the credential. A hard bounce or complaint suppresses every
/// stream, an unsubscribe bulk mail only, and five soft bounces in seven
/// days suppress the address.
#[utoipa::path(
    post,
    path = "/api/v1/email/webhooks/{provider}",
    tag = "email",
    operation_id = "receive_email_feedback",
    params(("provider" = String, Path, description = "`ses` or `sendgrid`")),
    request_body(content = Object, description = "The provider's event payload, as it sends it"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Accepted"),
        (status = 401, description = "Unsigned, wrongly signed, stale or from a topic not configured", body = ErrorResponse),
        (status = 404, description = "No such provider, or it is not configured", body = ErrorResponse),
    ),
)]
async fn receive(
    State(state): State<EngineState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let events = match provider.as_str() {
        "ses" => ses(&state, &body).await?,
        "sendgrid" => sendgrid(&state, &headers, &body)?,
        _ => return Err(AppError::NotFound),
    };
    if events.is_empty() {
        return Ok(StatusCode::OK);
    }
    let suppressed = feedback::apply(&state.base.db, &events)
        .await
        .map_err(AppError::internal)?;
    if suppressed > 0 {
        attome_audit::write_business_event(
            &state,
            "email_suppression",
            uuid::Uuid::nil(),
            attome_audit::AuditOperation::Create,
            "email.feedback_suppressed",
            uuid::Uuid::nil(),
            None,
            None,
            format!(
                "{provider}: {suppressed} of {} reported addresses suppressed",
                events.len()
            ),
        )
        .await;
    }
    Ok(StatusCode::OK)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/email/webhooks/{provider}", post(receive))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(receive))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_links_must_be_sns() {
        assert!(sns_endpoint_ok(
            "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=x&Token=y"
        ));
        assert!(!sns_endpoint_ok(
            "https://sns.us-east-1.amazonaws.com.evil.io/?x"
        ));
        assert!(!sns_endpoint_ok("http://sns.us-east-1.amazonaws.com/?x"));
        assert!(!sns_endpoint_ok(
            "https://evil.io/?sns.us-east-1.amazonaws.com"
        ));
    }
}
