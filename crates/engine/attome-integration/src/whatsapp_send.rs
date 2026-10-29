//! N18-T1: free-form WhatsApp text through a WhatsApp system (an integration
//! system whose config has `"social": "whatsapp"`), the HTTP half of J5-T1's
//! codecs, as `sms.rs` is for texts.
//!
//! The system's config names `phone_number_id` and, optionally,
//! `graph_version` (default [`whatsapp::DEFAULT_GRAPH_VERSION`]); its
//! envelope-encrypted credential holds `access_token`. A free-form message
//! goes only within 24 hours of the person's last message
//! ([`whatsapp::check_window`]): the caller passes when that was.

use std::sync::OnceLock;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::connector::adapters::sms::SendAnswer;
use crate::connector::adapters::social;
use crate::connector::adapters::whatsapp::{self, Outbound, Refusal};
use crate::system::IntegrationSystem;

const SEND_TIMEOUT: Duration = Duration::from_secs(15);

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("whatsapp"), |b| {
            b.timeout(SEND_TIMEOUT)
        })
    })
}

/// The messages endpoint of `system`'s number. Pure.
pub fn endpoint(config: &Value) -> Result<String, AppError> {
    let number = config
        .get("phone_number_id")
        .and_then(Value::as_str)
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| {
            AppError::Validation("whatsapp: the system names no phone_number_id".into())
        })?;
    let version = config
        .get("graph_version")
        .and_then(Value::as_str)
        .unwrap_or(whatsapp::DEFAULT_GRAPH_VERSION);
    Ok(whatsapp::send_url(version, number))
}

/// Sends `body` to `to` (E.164) as a text message; the provider message id.
/// `last_inbound` is when the person last wrote: outside the 24-hour window
/// the message is refused before anything is sent.
pub async fn send_text(
    state: &EngineState,
    system: &IntegrationSystem,
    to: &str,
    body: &str,
    last_inbound: Option<DateTime<Utc>>,
) -> Result<String, AppError> {
    let message = Outbound::Text {
        body: body.trim().chars().take(4096).collect(),
        preview_url: false,
    };
    let refused = |r: Refusal| match r {
        Refusal::OutsideWindow => AppError::Validation(
            "whatsapp: more than 24 hours since the person last wrote; only a template may go"
                .into(),
        ),
        Refusal::Invalid(why) => AppError::Validation(format!("whatsapp: {why}")),
    };
    whatsapp::check_window(&message, last_inbound, Utc::now()).map_err(refused)?;
    let payload = whatsapp::message_body(to, &message).map_err(refused)?;
    let url = endpoint(&social::config(system))?;
    let token = social::sealed_secret(state, system, "access_token").await?;
    let request = token.bearer(client().post(url).json(&payload));
    let response = request.send().await.map_err(AppError::internal)?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    match whatsapp::parse_send(status, &text) {
        SendAnswer::Accepted {
            provider_message_id,
        } => Ok(provider_message_id),
        SendAnswer::Refused { code } => Err(AppError::internal(format!(
            "whatsapp: the provider refused the message ({code})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_endpoint_names_the_number_and_version() {
        assert_eq!(
            endpoint(&json!({"phone_number_id": "123"})).unwrap(),
            whatsapp::send_url(whatsapp::DEFAULT_GRAPH_VERSION, "123")
        );
        assert_eq!(
            endpoint(&json!({"phone_number_id": "9", "graph_version": "v22.0"})).unwrap(),
            "https://graph.facebook.com/v22.0/9/messages"
        );
        assert!(endpoint(&json!({})).is_err());
    }
}
