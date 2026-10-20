//! J6-T1: an Asterisk PBX (or another PBX that speaks the same two things).
//!
//! **Placing** a call is ARI's originate: `POST {base_url}/channels` with the
//! agent's endpoint (`endpoint` with `{agent}` replaced), the number as the
//! extension to dial in `context`, and the system's number as caller id.
//!
//! **Events** come from the PBX as JSON posted to
//! `/api/v1/voice/pbx/{inbound_key}/events`:
//! `{"call_id", "event": "ringing" | "answered" | "hangup", "direction":
//! "inbound" | "outbound", "from", "to", "duration", "recording_url",
//! "disposition"}`, sent from the dialplan with `CURL()` (or a 3CX call
//! webhook mapped to these names). A hang-up whose `disposition` is not
//! `ANSWERED` is a missed call.

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;

use super::{CallEvent, CallState, config, credential, setting};
use crate::system::IntegrationSystem;

/// Reads a PBX call event. Pure.
pub fn parse_event(body: &[u8]) -> Option<CallEvent> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let text = |key: &str| {
        v.get(key)
            .and_then(|x| match x {
                Value::String(s) => Some(s.trim().to_owned()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
    };
    let call_id = text("call_id")?;
    let disposition = text("disposition").map(|d| d.to_ascii_uppercase());
    let (state, missed) = match text("event")?.to_ascii_lowercase().as_str() {
        "ringing" | "ring" | "newchannel" => (CallState::Ringing, false),
        "answered" | "answer" | "up" => (CallState::Answered, false),
        "hangup" | "ended" | "end" => (
            CallState::Ended,
            disposition.as_deref().is_some_and(|d| d != "ANSWERED"),
        ),
        _ => return None,
    };
    let direction = match text("direction").as_deref() {
        Some("inbound" | "in") => Some("inbound"),
        Some("outbound" | "out") => Some("outbound"),
        _ => None,
    };
    Some(CallEvent {
        call_id,
        state,
        direction,
        from: text("from"),
        to: text("to"),
        duration_seconds: text("duration").and_then(|d| d.parse().ok()),
        recording_url: text("recording_url")
            .filter(|u| u.starts_with("https://") || u.starts_with("http://")),
        missed,
    })
}

/// The originate request's query. Pure; `None` for an agent that is not
/// a plain extension or number.
pub fn originate_query(
    endpoint: &str,
    agent: &str,
    number: &str,
    context: &str,
    caller_id: &str,
) -> Option<Vec<(&'static str, String)>> {
    let plain = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+');
    if !plain(agent) || !plain(number) {
        return None;
    }
    Some(vec![
        ("endpoint", endpoint.replace("{agent}", agent)),
        ("extension", number.to_owned()),
        ("context", context.to_owned()),
        ("priority", "1".to_owned()),
        ("callerId", caller_id.to_owned()),
        ("timeout", "30".to_owned()),
    ])
}

/// The channel id ARI gives the call. Pure.
pub fn channel_id(status: u16, body: &str) -> Option<String> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    v.get("id")?.as_str().map(str::to_owned)
}

pub(super) async fn place_call(
    state: &EngineState,
    system: &IntegrationSystem,
    agent: &str,
    to: &str,
    caller_id: Option<&str>,
) -> Result<String, AppError> {
    let cfg = config(system);
    let base = setting(&cfg, "base_url")
        .filter(|b| b.starts_with("https://") || b.starts_with("http://"))
        .ok_or_else(|| AppError::Validation(format!("{}: config has no base_url", system.name)))?;
    let query = originate_query(
        setting(&cfg, "endpoint").unwrap_or("PJSIP/{agent}"),
        agent,
        to,
        setting(&cfg, "context").unwrap_or("from-internal"),
        caller_id.unwrap_or(setting(&cfg, "from_number").unwrap_or_default()),
    )
    .ok_or_else(|| AppError::Validation("agent and number: digits only".into()))?;
    let secret = credential(state, system).await?;
    let (user, password) = secret.split_once(':').unwrap_or((secret.as_str(), ""));
    // Q21-T1: the PBX is the customer's own, so this connector's configured
    // `base_url` host may be private; nothing else private is reachable.
    let purpose = attome_outbound::http::Purpose::public("asterisk").with_private_urls([base]);
    let client = attome_outbound::http::client(purpose, |b| b.timeout(super::TIMEOUT))
        .map_err(AppError::internal)?;
    let url =
        url::Url::parse_with_params(&format!("{}/channels", base.trim_end_matches('/')), &query)
            .map_err(AppError::internal)?;
    let res = client
        .post(url)
        .basic_auth(user, Some(password))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    channel_id(status, &body)
        .ok_or_else(|| AppError::Validation(format!("the PBX refused the call ({status})")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_adapters_asterisk_reads_pbx_events() {
        let ring = parse_event(br#"{"call_id":"1697.42","event":"ringing","direction":"in","from":"+966551234567","to":"200"}"#).unwrap();
        assert_eq!(
            (ring.state, ring.direction),
            (CallState::Ringing, Some("inbound"))
        );
        let up = parse_event(br#"{"call_id":"1697.42","event":"answered"}"#).unwrap();
        assert_eq!(up.state, CallState::Answered);
        let done = parse_event(
            br#"{"call_id":"1697.42","event":"hangup","duration":95,"disposition":"ANSWERED","recording_url":"https://pbx/rec/1697.42.wav"}"#,
        )
        .unwrap();
        assert_eq!(
            (done.state, done.duration_seconds, done.missed),
            (CallState::Ended, Some(95), false)
        );
        assert_eq!(
            done.recording_url.as_deref(),
            Some("https://pbx/rec/1697.42.wav")
        );
        let missed =
            parse_event(br#"{"call_id":"1697.43","event":"hangup","disposition":"NO ANSWER"}"#)
                .unwrap();
        assert!(missed.missed);
        assert!(
            parse_event(
                br#"{"call_id":"x","event":"hangup","recording_url":"file:///etc/passwd"}"#
            )
            .unwrap()
            .recording_url
            .is_none()
        );
        assert_eq!(parse_event(br#"{"event":"ringing"}"#), None);
        assert_eq!(parse_event(br#"{"call_id":"x","event":"transfer"}"#), None);
    }

    #[test]
    fn voice_adapters_asterisk_originates() {
        let q = originate_query(
            "PJSIP/{agent}",
            "201",
            "+966551234567",
            "from-internal",
            "+966110000000",
        )
        .unwrap();
        assert!(q.contains(&("endpoint", "PJSIP/201".to_owned())));
        assert!(q.contains(&("extension", "+966551234567".to_owned())));
        assert_eq!(
            originate_query("PJSIP/{agent}", "201&x=1", "+1", "c", ""),
            None
        );
        assert_eq!(
            channel_id(200, r#"{"id":"1697.44","state":"Down"}"#),
            Some("1697.44".into())
        );
        assert_eq!(channel_id(500, "{}"), None);
    }
}
