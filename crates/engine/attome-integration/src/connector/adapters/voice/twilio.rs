//! J6-T1: Twilio Voice.
//!
//! **Placing** a call is `POST /Accounts/{sid}/Calls.json` to the agent's
//! own phone from the system's number, with `Url` (the instructions Twilio
//! fetches when the agent answers: dial the customer) and `StatusCallback`
//! (every step of the call), both signed per call by the caller.
//!
//! **Events** are Twilio's form posts: `CallSid`, `CallStatus`, `Direction`,
//! `From`, `To`, `CallDuration`, and `RecordingUrl` when a recording is
//! ready.

use attome_core::EngineState;
use attome_types::AppError;

use super::{CallEvent, CallState, CallbackUrls, config, credential, setting};
use crate::system::IntegrationSystem;

const API: &str = "https://api.twilio.com/2010-04-01";

/// Reads a Twilio call status callback. Pure.
pub fn parse_event(body: &[u8]) -> Option<CallEvent> {
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |key: &str| {
        form.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let call_id = get("CallSid")?;
    let recording_url = get("RecordingUrl");
    let status = get("CallStatus").unwrap_or_default();
    let (state, missed) = match status.as_str() {
        "queued" | "initiated" | "ringing" => (CallState::Ringing, false),
        "in-progress" => (CallState::Answered, false),
        "completed" => (CallState::Ended, false),
        "busy" | "failed" | "no-answer" | "canceled" => (CallState::Ended, true),
        // A recording callback carries no call status: the call has ended.
        "" if recording_url.is_some() => (CallState::Ended, false),
        _ => return None,
    };
    let direction = get("Direction").map(|d| {
        if d == "inbound" {
            "inbound"
        } else {
            "outbound"
        }
    });
    Some(CallEvent {
        call_id,
        state,
        direction,
        from: get("From"),
        to: get("To"),
        duration_seconds: get("CallDuration")
            .or_else(|| get("RecordingDuration"))
            .and_then(|d| d.parse().ok()),
        // Twilio's recording URL is the resource; `.mp3` is the audio.
        recording_url: recording_url.map(|u| {
            if u.ends_with(".mp3") {
                u
            } else {
                format!("{u}.mp3")
            }
        }),
        missed,
    })
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// TwiML that dials `number` from `caller_id`, reporting the dialled leg to
/// `events` and recording it when `record`. Pure.
pub fn dial_twiml(caller_id: &str, number: &str, events: &str, record: bool) -> String {
    let record = if record {
        format!(
            " record=\"record-from-answer-dual\" recordingStatusCallback=\"{}\"",
            xml(events)
        )
    } else {
        String::new()
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Dial callerId=\"{}\"{record}>\
         <Number statusCallbackEvent=\"initiated ringing answered completed\" statusCallback=\"{}\">{}</Number>\
         </Dial></Response>",
        xml(caller_id),
        xml(events),
        xml(number)
    )
}

/// TwiML that says nobody can take the call. Pure.
pub fn unavailable_twiml() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Say>Sorry, nobody can take your call right now.</Say><Hangup/></Response>".to_owned()
}

/// The form that places a call to `agent`. Pure.
pub fn place_form(from: &str, agent: &str, urls: &CallbackUrls) -> Vec<(&'static str, String)> {
    vec![
        ("To", agent.to_owned()),
        ("From", from.to_owned()),
        ("Url", urls.twiml.clone()),
        ("StatusCallback", urls.events.clone()),
        (
            "StatusCallbackEvent",
            "initiated ringing answered completed".to_owned(),
        ),
    ]
}

/// The call id in Twilio's answer. Pure.
pub fn created_sid(status: u16, body: &str) -> Option<String> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("sid")?.as_str().map(str::to_owned)
}

pub(super) async fn place_call(
    state: &EngineState,
    system: &IntegrationSystem,
    agent: &str,
    urls: &CallbackUrls,
) -> Result<String, AppError> {
    let cfg = config(system);
    let sid = setting(&cfg, "account_sid")
        .filter(|s| s.chars().all(|c| c.is_ascii_alphanumeric()))
        .ok_or_else(|| {
            AppError::Validation(format!("{}: config has no account_sid", system.name))
        })?;
    let from = setting(&cfg, "from_number").ok_or_else(|| {
        AppError::Validation(format!("{}: config has no from_number", system.name))
    })?;
    let token = credential(state, system).await?;
    let client = reqwest::Client::builder()
        .timeout(super::TIMEOUT)
        .build()
        .map_err(AppError::internal)?;
    let res = client
        .post(format!("{API}/Accounts/{sid}/Calls.json"))
        .basic_auth(sid, Some(token))
        .form(&place_form(from, agent, urls))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    created_sid(status, &body)
        .ok_or_else(|| AppError::Validation(format!("Twilio refused the call ({status})")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_adapters_twilio_reads_call_events() {
        let ringing = parse_event(b"CallSid=CA1&CallStatus=ringing&Direction=outbound-api&From=%2B15550001111&To=%2B966551234567");
        let ringing = ringing.unwrap();
        assert_eq!(
            (ringing.call_id.as_str(), ringing.state),
            ("CA1", CallState::Ringing)
        );
        assert_eq!(ringing.direction, Some("outbound"));
        assert_eq!(ringing.to.as_deref(), Some("+966551234567"));

        let ended =
            parse_event(b"CallSid=CA1&CallStatus=completed&CallDuration=127&Direction=inbound")
                .unwrap();
        assert_eq!(
            (ended.state, ended.duration_seconds, ended.missed),
            (CallState::Ended, Some(127), false)
        );
        assert_eq!(ended.direction, Some("inbound"));

        let missed = parse_event(b"CallSid=CA2&CallStatus=no-answer").unwrap();
        assert!(missed.missed);

        let recording = parse_event(
            b"CallSid=CA1&RecordingSid=RE1&RecordingStatus=completed&RecordingDuration=120&RecordingUrl=https%3A%2F%2Fapi.twilio.com%2F2010-04-01%2FAccounts%2FAC1%2FRecordings%2FRE1",
        )
        .unwrap();
        assert_eq!(
            recording.recording_url.as_deref(),
            Some("https://api.twilio.com/2010-04-01/Accounts/AC1/Recordings/RE1.mp3")
        );
        assert_eq!(recording.state, CallState::Ended);
        assert_eq!(parse_event(b"CallStatus=ringing"), None, "no call id");
        assert_eq!(parse_event(b"CallSid=CA3&CallStatus=weird"), None);
    }

    #[test]
    fn voice_adapters_twilio_instructions_and_placing() {
        let twiml = dial_twiml(
            "+15550001111",
            "+966551234567",
            "https://x/api/v1/voice/events/a.b?c=1&d=2",
            true,
        );
        assert!(
            twiml.contains("<Dial callerId=\"+15550001111\" record=\"record-from-answer-dual\"")
        );
        assert!(twiml.contains(">+966551234567</Number>"));
        assert!(
            twiml.contains("events/a.b?c=1&amp;d=2"),
            "the URL is escaped"
        );
        assert!(!dial_twiml("+1", "+2", "u", false).contains("record="));
        assert!(unavailable_twiml().contains("<Hangup/>"));

        let urls = CallbackUrls {
            events: "https://x/e".into(),
            twiml: "https://x/t".into(),
        };
        let form = place_form("+15550001111", "+966500000000", &urls);
        assert!(form.contains(&("To", "+966500000000".to_owned())));
        assert!(form.contains(&("Url", "https://x/t".to_owned())));
        assert_eq!(
            created_sid(201, r#"{"sid":"CA9","status":"queued"}"#),
            Some("CA9".into())
        );
        assert_eq!(created_sid(400, r#"{"code":21211}"#), None);
    }
}
