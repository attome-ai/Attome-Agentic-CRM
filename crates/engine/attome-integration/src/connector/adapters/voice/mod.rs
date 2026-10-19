//! J6-T1: telephony. A voice system is an `integration_system` row whose
//! config names its provider (`"voice": "twilio"` or `"voice": "asterisk"`).
//!
//! - **Twilio Voice** ([`twilio`]): `account_sid`, `from_number`, and for
//!   inbound calls `inbound_key` and `forward_to`; the auth token is the
//!   credential. A call placed from Attome rings the agent's own phone first
//!   and, when they answer, dials the customer (TwiML `<Dial>`); Twilio
//!   reports each step to a signed callback URL per call.
//! - **Asterisk** ([`asterisk`]): `base_url` (the ARI root, e.g.
//!   `https://pbx.example/ari`), `endpoint` (e.g. `PJSIP/{agent}`),
//!   `context`, `from_number` and `inbound_key`; `user:password` for ARI is
//!   the credential. A call is originated through ARI; the PBX reports call
//!   events by posting the small JSON [`asterisk::parse_event`] reads, from
//!   its dialplan (`CURL()`) or a 3CX-style call webhook.
//!
//! Every event becomes a [`CallEvent`]: ringing, answered or ended, with the
//! duration and recording when there is one. The app side keeps one
//! `voice_call` row per call and the matching `phone_call` activity.

pub mod asterisk;
pub mod twilio;

use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::system::IntegrationSystem;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(15);

/// Where a call is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Ringing,
    Answered,
    /// Over: answered and hung up, or never answered (busy, no answer,
    /// failed, cancelled; [`CallEvent::missed`]).
    Ended,
}

impl CallState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ringing => "ringing",
            Self::Answered => "answered",
            Self::Ended => "ended",
        }
    }
}

/// One thing that happened on a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEvent {
    /// The provider's id for the call.
    pub call_id: String,
    pub state: CallState,
    /// `inbound` or `outbound`, when the event says.
    pub direction: Option<&'static str>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub duration_seconds: Option<i64>,
    pub recording_url: Option<String>,
    /// Ended without being answered (busy, no answer, failed, cancelled).
    pub missed: bool,
}

/// The system's config as JSON.
pub fn config(system: &IntegrationSystem) -> Value {
    system
        .config
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(Value::Null)
}

/// A config value by name.
pub fn setting<'a>(config: &'a Value, name: &str) -> Option<&'a str> {
    config
        .get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

/// The provider a system uses.
pub fn provider(system: &IntegrationSystem) -> Option<String> {
    setting(&config(system), "voice").map(str::to_owned)
}

/// The active voice systems, oldest first.
pub async fn systems(state: &EngineState) -> Result<Vec<IntegrationSystem>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'voice' END \
                IN ('twilio', 'asterisk') \
          ORDER BY created_at, id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for id in ids {
        if let Some(system) = crate::system::load(&state.base.db, id).await? {
            out.push(system);
        }
    }
    Ok(out)
}

/// The voice system whose `inbound_key` is `key` (16+ characters, compared
/// by digest).
pub async fn system_by_key(
    state: &EngineState,
    key: &str,
) -> Result<Option<IntegrationSystem>, AppError> {
    use sha2::{Digest, Sha256};
    let presented = Sha256::digest(key.as_bytes());
    for system in systems(state).await? {
        let expected = setting(&config(&system), "inbound_key")
            .filter(|k| k.len() >= 16)
            .map(str::to_owned);
        if let Some(expected) = expected
            && Sha256::digest(expected.as_bytes()) == presented
        {
            return Ok(Some(system));
        }
    }
    Ok(None)
}

/// The system's secret.
pub async fn credential(
    state: &EngineState,
    system: &IntegrationSystem,
) -> Result<String, AppError> {
    crate::credential::resolve(
        &state.base.db,
        &state.base.config.integration.credential_encryption_key,
        system.credential_ref.as_deref(),
    )
    .await?
    .ok_or_else(|| AppError::Validation(format!("{}: no credential set", system.name)))
}

/// A number as E.164 (`+` and 8 to 15 digits), or none. Pure.
pub fn e164(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    (raw.trim().starts_with('+') && (8..=15).contains(&digits.len())).then(|| format!("+{digits}"))
}

/// Whether a recording URL may be fetched for this system: Twilio's own
/// API host, or the PBX's own origin. Anything else is refused, so a
/// callback cannot make the server fetch an arbitrary address. Pure.
pub fn recording_allowed(provider: &str, config: &Value, url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match provider {
        "twilio" => parsed.scheme() == "https" && parsed.host_str() == Some("api.twilio.com"),
        "asterisk" => setting(config, "base_url")
            .and_then(|b| url::Url::parse(b).ok())
            .is_some_and(|base| {
                base.scheme() == parsed.scheme()
                    && base.host_str() == parsed.host_str()
                    && base.port_or_known_default() == parsed.port_or_known_default()
            }),
        _ => false,
    }
}

/// The audio type and a file name for a recording URL. Pure.
pub fn recording_kind(url: &str) -> Option<(&'static str, &'static str)> {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if path.ends_with(".mp3") {
        Some(("audio/mpeg", "call-recording.mp3"))
    } else if path.ends_with(".wav") {
        Some(("audio/x-wav", "call-recording.wav"))
    } else if path.ends_with(".ogg") {
        Some(("audio/ogg", "call-recording.ogg"))
    } else if path.ends_with(".m4a") {
        Some(("audio/m4a", "call-recording.m4a"))
    } else {
        None
    }
}

/// Downloads a call's recording with the system's credentials, at most
/// `max_bytes`; answers the bytes, audio type and file name.
pub async fn fetch_recording(
    state: &EngineState,
    system: &IntegrationSystem,
    url: &str,
    max_bytes: u64,
) -> Result<(Vec<u8>, &'static str, &'static str), AppError> {
    let cfg = config(system);
    let provider = provider(system).unwrap_or_default();
    if !recording_allowed(&provider, &cfg, url) {
        return Err(AppError::Validation(
            "the recording is not on the provider's own host".into(),
        ));
    }
    let (content_type, filename) =
        recording_kind(url).ok_or_else(|| AppError::Validation("not an audio recording".into()))?;
    let secret = credential(state, system).await?;
    let (user, password) = match provider.as_str() {
        "twilio" => (
            setting(&cfg, "account_sid").unwrap_or_default().to_owned(),
            twilio::Secrets::parse(&secret).auth_token,
        ),
        _ => {
            let (u, p) = secret.split_once(':').unwrap_or((secret.as_str(), ""));
            (u.to_owned(), p.to_owned())
        }
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(AppError::internal)?;
    let res = client
        .get(url)
        .basic_auth(user, Some(password))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(AppError::Validation(format!(
            "the recording could not be fetched ({status})"
        )));
    }
    if res.content_length().is_some_and(|len| len > max_bytes) {
        return Err(AppError::Validation(
            "the recording is over the upload limit".into(),
        ));
    }
    let bytes = res.bytes().await.map_err(AppError::internal)?;
    if bytes.len() as u64 > max_bytes {
        return Err(AppError::Validation(
            "the recording is over the upload limit".into(),
        ));
    }
    Ok((bytes.to_vec(), content_type, filename))
}

/// Where the provider should report a call's events and fetch its
/// instructions: built by the caller (it signs them).
#[derive(Debug, Clone)]
pub struct CallbackUrls {
    pub events: String,
    pub twiml: String,
}

/// Places a call from `agent` (their phone number or extension) to `to`;
/// answers the provider's call id.
pub async fn place_call(
    state: &EngineState,
    system: &IntegrationSystem,
    agent: &str,
    to: &str,
    urls: &CallbackUrls,
) -> Result<String, AppError> {
    match provider(system).as_deref() {
        Some("twilio") => twilio::place_call(state, system, agent, urls).await,
        Some("asterisk") => asterisk::place_call(state, system, agent, to).await,
        _ => Err(AppError::Validation(format!(
            "{}: not a voice system",
            system.name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_adapters_normalise_numbers() {
        assert_eq!(e164("+966 55 123 4567"), Some("+966551234567".into()));
        assert_eq!(e164("0551234567"), None, "a local number");
        assert_eq!(e164("+123"), None);
        assert_eq!(CallState::Answered.as_str(), "answered");
    }

    #[test]
    fn call_logging_fetches_recordings_only_from_the_provider() {
        let pbx = serde_json::json!({ "base_url": "https://pbx.example:8089/ari" });
        assert!(recording_allowed(
            "twilio",
            &Value::Null,
            "https://api.twilio.com/2010-04-01/Accounts/AC1/Recordings/RE1.mp3"
        ));
        assert!(!recording_allowed(
            "twilio",
            &Value::Null,
            "http://api.twilio.com/x.mp3"
        ));
        assert!(!recording_allowed(
            "twilio",
            &Value::Null,
            "https://169.254.169.254/latest.mp3"
        ));
        assert!(recording_allowed(
            "asterisk",
            &pbx,
            "https://pbx.example:8089/recordings/1.wav"
        ));
        assert!(
            !recording_allowed("asterisk", &pbx, "https://pbx.example/recordings/1.wav"),
            "another port"
        );
        assert!(!recording_allowed(
            "asterisk",
            &pbx,
            "https://evil.example:8089/1.wav"
        ));
        assert_eq!(
            recording_kind("https://x/RE1.mp3?Download=true"),
            Some(("audio/mpeg", "call-recording.mp3"))
        );
        assert_eq!(
            recording_kind("https://x/1697.42.WAV"),
            Some(("audio/x-wav", "call-recording.wav"))
        );
        assert_eq!(recording_kind("https://x/1697.42.gsm"), None);
    }
}
