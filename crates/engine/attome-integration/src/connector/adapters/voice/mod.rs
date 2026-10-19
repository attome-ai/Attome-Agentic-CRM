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
    caller_id: Option<&str>,
    urls: &CallbackUrls,
) -> Result<String, AppError> {
    match provider(system).as_deref() {
        // Twilio's customer leg takes its caller id from the call's row,
        // when the TwiML step dials it.
        Some("twilio") => twilio::place_call(state, system, agent, urls).await,
        Some("asterisk") => asterisk::place_call(state, system, agent, to, caller_id).await,
        _ => Err(AppError::Validation(format!(
            "{}: not a voice system",
            system.name
        ))),
    }
}

// ── Calls (J6-T1, the public API the dialer uses, D21-T6) ───────────────────

const LINK_DOMAIN: &str = "attome-voice";

/// The numbers a system owns: its `from_number` and the `numbers` list in
/// its config, as E.164, each once. Pure.
pub fn owned_numbers(config: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let listed = config
        .get("numbers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for raw in setting(config, "from_number").into_iter().chain(listed) {
        if let Some(n) = e164(raw)
            && !out.contains(&n)
        {
            out.push(n);
        }
    }
    out
}

/// The person's own number or extension (personal setting
/// `voice.agent_number`).
pub fn agent_number(state: &EngineState, user: Uuid) -> Option<String> {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get("voice.agent_number")
        .map(|d| settings.resolve(d, Some(user), None).0)
        .and_then(|v| v.as_str().map(str::trim).map(str::to_owned))
        .filter(|v| !v.is_empty())
}

fn link_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

/// The provider's URLs for one call, signed for a day.
pub fn callback_urls(state: &EngineState, call: Uuid) -> Result<CallbackUrls, AppError> {
    let expires = (chrono::Utc::now() + chrono::Duration::days(1)).timestamp();
    let token = attome_auth::signed_link::sign(
        &link_secret(state)?,
        LINK_DOMAIN,
        &call.to_string(),
        expires,
    )
    .ok_or_else(|| AppError::internal("voice callback could not be signed"))?;
    let base = state.base.config.frontend_url();
    let base = base.trim_end_matches('/');
    Ok(CallbackUrls {
        events: format!("{base}/api/v1/voice/events/{token}"),
        twiml: format!("{base}/api/v1/voice/twiml/{token}"),
    })
}

/// The call a callback token names.
pub fn call_of(state: &EngineState, token: &str) -> Result<Uuid, AppError> {
    attome_auth::signed_link::verify(
        &link_secret(state)?,
        LINK_DOMAIN,
        token,
        chrono::Utc::now().timestamp(),
    )
    .and_then(|s| Uuid::parse_str(&s).ok())
    .ok_or(AppError::NotFound)
}

/// A call started from Attome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct StartedCall {
    pub call_id: Uuid,
    pub activity_id: Uuid,
}

async fn cancel_activity(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    user: Uuid,
    activity: Uuid,
) -> Result<(), AppError> {
    let version: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM activity WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(activity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(version) = version {
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            user,
            "activity",
            activity,
            version,
            serde_json::json!({ "status": "cancelled" }),
        )
        .await?;
    }
    Ok(())
}

/// Starts a call from `user` to `to` about a record: logs a `phone_call`
/// activity on it as the user, keeps the `voice_call` row, and has the
/// provider ring the user's own phone and then the number (`browser`
/// false), or leaves dialling to the browser softphone (`browser` true).
/// `caller_id`, when given, is what the customer sees; it must be one the
/// system owns. A failed start cancels the activity and marks the call
/// failed. The caller holds no transaction: the provider is called with
/// none open.
#[allow(clippy::too_many_arguments)]
pub async fn start_call(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    system: &IntegrationSystem,
    to: &str,
    caller_id: Option<&str>,
    about: (&str, Uuid),
    browser: bool,
) -> Result<StartedCall, AppError> {
    use attome_security::SecurityContextExt;
    ctx.require("activity", "create")?;
    let user = ctx.user_id;
    let to = e164(to).ok_or_else(|| AppError::Validation("to: an E.164 number".into()))?;
    let caller_id = match caller_id {
        Some(c) => {
            let c =
                e164(c).ok_or_else(|| AppError::Validation("caller_id: an E.164 number".into()))?;
            if !owned_numbers(&config(system)).contains(&c) {
                return Err(AppError::Validation(
                    "caller_id: not a number this system owns".into(),
                ));
            }
            Some(c)
        }
        None => None,
    };
    let agent = if browser {
        format!("client:{}", twilio::client_identity(user))
    } else {
        agent_number(state, user).ok_or_else(|| {
            AppError::Validation(
                "set your phone number or extension (voice.agent_number) first".into(),
            )
        })?
    };
    let (activity, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        user,
        "activity",
        serde_json::json!({
            "subject": format!("Call to {to}"),
            "activity_type": "phone_call",
            "direction": "outbound",
            "due_at": chrono::Utc::now().to_rfc3339(),
            "entity_name": about.0,
            "record_id": about.1.to_string(),
        }),
    )
    .await?;
    let call = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO voice_call (id, system_id, user_id, activity_id, direction, from_number, to_number, caller_id) \
         VALUES ($1, $2, $3, $4, 'outbound', $5, $6, $7)",
    )
    .bind(call)
    .bind(system.id)
    .bind(user)
    .bind(activity)
    .bind(&agent)
    .bind(&to)
    .bind(caller_id.as_deref())
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let started = StartedCall {
        call_id: call,
        activity_id: activity,
    };
    if browser {
        return Ok(started);
    }
    let placed = match callback_urls(state, call) {
        Ok(urls) => place_call(state, system, &agent, &to, caller_id.as_deref(), &urls).await,
        Err(error) => Err(error),
    };
    match placed {
        Ok(provider_id) => {
            sqlx::query(
                "UPDATE voice_call SET provider_call_id = $2, updated_at = now() WHERE id = $1",
            )
            .bind(call)
            .bind(provider_id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(started)
        }
        Err(error) => {
            sqlx::query(
                "UPDATE voice_call SET state = 'failed', activity_done = true, updated_at = now() WHERE id = $1",
            )
            .bind(call)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            cancel_activity(state, ctx, user, activity).await?;
            Err(error)
        }
    }
}

/// Plays a recorded message into a call in progress and hangs up
/// (voicemail drop). Twilio only: Attome opens no audio stream, it tells
/// the provider which recording to play.
pub async fn drop_voicemail(
    state: &EngineState,
    system: &IntegrationSystem,
    call: Uuid,
    recording_url: &str,
) -> Result<(), AppError> {
    if !recording_url.starts_with("https://") {
        return Err(AppError::Validation("recording: an https address".into()));
    }
    let (provider_call_id, call_system): (Option<String>, Uuid) =
        sqlx::query_as("SELECT provider_call_id, system_id FROM voice_call WHERE id = $1")
            .bind(call)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    if call_system != system.id {
        return Err(AppError::NotFound);
    }
    let sid = provider_call_id.ok_or_else(|| AppError::Conflict("the call has not started yet"))?;
    match provider(system).as_deref() {
        Some("twilio") => twilio::play_and_hang_up(state, system, &sid, recording_url).await,
        _ => Err(AppError::Validation(
            "voicemail drop needs a Twilio voice system".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_adapters_list_owned_numbers() {
        let cfg = serde_json::json!({
            "from_number": "+966 11 000 0000",
            "numbers": ["+971 4 000 0000", "+966110000000", "not a number"],
        });
        assert_eq!(owned_numbers(&cfg), vec!["+966110000000", "+97140000000"]);
        assert!(owned_numbers(&Value::Null).is_empty());
    }

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
