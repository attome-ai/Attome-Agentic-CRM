//! J6-T1: calls through Twilio Voice or an Asterisk PBX (the adapters are
//! `attome_integration::connector::adapters::voice`).
//!
//! **Calling out.** `POST /api/v1/voice/calls` (staff) opens a `phone_call`
//! activity on the record as the caller, keeps a `voice_call` row, and asks
//! the provider to ring the caller's own phone (personal setting
//! `voice.agent_number`) and then the customer. Twilio fetches the dialling
//! instructions and reports each step at URLs signed for that one call.
//!
//! **Calls coming in** reach `POST /api/v1/voice/twilio/{key}/inbound`
//! (Twilio's number) or arrive as PBX events at
//! `POST /api/v1/voice/pbx/{key}/events`; the caller's number is matched to
//! a contact, lead or account (else the call goes on the voice system's
//! record) and a `phone_call` activity is opened as the system's service
//! principal. Twilio forwards the call to the system's `forward_to`.
//!
//! **Events** move the `voice_call` forward (ringing, answered, ended, or
//! missed) under a row lock, so repeated or out-of-order callbacks do no
//! harm; when the call ends the activity is completed once, with the
//! duration, and the recording link is added when it is ready. Every
//! activity change goes through the generic mutation path.

use attome_auth::signed_link;
use attome_core::EngineState;
use attome_integration::connector::adapters::voice::{
    self, CallEvent, CallState, CallbackUrls, asterisk, twilio,
};
use attome_integration::system::IntegrationSystem;
use attome_modules::MODULE_OMNICHANNEL;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

const LINK_DOMAIN: &str = "attome-voice";

fn licensed(state: &EngineState) -> Result<(), AppError> {
    state
        .modules
        .load()
        .require(MODULE_OMNICHANNEL)
        .map_err(|_| AppError::NotFound)
}

fn secret(state: &EngineState) -> Result<String, AppError> {
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
fn callback_urls(state: &EngineState, call: Uuid) -> Result<CallbackUrls, AppError> {
    let expires = (Utc::now() + Duration::days(1)).timestamp();
    let token = signed_link::sign(&secret(state)?, LINK_DOMAIN, &call.to_string(), expires)
        .ok_or_else(|| AppError::internal("voice callback could not be signed"))?;
    let base = state.base.config.frontend_url();
    let base = base.trim_end_matches('/');
    Ok(CallbackUrls {
        events: format!("{base}/api/v1/voice/events/{token}"),
        twiml: format!("{base}/api/v1/voice/twiml/{token}"),
    })
}

fn call_of(state: &EngineState, token: &str) -> Result<Uuid, AppError> {
    signed_link::verify(&secret(state)?, LINK_DOMAIN, token, Utc::now().timestamp())
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or(AppError::NotFound)
}

fn twiml(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/xml; charset=utf-8")], body).into_response()
}

/// The person's own number or extension (personal setting `voice.agent_number`).
fn agent_number(state: &EngineState, user: Uuid) -> Option<String> {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get("voice.agent_number")
        .map(|d| settings.resolve(d, Some(user), None).0)
        .and_then(|v| v.as_str().map(str::trim).map(str::to_owned))
        .filter(|v| !v.is_empty())
}

#[derive(sqlx::FromRow)]
struct CallRow {
    id: Uuid,
    system_id: Uuid,
    user_id: Option<Uuid>,
    activity_id: Option<Uuid>,
    state: String,
    to_number: Option<String>,
    recording_url: Option<String>,
    activity_done: bool,
}

const CALL_COLUMNS: &str =
    "id, system_id, user_id, activity_id, state, to_number, recording_url, activity_done";

async fn load_call(state: &EngineState, id: Uuid) -> Result<CallRow, AppError> {
    sqlx::query_as(&format!(
        "SELECT {CALL_COLUMNS} FROM voice_call WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Where the state machine may go: never back from an end.
fn next_state(current: &str, event: &CallEvent) -> Option<&'static str> {
    let rank = |s: &str| match s {
        "placing" => 0,
        "ringing" => 1,
        "answered" => 2,
        _ => 3,
    };
    let to = match event.state {
        CallState::Ringing => "ringing",
        CallState::Answered => "answered",
        CallState::Ended if event.missed && current != "answered" => "missed",
        CallState::Ended => "ended",
    };
    (rank(to) > rank(current)).then_some(to)
}

/// Writes `body` onto the call's activity as `actor`.
async fn update_activity(
    state: &EngineState,
    actor: Uuid,
    activity: Uuid,
    body: Value,
) -> Result<(), AppError> {
    let version: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM activity WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(activity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(version) = version else {
        return Ok(());
    };
    let ctx = state.base.security.resolve(actor).await?;
    attome_records::entity_crud::update_record_for(
        state, &ctx, actor, "activity", activity, version, body,
    )
    .await?;
    Ok(())
}

/// The person the activity is written as: the caller, else the system's
/// service principal.
fn actor(call: &CallRow, system: &IntegrationSystem) -> Result<Uuid, AppError> {
    match call.user_id {
        Some(user) => Ok(user),
        None => attome_integration::system::service_principal_id(system),
    }
}

/// Moves the call forward and, when it ends, completes its activity once.
async fn apply_event(
    state: &EngineState,
    call_id: Uuid,
    event: &CallEvent,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let call: CallRow = sqlx::query_as(&format!(
        "SELECT {CALL_COLUMNS} FROM voice_call WHERE id = $1 FOR UPDATE"
    ))
    .bind(call_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let next = next_state(&call.state, event);
    let new_recording = event
        .recording_url
        .clone()
        .filter(|u| call.recording_url.as_deref() != Some(u.as_str()));
    let finishing = matches!(next, Some("ended" | "missed")) && !call.activity_done;
    sqlx::query(
        "UPDATE voice_call SET \
            state = coalesce($2, state), \
            answered_at = CASE WHEN $2 = 'answered' THEN now() ELSE answered_at END, \
            ended_at = CASE WHEN $2 IN ('ended', 'missed') THEN now() ELSE ended_at END, \
            duration_seconds = coalesce($3, duration_seconds), \
            recording_url = coalesce($4, recording_url), \
            activity_done = activity_done OR $5, \
            updated_at = now() \
          WHERE id = $1",
    )
    .bind(call.id)
    .bind(next)
    .bind(
        event
            .duration_seconds
            .map(|d| d.clamp(0, i64::from(i32::MAX)) as i32),
    )
    .bind(new_recording.as_deref())
    .bind(finishing)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;

    let Some(activity) = call.activity_id else {
        return Ok(());
    };
    if !finishing && new_recording.is_none() {
        return Ok(());
    }
    let system = attome_integration::system::load(&state.base.db, call.system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let actor = actor(&call, &system)?;
    let mut body = serde_json::Map::new();
    if finishing {
        body.insert("status".into(), json!("completed"));
        body.insert("completed_at".into(), json!(Utc::now().to_rfc3339()));
        if let Some(seconds) = event.duration_seconds.filter(|s| *s > 0) {
            body.insert("duration_minutes".into(), json!((seconds + 59) / 60));
        }
    }
    let mut notes = Vec::new();
    if next == Some("missed") {
        notes.push("Missed call (not answered).".to_owned());
    }
    if let Some(url) = &new_recording {
        notes.push(format!("Recording: {url}"));
    }
    if !notes.is_empty() {
        let current: Option<String> =
            sqlx::query_scalar("SELECT description FROM activity WHERE id = $1")
                .bind(activity)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .flatten();
        let mut description = current.unwrap_or_default();
        for note in notes {
            if !description.contains(&note) {
                if !description.is_empty() {
                    description.push('\n');
                }
                description.push_str(&note);
            }
        }
        body.insert("description".into(), Value::String(description));
    }
    update_activity(state, actor, activity, Value::Object(body)).await
}

/// Opens an inbound call: its `voice_call` row and a `phone_call` activity
/// on the matching person (else the system), as the system's principal.
async fn open_inbound(
    state: &EngineState,
    system: &IntegrationSystem,
    event: &CallEvent,
) -> Result<Uuid, AppError> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM voice_call WHERE system_id = $1 AND provider_call_id = $2",
    )
    .bind(system.id)
    .bind(&event.call_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let principal = attome_integration::system::service_principal_id(system)?;
    let ctx = state.base.security.resolve(principal).await?;
    ctx.require("activity", "create")?;
    let from = event.from.clone().unwrap_or_default();
    let found = match voice::e164(&from) {
        Some(number) => crate::sms_inbound::find_sender(state, &number).await?,
        None => None,
    };
    let (entity, record) = found.unwrap_or_else(|| ("integration_system".to_owned(), system.id));
    let (activity, _) = attome_records::entity_crud::create_record_for(
        state,
        &ctx,
        principal,
        "activity",
        json!({
            "subject": format!("Call from {}", if from.is_empty() { "an unknown number" } else { from.as_str() }),
            "activity_type": "phone_call",
            "direction": "inbound",
            "due_at": Utc::now().to_rfc3339(),
            "entity_name": entity,
            "record_id": record.to_string(),
        }),
    )
    .await?;
    let id = Uuid::now_v7();
    let inserted = sqlx::query(
        "INSERT INTO voice_call (id, system_id, provider_call_id, activity_id, direction, from_number, to_number) \
         VALUES ($1, $2, $3, $4, 'inbound', $5, $6) \
         ON CONFLICT (system_id, provider_call_id) DO NOTHING",
    )
    .bind(id)
    .bind(system.id)
    .bind(&event.call_id)
    .bind(activity)
    .bind(event.from.as_deref())
    .bind(event.to.as_deref())
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if inserted.rows_affected() == 0 {
        // The same call's event raced this one in: keep the first, drop ours.
        update_activity(state, principal, activity, json!({ "status": "cancelled" })).await?;
        return sqlx::query_scalar(
            "SELECT id FROM voice_call WHERE system_id = $1 AND provider_call_id = $2",
        )
        .bind(system.id)
        .bind(&event.call_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal);
    }
    Ok(id)
}

// ── Staff: placing a call ───────────────────────────────────────────────────

/// A call to place.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PlaceCall {
    /// The number to call, E.164.
    pub to: String,
    /// The record the call is about.
    pub entity_name: String,
    pub record_id: Uuid,
    /// Which voice system; the first active one when left out.
    pub system_id: Option<Uuid>,
}

/// A placed call.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlacedCall {
    pub call_id: Uuid,
    pub activity_id: Uuid,
}

/// Rings the caller's own phone, then the number, and logs the call.
#[utoipa::path(
    post,
    path = "/api/v1/voice/calls",
    tag = "omnichannel",
    request_body = PlaceCall,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Ringing the caller's phone", body = PlacedCall),
        (status = 403, description = "No privilege to log calls on the record", body = ErrorResponse),
        (status = 404, description = "No voice system", body = ErrorResponse),
        (status = 422, description = "Not an E.164 number, no agent number set, or the provider refused", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_call(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(req): Json<PlaceCall>,
) -> Result<(StatusCode, Json<PlacedCall>), AppError> {
    licensed(&state)?;
    ctx.require("activity", "create")?;
    let to =
        voice::e164(&req.to).ok_or_else(|| AppError::Validation("to: an E.164 number".into()))?;
    let user = ctx.user_id;
    let agent = agent_number(&state, user).ok_or_else(|| {
        AppError::Validation("set your phone number or extension (voice.agent_number) first".into())
    })?;
    let system = match req.system_id {
        Some(id) => attome_integration::system::load(&state.base.db, id)
            .await?
            .filter(|s| voice::provider(s).is_some()),
        None => voice::systems(&state).await?.into_iter().next(),
    }
    .ok_or(AppError::NotFound)?;
    let (activity, _) = attome_records::entity_crud::create_record_for(
        &state,
        &ctx,
        user,
        "activity",
        json!({
            "subject": format!("Call to {to}"),
            "activity_type": "phone_call",
            "direction": "outbound",
            "due_at": Utc::now().to_rfc3339(),
            "entity_name": req.entity_name,
            "record_id": req.record_id.to_string(),
        }),
    )
    .await?;
    let call = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO voice_call (id, system_id, user_id, activity_id, direction, from_number, to_number) \
         VALUES ($1, $2, $3, $4, 'outbound', $5, $6)",
    )
    .bind(call)
    .bind(system.id)
    .bind(user)
    .bind(activity)
    .bind(&agent)
    .bind(&to)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let placed = match callback_urls(&state, call) {
        Ok(urls) => voice::place_call(&state, &system, &agent, &to, &urls).await,
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
            Ok((
                StatusCode::CREATED,
                Json(PlacedCall {
                    call_id: call,
                    activity_id: activity,
                }),
            ))
        }
        Err(error) => {
            sqlx::query("UPDATE voice_call SET state = 'failed', activity_done = true, updated_at = now() WHERE id = $1")
                .bind(call)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            update_activity(&state, user, activity, json!({ "status": "cancelled" })).await?;
            Err(error)
        }
    }
}

// ── Public: the providers' callbacks ────────────────────────────────────────

/// Twilio fetches what to do when the caller answers: dial the customer.
#[utoipa::path(
    post,
    path = "/api/v1/voice/twiml/{token}",
    tag = "omnichannel",
    params(("token" = String, Path, description = "The call's signed token")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "answers the dialling instructions for a call; changes nothing"
    )))),
    responses(
        (status = 200, description = "TwiML", body = String, content_type = "text/xml"),
        (status = 404, description = "Altered or expired token", body = ErrorResponse),
    ),
)]
async fn post_twiml(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    licensed(&state)?;
    let call = load_call(&state, call_of(&state, &token)?).await?;
    let system = attome_integration::system::load(&state.base.db, call.system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let cfg = voice::config(&system);
    let (Some(number), Some(caller_id)) = (
        call.to_number.as_deref(),
        voice::setting(&cfg, "from_number"),
    ) else {
        return Ok(twiml(twilio::unavailable_twiml()));
    };
    let urls = callback_urls(&state, call.id)?;
    let record = cfg.get("record").and_then(Value::as_bool).unwrap_or(false);
    Ok(twiml(twilio::dial_twiml(
        caller_id,
        number,
        &urls.events,
        record,
    )))
}

/// Twilio's reports on one call.
#[utoipa::path(
    post,
    path = "/api/v1/voice/events/{token}",
    tag = "omnichannel",
    params(("token" = String, Path, description = "The call's signed token")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 404, description = "Altered or expired token", body = ErrorResponse),
        (status = 422, description = "Not a call event", body = ErrorResponse),
    ),
)]
async fn post_events(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    licensed(&state)?;
    let call = call_of(&state, &token)?;
    let event = twilio::parse_event(&body)
        .ok_or_else(|| AppError::Validation("not a call event".into()))?;
    apply_event(&state, call, &event).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A call to the deployment's Twilio number.
#[utoipa::path(
    post,
    path = "/api/v1/voice/twilio/{key}/inbound",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The voice system's inbound key")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "TwiML that forwards the call", body = String, content_type = "text/xml"),
        (status = 404, description = "Not licensed, or no system has this key", body = ErrorResponse),
        (status = 422, description = "Not a call", body = ErrorResponse),
    ),
)]
async fn post_twilio_inbound(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    licensed(&state)?;
    let system = voice::system_by_key(&state, &key)
        .await?
        .filter(|s| voice::provider(s).as_deref() == Some("twilio"))
        .ok_or(AppError::NotFound)?;
    let mut event =
        twilio::parse_event(&body).ok_or_else(|| AppError::Validation("not a call".into()))?;
    event.direction = Some("inbound");
    let call = open_inbound(&state, &system, &event).await?;
    apply_event(&state, call, &event).await?;
    let cfg = voice::config(&system);
    let Some(forward) = voice::setting(&cfg, "forward_to").and_then(voice::e164) else {
        return Ok(twiml(twilio::unavailable_twiml()));
    };
    let urls = callback_urls(&state, call)?;
    let record = cfg.get("record").and_then(Value::as_bool).unwrap_or(false);
    let caller = event.from.clone().unwrap_or_default();
    Ok(twiml(twilio::dial_twiml(
        &caller,
        &forward,
        &urls.events,
        record,
    )))
}

/// A PBX's call events.
#[utoipa::path(
    post,
    path = "/api/v1/voice/pbx/{key}/events",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The voice system's inbound key")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 404, description = "Not licensed, no system has this key, or an unknown outbound call", body = ErrorResponse),
        (status = 422, description = "Not a call event", body = ErrorResponse),
    ),
)]
async fn post_pbx_events(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    licensed(&state)?;
    let system = voice::system_by_key(&state, &key)
        .await?
        .filter(|s| voice::provider(s).as_deref() == Some("asterisk"))
        .ok_or(AppError::NotFound)?;
    let event = asterisk::parse_event(&body)
        .ok_or_else(|| AppError::Validation("not a call event".into()))?;
    let known: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM voice_call WHERE system_id = $1 AND provider_call_id = $2",
    )
    .bind(system.id)
    .bind(&event.call_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let call = match known {
        Some(id) => id,
        None if event.direction == Some("inbound") => open_inbound(&state, &system, &event).await?,
        None => return Err(AppError::NotFound),
    };
    apply_event(&state, call, &event).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/voice/calls", post(post_call))
        .route("/api/v1/voice/twiml/{token}", post(post_twiml))
        .route("/api/v1/voice/events/{token}", post(post_events))
        .route(
            "/api/v1/voice/twilio/{key}/inbound",
            post(post_twilio_inbound),
        )
        .route("/api/v1/voice/pbx/{key}/events", post(post_pbx_events))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    post_call,
    post_twiml,
    post_events,
    post_twilio_inbound,
    post_pbx_events
))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(state: CallState, missed: bool) -> CallEvent {
        CallEvent {
            call_id: "CA1".into(),
            state,
            direction: None,
            from: None,
            to: None,
            duration_seconds: None,
            recording_url: None,
            missed,
        }
    }

    #[test]
    fn voice_adapters_call_states_only_move_forward() {
        assert_eq!(
            next_state("placing", &event(CallState::Ringing, false)),
            Some("ringing")
        );
        assert_eq!(
            next_state("ringing", &event(CallState::Answered, false)),
            Some("answered")
        );
        assert_eq!(
            next_state("answered", &event(CallState::Ringing, false)),
            None,
            "a late ringing"
        );
        assert_eq!(
            next_state("answered", &event(CallState::Ended, false)),
            Some("ended")
        );
        assert_eq!(
            next_state("ringing", &event(CallState::Ended, true)),
            Some("missed")
        );
        assert_eq!(
            next_state("answered", &event(CallState::Ended, true)),
            Some("ended"),
            "a dropped leg after an answer is not a missed call"
        );
        assert_eq!(
            next_state("ended", &event(CallState::Ended, false)),
            None,
            "twice"
        );
        assert_eq!(
            next_state("missed", &event(CallState::Answered, false)),
            None
        );
    }
}
