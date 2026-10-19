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
//!
//! **After the call** (J6-T3) the person who placed it is asked for its
//! outcome (an in-app notification that opens the record). The recording is
//! fetched from the provider (its own host only), stored as a document on
//! the call through the upload pipeline (so the virus scan runs), attached
//! once the scan passes, and sent to N22 transcription: the
//! `voice_recording` job, retried until the scan has finished.

use attome_core::EngineState;
use attome_integration::connector::adapters::voice::{
    self, CallEvent, CallState, asterisk, call_of, callback_urls, twilio,
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
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

fn licensed(state: &EngineState) -> Result<(), AppError> {
    state
        .modules
        .load()
        .require(MODULE_OMNICHANNEL)
        .map_err(|_| AppError::NotFound)
}

fn twiml(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/xml; charset=utf-8")], body).into_response()
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

/// The caller id chosen for a call (D21-T6), if any.
async fn caller_id_of(state: &EngineState, call: Uuid) -> Result<Option<String>, AppError> {
    let chosen: Option<Option<String>> =
        sqlx::query_scalar("SELECT caller_id FROM voice_call WHERE id = $1")
            .bind(call)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(chosen.flatten())
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

    if new_recording.is_some() {
        enqueue_recording(state, call.id).await?;
    }
    let Some(activity) = call.activity_id else {
        return Ok(());
    };
    if finishing
        && next == Some("ended")
        && let Some(user) = call.user_id
    {
        prompt_outcome(
            state,
            user,
            activity,
            call.to_number.as_deref(),
            event.duration_seconds,
        )
        .await;
    }
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

/// J6-T3: asks the caller for the call's outcome: an in-app notification
/// that opens the record the call is on. Best effort; a failure is logged.
async fn prompt_outcome(
    state: &EngineState,
    user: Uuid,
    activity: Uuid,
    to: Option<&str>,
    seconds: Option<i64>,
) {
    let place: Option<(String, String)> =
        sqlx::query_as("SELECT entity_name, record_id FROM activity WHERE id = $1")
            .bind(activity)
            .fetch_optional(&state.base.db)
            .await
            .ok()
            .flatten();
    let route = place.map_or_else(
        || format!("/xrm/entity/activity/form?id={activity}"),
        |(entity, record)| format!("/xrm/entity/{entity}/form?id={record}"),
    );
    let minutes = seconds.filter(|s| *s > 0).map(|s| (s + 59) / 60);
    let body = match (to, minutes) {
        (Some(to), Some(m)) => format!("Your call to {to} ended after {m} min. Add its outcome."),
        (Some(to), None) => format!("Your call to {to} ended. Add its outcome."),
        _ => "Your call ended. Add its outcome.".to_owned(),
    };
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_owned(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned()]),
        subject: Some("Call ended: add the outcome".to_owned()),
        body_html: None,
        body_text: Some(body),
        route: Some(route),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        tracing::warn!(%user, %activity, %error, "voice: outcome prompt not sent");
    }
}

/// Queues the `voice_recording` job for a call.
async fn enqueue_recording(state: &EngineState, call: Uuid) -> Result<(), AppError> {
    crate::jobs::register_job_types();
    let job = attome_core::jobs::JOB_TYPES
        .job(
            crate::jobs::VOICE_RECORDING.name,
            &json!({ "call_id": call }),
        )
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_on_pool(
        &state.base.db,
        attome_core::jobs::EngineJob::Registered(job),
    )
    .await
    .map_err(AppError::internal)
}

#[derive(sqlx::FromRow)]
struct RecordingRow {
    system_id: Uuid,
    user_id: Option<Uuid>,
    activity_id: Option<Uuid>,
    recording_url: Option<String>,
    recording_document_id: Option<Uuid>,
    recording_session_id: Option<Uuid>,
    recording_attached: bool,
}

/// How long one run waits for the virus scan before handing the call back
/// to the queue.
const SCAN_WAIT_ROUNDS: u32 = 24;
const SCAN_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// J6-T3, the `voice_recording` job: fetches the call's recording, stores
/// it as a document on the call through the upload pipeline, attaches it
/// once the scan is clean and sends it to transcription. Resumable: each
/// step is kept on the `voice_call` row, so a retry starts where the last
/// run stopped. An error while the scan is still running makes the queue
/// try again later.
pub async fn attach_recording(state: &EngineState, call_id: Uuid) -> Result<(), AppError> {
    let row: RecordingRow = sqlx::query_as(
        "SELECT system_id, user_id, activity_id, recording_url, recording_document_id, \
                recording_session_id, recording_attached \
           FROM voice_call WHERE id = $1",
    )
    .bind(call_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let (Some(url), Some(activity)) = (row.recording_url.as_deref(), row.activity_id) else {
        return Ok(());
    };
    if row.recording_attached {
        return Ok(());
    }
    let system = attome_integration::system::load(&state.base.db, row.system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let actor = match row.user_id {
        Some(user) => user,
        None => attome_integration::system::service_principal_id(&system)?,
    };
    let ctx = state.base.security.resolve(actor).await?;

    let (document, session) = match (row.recording_document_id, row.recording_session_id) {
        (Some(document), Some(session)) => (document, session),
        _ => {
            let max = state.base.config.storage.max_upload_size_bytes;
            let (bytes, content_type, filename) =
                voice::fetch_recording(state, &system, url, max).await?;
            let document = match row.recording_document_id {
                Some(document) => document,
                None => {
                    let (document, _) = attome_records::entity_crud::create_record_for(
                        state,
                        &ctx,
                        actor,
                        "attome_document",
                        json!({
                            "name": filename,
                            "entity_name": "activity",
                            "record_id": activity.to_string(),
                        }),
                    )
                    .await?;
                    sqlx::query("UPDATE voice_call SET recording_document_id = $2, updated_at = now() WHERE id = $1")
                        .bind(call_id)
                        .bind(document)
                        .execute(&state.base.db)
                        .await
                        .map_err(AppError::internal)?;
                    document
                }
            };
            let session = attome_document::files::ingest(
                state,
                attome_document::files::FileOwner::Staff(actor),
                "attome_document",
                document,
                "file",
                filename,
                content_type,
                bytes,
            )
            .await?;
            sqlx::query(
                "UPDATE voice_call SET recording_session_id = $2, updated_at = now() WHERE id = $1",
            )
            .bind(call_id)
            .bind(session)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            (document, session)
        }
    };

    let mut clean_key = None;
    for _ in 0..SCAN_WAIT_ROUNDS {
        let status: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT status, final_key FROM upload_session WHERE id = $1")
                .bind(session)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        match status {
            Some((status, Some(key))) if status == "clean" => {
                clean_key = Some(key);
                break;
            }
            Some((status, _)) if status == "rejected" || status == "expired" => {
                sqlx::query("UPDATE voice_call SET recording_attached = true, updated_at = now() WHERE id = $1")
                    .bind(call_id)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                tracing::warn!(%call_id, %session, "voice: the recording did not pass the upload scan; not attached");
                return Ok(());
            }
            _ => tokio::time::sleep(SCAN_WAIT).await,
        }
    }
    let Some(final_key) = clean_key else {
        return Err(AppError::Conflict("the recording is still being scanned"));
    };
    let version: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM attome_document WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(document)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(version) = version else {
        return Ok(());
    };
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        actor,
        "attome_document",
        document,
        version,
        json!({ "file": final_key }),
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_document::transcribe::enqueue_in_tx(&mut tx, document).await?;
    sqlx::query(
        "UPDATE voice_call SET recording_attached = true, updated_at = now() WHERE id = $1",
    )
    .bind(call_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(%call_id, %document, "voice: recording attached and sent to transcription");
    Ok(())
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
    /// `phone` (the default: ring your own phone, then the number) or
    /// `browser` (J6-T2: the softphone dials, through the TwiML app, with
    /// the returned `call_id` as its `CallRef`).
    pub mode: Option<String>,
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
    let browser = match req.mode.as_deref().unwrap_or("phone") {
        "phone" => false,
        "browser" => true,
        _ => return Err(AppError::Validation("mode: phone or browser".into())),
    };
    let system = match req.system_id {
        Some(id) => attome_integration::system::load(&state.base.db, id)
            .await?
            .filter(|s| voice::provider(s).is_some()),
        None => voice::systems(&state).await?.into_iter().next(),
    }
    .ok_or(AppError::NotFound)?;
    let started = voice::start_call(
        &state,
        &ctx,
        &system,
        &req.to,
        None,
        (&req.entity_name, req.record_id),
        browser,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(PlacedCall {
            call_id: started.call_id,
            activity_id: started.activity_id,
        }),
    ))
}

// ── Staff: the softphone (J6-T2) ────────────────────────────────────────────

/// What the browser softphone needs.
#[derive(Debug, Serialize, ToSchema)]
pub struct SoftphoneConfig {
    /// Whether a browser softphone is set up (a Twilio system with an API
    /// key, a TwiML app and the SDK's address).
    pub available: bool,
    pub identity: Option<String>,
    /// A Voice SDK access token, valid for an hour.
    pub token: Option<String>,
    /// Where the provider's SDK is loaded from (an administrator's setting).
    pub sdk_url: Option<String>,
    pub expires_in: i64,
}

const SOFTPHONE_TTL_SECS: i64 = 3600;

/// The softphone's settings and an access token for the caller.
#[utoipa::path(
    get,
    path = "/api/v1/voice/softphone",
    tag = "omnichannel",
    responses(
        (status = 200, description = "Settings; `available` false when no softphone is set up", body = SoftphoneConfig),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_softphone(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<SoftphoneConfig>, AppError> {
    let none = SoftphoneConfig {
        available: false,
        identity: None,
        token: None,
        sdk_url: None,
        expires_in: 0,
    };
    if licensed(&state).is_err() || ctx.require("activity", "create").is_err() {
        return Ok(Json(none));
    }
    for system in voice::systems(&state).await? {
        if voice::provider(&system).as_deref() != Some("twilio") {
            continue;
        }
        let cfg = voice::config(&system);
        let (Some(account), Some(key), Some(app), Some(sdk)) = (
            voice::setting(&cfg, "account_sid"),
            voice::setting(&cfg, "api_key_sid"),
            voice::setting(&cfg, "twiml_app_sid"),
            voice::setting(&cfg, "sdk_url").filter(|u| u.starts_with("https://")),
        ) else {
            continue;
        };
        let secrets = twilio::Secrets::parse(&voice::credential(&state, &system).await?);
        let Some(key_secret) = secrets.api_key_secret else {
            continue;
        };
        let identity = twilio::client_identity(ctx.user_id);
        let token = twilio::access_token(
            account,
            key,
            &key_secret,
            app,
            &identity,
            Utc::now().timestamp(),
            SOFTPHONE_TTL_SECS,
        )
        .ok_or_else(|| AppError::internal("softphone token could not be signed"))?;
        return Ok(Json(SoftphoneConfig {
            available: true,
            identity: Some(identity),
            token: Some(token),
            sdk_url: Some(sdk.to_owned()),
            expires_in: SOFTPHONE_TTL_SECS,
        }));
    }
    Ok(Json(none))
}

/// A screen pop: the record a caller's number belongs to.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScreenPop {
    pub entity: String,
    pub id: Uuid,
    pub name: Option<String>,
}

/// The number to look up.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LookupQuery {
    /// E.164.
    pub number: String,
}

/// The contact, lead or account a number belongs to, when the caller may
/// see it.
#[utoipa::path(
    get,
    path = "/api/v1/voice/lookup",
    tag = "omnichannel",
    params(LookupQuery),
    responses(
        (status = 200, description = "The record", body = ScreenPop),
        (status = 404, description = "No record the caller may see has this number", body = ErrorResponse),
        (status = 422, description = "Not an E.164 number", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_lookup(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    axum::extract::Query(query): axum::extract::Query<LookupQuery>,
) -> Result<Json<ScreenPop>, AppError> {
    licensed(&state)?;
    let number = voice::e164(&query.number)
        .ok_or_else(|| AppError::Validation("number: an E.164 number".into()))?;
    let (entity, id) = crate::sms_inbound::find_sender(&state, &number)
        .await?
        .ok_or(AppError::NotFound)?;
    // Read as the caller: a record they may not see is not popped.
    let record = attome_records::entity_crud::read_record(&state, &ctx, &entity, id)
        .await
        .map_err(|_| AppError::NotFound)?;
    let primary = state
        .entities
        .load()
        .get(&entity)
        .and_then(|m| m.primary_name_attribute.clone());
    let name = primary.and_then(|p| {
        record
            .data()
            .get(&p)
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    Ok(Json(ScreenPop { entity, id, name }))
}

// ── Public: the providers' callbacks ────────────────────────────────────────

/// Twilio asks what to do with a call placed from the browser softphone:
/// dial the number of the call the softphone created (`CallRef`), never a
/// number the browser sends.
#[utoipa::path(
    post,
    path = "/api/v1/voice/twilio/{key}/client",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The voice system's inbound key")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "TwiML that dials the call's number", body = String, content_type = "text/xml"),
        (status = 404, description = "Not licensed, no system has this key, or not this agent's call", body = ErrorResponse),
    ),
)]
async fn post_twilio_client(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    licensed(&state)?;
    let system = voice::system_by_key(&state, &key)
        .await?
        .filter(|s| voice::provider(s).as_deref() == Some("twilio"))
        .ok_or(AppError::NotFound)?;
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |k: &str| {
        form.iter()
            .find(|(name, _)| name == k)
            .map(|(_, v)| v.clone())
    };
    let call_id = get("CallRef")
        .and_then(|r| Uuid::parse_str(&r).ok())
        .ok_or(AppError::NotFound)?;
    let call = load_call(&state, call_id).await?;
    let agent: Option<String> =
        sqlx::query_scalar("SELECT from_number FROM voice_call WHERE id = $1")
            .bind(call.id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    // Only the agent who created the call may place it, and only once.
    if call.system_id != system.id
        || agent.is_none()
        || agent != get("From")
        || call.state != "placing"
    {
        return Err(AppError::NotFound);
    }
    if let Some(sid) = get("CallSid") {
        sqlx::query("UPDATE voice_call SET provider_call_id = $2, updated_at = now() WHERE id = $1 AND provider_call_id IS NULL")
            .bind(call.id)
            .bind(sid)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    }
    let cfg = voice::config(&system);
    let chosen = caller_id_of(&state, call.id).await?;
    let (Some(number), Some(caller_id)) = (
        call.to_number.as_deref(),
        chosen.as_deref().or(voice::setting(&cfg, "from_number")),
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
    let chosen = caller_id_of(&state, call.id).await?;
    let (Some(number), Some(caller_id)) = (
        call.to_number.as_deref(),
        chosen.as_deref().or(voice::setting(&cfg, "from_number")),
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
    // J6-T2: `client:<identity>` rings a browser softphone instead.
    let forward = voice::setting(&cfg, "forward_to").and_then(|f| {
        if f.starts_with("client:user_") {
            Some(f.to_owned())
        } else {
            voice::e164(f)
        }
    });
    let Some(forward) = forward else {
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
        .route("/api/v1/voice/softphone", axum::routing::get(get_softphone))
        .route("/api/v1/voice/lookup", axum::routing::get(get_lookup))
        .route(
            "/api/v1/voice/twilio/{key}/client",
            post(post_twilio_client),
        )
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
    get_softphone,
    get_lookup,
    post_twiml,
    post_events,
    post_twilio_inbound,
    post_twilio_client,
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
