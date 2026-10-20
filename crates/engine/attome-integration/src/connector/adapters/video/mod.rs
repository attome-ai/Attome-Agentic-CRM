//! J7-T1: online meetings on Teams, Google Meet, Zoom and a self-hosted
//! Jitsi.
//!
//! Each provider is a pure codec (the request body, the meeting it answers,
//! its attendance and recordings), tested with recorded answers; the calls
//! are made here with the right token:
//! - **Teams** and **Google Meet** act for the signed-in person, with their
//!   own connection (D15-T1, [`super::user_mail_sync::access_token`]).
//! - **Zoom** uses the deployment's server-to-server app: an
//!   `integration_system` row with `"video": "zoom"`, `account_id` and
//!   `client_id`, the client secret as its credential.
//! - **Jitsi** needs no account: `"video": "jitsi"` and `domain`; with an
//!   `app_id` and the app secret as credential, rooms carry a signed token.
//!
//! Attendance and recordings are read after the meeting where the provider
//! offers them (Teams attendance reports and recordings, Meet conference
//! records, Zoom reports and cloud recordings); Jitsi offers neither.

pub mod google_meet;
pub mod jitsi;
pub mod teams;
pub mod zoom;

use std::sync::OnceLock;
use std::time::Duration;

use attome_audit::security::{ExemptReason, x_audit_exempt};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::user_mail_sync::{Provider as MailProvider, access_token};

const TIMEOUT: Duration = Duration::from_secs(15);

/// What to create.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct MeetingRequest {
    /// `teams`, `meet`, `zoom` or `jitsi`.
    pub provider: String,
    pub subject: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// A created meeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Meeting {
    pub provider: String,
    /// The provider's id for it.
    pub id: String,
    pub join_url: String,
}

/// One person's time in a meeting.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Attendee {
    pub name: Option<String>,
    pub email: Option<String>,
    /// Seconds present.
    pub seconds: i64,
}

/// A meeting's recording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Recording {
    pub url: String,
    pub kind: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeetingReport {
    pub attendance: Vec<Attendee>,
    pub recordings: Vec<Recording>,
}

pub(crate) fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(
            attome_outbound::http::Purpose::public("video-meetings"),
            |b| b.timeout(TIMEOUT),
        )
    })
}

/// A provider answer as (status, body).
pub(crate) async fn answer(request: reqwest::RequestBuilder) -> Result<(u16, String), AppError> {
    let res = request.send().await.map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

pub(crate) fn refused(provider: &str, status: u16) -> AppError {
    AppError::Validation(format!("{provider} refused the request ({status})"))
}

/// A deployment-level video app (`"video": kind`): its config and secret.
pub(crate) async fn video_app(
    state: &EngineState,
    kind: &str,
) -> Result<Option<(Value, Option<String>)>, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'video' END = $1 \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(kind)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((config, credential_ref)) = row else {
        return Ok(None);
    };
    let secret = crate::credential::resolve(
        &state.base.db,
        &state.base.config.integration.credential_encryption_key,
        credential_ref.as_deref(),
    )
    .await?;
    Ok(Some((
        config
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or(Value::Null),
        secret,
    )))
}

async fn person_token(
    state: &EngineState,
    user: Uuid,
    provider: MailProvider,
) -> Result<String, AppError> {
    access_token(state, user, provider).await?.ok_or_else(|| {
        AppError::Validation(format!("connect your {} account first", provider.as_str()))
    })
}

/// Creates a meeting for `user` on the provider asked for.
pub async fn create(
    state: &EngineState,
    user: Uuid,
    req: &MeetingRequest,
) -> Result<Meeting, AppError> {
    if req.end <= req.start {
        return Err(AppError::Validation("end: after start".into()));
    }
    let subject = req.subject.trim();
    if subject.is_empty() || subject.chars().count() > 255 {
        return Err(AppError::Validation("subject: 1 to 255 characters".into()));
    }
    match req.provider.as_str() {
        "teams" => {
            let token = person_token(state, user, MailProvider::Microsoft).await?;
            let (status, body) = answer(
                client()
                    .post(teams::CREATE_URL)
                    .bearer_auth(token)
                    .json(&teams::create_body(subject, req.start, req.end)),
            )
            .await?;
            teams::parse_meeting(status, &body).ok_or_else(|| refused("Teams", status))
        }
        "meet" => {
            let token = person_token(state, user, MailProvider::Google).await?;
            let (status, body) = answer(
                client()
                    .post(google_meet::CREATE_URL)
                    .bearer_auth(token)
                    .json(&google_meet::create_body(
                        subject,
                        req.start,
                        req.end,
                        Uuid::now_v7(),
                    )),
            )
            .await?;
            google_meet::parse_meeting(status, &body).ok_or_else(|| refused("Google", status))
        }
        "zoom" => {
            let token = zoom::app_token(state).await?;
            let (status, body) = answer(
                client()
                    .post(zoom::CREATE_URL)
                    .bearer_auth(token)
                    .json(&zoom::create_body(subject, req.start, req.end)),
            )
            .await?;
            zoom::parse_meeting(status, &body).ok_or_else(|| refused("Zoom", status))
        }
        "jitsi" => jitsi::create(state, subject, req.start, req.end).await,
        _ => Err(AppError::Validation(
            "provider: teams, meet, zoom or jitsi".into(),
        )),
    }
}

/// Attendance and recordings, where the provider offers them.
pub async fn report(
    state: &EngineState,
    user: Uuid,
    provider: &str,
    id: &str,
) -> Result<MeetingReport, AppError> {
    match provider {
        "teams" => {
            let token = person_token(state, user, MailProvider::Microsoft).await?;
            let (_, attendance) =
                answer(client().get(teams::attendance_url(id)).bearer_auth(&token)).await?;
            let (_, recordings) =
                answer(client().get(teams::recordings_url(id)).bearer_auth(&token)).await?;
            Ok(MeetingReport {
                attendance: teams::parse_attendance(&attendance),
                recordings: teams::parse_recordings(&recordings),
            })
        }
        "meet" => {
            let token = person_token(state, user, MailProvider::Google).await?;
            let (_, participants) = answer(
                client()
                    .get(google_meet::participants_url(id))
                    .bearer_auth(&token),
            )
            .await?;
            let (_, recordings) = answer(
                client()
                    .get(google_meet::recordings_url(id))
                    .bearer_auth(&token),
            )
            .await?;
            Ok(MeetingReport {
                attendance: google_meet::parse_attendance(&participants),
                recordings: google_meet::parse_recordings(&recordings),
            })
        }
        "zoom" => {
            let token = zoom::app_token(state).await?;
            let (_, participants) =
                answer(client().get(zoom::participants_url(id)).bearer_auth(&token)).await?;
            let (_, recordings) =
                answer(client().get(zoom::recordings_url(id)).bearer_auth(&token)).await?;
            Ok(MeetingReport {
                attendance: zoom::parse_attendance(&participants),
                recordings: zoom::parse_recordings(&recordings),
            })
        }
        "jitsi" => Ok(MeetingReport {
            attendance: Vec::new(),
            recordings: Vec::new(),
        }),
        _ => Err(AppError::NotFound),
    }
}

/// J7-T1: creates an online meeting with its join link.
#[utoipa::path(
    post,
    path = "/api/v1/me/meetings",
    tag = "integration",
    request_body = MeetingRequest,
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::Delegated,
        None,
        "creates the meeting at the provider; nothing is stored in Attome until the caller saves it on a record"
    )))),
    responses(
        (status = 200, description = "The meeting and its link", body = Meeting),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "The provider is not configured", body = ErrorResponse),
        (status = 422, description = "Bad times or subject, no connected account, or the provider refused", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_meeting(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<MeetingRequest>,
) -> Result<Json<Meeting>, AppError> {
    Ok(Json(create(&state, ctx.user_id, &body).await?))
}

/// J7-T1: who attended and the recordings, after the meeting.
#[utoipa::path(
    get,
    path = "/api/v1/me/meetings/{provider}/{id}/report",
    operation_id = "get_meeting_report",
    tag = "integration",
    params(("provider" = String, Path), ("id" = String, Path)),
    responses(
        (status = 200, description = "Attendance and recordings", body = MeetingReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Unknown provider or not configured", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_report(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((provider, id)): Path<(String, String)>,
) -> Result<Json<MeetingReport>, AppError> {
    Ok(Json(report(&state, ctx.user_id, &provider, &id).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/me/meetings", post(post_meeting))
        .route(
            "/api/v1/me/meetings/{provider}/{id}/report",
            get(get_report),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_meeting, get_report))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
