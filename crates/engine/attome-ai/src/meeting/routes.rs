//! AI6-T6: meeting routes.
//!
//! - `GET /api/v1/ai/meetings/{id}/brief` — the meeting's brief, for anyone
//!   who may read the meeting;
//! - `POST /api/v1/ai/meetings/{id}/brief/regenerate` — runs `meeting.brief`
//!   now, as the caller;
//! - `POST /api/v1/ai/meetings/{id}/notes` — queues `meeting.notes` for a
//!   transcript (202);
//! - `POST /api/v1/ai/meetings/{id}/notes/confirm` — runs
//!   `meeting.confirm_notes` under `If-Match`.
//!
//! The POSTs invoke actions through `dispatch` as the calling human, exactly
//! as `POST /api/v1/actions/{id}/invoke` does, so the gate, the licence, the
//! AI switch and the budget apply, and whatever the action writes is
//! audited by the record engine it writes through.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use super::brief::{MEETING_BRIEF, MEETING_ENTITY};
use crate::context::ActionContext;
use crate::execute::{ActionOutcome, dispatch};

/// A meeting's brief.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeetingBriefView {
    pub id: Uuid,
    pub meeting_id: Uuid,
    /// `ready` or `failed`.
    pub status: Option<String>,
    /// `ar` or `en`.
    pub language: Option<String>,
    pub brief_text: Option<String>,
    pub generated_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// Asks for notes from a transcript.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MeetingNotesRequest {
    /// The recording document whose transcript is read.
    pub transcript_ref: Uuid,
}

/// The notes job, as queued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MeetingNotesQueued {
    pub meeting_id: Uuid,
    pub transcript_ref: Uuid,
    /// The job's queue key; one job per meeting, transcript and caller is
    /// queued at a time.
    pub job_key: String,
    /// False when the same job was already waiting.
    pub queued: bool,
}

/// Which items of the notes to keep.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MeetingNotesConfirm {
    /// The notes to confirm; omitted, the meeting's newest draft.
    #[serde(default)]
    pub notes_id: Option<Uuid>,
    #[serde(default)]
    pub action_item_indexes: Vec<usize>,
    #[serde(default)]
    pub record_update_indexes: Vec<usize>,
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to confirm notes".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// The meeting's brief, after the caller's read of the meeting.
pub async fn brief_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    meeting_id: Uuid,
) -> Result<MeetingBriefView, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, MEETING_ENTITY, meeting_id).await?;
    let row: Option<BriefRow> = sqlx::query_as(
        "SELECT id, status::text, language::text, brief_text, generated_at::timestamptz, \
                row_version::bigint \
           FROM ai_meeting_brief \
          WHERE meeting_entity = $1 AND meeting_id = $2 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(MEETING_ENTITY)
    .bind(meeting_id.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (id, status, language, brief_text, generated_at, row_version) =
        row.ok_or(AppError::NotFound)?;
    Ok(MeetingBriefView {
        id,
        meeting_id,
        status,
        language,
        brief_text,
        generated_at,
        row_version,
    })
}

/// `(id, status, language, text, generated at, row_version)`.
type BriefRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    i64,
);

/// Runs `action` through the gate as the calling human.
async fn invoke(
    state: &EngineState,
    ctx: Authorized<SelfService>,
    action: &str,
    args: &Value,
) -> Result<ActionOutcome, AppError> {
    let module = crate::engine::REGISTRY
        .resolve(action)
        .map(|d| d.module)
        .ok_or(AppError::NotFound)?;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, module);
    let action_ctx = ActionContext::user(ctx.into_inner());
    dispatch(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        action,
        &action_ctx,
        &inputs,
        args,
    )
    .await
}

/// The meeting's newest draft notes.
async fn newest_draft(state: &EngineState, meeting_id: Uuid) -> Result<Uuid, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ai_meeting_notes \
          WHERE meeting_entity = $1 AND meeting_id = $2 AND status::text = 'draft' \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(MEETING_ENTITY)
    .bind(meeting_id.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    id.ok_or(AppError::NotFound)
}

#[utoipa::path(
    get,
    path = "/api/v1/ai/meetings/{id}/brief",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The meeting activity")),
    responses(
        (status = 200, description = "The meeting's brief", body = MeetingBriefView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such meeting the caller may read, or no brief yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_meeting_brief(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(meeting_id): Path<Uuid>,
) -> Result<Json<MeetingBriefView>, AppError> {
    Ok(Json(brief_for(&state, &ctx, meeting_id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/meetings/{id}/brief/regenerate",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The meeting activity")),
    responses(
        (status = 200, description = "The action's outcome: the new brief, or why it waits", body = ActionOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such meeting the caller may read, or AI is off", body = ErrorResponse),
        (status = 422, description = "The activity is not a meeting", body = ErrorResponse),
        (status = 429, description = "The AI budget is spent", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("dispatch -> meeting.brief"),
        "invoked as the calling human like POST /api/v1/actions/{id}/invoke; the brief row \
         is written through entity_crud, which audits it",
    )))),
)]
async fn regenerate_meeting_brief(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(meeting_id): Path<Uuid>,
) -> Result<Json<ActionOutcome>, AppError> {
    let args = json!({ "meeting_id": meeting_id });
    Ok(Json(invoke(&state, ctx, MEETING_BRIEF, &args).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/meetings/{id}/notes",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The meeting activity")),
    request_body = MeetingNotesRequest,
    responses(
        (status = 202, description = "The notes are being made", body = MeetingNotesQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such meeting or recording the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("ai_meeting_notes job -> meeting.notes"),
        "only queues a job; the job invokes meeting.notes as the caller and writes the \
         notes through entity_crud, which audits them",
    )))),
)]
async fn post_meeting_notes(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(meeting_id): Path<Uuid>,
    Json(body): Json<MeetingNotesRequest>,
) -> Result<(StatusCode, Json<MeetingNotesQueued>), AppError> {
    // Both reads fail fast here rather than in the job.
    attome_records::entity_crud::read_record_bulk(&state, &ctx, MEETING_ENTITY, meeting_id).await?;
    attome_records::entity_crud::read_record_bulk(
        &state,
        &ctx,
        "attome_document",
        body.transcript_ref,
    )
    .await?;
    let job = super::run::NotesJob {
        meeting_id,
        transcript_ref: body.transcript_ref,
        user_id: ctx.user_id,
    };
    let (job_key, queued) = super::run::queue_notes(&state, &job).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(MeetingNotesQueued {
            meeting_id,
            transcript_ref: body.transcript_ref,
            job_key,
            queued,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/meetings/{id}/notes/confirm",
    tag = "ai",
    params(
        ("id" = Uuid, Path, description = "The meeting activity"),
        ("If-Match" = String, Header, description = "The notes' row_version, quoted"),
    ),
    request_body = MeetingNotesConfirm,
    responses(
        (status = 200, description = "The action's outcome: tasks made and updates proposed", body = ActionOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such notes the caller may read", body = ErrorResponse),
        (status = 409, description = "Already confirmed, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed, or an item that does not exist", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("dispatch -> meeting.confirm_notes"),
        "invoked as the calling human; the notes, the tasks and every record update are \
         written through entity_crud or record.update_field, which audit them",
    )))),
)]
async fn confirm_meeting_notes(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(meeting_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<MeetingNotesConfirm>,
) -> Result<Json<ActionOutcome>, AppError> {
    let row_version = if_match(&headers)?;
    let notes_id = match body.notes_id {
        Some(id) => id,
        None => newest_draft(&state, meeting_id).await?,
    };
    let args = json!({
        "notes_id": notes_id,
        "row_version": row_version,
        "action_item_indexes": body.action_item_indexes,
        "record_update_indexes": body.record_update_indexes,
    });
    Ok(Json(
        invoke(
            &state,
            ctx,
            crate::actions::meeting::MEETING_CONFIRM_NOTES,
            &args,
        )
        .await?,
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ai/meetings/{id}/brief", get(get_meeting_brief))
        .route(
            "/api/v1/ai/meetings/{id}/brief/regenerate",
            post(regenerate_meeting_brief),
        )
        .route("/api/v1/ai/meetings/{id}/notes", post(post_meeting_notes))
        .route(
            "/api/v1/ai/meetings/{id}/notes/confirm",
            post(confirm_meeting_notes),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_meeting_brief,
        regenerate_meeting_brief,
        post_meeting_notes,
        confirm_meeting_notes
    ),
    components(schemas(
        MeetingBriefView,
        MeetingNotesRequest,
        MeetingNotesQueued,
        MeetingNotesConfirm
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn confirm_reads_the_row_version_from_if_match() {
        let mut headers = HeaderMap::new();
        assert!(if_match(&headers).is_err(), "missing is refused");
        headers.insert(IF_MATCH, HeaderValue::from_static("\"7\""));
        assert_eq!(if_match(&headers).expect("a version"), 7);
        headers.insert(IF_MATCH, HeaderValue::from_static("seven"));
        assert!(if_match(&headers).is_err(), "malformed is refused");
    }
}
