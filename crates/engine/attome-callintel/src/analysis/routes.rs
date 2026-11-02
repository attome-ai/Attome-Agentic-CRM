//! D22-T8: the call page and coaching as thin routes over
//! [`super::coach`] and the analysis records. Mounted only with the
//! `callintel` module on.
//!
//! - `GET /api/v1/callintel/calls/{activity_id}`: the call's latest analysis,
//!   its findings, scorecard answers and redacted transcript; the talk patterns only for the
//!   call's owner and their managers. The caller must be able to read the
//!   call (`activity`) itself.
//! - `GET /api/v1/callintel/calls/{activity_id}/recording`: a short-lived
//!   download URL of the call's recording (the J6 `attome_document` file),
//!   and one audit event (an export: the recording leaves the system) per
//!   playback.
//! - `POST /api/v1/callintel/findings/{id}/task`,
//!   `POST /api/v1/callintel/scorecard-answers/{id}/confirm`,
//!   `POST /api/v1/callintel/calls/{activity_id}/comments`: the coaching
//!   functions, each checking who may.

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// `call_analysis.read`: who opens a call page.
#[derive(Debug)]
pub struct CallAnalysisRead;

impl PrivilegeKey for CallAnalysisRead {
    const KEY: &'static str = "call_analysis.read";
}

/// A call page.
#[derive(Debug, Serialize, ToSchema)]
pub struct CallPage {
    pub activity_id: Uuid,
    pub analysis_id: Uuid,
    pub status: Option<String>,
    /// Only for the call's owner and their managers.
    #[schema(value_type = Option<Object>)]
    pub talk: Option<Value>,
    #[schema(value_type = Vec<Object>)]
    pub findings: Vec<Value>,
    #[schema(value_type = Vec<Object>)]
    pub scorecard: Vec<Value>,
    /// D22-T12: the redacted transcript, `[{start_ms, end_ms, speaker, text}]`.
    #[schema(value_type = Vec<Object>)]
    pub transcript: Vec<Value>,
}

type AnalysisRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// The latest analysis of `activity`, after checking the caller reads it.
async fn analysis_of(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    activity: Uuid,
) -> Result<AnalysisRow, AppError> {
    attome_records::entity_crud::read_record(state, ctx, "activity", activity).await?;
    sqlx::query_as(
        "SELECT id, status::text, owner_user, staff_talk_share::float8, \
                longest_monologue_s::float8, customer_longest_story_s::float8, \
                interruptions::float8, staff_questions::float8, customer_questions::float8, \
                staff_words_per_minute::float8 \
           FROM call_analysis WHERE activity_id = $1 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(activity.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// A call's analysis
///
/// D22-T8: the latest analysis of a call with its findings and scorecard answers; talk patterns only
/// for the call's owner and their managers.
#[utoipa::path(
    get,
    path = "/api/v1/callintel/calls/{activity_id}",
    tag = "callintel",
    params(("activity_id" = Uuid, Path, description = "The call (activity)")),
    responses(
        (status = 200, description = "The call page", body = CallPage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks call_analysis.read or cannot read the call", body = ErrorResponse),
        (status = 404, description = "No such call, or not analysed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn call_page(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallAnalysisRead>>,
    Path(activity): Path<Uuid>,
) -> Result<Json<CallPage>, AppError> {
    let (id, status, owner, share, monologue, story, interruptions, staff_q, customer_q, wpm) =
        analysis_of(&state, &ctx, activity).await?;
    let sees_talk = match owner {
        Some(owner) => {
            owner == ctx.user_id || super::coach::is_manager_of(&state, ctx.user_id, owner).await?
        }
        None => false,
    };
    let talk = sees_talk.then(|| {
        json!({
            "staff_talk_share": share, "longest_monologue_s": monologue,
            "customer_longest_story_s": story, "interruptions": interruptions,
            "staff_questions": staff_q, "customer_questions": customer_q,
            "staff_words_per_minute": wpm,
        })
    });
    let findings: Vec<(
        Uuid,
        Option<String>,
        Option<String>,
        Option<f64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, kind::text, text, start_ms::float8, task_ref FROM call_finding \
              WHERE analysis_ref = $1 AND (is_active IS NULL OR is_active = true) \
              ORDER BY start_ms NULLS LAST, id",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let answers: Vec<(Uuid, Option<String>, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, question_key, proposed_value::text, confirmed_value::text, row_version \
               FROM call_scorecard_answer \
              WHERE analysis_ref = $1 AND (is_active IS NULL OR is_active = true) \
              ORDER BY question_key, id",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let transcript: Option<Value> =
        sqlx::query_scalar("SELECT segments FROM call_transcript_redacted WHERE analysis_id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let transcript = match transcript {
        Some(Value::Array(segments)) => segments,
        _ => Vec::new(),
    };
    Ok(Json(CallPage {
        transcript,
        activity_id: activity,
        analysis_id: id,
        status,
        talk,
        findings: findings
            .into_iter()
            .map(|(id, kind, text, at, task)| {
                json!({ "id": id, "kind": kind, "text": text, "start_ms": at, "task_ref": task })
            })
            .collect(),
        scorecard: answers
            .into_iter()
            .map(|(id, key, proposed, confirmed, version)| {
                json!({ "id": id, "question_key": key, "proposed_value": proposed,
                        "confirmed_value": confirmed, "row_version": version })
            })
            .collect(),
    }))
}

/// One analysis about the caller's own call.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct MyAnalysis {
    pub analysis_id: Uuid,
    pub activity_id: Option<String>,
    pub status: Option<String>,
    pub analysed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub staff_talk_share: Option<f64>,
    pub staff_questions: Option<f64>,
}

/// The analyses about my calls
///
/// D22-T13: every analysis whose call the caller owns, newest first: staff see all that is analysed
/// about them. No analysis carries a sentiment for staff.
#[utoipa::path(
    get,
    path = "/api/v1/callintel/my-analyses",
    tag = "callintel",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The caller's analyses", body = PaginatedResponse<MyAnalysis>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn my_analyses(
    State(state): State<EngineState>,
    ctx: Authorized<attome_server::authz::SelfService>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<MyAnalysis>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
        ..
    } = paging.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM call_analysis WHERE owner_user = $1 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<MyAnalysis> = sqlx::query_as(
        "SELECT id AS analysis_id, activity_id, status::text AS status, analysed_at, \
                staff_talk_share::float8 AS staff_talk_share, \
                staff_questions::float8 AS staff_questions \
           FROM call_analysis WHERE owner_user = $1 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(ctx.user_id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// A recording to play.
#[derive(Debug, Serialize, ToSchema)]
pub struct Recording {
    pub download_url: String,
    pub expires_in_secs: u64,
}

/// Play a call's recording
///
/// D22-T8: a short-lived URL of the call's recording; each playback is audited.
#[utoipa::path(
    get,
    path = "/api/v1/callintel/calls/{activity_id}/recording",
    tag = "callintel",
    params(("activity_id" = Uuid, Path, description = "The call (activity)")),
    responses(
        (status = 200, description = "Where to play it", body = Recording),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks call_analysis.read or cannot read the call or recording", body = ErrorResponse),
        (status = 404, description = "No such call, or no recording", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn recording(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallAnalysisRead>>,
    Path(activity): Path<Uuid>,
) -> Result<Json<Recording>, AppError> {
    attome_records::entity_crud::read_record(&state, &ctx, "activity", activity).await?;
    let document: Uuid = sqlx::query_scalar(
        "SELECT id FROM attome_document WHERE entity_name = 'activity' AND record_id = $1 \
           AND file IS NOT NULL AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(activity.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let record =
        attome_records::entity_crud::read_record(&state, &ctx, "attome_document", document).await?;
    let key = record
        .data()
        .get("file")
        .and_then(Value::as_str)
        .ok_or(AppError::NotFound)?
        .to_owned();
    let url = attome_document::files::record_file_download(
        &state,
        "attome_document",
        document,
        "file",
        &key,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "activity",
            activity,
            AuditOperation::Export,
            "callintel.recording_played",
            ctx.user_id,
        )
        .comment(format!("recording {document} played")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(Recording {
        download_url: url.download_url,
        expires_in_secs: url.expires_in_secs,
    }))
}

/// A task made from a finding.
#[derive(Debug, Serialize, ToSchema)]
pub struct TaskMade {
    pub task_id: Uuid,
}

/// Make a task from a finding
///
/// D22-T8: a next step (or any finding) as a task for the call's owner, made once.
#[utoipa::path(
    post,
    path = "/api/v1/callintel/findings/{id}/task",
    tag = "callintel",
    params(("id" = Uuid, Path, description = "The finding")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The task", body = TaskMade),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks call_analysis.read or activity.create", body = ErrorResponse),
        (status = 404, description = "No such finding", body = ErrorResponse),
        (status = 409, description = "A task is being made from it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn finding_task(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallAnalysisRead>>,
    Path(finding): Path<Uuid>,
) -> Result<Json<TaskMade>, AppError> {
    let task_id = super::coach::create_task_from_finding(&state, &ctx, finding).await?;
    Ok(Json(TaskMade { task_id }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConfirmBody {
    /// `yes`, `no` or `unclear`.
    pub value: String,
    /// The answer's `row_version` as read.
    pub row_version: i64,
}

/// Confirm a scorecard answer
///
/// D22-T8: a manager of the call's owner confirms an answer.
#[utoipa::path(
    post,
    path = "/api/v1/callintel/scorecard-answers/{id}/confirm",
    operation_id = "confirm_scorecard_answer",
    tag = "callintel",
    params(("id" = Uuid, Path, description = "The scorecard answer")),
    request_body = ConfirmBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Confirmed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a manager of the call's owner", body = ErrorResponse),
        (status = 404, description = "No such answer", body = ErrorResponse),
        (status = 409, description = "The answer changed since it was read", body = ErrorResponse),
        (status = 422, description = "Not yes, no or unclear", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn confirm(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallAnalysisRead>>,
    Path(answer): Path<Uuid>,
    Json(body): Json<ConfirmBody>,
) -> Result<axum::http::StatusCode, AppError> {
    super::coach::confirm_answer(&state, &ctx, answer, &body.value, body.row_version).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "call_scorecard_answer",
            answer,
            AuditOperation::Update,
            "callintel.answer_confirmed",
            ctx.user_id,
        )
        .comment(format!("confirmed {}", body.value)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommentBody {
    /// The moment of the call, in milliseconds.
    pub at_ms: i64,
    pub body: String,
    pub parent_id: Option<Uuid>,
}

/// A comment made.
#[derive(Debug, Serialize, ToSchema)]
pub struct CommentMade {
    pub comment_id: Uuid,
}

/// Comment on a call
///
/// D22-T8: the owner, their managers or a peer holding call_comment.create comments at a moment of
/// the call; the owner is notified.
#[utoipa::path(
    post,
    path = "/api/v1/callintel/calls/{activity_id}/comments",
    tag = "callintel",
    params(("activity_id" = Uuid, Path, description = "The call (activity)")),
    request_body = CommentBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The comment", body = CommentMade),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not allowed to comment on this call", body = ErrorResponse),
        (status = 404, description = "No such call, or not analysed", body = ErrorResponse),
        (status = 422, description = "An empty or too long comment", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn comment(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallAnalysisRead>>,
    Path(activity): Path<Uuid>,
    Json(body): Json<CommentBody>,
) -> Result<Json<CommentMade>, AppError> {
    let (analysis, ..) = analysis_of(&state, &ctx, activity).await?;
    let comment_id = super::coach::add_comment(
        &state,
        &ctx,
        analysis,
        body.at_ms,
        &body.body,
        body.parent_id,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "call_comment",
            comment_id,
            AuditOperation::Create,
            "callintel.comment_added",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(CommentMade { comment_id }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/callintel/calls/{activity_id}", get(call_page))
        .route(
            "/api/v1/callintel/calls/{activity_id}/recording",
            get(recording),
        )
        .route(
            "/api/v1/callintel/calls/{activity_id}/comments",
            post(comment),
        )
        .route("/api/v1/callintel/findings/{id}/task", post(finding_task))
        .route("/api/v1/callintel/my-analyses", get(my_analyses))
        .route(
            "/api/v1/callintel/scorecard-answers/{id}/confirm",
            post(confirm),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(call_page, recording, finding_task, confirm, comment, my_analyses),
    components(schemas(
        CallPage,
        Recording,
        TaskMade,
        ConfirmBody,
        CommentBody,
        CommentMade,
        MyAnalysis
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
