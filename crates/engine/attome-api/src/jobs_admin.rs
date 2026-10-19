//! P-job-queue-hardening (D-165) — dead-letter visibility and replay for the
//! apalis job system's `Killed` (attempts-exhausted) rows. A dedicated route
//! (guidelines §9: this isn't CRUD on a registered entity), gated on
//! `system.admin` the same way `s2s_admin`/`license_admin`/`rewrap_admin`
//! are.
//!
//! The list endpoint deliberately never returns the raw `apalis.jobs.job`
//! payload — `EngineJob::SendEmail` carries the actual email body, which
//! for password-reset/verification mail includes a live token URL. Only the
//! externally-tagged variant name is surfaced.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
struct DeadLetterQuery {
    /// `"fast"` (default) or `"batch"` — see `EngineJob::is_batch`.
    queue: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

fn parse_queue(queue: Option<&str>) -> Result<bool, AppError> {
    match queue.unwrap_or("fast") {
        "fast" => Ok(false),
        "batch" => Ok(true),
        other => Err(AppError::Validation(format!(
            "queue must be \"fast\" or \"batch\", got {other:?}"
        ))),
    }
}

#[derive(Serialize, ToSchema)]
struct DeadLetterJobSummary {
    id: String,
    /// The externally-tagged `EngineJob` variant name (e.g.
    /// `"BulkEntityOperation"`) — never the payload itself.
    variant: String,
    attempts: i32,
    max_attempts: i32,
    last_error: Option<String>,
    run_at: DateTime<Utc>,
    done_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/jobs/dead-letter",
    tag = "admin",
    params(DeadLetterQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DeadLetterJobSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_dead_letter(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<DeadLetterQuery>,
) -> Result<Json<PaginatedResponse<DeadLetterJobSummary>>, AppError> {
    let batch = parse_queue(query.queue.as_deref())?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let rows = attome_jobs::list_dead_letter_jobs(&state.base.db, batch, offset, page_size)
        .await
        .map_err(AppError::internal)?;
    let total = attome_jobs::dead_letter_count(&state.base.db, batch)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|row| DeadLetterJobSummary {
            variant: attome_jobs::job_variant_tag(&row.job)
                .unwrap_or("unknown")
                .to_string(),
            id: row.id,
            attempts: row.attempts,
            max_attempts: row.max_attempts,
            last_error: row.last_error,
            run_at: row.run_at,
            done_at: row.done_at,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Serialize, ToSchema)]
struct ReplayResult {
    replayed: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/jobs/{id}/replay",
    tag = "admin",
    params(("id" = String, Path)),
    responses(
        (status = 200, description = "Success", body = ReplayResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Not dead-lettered, or a live job already holds its dedup key (the live row is named in the log and the audit event)", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Execute)])))),
)]
async fn replay(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ReplayResult>), AppError> {
    // BJB-6b: the checked form says *why* nothing was replayed. The bare bool
    // collapsed "already replayed" and "a live row holds the dedup slot" into
    // one Conflict, and the collision reached the operator as a masked 500
    // before BJB-6a — the index error was the only signal.
    match attome_jobs::replay_dead_letter_job_checked(&state.base.db, &id)
        .await
        .map_err(AppError::internal)?
    {
        attome_jobs::ReplayOutcome::Replayed => {}
        attome_jobs::ReplayOutcome::NotDeadLettered => {
            return Err(AppError::Conflict("job is not in a dead-letter state"));
        }
        attome_jobs::ReplayOutcome::DedupSlotTaken { live_id } => {
            // AppError::Conflict carries a `&'static str`, so the live row's id
            // cannot ride in the body without a public enum change; it goes to
            // the log instead (and the audit event below stays the durable
            // record). The status and the reason are what the operator needs to
            // act; the id is what they need to look up.
            tracing::warn!(
                dead_letter_id = %id,
                live_id = %live_id,
                "job replay refused: a live job already holds this job's dedup key"
            );
            return Err(AppError::Conflict(
                "a live job already holds this job's dedup key; wait for it to finish, or discard \
                 this dead letter instead of replaying it",
            ));
        }
    }
    // attome-jobs cannot depend on attome-audit (layering, coding-guidelines §1), so
    // this writes after the base-layer commit rather than inside its transaction
    // — the same documented D-062 deviation Phase 3 item 3.3 uses for attome-auth.
    attome_audit::security::SecurityAuditor::from_state(&state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::Execute,
                ctx.user_id,
                "base_jobs_dead_letter",
                None,
            )
            .named("job.replay"),
        )
        .await?;
    Ok((StatusCode::OK, Json(ReplayResult { replayed: true })))
}

/// BJB-6c — discards one dead letter: the row is deleted while it is still
/// `Killed`, so an operator can clear something that will never be replayed
/// instead of letting the retention sweep delete it untriaged (BJB-F9).
///
/// `HardDelete` under `Configuration` is the honest audit category: the row is
/// gone, not archived, and the event below is the only durable record that it
/// existed. A row that is not a dead letter is a 409 — the same status the
/// replay path answers for that condition, so a caller sees one vocabulary.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/jobs/{id}",
    tag = "admin",
    params(("id" = String, Path)),
    responses(
        (status = 204, description = "The dead letter was deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The row is not a dead letter (already replayed, discarded, or still live)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::HardDelete)])))),
)]
async fn discard(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let Some(discarded) = attome_jobs::discard_dead_letter_job(&state.base.db, &id)
        .await
        .map_err(AppError::internal)?
    else {
        return Err(AppError::Conflict("job is not in a dead-letter state"));
    };
    // Same layering note as the replay handler: attome-jobs cannot depend on
    // attome-audit, so the event is written after the base-layer commit (D-062).
    // The apalis id is not a UUID, so it rides in the comment, not record_id.
    attome_audit::security::SecurityAuditor::from_state(&state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::HardDelete,
                ctx.user_id,
                "base_jobs_dead_letter",
                None,
            )
            .named("job.discard")
            .comment(format!(
                "id={} queue={} variant={}",
                discarded.id,
                discarded.queue,
                discarded.variant.as_deref().unwrap_or("unknown")
            )),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Z7-T4: a chunked batch job's progress, as `GET /api/v1/jobs/{id}` shows it.
#[derive(Serialize, ToSchema)]
struct BatchJobProgress {
    id: Uuid,
    name: String,
    /// `running`, `finished` or `cancelled`.
    status: String,
    /// Items done so far.
    done: i64,
    /// Items in all, when the job knows.
    total: Option<i64>,
    cancel_requested: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

/// The batch, if the caller may see it: the person who started it or an
/// administrator. Anyone else gets not-found, as for a record.
async fn visible_batch(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    id: Uuid,
) -> Result<attome_jobs::batch::BatchProgress, AppError> {
    let batch = attome_jobs::batch::progress(&state.base.db, id)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    if ctx.is_admin || batch.started_by == Some(ctx.user_id) {
        Ok(batch)
    } else {
        Err(AppError::NotFound)
    }
}

fn batch_body(batch: attome_jobs::batch::BatchProgress) -> BatchJobProgress {
    BatchJobProgress {
        id: batch.id,
        name: batch.name,
        status: batch.status.as_str().to_owned(),
        done: batch.done,
        total: batch.total,
        cancel_requested: batch.cancel_requested,
        created_at: batch.created_at,
        updated_at: batch.updated_at,
        finished_at: batch.finished_at,
    }
}

/// Z7-T4: a chunked batch job's progress, for the person who started it or
/// an administrator.
#[utoipa::path(
    get,
    path = "/api/v1/jobs/{id}",
    tag = "jobs",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The batch job's status and progress", body = BatchJobProgress),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such batch job, or not one the caller started", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn batch_progress(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<BatchJobProgress>, AppError> {
    Ok(Json(batch_body(visible_batch(&state, &ctx, id).await?)))
}

/// Z7-T4: asks a running batch job to stop after its current chunk. What
/// it already did stays done; a finished or cancelled job answers 409.
#[utoipa::path(
    post,
    path = "/api/v1/jobs/{id}/cancel",
    tag = "jobs",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "The job stops after its current chunk", body = BatchJobProgress),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such batch job, or not one the caller started", body = ErrorResponse),
        (status = 409, description = "The job has already finished or been cancelled", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_batch(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<BatchJobProgress>), AppError> {
    visible_batch(&state, &ctx, id).await?;
    if !attome_jobs::batch::request_cancel(&state.base.db, id)
        .await
        .map_err(AppError::internal)?
    {
        return Err(AppError::Conflict(
            "the job has already finished or been cancelled",
        ));
    }
    attome_audit::security::SecurityAuditor::from_state(&state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::Update,
                ctx.user_id,
                "job_batch",
                Some(id),
            )
            .named("job.cancel"),
        )
        .await?;
    let batch = visible_batch(&state, &ctx, id).await?;
    Ok((StatusCode::ACCEPTED, Json(batch_body(batch))))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/jobs/dead-letter", get(list_dead_letter))
        .route("/api/v1/admin/jobs/{id}/replay", post(replay))
        .route("/api/v1/admin/jobs/{id}", delete(discard))
        .route("/api/v1/jobs/{id}", get(batch_progress))
        .route("/api/v1/jobs/{id}/cancel", post(cancel_batch))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_dead_letter, replay, discard, batch_progress, cancel_batch))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
