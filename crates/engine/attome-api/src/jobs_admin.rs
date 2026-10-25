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
use attome_core::dead_letter::{DeadLetter, DeadLetterFuture, DeadLetterSource, ReplayOutcome};
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
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

/// Dead-lettered jobs
///
/// Dead-lettered jobs. Administrators only.
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

/// Z7-T6: one queue at a glance.
#[derive(Serialize, ToSchema)]
struct JobLane {
    /// `fast` or `batch`.
    queue: &'static str,
    pending: i64,
    running: i64,
    /// Waiting out a retry backoff.
    retrying: i64,
    dead_letters: i64,
    /// Seconds since the oldest pending job was due; absent when none is.
    oldest_pending_age_secs: Option<f64>,
    done_last_hour: i64,
    failed_last_hour: i64,
    /// Failed over failed plus done in the last hour, 0 to 1; absent when
    /// nothing finished.
    failure_rate_last_hour: Option<f64>,
}

/// The job queues
///
/// Z7-T6: each queue's depth, running jobs, retries, dead letters, the age
/// of its oldest waiting job and its failure rate over the last hour.
#[utoipa::path(
    get,
    path = "/api/v1/admin/jobs/lanes",
    tag = "admin",
    responses(
        (status = 200, description = "Both queues, fast first", body = PaginatedResponse<JobLane>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn lanes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<JobLane>>, AppError> {
    let mut items = Vec::with_capacity(2);
    for (queue, batch) in [("fast", false), ("batch", true)] {
        let s = attome_jobs::lane_stats(&state.base.db, batch)
            .await
            .map_err(AppError::internal)?;
        items.push(JobLane {
            queue,
            pending: s.pending,
            running: s.running,
            retrying: s.retrying,
            dead_letters: s.dead_letters,
            oldest_pending_age_secs: s.oldest_pending_age_secs,
            done_last_hour: s.done_last_hour,
            failed_last_hour: s.failed_last_hour,
            failure_rate_last_hour: attome_jobs::failure_rate(s.done_last_hour, s.failed_last_hour),
        });
    }
    Ok(Json(PaginatedResponse::new(items, 2, 1, 2)))
}

#[derive(Serialize, ToSchema)]
struct ReplayResult {
    replayed: bool,
}

/// Replay a dead-lettered job
///
/// Replay a dead-lettered job. Administrators only. Audited.
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
    audit_job_replay(&state, ctx.user_id, &id).await?;
    Ok((StatusCode::OK, Json(ReplayResult { replayed: true })))
}

/// attome-jobs cannot depend on attome-audit (layering, coding-guidelines §1), so
/// this writes after the base-layer commit rather than inside its transaction
/// — the same documented D-062 deviation Phase 3 item 3.3 uses for attome-auth.
/// The apalis id is not a UUID, so it rides in the comment, not record_id.
async fn audit_job_replay(state: &EngineState, actor: Uuid, id: &str) -> Result<(), AppError> {
    attome_audit::security::SecurityAuditor::from_state(state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::Execute,
                actor,
                "base_jobs_dead_letter",
                None,
            )
            .named("job.replay")
            .comment(format!("id={id}")),
        )
        .await
        .map(|_| ())
}

/// The discard handler's audit event (same layering note as
/// [`audit_job_replay`]); M5-T1's inbox adds the operator's reason.
async fn audit_job_discard(
    state: &EngineState,
    actor: Uuid,
    discarded: &attome_jobs::DiscardedJob,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let mut comment = format!(
        "id={} queue={} variant={}",
        discarded.id,
        discarded.queue,
        discarded.variant.as_deref().unwrap_or("unknown")
    );
    if let Some(reason) = reason {
        comment.push_str(&format!("; reason: {reason}"));
    }
    attome_audit::security::SecurityAuditor::from_state(state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::HardDelete,
                actor,
                "base_jobs_dead_letter",
                None,
            )
            .named("job.discard")
            .comment(comment),
        )
        .await
        .map(|_| ())
}

/// Discard a dead letter
///
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
    audit_job_discard(&state, ctx.user_id, &discarded, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// M5-T1: background jobs as a [`DeadLetterSource`], one per queue. Step is
/// the job variant; the payload is never exposed (some variants carry live
/// tokens), so there is no payload reference.
#[derive(Debug, Clone, Copy)]
pub struct JobDeadLetters {
    /// The batch queue rather than the fast one.
    pub batch: bool,
}

impl JobDeadLetters {
    fn name(self) -> &'static str {
        if self.batch { "batch_jobs" } else { "jobs" }
    }

    fn item(self, row: attome_jobs::DeadLetterJobRow) -> DeadLetter {
        DeadLetter::new(
            self.name(),
            row.id.clone(),
            attome_jobs::job_variant_tag(&row.job).map(str::to_string),
            row.last_error.as_deref(),
            row.done_at.unwrap_or(row.run_at),
            row.attempts,
            None,
        )
    }
}

impl DeadLetterSource for JobDeadLetters {
    fn source(&self) -> &'static str {
        self.name()
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        offset: i64,
        limit: i64,
    ) -> DeadLetterFuture<'a, Vec<DeadLetter>> {
        Box::pin(async move {
            let rows =
                attome_jobs::list_dead_letter_jobs(&state.base.db, self.batch, offset, limit)
                    .await
                    .map_err(AppError::internal)?;
            Ok(rows.into_iter().map(|row| self.item(row)).collect())
        })
    }

    fn count<'a>(&'a self, state: &'a EngineState) -> DeadLetterFuture<'a, i64> {
        Box::pin(async move {
            attome_jobs::dead_letter_count(&state.base.db, self.batch)
                .await
                .map_err(AppError::internal)
        })
    }

    fn get<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
    ) -> DeadLetterFuture<'a, Option<DeadLetter>> {
        Box::pin(async move {
            let found = attome_jobs::get_dead_letter_job(&state.base.db, id)
                .await
                .map_err(AppError::internal)?;
            Ok(found
                .filter(|(_, batch)| *batch == self.batch)
                .map(|(row, _)| self.item(row)))
        })
    }

    fn replay<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
    ) -> DeadLetterFuture<'a, ReplayOutcome> {
        Box::pin(async move {
            match attome_jobs::replay_dead_letter_job_checked(&state.base.db, id)
                .await
                .map_err(AppError::internal)?
            {
                attome_jobs::ReplayOutcome::Replayed => {
                    audit_job_replay(state, actor, id).await?;
                    Ok(ReplayOutcome::Replayed)
                }
                attome_jobs::ReplayOutcome::NotDeadLettered => Ok(ReplayOutcome::NotDeadLettered),
                attome_jobs::ReplayOutcome::DedupSlotTaken { .. } => Ok(ReplayOutcome::Refused(
                    "a live job already holds this job's dedup key",
                )),
            }
        })
    }

    fn discard<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
        reason: &'a str,
    ) -> DeadLetterFuture<'a, bool> {
        Box::pin(async move {
            let Some(discarded) = attome_jobs::discard_dead_letter_job(&state.base.db, id)
                .await
                .map_err(AppError::internal)?
            else {
                return Ok(false);
            };
            audit_job_discard(state, actor, &discarded, Some(reason)).await?;
            Ok(true)
        })
    }
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

/// M12-T4: the batch jobs the caller started (imports, bulk edits, exports,
/// merges), newest first, with their progress. Only the caller's own, even
/// for an administrator.
#[utoipa::path(
    get,
    path = "/api/v1/jobs",
    description = "The batch jobs the caller started, newest first, with their progress and whether they can still be cancelled (M12-T4).",
    tag = "jobs",
    operation_id = "list_my_batch_jobs",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The caller's batch jobs, newest first", body = PaginatedResponse<BatchJobProgress>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn my_batches(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<BatchJobProgress>>, AppError> {
    let window = page.window();
    let (batches, total) = attome_jobs::batch::list_started_by(
        &state.base.db,
        ctx.user_id,
        window.page_size,
        window.offset,
    )
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        batches.into_iter().map(batch_body).collect(),
        total,
        window.page,
        window.page_size,
    )))
}

/// M10-T4: every pending timer, soonest first (administrators).
#[utoipa::path(
    get,
    path = "/api/v1/admin/timers",
    description = "Every pending timer on every record, soonest first: what it will do, on which record and when (M10-T4). Administrators only.",
    tag = "admin",
    operation_id = "list_pending_timers",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Pending timers, soonest first", body = PaginatedResponse<attome_core::timer::PendingTimer>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn pending_timers(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<attome_core::timer::PendingTimer>>, AppError> {
    let window = page.window();
    let (items, total) =
        attome_core::timer::pending_page(&state.base.db, window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// A batch job's progress
///
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

/// Cancel a batch job
///
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
        .route("/api/v1/admin/jobs/lanes", get(lanes))
        .route("/api/v1/admin/jobs/{id}/replay", post(replay))
        .route("/api/v1/admin/jobs/{id}", delete(discard))
        .route("/api/v1/jobs", get(my_batches))
        .route("/api/v1/admin/timers", get(pending_timers))
        .route("/api/v1/jobs/{id}", get(batch_progress))
        .route("/api/v1/jobs/{id}/cancel", post(cancel_batch))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_dead_letter,
    lanes,
    replay,
    discard,
    my_batches,
    pending_timers,
    batch_progress,
    cancel_batch
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_letter_sources_jobs_group_by_variant_per_queue() {
        let row = attome_jobs::DeadLetterJobRow {
            id: "42".into(),
            job: serde_json::json!({"version": 1, "variant": "SendEmail", "payload": {}}),
            attempts: 5,
            max_attempts: 5,
            last_error: Some("smtp connection refused".into()),
            run_at: Utc::now(),
            done_at: None,
        };
        let fast = JobDeadLetters { batch: false }.item(row.clone());
        assert_eq!(fast.source, "jobs");
        assert_eq!(fast.error_kind, "connect");
        assert_eq!(fast.payload_ref, None, "a job payload is never referenced");
        let batch = JobDeadLetters { batch: true }.item(row);
        assert_eq!(batch.source, "batch_jobs");
    }
}
