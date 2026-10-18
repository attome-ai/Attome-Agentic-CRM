//! Y12-T5: a data step run's progress and its controls.
//!
//! - `GET /api/v1/admin/data-step-runs/{id}`: status, counts and an ETA (the
//!   rows left over the run's rate since it started).
//! - `POST .../{id}/pause`: a queued or running run stops after its current
//!   batch (each batch commits with its cursor, so none is half applied).
//! - `POST .../{id}/resume`: a paused run is queued again and continues from
//!   its cursor.
//! - `POST .../{id}/cancel`: a run that has not finished stops. An orphan
//!   scan, which changes nothing, ends `abandoned`; a field run (a retype's
//!   shadow column, a delete's archive copies) ends `failed`, so the field's
//!   `runs/{run_id}/abandon` route undoes its partial state.
//!
//! Outside the metadata-authoring prefix: operating a run is not authoring
//! metadata. Admin only.

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_core::EngineState;
use attome_metadata::provision::field_change as fc;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// A run's progress.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DataStepRunStatus {
    pub id: Uuid,
    pub kind: String,
    pub entity: String,
    /// `queued`, `claimed`, `running`, `paused`, `succeeded`, `failed` or
    /// `abandoned`.
    pub status: String,
    /// The planner's row estimate when the run was queued.
    pub rows_total: Option<i64>,
    pub rows_scanned: i64,
    pub rows_written: i64,
    pub rows_nulled: i64,
    pub started_at: Option<chrono::DateTime<Utc>>,
    pub finished_at: Option<chrono::DateTime<Utc>>,
    pub error_message: Option<String>,
    /// Seconds left at the run's rate so far; `None` before it has a rate or
    /// once it is not running.
    #[sqlx(skip)]
    pub eta_secs: Option<u64>,
}

async fn load(state: &EngineState, id: Uuid) -> Result<DataStepRunStatus, AppError> {
    let mut run: DataStepRunStatus = sqlx::query_as(
        "SELECT id, kind, entity_logicalname AS entity, status, rows_estimate AS rows_total, \
                rows_scanned, rows_written, rows_nulled, started_at, finished_at, error_message \
           FROM data_step_run WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    run.eta_secs = eta(&run, Utc::now());
    Ok(run)
}

/// The rows left over the rate since the run started.
fn eta(run: &DataStepRunStatus, now: chrono::DateTime<Utc>) -> Option<u64> {
    if !matches!(run.status.as_str(), "running" | "claimed") {
        return None;
    }
    let total = run.rows_total?;
    let elapsed = (now - run.started_at?).num_milliseconds();
    if run.rows_scanned <= 0 || elapsed <= 0 {
        return None;
    }
    let left = (total - run.rows_scanned).max(0);
    // Seconds, rounded up; row counts sit far below 2^52.
    let rate = run.rows_scanned as f64 * 1000.0 / elapsed as f64;
    Some((left as f64 / rate).ceil() as u64)
}

async fn audit(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    user_id: Uuid,
    run: &DataStepRunStatus,
    event: &str,
) -> Result<(), AppError> {
    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    audit_service(state)
        .write_in_tx(
            tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(run.entity.clone()),
                record_id: Some(run.id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some(event.to_owned()),
                event_comment: Some(format!(
                    "{event}: {} run {} of {}",
                    run.kind, run.id, run.entity
                )),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await
}

/// One control: the states it leaves, the one it enters, the error it
/// records, its audit event and its refusal.
struct Move {
    from: &'static [&'static str],
    to: &'static str,
    error: Option<&'static str>,
    event: &'static str,
    refused: &'static str,
}

/// Applies `mv` with its audit event in one transaction; a run moved to
/// `queued` is enqueued in the same transaction.
async fn transition(
    state: &EngineState,
    user_id: Uuid,
    id: Uuid,
    mv: Move,
) -> Result<DataStepRunStatus, AppError> {
    let run = load(state, id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    if !fc::set_run_status(&mut tx, id, mv.from, mv.to, mv.error).await? {
        return Err(AppError::Conflict(mv.refused));
    }
    let (to, event) = (mv.to, mv.event);
    if to == "queued" {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::RunDataStep { run_id: id },
        )
        .await
        .map_err(AppError::internal)?;
    }
    audit(state, &mut tx, user_id, &run, event).await?;
    attome_db::tx::commit(tx).await?;
    load(state, id).await
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/data-step-runs/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The run's progress", body = DataStepRunStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_run(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataStepRunStatus>, AppError> {
    load(&state, id).await.map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/data-step-runs/{id}/pause",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Paused; a running batch finishes first", body = DataStepRunStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
        (status = 409, description = "`run_not_active`: the run is not queued or running", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn pause_run(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataStepRunStatus>, AppError> {
    transition(
        &state,
        ctx.user_id,
        id,
        Move {
            from: &["queued", "claimed", "running"],
            to: "paused",
            error: None,
            event: "pause_data_step_run",
            refused: "run_not_active: only a queued or running run can be paused",
        },
    )
    .await
    .map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/data-step-runs/{id}/resume",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Queued again; it continues from its cursor", body = DataStepRunStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
        (status = 409, description = "`run_not_paused`", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn resume_run(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataStepRunStatus>, AppError> {
    transition(
        &state,
        ctx.user_id,
        id,
        Move {
            from: &["paused"],
            to: "queued",
            error: None,
            event: "resume_data_step_run",
            refused: "run_not_paused: only a paused run can be resumed",
        },
    )
    .await
    .map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/data-step-runs/{id}/cancel",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Stopped: an orphan scan is abandoned, a field run is failed for its abandon route", body = DataStepRunStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
        (status = 409, description = "`run_finished`: the run already ended", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn cancel_run(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataStepRunStatus>, AppError> {
    let run = load(&state, id).await?;
    let (to, error) = if run.kind == "orphan_scan" {
        ("abandoned", None)
    } else {
        ("failed", Some("cancelled by an administrator"))
    };
    transition(
        &state,
        ctx.user_id,
        id,
        Move {
            from: &["queued", "claimed", "running", "paused"],
            to,
            error,
            event: "cancel_data_step_run",
            refused: "run_finished: the run already ended",
        },
    )
    .await
    .map(Json)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/data-step-runs/{id}", get(get_run))
        .route("/api/v1/admin/data-step-runs/{id}/pause", post(pause_run))
        .route("/api/v1/admin/data-step-runs/{id}/resume", post(resume_run))
        .route("/api/v1/admin/data-step-runs/{id}/cancel", post(cancel_run))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_run, pause_run, resume_run, cancel_run))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta_is_rows_left_over_the_rate_so_far() {
        let now = Utc::now();
        let run = DataStepRunStatus {
            id: Uuid::nil(),
            kind: "retype".into(),
            entity: "deal".into(),
            status: "running".into(),
            rows_total: Some(10_000),
            rows_scanned: 2_000,
            rows_written: 2_000,
            rows_nulled: 0,
            started_at: Some(now - chrono::Duration::seconds(10)),
            finished_at: None,
            error_message: None,
            eta_secs: None,
        };
        assert_eq!(eta(&run, now), Some(40));
        let paused = DataStepRunStatus {
            status: "paused".into(),
            ..run.clone()
        };
        assert_eq!(eta(&paused, now), None);
    }
}
