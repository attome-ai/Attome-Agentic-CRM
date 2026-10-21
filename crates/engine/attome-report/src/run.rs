//! M25 Phase 1 (Report, D-440) — `POST /api/v1/reports/{id}/run` and its
//! worker.
//!
//! Security model (`document/decisions/security/D-440.md`): a report run
//! always executes its `query_ref` stored query through
//! `attome_records::query_exec::execute_stored_query` — the exact function
//! `GET /api/v1/query/execute` and `attome-ai`'s `query.execute` call, so
//! the per-query privilege gate, D-133 record-level scoping, and field
//! security are one implementation, never a second one grown here — under a
//! `SecurityContext` resolved **fresh from Postgres for the run's
//! `requested_by` user** (`attome_security::resolve_uncached`, the same
//! never-trust-the-enqueue-snapshot discipline `data_export.rs`'s own
//! `DataExport` worker follows), never the enqueuing caller's cached
//! context and never a superuser one. For a manual run `requested_by` is
//! the caller; for a scheduled run (`crate::scheduler`) it is the
//! schedule's `run_as` — the property `document/decisions/security/
//! D-440.md` exists to state.
//!
//! `report_run` is a migration-owned infrastructure table
//! (`0240_xrm_report_run.sql`), not a provisioned entity — see that
//! migration's header comment for why.
//!
//! Authorization: `Authorized<Privilege<ReportRead>>` (`crate::auth`), not
//! `RecordScoped` — neither route is shaped `/api/v1/{entity}/...`, so
//! there is no `{entity}` path segment for `RecordScoped` to bind against;
//! see `crate::auth`'s module doc for why `Privilege<K>` is the correct
//! policy here instead of a bare `Authorized<RecordScoped>` +
//! `ctx.require(..)`. Record-level scope for the specific report id run
//! reuses `attome_records::entity_crud::read_record` (below); scope for the
//! specific *run* id is `run.requested_by == ctx.user_id` (or admin) —
//! tighter than the report's own D-133 sharing, since a run holds an actual
//! data extract.

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_core::{EngineState, Filter};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::ReportRead;

const ENTITY: &str = "attome_report";
/// No measured production-shaped throughput exists yet for an in-memory
/// report render (coding-guidelines §14) — capped well inside what
/// `render::render_xlsx`'s whole-workbook-in-memory approach can comfortably
/// hold, mirroring `data_export.rs::MAX_EXPORT_ROWS`'s own reasoning at a
/// smaller ceiling (a report is rendered in memory, not streamed).
const MAX_REPORT_ROWS: i64 = 100_000;
/// Rows per query page: the most `query/execute` serves in one page.
const REPORT_PAGE_SIZE: i64 = attome_types::MAX_PAGE_SIZE;
const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Deserialize, ToSchema, Default)]
pub struct RunReportBody {
    /// Overrides the report's default `parameters` entirely when non-empty
    /// (not a deep merge) — same `Filter` grammar as `query/execute`.
    #[serde(default)]
    params: Vec<Filter>,
}

impl std::fmt::Debug for RunReportBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunReportBody").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
struct RunEnqueueResponse {
    id: Uuid,
    status: String,
}

#[derive(Serialize, ToSchema)]
struct RunStatusResponse {
    id: Uuid,
    report_ref: Uuid,
    format: String,
    status: String,
    row_count: Option<i64>,
    error: Option<String>,
    requested_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_secs: Option<u64>,
}

#[derive(sqlx::FromRow)]
struct ReportRow {
    query_ref: String,
    parameters: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct RunRow {
    pub(crate) id: Uuid,
    pub(crate) report_ref: Uuid,
    pub(crate) format: String,
    pub(crate) params: Value,
    pub(crate) status: String,
    pub(crate) requested_by: Uuid,
    pub(crate) requested_at: DateTime<Utc>,
    row_count: Option<i64>,
    object_key: Option<String>,
    error: Option<String>,
}

/// Creates a `pending` `report_run` row for `report_id` and enqueues its
/// `EngineJob::ReportRun`, in one transaction — same insert-and-enqueue
/// atomicity `data_export.rs::enqueue_export` gets for
/// `data_export`. `source`/`schedule_ref` distinguish
/// `crate::scheduler`'s dispatch (which creates the identical row shape for
/// a scheduled run) from a manual one.
pub(crate) async fn create_run(
    state: &EngineState,
    report_id: Uuid,
    format: &str,
    params: &[Filter],
    requested_by: Uuid,
    source: &str,
    schedule_ref: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let run_id = Uuid::now_v7();
    let params_json = serde_json::to_value(params).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO report_run \
            (id, report_ref, schedule_ref, source, status, format, params, requested_by, requested_at) \
         VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, NOW())",
    )
    .bind(run_id)
    .bind(report_id)
    .bind(schedule_ref)
    .bind(source)
    .bind(format)
    .bind(&params_json)
    .bind(requested_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::ReportRun { run_id })
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(run_id)
}

#[utoipa::path(
    post,
    path = "/api/v1/reports/{id}/run",
    tag = "report",
    params(("id" = Uuid, Path)),
    request_body = RunReportBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::ReportRun"),
        "the route only enqueues a run; the job writes entity+export in the run's completion transaction",
    )))),
    responses(
        (status = 202, description = "Success", body = RunEnqueueResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such report", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run_report(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ReportRead>>,
    Path(report_id): Path<Uuid>,
    Json(body): Json<RunReportBody>,
) -> Result<(StatusCode, Json<RunEnqueueResponse>), AppError> {
    // D-766: this work escapes the S2S entity ceiling (it re-resolves the
    // caller later, or reads across entities by role), so a capped caller
    // is refused until the ceiling is carried through.
    ctx.refuse_if_capped()?;
    // `read_record` is the same record-level+field-security check the
    // generic `GET /api/v1/attome_report/{id}` applies — a caller who cannot
    // see this report definition cannot run it either.
    let record = attome_records::entity_crud::read_record(&state, &ctx, ENTITY, report_id).await?;
    let record = serde_json::to_value(record).map_err(AppError::internal)?;
    let format = record
        .get("data")
        .and_then(|d| d.get("format"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("report record missing format"))?
        .to_string();

    let run_id = create_run(
        &state,
        report_id,
        &format,
        &body.params,
        ctx.user_id,
        "manual",
        None,
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RunEnqueueResponse {
            id: run_id,
            status: "pending".into(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/reports/runs/{run_id}",
    tag = "report",
    params(("run_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = RunStatusResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run_status(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ReportRead>>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<RunStatusResponse>, AppError> {
    let row = load_run(&state.base.db, run_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // Every run's `requested_by` may see it; anyone else needs `system.admin`
    // — a run holds an actual data extract, so this is deliberately tighter
    // than the report definition's own record-level sharing.
    if row.requested_by != ctx.user_id && !ctx.is_admin {
        return Err(AppError::NotFound);
    }

    let (download_url, expires_in_secs) = if row.status == "completed" {
        if let Some(key) = &row.object_key {
            let url = attome_storage::presign_download(&state.base.storage, key, DOWNLOAD_URL_TTL)
                .await
                .map_err(AppError::internal)?;
            (Some(url), Some(DOWNLOAD_URL_TTL.as_secs()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    Ok(Json(RunStatusResponse {
        id: row.id,
        report_ref: row.report_ref,
        format: row.format,
        status: row.status,
        row_count: row.row_count,
        error: row.error,
        requested_at: row.requested_at,
        download_url,
        expires_in_secs,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/reports/{id}/run", post(run_report))
        .route("/api/v1/reports/runs/{run_id}", get(run_status))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged in `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(run_report, run_status))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Worker ────────────────────────────────────────────────────────────────

pub(crate) async fn load_run(
    db: &attome_db::DbPool,
    run_id: Uuid,
) -> Result<Option<RunRow>, AppError> {
    sqlx::query_as(
        "SELECT id, report_ref, format, params, status, requested_by, requested_at, \
                row_count, object_key, error \
         FROM report_run WHERE id = $1 AND is_deleted = false",
    )
    .bind(run_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn load_report(
    db: &attome_db::DbPool,
    report_id: Uuid,
) -> Result<Option<ReportRow>, AppError> {
    sqlx::query_as(
        "SELECT query_ref, parameters FROM attome_report WHERE id = $1 AND is_active = true",
    )
    .bind(report_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn mark_running(db: &attome_db::DbPool, run_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE report_run SET status = 'running', started_at = NOW(), updated_at = NOW(), \
            row_version = row_version + 1 WHERE id = $1",
    )
    .bind(run_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn mark_failed(state: &EngineState, run_id: Uuid, message: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE report_run SET status = 'failed', error = $2, completed_at = NOW(), \
            updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(run_id)
    .bind(message)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // P3-T1: a failed scheduled run alerts the schedule's owner.
    crate::delivery::alert_owner(state, run_id, message).await;
    Ok(())
}

/// Worker for `EngineJob::ReportRun`. Re-derives everything from `run_id`
/// rather than a job payload snapshot — same discipline `data_export.rs`'s
/// `DataExport` worker follows — and re-resolves `requested_by`'s
/// `SecurityContext` directly from Postgres (D-440's core property: never
/// the enqueuing caller's context, never a superuser one).
pub async fn process(state: &EngineState, run_id: Uuid) -> Result<(), AppError> {
    let Some(run) = load_run(&state.base.db, run_id).await? else {
        tracing::warn!(%run_id, "report run: run not found, dropping job");
        return Ok(());
    };
    if run.status != "pending" {
        // At-least-once redelivery of an already-started run — nothing to do.
        return Ok(());
    }

    let Some(report) = load_report(&state.base.db, run.report_ref).await? else {
        mark_failed(state, run_id, "report definition not found or inactive").await?;
        return Ok(());
    };

    let security = attome_security::resolve_uncached(&state.base.db, run.requested_by).await?;
    if security.require(ENTITY, "read").is_err() {
        mark_failed(
            state,
            run_id,
            "report run authorization was revoked before processing",
        )
        .await?;
        return Ok(());
    }

    let Ok(query_id) = Uuid::parse_str(&report.query_ref) else {
        mark_failed(state, run_id, "report has an invalid query_ref").await?;
        return Ok(());
    };

    let run_filters: Vec<Filter> = serde_json::from_value(run.params.clone()).unwrap_or_default();
    let filters = if run_filters.is_empty() {
        report
            .parameters
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<Filter>>(s).ok())
            .unwrap_or_default()
    } else {
        run_filters
    };

    mark_running(&state.base.db, run_id).await?;

    let mut rows: Vec<Value> = Vec::new();
    let mut header: Vec<String> = Vec::new();
    let mut after_id: Option<Uuid> = None;
    loop {
        let request_json = serde_json::json!({
            "query_id": query_id,
            "page_size": REPORT_PAGE_SIZE,
            "after_id": after_id,
            "filters": filters,
        });
        // Deserialised into the SAME request type `POST /api/v1/query/execute`
        // uses, whose fields are private — this cannot smuggle a field the
        // route would not accept (same technique `attome-ai`'s
        // `query.execute` action uses).
        let request: attome_records::query_exec::ExecuteQueryRequest =
            match serde_json::from_value(request_json) {
                Ok(r) => r,
                Err(e) => {
                    mark_failed(state, run_id, &format!("invalid query parameters: {e}")).await?;
                    return Ok(());
                }
            };
        let response =
            match attome_records::query_exec::execute_stored_query(state, &security, request).await
            {
                Ok(r) => r,
                Err(e) => {
                    mark_failed(state, run_id, &format!("query execution failed: {e}")).await?;
                    return Ok(());
                }
            };
        let value = serde_json::to_value(&response).map_err(AppError::internal)?;
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        if header.is_empty() {
            header = data
                .get("columns")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|c| c.get("name").and_then(Value::as_str).map(String::from))
                .collect();
        }
        let records = data
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let got = records.len();
        rows.extend(records);
        if rows.len() as i64 > MAX_REPORT_ROWS {
            mark_failed(
                state,
                run_id,
                &format!("report exceeded the {MAX_REPORT_ROWS}-row cap — narrow the parameters"),
            )
            .await?;
            return Ok(());
        }
        let next_cursor = data
            .get("next_cursor")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        match next_cursor {
            Some(cursor) if got > 0 => after_id = Some(cursor),
            _ => break,
        }
    }

    let bytes = match run.format.as_str() {
        "csv" => crate::render::render_csv(&header, &rows),
        "xlsx" => match crate::render::render_xlsx(&header, &rows) {
            Ok(b) => b,
            Err(e) => {
                mark_failed(state, run_id, &format!("xlsx render failed: {e}")).await?;
                return Ok(());
            }
        },
        other => {
            mark_failed(
                state,
                run_id,
                &format!("unsupported report format: {other}"),
            )
            .await?;
            return Ok(());
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let checksum = hex::encode(hasher.finalize());

    let object_key = format!("report-runs/{}/{run_id}.{}", run.report_ref, run.format);
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid report object key: {e}")))?;
    if let Err(e) = state.base.storage.store().put(&path, bytes.into()).await {
        mark_failed(state, run_id, &format!("upload failed: {e}")).await?;
        return Ok(());
    }

    let row_count = rows.len() as i64;

    // D-062 / audit plan 3.6: the `completed` transition (which is what makes
    // the extract downloadable) and its Entity+Export audit event commit in
    // one transaction, opened only after the upload (no external I/O inside
    // it). A failed audit write rolls the transition back.
    let (user_ctx, org_ref) = attome_audit::fetch_audit_ctx(state, run.requested_by).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(ENTITY.to_string()),
        record_id: Some(run.report_ref),
        operation: AuditOperation::Export,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(run_id),
        event_name: None,
        event_comment: Some(format!(
            "report run produced {row_count} row(s) as {}",
            run.format
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };

    if let Err(e) = complete_run(state, run_id, row_count, &object_key, &checksum, event).await {
        // The rolled-back transition leaves the row `running`, and this
        // job's own guard (`status != "pending"` → no-op) means a queue
        // retry would never finish it — so record the failure durably (no
        // download URL is ever offered for a non-`completed` run) and still
        // return the error so the job run is visibly failed. The requester
        // (or the next scheduled dispatch) runs it again; nothing was
        // delivered without evidence.
        mark_failed(
            state,
            run_id,
            &format!("completion could not be recorded: {e}"),
        )
        .await?;
        return Err(e);
    }
    // P3-T1: a scheduled run goes to its recipient.
    crate::delivery::deliver(state, run_id).await;

    Ok(())
}

/// Moves a run to `completed` and writes its audit event in one transaction
/// (D-062): either both commit or neither does.
async fn complete_run(
    state: &EngineState,
    run_id: Uuid,
    row_count: i64,
    object_key: &str,
    checksum: &str,
    event: AuditEvent,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE report_run \
            SET status = 'completed', row_count = $2, object_key = $3, checksum = $4, \
                completed_at = NOW(), \
                duration_ms = GREATEST(0, EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000)::bigint, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(run_id)
    .bind(row_count)
    .bind(object_key)
    .bind(checksum)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::audit_service(state)
        .write_in_tx(&mut tx, event)
        .await?;
    attome_db::tx::commit(tx).await
}
