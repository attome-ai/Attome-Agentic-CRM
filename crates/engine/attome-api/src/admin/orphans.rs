//! Y2-T4: the orphan scan. `GET /api/v1/admin/entities/{entity_id}/orphans`
//! lists, per lookup field, how many rows point at a record that does not
//! exist. A table up to [`ORPHAN_SCAN_INLINE_ROW_LIMIT`] rows is scanned on
//! the request; a larger one answers from its latest finished scan, which
//! `POST /api/v1/admin/data-step-runs/orphan-scans` queues as a durable
//! `orphan_scan` run (a 409 `orphan_scan_required` until one has finished).
//! The queue route sits outside the metadata-authoring prefix: a scan only
//! reads, so it runs on a production deployment too, where its data lives.
//! Admin only. The scan never clears or deletes a value.

use attome_core::EngineState;
use attome_metadata::provision::{
    self,
    lookup_fk::{self, LookupColumn, OrphanTally},
};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Tables up to this many rows are scanned on the request.
pub const ORPHAN_SCAN_INLINE_ROW_LIMIT: i64 = 10_000;

/// One lookup field's orphans.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrphanCount {
    pub attribute: String,
    /// The entity the lookup points at.
    pub target_entity: String,
    /// Rows whose value names no record of the target.
    pub orphans: i64,
    /// When the count was taken.
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    /// The scan run it came from; `None` for a scan on the request.
    pub run_id: Option<Uuid>,
}

/// The entity to scan.
#[derive(Debug, Clone, serde::Deserialize, ToSchema)]
pub struct OrphanScanRequest {
    pub entity_id: Uuid,
}

/// A queued (or already running) scan.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrphanScanQueued {
    pub run_id: Uuid,
    /// `false` when a scan of this entity was already queued or running.
    pub created: bool,
}

fn entity_of(
    state: &EngineState,
    entity_id: Uuid,
) -> Result<(String, Vec<LookupColumn>), AppError> {
    let registry = state.entities.load();
    let meta = registry.get_by_id(entity_id).ok_or(AppError::NotFound)?;
    Ok((
        meta.logicalname.clone(),
        lookup_fk::lookup_columns(meta, &registry),
    ))
}

fn counts(
    tallies: Vec<OrphanTally>,
    scanned_at: chrono::DateTime<chrono::Utc>,
    run_id: Option<Uuid>,
) -> Vec<OrphanCount> {
    tallies
        .into_iter()
        .map(|t| OrphanCount {
            attribute: t.attribute,
            target_entity: t.target_entity,
            orphans: t.orphans,
            scanned_at,
            run_id,
        })
        .collect()
}

/// Orphaned lookup values
///
/// Orphaned lookup values. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/orphans",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity"), OnePageQuery),
    responses(
        (status = 200, description = "Orphan counts per lookup field, in field order", body = PaginatedResponse<OrphanCount>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "orphan_scan_required: the table is over the inline limit and no scan has finished; POST /api/v1/admin/data-step-runs/orphan-scans", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_orphans(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OrphanCount>>, AppError> {
    let (entity, columns) = entity_of(&state, entity_id)?;
    let db = &state.base.db;
    let all = if provision::table_row_count_exceeds(db, &entity, ORPHAN_SCAN_INLINE_ROW_LIMIT)
        .await?
    {
        let Some((run_id, finished_at, spec)) = lookup_fk::latest_scan(db, &entity).await? else {
            return Err(AppError::Conflict("orphan_scan_required"));
        };
        counts(lookup_fk::run_tallies(&spec)?, finished_at, Some(run_id))
    } else {
        counts(
            lookup_fk::count_orphans(db, &entity, &columns).await?,
            chrono::Utc::now(),
            None,
        )
    };
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let items = all
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(usize::try_from(page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Start an orphan scan
///
/// Start an orphan scan. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data-step-runs/orphan-scans",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "queues a read-only scan of the entity's lookup values; the run row is \
         operational bookkeeping and no record, metadata or security state changes"
    )))),
    request_body = OrphanScanRequest,
    responses(
        (status = 202, description = "The scan is queued (or was already queued or running)", body = OrphanScanQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn queue_orphan_scan(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<OrphanScanRequest>,
) -> Result<impl IntoResponse, AppError> {
    let entity_id = body.entity_id;
    let (entity, columns) = entity_of(&state, entity_id)?;
    let spec = lookup_fk::scan_spec(entity_id, &columns);
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    let (run_id, created) =
        lookup_fk::create_scan_run_in_tx(&mut tx, &entity, &spec, None, ctx.user_id).await?;
    if created {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::RunDataStep { run_id },
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(OrphanScanQueued { run_id, created }),
    ))
}

/// `RunDataStep` for an `orphan_scan` run: batches from the run's cursor,
/// each batch's counts and cursor committed together, then finished.
pub(crate) async fn continue_scan(
    state: &EngineState,
    run: &provision::field_change::RunRow,
) -> Result<(), AppError> {
    use provision::field_change as fc;
    let db = &state.base.db_migrator;
    let (columns, _) = lookup_fk::spec_tallies(&run.spec)?;
    let mut spec = run.spec.clone();
    let mut cursor = run.cursor;
    loop {
        if fc::run_stopped(db, run.id).await? {
            tracing::info!(run_id = %run.id, "orphan scan: paused or cancelled; stopped between batches");
            return Ok(());
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let batch = lookup_fk::scan_batch(
            &mut tx,
            &run.entity_logicalname,
            &columns,
            cursor,
            Some(lookup_fk::ORPHAN_SCAN_BATCH),
        )
        .await?;
        spec = lookup_fk::add_batch_in_tx(&mut tx, run.id, &spec, &batch).await?;
        let scanned = u64::try_from(batch.scanned).unwrap_or(0);
        if batch.last.is_some() {
            cursor = batch.last;
        }
        fc::advance_run(&mut tx, run.id, cursor, scanned, 0, 0).await?;
        attome_db::tx::commit(tx).await?;
        if batch.scanned < lookup_fk::ORPHAN_SCAN_BATCH {
            break;
        }
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    fc::finish_run(&mut conn, run.id, None).await?;
    tracing::info!(run_id = %run.id, entity = %run.entity_logicalname, "orphan scan: finished");
    Ok(())
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/entities/{entity_id}/orphans",
            get(list_orphans),
        )
        .route(
            "/api/v1/admin/data-step-runs/orphan-scans",
            post(queue_orphan_scan),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_orphans, queue_orphan_scan))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
