//! Y2-T12: partitioning a large entity table online, by created date
//! (`attome_metadata::provision::partition`). A builder starts it; nothing
//! partitions on its own.
//!
//! - `POST /api/v1/admin/entities/{entity_id}/partition` checks the table
//!   (over `records.partition_row_threshold` rows, 50,000,000 unless set; no
//!   unique business key, keyed lookup to it, trigger or view in the way),
//!   creates the partitioned copy with its sync trigger and queues the copy:
//!   a data step run of kind `partition`, in batches of 10,000 rows by id,
//!   paused, resumed and cancelled through `/api/v1/admin/data-step-runs/{id}`
//!   (a cancel drops the copy and the trigger). When the copy is done the
//!   run swaps the tables in one short transaction and the entity becomes
//!   `high_volume`; the original stays as `<entity>__old` until a builder
//!   drops it.
//! - `GET` the same path: the entity's storage mode, its latest partition
//!   run and whether the old table is still kept.

use attome_core::EngineState;
use attome_metadata::provision::field_change as fc;
use attome_metadata::provision::partition as part;
use attome_metadata::provision::storage::storage_mode_of;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// Tries at the swap's lock before the run gives up.
const SWAP_ATTEMPTS: u32 = 5;

/// A partition run.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PartitionRun {
    pub id: Uuid,
    /// `queued`, `running`, `paused`, `succeeded`, `failed` or `abandoned`.
    pub status: String,
    pub rows_estimate: Option<i64>,
    pub rows_scanned: i64,
    pub rows_written: i64,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// An entity's partitioning.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PartitionStatus {
    pub entity: String,
    /// `standard` or `high_volume` (partitioned by month on `created_at`).
    pub storage_mode: String,
    /// The latest partition run, if any.
    pub run: Option<PartitionRun>,
    /// `<entity>__old`, the table before the swap, is still kept.
    pub old_table_kept: bool,
}

/// The rows a table must exceed: the setting, else the default.
fn threshold(state: &EngineState) -> i64 {
    attome_core::setting_registry()
        .get(part::ROW_THRESHOLD_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .filter(|n| *n >= 0)
        .unwrap_or(part::DEFAULT_ROW_THRESHOLD)
}

fn entity_name(state: &EngineState, entity_id: Uuid) -> Result<String, AppError> {
    state
        .entities
        .load()
        .get_by_id(entity_id)
        .map(|e| e.logicalname.clone())
        .ok_or(AppError::NotFound)
}

async fn status_of(state: &EngineState, entity: &str) -> Result<PartitionStatus, AppError> {
    let db = &state.base.db_migrator;
    let mode = storage_mode_of(db, entity).await?;
    let run: Option<PartitionRun> = sqlx::query_as(
        "SELECT id, status, rows_estimate, rows_scanned, rows_written, error_message, \
                created_at, finished_at \
           FROM data_step_run WHERE entity_logicalname = $1 AND kind = $2 \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity)
    .bind(part::PARTITION_KIND)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let old_table_kept: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(attome_core::quote_ident(&part::old_name(entity)))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok(PartitionStatus {
        entity: entity.to_owned(),
        storage_mode: mode.as_str().to_owned(),
        run,
        old_table_kept,
    })
}

/// An entity's partitioning
///
/// Y2-T12: whether entity `entity_id` is partitioned by created date, its latest partition run and
/// whether the table from before the swap is still kept. Administrators with the data-model area.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/partition",
    operation_id = "get_entity_partition",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity")),
    responses(
        (status = 200, description = "The entity's partitioning", body = PartitionStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the data-model area", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_partition(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<PartitionStatus>, AppError> {
    let entity = entity_name(&state, entity_id)?;
    Ok(Json(status_of(&state, &entity).await?))
}

/// Partition an entity by created date
///
/// Y2-T12: starts partitioning entity `entity_id`'s table by month on `created_at`, online. Refused
/// (422) unless the table holds more rows than `records.partition_row_threshold` (50,000,000 unless
/// set) and has no unique business key, keyed lookup pointing at it, trigger or view; 409 while a
/// run's tables or the old table are still there. Creates the partitioned copy and its sync trigger,
/// then queues the copy (a data step run of kind `partition`); the run swaps the tables when the
/// copy is done. Administrators with the data-model area.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/partition",
    operation_id = "partition_entity",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
    params(("entity_id" = Uuid, Path, description = "The entity")),
    responses(
        (status = 202, description = "The copy is queued", body = PartitionStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the data-model area", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "Already partitioned, or an earlier run's tables are there", body = ErrorResponse),
        (status = 422, description = "Too small, or something in the table keeps it from moving", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn partition_entity(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
) -> Result<(StatusCode, Json<PartitionStatus>), AppError> {
    let entity = entity_name(&state, entity_id)?;
    let db = &state.base.db_migrator;
    let plan = part::plan_partition(db, &entity, threshold(&state)).await?;
    part::prepare(db, &entity).await?;

    let queued = async {
        let mut tx = attome_db::tx::begin(db).await?;
        let run_id: Uuid = sqlx::query_scalar(
            "INSERT INTO data_step_run (source, entity_logicalname, kind, spec, rows_estimate, \
                                        created_by) \
             VALUES ('admin', $1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(&entity)
        .bind(part::PARTITION_KIND)
        .bind(json!({ "entity_id": entity_id }))
        .bind(plan.rows)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::RunDataStep { run_id },
        )
        .await
        .map_err(AppError::internal)?;
        attome_audit::write_business_event_in_tx(
            &mut tx,
            &attome_audit::audit_service(&state),
            attome_audit::BusinessEvent::new(
                "entity_info",
                entity_id,
                attome_audit::AuditOperation::Update,
                "entity.partition",
                ctx.user_id,
            )
            .comment(format!(
                "partition {entity} by created_at ({} rows)",
                plan.rows
            )),
        )
        .await?;
        attome_db::tx::commit(tx).await
    }
    .await;
    if let Err(error) = queued {
        // Nothing will copy into the new table: take it and its trigger away.
        if let Err(e) = part::discard(db, &entity).await {
            tracing::error!(error = %e, %entity, "partition: discarding the copy after a failed queue failed");
        }
        return Err(error);
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(status_of(&state, &entity).await?),
    ))
}

/// `RunDataStep` for a `partition` run: batches of rows from the run's
/// cursor, each batch's copy, counts and cursor committed together; then
/// the swap.
pub(crate) async fn continue_partition(
    state: &EngineState,
    run: &fc::RunRow,
) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let entity = run.entity_logicalname.clone();
    let shadow_there: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(attome_core::quote_ident(&part::shadow_name(&entity)))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !shadow_there {
        return Err(AppError::internal(format!(
            "partition run {}: {} is gone",
            run.id,
            part::shadow_name(&entity)
        )));
    }
    let columns = part::columns(db, &entity).await?;
    let insert = part::batch_sql(&entity, &columns);
    let mut cursor = run.cursor;
    loop {
        if fc::run_stopped(db, run.id).await? {
            tracing::info!(run_id = %run.id, "partition: paused or cancelled; stopped between batches");
            return Ok(());
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let (read, written, last) = part::copy_batch(&mut tx, &entity, &insert, cursor).await?;
        cursor = last;
        fc::advance_run(&mut tx, run.id, cursor, read, written, 0).await?;
        attome_db::tx::commit(tx).await?;
        if (read as i64) < part::PARTITION_BATCH {
            break;
        }
    }

    let mut attempt = 0;
    loop {
        attempt += 1;
        match part::swap(db, &entity).await {
            Ok(()) => break,
            Err(e) if attempt < SWAP_ATTEMPTS && is_lock_timeout(&e) => {
                tracing::warn!(run_id = %run.id, %entity, attempt, "partition: the swap waited too long for the table; retrying");
                tokio::time::sleep(std::time::Duration::from_secs(2 * u64::from(attempt))).await;
            }
            Err(e) => return Err(e),
        }
    }
    super::notify_metadata_change(&state.base.redis).await;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    fc::finish_run(&mut conn, run.id, None).await?;
    tracing::info!(run_id = %run.id, %entity, "partition: swapped; the old table is kept");
    Ok(())
}

fn is_lock_timeout(error: &AppError) -> bool {
    matches!(error, AppError::Internal(text) if text.contains("55P03") || text.contains("lock timeout"))
}

/// A cancelled partition run's cleanup: the copy and its trigger go, the
/// table stays as it was. Nothing to do once the swap happened.
pub(crate) async fn discard_after_cancel(
    state: &EngineState,
    entity: &str,
) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    if storage_mode_of(db, entity).await?.is_high_volume() {
        return Ok(());
    }
    part::discard(db, entity).await
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/partition",
        get(get_partition).post(partition_entity),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_partition, partition_entity),
    components(schemas(PartitionStatus, PartitionRun))
)]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_timeout_is_retried() {
        assert!(is_lock_timeout(&AppError::internal(
            "error returned from database: canceling statement due to lock timeout"
        )));
        assert!(!is_lock_timeout(&AppError::Conflict("fields changed")));
    }

    #[test]
    fn the_spec_names_the_entity() {
        let spec: serde_json::Value = json!({ "entity_id": Uuid::nil() });
        assert!(spec.get("entity_id").is_some());
    }
}
