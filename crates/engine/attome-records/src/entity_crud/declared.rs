//! K7-T1: declared records. A record declared under a records-management
//! category (`record_declaration`, migration 0242) is immutable: the generic
//! update, delete, hard delete and restore refuse it with `409`. It leaves
//! only by erasure (R2) or by an approved disposition
//! (`attome_compliance::records_mgmt`), neither of which goes through these
//! paths.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// The refusal a declared record's write meets.
pub const DECLARED: &str = "this record is declared under records management and cannot be changed";

/// Whether `record_id` of `entity` is declared and not yet disposed.
pub async fn is_declared(db: &DbPool, entity: &str, record_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM record_declaration \
                         WHERE entity = $1 AND record_id = $2 AND disposed_at IS NULL)",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// `409` when the record is declared.
pub async fn refuse_if_declared(
    db: &DbPool,
    entity: &str,
    record_id: Uuid,
) -> Result<(), AppError> {
    if is_declared(db, entity, record_id).await? {
        Err(AppError::Conflict(DECLARED))
    } else {
        Ok(())
    }
}
