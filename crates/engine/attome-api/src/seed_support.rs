//! Tiny shared helper for the `*_seed.rs` modules in this crate that need to
//! resolve another entity's `entity_info` id (e.g. a lookup target)
//! before calling `ensure_attribute` — the same `entity_id_by_logicalname`
//! shape `attome_project::seed` defines privately for its own use, pulled out
//! here once a fourth caller in this crate needed it
//! (`communication_seed`/`relationship_seed`/`follow_seed`/`resource_seed`).

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

pub(crate) async fn entity_id_by_logicalname(
    db: &DbPool,
    logicalname: &str,
) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}
