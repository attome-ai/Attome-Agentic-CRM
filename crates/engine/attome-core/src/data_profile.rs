//! L6-T8: reading a stored data profile (`data_profile`, written by the
//! profiling job in `attome-api`'s `data_profile_admin`), for callers that
//! are not the profile routes: the agent tool `profile.summary`.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// One completed profile of an entity.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub id: Uuid,
    pub entity: String,
    pub row_count: Option<i64>,
    /// The per-attribute summaries, as the profiling job wrote them.
    pub fields: Value,
    /// Rows the statistics were computed from.
    pub sample_size: Option<i64>,
    pub full_scan: bool,
    pub completed_at: Option<DateTime<Utc>>,
}

/// The newest completed profile of `entity`, if any.
pub async fn latest(db: &DbPool, entity: &str) -> Result<Option<Profile>, AppError> {
    type Row = (
        Uuid,
        String,
        Option<i64>,
        Value,
        Option<i64>,
        bool,
        Option<DateTime<Utc>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, entity_logicalname, row_count, fields, sample_size, full_scan, completed_at \
           FROM data_profile \
          WHERE entity_logicalname = $1 AND status = 'completed' AND is_deleted = false \
          ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(
        |(id, entity, row_count, fields, sample_size, full_scan, completed_at)| Profile {
            id,
            entity,
            row_count,
            fields,
            sample_size,
            full_scan,
            completed_at,
        },
    ))
}
