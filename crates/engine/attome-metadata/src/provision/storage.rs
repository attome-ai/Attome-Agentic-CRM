//! A1-T6: high-volume entities.
//!
//! An entity is created `standard` (one table, the default) or
//! `high_volume`: its table is partitioned by month on the system column
//! `created_at` (a `timestamptz`, so a partition's bounds are instants and
//! never shift with a time zone), its primary key is `(id, created_at)`, and
//! a BRIN index on `created_at` serves date windows. Partitions are created
//! [`PARTITION_MONTHS_AHEAD`] months ahead when the entity is created and by
//! the partition job ([`maintain_partitions`]). The mode is chosen at
//! creation and never changed in place (converting a populated table needs
//! a copy job). A unique business key on such an entity is refused: a unique
//! rule on a partitioned table must include the partition key, which a
//! business key never does (`unique_needs_partition_key`). Reads must name a
//! window on `created_at` (`attome_records::query_exec`); the entity's
//! default views show the last [`DEFAULT_WINDOW_DAYS`] days.

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};

/// The column a high-volume table is partitioned by.
pub const PARTITION_COLUMN: &str = "created_at";

/// Months of partitions kept ahead of today.
pub const PARTITION_MONTHS_AHEAD: u32 = 12;

/// The window a high-volume entity's default views show.
pub const DEFAULT_WINDOW_DAYS: i64 = 30;

/// Storage parameters of a high-volume partition (the parent takes none).
pub const PARTITION_STORAGE_PARAMS: &str =
    "fillfactor = 90, autovacuum_vacuum_scale_factor = 0.02, autovacuum_vacuum_cost_delay = 2";

/// How an entity's table is stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    #[default]
    Standard,
    HighVolume,
}

impl StorageMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::HighVolume => "high_volume",
        }
    }

    /// The mode a stored or requested value names. Pure.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "standard" => Some(Self::Standard),
            "high_volume" => Some(Self::HighVolume),
            _ => None,
        }
    }

    pub fn is_high_volume(self) -> bool {
        self == Self::HighVolume
    }
}

/// The storage mode of a live entity; `Standard` for one the table does not
/// know.
pub async fn storage_mode_of<'e, E>(executor: E, logicalname: &str) -> Result<StorageMode, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT storage_mode::text FROM entity_info \
          WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(logicalname)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?;
    Ok(stored
        .as_deref()
        .and_then(StorageMode::parse)
        .unwrap_or_default())
}

/// The 422 a unique rule on a high-volume entity gets.
pub fn unique_needs_partition_key(logicalname: &str) -> AppError {
    AppError::Validation(format!(
        "unique_needs_partition_key: {logicalname} is a high-volume entity; a unique rule on it \
         would have to include {PARTITION_COLUMN}, which a business key cannot"
    ))
}

/// The partition job's step for high-volume entities (on the migrator
/// pool): every one keeps [`PARTITION_MONTHS_AHEAD`] months of partitions.
pub async fn maintain_partitions(db_migrator: &DbPool) -> Result<(), AppError> {
    let entities: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname::text FROM entity_info \
          WHERE storage_mode = 'high_volume' AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(db_migrator)
    .await
    .map_err(AppError::internal)?;
    for entity in entities {
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db_migrator,
            &entity,
            PARTITION_COLUMN,
            PARTITION_STORAGE_PARAMS,
            PARTITION_MONTHS_AHEAD,
        )
        .await?;
        if created > 0 {
            tracing::info!(%entity, created, "high-volume entity: partitions created");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_mode_round_trips() {
        for mode in [StorageMode::Standard, StorageMode::HighVolume] {
            assert_eq!(StorageMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(StorageMode::parse("partitioned"), None);
        assert_eq!(StorageMode::default(), StorageMode::Standard);
        assert!(
            unique_needs_partition_key("event")
                .to_string()
                .contains("unique_needs_partition_key")
                || matches!(unique_needs_partition_key("event"), AppError::Validation(_))
        );
    }
}
