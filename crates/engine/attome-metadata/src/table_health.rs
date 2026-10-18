//! Table health (roadmap Y2-T8): per entity table, its size, live and dead
//! rows, last autovacuum, indexes never used, lookup fields with no index
//! leading on them, and growth over seven days, read from PostgreSQL's
//! statistics views only (never business rows). Here so both the admin
//! route (`attome-api`) and the agents' read tool (`table.health`, Y2-T14)
//! use one reading.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

/// One entity table's health.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct TableHealth {
    pub entity: String,
    pub total_bytes: i64,
    pub live_rows: i64,
    pub dead_rows: i64,
    /// Dead rows over all rows; 0 for an empty table.
    pub dead_ratio: f64,
    pub last_autovacuum: Option<DateTime<Utc>>,
    /// Indexes never scanned since statistics were reset (unique and primary
    /// keys excepted: they enforce rules even unscanned).
    pub unused_indexes: Vec<String>,
    /// Lookup fields no index leads on.
    pub lookups_without_index: Vec<String>,
    /// Live rows added over the last seven days, when a sample exists.
    pub growth_rows_7d: Option<i64>,
}

/// Dead rows over all rows.
pub fn dead_ratio(live: i64, dead: i64) -> f64 {
    let total = live.saturating_add(dead);
    if total <= 0 {
        0.0
    } else {
        dead as f64 / total as f64
    }
}

/// The lookups among `lookups` that no index leads on.
pub fn unindexed(lookups: &[String], leading: &[String]) -> Vec<String> {
    lookups
        .iter()
        .filter(|l| !leading.contains(l))
        .cloned()
        .collect()
}

/// One entity's health from the statistics views.
pub async fn health_of(state: &EngineState, entity: &str) -> Result<TableHealth, AppError> {
    let lookups: Vec<String> = {
        let registry = state.entities.load();
        let meta = registry.get(entity).ok_or(AppError::NotFound)?;
        meta.attrs
            .iter()
            .filter(|a| a.field_type_int == 11)
            .map(|a| a.logicalname.clone())
            .collect()
    };
    let db = &state.base.db;
    let stats: Option<(i64, i64, Option<DateTime<Utc>>, i64)> = sqlx::query_as(
        "SELECT COALESCE(s.n_live_tup, 0), COALESCE(s.n_dead_tup, 0), s.last_autovacuum, \
                pg_total_relation_size(s.relid) \
         FROM pg_stat_user_tables s WHERE s.relid = to_regclass($1)",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (live, dead, vacuum, bytes) = stats.unwrap_or((0, 0, None, 0));
    let unused: Vec<String> = sqlx::query_scalar(
        "SELECT s.indexrelname::text FROM pg_stat_user_indexes s \
         JOIN pg_index i ON i.indexrelid = s.indexrelid \
         WHERE s.relid = to_regclass($1) AND s.idx_scan = 0 \
           AND NOT i.indisunique AND NOT i.indisprimary \
         ORDER BY 1",
    )
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let leading: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.attname::text FROM pg_index i \
         JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] \
         WHERE i.indrelid = to_regclass($1)",
    )
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let week_ago: Option<i64> = sqlx::query_scalar(
        "SELECT live_rows FROM table_health_sample \
         WHERE entity = $1 AND sampled_on <= now()::date - 7 \
         ORDER BY sampled_on DESC LIMIT 1",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(TableHealth {
        entity: entity.to_owned(),
        total_bytes: bytes,
        live_rows: live,
        dead_rows: dead,
        dead_ratio: dead_ratio(live, dead),
        last_autovacuum: vacuum,
        unused_indexes: unused,
        lookups_without_index: unindexed(&lookups, &leading),
        growth_rows_7d: week_ago.map(|then| live - then),
    })
}
