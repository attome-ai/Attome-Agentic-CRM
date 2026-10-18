//! Table health (roadmap Y2-T8): per entity table, its size, live and dead
//! rows, last autovacuum, indexes never used, lookup fields with no index
//! leading on them, and growth over seven days. Read from PostgreSQL's
//! statistics views only (never business rows); a daily job keeps one
//! sample per table (`table_health_sample`) for the growth figure.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

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

/// Y2-T9: the fill factor an entity table should have, from what its rows
/// do, or `None` to leave it. An append-only table packs its pages full
/// (100); a table updated more than inserted whose updates mostly miss
/// heap-only (HOT) updates leaves room on each page for them (80).
pub fn recommend_fillfactor(
    is_append_only: bool,
    inserts: i64,
    updates: i64,
    hot_updates: i64,
    current: i32,
) -> Option<i32> {
    let wanted = if is_append_only {
        100
    } else if updates > inserts && updates > 0 && (hot_updates as f64 / updates as f64) < 0.5 {
        80
    } else {
        return None;
    };
    (wanted != current).then_some(wanted)
}

/// Y2-T9: sets the recommended fill factor on every entity table that needs
/// a change (`metadata.storage_tuning_enabled`), each in its own bounded
/// transaction on the migrator pool (`ALTER TABLE ... SET` takes a lock that
/// blocks neither reads nor writes, and applies to pages written from now).
/// A table whose lock does not come within the DDL bound is skipped with a
/// warning and tried again tomorrow. Returns the tables changed.
pub async fn tune_storage(state: &EngineState) -> Result<u64, AppError> {
    let entities: Vec<(String, bool)> = state
        .entities
        .load()
        .iter()
        .map(|m| (m.logicalname.clone(), m.is_append_only))
        .collect();
    let names: Vec<String> = entities.iter().map(|(n, _)| n.clone()).collect();
    let stats: Vec<(String, i64, i64, i64, i32)> = sqlx::query_as(
        "SELECT e.name, COALESCE(s.n_tup_ins, 0), COALESCE(s.n_tup_upd, 0), \
                COALESCE(s.n_tup_hot_upd, 0), \
                COALESCE((SELECT substring(o FROM 'fillfactor=([0-9]+)')::int \
                            FROM unnest(c.reloptions) AS o WHERE o LIKE 'fillfactor=%'), 100) \
           FROM unnest($1::text[]) AS e(name) \
           JOIN pg_class c ON c.oid = to_regclass(e.name) \
           LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid",
    )
    .bind(&names)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut changed = 0;
    for (entity, inserts, updates, hot, current) in stats {
        let append_only = entities
            .iter()
            .any(|(name, append_only)| *name == entity && *append_only);
        let Some(wanted) = recommend_fillfactor(append_only, inserts, updates, hot, current) else {
            continue;
        };
        if !attome_db::ident::is_identifier(&entity) {
            continue;
        }
        let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
        attome_metadata::provision::field_change::set_ddl_bounds_in_tx(&mut tx).await?;
        let altered = sqlx::query(&format!(
            "ALTER TABLE {} SET (fillfactor = {wanted})",
            attome_core::quote_ident(&entity)
        ))
        .execute(&mut *tx)
        .await;
        match altered {
            Ok(_) => {
                attome_db::tx::commit(tx).await?;
                tracing::info!(entity = %entity, old = current, new = wanted, updates, hot_updates = hot, "storage tuning: fill factor changed");
                changed += 1;
            }
            Err(error) => {
                tracing::warn!(entity = %entity, %error, "storage tuning: fill factor not changed (lock not granted in time); next run retries");
            }
        }
    }
    Ok(changed)
}

/// The daily sample of every entity table; tables sampled.
pub async fn sample_all(state: &EngineState) -> Result<u64, AppError> {
    let entities: Vec<String> = state
        .entities
        .load()
        .iter()
        .map(|m| m.logicalname.clone())
        .collect();
    let inserted = sqlx::query(
        "INSERT INTO table_health_sample (entity, sampled_on, live_rows, total_bytes) \
         SELECT e.name, now()::date, COALESCE(s.n_live_tup, 0), pg_total_relation_size(s.relid) \
         FROM unnest($1::text[]) AS e(name) \
         JOIN pg_stat_user_tables s ON s.relid = to_regclass(e.name) \
         ON CONFLICT (entity, sampled_on) DO UPDATE \
             SET live_rows = EXCLUDED.live_rows, total_bytes = EXCLUDED.total_bytes",
    )
    .bind(&entities)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    // Samples past a year are no longer needed for growth.
    sqlx::query("DELETE FROM table_health_sample WHERE sampled_on < now()::date - 400")
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(inserted)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/health",
    tag = "admin-entities",
    params(("entity_id" = Uuid, Path, description = "The entity")),
    responses(
        (status = 200, description = "The entity table's health", body = TableHealth),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_entity_health(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<TableHealth>, AppError> {
    let entity = state
        .entities
        .load()
        .get_by_id(entity_id)
        .map(|m| m.logicalname.clone())
        .ok_or(AppError::NotFound)?;
    Ok(Json(health_of(&state, &entity).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/table-health",
    tag = "admin-entities",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Every entity table's health, largest first", body = PaginatedResponse<TableHealth>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_table_health(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<TableHealth>>, AppError> {
    let window = page.window();
    let entities: Vec<String> = state
        .entities
        .load()
        .iter()
        .map(|m| m.logicalname.clone())
        .collect();
    // Largest first, by the statistics views alone.
    let ordered: Vec<String> = sqlx::query_scalar(
        "SELECT e.name FROM unnest($1::text[]) AS e(name) \
         LEFT JOIN pg_stat_user_tables s ON s.relid = to_regclass(e.name) \
         ORDER BY pg_total_relation_size(s.relid) DESC NULLS LAST, e.name",
    )
    .bind(&entities)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = ordered.len() as i64;
    let mut items = Vec::new();
    for entity in ordered
        .iter()
        .skip(usize::try_from(window.offset).unwrap_or(0))
        .take(usize::try_from(window.page_size).unwrap_or(0))
    {
        items.push(health_of(&state, entity).await?);
    }
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/entities/{entity_id}/health",
            get(get_entity_health),
        )
        .route("/api/v1/admin/table-health", get(get_table_health))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_entity_health, get_table_health),
    components(schemas(TableHealth))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_hot_ratio_lowers_fillfactor() {
        // Updated more than inserted, a fifth of updates HOT: leave room.
        assert_eq!(recommend_fillfactor(false, 100, 1_000, 200, 100), Some(80));
        // Already 80: nothing to do.
        assert_eq!(recommend_fillfactor(false, 100, 1_000, 200, 80), None);
        // Mostly HOT already, or mostly inserts: unchanged.
        assert_eq!(recommend_fillfactor(false, 100, 1_000, 900, 100), None);
        assert_eq!(recommend_fillfactor(false, 5_000, 1_000, 0, 100), None);
        // Append-only packs pages full.
        assert_eq!(recommend_fillfactor(true, 5_000, 0, 0, 80), Some(100));
        assert_eq!(recommend_fillfactor(true, 5_000, 0, 0, 100), None);
    }

    #[test]
    fn dead_ratio_and_unindexed_lookups() {
        assert_eq!(dead_ratio(0, 0), 0.0);
        assert!((dead_ratio(75, 25) - 0.25).abs() < f64::EPSILON);
        let lookups = vec!["account_ref".to_owned(), "owner_ref".to_owned()];
        let leading = vec!["id".to_owned(), "owner_ref".to_owned()];
        assert_eq!(
            unindexed(&lookups, &leading),
            vec!["account_ref".to_owned()]
        );
    }
}
