//! Z1-T7: the record of node starts and the configuration each started
//! with (`config_start`, migration 0118). Boot writes one row per start;
//! administrators list them and compare two (`config_admin`).

use attome_config::fingerprint::{ChangedKey, diff as diff_views};
use attome_db::DbPool;
use attome_types::{AppError, PageWindow, PaginatedResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// One start, without its view.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct ConfigStartRow {
    pub id: Uuid,
    pub node_name: String,
    pub started_at: DateTime<Utc>,
    pub app_version: String,
    pub fingerprint: String,
}

/// Records this start.
pub async fn record_start(
    db: &DbPool,
    node: &str,
    version: &str,
    fingerprint: &str,
    view: &Value,
) -> Result<Uuid, AppError> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO config_start (id, node_name, app_version, fingerprint, view) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(node)
    .bind(version)
    .bind(fingerprint)
    .bind(view)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Starts, newest first.
pub async fn list(
    db: &DbPool,
    window: PageWindow,
) -> Result<PaginatedResponse<ConfigStartRow>, AppError> {
    let items: Vec<ConfigStartRow> = sqlx::query_as(
        "SELECT id, node_name, started_at, app_version, fingerprint FROM config_start \
         ORDER BY started_at DESC, id DESC LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM config_start")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

async fn view(db: &DbPool, id: Uuid) -> Result<Value, AppError> {
    sqlx::query_scalar("SELECT view FROM config_start WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// The configuration keys that differ from start `a` to start `b`.
pub async fn diff(db: &DbPool, a: Uuid, b: Uuid) -> Result<Vec<ChangedKey>, AppError> {
    Ok(diff_views(&view(db, a).await?, &view(db, b).await?))
}
