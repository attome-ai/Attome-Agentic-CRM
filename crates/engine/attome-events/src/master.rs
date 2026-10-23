//! L1-T7: what a webhook body adds for a golden-record change
//! (`master.golden_changed`, written by the master-data rebuild).
//!
//! The body's `master` object carries the golden record's certification and,
//! when the subscription names its `external_system`, that system's own
//! external id for the record: its attached contribution's, else its A29
//! external-id link. A system that never sent the record gets `null`.

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// The event name the master-data rebuild writes.
pub const GOLDEN_CHANGED: &str = "master.golden_changed";

/// The `master` object of a golden-record change's webhook body.
pub async fn block(
    db: &DbPool,
    entity: &str,
    golden: Uuid,
    system: Option<&str>,
) -> Result<Value, AppError> {
    let certification: Option<String> = sqlx::query_scalar(
        "SELECT status FROM master_certification WHERE entity = $1 AND golden_id = $2",
    )
    .bind(entity)
    .bind(golden)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let external_id = match system {
        Some(system) => external_id(db, entity, golden, system).await?,
        None => None,
    };
    Ok(json!({
        "certification": certification.unwrap_or_else(|| "draft".to_owned()),
        "external_system": system,
        "external_id": external_id,
    }))
}

/// `system`'s own id for `golden`.
async fn external_id(
    db: &DbPool,
    entity: &str,
    golden: Uuid,
    system: &str,
) -> Result<Option<String>, AppError> {
    let table = format!("{entity}__contribution");
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(attome_core::quote_ident(&table))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if exists {
        let from_contribution: Option<String> = sqlx::query_scalar(&format!(
            "SELECT external_id FROM {} \
              WHERE golden_id = $1 AND source_system = $2 AND status = 'attached' \
              ORDER BY received_at DESC LIMIT 1",
            attome_core::quote_ident(&table)
        ))
        .bind(golden)
        .bind(system)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if from_contribution.is_some() {
            return Ok(from_contribution);
        }
    }
    sqlx::query_scalar(
        "SELECT external_id FROM external_id_link \
          WHERE entity = $1 AND record_id = $2 AND system = $3 LIMIT 1",
    )
    .bind(entity)
    .bind(golden)
    .bind(system)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}
