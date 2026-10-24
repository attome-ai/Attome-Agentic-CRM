//! L1-T6: a master entity's cross-references, read through its
//! contributions (`<entity>__contribution`).
//!
//! - [`golden_for`] finds the golden record a source system's id belongs
//!   to: one lookup on the contribution's `(source_system, external_id)`
//!   unique key.
//! - [`system_ids`] lists every source system id a golden record carries,
//!   through the contribution's `golden_id` index.
//! - [`provenance`] lists where each attribute's value came from (L1-T9's
//!   golden record panel): the contribution, its system and the rule.
//!
//! None checks access: the caller reads the golden record as the person
//! first, so a record they cannot read stays `NotFound`. Payloads are never
//! returned; they may carry attributes the person cannot read.

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_metadata::provision::master::{contribution_table, provenance_table};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The most system ids one golden record lists.
pub const MAX_SYSTEM_IDS: i64 = 500;

/// One source system's id for a golden record.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SystemId {
    /// The contribution's id, for a steward's detach.
    pub id: Uuid,
    pub source_system: String,
    pub external_id: String,
    /// `attached`, `held` or `detached`.
    pub status: String,
    pub received_at: DateTime<Utc>,
}

/// The golden record `system`'s `external_id` belongs to, with its
/// contribution's status; `None` when the id is unknown or not (or no
/// longer) linked to a golden record.
pub async fn golden_for(
    db: &DbPool,
    entity: &str,
    system: &str,
    external_id: &str,
) -> Result<Option<(Uuid, String)>, AppError> {
    let row: Option<(Option<Uuid>, String)> = sqlx::query_as(&format!(
        "SELECT golden_id, status FROM {} WHERE source_system = $1 AND external_id = $2",
        quote_ident(&contribution_table(entity))
    ))
    .bind(system)
    .bind(external_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|(golden, status)| golden.map(|g| (g, status))))
}

/// Every source system id `golden` carries, by system then id.
pub async fn system_ids(
    db: &DbPool,
    entity: &str,
    golden: Uuid,
) -> Result<Vec<SystemId>, AppError> {
    sqlx::query_as(&format!(
        "SELECT id, source_system, external_id, status, received_at FROM {} \
          WHERE golden_id = $1 ORDER BY source_system, external_id LIMIT $2",
        quote_ident(&contribution_table(entity))
    ))
    .bind(golden)
    .bind(MAX_SYSTEM_IDS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Where one attribute's golden value came from.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Provenance {
    pub attribute: String,
    /// The rule that chose it: `source_system_rank`, `most_recent`, or `pinned`.
    pub rule: String,
    pub chosen_at: DateTime<Utc>,
    pub pinned_by: Option<Uuid>,
    /// The contribution it came from; none for a pinned value set by hand or
    /// a contribution since removed.
    pub contribution_id: Option<Uuid>,
    pub source_system: Option<String>,
    pub external_id: Option<String>,
    pub received_at: Option<DateTime<Utc>>,
}

/// Every attribute's provenance on `golden`, by attribute.
pub async fn provenance(
    db: &DbPool,
    entity: &str,
    golden: Uuid,
) -> Result<Vec<Provenance>, AppError> {
    sqlx::query_as(&format!(
        "SELECT p.attribute, p.rule, p.chosen_at, p.pinned_by, p.contribution_id, \
                c.source_system, c.external_id, c.received_at \
           FROM {} p LEFT JOIN {} c ON c.id = p.contribution_id \
          WHERE p.golden_id = $1 ORDER BY p.attribute",
        quote_ident(&provenance_table(entity)),
        quote_ident(&contribution_table(entity))
    ))
    .bind(golden)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}
