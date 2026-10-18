//! The reference graph (roadmap Y1-T4): every object's outgoing references,
//! replaced on each save in the save's own transaction, in the existing
//! `metadata_reference` table.
//!
//! A metadata-model target is written as `to_entity = '<kind>:<object id>'`
//! with an empty `to_attribute` (migration 0012), so the table's unique
//! `(from_kind, from_ref, to_entity, to_attribute)` index still holds one row
//! per source and target and the existing name-based readers are untouched.
//!
//! A reference to an object that does not exist is *dangling*. It does not
//! block saving a draft (the target may be created next); publishing refuses
//! it (Y1-T5).

use attome_db::{DbPool, Tx};
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::KindRegistry;
use crate::identity::{ObjectId, ObjectRef};
use crate::kind::{Issue, RefMode, Reference};

impl RefMode {
    /// The stored value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reads => "reads",
            Self::Writes => "writes",
            Self::Triggers => "triggers",
        }
    }
}

/// The stored target of a reference to a metadata-model object.
pub fn target_key(target: &ObjectRef) -> String {
    format!("{}:{}", target.kind, target.id)
}

/// Replaces `source`'s outgoing references with `refs`, in `tx`.
pub async fn replace_references(
    tx: &mut Tx<'_>,
    source: &ObjectRef,
    refs: &[Reference],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM metadata_reference WHERE from_kind = $1 AND from_ref = $2")
        .bind(source.kind.as_str())
        .bind(source.id.0)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    let mut seen = std::collections::BTreeSet::new();
    for reference in refs {
        // One row per target: the strongest use wins (triggers > writes > reads).
        if !seen.insert(target_key(&reference.target)) {
            continue;
        }
        let mode = refs
            .iter()
            .filter(|r| r.target == reference.target)
            .map(|r| r.mode)
            .max()
            .unwrap_or(reference.mode);
        sqlx::query(
            "INSERT INTO metadata_reference (from_kind, from_ref, to_entity, to_attribute, mode) \
             VALUES ($1, $2, $3, '', $4)",
        )
        .bind(source.kind.as_str())
        .bind(source.id.0)
        .bind(target_key(&reference.target))
        .bind(mode.as_str())
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// The targets of `refs` that do not exist. A target of an adapter kind is
/// looked up in that kind's own table; any other target in the metadata
/// object store. A target of an unknown kind does not exist.
pub async fn missing_targets(
    tx: &mut Tx<'_>,
    registry: &KindRegistry,
    refs: &[Reference],
) -> Result<Vec<ObjectRef>, AppError> {
    let mut missing = Vec::new();
    for reference in refs {
        let target = &reference.target;
        let exists = match registry.get(target.kind.as_str()) {
            None => false,
            Some(kind) => match kind.adapter_table() {
                // A code-literal table name the kind declares, never input.
                Some(table) => sqlx::query_scalar(&format!(
                    "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1)"
                ))
                .bind(target.id.0)
                .fetch_one(&mut **tx)
                .await
                .map_err(AppError::internal)?,
                None => sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM metadata_object \
                     WHERE id = $1 AND kind = $2 AND is_active)",
                )
                .bind(target.id.0)
                .bind(target.kind.as_str())
                .fetch_one(&mut **tx)
                .await
                .map_err(AppError::internal)?,
            },
        };
        if !exists && !missing.contains(target) {
            missing.push(*target);
        }
    }
    Ok(missing)
}

/// The issue reported for a reference to an object that does not exist.
pub fn dangling_issue(target: &ObjectRef) -> Issue {
    Issue::new(
        "",
        "dangling_reference",
        format!("{} {} does not exist", target.kind, target.id),
    )
}

/// Issues for the references whose target does not exist.
pub async fn dangling(
    tx: &mut Tx<'_>,
    registry: &KindRegistry,
    refs: &[Reference],
) -> Result<Vec<Issue>, AppError> {
    Ok(missing_targets(tx, registry, refs)
        .await?
        .iter()
        .map(dangling_issue)
        .collect())
}

/// One stored reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct ReferenceRow {
    pub from_kind: String,
    pub from_ref: Uuid,
    pub to_entity: String,
    pub to_attribute: String,
    pub mode: String,
    pub created_at: DateTime<Utc>,
}

const ROW_COLUMNS: &str = "from_kind, from_ref, to_entity, to_attribute, mode, created_at";
const ROW_ORDER: &str = "ORDER BY from_kind, from_ref, to_entity, to_attribute";

/// The references pointing at `target`.
pub async fn references_in(
    pool: &DbPool,
    target: &ObjectRef,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<ReferenceRow>, AppError> {
    let window = page.window();
    let key = target_key(target);
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metadata_reference WHERE to_entity = $1")
            .bind(&key)
            .fetch_one(pool)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<ReferenceRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM metadata_reference WHERE to_entity = $1 {ROW_ORDER} LIMIT $2 OFFSET $3"
    ))
    .bind(&key)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    })
}

/// The references `source` makes.
pub async fn references_out(
    pool: &DbPool,
    source: &ObjectRef,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<ReferenceRow>, AppError> {
    let window = page.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM metadata_reference WHERE from_kind = $1 AND from_ref = $2",
    )
    .bind(source.kind.as_str())
    .bind(source.id.0)
    .fetch_one(pool)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<ReferenceRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM metadata_reference WHERE from_kind = $1 AND from_ref = $2 \
         {ROW_ORDER} LIMIT $3 OFFSET $4"
    ))
    .bind(source.kind.as_str())
    .bind(source.id.0)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    })
}

/// The source of a stored model reference, parsed back from `to_entity`.
pub fn parse_target(to_entity: &str) -> Option<(String, ObjectId)> {
    let (kind, id) = to_entity.split_once(':')?;
    Some((kind.to_owned(), ObjectId(Uuid::parse_str(id).ok()?)))
}
