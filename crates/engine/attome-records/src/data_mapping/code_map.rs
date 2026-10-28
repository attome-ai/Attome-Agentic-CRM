//! L1-T8: reference-data code mappings, versioned. A source system's code in
//! one of its code lists (an ERP's `"03"` in `country`) maps to the value
//! this deployment stores (`"EG"`). Every edit is a new version row; old
//! versions stay, and the newest version already in effect (`valid_from` not
//! in the future) is the one used. A version with no value retires the code.
//!
//! Imports apply them through a mapping field's `code_map`
//! ([`super::DataMappingField`]): the cell is the source code, and the
//! stored value is what it maps to now.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Longest system, code list, code or value accepted.
pub const MAX_PART_LEN: usize = 200;

/// One version of one code's mapping.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct CodeMapVersion {
    pub id: Uuid,
    pub source_system: String,
    pub code_list: String,
    pub code: String,
    /// What the code maps to; absent when this version retires it.
    pub value: Option<String>,
    /// 1 for the first mapping of this code, one more for every edit.
    pub version: i32,
    /// When this version takes effect.
    pub valid_from: DateTime<Utc>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

const COLUMNS: &str =
    "id, source_system, code_list, code, value, version, valid_from, created_by, created_at";

/// Rejects an empty or overlong part. Pure.
pub fn validate_part(what: &str, part: &str) -> Result<(), AppError> {
    if part.trim().is_empty() {
        return Err(AppError::Validation(format!("{what} must not be empty")));
    }
    if part.chars().count() > MAX_PART_LEN {
        return Err(AppError::Validation(format!(
            "{what} must be at most {MAX_PART_LEN} characters"
        )));
    }
    Ok(())
}

/// Writes a new version of `code`'s mapping in `tx`: one more than its
/// newest, effective from `valid_from` (now when absent). Never updates a
/// row. Two edits of one code at once race for the same version number; the
/// unique key refuses the second, which is a `Conflict` to retry.
pub async fn set_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source_system: &str,
    code_list: &str,
    code: &str,
    value: Option<&str>,
    valid_from: Option<DateTime<Utc>>,
    actor: Uuid,
) -> Result<CodeMapVersion, AppError> {
    validate_part("source_system", source_system)?;
    validate_part("code_list", code_list)?;
    validate_part("code", code)?;
    if let Some(value) = value {
        validate_part("value", value)?;
    }
    sqlx::query_as(&format!(
        "INSERT INTO reference_code_map \
             (source_system, code_list, code, value, version, valid_from, created_by) \
         SELECT $1, $2, $3, $4, COALESCE(MAX(version), 0) + 1, COALESCE($5, now()), $6 \
           FROM reference_code_map \
          WHERE source_system = $1 AND code_list = $2 AND code = $3 \
         RETURNING {COLUMNS}"
    ))
    .bind(source_system)
    .bind(code_list)
    .bind(code)
    .bind(value)
    .bind(valid_from)
    .bind(actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(crate::entity_mutation::classify_db_error)
}

/// The value `code` maps to now: the newest version in effect, `None` when
/// there is none or it retires the code.
pub async fn map_code(
    db: &attome_db::DbPool,
    source_system: &str,
    code_list: &str,
    code: &str,
) -> Result<Option<String>, AppError> {
    let value: Option<Option<String>> = sqlx::query_scalar(
        "SELECT value FROM reference_code_map \
          WHERE source_system = $1 AND code_list = $2 AND code = $3 AND valid_from <= now() \
          ORDER BY version DESC LIMIT 1",
    )
    .bind(source_system)
    .bind(code_list)
    .bind(code)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(value.flatten())
}

/// The mappings of one code list in effect now, one row per code, by code;
/// retired codes are left out. With `history`, every version of every code
/// instead, newest first per code. A page and the total.
pub async fn list(
    db: &attome_db::DbPool,
    source_system: &str,
    code_list: &str,
    history: bool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<CodeMapVersion>, i64), AppError> {
    // Literal statements: every column named, nothing spliced in.
    let (rows_sql, count_sql) = if history {
        (
            "SELECT id, source_system, code_list, code, value, version, valid_from, created_by,                     created_at                FROM reference_code_map WHERE source_system = $1 AND code_list = $2               ORDER BY code, version DESC LIMIT $3 OFFSET $4",
            "SELECT COUNT(*) FROM reference_code_map WHERE source_system = $1 AND code_list = $2",
        )
    } else {
        (
            "SELECT id, source_system, code_list, code, value, version, valid_from, created_by,                     created_at FROM (                  SELECT DISTINCT ON (code) id, source_system, code_list, code, value, version,                         valid_from, created_by, created_at                    FROM reference_code_map                   WHERE source_system = $1 AND code_list = $2 AND valid_from <= now()                   ORDER BY code, version DESC              ) current WHERE value IS NOT NULL ORDER BY code LIMIT $3 OFFSET $4",
            "SELECT COUNT(*) FROM (                  SELECT DISTINCT ON (code) value FROM reference_code_map                   WHERE source_system = $1 AND code_list = $2 AND valid_from <= now()                   ORDER BY code, version DESC              ) current WHERE value IS NOT NULL",
        )
    };
    let items: Vec<CodeMapVersion> = sqlx::query_as(rows_sql)
        .bind(source_system)
        .bind(code_list)
        .bind(limit)
        .bind(offset)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(count_sql)
        .bind(source_system)
        .bind(code_list)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok((items, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_are_bounded() {
        assert!(validate_part("code", "03").is_ok());
        assert!(validate_part("code", "  ").is_err());
        assert!(validate_part("code", &"x".repeat(MAX_PART_LEN + 1)).is_err());
    }
}
