//! Brand themes (roadmap B13-T3): drafts, publishing behind the contrast
//! gate, and the theme a request sees.
//!
//! Each save of a scope's theme is a new numbered version; publishing one
//! retires the version published before it, so a scope has at most one
//! published theme (`theme_one_published`). A theme whose colours fail
//! [`crate::theme_tokens::check`] is refused with its report. The functions
//! that write take the caller's connection, so the caller writes its audit
//! event in the same transaction.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use attome_types::AppError;

use crate::theme_tokens::{ContrastReport, ThemeTokens, check, merge};

/// The scopes a theme can belong to.
pub const SCOPE_KINDS: &[&str] = &["deployment", "app", "unit", "domain", "portal"];

/// One version of a scope's theme.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ThemeRow {
    pub id: Uuid,
    pub scope_kind: String,
    pub scope_ref: String,
    pub version: i32,
    /// `draft`, `published` or `retired`.
    pub status: String,
    #[schema(value_type = ThemeTokens)]
    pub tokens: sqlx::types::Json<ThemeTokens>,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

const COLUMNS: &str =
    "id, scope_kind, scope_ref, version, status, tokens, created_at, published_at, row_version";

fn check_scope(scope_kind: &str, scope_ref: &str) -> Result<(), AppError> {
    if !SCOPE_KINDS.contains(&scope_kind) {
        return Err(AppError::Validation(format!(
            "scope_kind must be one of {}",
            SCOPE_KINDS.join(", ")
        )));
    }
    if scope_kind != "deployment" && scope_ref.trim().is_empty() {
        return Err(AppError::Validation(
            "scope_ref names the app, unit, domain or portal".into(),
        ));
    }
    if scope_ref.chars().count() > 200 {
        return Err(AppError::Validation(
            "scope_ref is at most 200 characters".into(),
        ));
    }
    Ok(())
}

/// Saves a new draft version of a scope's theme. Serialized per scope.
pub async fn save_draft(
    conn: &mut PgConnection,
    scope_kind: &str,
    scope_ref: &str,
    tokens: &ThemeTokens,
    actor: Uuid,
) -> Result<ThemeRow, AppError> {
    check_scope(scope_kind, scope_ref)?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-core/theme-version:{scope_kind}:{scope_ref}"
        ))
        .fetch_one(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
    if !locked {
        return Err(AppError::Conflict(
            "another save of this theme is in progress; retry",
        ));
    }
    sqlx::query_as(&format!(
        "INSERT INTO theme (id, scope_kind, scope_ref, version, status, tokens, created_by) \
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, 'draft', $4, $5 \
         FROM theme WHERE scope_kind = $2 AND scope_ref = $3 \
         RETURNING {COLUMNS}"
    ))
    .bind(Uuid::now_v7())
    .bind(scope_kind)
    .bind(scope_ref)
    .bind(sqlx::types::Json(tokens))
    .bind(actor)
    .fetch_one(&mut *conn)
    .await
    .map_err(attome_db::classify)
}

/// Replaces a draft's tokens; a stale `row_version` is a conflict, and a
/// published or retired version is never edited (save a new draft instead).
pub async fn update_draft(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
    tokens: &ThemeTokens,
) -> Result<ThemeRow, AppError> {
    let row: Option<ThemeRow> = sqlx::query_as(&format!(
        "UPDATE theme SET tokens = $3, row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'draft' RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(sqlx::types::Json(tokens))
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    match row {
        Some(row) => Ok(row),
        None => {
            let status: Option<String> =
                sqlx::query_scalar("SELECT status FROM theme WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(attome_db::classify)?;
            match status.as_deref() {
                None => Err(AppError::NotFound),
                Some("draft") => Err(AppError::Conflict("version_conflict")),
                Some(_) => Err(AppError::Validation(
                    "only a draft is edited; save a new draft instead".into(),
                )),
            }
        }
    }
}

/// Publishes a version: refused with its contrast report when its colours
/// fail; otherwise the scope's published version is retired and this one
/// published, in the caller's transaction.
pub async fn publish(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
) -> Result<(ThemeRow, ContrastReport), AppError> {
    let row: ThemeRow = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM theme WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)?;
    let report = check(&row.tokens);
    if !report.passed {
        let named: Vec<String> = report
            .failures
            .iter()
            .map(|f| {
                format!(
                    "{} ({}) is {} where {} is needed",
                    f.pair, f.mode, f.ratio, f.required
                )
            })
            .collect();
        return Err(AppError::Validation(format!(
            "the theme's colours do not read clearly enough: {}",
            named.join("; ")
        )));
    }
    sqlx::query(
        "UPDATE theme SET status = 'retired', row_version = row_version + 1 \
         WHERE scope_kind = $1 AND scope_ref = $2 AND status = 'published' AND id <> $3",
    )
    .bind(&row.scope_kind)
    .bind(&row.scope_ref)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    let published: Option<ThemeRow> = sqlx::query_as(&format!(
        "UPDATE theme SET status = 'published', published_at = now(), contrast_report = $3, \
                row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(sqlx::types::Json(&report))
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    let published = published.ok_or(AppError::Conflict("version_conflict"))?;
    Ok((published, report))
}

/// The published theme of each scope a request falls under, merged from the
/// deployment's outwards: deployment, then the domain (`host`), then the
/// portal. A scope with no published theme adds nothing.
pub async fn resolve(
    db: &attome_db::DbPool,
    host: Option<&str>,
    portal: Option<&str>,
) -> Result<ThemeTokens, AppError> {
    let rows: Vec<(String, sqlx::types::Json<ThemeTokens>)> = sqlx::query_as(
        "SELECT scope_kind, tokens FROM theme WHERE status = 'published' AND ( \
             scope_kind = 'deployment' \
             OR (scope_kind = 'domain' AND scope_ref = $1) \
             OR (scope_kind = 'portal' AND scope_ref = $2))",
    )
    .bind(host.unwrap_or(""))
    .bind(portal.unwrap_or(""))
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let mut theme = ThemeTokens::default();
    for kind in ["deployment", "domain", "portal"] {
        if let Some((_, tokens)) = rows.iter().find(|(k, _)| k == kind) {
            theme = merge(&theme, tokens);
        }
    }
    Ok(theme)
}

/// A page of themes, newest version first.
pub async fn list(
    db: &attome_db::DbPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ThemeRow>, i64), AppError> {
    let rows: Vec<ThemeRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM theme ORDER BY scope_kind, scope_ref, version DESC LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM theme")
        .fetch_one(db)
        .await
        .map_err(attome_db::classify)?;
    Ok((rows, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_checked() {
        assert!(check_scope("deployment", "").is_ok());
        assert!(check_scope("portal", "customers").is_ok());
        assert!(check_scope("portal", " ").is_err());
        assert!(check_scope("galaxy", "x").is_err());
    }
}
