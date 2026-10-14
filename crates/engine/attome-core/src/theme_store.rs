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

/// Puts an earlier version of a scope's theme back: that version is
/// published again (its colours still checked) and the current one retired.
pub async fn rollback(
    conn: &mut PgConnection,
    scope_kind: &str,
    scope_ref: &str,
    version: i32,
) -> Result<ThemeRow, AppError> {
    check_scope(scope_kind, scope_ref)?;
    let target: (Uuid, i64) = sqlx::query_as(
        "SELECT id, row_version FROM theme \
         WHERE scope_kind = $1 AND scope_ref = $2 AND version = $3 FOR UPDATE",
    )
    .bind(scope_kind)
    .bind(scope_ref)
    .bind(version)
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)?;
    publish(conn, target.0, target.1).await.map(|(row, _)| row)
}

/// One token that differs between a version and its scope's published one.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct TokenChange {
    pub field: String,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

/// The tokens `after` changes against `before`, field by field.
pub fn token_changes(before: &ThemeTokens, after: &ThemeTokens) -> Vec<TokenChange> {
    let as_map = |t: &ThemeTokens| match serde_json::to_value(t) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    let (b, a) = (as_map(before), as_map(after));
    let mut fields: Vec<&String> = b.keys().chain(a.keys()).collect();
    fields.sort();
    fields.dedup();
    fields
        .into_iter()
        .filter_map(|field| {
            let present = |m: &serde_json::Map<String, serde_json::Value>| {
                m.get(field).filter(|v| !v.is_null()).cloned()
            };
            let (old, new) = (present(&b), present(&a));
            (old != new).then(|| TokenChange {
                field: field.clone(),
                before: old,
                after: new,
            })
        })
        .collect()
}

/// What a version changes against its scope's published version (all of it
/// when nothing is published).
pub async fn diff(db: &attome_db::DbPool, id: Uuid) -> Result<Vec<TokenChange>, AppError> {
    let row: ThemeRow = sqlx::query_as(&format!("SELECT {COLUMNS} FROM theme WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(attome_db::classify)?
        .ok_or(AppError::NotFound)?;
    let published: Option<sqlx::types::Json<ThemeTokens>> = sqlx::query_scalar(
        "SELECT tokens FROM theme WHERE scope_kind = $1 AND scope_ref = $2 \
           AND status = 'published' AND id <> $3",
    )
    .bind(&row.scope_kind)
    .bind(&row.scope_ref)
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)?;
    let before = published.map(|p| p.0).unwrap_or_default();
    Ok(token_changes(&before, &row.tokens))
}

/// Where a request sits: each scope a published theme can target. A `None`
/// scope matches no theme.
#[derive(Debug, Default, Clone, Copy)]
pub struct BrandScope<'a> {
    /// An app's name.
    pub app: Option<&'a str>,
    /// The caller's business unit id.
    pub unit: Option<&'a str>,
    /// The request's host name, lower case and without a port.
    pub host: Option<&'a str>,
    pub portal: Option<&'a str>,
}

/// The order scopes merge in, the broadest first.
const RESOLVE_ORDER: [&str; 5] = ["deployment", "app", "unit", "domain", "portal"];

/// The published theme of each scope a request falls under, merged from the
/// deployment's outwards: deployment, app, unit, domain (`host`), portal. A
/// scope with no published theme adds nothing. The tag names the published
/// versions merged, so it changes whenever one does (an ETag).
pub async fn resolve(
    db: &attome_db::DbPool,
    scope: BrandScope<'_>,
) -> Result<(ThemeTokens, String), AppError> {
    type Row = (String, Uuid, i32, sqlx::types::Json<ThemeTokens>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT scope_kind, id, version, tokens FROM theme WHERE status = 'published' AND ( \
             scope_kind = 'deployment' \
             OR (scope_kind = 'app' AND scope_ref = $1) \
             OR (scope_kind = 'unit' AND scope_ref = $2) \
             OR (scope_kind = 'domain' AND scope_ref = $3) \
             OR (scope_kind = 'portal' AND scope_ref = $4))",
    )
    .bind(scope.app.unwrap_or(""))
    .bind(scope.unit.unwrap_or(""))
    .bind(scope.host.unwrap_or(""))
    .bind(scope.portal.unwrap_or(""))
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let mut theme = ThemeTokens::default();
    let mut used = String::new();
    for kind in RESOLVE_ORDER {
        if let Some((_, id, version, tokens)) = rows.iter().find(|(k, ..)| k == kind) {
            theme = merge(&theme, tokens);
            used.push_str(&format!("{id}:{version};"));
        }
    }
    Ok((theme, version_tag(&used)))
}

/// A short, stable tag for the published versions a resolve merged.
fn version_tag(used: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(used.as_bytes());
    hex::encode(&digest[..8])
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
    fn token_changes_name_only_what_differs() {
        use crate::theme_tokens::HexColor;
        let before = ThemeTokens {
            primary: Some(HexColor::parse("#111111").unwrap()),
            radius_px: Some(4),
            ..ThemeTokens::default()
        };
        let after = ThemeTokens {
            primary: Some(HexColor::parse("#222222").unwrap()),
            radius_px: Some(4),
            hide_vendor_name: Some(true),
            ..ThemeTokens::default()
        };
        let changes = token_changes(&before, &after);
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, vec!["hide_vendor_name", "primary"]);
        assert_eq!(changes[1].before, Some(serde_json::json!("#111111")));
        assert!(token_changes(&after, &after).is_empty());
    }

    #[test]
    fn version_tag_changes_with_the_versions() {
        assert_eq!(version_tag("a:1;"), version_tag("a:1;"));
        assert_ne!(version_tag("a:1;"), version_tag("a:2;"));
        assert_eq!(version_tag("").len(), 16);
    }

    #[test]
    fn scopes_are_checked() {
        assert!(check_scope("deployment", "").is_ok());
        assert!(check_scope("portal", "customers").is_ok());
        assert!(check_scope("portal", " ").is_err());
        assert!(check_scope("galaxy", "x").is_err());
    }
}
