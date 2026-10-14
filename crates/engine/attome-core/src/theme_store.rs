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

/// A theme's text tokens: an app name of 1 to 60 characters with no
/// control characters.
fn check_text(tokens: &ThemeTokens) -> Result<(), AppError> {
    if let Some(name) = &tokens.app_name {
        let n = name.trim().chars().count();
        if n == 0 || n > 60 || name.chars().any(char::is_control) {
            return Err(AppError::Validation(
                "app_name is 1 to 60 characters with no control characters".into(),
            ));
        }
    }
    Ok(())
}

/// B13-T10: the deployment's published brand for an email: its app name,
/// logo (an absolute URL under `base_url`) and primary colour. A failure to
/// read it is logged and gives the plain email; branding never stops a
/// password reset.
pub async fn email_brand(
    db: &attome_db::DbPool,
    base_url: &str,
) -> attome_email::templates::BrandContext {
    let scope = BrandScope::default();
    let tokens = match resolve(db, scope).await {
        Ok((tokens, _)) => tokens,
        Err(error) => {
            tracing::warn!(%error, "brand for an email unavailable; sending it unbranded");
            return attome_email::templates::BrandContext::default();
        }
    };
    let logo = match published_assets(db, scope).await {
        Ok(assets) => assets.into_iter().find(|a| a.kind == "logo"),
        Err(error) => {
            tracing::warn!(%error, "brand logo for an email unavailable; sending it without");
            None
        }
    };
    attome_email::templates::BrandContext {
        app_name: tokens.app_name,
        logo_url: logo.map(|a| {
            let short = a.sha256.get(..12).unwrap_or(&a.sha256);
            format!(
                "{}/api/v1/branding/asset?kind=logo&v={short}",
                base_url.trim_end_matches('/')
            )
        }),
        primary: tokens.primary.map(|p| p.as_str().to_owned()),
    }
}

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
    check_text(tokens)?;
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
    let row: ThemeRow = sqlx::query_as(&format!(
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
    .map_err(attome_db::classify)?;
    // A new version keeps the previous version's logo, favicon and fonts
    // until it is given new ones.
    let previous: Vec<(String, String, String, i64, String)> = sqlx::query_as(
        "SELECT a.kind, a.storage_key, a.content_type, a.byte_size, a.sha256 \
         FROM brand_asset a JOIN theme t ON t.id = a.theme_id \
         WHERE t.scope_kind = $1 AND t.scope_ref = $2 AND t.version = $3",
    )
    .bind(scope_kind)
    .bind(scope_ref)
    .bind(row.version - 1)
    .fetch_all(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    for (kind, storage_key, content_type, byte_size, sha256) in previous {
        sqlx::query(
            "INSERT INTO brand_asset (id, theme_id, kind, storage_key, content_type, byte_size, sha256) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(row.id)
        .bind(kind)
        .bind(storage_key)
        .bind(content_type)
        .bind(byte_size)
        .bind(sha256)
        .execute(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
    }
    Ok(row)
}

/// Replaces a draft's tokens; a stale `row_version` is a conflict, and a
/// published or retired version is never edited (save a new draft instead).
pub async fn update_draft(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
    tokens: &ThemeTokens,
) -> Result<ThemeRow, AppError> {
    check_text(tokens)?;
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

/// The themes a [`BrandScope`] falls under, for a query on `theme t` that
/// binds app, unit, host and portal as `$1` to `$4`.
const IN_SCOPE: &str = "(t.scope_kind = 'deployment' \
     OR (t.scope_kind = 'app' AND t.scope_ref = $1) \
     OR (t.scope_kind = 'unit' AND t.scope_ref = $2) \
     OR (t.scope_kind = 'domain' AND t.scope_ref = $3) \
     OR (t.scope_kind = 'portal' AND t.scope_ref = $4))";

/// Each kind of brand asset and the content types it accepts.
pub const ASSET_KINDS: [(&str, &[&str]); 6] = [
    ("logo", &["image/png", "image/svg+xml"]),
    ("logo_dark", &["image/png", "image/svg+xml"]),
    ("favicon", &["image/png", "image/x-icon", "image/svg+xml"]),
    ("font_arabic", &["font/woff2"]),
    ("font_latin", &["font/woff2"]),
    ("guidelines_pdf", &["application/pdf"]),
];

/// The largest brand asset accepted.
pub const MAX_ASSET_BYTES: usize = 2 * 1024 * 1024;

/// Asset kinds served without a session (the sign-in page needs them); the
/// guidelines PDF is for administrators only.
pub const PUBLIC_ASSET_KINDS: [&str; 5] =
    ["logo", "logo_dark", "favicon", "font_arabic", "font_latin"];

/// Checks an upload before it is stored: a known kind, a content type that
/// kind accepts, at most [`MAX_ASSET_BYTES`], a file that starts the way its
/// type does, and an SVG with nothing that could run (no script, event
/// handler, `javascript:` link, foreign object or external reference).
pub fn check_asset(kind: &str, content_type: &str, bytes: &[u8]) -> Result<(), AppError> {
    let Some((_, types)) = ASSET_KINDS.iter().find(|(k, _)| *k == kind) else {
        let kinds: Vec<&str> = ASSET_KINDS.iter().map(|(k, _)| *k).collect();
        return Err(AppError::Validation(format!(
            "kind must be one of {}",
            kinds.join(", ")
        )));
    };
    if !types.contains(&content_type) {
        return Err(AppError::Validation(format!(
            "a {kind} must be one of {}",
            types.join(", ")
        )));
    }
    if bytes.is_empty() {
        return Err(AppError::Validation("the file is empty".into()));
    }
    if bytes.len() > MAX_ASSET_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    let starts = |magic: &[u8]| bytes.starts_with(magic);
    let shaped = match content_type {
        "image/png" => starts(b"\x89PNG\r\n\x1a\n"),
        "image/x-icon" => starts(&[0, 0, 1, 0]),
        "font/woff2" => starts(b"wOF2"),
        "application/pdf" => starts(b"%PDF-"),
        "image/svg+xml" => svg_is_inert(bytes)?,
        _ => false,
    };
    if !shaped {
        return Err(AppError::Validation(format!(
            "the file is not a {content_type} file"
        )));
    }
    Ok(())
}

/// True for an SVG document with nothing that could run or fetch.
fn svg_is_inert(bytes: &[u8]) -> Result<bool, AppError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AppError::Validation("an SVG must be UTF-8 text".into()))?
        .to_ascii_lowercase();
    if !text.contains("<svg") {
        return Ok(false);
    }
    let forbidden = [
        "<script",
        "javascript:",
        "<foreignobject",
        "<iframe",
        "<embed",
        "<object",
        "<!entity",
        "xlink:href=\"http",
        "href=\"http",
        "@import",
        "url(http",
    ];
    if let Some(found) = forbidden.iter().find(|f| text.contains(*f)) {
        return Err(AppError::Validation(format!(
            "an SVG may not contain {found}"
        )));
    }
    let has_handler = text.match_indices(" on").any(|(i, _)| {
        let rest = &text[i + 3..];
        let name_len = rest.chars().take_while(|c| c.is_ascii_alphabetic()).count();
        name_len > 0 && rest[name_len..].trim_start().starts_with('=')
    });
    if has_handler {
        return Err(AppError::Validation(
            "an SVG may not contain event handlers".into(),
        ));
    }
    Ok(true)
}

/// A brand asset of one theme version.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct BrandAsset {
    pub id: Uuid,
    pub theme_id: Uuid,
    pub kind: String,
    pub content_type: String,
    pub byte_size: i64,
    pub sha256: String,
    pub created_at: DateTime<Utc>,
}

const ASSET_COLUMNS: &str = "id, theme_id, kind, content_type, byte_size, sha256, created_at";

/// The object-store key for an asset's bytes.
pub fn asset_storage_key(theme_id: Uuid, kind: &str, sha256: &str) -> String {
    format!("branding/{theme_id}/{kind}-{sha256}")
}

/// Records a draft's asset of `kind` (replacing one it already has), once
/// its bytes are in the object store under `storage_key`. Only a draft
/// takes new assets.
pub async fn put_asset(
    conn: &mut PgConnection,
    theme_id: Uuid,
    kind: &str,
    storage_key: &str,
    content_type: &str,
    byte_size: i64,
    sha256: &str,
) -> Result<BrandAsset, AppError> {
    let status: String = sqlx::query_scalar("SELECT status FROM theme WHERE id = $1 FOR UPDATE")
        .bind(theme_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(attome_db::classify)?
        .ok_or(AppError::NotFound)?;
    if status != "draft" {
        return Err(AppError::Conflict(
            "only a draft takes new assets; save a new draft first",
        ));
    }
    let updated: Option<BrandAsset> = sqlx::query_as(&format!(
        "UPDATE brand_asset SET storage_key = $3, content_type = $4, byte_size = $5, \
           sha256 = $6, created_at = now() \
         WHERE theme_id = $1 AND kind = $2 RETURNING {ASSET_COLUMNS}"
    ))
    .bind(theme_id)
    .bind(kind)
    .bind(storage_key)
    .bind(content_type)
    .bind(byte_size)
    .bind(sha256)
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    if let Some(asset) = updated {
        return Ok(asset);
    }
    sqlx::query_as(&format!(
        "INSERT INTO brand_asset (id, theme_id, kind, storage_key, content_type, byte_size, sha256) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {ASSET_COLUMNS}"
    ))
    .bind(Uuid::now_v7())
    .bind(theme_id)
    .bind(kind)
    .bind(storage_key)
    .bind(content_type)
    .bind(byte_size)
    .bind(sha256)
    .fetch_one(&mut *conn)
    .await
    .map_err(attome_db::classify)
}

/// A version's assets, by kind.
pub async fn list_assets(
    db: &attome_db::DbPool,
    theme_id: Uuid,
) -> Result<Vec<BrandAsset>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {ASSET_COLUMNS} FROM brand_asset WHERE theme_id = $1 ORDER BY kind"
    ))
    .bind(theme_id)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// A published asset a request sees: the most specific published theme
/// that has one of that kind wins.
#[derive(Debug, Clone)]
pub struct PublishedAsset {
    pub kind: String,
    pub storage_key: String,
    pub content_type: String,
    pub sha256: String,
}

/// The published assets for `scope`, one per kind.
pub async fn published_assets(
    db: &attome_db::DbPool,
    scope: BrandScope<'_>,
) -> Result<Vec<PublishedAsset>, AppError> {
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(&format!(
        "SELECT t.scope_kind, a.kind, a.storage_key, a.content_type, a.sha256 \
         FROM brand_asset a JOIN theme t ON t.id = a.theme_id \
         WHERE t.status = 'published' AND {IN_SCOPE}"
    ))
    .bind(scope.app.unwrap_or(""))
    .bind(scope.unit.unwrap_or(""))
    .bind(scope.host.unwrap_or(""))
    .bind(scope.portal.unwrap_or(""))
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let rank = |scope_kind: &str| RESOLVE_ORDER.iter().position(|k| *k == scope_kind);
    let mut best: Vec<(usize, PublishedAsset)> = Vec::new();
    for (scope_kind, kind, storage_key, content_type, sha256) in rows {
        let Some(r) = rank(&scope_kind) else { continue };
        let asset = PublishedAsset {
            kind,
            storage_key,
            content_type,
            sha256,
        };
        match best.iter_mut().find(|(_, a)| a.kind == asset.kind) {
            Some(slot) if slot.0 < r => *slot = (r, asset),
            Some(_) => {}
            None => best.push((r, asset)),
        }
    }
    let mut assets: Vec<PublishedAsset> = best.into_iter().map(|(_, a)| a).collect();
    assets.sort_by(|a, b| a.kind.cmp(&b.kind));
    Ok(assets)
}

/// The published theme of each scope a request falls under, merged from the
/// deployment's outwards: deployment, app, unit, domain (`host`), portal. A
/// scope with no published theme adds nothing. The tag names the published
/// versions merged, so it changes whenever one does (an ETag).
pub async fn resolve(
    db: &attome_db::DbPool,
    scope: BrandScope<'_>,
) -> Result<(ThemeTokens, String), AppError> {
    type Row = (String, Uuid, i32, sqlx::types::Json<ThemeTokens>);
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT scope_kind, id, version, tokens FROM theme t \
         WHERE status = 'published' AND {IN_SCOPE}"
    ))
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
    fn assets_are_checked_before_they_are_stored() {
        let png = b"\x89PNG\r\n\x1a\nrest";
        assert!(check_asset("logo", "image/png", png).is_ok());
        assert!(check_asset("banner", "image/png", png).is_err());
        assert!(check_asset("font_latin", "image/png", png).is_err());
        assert!(check_asset("logo", "image/png", b"GIF89a").is_err());
        assert!(check_asset("logo", "image/png", b"").is_err());
        let big = vec![0u8; MAX_ASSET_BYTES + 1];
        assert!(matches!(
            check_asset("guidelines_pdf", "application/pdf", &big),
            Err(AppError::PayloadTooLarge)
        ));
        assert!(check_asset("font_arabic", "font/woff2", b"wOF2....").is_ok());
        assert!(check_asset("favicon", "image/x-icon", &[0, 0, 1, 0, 1]).is_ok());
    }

    #[test]
    fn only_inert_svg_is_accepted() {
        let ok = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#0b4f6c"/></svg>"##;
        assert!(check_asset("logo", "image/svg+xml", ok).is_ok());
        for bad in [
            &br##"<svg><script>alert(1)</script></svg>"##[..],
            br##"<svg><rect onload="alert(1)"/></svg>"##,
            br##"<svg><rect ONCLICK = "x"/></svg>"##,
            br##"<svg><a href="javascript:alert(1)"><rect/></a></svg>"##,
            br##"<svg><foreignObject><div/></foreignObject></svg>"##,
            br##"<svg><image href="https://tracker.example/x.png"/></svg>"##,
            br##"<html>not svg</html>"##,
        ] {
            assert!(
                check_asset("logo", "image/svg+xml", bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
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
