//! K6-T10: what the webcrawl admin routes do beyond adding and crawling a
//! source, kept out of the handlers (guidelines §1): who may manage a
//! source, changing its settings under its row version, its run history and
//! the knowledge items its changes left for review.
//!
//! **Who.** An administrator of the Integrations area, as before, or a
//! knowledge manager: whoever may update knowledge data sources (the
//! Knowledge Manager role template, `attome-security`), since a crawl target
//! is how a website becomes a knowledge source. Reading needs
//! `knowledge_data_source.read`. Two settings stay with administrators: the
//! intranet host a source may reach (`allow_host`, K6-T8) and the credential
//! it signs in with, because they open private addresses and secrets.

use attome_security::SecurityContextExt;
use attome_server::authz::AdminArea;
use attome_server::security::SecurityContext;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::model::{CreateTargetBody, MAX_DEPTH, MIN_DEPTH, TARGET_COLUMNS, TargetListItem};

/// What a caller wants to do with crawl sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Manage,
}

/// Whether `ctx` may read or manage crawl sources.
pub fn authorize(ctx: &SecurityContext, access: Access) -> Result<(), AppError> {
    if AdminArea::Integrations.held_by(ctx) {
        return Ok(());
    }
    let action = match access {
        Access::Read => "read",
        Access::Manage => "update",
    };
    ctx.require("knowledge_data_source", action)
        .map_err(|_| AppError::Forbidden)
}

/// A source's settings to change; each one left out keeps its value.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdateTargetBody {
    #[serde(default)]
    pub max_depth: Option<i32>,
    #[serde(default)]
    pub include_patterns: Option<String>,
    #[serde(default)]
    pub exclude_patterns: Option<String>,
    #[serde(default)]
    pub languages: Option<Vec<String>>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub import_mode: Option<String>,
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default)]
    pub sitemap_url: Option<String>,
    #[serde(default)]
    pub watch_only: Option<bool>,
    /// Administrators only.
    #[serde(default)]
    pub allow_host: Option<String>,
    /// Administrators only.
    #[serde(default)]
    pub credential_ref: Option<String>,
}

impl UpdateTargetBody {
    /// The same checks a new source's settings get, and the two settings
    /// only an administrator changes. Pure.
    pub fn validate(&self, admin: bool) -> Result<(), AppError> {
        if !admin && (self.allow_host.is_some() || self.credential_ref.is_some()) {
            return Err(AppError::Forbidden);
        }
        if self
            .max_depth
            .is_some_and(|d| !(MIN_DEPTH..=MAX_DEPTH).contains(&d))
        {
            return Err(AppError::Validation(format!(
                "max_depth must be {MIN_DEPTH} to {MAX_DEPTH}"
            )));
        }
        CreateTargetBody {
            url: String::new(),
            max_depth: self.max_depth,
            include_patterns: self.include_patterns.clone(),
            exclude_patterns: self.exclude_patterns.clone(),
            languages: self.languages.clone(),
            audience: self.audience.clone(),
            import_mode: self.import_mode.clone(),
            schedule: self.schedule.clone(),
            sitemap_url: self.sitemap_url.clone(),
            watch_only: self.watch_only,
            allow_host: self.allow_host.clone(),
            credential_ref: self.credential_ref.clone(),
        }
        .validate_settings()
        .map_err(AppError::Validation)
    }
}

/// Changes `id`'s settings when its row version is still `expected`:
/// `NotFound` for no such source, `VersionConflict` for a stale version.
pub async fn update_target(
    db: &attome_db::DbPool,
    ctx: &SecurityContext,
    id: Uuid,
    expected: i64,
    body: &UpdateTargetBody,
) -> Result<TargetListItem, AppError> {
    authorize(ctx, Access::Manage)?;
    body.validate(AdminArea::Integrations.held_by(ctx))?;
    let updated: Option<TargetListItem> = sqlx::query_as(&format!(
        "UPDATE webcrawl_target \
            SET max_depth = COALESCE($3, max_depth), \
                include_patterns = COALESCE($4, include_patterns), \
                exclude_patterns = COALESCE($5, exclude_patterns), \
                languages = COALESCE($6, languages), \
                audience = COALESCE($7, audience), \
                import_mode = COALESCE($8, import_mode), \
                schedule = COALESCE($9, schedule), \
                sitemap_url = COALESCE($10, sitemap_url), \
                watch_only = COALESCE($11, watch_only), \
                allow_host = COALESCE($12, allow_host), \
                credential_ref = COALESCE($13, credential_ref), \
                row_version = row_version + 1, updated_at = NOW() \
          WHERE id = $1 AND is_deleted = FALSE AND row_version = $2 \
         RETURNING {TARGET_COLUMNS}"
    ))
    .bind(id)
    .bind(expected)
    .bind(body.max_depth.and_then(|d| i16::try_from(d).ok()))
    .bind(body.include_patterns.as_deref())
    .bind(body.exclude_patterns.as_deref())
    .bind(body.languages.clone())
    .bind(body.audience.as_deref())
    .bind(body.import_mode.as_deref())
    .bind(body.schedule.as_deref())
    .bind(body.sitemap_url.as_deref())
    .bind(body.watch_only)
    .bind(body.allow_host.as_deref())
    .bind(body.credential_ref.as_deref())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(row) = updated {
        return Ok(row);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webcrawl_target WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Err(if exists {
        AppError::VersionConflict
    } else {
        AppError::NotFound
    })
}

/// One crawl of a source.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct RunItem {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// `running | completed | failed`.
    pub status: String,
    pub pages_found: i32,
    pub items_imported: i32,
    pub items_updated: i32,
    /// Items an editor published that the site changed, waiting for review.
    pub items_flagged: i32,
    pub error: Option<String>,
}

async fn require_target(db: &attome_db::DbPool, id: Uuid) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webcrawl_target WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// `id`'s runs, newest first.
pub async fn runs(
    db: &attome_db::DbPool,
    ctx: &SecurityContext,
    id: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<RunItem>, AppError> {
    authorize(ctx, Access::Read)?;
    require_target(db, id).await?;
    let window = page.window();
    let items: Vec<RunItem> = sqlx::query_as(
        "SELECT id, started_at, finished_at, status, pages_found, items_imported, \
                items_updated, items_flagged, error \
           FROM webcrawl_run WHERE target_id = $1 \
          ORDER BY started_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webcrawl_run WHERE target_id = $1")
        .bind(id)
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

/// A knowledge item a recrawl changed under its editor, waiting for review.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct ChangeItem {
    pub page_id: Uuid,
    pub url_path: String,
    pub item_id: Uuid,
    pub title: Option<String>,
    pub version: Option<i32>,
    pub changed_at: DateTime<Utc>,
}

/// `id`'s imported items flagged `needs_review` by a recrawl (K6-T4), oldest
/// change first. Read through the row's JSON, so a deployment whose items
/// lack the K6-T4 fields lists nothing rather than failing.
pub async fn changes(
    db: &attome_db::DbPool,
    ctx: &SecurityContext,
    id: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<ChangeItem>, AppError> {
    authorize(ctx, Access::Read)?;
    require_target(db, id).await?;
    let window = page.window();
    const FROM: &str = "FROM webcrawl_page p \
           JOIN knowledge_data_item k ON k.id = p.imported_data_item_ref \
          WHERE p.target_ref = $1 AND p.is_deleted = FALSE \
            AND (to_jsonb(k) ->> 'needs_review') = 'true' AND k.is_active IS NOT FALSE";
    let items: Vec<ChangeItem> = sqlx::query_as(&format!(
        "SELECT p.id AS page_id, p.url_path, k.id AS item_id, k.title, \
                (to_jsonb(k) ->> 'version')::numeric::int4 AS version, p.updated_at AS changed_at \
         {FROM} ORDER BY p.updated_at, p.id LIMIT $2 OFFSET $3"
    ))
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) {FROM}"))
        .bind(id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_administrator_opens_hosts_or_credentials() {
        let host = UpdateTargetBody {
            allow_host: Some("intranet.local".into()),
            ..Default::default()
        };
        assert!(matches!(host.validate(false), Err(AppError::Forbidden)));
        assert!(host.validate(true).is_ok());
        let schedule = UpdateTargetBody {
            schedule: Some("weekly".into()),
            ..Default::default()
        };
        assert!(schedule.validate(false).is_ok());
        let bad = UpdateTargetBody {
            schedule: Some("hourly".into()),
            ..Default::default()
        };
        assert!(matches!(bad.validate(false), Err(AppError::Validation(_))));
        let deep = UpdateTargetBody {
            max_depth: Some(MAX_DEPTH + 1),
            ..Default::default()
        };
        assert!(deep.validate(true).is_err());
    }
}
