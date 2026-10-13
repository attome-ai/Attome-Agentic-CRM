//! Wire DTOs and row shapes for the Content Management admin
//! (`attome-api/src/content_admin.rs`) and public (`content_public.rs`)
//! surfaces.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The full block library (mockup's block-library modal). Kept as a real
/// enum (not a bare string) so an unrecognized `kind` is rejected by
/// deserialization itself, before `blocks::validate_blocks` ever runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    Heading,
    RichText,
    Alert,
    Image,
    Columns,
    DataTable,
    Chart,
    Form,
    Component,
}

/// One block on the canvas. `props` is validated against `kind`'s shape by
/// `blocks::validate_blocks` before a draft save or publish is accepted —
/// never stored as trusted-opaque JSON (coding-guidelines §8).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct Block {
    pub id: Uuid,
    pub kind: BlockKind,
    #[schema(value_type = Object)]
    pub props: serde_json::Value,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct PageSummary {
    pub id: Uuid,
    pub parent_page_id: Option<Uuid>,
    pub content_space_id: Uuid,
    pub title: String,
    pub url_path: String,
    /// `draft | published`.
    pub status: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct PageDetail {
    pub id: Uuid,
    pub parent_page_id: Option<Uuid>,
    pub content_space_id: Uuid,
    pub title: String,
    pub url_path: String,
    /// `draft | published`.
    pub status: String,
    /// `None` if this page was built from scratch, not from a template.
    pub template_id: Option<Uuid>,
    #[schema(value_type = Vec<Object>)]
    pub blocks_draft: serde_json::Value,
    #[schema(value_type = Option<Vec<Object>>)]
    pub blocks_published: Option<serde_json::Value>,
    pub seo_title: Option<String>,
    pub seo_description: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    /// M56 Phase 1 (D-436, migration `0230`) — when set on a `draft` page,
    /// the scheduled-publish sweep publishes it once `NOW()` passes this.
    pub publish_at: Option<DateTime<Utc>>,
    /// When set on a `published` page, the same sweep reverts it to `draft`
    /// once `NOW()` passes this.
    pub unpublish_at: Option<DateTime<Utc>>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// M37 Phase 2 (D-452) — when set, the owner (`updated_by`) is reminded
    /// through M51 once `NOW()` passes it, and retrieval callers are told the
    /// underlying content is stale. `None` means no review cadence is set,
    /// not "never review".
    pub review_by: Option<NaiveDate>,
}

/// A reusable container of pages — a pure organizational grouping, not a URL
/// namespace (`url_path` uniqueness stays global across all spaces; see
/// D-369). Infra-mutable class (D-005).
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ContentSpace {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSpaceBody {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSpaceBody {
    pub name: Option<String>,
    /// `None` leaves the stored value unchanged, `Some("")` clears it,
    /// `Some(nonempty)` sets it — same convention as `UpdatePageBody`'s
    /// `seo_title`/`seo_description`.
    pub description: Option<String>,
}

/// A reusable block-content starting point for new pages — selecting one at
/// page-create time copies `blocks` into the new page's `blocks_draft` once;
/// there is no ongoing link back to the template afterward (D-369).
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ContentTemplate {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    #[schema(value_type = Vec<Object>)]
    pub blocks: serde_json::Value,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTemplateBody {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub blocks: Vec<Block>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTemplateBody {
    pub name: Option<String>,
    pub description: Option<String>,
    pub blocks: Option<Vec<Block>>,
}

/// Full-set replace for a page's symmetric "related pages" — the admin API
/// writes both directions (A→B and B→A) in one transaction, so a read for
/// either page's related list is a single-direction query.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RelatedPagesBody {
    pub related_page_ids: Vec<Uuid>,
}

/// Full-set replace for which templates a space's editors may pick from.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SpaceTemplatesBody {
    pub template_ids: Vec<Uuid>,
}

/// Read-only shape served by the public, anonymous `content_public.rs`
/// route — deliberately narrower than `PageDetail`: no `id`/`row_version`/
/// `status`/draft blocks, nothing an anonymous visitor has any business
/// seeing.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct PublicPageView {
    pub title: String,
    #[schema(value_type = Vec<Object>)]
    pub blocks: serde_json::Value,
    pub seo_title: Option<String>,
    pub seo_description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePageBody {
    pub parent_page_id: Option<Uuid>,
    pub content_space_id: Uuid,
    pub title: String,
    pub url_path: String,
    /// When set, must be one of `content_space_id`'s allowed templates
    /// (`content_space_template`) — its `blocks` are copied into the new
    /// page's `blocks_draft` once, at create time.
    pub template_id: Option<Uuid>,
}

/// The optimistic-concurrency guard is the `If-Match` header (D-079's
/// contract, reused as-is), not a body field — `attome-api`'s
/// `content_admin::update_page` parses it before this deserializes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePageBody {
    pub title: Option<String>,
    pub url_path: Option<String>,
    pub blocks: Option<Vec<Block>>,
    pub seo_title: Option<String>,
    pub seo_description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MovePageBody {
    pub parent_page_id: Option<Uuid>,
}

/// Full replace, `null` clears — same convention as `SchedulePageBody`
/// (D-452's `review_by`, a plain `Option<NaiveDate>` full-replace, has no
/// empty-string-vs-null ambiguity to resolve).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewByBody {
    pub review_by: Option<NaiveDate>,
}

/// The public/anonymous-safe "was this useful" vote body (D-452). Identifies
/// the page by `url_path`, the same identifier `content_public.rs`'s
/// `/content/view` already resolves by — a caller who can see a page can
/// always vote on it without needing its internal id.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VoteBody {
    pub url_path: String,
    pub useful: bool,
}

/// The read model `attome_content::analytics::rollup_page_stats` maintains
/// (D-452). Served by the admin page-stats panel; not written directly by
/// any request handler.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct PageStats {
    pub page_ref: Uuid,
    pub views: i64,
    pub retrievals: i64,
    pub helpfulness_up: i64,
    pub helpfulness_down: i64,
    pub last_useful_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Full replace, not a partial patch — both fields are always written
/// exactly as given (`null` clears), so there is no absent-vs-null
/// ambiguity to resolve (the trap `UpdatePageBody`'s `seo_title`/
/// `seo_description` sentinel-empty-string convention exists to avoid for a
/// string field; a plain `Option<DateTime<Utc>>` full-replace is the
/// simpler fix for a field with no such sentinel).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SchedulePageBody {
    #[serde(default)]
    pub publish_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub unpublish_at: Option<DateTime<Utc>>,
}

/// `url_path` format: absolute, lowercase, `[a-z0-9/-]`, no `..` or `//`,
/// and never inside a reserved top-level prefix a real app route already
/// owns — a custom page must never be able to shadow `/api`, `/xrm`, static
/// assets, or the health/version probes.
const RESERVED_URL_PREFIXES: &[&str] = &["/api", "/xrm", "/assets", "/health", "/version"];

pub fn validate_url_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("url_path must start with \"/\"".to_string());
    }
    if path.len() > 1 && path.ends_with('/') {
        return Err("url_path must not end with \"/\"".to_string());
    }
    if path.contains("..") || path.contains("//") {
        return Err("url_path must not contain \"..\" or \"//\"".to_string());
    }
    if !path
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '/' || c == '-')
    {
        return Err(
            "url_path may only contain lowercase letters, digits, \"/\" and \"-\"".to_string(),
        );
    }
    for prefix in RESERVED_URL_PREFIXES {
        if path == *prefix || path.starts_with(&format!("{prefix}/")) {
            return Err(format!(
                "url_path may not start with the reserved prefix \"{prefix}\""
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_normal_custom_path() {
        assert!(validate_url_path("/guide/templates").is_ok());
        assert!(validate_url_path("/").is_ok());
    }

    #[test]
    fn rejects_missing_leading_slash() {
        assert!(validate_url_path("guide/templates").is_err());
    }

    #[test]
    fn rejects_traversal_and_double_slash() {
        assert!(validate_url_path("/guide/../secret").is_err());
        assert!(validate_url_path("/guide//templates").is_err());
    }

    #[test]
    fn rejects_uppercase_and_invalid_characters() {
        assert!(validate_url_path("/Guide/Templates").is_err());
        assert!(validate_url_path("/guide/templates?x=1").is_err());
    }

    #[test]
    fn rejects_reserved_prefixes() {
        assert!(validate_url_path("/api/v1/whatever").is_err());
        assert!(validate_url_path("/xrm/admin").is_err());
        assert!(validate_url_path("/assets/logo.png").is_err());
        assert!(validate_url_path("/health").is_err());
        assert!(validate_url_path("/version").is_err());
        // Lookalikes that merely start with the same letters must NOT be
        // rejected — only an exact segment match counts as the reserved
        // route, matching bypass.rs's own "slash boundary" convention.
        assert!(validate_url_path("/apidocs").is_ok());
    }
}
