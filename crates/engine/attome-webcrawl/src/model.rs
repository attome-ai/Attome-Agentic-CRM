//! Wire DTOs and row shapes for the Web Crawling admin surface
//! (`attome-api/src/webcrawl_admin.rs`) and the crawl job (`crate::crawl`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct TargetListItem {
    pub id: Uuid,
    pub url: String,
    /// `pending | crawling | completed | failed`.
    pub status: String,
    pub max_depth: i16,
    pub pages_found: i32,
    pub pages_imported: i32,
    pub last_error: Option<String>,
    pub last_crawled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, ToSchema)]
pub struct PageListItem {
    pub id: Uuid,
    pub url_path: String,
    pub parent_path: Option<String>,
    pub depth: i32,
    pub size_bytes: Option<i32>,
    /// `pending | crawled | failed`.
    pub status: String,
    pub is_selected: bool,
    pub imported_data_item_ref: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTargetBody {
    pub url: String,
    /// Defaults to `config.webcrawl.max_depth` (6) when omitted; clamped to
    /// `MIN_DEPTH..=MAX_DEPTH` regardless of what's requested.
    #[serde(default)]
    pub max_depth: Option<i32>,
}

/// Per-crawl depth bounds — `max_pages` already caps total work regardless
/// of depth, so this range exists to reject nonsensical input, not to bound
/// crawl cost.
pub const MIN_DEPTH: i32 = 1;
pub const MAX_DEPTH: i32 = 20;

#[derive(Debug, Deserialize, ToSchema)]
pub struct SelectionBody {
    pub page_ids: Vec<Uuid>,
    pub selected: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = CrawlImportBody)]
pub struct ImportBody {
    pub page_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportResult {
    pub data_source_ref: Uuid,
    pub imported_count: i64,
}
