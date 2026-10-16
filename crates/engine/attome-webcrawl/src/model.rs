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
    /// K6-T1: path patterns to crawl, one glob per line (empty: everything).
    pub include_patterns: String,
    /// K6-T1: path patterns to skip, one glob per line.
    pub exclude_patterns: String,
    /// K6-T1: `ar` and/or `en`; empty keeps every language.
    pub languages: Vec<String>,
    /// K6-T1: `internal | partner | customer` — who may read what it imports.
    pub audience: String,
    /// K6-T1: `review` (a person selects pages) or `automatic`.
    pub import_mode: String,
    /// K6-T1: `manual | daily | weekly`.
    pub schedule: String,
    pub sitemap_url: Option<String>,
    /// K6-T1: watch for changes and report them, import nothing.
    pub watch_only: bool,
    /// K6-T1: the one intranet host this source may reach (K6-T8); empty
    /// keeps every private address refused.
    pub allow_host: String,
    /// K6-T1: reference to the credential the crawl signs in with.
    pub credential_ref: Option<String>,
}

/// The `webcrawl_target` columns a [`TargetListItem`] reads, in its order.
pub const TARGET_COLUMNS: &str = "id, url, status, max_depth, pages_found, pages_imported, \
     last_error, last_crawled_at, created_at, include_patterns, exclude_patterns, languages, \
     audience, import_mode, schedule, sitemap_url, watch_only, allow_host, credential_ref";

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
    /// K6-T1 source settings; each one omitted keeps its default (or, on a
    /// re-submitted URL, the value the target already has).
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
    #[serde(default)]
    pub allow_host: Option<String>,
    #[serde(default)]
    pub credential_ref: Option<String>,
}

impl CreateTargetBody {
    /// K6-T1: refuses a setting outside its allowed values, with the reason.
    pub fn validate_settings(&self) -> Result<(), String> {
        fn one_of(field: &str, value: Option<&str>, allowed: &[&str]) -> Result<(), String> {
            match value {
                Some(v) if !allowed.contains(&v) => {
                    Err(format!("{field} must be one of {}", allowed.join(", ")))
                }
                _ => Ok(()),
            }
        }
        one_of(
            "audience",
            self.audience.as_deref(),
            &["internal", "partner", "customer"],
        )?;
        one_of(
            "import_mode",
            self.import_mode.as_deref(),
            &["review", "automatic"],
        )?;
        one_of(
            "schedule",
            self.schedule.as_deref(),
            &["manual", "daily", "weekly"],
        )?;
        if let Some(languages) = &self.languages
            && languages.iter().any(|l| l != "ar" && l != "en")
        {
            return Err("languages may only hold ar and en".into());
        }
        if let Some(host) = &self.allow_host
            && (host.len() > 253
                || host.contains(['/', ':', '@'])
                || host.chars().any(char::is_whitespace))
        {
            return Err("allow_host must be one bare host name".into());
        }
        for (field, patterns) in [
            ("include_patterns", &self.include_patterns),
            ("exclude_patterns", &self.exclude_patterns),
        ] {
            if patterns.as_ref().is_some_and(|p| p.len() > 10_000) {
                return Err(format!("{field} is too long"));
            }
        }
        Ok(())
    }
}

/// Per-crawl depth bounds — `max_pages` already caps total work regardless
/// of depth, so this range exists to reject nonsensical input, not to bound
/// crawl cost.
pub const MIN_DEPTH: i32 = 1;

#[cfg(test)]
mod source_settings {
    use super::CreateTargetBody;

    fn body(json: &str) -> CreateTargetBody {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    #[test]
    fn old_bodies_still_deserialize_with_no_settings() {
        let b = body(r#"{"url": "https://example.com"}"#);
        assert!(b.audience.is_none() && b.languages.is_none());
        assert_eq!(b.validate_settings(), Ok(()));
    }

    #[test]
    fn settings_outside_their_values_are_refused() {
        assert!(
            body(r#"{"url": "x", "audience": "public"}"#)
                .validate_settings()
                .is_err()
        );
        assert!(
            body(r#"{"url": "x", "languages": ["fr"]}"#)
                .validate_settings()
                .is_err()
        );
        assert!(
            body(r#"{"url": "x", "allow_host": "http://intranet"}"#)
                .validate_settings()
                .is_err()
        );
        assert_eq!(
            body(r#"{"url": "x", "languages": ["ar", "en"], "schedule": "weekly", "allow_host": "intranet.local"}"#)
                .validate_settings(),
            Ok(())
        );
    }
}
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
