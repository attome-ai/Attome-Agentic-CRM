//! A page's search settings (roadmap E13-T4): title, description,
//! canonical URL, robots flags and the Open Graph card, stored on
//! `content_page` (migration 0057), with [`effective`] filling what an
//! author left empty from the page itself.

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::model::{Block, BlockKind, PageDetail};

/// The longest description search engines show.
pub const DESCRIPTION_CHARS: usize = 160;

/// A page's search settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PageSeo {
    pub title: Option<String>,
    pub description: Option<String>,
    pub canonical_url: Option<String>,
    #[serde(default)]
    pub noindex: bool,
    #[serde(default)]
    pub nofollow: bool,
    pub og_title: Option<String>,
    pub og_description: Option<String>,
    pub og_image_ref: Option<Uuid>,
}

pub(crate) fn filled(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// Text without tags or entities, whitespace collapsed. Pure.
pub fn plain_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The first `max` characters of `text`, cut at a word when it is longer.
/// Pure.
pub fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let cut: String = text.chars().take(max).collect();
    match cut.rfind(' ') {
        Some(at) if at > max / 2 => cut[..at].trim_end().to_owned(),
        _ => cut,
    }
}

/// The first paragraph block's text: the first rich-text block. Pure.
pub fn first_paragraph(blocks: &[Block]) -> Option<String> {
    blocks
        .iter()
        .find(|b| b.kind == BlockKind::RichText)
        .and_then(|b| b.props.get("html").and_then(serde_json::Value::as_str))
        .map(plain_text)
        .filter(|t| !t.is_empty())
}

fn page_blocks(page: &PageDetail) -> Vec<Block> {
    page.blocks_published
        .as_ref()
        .unwrap_or(&page.blocks_draft)
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|b| serde_json::from_value::<Block>(b.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The settings a page is served with: an empty title is the page title
/// (with the site's default after it), an empty description the first
/// paragraph's first 160 characters, an empty canonical the site base URL
/// plus the page's path, and the Open Graph card falls back to the title
/// and description. Pure.
pub fn effective(
    stored: &PageSeo,
    page: &PageDetail,
    site_default_title: &str,
    site_base_url: &str,
) -> PageSeo {
    let title = filled(stored.title.as_ref()).unwrap_or_else(|| {
        let site = site_default_title.trim();
        if site.is_empty() {
            page.title.clone()
        } else {
            format!("{} | {site}", page.title)
        }
    });
    let description = filled(stored.description.as_ref())
        .or_else(|| first_paragraph(&page_blocks(page)).map(|t| clip(&t, DESCRIPTION_CHARS)));
    let canonical_url = filled(stored.canonical_url.as_ref()).or_else(|| {
        let base = site_base_url.trim().trim_end_matches('/');
        (!base.is_empty()).then(|| {
            let path = page.url_path.trim();
            if path.starts_with('/') {
                format!("{base}{path}")
            } else {
                format!("{base}/{path}")
            }
        })
    });
    PageSeo {
        og_title: filled(stored.og_title.as_ref()).or_else(|| Some(title.clone())),
        og_description: filled(stored.og_description.as_ref()).or_else(|| description.clone()),
        title: Some(title),
        description,
        canonical_url,
        noindex: stored.noindex,
        nofollow: stored.nofollow,
        og_image_ref: stored.og_image_ref,
    }
}

type SeoRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    bool,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    i64,
);

/// A page's stored settings and its row version. `NotFound` for no page.
pub async fn get_page_seo(db: &DbPool, page_id: Uuid) -> Result<(PageSeo, i64), AppError> {
    let row: SeoRow = sqlx::query_as(
        "SELECT seo_title, seo_description, seo_canonical_url, seo_noindex, seo_nofollow, \
                og_title, og_description, og_image_ref, row_version \
           FROM content_page WHERE id = $1 AND is_deleted = false",
    )
    .bind(page_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let (
        title,
        description,
        canonical_url,
        noindex,
        nofollow,
        og_title,
        og_description,
        og_image_ref,
        version,
    ) = row;
    Ok((
        PageSeo {
            title,
            description,
            canonical_url,
            noindex,
            nofollow,
            og_title,
            og_description,
            og_image_ref,
        },
        version,
    ))
}

pub(crate) fn check(body: &PageSeo) -> Result<(), AppError> {
    let long = |v: &Option<String>, max: usize| v.as_ref().is_some_and(|s| s.chars().count() > max);
    if long(&body.title, 200) || long(&body.og_title, 200) {
        return Err(AppError::Validation(
            "a title is at most 200 characters".into(),
        ));
    }
    if long(&body.description, 500) || long(&body.og_description, 500) {
        return Err(AppError::Validation(
            "a description is at most 500 characters".into(),
        ));
    }
    if let Some(url) = filled(body.canonical_url.as_ref())
        && !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(AppError::Validation(
            "the canonical URL must be http(s)".into(),
        ));
    }
    Ok(())
}

/// E13-T8: writes a page's settings in the caller's transaction, after the
/// caller locked the row and checked its version. Returns the new version.
pub(crate) async fn write_page_seo(
    tx: &mut attome_db::Tx<'_>,
    page_id: Uuid,
    body: &PageSeo,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "UPDATE content_page SET seo_title = $2, seo_description = $3, seo_canonical_url = $4, \
                seo_noindex = $5, seo_nofollow = $6, og_title = $7, og_description = $8, \
                og_image_ref = $9, row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND is_deleted = false \
          RETURNING row_version",
    )
    .bind(page_id)
    .bind(filled(body.title.as_ref()))
    .bind(filled(body.description.as_ref()))
    .bind(filled(body.canonical_url.as_ref()))
    .bind(body.noindex)
    .bind(body.nofollow)
    .bind(filled(body.og_title.as_ref()))
    .bind(filled(body.og_description.as_ref()))
    .bind(body.og_image_ref)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Writes a page's settings at `expected_row_version`; a page changed since
/// is `Conflict("version_conflict")`. Returns the new row version.
pub async fn update_page_seo(
    db: &DbPool,
    page_id: Uuid,
    body: &PageSeo,
    expected_row_version: i64,
) -> Result<i64, AppError> {
    check(body)?;
    let updated: Option<i64> = sqlx::query_scalar(
        "UPDATE content_page SET seo_title = $3, seo_description = $4, seo_canonical_url = $5, \
                seo_noindex = $6, seo_nofollow = $7, og_title = $8, og_description = $9, \
                og_image_ref = $10, row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND row_version = $2 AND is_deleted = false \
          RETURNING row_version",
    )
    .bind(page_id)
    .bind(expected_row_version)
    .bind(filled(body.title.as_ref()))
    .bind(filled(body.description.as_ref()))
    .bind(filled(body.canonical_url.as_ref()))
    .bind(body.noindex)
    .bind(body.nofollow)
    .bind(filled(body.og_title.as_ref()))
    .bind(filled(body.og_description.as_ref()))
    .bind(body.og_image_ref)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match updated {
        Some(version) => Ok(version),
        None => {
            // Zero rows: the page is gone, or someone saved it first.
            get_page_seo(db, page_id).await?;
            Err(AppError::Conflict("version_conflict"))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    pub(crate) fn page(blocks: serde_json::Value) -> PageDetail {
        serde_json::from_value(json!({
            "id": Uuid::now_v7(),
            "parent_page_id": null,
            "content_space_id": Uuid::now_v7(),
            "title": "Pricing",
            "url_path": "/pricing",
            "status": "published",
            "template_id": null,
            "blocks_draft": blocks,
            "blocks_published": null,
            "seo_title": null,
            "seo_description": null,
            "published_at": null,
            "publish_at": null,
            "unpublish_at": null,
            "row_version": 1,
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        }))
        .expect("a page")
    }

    #[test]
    fn effective_fills_empty_description_from_first_paragraph() {
        let long = "word ".repeat(60);
        let p = page(json!([
            { "id": Uuid::now_v7(), "kind": "heading", "props": { "text": "Plans" } },
            { "id": Uuid::now_v7(), "kind": "rich_text", "props": { "html": format!("<p>Simple <b>pricing</b> &amp; {long}</p>") } }
        ]));
        let seo = effective(&PageSeo::default(), &p, "Acme", "https://acme.sa/");
        assert_eq!(seo.title.as_deref(), Some("Pricing | Acme"));
        let description = seo.description.unwrap();
        assert!(
            description.starts_with("Simple pricing & word"),
            "{description}"
        );
        assert!(description.chars().count() <= DESCRIPTION_CHARS);
        assert_eq!(
            seo.canonical_url.as_deref(),
            Some("https://acme.sa/pricing")
        );
        assert_eq!(seo.og_title.as_deref(), Some("Pricing | Acme"));
    }

    #[test]
    fn effective_keeps_explicit_values() {
        let p = page(json!([]));
        let stored = PageSeo {
            title: Some("Custom".into()),
            description: Some("Explicit".into()),
            canonical_url: Some("https://example.com/x".into()),
            noindex: true,
            ..PageSeo::default()
        };
        let seo = effective(&stored, &p, "Acme", "https://acme.sa");
        assert_eq!(seo.title.as_deref(), Some("Custom"));
        assert_eq!(seo.description.as_deref(), Some("Explicit"));
        assert_eq!(seo.canonical_url.as_deref(), Some("https://example.com/x"));
        assert!(seo.noindex);
    }
}
