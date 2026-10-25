//! E13-T11: what the SEO drafting action (`attome_ai`'s `seo.draft`) reads
//! from one page: its title, path and text, its search settings, its audit
//! findings and the other published pages of its space to link to. Reading
//! only: the action drafts, an administrator saves.

use attome_db::DbPool;
use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::audit::flat_blocks;
use super::settings::PageSeo;
use crate::model::{BlockKind, PageDetail};

/// The most page text a draft reads, in characters.
pub const MAX_TEXT_CHARS: usize = 12_000;
/// The most pages offered as internal links.
pub const MAX_LINK_CANDIDATES: i64 = 50;

/// One page as the drafting action sees it.
#[derive(Debug, Clone, Serialize)]
pub struct SeoMaterial {
    pub page_id: Uuid,
    pub title: String,
    pub url_path: String,
    /// The page's readable text, headings and paragraphs, capped at
    /// [`MAX_TEXT_CHARS`].
    pub text: String,
    pub seo: PageSeo,
    /// `(rule, severity, message key)`, errors first.
    pub findings: Vec<(String, String, Option<String>)>,
    /// `(title, url path)` of other published pages in the same space.
    pub link_candidates: Vec<(String, String)>,
}

/// `html` without its tags and with entities for `&`, `<`, `>`, quotes and
/// spaces read back. Pure.
pub fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' if in_tag => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn prop_text<'a>(props: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| props.get(*k).and_then(Value::as_str))
        .filter(|s| !s.trim().is_empty())
}

/// The page's readable text, one block a line, capped. Pure.
pub fn page_text(page: &PageDetail) -> String {
    let mut lines = Vec::new();
    for block in flat_blocks(page) {
        let line = match block.kind {
            BlockKind::Heading => prop_text(&block.props, &["text"]).map(|t| format!("# {t}")),
            BlockKind::RichText => prop_text(&block.props, &["html", "text"]).map(strip_tags),
            BlockKind::Alert => prop_text(&block.props, &["text", "message"]).map(str::to_owned),
            BlockKind::Image => prop_text(&block.props, &["alt"]).map(|t| format!("[image: {t}]")),
            _ => None,
        };
        lines.extend(line.filter(|l| !l.trim().is_empty()));
    }
    let text = lines.join("\n");
    match text.char_indices().nth(MAX_TEXT_CHARS) {
        Some((cut, _)) => text[..cut].to_owned(),
        None => text,
    }
}

/// Everything the drafting action reads for `page_id`.
pub async fn material(db: &DbPool, page_id: Uuid) -> Result<SeoMaterial, AppError> {
    let page = crate::admin::load_page(db, page_id).await?;
    let (seo, _) = super::settings::get_page_seo(db, page_id).await?;
    let (findings, _) = super::site::findings(db, page_id, 50, 0).await?;
    let link_candidates: Vec<(String, String)> = sqlx::query_as(
        "SELECT title, url_path FROM content_page \
          WHERE content_space_id = $1 AND id <> $2 AND is_deleted = false \
            AND status = 'published' \
          ORDER BY updated_at DESC LIMIT $3",
    )
    .bind(page.content_space_id)
    .bind(page_id)
    .bind(MAX_LINK_CANDIDATES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(SeoMaterial {
        page_id,
        text: page_text(&page),
        title: page.title,
        url_path: page.url_path,
        seo,
        findings: findings
            .into_iter()
            .map(|f| (f.rule, f.severity, f.message_key))
            .collect(),
        link_candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn seo_agent_strips_tags_and_entities() {
        assert_eq!(
            strip_tags("<p>Fast <b>VAT</b> returns &amp; refunds</p><p>in&nbsp;Riyadh</p>"),
            "Fast VAT returns & refunds in Riyadh"
        );
        assert_eq!(strip_tags("no tags"), "no tags");
    }

    #[test]
    fn seo_agent_reads_headings_text_and_alt() {
        let page: PageDetail = serde_json::from_value(json!({
            "id": Uuid::nil(), "parent_page_id": null, "content_space_id": Uuid::nil(),
            "title": "VAT", "url_path": "/vat", "status": "draft", "template_id": null,
            "blocks_draft": [
                {"id": Uuid::now_v7(), "kind": "heading", "props": {"text": "File VAT on time", "level": 1}},
                {"id": Uuid::now_v7(), "kind": "rich_text", "props": {"html": "<p>Due by the 28th.</p>"}},
                {"id": Uuid::now_v7(), "kind": "image", "props": {"alt": "A calendar"}}
            ],
            "blocks_published": null, "seo_title": null, "seo_description": null,
            "published_at": null, "publish_at": null, "unpublish_at": null, "row_version": 1,
            "created_at": "2026-10-25T00:00:00Z", "updated_at": "2026-10-25T00:00:00Z",
            "review_by": null, "audience": "public"
        }))
        .unwrap();
        assert_eq!(
            page_text(&page),
            "# File VAT on time\nDue by the 28th.\n[image: A calendar]"
        );
    }
}
