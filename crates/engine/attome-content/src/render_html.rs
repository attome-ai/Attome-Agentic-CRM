//! E12-T1: a published page as server-rendered HTML.
//!
//! At publish (`admin::do_publish_page`), in the publish transaction, the
//! new version's blocks are rendered into a whole HTML document and kept
//! on the version (`content_page_version.html`), so serving it does no
//! work: `GET /api/v1/content/html` answers the stored document with the
//! same ETag as the delivery API (page and version), and 304 to a client
//! that holds it.
//!
//! **Rendering** ([`render_page`], pure): headings, rich text (cleaned
//! again through the rich-text allow-list), alerts, images (http, https or
//! a site path only) and columns become plain HTML; data tables, charts,
//! forms and components are interactive and become a placeholder
//! (`<div data-hydrate="…" data-block="…" data-props="…">`) the web app
//! hydrates in place, so the text of the page is readable without script.
//! Every value is escaped. The document's `lang` and `dir` follow the
//! page's language (Arabic right to left); the base style uses logical
//! properties and theme custom properties a site may override.
//!
//! **The head** ([`render_head`]) is the one function that writes `<head>`:
//! the title, the description (the SEO description, else the first
//! paragraph), the canonical link and robots directives. E13-T6 extends it.

use attome_html::escape_html;
use serde_json::Value;

use crate::model::{Block, BlockKind};

/// How deep columns may nest.
const MAX_DEPTH: usize = 3;

/// What `<head>` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeadInput {
    pub title: String,
    pub description: Option<String>,
    pub canonical_url: Option<String>,
    pub noindex: bool,
    pub nofollow: bool,
    /// `ar`, `en`, …; `None` is English.
    pub language: Option<String>,
}

/// A published page to render.
#[derive(Debug, Clone)]
pub struct PageInput {
    pub head: HeadInput,
    pub blocks: Vec<Block>,
}

/// Whether a language is written right to left. Pure.
pub fn is_rtl(language: Option<&str>) -> bool {
    matches!(
        language.map(|l| l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase()),
        Some(ref l) if ["ar", "fa", "he", "ur"].contains(&l.as_str())
    )
}

/// The page's `<head>`. Pure.
pub fn render_head(head: &HeadInput) -> String {
    let mut out = String::from(
        "<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    );
    out.push_str(&format!("<title>{}</title>", escape_html(&head.title)));
    if let Some(d) = head.description.as_deref().filter(|d| !d.trim().is_empty()) {
        out.push_str(&format!(
            "<meta name=\"description\" content=\"{}\">",
            escape_html(d)
        ));
    }
    if let Some(c) = head.canonical_url.as_deref().filter(|c| safe_url(c)) {
        out.push_str(&format!(
            "<link rel=\"canonical\" href=\"{}\">",
            escape_html(c)
        ));
    }
    let robots: Vec<&str> = [(head.noindex, "noindex"), (head.nofollow, "nofollow")]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, v)| *v)
        .collect();
    if !robots.is_empty() {
        out.push_str(&format!(
            "<meta name=\"robots\" content=\"{}\">",
            robots.join(",")
        ));
    }
    out.push_str("<style>");
    out.push_str(BASE_STYLE);
    out.push_str("</style></head>");
    out
}

const BASE_STYLE: &str = ":root{--ac-text:#1a202c;--ac-muted:#4a5568;--ac-bg:#fff;--ac-info:#2b6cb0;\
--ac-success:#2f855a;--ac-warning:#b7791f;--ac-danger:#c53030}\
body{margin:0;background:var(--ac-bg);color:var(--ac-text);font-family:system-ui,sans-serif;line-height:1.6}\
main{max-inline-size:72rem;margin-inline:auto;padding-inline:1rem;padding-block:2rem}\
img{max-inline-size:100%;block-size:auto}\
.ac-alert{border-inline-start:4px solid var(--ac-info);padding-inline:1rem;padding-block:.5rem;margin-block:1rem}\
.ac-alert-success{border-inline-start-color:var(--ac-success)}\
.ac-alert-warning{border-inline-start-color:var(--ac-warning)}\
.ac-alert-danger{border-inline-start-color:var(--ac-danger)}\
.ac-columns{display:grid;gap:1.5rem;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr))}";

/// An image or link target this renderer will write: http(s), or a path
/// on the site. Pure.
fn safe_url(url: &str) -> bool {
    let u = url.trim().to_ascii_lowercase();
    u.starts_with("https://")
        || u.starts_with("http://")
        || (u.starts_with('/') && !u.starts_with("//"))
}

fn text<'a>(props: &'a Value, key: &str) -> &'a str {
    props.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn kind_name(kind: &BlockKind) -> &'static str {
    match kind {
        BlockKind::Heading => "heading",
        BlockKind::RichText => "rich_text",
        BlockKind::Alert => "alert",
        BlockKind::Image => "image",
        BlockKind::Columns => "columns",
        BlockKind::DataTable => "data_table",
        BlockKind::Chart => "chart",
        BlockKind::Form => "form",
        BlockKind::Component => "component",
    }
}

fn render_block(block: &Block, depth: usize, out: &mut String) {
    let p = &block.props;
    match block.kind {
        BlockKind::Heading => {
            let level = p
                .get("level")
                .and_then(Value::as_u64)
                .filter(|l| (1..=6).contains(l))
                .unwrap_or(2);
            out.push_str(&format!(
                "<h{level}>{}</h{level}>",
                escape_html(text(p, "text"))
            ));
        }
        BlockKind::RichText => {
            out.push_str("<div class=\"ac-rich\">");
            out.push_str(&attome_html::sanitize_rich_text(text(p, "html")));
            out.push_str("</div>");
        }
        BlockKind::Alert => {
            let tone = match text(p, "tone") {
                t @ ("success" | "warning" | "danger") => t,
                _ => "info",
            };
            out.push_str(&format!(
                "<div class=\"ac-alert ac-alert-{tone}\" role=\"note\">{}</div>",
                escape_html(text(p, "message"))
            ));
        }
        BlockKind::Image => {
            let src = text(p, "src");
            if safe_url(src) {
                out.push_str(&format!(
                    "<img src=\"{}\" alt=\"{}\" loading=\"lazy\">",
                    escape_html(src),
                    escape_html(text(p, "alt"))
                ));
            }
        }
        BlockKind::Columns => {
            out.push_str("<div class=\"ac-columns\">");
            let columns = p.get("columns").and_then(Value::as_array);
            for column in columns.into_iter().flatten() {
                out.push_str("<div class=\"ac-column\">");
                if depth < MAX_DEPTH {
                    let inner: Vec<Block> = column
                        .get("blocks")
                        .cloned()
                        .and_then(|b| serde_json::from_value(b).ok())
                        .unwrap_or_default();
                    for b in &inner {
                        render_block(b, depth + 1, out);
                    }
                }
                out.push_str("</div>");
            }
            out.push_str("</div>");
        }
        BlockKind::DataTable | BlockKind::Chart | BlockKind::Form | BlockKind::Component => {
            out.push_str(&format!(
                "<div data-hydrate=\"{}\" data-block=\"{}\" data-props=\"{}\"></div>",
                kind_name(&block.kind),
                block.id,
                escape_html(&p.to_string())
            ));
        }
    }
}

/// The whole document. Pure.
pub fn render_page(page: &PageInput) -> String {
    let language = page
        .head
        .language
        .as_deref()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or("en");
    let dir = if is_rtl(Some(language)) { "rtl" } else { "ltr" };
    let mut out = format!(
        "<!doctype html><html lang=\"{}\" dir=\"{dir}\">",
        escape_html(language)
    );
    out.push_str(&render_head(&page.head));
    out.push_str("<body><main>");
    for block in &page.blocks {
        render_block(block, 0, &mut out);
    }
    out.push_str("</main></body></html>");
    out
}

/// Renders the page's newest version and keeps the HTML on it, in the
/// publish transaction.
pub async fn render_version_in_tx(
    tx: &mut attome_db::Tx<'_>,
    page_id: uuid::Uuid,
    version: i32,
) -> Result<(), attome_types::AppError> {
    type Row = (
        String,
        Value,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
        bool,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT v.title, v.blocks, v.seo_title, v.seo_description, p.seo_canonical_url, \
                p.seo_noindex, p.seo_nofollow, p.language \
           FROM content_page_version v JOIN content_page p ON p.id = v.page_id \
          WHERE v.page_id = $1 AND v.version_number = $2",
    )
    .bind(page_id)
    .bind(version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    let Some((title, blocks, seo_title, seo_description, canonical, noindex, nofollow, language)) =
        row
    else {
        return Ok(());
    };
    let blocks: Vec<Block> = serde_json::from_value(blocks).unwrap_or_default();
    let description = seo_description
        .filter(|d| !d.trim().is_empty())
        .or_else(|| crate::seo::settings::first_paragraph(&blocks));
    let html = render_page(&PageInput {
        head: HeadInput {
            title: seo_title.filter(|t| !t.trim().is_empty()).unwrap_or(title),
            description,
            canonical_url: canonical,
            noindex,
            nofollow,
            language,
        },
        blocks,
    });
    sqlx::query(
        "UPDATE content_page_version SET html = $3 WHERE page_id = $1 AND version_number = $2",
    )
    .bind(page_id)
    .bind(version)
    .bind(&html)
    .execute(&mut **tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn block(kind: BlockKind, props: Value) -> Block {
        Block {
            id: Uuid::nil(),
            kind,
            props,
        }
    }

    fn page(language: &str, blocks: Vec<Block>) -> PageInput {
        PageInput {
            head: HeadInput {
                title: "Pricing & plans".into(),
                description: Some("What it costs".into()),
                canonical_url: Some("https://example.com/pricing".into()),
                noindex: true,
                nofollow: false,
                language: Some(language.into()),
            },
            blocks,
        }
    }

    #[test]
    fn blocks_render_as_escaped_html() {
        let html = render_page(&page(
            "en",
            vec![
                block(BlockKind::Heading, json!({"text": "Plans <b>", "level": 1})),
                block(
                    BlockKind::RichText,
                    json!({"html": "<p>Hi</p><script>alert(1)</script>"}),
                ),
                block(
                    BlockKind::Alert,
                    json!({"message": "Note", "tone": "warning"}),
                ),
                block(
                    BlockKind::Image,
                    json!({"src": "javascript:alert(1)", "alt": "x"}),
                ),
                block(
                    BlockKind::Image,
                    json!({"src": "/media/a.png", "alt": "A \"quote\""}),
                ),
            ],
        ));
        assert!(html.starts_with("<!doctype html><html lang=\"en\" dir=\"ltr\">"));
        assert!(html.contains("<title>Pricing &amp; plans</title>"));
        assert!(html.contains("<h1>Plans &lt;b&gt;</h1>"));
        assert!(html.contains("<p>Hi</p>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("ac-alert-warning"));
        assert!(!html.contains("javascript:"));
        assert!(html.contains("src=\"/media/a.png\""));
        assert!(html.contains("<link rel=\"canonical\" href=\"https://example.com/pricing\">"));
        assert!(html.contains("<meta name=\"robots\" content=\"noindex\">"));
    }

    #[test]
    fn arabic_page_is_right_to_left() {
        let html = render_page(&page(
            "ar",
            vec![block(BlockKind::Heading, json!({"text": "الأسعار"}))],
        ));
        assert!(html.starts_with("<!doctype html><html lang=\"ar\" dir=\"rtl\">"));
        assert!(html.contains("<h2>الأسعار</h2>"));
        assert!(is_rtl(Some("ar-SA")));
        assert!(!is_rtl(Some("en")));
    }

    #[test]
    fn interactive_blocks_become_hydration_points() {
        let html = render_page(&page(
            "en",
            vec![block(
                BlockKind::Columns,
                json!({"columns": [
                    {"blocks": [{"id": Uuid::nil(), "kind": "chart", "props": {"query_id": Uuid::nil()}}]},
                    {"blocks": [{"id": Uuid::nil(), "kind": "heading", "props": {"text": "Side"}}]}
                ]}),
            )],
        ));
        assert!(html.contains(
            "<div class=\"ac-columns\"><div class=\"ac-column\"><div data-hydrate=\"chart\""
        ));
        assert!(html.contains("data-props=\"{&quot;query_id&quot;"));
        assert!(html.contains("<h2>Side</h2>"));
    }
}
