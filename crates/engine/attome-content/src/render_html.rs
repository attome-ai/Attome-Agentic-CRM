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
//! paragraph), the canonical link and robots directives (E12-T1); and
//! (E13-T6) the Open Graph card (`og:title`, `og:description`, `og:image`,
//! `og:locale`), the X card, an `hreflang` link for every published public
//! language version of the page (its K5 linked translations) with
//! `x-default` on the original, and one JSON-LD script for each structured
//! data document that passes `validate_json_ld` (one that fails is logged
//! with the page and skipped). Absolute URLs start from the deployment's
//! public frontend URL (`app.public_frontend_url`). Attribute values are
//! HTML-escaped; JSON-LD is written as JSON with `<` escaped so it cannot
//! close its script.

use attome_html::escape_html;
use serde_json::Value;

use crate::model::{Block, BlockKind};

/// How deep columns may nest.
const MAX_DEPTH: usize = 3;

/// What `<head>` says.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HeadInput {
    pub title: String,
    pub description: Option<String>,
    pub canonical_url: Option<String>,
    pub noindex: bool,
    pub nofollow: bool,
    /// `ar`, `en`, …; `None` is English.
    pub language: Option<String>,
    /// E13-T6: the Open Graph card.
    pub og_title: Option<String>,
    pub og_description: Option<String>,
    /// An absolute URL.
    pub og_image: Option<String>,
    /// The page's language versions: (language, absolute URL).
    pub alternates: Vec<(String, String)>,
    /// The original language version's absolute URL.
    pub x_default: Option<String>,
    /// Structured data documents that passed validation.
    pub json_ld: Vec<Value>,
}

/// Where the site is served, for absolute URLs.
#[derive(Debug, Clone, Default)]
pub struct Site {
    /// The deployment's public frontend URL, without a trailing slash.
    pub base_url: String,
}

impl Site {
    /// `path` (a site path) as an absolute URL; an absolute URL unchanged.
    /// Pure.
    pub fn absolute(&self, path: &str) -> String {
        let p = path.trim();
        if p.starts_with("http://") || p.starts_with("https://") {
            return p.to_owned();
        }
        let base = self.base_url.trim().trim_end_matches('/');
        if p.starts_with('/') {
            format!("{base}{p}")
        } else {
            format!("{base}/{p}")
        }
    }
}

/// The Open Graph locale for a language. Pure.
pub fn og_locale(language: Option<&str>) -> &'static str {
    match language
        .map(|l| l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase())
        .as_deref()
    {
        Some("ar") => "ar_SA",
        Some("fr") => "fr_FR",
        Some("es") => "es_ES",
        Some("de") => "de_DE",
        _ => "en_US",
    }
}

/// JSON safe inside a `<script>` element: `<` written as `\u003c`. Pure.
pub fn script_json(value: &Value) -> String {
    value.to_string().replace('<', "\\u003c")
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
    let meta = |out: &mut String, property: &str, content: &str| {
        out.push_str(&format!(
            "<meta property=\"{property}\" content=\"{}\">",
            escape_html(content)
        ));
    };
    meta(
        &mut out,
        "og:title",
        head.og_title.as_deref().unwrap_or(&head.title),
    );
    if let Some(d) = head
        .og_description
        .as_deref()
        .or(head.description.as_deref())
        .filter(|d| !d.trim().is_empty())
    {
        meta(&mut out, "og:description", d);
    }
    if let Some(i) = head.og_image.as_deref().filter(|i| safe_url(i)) {
        meta(&mut out, "og:image", i);
    }
    if let Some(c) = head.canonical_url.as_deref().filter(|c| safe_url(c)) {
        meta(&mut out, "og:url", c);
    }
    meta(&mut out, "og:type", "website");
    meta(&mut out, "og:locale", og_locale(head.language.as_deref()));
    out.push_str("<meta name=\"twitter:card\" content=\"summary_large_image\">");
    for (language, url) in &head.alternates {
        if safe_url(url) {
            out.push_str(&format!(
                "<link rel=\"alternate\" hreflang=\"{}\" href=\"{}\">",
                escape_html(language),
                escape_html(url)
            ));
        }
    }
    if let Some(url) = head.x_default.as_deref().filter(|u| safe_url(u)) {
        out.push_str(&format!(
            "<link rel=\"alternate\" hreflang=\"x-default\" href=\"{}\">",
            escape_html(url)
        ));
    }
    for doc in &head.json_ld {
        out.push_str("<script type=\"application/ld+json\">");
        out.push_str(&script_json(doc));
        out.push_str("</script>");
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
    site: &Site,
) -> Result<(), attome_types::AppError> {
    use attome_types::AppError;
    type Row = (
        String,
        Value,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<uuid::Uuid>,
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT v.title, v.blocks, v.seo_title, v.seo_description, p.seo_canonical_url, \
                p.seo_noindex, p.seo_nofollow, p.language, p.og_title, p.og_description, \
                p.translation_of, p.page_type \
           FROM content_page_version v JOIN content_page p ON p.id = v.page_id \
          WHERE v.page_id = $1 AND v.version_number = $2",
    )
    .bind(page_id)
    .bind(version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((
        title,
        blocks,
        seo_title,
        seo_description,
        canonical,
        noindex,
        nofollow,
        language,
        og_title,
        og_description,
        translation_of,
        page_type,
    )) = row
    else {
        return Ok(());
    };
    let detail: Option<crate::model::PageDetail> = sqlx::query_as(&format!(
        "SELECT {} FROM content_page WHERE id = $1 AND is_deleted = FALSE",
        crate::admin::PAGE_COLUMNS
    ))
    .bind(page_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let blocks: Vec<Block> = serde_json::from_value(blocks).unwrap_or_default();
    let stored = crate::seo::settings::PageSeo {
        title: seo_title,
        description: seo_description,
        canonical_url: canonical,
        noindex,
        nofollow,
        og_title,
        og_description,
        og_image_ref: None,
    };
    let seo = match &detail {
        Some(d) => crate::seo::settings::effective(&stored, d, "", &site.base_url),
        None => stored.clone(),
    };

    // K5 linked translations: every published public language version.
    let root = translation_of.unwrap_or(page_id);
    let versions: Vec<(uuid::Uuid, Option<String>, String)> = sqlx::query_as(
        "SELECT id, language, url_path FROM content_page \
          WHERE (id = $1 OR translation_of = $1) AND status = 'published' \
            AND is_deleted = FALSE AND audience = 'public' ORDER BY id",
    )
    .bind(root)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let alternates: Vec<(String, String)> = if versions.len() > 1 {
        versions
            .iter()
            .filter_map(|(_, l, path)| {
                let l = l.as_deref()?.trim();
                (!l.is_empty()).then(|| (l.to_owned(), site.absolute(path)))
            })
            .collect()
    } else {
        Vec::new()
    };
    let x_default = (!alternates.is_empty())
        .then(|| versions.iter().find(|(id, _, _)| *id == root))
        .flatten()
        .map(|(_, _, path)| site.absolute(path));

    // The page's own first image is its card image.
    let og_image = blocks
        .iter()
        .find(|b| b.kind == BlockKind::Image)
        .map(|b| text(&b.props, "src").to_owned())
        .filter(|src| safe_url(src))
        .map(|src| site.absolute(&src));

    let mut json_ld = Vec::new();
    if let Some(d) = detail.as_ref().filter(|_| page_type == "article") {
        let doc = crate::seo::structured_data::json_ld(
            d,
            crate::seo::structured_data::SchemaKind::Article,
            &[],
        );
        match crate::seo::structured_data::validate_json_ld(&doc) {
            Ok(()) => json_ld.push(doc),
            Err(problems) => tracing::warn!(
                page = %page_id,
                problems = ?problems,
                "page structured data failed validation; not written"
            ),
        }
    }

    let html = render_page(&PageInput {
        head: HeadInput {
            title: seo.title.clone().unwrap_or(title),
            description: seo.description.clone(),
            canonical_url: seo.canonical_url.clone(),
            noindex,
            nofollow,
            language,
            og_title: seo.og_title.clone(),
            og_description: seo.og_description.clone(),
            og_image,
            alternates,
            x_default,
            json_ld,
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
    .map_err(AppError::internal)?;
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
                ..HeadInput::default()
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
    fn head_carries_cards_alternates_and_json_ld() {
        let site = Site {
            base_url: "https://example.com/".into(),
        };
        let mut p = page("ar", vec![]);
        p.head.og_image = Some(site.absolute("/media/card.png"));
        p.head.alternates = vec![
            ("ar".into(), site.absolute("/ar/pricing")),
            ("en".into(), site.absolute("/pricing")),
        ];
        p.head.x_default = Some(site.absolute("/pricing"));
        p.head.json_ld = vec![serde_json::json!({
            "@context": "https://schema.org", "@type": "Article",
            "headline": "</script><script>alert(1)</script>", "datePublished": "2026-10-20"
        })];
        let html = render_page(&p);
        assert!(html.contains("<meta property=\"og:title\" content=\"Pricing &amp; plans\">"));
        assert!(html.contains(
            "<meta property=\"og:image\" content=\"https://example.com/media/card.png\">"
        ));
        assert!(html.contains("<meta property=\"og:locale\" content=\"ar_SA\">"));
        assert!(html.contains("<meta name=\"twitter:card\" content=\"summary_large_image\">"));
        assert!(html.contains(
            "<link rel=\"alternate\" hreflang=\"ar\" href=\"https://example.com/ar/pricing\">"
        ));
        assert!(html.contains(
            "<link rel=\"alternate\" hreflang=\"en\" href=\"https://example.com/pricing\">"
        ));
        assert!(html.contains("hreflang=\"x-default\" href=\"https://example.com/pricing\""));
        assert_eq!(html.matches("application/ld+json").count(), 1);
        assert!(
            !html.contains("</script><script>alert"),
            "JSON-LD cannot close its script"
        );
        assert_eq!(og_locale(Some("en-GB")), "en_US");
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
