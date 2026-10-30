//! E12-T2: a content space as a site — its domain, title, theme, menu and
//! blog.
//!
//! - **Domain**: a space may name one domain (unique among live spaces);
//!   `GET /api/v1/content/site?path=` serves the page at `path` of the space
//!   whose domain is the request's host, as E12-T1's stored HTML.
//! - **Theme**: a map of the renderer's CSS custom properties to values,
//!   served as `GET /api/v1/content/theme.css?space=` and linked from every
//!   rendered page, so a theme change needs no republish. Only the known
//!   properties are accepted, and a value may hold only characters a colour,
//!   length or font list needs ([`theme_css`]).
//! - **Menu**: ordered links (`label`, optional `label_ar`, site `path`),
//!   written into a rendered page where it says `<!--ac-site-nav-->` when the
//!   page is served, so a menu change needs no republish either.
//! - **Blog**: the published public pages under the space's `blog_path`,
//!   newest first, are its posts, and `GET /api/v1/content/rss?space=` is
//!   their RSS 2.0 feed.

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_html::escape_html;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// Where a rendered page takes the site's menu.
pub const NAV_PLACEHOLDER: &str = "<!--ac-site-nav-->";
/// Posts an RSS feed lists.
pub const RSS_ITEMS: i64 = 20;
/// Links a menu may hold.
pub const MAX_MENU_ITEMS: usize = 30;

/// The theme properties a site may set.
pub const THEME_PROPERTIES: &[&str] = &[
    "--ac-text",
    "--ac-muted",
    "--ac-bg",
    "--ac-info",
    "--ac-success",
    "--ac-warning",
    "--ac-danger",
    "--ac-font",
];

/// One menu link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MenuItem {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_ar: Option<String>,
    /// A path on the site (`/pricing`) or an absolute http(s) URL.
    pub path: String,
}

/// A site's settings, as served.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SiteConfig {
    pub space_id: Uuid,
    pub domain: Option<String>,
    pub title: Option<String>,
    pub theme: BTreeMap<String, String>,
    pub menu: Vec<MenuItem>,
    pub blog_path: Option<String>,
    pub row_version: i64,
}

/// A host name as stored and matched (moved to `attome_types::text` for
/// portal domains too, G12-T3).
pub use attome_types::text::normalise_domain;

/// Whether a theme value is safe inside a declaration: the characters a
/// colour, length or font list needs, nothing that ends the declaration or
/// opens a URL. Pure.
pub fn safe_css_value(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty()
        && v.len() <= 120
        && !v.to_ascii_lowercase().contains("url(")
        && !v.to_ascii_lowercase().contains("expression")
        && v.chars()
            .all(|c| c.is_alphanumeric() || " #%(),.-'\"".contains(c))
}

/// Checks a theme: known properties and safe values only. Pure.
pub fn validate_theme(theme: &BTreeMap<String, String>) -> Result<(), AppError> {
    for (key, value) in theme {
        if !THEME_PROPERTIES.contains(&key.as_str()) {
            return Err(AppError::Validation(format!(
                "theme: {key} is not a theme property ({})",
                THEME_PROPERTIES.join(", ")
            )));
        }
        if !safe_css_value(value) {
            return Err(AppError::Validation(format!(
                "theme: the value of {key} is not a plain colour, length or font"
            )));
        }
    }
    Ok(())
}

/// Checks a menu: at most [`MAX_MENU_ITEMS`] links, each with a label and a
/// site path or http(s) URL. Pure.
pub fn validate_menu(menu: &[MenuItem]) -> Result<(), AppError> {
    if menu.len() > MAX_MENU_ITEMS {
        return Err(AppError::Validation(format!(
            "menu: at most {MAX_MENU_ITEMS} links"
        )));
    }
    for item in menu {
        if item.label.trim().is_empty() {
            return Err(AppError::Validation(
                "menu: every link needs a label".into(),
            ));
        }
        if !link_ok(&item.path) {
            return Err(AppError::Validation(format!(
                "menu: {} is not a site path or an http(s) URL",
                item.path
            )));
        }
    }
    Ok(())
}

fn link_ok(path: &str) -> bool {
    let p = path.trim().to_ascii_lowercase();
    p.starts_with("https://")
        || p.starts_with("http://")
        || (p.starts_with('/') && !p.starts_with("//"))
}

/// The theme as a stylesheet. Unknown properties and unsafe values are left
/// out (stored themes were checked; this keeps the output safe anyway).
/// Pure.
pub fn theme_css(theme: &BTreeMap<String, String>) -> String {
    let body: String = theme
        .iter()
        .filter(|(k, v)| THEME_PROPERTIES.contains(&k.as_str()) && safe_css_value(v))
        .map(|(k, v)| format!("{k}:{};", v.trim()))
        .collect();
    let font = theme
        .get("--ac-font")
        .filter(|v| safe_css_value(v))
        .map(|_| "body{font-family:var(--ac-font)}")
        .unwrap_or_default();
    format!(":root{{{body}}}{font}")
}

/// The menu as a `<nav>`, labels in the page's language. Pure.
pub fn menu_html(menu: &[MenuItem], arabic: bool, current_path: &str) -> String {
    if menu.is_empty() {
        return String::new();
    }
    let mut out = String::from("<nav class=\"ac-site-nav\"><ul>");
    for item in menu.iter().filter(|i| link_ok(&i.path)) {
        let label = if arabic {
            item.label_ar
                .as_deref()
                .filter(|l| !l.trim().is_empty())
                .unwrap_or(&item.label)
        } else {
            &item.label
        };
        let current = if item.path.trim() == current_path {
            " aria-current=\"page\""
        } else {
            ""
        };
        out.push_str(&format!(
            "<li><a href=\"{}\"{current}>{}</a></li>",
            escape_html(item.path.trim()),
            escape_html(label)
        ));
    }
    out.push_str("</ul></nav>");
    out
}

/// One blog post.
#[derive(Debug, Clone, PartialEq)]
pub struct Post {
    pub title: String,
    pub url_path: String,
    pub published_at: DateTime<Utc>,
    pub description: Option<String>,
}

fn xml(text: &str) -> String {
    escape_html(text)
}

/// The site's RSS 2.0 feed. Pure.
pub fn rss(site_title: &str, site_url: &str, posts: &[Post]) -> String {
    let base = site_url.trim_end_matches('/');
    let mut out =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><rss version=\"2.0\"><channel>");
    out.push_str(&format!(
        "<title>{}</title><link>{}</link><description>{}</description>",
        xml(site_title),
        xml(base),
        xml(site_title)
    ));
    for post in posts {
        let link = format!("{base}{}", post.url_path);
        out.push_str("<item>");
        out.push_str(&format!("<title>{}</title>", xml(&post.title)));
        out.push_str(&format!("<link>{}</link>", xml(&link)));
        out.push_str(&format!("<guid isPermaLink=\"true\">{}</guid>", xml(&link)));
        out.push_str(&format!(
            "<pubDate>{}</pubDate>",
            post.published_at.to_rfc2822()
        ));
        if let Some(d) = post.description.as_deref().filter(|d| !d.trim().is_empty()) {
            out.push_str(&format!("<description>{}</description>", xml(d)));
        }
        out.push_str("</item>");
    }
    out.push_str("</channel></rss>");
    out
}

type SiteRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Value,
    Value,
    Option<String>,
    i64,
);

fn site(row: SiteRow) -> SiteConfig {
    let (space_id, domain, title, theme, menu, blog_path, row_version) = row;
    SiteConfig {
        space_id,
        domain,
        title,
        theme: serde_json::from_value(theme).unwrap_or_default(),
        menu: serde_json::from_value(menu).unwrap_or_default(),
        blog_path,
        row_version,
    }
}

const SITE_COLUMNS: &str = "id, domain, site_title, theme, menu, blog_path, row_version";

/// The live space whose domain is `host`.
pub async fn site_for_host(db: &DbPool, host: &str) -> Result<Option<SiteConfig>, AppError> {
    let Some(domain) = normalise_domain(host) else {
        return Ok(None);
    };
    let row: Option<SiteRow> = sqlx::query_as(&format!(
        "SELECT {SITE_COLUMNS} FROM content_space \
          WHERE lower(domain) = $1 AND is_deleted = FALSE"
    ))
    .bind(domain)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(site))
}

/// A live space's site settings.
pub async fn site_for_space(db: &DbPool, space: Uuid) -> Result<Option<SiteConfig>, AppError> {
    let row: Option<SiteRow> = sqlx::query_as(&format!(
        "SELECT {SITE_COLUMNS} FROM content_space WHERE id = $1 AND is_deleted = FALSE"
    ))
    .bind(space)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(site))
}

/// The site's newest published public posts (pages under its blog path).
pub async fn recent_posts(db: &DbPool, site: &SiteConfig) -> Result<Vec<Post>, AppError> {
    let Some(prefix) = site.blog_path.as_deref().filter(|p| p.starts_with('/')) else {
        return Ok(Vec::new());
    };
    let prefix = format!("{}/", prefix.trim_end_matches('/'));
    let rows: Vec<(String, String, DateTime<Utc>, Option<String>)> = sqlx::query_as(
        "SELECT title, url_path, published_at, seo_description FROM content_page \
          WHERE content_space_id = $1 AND status = 'published' AND is_deleted = FALSE \
            AND audience = 'public' AND published_at IS NOT NULL \
            AND left(url_path, length($2)) = $2 \
          ORDER BY published_at DESC, id DESC LIMIT $3",
    )
    .bind(site.space_id)
    .bind(&prefix)
    .bind(RSS_ITEMS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(title, url_path, published_at, description)| Post {
            title,
            url_path,
            published_at,
            description,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn theme(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn domains_normalise_and_bad_ones_are_refused() {
        assert_eq!(
            normalise_domain("Shop.Example.COM:443").as_deref(),
            Some("shop.example.com")
        );
        assert_eq!(
            normalise_domain("example.com.").as_deref(),
            Some("example.com")
        );
        assert!(normalise_domain("localhost").is_none());
        assert!(normalise_domain("bad_host.com").is_none());
        assert!(normalise_domain("-x.com").is_none());
    }

    #[test]
    fn theme_values_are_sanitised() {
        assert!(
            validate_theme(&theme(&[
                ("--ac-bg", "#fafafa"),
                ("--ac-font", "'Noto Kufi Arabic', sans-serif")
            ]))
            .is_ok()
        );
        assert!(validate_theme(&theme(&[("--ac-bg", "red;}body{display:none")])).is_err());
        assert!(validate_theme(&theme(&[("--ac-bg", "url(https://x)")])).is_err());
        assert!(validate_theme(&theme(&[("color", "red")])).is_err());
        let css = theme_css(&theme(&[("--ac-bg", "#fff"), ("--ac-text", "</style>")]));
        assert_eq!(css, ":root{--ac-bg:#fff;}");
    }

    #[test]
    fn menu_renders_with_escaped_labels() {
        let menu = vec![
            MenuItem {
                label: "Home & news".into(),
                label_ar: Some("الرئيسية".into()),
                path: "/".into(),
            },
            MenuItem {
                label: "Blog".into(),
                label_ar: None,
                path: "/blog".into(),
            },
            MenuItem {
                label: "Bad".into(),
                label_ar: None,
                path: "javascript:alert(1)".into(),
            },
        ];
        assert!(validate_menu(&menu).is_err());
        let html = menu_html(&menu, false, "/blog");
        assert!(html.contains("<a href=\"/\">Home &amp; news</a>"));
        assert!(html.contains("<a href=\"/blog\" aria-current=\"page\">Blog</a>"));
        assert!(!html.contains("javascript"));
        assert!(menu_html(&menu, true, "/").contains(">الرئيسية</a>"));
    }

    #[test]
    fn rss_lists_posts_with_absolute_links() {
        let at = |d: u32| {
            format!("2026-10-{d:02}T09:00:00Z")
                .parse::<DateTime<Utc>>()
                .unwrap()
        };
        let posts = vec![
            Post {
                title: "Second <post>".into(),
                url_path: "/blog/two".into(),
                published_at: at(20),
                description: Some("More".into()),
            },
            Post {
                title: "First".into(),
                url_path: "/blog/one".into(),
                published_at: at(10),
                description: None,
            },
        ];
        let feed = rss("Acme", "https://acme.example/", &posts);
        assert!(
            feed.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?><rss version=\"2.0\">")
        );
        assert!(feed.contains("<title>Second &lt;post&gt;</title>"));
        assert!(feed.contains("<link>https://acme.example/blog/two</link>"));
        assert!(feed.contains("<pubDate>Tue, 20 Oct 2026 09:00:00 +0000</pubDate>"));
        assert!(feed.find("blog/two").unwrap() < feed.find("blog/one").unwrap());
    }
}
