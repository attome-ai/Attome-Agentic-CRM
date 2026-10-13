//! The BFS same-origin crawl algorithm, generic over a [`Fetcher`] so it is
//! unit-testable against a fake in-memory implementation with zero real
//! network/SSRF surface (see `tests` below) — no bypass flag lives anywhere
//! near `crate::safety`'s production SSRF path.
//!
//! `parent_path`/`depth` are derived purely from a page's URL path segments
//! (a materialized path, same shape `attome_document.folder` already uses in
//! this codebase — D-364), not from crawl/discovery order: a page reachable
//! via two different links has one unambiguous position in the tree either
//! way, and the tree the "Crawled Pages Details" page renders doesn't depend
//! on which link the crawler happened to follow first.

use std::collections::{HashSet, VecDeque};

use reqwest::Url;
use scraper::{Html, Selector};
use uuid::Uuid;

use attome_core::EngineState;
use attome_types::AppError;

use crate::safety::{self, FetchedPage, RobotsRules};

pub trait Fetcher {
    fn fetch(
        &self,
        url: &Url,
    ) -> impl std::future::Future<Output = Result<FetchedPage, String>> + Send;
}

pub struct RealFetcher {
    pub client: attome_server::ssrf_guard::GuardedClient,
    pub max_bytes: usize,
    pub user_agent: String,
}

impl std::fmt::Debug for RealFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealFetcher").finish_non_exhaustive()
    }
}

impl Fetcher for RealFetcher {
    async fn fetch(&self, url: &Url) -> Result<FetchedPage, String> {
        safety::fetch_safely(&self.client, url, self.max_bytes, &self.user_agent)
            .await
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPage {
    pub url_path: String,
    pub parent_path: Option<String>,
    pub depth: i32,
    /// `"crawled"` or `"failed"`.
    pub status: &'static str,
    pub size_bytes: Option<i32>,
    pub content: Option<String>,
}

pub trait PageSink {
    fn record(&mut self, page: DiscoveredPage) -> impl std::future::Future<Output = ()> + Send;
}

pub struct CrawlLimits {
    pub max_pages: usize,
    pub max_depth: i32,
}

impl std::fmt::Debug for CrawlLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrawlLimits").finish_non_exhaustive()
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn normalize_path(url: &Url) -> String {
    let mut p = url.path().to_string();
    if p.is_empty() {
        p = "/".to_string();
    }
    if let Some(q) = url.query() {
        p.push('?');
        p.push_str(q);
    }
    p
}

fn path_depth(path: &str) -> i32 {
    let path = path.split('?').next().unwrap_or(path);
    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .count() as i32
}

fn parent_of(path: &str) -> Option<String> {
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only == "/" || path_only.is_empty() {
        return None;
    }
    let trimmed = path_only.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None => Some("/".to_string()),
        Some(idx) => Some(trimmed[..idx].to_string()),
    }
}

fn extract_links(html: &str, base: &Url) -> Vec<Url> {
    let doc = Html::parse_document(html);
    let Ok(sel) = Selector::parse("a[href]") else {
        return Vec::new();
    };
    doc.select(&sel)
        .filter_map(|el| el.value().attr("href"))
        .filter_map(|href| base.join(href).ok())
        .collect()
}

/// Walks `root` same-origin via BFS, up to `limits`, recording every visited
/// page (success or failure) through `sink`. Pure algorithm — no DB, no real
/// network — so tests can supply a fake `Fetcher`/`PageSink` and prove the
/// traversal, cap enforcement, and tree derivation with zero SSRF surface.
pub async fn walk<F: Fetcher, S: PageSink>(
    fetcher: &F,
    root: &Url,
    limits: &CrawlLimits,
    robots: &RobotsRules,
    sink: &mut S,
) {
    let origin = root.clone();
    let root_path = normalize_path(root);

    let mut queue = VecDeque::new();
    queue.push_back(root.clone());
    let mut seen = HashSet::new();
    seen.insert(root_path);

    let mut visited = 0usize;
    while let Some(url) = queue.pop_front() {
        if visited >= limits.max_pages {
            break;
        }
        let path = normalize_path(&url);
        let depth = path_depth(&path);
        if depth > limits.max_depth {
            continue;
        }
        if !robots.allows(&path) {
            continue;
        }
        visited += 1;

        match fetcher.fetch(&url).await {
            Ok(page) => {
                let is_html = page.content_type.starts_with("text/html");
                let is_text = page.content_type.starts_with("text/plain");
                let size = page.body.len() as i32;
                let content = if is_html {
                    // Visible text only: `<script>`/`<style>`/`<noscript>`
                    // content is code or a fallback, never page content a
                    // knowledge-base import should see (owner decision 4).
                    Some(attome_html::html_to_text(&page.body))
                } else if is_text {
                    Some(page.body.clone())
                } else {
                    None
                };
                sink.record(DiscoveredPage {
                    url_path: path.clone(),
                    parent_path: parent_of(&path),
                    depth,
                    status: "crawled",
                    size_bytes: Some(size),
                    content,
                })
                .await;

                if is_html {
                    for link in extract_links(&page.body, &url) {
                        if same_origin(&link, &origin) {
                            let lp = normalize_path(&link);
                            if !seen.contains(&lp) {
                                seen.insert(lp);
                                queue.push_back(link);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                sink.record(DiscoveredPage {
                    url_path: path.clone(),
                    parent_path: parent_of(&path),
                    depth,
                    status: "failed",
                    size_bytes: None,
                    content: None,
                })
                .await;
            }
        }
    }
}

// ── Production entrypoint ───────────────────────────────────────────────────

const USER_AGENT: &str = "AttomeKnowledgeBaseCrawler/1.0";

struct DbPageSink<'a> {
    db: &'a attome_db::DbPool,
    target_id: Uuid,
    recorded: i32,
}

impl PageSink for DbPageSink<'_> {
    async fn record(&mut self, page: DiscoveredPage) {
        let result = sqlx::query(
            r#"INSERT INTO webcrawl_page
                   (target_ref, url_path, parent_path, depth, size_bytes, status, content)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (target_ref, url_path) DO UPDATE
               SET parent_path = EXCLUDED.parent_path,
                   depth = EXCLUDED.depth,
                   size_bytes = EXCLUDED.size_bytes,
                   status = EXCLUDED.status,
                   content = EXCLUDED.content,
                   row_version = webcrawl_page.row_version + 1,
                   updated_at = NOW()"#,
        )
        .bind(self.target_id)
        .bind(&page.url_path)
        .bind(&page.parent_path)
        .bind(page.depth)
        .bind(page.size_bytes)
        .bind(page.status)
        .bind(&page.content)
        .execute(self.db)
        .await;
        match result {
            Ok(_) => self.recorded += 1,
            Err(e) => tracing::warn!(
                target_id = %self.target_id,
                url_path = %page.url_path,
                error = %e,
                "webcrawl: failed to persist a discovered page — continuing the crawl"
            ),
        }
    }
}

async fn set_target_status(
    db: &attome_db::DbPool,
    target_id: Uuid,
    status: &str,
    last_error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE webcrawl_target \
         SET status = $2, last_error = $3, row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(target_id)
    .bind(status)
    .bind(last_error)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The job body for `EngineJob::CrawlWebsite`. Never fails the whole job
/// on a crawl-domain failure (unreachable host, SSRF-rejected address,
/// timeout) — those are recorded on the target row (`status='failed'`,
/// `last_error`) so the admin UI shows why, rather than retried by apalis's
/// generic job-failure machinery, which has no way to know a permanently
/// unreachable site will ever succeed. Returns `Err` only for a genuine
/// infrastructure failure (DB unavailable), which apalis's normal retry
/// *should* cover.
pub async fn run(state: &EngineState, target_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let cfg = state.base.config.webcrawl.clone();

    let row: Option<(String, i16)> = sqlx::query_as(
        "SELECT url, max_depth FROM webcrawl_target WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(target_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((url_str, max_depth)) = row else {
        tracing::info!(target_id = %target_id, "webcrawl: target no longer exists, skipping");
        return Ok(());
    };
    let Ok(root) = Url::parse(&url_str) else {
        set_target_status(db, target_id, "failed", Some("stored URL no longer parses")).await?;
        return Ok(());
    };

    set_target_status(db, target_id, "crawling", None).await?;

    let client = match safety::build_client(cfg.request_timeout_secs) {
        Ok(c) => c,
        Err(e) => {
            set_target_status(db, target_id, "failed", Some(&e.to_string())).await?;
            return Ok(());
        }
    };

    let robots = safety::fetch_robots_rules(&client, &root, USER_AGENT).await;
    let fetcher = RealFetcher {
        client,
        max_bytes: cfg.max_page_bytes,
        user_agent: USER_AGENT.to_string(),
    };
    let limits = CrawlLimits {
        max_pages: cfg.max_pages as usize,
        max_depth: max_depth as i32,
    };

    let mut sink = DbPageSink {
        db,
        target_id,
        recorded: 0,
    };
    walk(&fetcher, &root, &limits, &robots, &mut sink).await;

    let (status, last_error) = if sink.recorded == 0 {
        (
            "failed",
            Some("no pages could be crawled — see the root page's own error".to_string()),
        )
    } else {
        ("completed", None)
    };
    sqlx::query(
        "UPDATE webcrawl_target \
         SET status = $2, last_error = $3, pages_found = $4, last_crawled_at = NOW(), \
             row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(target_id)
    .bind(status)
    .bind(last_error)
    .bind(sink.recorded)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeFetcher(HashMap<String, (&'static str, String)>);

    impl Fetcher for FakeFetcher {
        async fn fetch(&self, url: &Url) -> Result<FetchedPage, String> {
            self.0
                .get(url.as_str())
                .map(|(ct, body)| FetchedPage {
                    content_type: ct.to_string(),
                    body: body.clone(),
                })
                .ok_or_else(|| "404".to_string())
        }
    }

    #[derive(Default)]
    struct VecSink(Vec<DiscoveredPage>);

    impl PageSink for VecSink {
        async fn record(&mut self, page: DiscoveredPage) {
            self.0.push(page);
        }
    }

    fn html(links: &[&str], text: &str) -> String {
        let anchors: String = links
            .iter()
            .map(|l| format!(r#"<a href="{l}">link</a>"#))
            .collect();
        format!("<html><body>{text}{anchors}</body></html>")
    }

    #[tokio::test]
    async fn walks_same_origin_links_breadth_first() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            (
                "text/html",
                html(&["/about", "https://other.example/x"], "home"),
            ),
        );
        pages.insert(
            "https://example.com/about".to_string(),
            ("text/html", html(&[], "about page")),
        );
        let fetcher = FakeFetcher(pages);
        let root = Url::parse("https://example.com/").unwrap();
        let limits = CrawlLimits {
            max_pages: 10,
            max_depth: 3,
        };
        let mut sink = VecSink::default();

        walk(&fetcher, &root, &limits, &RobotsRules::default(), &mut sink).await;

        let paths: Vec<_> = sink.0.iter().map(|p| p.url_path.clone()).collect();
        assert_eq!(paths, vec!["/".to_string(), "/about".to_string()]);
        // The off-origin link must never be followed.
        assert!(!paths.iter().any(|p| p.contains("other.example")));
    }

    #[tokio::test]
    async fn stops_at_max_pages() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            ("text/html", html(&["/a", "/b", "/c"], "")),
        );
        for p in ["a", "b", "c"] {
            pages.insert(
                format!("https://example.com/{p}"),
                ("text/html", html(&[], "")),
            );
        }
        let fetcher = FakeFetcher(pages);
        let root = Url::parse("https://example.com/").unwrap();
        let limits = CrawlLimits {
            max_pages: 2,
            max_depth: 5,
        };
        let mut sink = VecSink::default();

        walk(&fetcher, &root, &limits, &RobotsRules::default(), &mut sink).await;

        assert_eq!(sink.0.len(), 2);
    }

    #[tokio::test]
    async fn records_a_failed_fetch_instead_of_aborting_the_crawl() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            ("text/html", html(&["/missing", "/ok"], "")),
        );
        pages.insert(
            "https://example.com/ok".to_string(),
            ("text/html", html(&[], "ok")),
        );
        let fetcher = FakeFetcher(pages);
        let root = Url::parse("https://example.com/").unwrap();
        let limits = CrawlLimits {
            max_pages: 10,
            max_depth: 3,
        };
        let mut sink = VecSink::default();

        walk(&fetcher, &root, &limits, &RobotsRules::default(), &mut sink).await;

        let missing = sink.0.iter().find(|p| p.url_path == "/missing").unwrap();
        assert_eq!(missing.status, "failed");
        let ok = sink.0.iter().find(|p| p.url_path == "/ok").unwrap();
        assert_eq!(ok.status, "crawled");
    }

    #[tokio::test]
    async fn respects_robots_disallow() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            ("text/html", html(&["/private"], "")),
        );
        pages.insert(
            "https://example.com/private".to_string(),
            ("text/html", html(&[], "secret")),
        );
        let fetcher = FakeFetcher(pages);
        let root = Url::parse("https://example.com/").unwrap();
        let limits = CrawlLimits {
            max_pages: 10,
            max_depth: 3,
        };
        let robots = RobotsRules::parse("User-agent: *\nDisallow: /private\n");
        let mut sink = VecSink::default();

        walk(&fetcher, &root, &limits, &robots, &mut sink).await;

        assert!(!sink.0.iter().any(|p| p.url_path == "/private"));
    }

    #[test]
    fn parent_of_derives_a_materialized_path_tree() {
        assert_eq!(parent_of("/"), None);
        assert_eq!(parent_of("/about"), Some("/".to_string()));
        assert_eq!(parent_of("/about/team"), Some("/about".to_string()));
        assert_eq!(parent_of("/about/team/"), Some("/about".to_string()));
    }

    #[test]
    fn path_depth_counts_segments() {
        assert_eq!(path_depth("/"), 0);
        assert_eq!(path_depth("/about"), 1);
        assert_eq!(path_depth("/about/team"), 2);
    }

    #[test]
    fn extract_text_excludes_script_and_style_content() {
        let doc = "<html><head><style>.x{color:red}</style></head><body><script>evil()</script><p>Hello world</p></body></html>";
        let text = attome_html::html_to_text(doc);
        assert!(text.contains("Hello world"));
        assert!(!text.contains("evil"));
        assert!(!text.contains("color:red"));
    }

    /// The crawl's text extraction (`attome_html::html_to_text` since owner
    /// decision 4) promises `<noscript>` is excluded. Worth its own test
    /// rather than a third assertion in the case above: `<noscript>` is the
    /// one of the three whose *parsing* is conditional — html5ever treats its
    /// contents as raw text when scripting is enabled and as ordinary markup
    /// when it is not, so which nodes end up under it is a parser decision,
    /// not a selector one. That makes it the element most likely to shift
    /// under a `scraper`/`html5ever` upgrade while still compiling and while
    /// the script/style case above stays green (CI-15: scraper 0.20 -> 0.27;
    /// attome-html's `ammonia` parses through the same `html5ever`).
    #[test]
    fn extract_text_excludes_noscript_content_including_nested_markup() {
        let doc = "<html><body><noscript>enable js</noscript>                   <noscript><p>nested fallback</p></noscript>                   <p>Hello world</p></body></html>";
        let text = attome_html::html_to_text(doc);
        assert!(
            text.contains("Hello world"),
            "real content must survive: {text:?}"
        );
        assert!(
            !text.contains("enable js"),
            "bare noscript text leaked: {text:?}"
        );
        assert!(
            !text.contains("nested fallback"),
            "markup nested under noscript leaked: {text:?}"
        );
    }

    #[test]
    fn extract_links_resolves_relative_hrefs_against_the_page_url() {
        let base = Url::parse("https://example.com/blog/post").unwrap();
        let links = extract_links(
            r#"<a href="../about">x</a><a href="https://other.example/">y</a>"#,
            &base,
        );
        let strs: Vec<_> = links.iter().map(|u| u.to_string()).collect();
        assert!(strs.contains(&"https://example.com/about".to_string()));
        assert!(strs.contains(&"https://other.example/".to_string()));
    }
}
