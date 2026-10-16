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
//!
//! K6-T2 makes the crawl scope-aware and polite ([`walk_with`]): include and
//! exclude patterns (exclude wins), seeding from the sitemap with only the
//! entries changed since the last crawl, conditional requests with the
//! stored `ETag`/`Last-Modified` (a 304 or an unchanged text hash marks the
//! page unchanged and skips extraction), the site's `Crawl-delay` or one
//! second between requests, an identifying user agent, and a stop after
//! [`MAX_CONSECUTIVE_ERRORS`] errors in a row.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

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

    /// A fetch that sends the validators from the last crawl; a fetcher
    /// without conditional support just fetches.
    fn fetch_conditional(
        &self,
        url: &Url,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> impl std::future::Future<Output = Result<FetchedPage, String>> + Send {
        let _ = (etag, last_modified);
        self.fetch(url)
    }
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

    async fn fetch_conditional(
        &self,
        url: &Url,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<FetchedPage, String> {
        safety::fetch_conditional(
            &self.client,
            url,
            self.max_bytes,
            &self.user_agent,
            etag,
            last_modified,
        )
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
    /// K6-T2: the validators and text hash to store for the next crawl.
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_hash: Option<String>,
    /// K6-T2: the page did not change since the last crawl (a 304, or the
    /// same text hash); its stored content stays.
    pub unchanged: bool,
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

/// The most errors in a row before a crawl stops.
pub const MAX_CONSECUTIVE_ERRORS: usize = 20;

/// The least time between two requests to the site.
pub const DEFAULT_HOST_INTERVAL: Duration = Duration::from_secs(1);

/// What the last crawl stored about a page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownPage {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_hash: Option<String>,
}

/// Scope and politeness of one crawl.
#[derive(Debug, Clone, Default)]
pub struct CrawlScope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    /// Extra start pages (from the sitemap), after the root.
    pub seeds: Vec<Url>,
    /// By path.
    pub known: HashMap<String, KnownPage>,
    pub min_interval: Duration,
}

/// How a crawl ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkOutcome {
    /// Why it stopped early, if it did.
    pub stopped: Option<String>,
}

/// Splits a stored pattern list (one per line or comma separated).
pub fn parse_patterns(text: &str) -> Vec<String> {
    text.split(['\n', ','])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether `text` matches a glob: `*` is any run of characters, `?` one.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Whether a path is in scope: no include pattern, or one matching it, and
/// no exclude pattern matching it (exclude wins).
pub fn in_scope(path: &str, include: &[String], exclude: &[String]) -> bool {
    if exclude.iter().any(|p| glob_match(p, path)) {
        return false;
    }
    include.is_empty() || include.iter().any(|p| glob_match(p, path))
}

/// The `<loc>` and `<lastmod>` of each `<url>` in a sitemap.
pub fn parse_sitemap(xml: &str) -> Vec<(String, Option<String>)> {
    fn inner<'a>(block: &'a str, tag: &str) -> Option<&'a str> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = block.find(&open)? + open.len();
        let end = block[start..].find(&close)? + start;
        Some(block[start..end].trim())
    }
    xml.split("<url>")
        .skip(1)
        .filter_map(|block| {
            let block = block.split("</url>").next().unwrap_or(block);
            let loc = inner(block, "loc")?.replace("&amp;", "&");
            Some((loc, inner(block, "lastmod").map(str::to_owned)))
        })
        .collect()
}

fn parse_when(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let text = text.trim();
    chrono::DateTime::parse_from_rfc3339(text)
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(text))
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|d| d.and_utc())
        })
}

/// The sitemap entries worth crawling: same origin, in scope, and either
/// never crawled or changed (by `lastmod`) since the stored `Last-Modified`.
pub fn sitemap_seeds(
    entries: &[(String, Option<String>)],
    root: &Url,
    include: &[String],
    exclude: &[String],
    known: &HashMap<String, KnownPage>,
) -> Vec<Url> {
    entries
        .iter()
        .filter_map(|(loc, lastmod)| {
            let url = Url::parse(loc).ok()?;
            if !same_origin(&url, root) {
                return None;
            }
            let path = normalize_path(&url);
            if !in_scope(&path, include, exclude) {
                return None;
            }
            let changed = match (known.get(&path), lastmod.as_deref().and_then(parse_when)) {
                (None, _) => true,
                (Some(page), Some(modified)) => page
                    .last_modified
                    .as_deref()
                    .and_then(parse_when)
                    .is_none_or(|stored| modified > stored),
                (Some(_), None) => true,
            };
            changed.then_some(url)
        })
        .collect()
}

/// The most lines a change event carries each way.
pub const MAX_DIFF_LINES: usize = 50;

/// K6-T9: the lines added and removed between two versions of a page's
/// text, in order, each list capped at [`MAX_DIFF_LINES`]. A line counts
/// as many times as it appears.
pub fn text_diff(old: &str, new: &str) -> (Vec<String>, Vec<String>) {
    let lines = |t: &str| -> Vec<String> {
        t.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let (old, new) = (lines(old), lines(new));
    let mut remaining: HashMap<&str, usize> = HashMap::new();
    for line in &old {
        *remaining.entry(line.as_str()).or_default() += 1;
    }
    let mut added = Vec::new();
    for line in &new {
        match remaining.get_mut(line.as_str()) {
            Some(n) if *n > 0 => *n -= 1,
            _ => added.push(line.clone()),
        }
    }
    let mut kept: HashMap<&str, usize> = HashMap::new();
    for line in &new {
        *kept.entry(line.as_str()).or_default() += 1;
    }
    let mut removed = Vec::new();
    for line in &old {
        match kept.get_mut(line.as_str()) {
            Some(n) if *n > 0 => *n -= 1,
            _ => removed.push(line.clone()),
        }
    }
    added.truncate(MAX_DIFF_LINES);
    removed.truncate(MAX_DIFF_LINES);
    (added, removed)
}

fn text_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
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
    walk_with(fetcher, root, limits, robots, &CrawlScope::default(), sink).await;
}

/// [`walk`] with a scope and politeness settings (K6-T2).
pub async fn walk_with<F: Fetcher, S: PageSink>(
    fetcher: &F,
    root: &Url,
    limits: &CrawlLimits,
    robots: &RobotsRules,
    scope: &CrawlScope,
    sink: &mut S,
) -> WalkOutcome {
    let origin = root.clone();
    let root_path = normalize_path(root);
    let interval = robots
        .crawl_delay()
        .map_or(scope.min_interval, |d| d.max(scope.min_interval));

    let mut queue = VecDeque::new();
    queue.push_back(root.clone());
    let mut seen = HashSet::new();
    seen.insert(root_path);
    for seed in &scope.seeds {
        if seen.insert(normalize_path(seed)) {
            queue.push_back(seed.clone());
        }
    }

    let mut visited = 0usize;
    let mut errors_in_a_row = 0usize;
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
        // The root is always crawled; everything else must be in scope.
        if visited > 0 && !in_scope(&path, &scope.include, &scope.exclude) {
            continue;
        }
        if visited > 0 && !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
        visited += 1;

        let known = scope.known.get(&path);
        let result = fetcher
            .fetch_conditional(
                &url,
                known.and_then(|k| k.etag.as_deref()),
                known.and_then(|k| k.last_modified.as_deref()),
            )
            .await;
        match result {
            Ok(page) if page.not_modified => {
                errors_in_a_row = 0;
                sink.record(DiscoveredPage {
                    url_path: path.clone(),
                    parent_path: parent_of(&path),
                    depth,
                    status: "crawled",
                    size_bytes: None,
                    content: None,
                    etag: page.etag,
                    last_modified: page.last_modified,
                    content_hash: known.and_then(|k| k.content_hash.clone()),
                    unchanged: true,
                })
                .await;
            }
            Ok(page) => {
                errors_in_a_row = 0;
                let is_html = page.content_type.starts_with("text/html");
                let is_text = page.content_type.starts_with("text/plain");
                let size = page.body.len() as i32;
                let content: Option<String> = if is_html {
                    // Visible text only: `<script>`/`<style>`/`<noscript>`
                    // content is code or a fallback, never page content a
                    // knowledge-base import should see (owner decision 4).
                    Some(attome_html::html_to_text(&page.body))
                } else if is_text {
                    Some(page.body.clone())
                } else {
                    None
                };
                let content_hash = content.as_deref().map(text_hash);
                let unchanged = content_hash.is_some()
                    && known.and_then(|k| k.content_hash.as_deref()) == content_hash.as_deref();
                sink.record(DiscoveredPage {
                    url_path: path.clone(),
                    parent_path: parent_of(&path),
                    depth,
                    status: "crawled",
                    size_bytes: Some(size),
                    content: if unchanged { None } else { content },
                    etag: page.etag.clone(),
                    last_modified: page.last_modified.clone(),
                    content_hash,
                    unchanged,
                })
                .await;

                if is_html {
                    for link in extract_links(&page.body, &url) {
                        if same_origin(&link, &origin) {
                            let lp = normalize_path(&link);
                            if !seen.contains(&lp) && in_scope(&lp, &scope.include, &scope.exclude)
                            {
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
                    etag: None,
                    last_modified: None,
                    content_hash: None,
                    unchanged: false,
                })
                .await;
                errors_in_a_row += 1;
                if errors_in_a_row >= MAX_CONSECUTIVE_ERRORS {
                    return WalkOutcome {
                        stopped: Some(format!(
                            "stopped after {MAX_CONSECUTIVE_ERRORS} errors in a row"
                        )),
                    };
                }
            }
        }
    }
    WalkOutcome::default()
}

// ── Production entrypoint ───────────────────────────────────────────────────

/// K6-T2: the crawler names itself and its version.
fn user_agent() -> String {
    format!(
        "AttomeCrawler/{} (+contact the site's Attome administrator)",
        env!("CARGO_PKG_VERSION")
    )
}

struct DbPageSink<'a> {
    db: &'a attome_db::DbPool,
    target_id: Uuid,
    recorded: i32,
    /// K6-T9: a watch-only source reports each changed page as an event.
    watch_only: bool,
}

impl DbPageSink<'_> {
    /// Emits `webcrawl.page_changed` with the text difference when a
    /// watched page's text changed. Best effort: a failure is logged.
    async fn report_change(&self, url_path: &str, old: &str, new: &str) {
        let (added, removed) = text_diff(old, new);
        if added.is_empty() && removed.is_empty() {
            return;
        }
        let result: Result<(), AppError> = async {
            let page_id: Uuid = sqlx::query_scalar(
                "SELECT id FROM webcrawl_page WHERE target_ref = $1 AND url_path = $2",
            )
            .bind(self.target_id)
            .bind(url_path)
            .fetch_one(self.db)
            .await
            .map_err(AppError::internal)?;
            let mut conn = self.db.acquire().await.map_err(AppError::internal)?;
            attome_core::change_feed::emit_with(
                &mut conn,
                "webcrawl_page",
                page_id,
                attome_core::change_feed::ChangeOperation::Update,
                Some("webcrawl.page_changed"),
                &attome_core::change_feed::ChangePayload {
                    changed_attributes: vec!["content".to_owned()],
                    before: Some(serde_json::json!({
                        "target_id": self.target_id, "url_path": url_path, "removed": removed,
                    })),
                    after: Some(serde_json::json!({
                        "target_id": self.target_id, "url_path": url_path, "added": added,
                    })),
                },
            )
            .await
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(target_id = %self.target_id, url_path, error = %e,
                "webcrawl: could not report a watched page's change");
        }
    }
}

impl PageSink for DbPageSink<'_> {
    async fn record(&mut self, page: DiscoveredPage) {
        if page.unchanged {
            // K6-T2: the stored text stays; only the validators move.
            let result = sqlx::query(
                "UPDATE webcrawl_page SET etag = COALESCE($3, etag), \
                     last_modified = COALESCE($4, last_modified), missing_count = 0, \
                     updated_at = NOW() \
                 WHERE target_ref = $1 AND url_path = $2",
            )
            .bind(self.target_id)
            .bind(&page.url_path)
            .bind(&page.etag)
            .bind(&page.last_modified)
            .execute(self.db)
            .await;
            match result {
                Ok(_) => self.recorded += 1,
                Err(e) => tracing::warn!(
                    target_id = %self.target_id, url_path = %page.url_path, error = %e,
                    "webcrawl: failed to mark an unchanged page — continuing the crawl"
                ),
            }
            return;
        }
        let previous: Option<String> = if self.watch_only && page.content.is_some() {
            sqlx::query_scalar(
                "SELECT content FROM webcrawl_page WHERE target_ref = $1 AND url_path = $2",
            )
            .bind(self.target_id)
            .bind(&page.url_path)
            .fetch_optional(self.db)
            .await
            .ok()
            .flatten()
            .flatten()
        } else {
            None
        };
        let result = sqlx::query(
            r#"INSERT INTO webcrawl_page
                   (target_ref, url_path, parent_path, depth, size_bytes, status, content,
                    etag, last_modified, content_hash)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (target_ref, url_path) DO UPDATE
               SET parent_path = EXCLUDED.parent_path,
                   depth = EXCLUDED.depth,
                   size_bytes = EXCLUDED.size_bytes,
                   status = EXCLUDED.status,
                   content = EXCLUDED.content,
                   etag = EXCLUDED.etag,
                   last_modified = EXCLUDED.last_modified,
                   content_hash = EXCLUDED.content_hash,
                   missing_count = 0,
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
        .bind(&page.etag)
        .bind(&page.last_modified)
        .bind(&page.content_hash)
        .execute(self.db)
        .await;
        if result.is_ok()
            && let (Some(old), Some(new)) = (previous.as_deref(), page.content.as_deref())
        {
            self.report_change(&page.url_path, old, new).await;
        }
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

type TargetRow = (String, i16, String, String, Option<String>, bool);

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

    let row: Option<TargetRow> = sqlx::query_as(
        "SELECT url, max_depth, include_patterns, exclude_patterns, sitemap_url, watch_only \
         FROM webcrawl_target WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(target_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((url_str, max_depth, include, exclude, sitemap_url, watch_only)) = row else {
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

    let agent = user_agent();
    let robots = safety::fetch_robots_rules(&client, &root, &agent).await;
    let fetcher = RealFetcher {
        client,
        max_bytes: cfg.max_page_bytes,
        user_agent: agent,
    };
    let known: HashMap<String, KnownPage> =
        sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>)>(
            "SELECT url_path, etag, last_modified, content_hash FROM webcrawl_page \
             WHERE target_ref = $1",
        )
        .bind(target_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(path, etag, last_modified, content_hash)| {
            (
                path,
                KnownPage {
                    etag,
                    last_modified,
                    content_hash,
                },
            )
        })
        .collect();
    let include = parse_patterns(&include);
    let exclude = parse_patterns(&exclude);
    let mut seeds = Vec::new();
    if let Some(sitemap) = sitemap_url.as_deref().and_then(|s| Url::parse(s).ok())
        && same_origin(&sitemap, &root)
    {
        match fetcher.fetch(&sitemap).await {
            Ok(page) => {
                seeds = sitemap_seeds(
                    &parse_sitemap(&page.body),
                    &root,
                    &include,
                    &exclude,
                    &known,
                );
            }
            Err(e) => tracing::info!(%target_id, error = %e, "webcrawl: sitemap not read"),
        }
    }
    let scope = CrawlScope {
        include,
        exclude,
        seeds,
        known,
        min_interval: DEFAULT_HOST_INTERVAL,
    };
    let limits = CrawlLimits {
        max_pages: cfg.max_pages as usize,
        max_depth: max_depth as i32,
    };

    let mut sink = DbPageSink {
        db,
        target_id,
        recorded: 0,
        watch_only,
    };
    let outcome = walk_with(&fetcher, &root, &limits, &robots, &scope, &mut sink).await;

    let (status, last_error) = if sink.recorded == 0 {
        (
            "failed",
            Some("no pages could be crawled — see the root page's own error".to_string()),
        )
    } else {
        ("completed", outcome.stopped)
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
                    ..FetchedPage::default()
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
    fn text_diff_lists_added_and_removed_lines() {
        let (added, removed) = text_diff(
            "Price: 10\nHours: 9-5\n",
            "Price: 12\nHours: 9-5\nNew branch\n",
        );
        assert_eq!(added, vec!["Price: 12", "New branch"]);
        assert_eq!(removed, vec!["Price: 10"]);
        let (a, r) = text_diff("same\n", "  same  \n\n");
        assert!(a.is_empty() && r.is_empty(), "spacing alone is no change");
    }

    #[test]
    fn exclude_beats_include() {
        let include = parse_patterns("/docs/*, /help/*");
        let exclude = parse_patterns("/docs/drafts/*");
        assert!(in_scope("/docs/start", &include, &exclude));
        assert!(!in_scope("/docs/drafts/x", &include, &exclude));
        assert!(!in_scope("/blog/post", &include, &exclude));
        assert!(
            in_scope("/anything", &[], &[]),
            "no include pattern: everything"
        );
    }

    #[test]
    fn sitemap_lastmod_filters_urls() {
        let xml = "<urlset><url><loc>https://example.com/docs/a</loc><lastmod>2026-10-01</lastmod></url>\
                   <url><loc>https://example.com/docs/b</loc><lastmod>2026-09-01</lastmod></url>\
                   <url><loc>https://example.com/docs/new</loc></url>\
                   <url><loc>https://other.example/docs/x</loc></url>\
                   <url><loc>https://example.com/blog/c</loc></url></urlset>";
        let entries = parse_sitemap(xml);
        assert_eq!(entries.len(), 5);
        let stored = KnownPage {
            last_modified: Some("Tue, 15 Sep 2026 00:00:00 GMT".into()),
            ..KnownPage::default()
        };
        let known = HashMap::from([
            ("/docs/a".to_string(), stored.clone()),
            ("/docs/b".to_string(), stored),
        ]);
        let root = Url::parse("https://example.com/").unwrap();
        let seeds = sitemap_seeds(&entries, &root, &parse_patterns("/docs/*"), &[], &known);
        let paths: Vec<_> = seeds.iter().map(|u| u.path().to_string()).collect();
        assert_eq!(paths, vec!["/docs/a", "/docs/new"]);
    }

    struct NotModified;

    impl Fetcher for NotModified {
        async fn fetch(&self, _url: &Url) -> Result<FetchedPage, String> {
            Err("unconditional fetch not expected".into())
        }

        async fn fetch_conditional(
            &self,
            _url: &Url,
            etag: Option<&str>,
            _last_modified: Option<&str>,
        ) -> Result<FetchedPage, String> {
            Ok(FetchedPage {
                not_modified: etag == Some("\"v1\""),
                content_type: "text/html".into(),
                body: html(&[], "fresh"),
                ..FetchedPage::default()
            })
        }
    }

    #[tokio::test]
    async fn not_modified_skips_extraction() {
        let root = Url::parse("https://example.com/").unwrap();
        let limits = CrawlLimits {
            max_pages: 5,
            max_depth: 3,
        };
        let scope = CrawlScope {
            known: HashMap::from([(
                "/".to_string(),
                KnownPage {
                    etag: Some("\"v1\"".into()),
                    content_hash: Some("abc".into()),
                    ..KnownPage::default()
                },
            )]),
            ..CrawlScope::default()
        };
        let mut sink = VecSink::default();
        walk_with(
            &NotModified,
            &root,
            &limits,
            &RobotsRules::default(),
            &scope,
            &mut sink,
        )
        .await;
        assert_eq!(sink.0.len(), 1);
        assert!(sink.0[0].unchanged);
        assert_eq!(sink.0[0].content, None);
        assert_eq!(sink.0[0].content_hash.as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn stops_after_20_errors() {
        let links: Vec<String> = (0..40).map(|i| format!("/missing/{i}")).collect();
        let link_refs: Vec<&str> = links.iter().map(String::as_str).collect();
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            ("text/html", html(&link_refs, "home")),
        );
        let fetcher = FakeFetcher(pages);
        let root = Url::parse("https://example.com/").unwrap();
        let limits = CrawlLimits {
            max_pages: 100,
            max_depth: 3,
        };
        let mut sink = VecSink::default();
        let outcome = walk_with(
            &fetcher,
            &root,
            &limits,
            &RobotsRules::default(),
            &CrawlScope::default(),
            &mut sink,
        )
        .await;
        assert_eq!(sink.0.len(), 1 + MAX_CONSECUTIVE_ERRORS);
        assert!(outcome.stopped.is_some());
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
