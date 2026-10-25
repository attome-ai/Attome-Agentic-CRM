//! E13-T10: search statistics from the engines, and IndexNow on publish.
//!
//! [`pull_daily`] runs from the daily `content_search_console` job when
//! `content.search_console` is on. For each site a customer connected
//! (`attome_integration::search_console`: an integration system naming the
//! engine and the site's domain), it reads yesterday's per-page
//! impressions, clicks, average position and leading queries from Google
//! and Bing, matches each URL to the site's published page, and, after
//! every HTTP call has finished, upserts `content_search_stat` in one short
//! transaction. A site with no connected engine is never called.
//!
//! [`ping_after_publish`] queues an `content_indexnow` job after a page's
//! publish commits, when `content.instant_indexing` is on and the page's
//! site has a domain; the job tells the engines through IndexNow, with the
//! job's backoff on failure.

use std::collections::{BTreeMap, BTreeSet};

use attome_core::EngineState;
use attome_integration::connector::adapters::search_console::PageStat;
use attome_integration::search_console as seam;
use attome_types::AppError;
use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::sitemap::page_url;

/// The daily statistics job.
pub const PULL_JOB: &str = "content_search_console";
/// The IndexNow job.
pub const PING_JOB: &str = "content_indexnow";

/// One IndexNow submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingJob {
    pub domain: String,
    pub urls: Vec<String>,
}

/// What a pull did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullStats {
    /// Site and engine pairs read.
    pub sites: usize,
    /// Statistics rows written.
    pub rows: usize,
}

/// The site and engine pairs to read: each site whose domain an engine's
/// system connects. A site without one is left out. Pure.
pub fn pull_plan<'a>(
    spaces: &'a [(Uuid, String)],
    connected: &[(String, String)],
) -> Vec<(Uuid, &'a str, String)> {
    let mut out = Vec::new();
    for (engine, domain) in connected {
        for (space, space_domain) in spaces {
            if space_domain.eq_ignore_ascii_case(domain) {
                out.push((*space, space_domain.as_str(), engine.clone()));
            }
        }
    }
    out
}

fn normalized(url: &str) -> String {
    let lower = url.trim().to_ascii_lowercase();
    let no_query = lower.split(['?', '#']).next().unwrap_or_default();
    no_query.trim_end_matches('/').to_owned()
}

/// Each statistic paired with its page, by URL (case, a trailing slash, a
/// query string and a fragment ignored). A URL no published page has is
/// left out. Pure.
pub fn match_pages<'s>(
    domain: &str,
    pages: &[(Uuid, String)],
    stats: &'s [PageStat],
) -> Vec<(Uuid, &'s PageStat)> {
    let by_url: BTreeMap<String, Uuid> = pages
        .iter()
        .map(|(id, path)| (normalized(&page_url(domain, path)), *id))
        .collect();
    let mut seen = BTreeSet::new();
    stats
        .iter()
        .filter_map(|stat| {
            let id = *by_url.get(&normalized(&stat.url))?;
            seen.insert(id).then_some((id, stat))
        })
        .collect()
}

/// Reads yesterday's statistics for every connected site and stores them.
pub async fn pull_daily(state: &EngineState) -> Result<PullStats, AppError> {
    if !state
        .feature_flags()
        .is_on_for_deployment("content.search_console")
    {
        return Ok(PullStats::default());
    }
    let db = &state.base.db;
    let day: NaiveDate = (Utc::now() - Duration::days(1)).date_naive();
    let mut systems = Vec::new();
    for engine in seam::ENGINES {
        systems.extend(seam::systems(state, engine).await?);
    }
    if systems.is_empty() {
        return Ok(PullStats::default());
    }
    let spaces: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, lower(domain) FROM content_space \
          WHERE domain IS NOT NULL AND domain <> '' AND is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let connected: Vec<(String, String)> = systems
        .iter()
        .map(|s| (s.engine.clone(), s.domain.clone()))
        .collect();
    let plan = pull_plan(&spaces, &connected);

    // Every HTTP call first; the writes after, in one short transaction.
    let mut rows: Vec<(Uuid, String, PageStat)> = Vec::new();
    let mut stats = PullStats::default();
    for (space, domain, engine) in plan {
        let Some(site) = systems
            .iter()
            .find(|s| s.engine == engine && s.domain == domain)
        else {
            continue;
        };
        let pulled = match seam::pull_site(state, site, day).await {
            Ok(pulled) => pulled,
            Err(error) => {
                tracing::warn!(%domain, %engine, %error, "search console: site not read");
                continue;
            }
        };
        let pages: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, url_path FROM content_page \
              WHERE content_space_id = $1 AND is_deleted = false AND status = 'published'",
        )
        .bind(space)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        stats.sites += 1;
        rows.extend(
            match_pages(domain, &pages, &pulled)
                .into_iter()
                .map(|(page, stat)| (page, engine.clone(), stat.clone())),
        );
    }
    if rows.is_empty() {
        return Ok(stats);
    }
    let pages: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let sources: Vec<String> = rows.iter().map(|r| r.1.clone()).collect();
    let impressions: Vec<i32> = rows
        .iter()
        .map(|r| i32::try_from(r.2.impressions).unwrap_or(i32::MAX))
        .collect();
    let clicks: Vec<i32> = rows
        .iter()
        .map(|r| i32::try_from(r.2.clicks).unwrap_or(i32::MAX))
        .collect();
    let positions: Vec<Option<f32>> = rows
        .iter()
        .map(|r| r.2.position.map(|p| p as f32))
        .collect();
    let queries: Vec<Value> = rows
        .iter()
        .map(|r| Value::Array(r.2.top_queries.clone()))
        .collect();
    let mut tx = attome_db::tx::begin(db).await?;
    let written = sqlx::query(
        "INSERT INTO content_search_stat \
             (page_ref, stat_date, source, impressions, clicks, avg_position, top_queries) \
         SELECT u.page, $1, u.source, u.impressions, u.clicks, u.position, u.queries \
           FROM UNNEST($2::uuid[], $3::text[], $4::int[], $5::int[], $6::real[], $7::jsonb[]) \
                AS u(page, source, impressions, clicks, position, queries) \
         ON CONFLICT (page_ref, stat_date, source) DO UPDATE \
            SET impressions = EXCLUDED.impressions, clicks = EXCLUDED.clicks, \
                avg_position = EXCLUDED.avg_position, top_queries = EXCLUDED.top_queries",
    )
    .bind(day)
    .bind(&pages)
    .bind(&sources)
    .bind(&impressions)
    .bind(&clicks)
    .bind(&positions)
    .bind(&queries)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    stats.rows = usize::try_from(written.rows_affected()).unwrap_or(usize::MAX);
    Ok(stats)
}

/// Queues an IndexNow submission for a page whose publish just committed,
/// when `content.instant_indexing` is on and the page's site has a domain.
/// A failure is logged and never undoes the publish.
pub async fn ping_after_publish(state: &EngineState, page: Uuid) {
    if !state
        .feature_flags()
        .is_on_for_deployment("content.instant_indexing")
    {
        return;
    }
    let run = async {
        let target: Option<(Option<String>, String)> = sqlx::query_as(
            "SELECT s.domain, p.url_path FROM content_page p \
               JOIN content_space s ON s.id = p.content_space_id \
              WHERE p.id = $1 AND p.is_deleted = false AND p.status = 'published'",
        )
        .bind(page)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some((Some(domain), path)) = target else {
            return Ok(());
        };
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return Ok(());
        }
        let job = PingJob {
            urls: vec![page_url(&domain, &path)],
            domain,
        };
        let registered = attome_core::jobs::JOB_TYPES
            .job(PING_JOB, &job)
            .map_err(AppError::internal)?;
        attome_jobs::enqueue_on_pool(
            &state.base.db,
            attome_core::jobs::EngineJob::Registered(registered),
        )
        .await
        .map_err(AppError::internal)
    };
    if let Err(error) = run.await {
        tracing::warn!(%page, %error, "indexnow: not queued; the publish stands");
    }
}

/// Runs one IndexNow job. A site with no IndexNow system is done.
pub async fn ping(state: &EngineState, job: &PingJob) -> Result<(), AppError> {
    if !state
        .feature_flags()
        .is_on_for_deployment("content.instant_indexing")
    {
        return Ok(());
    }
    seam::ping_indexnow(state, &job.domain, &job.urls).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(url: &str) -> PageStat {
        PageStat {
            url: url.into(),
            impressions: 10,
            clicks: 2,
            position: Some(3.5),
            top_queries: Vec::new(),
        }
    }

    #[test]
    fn skips_site_without_connector() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let spaces = vec![(a, "example.com".to_owned()), (b, "other.sa".to_owned())];
        let plan = pull_plan(&spaces, &[("google".into(), "Example.com".into())]);
        assert_eq!(plan, vec![(a, "example.com", "google".to_owned())]);
        assert!(pull_plan(&spaces, &[]).is_empty());
    }

    #[test]
    fn statistics_match_pages_by_url() {
        let pricing = Uuid::now_v7();
        let home = Uuid::now_v7();
        let pages = vec![(pricing, "/pricing".to_owned()), (home, "/".to_owned())];
        let stats = vec![
            stat("https://example.com/pricing/"),
            stat("https://EXAMPLE.com/?utm=x"),
            stat("https://example.com/missing"),
        ];
        let matched = match_pages("example.com", &pages, &stats);
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].0, pricing);
        assert_eq!(matched[1].0, home);
    }
}
