//! E18-T1: Brandwatch Consumer Research mentions for configured queries.
//!
//! The system is an `integration_system` with config `{"social":
//! "brandwatch", "project_id": "<id>", "queries": ["<query id>", ...]}` and
//! its API token as the credential (`{"token": "..."}`). Each poll reads a
//! query's mentions from the last one stored (or the past day) up to now,
//! page by page (at most [`MAX_PAGES`] pages of [`PAGE_SIZE`]); the app's
//! `social_mentions_sync` job stores them with their sentiment.

use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{config, secret, secrets};
use crate::system::IntegrationSystem;

const API: &str = "https://api.brandwatch.com";
const TIMEOUT: Duration = Duration::from_secs(20);
/// Mentions per page.
pub const PAGE_SIZE: u32 = 100;
/// Pages read per query per poll.
pub const MAX_PAGES: u32 = 10;

/// One mention.
#[derive(Debug, Clone, PartialEq)]
pub struct Mention {
    pub guid: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub snippet: Option<String>,
    pub author: Option<String>,
    pub domain: Option<String>,
    pub language: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    /// Brandwatch's own label (`positive`, `neutral`, `negative`).
    pub provider_sentiment: Option<String>,
}

/// One page: its mentions and the cursor to the next, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub mentions: Vec<Mention>,
    pub next_cursor: Option<String>,
}

/// The mentions URL for a page. Pure.
pub fn mentions_url(
    project: &str,
    query: &str,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    cursor: Option<&str>,
) -> Result<url::Url, AppError> {
    let mut params = vec![
        ("queryId", query.to_owned()),
        (
            "startDate",
            since.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        ),
        (
            "endDate",
            until.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        ),
        ("pageSize", PAGE_SIZE.to_string()),
        ("orderBy", "date".to_owned()),
        ("orderDirection", "asc".to_owned()),
    ];
    if let Some(cursor) = cursor {
        params.push(("cursor", cursor.to_owned()));
    }
    url::Url::parse_with_params(&format!("{API}/projects/{project}/data/mentions"), &params)
        .map_err(AppError::internal)
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A mentions answer. `None` for an answer that is not one. Pure.
pub fn parse_page(body: &str) -> Option<Page> {
    let v: Value = serde_json::from_str(body).ok()?;
    let mentions = v
        .get("results")?
        .as_array()?
        .iter()
        .filter_map(|m| {
            Some(Mention {
                guid: text(m, "guid")?,
                url: text(m, "url"),
                title: text(m, "title"),
                snippet: text(m, "snippet"),
                author: text(m, "author"),
                domain: text(m, "domain"),
                language: text(m, "language"),
                published_at: text(m, "date")
                    .and_then(|d| DateTime::parse_from_rfc3339(&d.replace("+0000", "+00:00")).ok())
                    .map(|d| d.with_timezone(&Utc)),
                provider_sentiment: text(m, "sentiment").map(|s| s.to_ascii_lowercase()),
            })
        })
        .collect();
    Some(Page {
        mentions,
        next_cursor: text(&v, "nextCursor"),
    })
}

/// The project and queries a system is configured with. Pure over the
/// config.
pub fn project_and_queries(system: &IntegrationSystem) -> Result<(String, Vec<String>), AppError> {
    let cfg = config(system);
    let safe = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let project = cfg
        .get("project_id")
        .map(|v| v.to_string().trim_matches('"').to_owned())
        .filter(|p| safe(p))
        .ok_or_else(|| {
            AppError::Validation(format!("{}: config has no valid project_id", system.name))
        })?;
    let queries: Vec<String> = cfg
        .get("queries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|q| q.to_string().trim_matches('"').to_owned())
        .filter(|q| safe(q))
        .collect();
    Ok((project, queries))
}

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: std::sync::OnceLock<attome_outbound::http::Outbound> =
        std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("brandwatch"), |b| {
            b.timeout(TIMEOUT)
        })
    })
}

/// A query's mentions since `since`, oldest first.
pub async fn fetch_mentions(
    state: &EngineState,
    system: &IntegrationSystem,
    project: &str,
    query: &str,
    since: DateTime<Utc>,
) -> Result<Vec<Mention>, AppError> {
    let secrets = secrets(state, system).await?;
    let token = secret(&secrets, "token")?.to_owned();
    let until = Utc::now();
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let url = mentions_url(project, query, since, until, cursor.as_deref())?;
        let res = client()
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AppError::internal)?;
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(AppError::Validation(format!(
                "Brandwatch refused the mentions request ({status})"
            )));
        }
        let page = parse_page(&body)
            .ok_or_else(|| AppError::Validation("Brandwatch answered an unreadable page".into()))?;
        out.extend(page.mentions);
        match page.next_cursor {
            Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
            _ => break,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brandwatch_reads_a_recorded_page() {
        let body = r#"{
            "resultsTotal": 2, "nextCursor": "abc",
            "results": [
                {"guid": "m-1", "url": "https://x.com/a/1", "title": "Great service", "snippet": "Loved it",
                 "author": "lina", "domain": "x.com", "language": "en", "sentiment": "Positive",
                 "date": "2026-10-19T08:30:00.000+0000"},
                {"url": "https://no-guid.example"}
            ]
        }"#;
        let page = parse_page(body).unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("abc"));
        assert_eq!(
            page.mentions.len(),
            1,
            "a mention without a guid is left out"
        );
        let m = &page.mentions[0];
        assert_eq!(m.guid, "m-1");
        assert_eq!(m.provider_sentiment.as_deref(), Some("positive"));
        assert_eq!(
            m.published_at,
            Some("2026-10-19T08:30:00Z".parse::<DateTime<Utc>>().unwrap())
        );
        assert_eq!(parse_page("{}"), None);
    }

    #[test]
    fn brandwatch_builds_the_page_url() {
        let since: DateTime<Utc> = "2026-10-19T00:00:00Z".parse().unwrap();
        let until: DateTime<Utc> = "2026-10-20T00:00:00Z".parse().unwrap();
        let url = mentions_url("1998", "2001", since, until, Some("abc")).unwrap();
        assert_eq!(url.path(), "/projects/1998/data/mentions");
        let q: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(q.contains(&("queryId".into(), "2001".into())));
        assert!(q.contains(&("startDate".into(), "2026-10-19T00:00:00.000Z".into())));
        assert!(q.contains(&("cursor".into(), "abc".into())));
    }
}
