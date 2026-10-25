//! E13-T10: search-engine webmaster APIs, as pure request and answer codecs;
//! the seam in [`crate::search_console`] does the HTTP.
//!
//! - **Google Search Console**: `POST {base}/webmasters/v3/sites/{site}/
//!   searchAnalytics/query` with a read-only OAuth access token
//!   (`webmasters.readonly`), one day, dimensions `page` and `query`. Each
//!   answer row is one page and query with its clicks, impressions and
//!   position; [`parse_google`] folds them per page.
//! - **Bing Webmaster Tools**: `GET {base}/webmaster/api.svc/json/
//!   GetPageStats?siteUrl=&apikey=`, per page and day, without queries.
//! - **IndexNow**: `POST https://api.indexnow.org/indexnow` with the host,
//!   the site's key, where the site serves the key file, and the URLs.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Google's API host; a system's `base_url` config replaces it.
pub const GOOGLE_BASE: &str = "https://www.googleapis.com";
/// Bing's API host.
pub const BING_BASE: &str = "https://ssl.bing.com";
/// The IndexNow endpoint every participating engine shares.
pub const INDEXNOW_URL: &str = "https://api.indexnow.org/indexnow";
/// The most queries kept per page.
pub const TOP_QUERIES: usize = 10;
/// The most URLs one IndexNow call carries.
pub const INDEXNOW_MAX_URLS: usize = 10_000;

/// One page's statistics for one day.
#[derive(Debug, Clone, PartialEq)]
pub struct PageStat {
    pub url: String,
    pub impressions: i64,
    pub clicks: i64,
    /// Average position, weighted by impressions.
    pub position: Option<f64>,
    /// The page's leading queries: `{query, clicks, impressions}`.
    pub top_queries: Vec<Value>,
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The Search Analytics query URL for `site` (`https://example.com/` or
/// `sc-domain:example.com`). Pure.
pub fn google_url(base: &str, site: &str) -> String {
    format!(
        "{}/webmasters/v3/sites/{}/searchAnalytics/query",
        base.trim_end_matches('/'),
        encode(site)
    )
}

/// The query for one day (`YYYY-MM-DD`). Pure.
pub fn google_body(day: &str) -> Value {
    json!({
        "startDate": day,
        "endDate": day,
        "dimensions": ["page", "query"],
        "rowLimit": 25000,
        "dataState": "final",
    })
}

/// Folds a Search Analytics answer into one row per page: clicks and
/// impressions summed, position weighted by impressions, the queries with
/// the most clicks (then impressions) kept. Pure.
pub fn parse_google(body: &Value) -> Vec<PageStat> {
    #[derive(Default)]
    struct Acc {
        impressions: i64,
        clicks: i64,
        weighted: f64,
        queries: Vec<(String, i64, i64)>,
    }
    let mut pages: BTreeMap<String, Acc> = BTreeMap::new();
    for row in body["rows"].as_array().into_iter().flatten() {
        let keys = row["keys"].as_array();
        let Some(page) = keys.and_then(|k| k.first()).and_then(Value::as_str) else {
            continue;
        };
        let query = keys
            .and_then(|k| k.get(1))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let clicks = row["clicks"].as_f64().unwrap_or(0.0).round() as i64;
        let impressions = row["impressions"].as_f64().unwrap_or(0.0).round() as i64;
        let position = row["position"].as_f64().unwrap_or(0.0);
        let acc = pages.entry(page.to_owned()).or_default();
        acc.clicks += clicks;
        acc.impressions += impressions;
        acc.weighted += position * impressions as f64;
        if !query.is_empty() {
            acc.queries.push((query.to_owned(), clicks, impressions));
        }
    }
    pages
        .into_iter()
        .map(|(url, mut acc)| {
            acc.queries
                .sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
            acc.queries.truncate(TOP_QUERIES);
            PageStat {
                url,
                impressions: acc.impressions,
                clicks: acc.clicks,
                position: (acc.impressions > 0).then(|| acc.weighted / acc.impressions as f64),
                top_queries: acc
                    .queries
                    .into_iter()
                    .map(|(q, c, i)| json!({ "query": q, "clicks": c, "impressions": i }))
                    .collect(),
            }
        })
        .collect()
}

/// The page statistics URL for `site` with `key`. Pure.
pub fn bing_url(base: &str, site: &str, key: &str) -> String {
    format!(
        "{}/webmaster/api.svc/json/GetPageStats?siteUrl={}&apikey={}",
        base.trim_end_matches('/'),
        encode(site),
        encode(key)
    )
}

fn bing_day_ms(value: &str) -> Option<i64> {
    let inner = value.strip_prefix("/Date(")?.strip_suffix(")/")?;
    let digits: String = inner
        .chars()
        .enumerate()
        .take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && *c == '-'))
        .map(|(_, c)| c)
        .collect();
    digits.parse().ok()
}

/// The pages of a Bing answer whose date falls on the UTC day starting at
/// `day_start_ms`. Pure.
pub fn parse_bing(body: &Value, day_start_ms: i64) -> Vec<PageStat> {
    const DAY_MS: i64 = 86_400_000;
    body["d"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| {
            row["Date"]
                .as_str()
                .and_then(bing_day_ms)
                .is_some_and(|ms| (day_start_ms..day_start_ms + DAY_MS).contains(&ms))
        })
        .filter_map(|row| {
            Some(PageStat {
                url: row["Query"].as_str()?.to_owned(),
                impressions: row["Impressions"].as_i64().unwrap_or(0),
                clicks: row["Clicks"].as_i64().unwrap_or(0),
                position: row["AvgImpressionPosition"].as_f64().filter(|p| *p > 0.0),
                top_queries: Vec::new(),
            })
        })
        .collect()
}

/// The IndexNow submission. Pure.
pub fn indexnow_body(host: &str, key: &str, key_location: &str, urls: &[String]) -> Value {
    json!({
        "host": host,
        "key": key,
        "keyLocation": key_location,
        "urlList": urls.iter().take(INDEXNOW_MAX_URLS).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_google_rows_to_stats() {
        let body = json!({ "rows": [
            { "keys": ["https://example.com/pricing", "crm pricing"], "clicks": 4, "impressions": 100, "position": 3.0 },
            { "keys": ["https://example.com/pricing", "سعر نظام crm"], "clicks": 6, "impressions": 50, "position": 6.0 },
            { "keys": ["https://example.com/about", "attome"], "clicks": 1, "impressions": 10, "position": 1.0 }
        ]});
        let stats = parse_google(&body);
        assert_eq!(stats.len(), 2);
        let pricing = stats.iter().find(|s| s.url.ends_with("/pricing")).unwrap();
        assert_eq!(pricing.clicks, 10);
        assert_eq!(pricing.impressions, 150);
        assert_eq!(pricing.position, Some(4.0));
        assert_eq!(pricing.top_queries[0]["query"], "سعر نظام crm");
        assert_eq!(pricing.top_queries.len(), 2);
        assert!(parse_google(&json!({})).is_empty());
        assert_eq!(
            google_url("https://www.googleapis.com/", "sc-domain:example.com"),
            "https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.com/searchAnalytics/query"
        );
    }

    #[test]
    fn bing_rows_are_kept_for_the_day_only() {
        let day = 1_792_800_000_000; // 2026-10-24T00:00Z
        let body = json!({ "d": [
            { "Query": "https://example.com/a", "Clicks": 2, "Impressions": 30, "AvgImpressionPosition": 5.5, "Date": "/Date(1792800000000)/" },
            { "Query": "https://example.com/b", "Clicks": 1, "Impressions": 9, "AvgImpressionPosition": 0, "Date": "/Date(1792713600000)/" }
        ]});
        let stats = parse_bing(&body, day);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].url, "https://example.com/a");
        assert_eq!(stats[0].position, Some(5.5));
        let ping = indexnow_body(
            "example.com",
            "k1",
            "https://example.com/k1.txt",
            &["https://example.com/a".into()],
        );
        assert_eq!(ping["urlList"][0], "https://example.com/a");
        assert_eq!(ping["keyLocation"], "https://example.com/k1.txt");
    }
}
