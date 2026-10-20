//! The web event batch writer (roadmap E14-T5), run by the
//! `marketing_web_event_batch` job the collect route enqueues.
//!
//! A batch is what the tracking script posts (`assets/track.js`): the
//! site, the visitor and session ids, up to 20 events, plus what the
//! collect route knew about the request (the truncated IP, the country,
//! the user agent or its class). Before anything is written the whole
//! batch is dropped when the site is unknown or disabled, the user agent is
//! a crawler (`bots.rs`), the script flagged a signed-in staff session, or
//! the IP falls inside one of the site's office networks.
//!
//! Writing is idempotent: each event's id is derived from the event
//! itself, the insert skips ids already written, and the session only
//! counts the page views this run actually inserted, so running a batch
//! twice changes nothing the second time. A session keeps the landing page,
//! referrer, UTM values and click ids of the first page view that carried
//! them; a later batch never overwrites them.

use std::net::IpAddr;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::bots;

/// The registered job's name.
pub const JOB: &str = "marketing_web_event_batch";
/// The most events one batch may carry; the script sends at most 20.
pub const MAX_EVENTS: usize = 100;
/// The largest custom event payload kept, serialised.
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// How old an event may be when its batch is written.
const MAX_AGE: Duration = Duration::days(2);
/// How far ahead of the server's clock an event may claim to be.
const MAX_SKEW: Duration = Duration::minutes(5);
/// The namespace event ids are derived in.
const EVENT_NAMESPACE: Uuid = Uuid::from_u128(0x7a3c_51e2_9d04_4b8f_a6e1_0c5d_2f3b_8e91);

/// One queued collection batch: the job's payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebEventBatch {
    pub site_key: String,
    /// The visitor's IP with its host part removed (`203.0.113.0`).
    pub ip_prefix: String,
    /// ISO 3166-1 alpha-2, when the collect route knew it.
    pub country: Option<String>,
    /// The user agent, or its class (`desktop`, `mobile`, `tablet`, `bot`).
    pub user_agent_class: String,
    /// The script's body: `{site, visitor, session, staff?, events: [...]}`.
    pub batch: Value,
}

/// What one run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WriteCounts {
    pub written: u64,
    /// Events already written by an earlier run of the same batch.
    pub duplicates: u64,
    pub dropped_bot: u64,
    pub dropped_staff: u64,
    pub dropped_office: u64,
    /// Unknown or disabled site, malformed ids, or a malformed, too old or
    /// oversized event.
    pub dropped_invalid: u64,
}

/// Why a whole batch is not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Bot,
    Staff,
    Office,
}

/// The batch-wide filter, in the order the task names. Pure.
pub fn drop_reason(
    user_agent_class: &str,
    ip_prefix: &str,
    staff: bool,
    office_networks: &str,
) -> Option<DropReason> {
    if bots::is_bot(user_agent_class) {
        Some(DropReason::Bot)
    } else if staff {
        Some(DropReason::Staff)
    } else if in_office_network(ip_prefix, office_networks) {
        Some(DropReason::Office)
    } else {
        None
    }
}

/// True when `ip_prefix` falls inside one of `office_networks`: entries
/// separated by commas, semicolons or white space, each a CIDR block
/// (`203.0.113.0/24`, `2001:db8::/32`) or a literal prefix (`203.0.113.`).
/// Pure.
pub fn in_office_network(ip_prefix: &str, office_networks: &str) -> bool {
    let ip_text = ip_prefix.split('/').next().unwrap_or("").trim();
    if ip_text.is_empty() {
        return false;
    }
    let addr = ip_text.parse::<IpAddr>().ok();
    office_networks
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| match entry.split_once('/') {
            Some((net, bits)) => match (addr, net.parse::<IpAddr>(), bits.parse::<u8>()) {
                (Some(addr), Ok(net), Ok(bits)) => cidr_contains(net, bits, addr),
                _ => false,
            },
            None => ip_text.starts_with(entry),
        })
}

fn cidr_contains(net: IpAddr, bits: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(net), IpAddr::V4(addr)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            u32::from(net) & mask == u32::from(addr) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            u128::from(net) & mask == u128::from(addr) & mask
        }
        _ => false,
    }
}

/// One event ready to insert.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    /// `page_view` or `custom` (a page leave is a custom `$page_leave`).
    pub kind: &'static str,
    pub event_type: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
    pub referrer: Option<String>,
    pub time_on_page_ms: Option<i32>,
    pub payload: Value,
    /// A page view's UTM values and click ids.
    pub landing: Map<String, Value>,
}

/// A batch's ids and its valid events.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub visitor: Uuid,
    pub session: Uuid,
    pub staff: bool,
    pub events: Vec<Event>,
    /// Events left out as malformed, too old or oversized.
    pub invalid: u64,
}

fn text(v: Option<&Value>, max: usize) -> Option<String> {
    let s = v?.as_str()?.trim();
    (!s.is_empty()).then(|| s.chars().take(max).collect())
}

fn parse_id(v: Option<&Value>) -> Option<Uuid> {
    v?.as_str().and_then(|s| Uuid::parse_str(s.trim()).ok())
}

/// Reads the script's body. `None` when the session id is missing or not a
/// UUID; an anonymous visitor (Global Privacy Control) is its session.
/// Pure.
pub fn parse(site_key: &str, body: &Value, now: DateTime<Utc>) -> Option<Parsed> {
    let session = parse_id(body.get("session"))?;
    let visitor = parse_id(body.get("visitor")).unwrap_or(session);
    let staff = body.get("staff").and_then(Value::as_bool) == Some(true);
    let raw = body.get("events").and_then(Value::as_array)?;
    let mut events = Vec::new();
    let mut invalid = 0u64;
    for (index, e) in raw.iter().enumerate() {
        if index >= MAX_EVENTS {
            invalid += 1;
            continue;
        }
        match parse_event(site_key, session, e, now) {
            Some(event) => events.push(event),
            None => invalid += 1,
        }
    }
    Some(Parsed {
        visitor,
        session,
        staff,
        events,
        invalid,
    })
}

fn parse_event(site_key: &str, session: Uuid, e: &Value, now: DateTime<Utc>) -> Option<Event> {
    let at = e
        .get("at")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())?
        .with_timezone(&Utc);
    if at < now - MAX_AGE || at > now + MAX_SKEW {
        return None;
    }
    let url = text(e.get("url"), 2000);
    let (kind, event_type) = match e.get("kind").and_then(Value::as_str)? {
        "page_view" => ("page_view", None),
        "page_leave" => ("custom", Some("$page_leave".to_string())),
        "custom" => ("custom", Some(text(e.get("event_type"), 100)?)),
        _ => return None,
    };
    let payload = match e.get("payload") {
        Some(p @ Value::Object(_)) => p.clone(),
        _ => Value::Object(Map::new()),
    };
    if payload.to_string().len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    let landing = e
        .get("landing")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    let v = v.as_str()?.trim();
                    (!v.is_empty() && k.len() <= 20)
                        .then(|| (k.clone(), Value::String(v.chars().take(200).collect())))
                })
                .collect()
        })
        .unwrap_or_default();
    let time_on_page_ms = e
        .get("time_on_page_ms")
        .and_then(Value::as_i64)
        .map(|ms| ms.clamp(0, i64::from(i32::MAX)) as i32);
    let id = Uuid::new_v5(
        &EVENT_NAMESPACE,
        format!(
            "{site_key}|{session}|{}|{kind}|{}|{}",
            at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type.as_deref().unwrap_or(""),
            url.as_deref().unwrap_or("")
        )
        .as_bytes(),
    );
    Some(Event {
        id,
        at,
        kind,
        event_type,
        url,
        title: text(e.get("title"), 300),
        referrer: text(e.get("referrer"), 2000),
        time_on_page_ms,
        payload,
        landing,
    })
}

/// A two-letter country code, upper-cased, or nothing.
fn country(code: Option<&str>) -> Option<String> {
    let c = code?.trim();
    (c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic())).then(|| c.to_ascii_uppercase())
}

/// The device column: the user agent's class when the collect route sent
/// one, otherwise nothing.
fn device(user_agent_class: &str) -> Option<String> {
    let c = user_agent_class.trim().to_ascii_lowercase();
    matches!(c.as_str(), "desktop" | "mobile" | "tablet").then_some(c)
}

const UTM: [&str; 5] = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
];

/// Writes one batch. Idempotent; see the module doc.
pub async fn write_batch(db: &DbPool, job: &WebEventBatch) -> Result<WriteCounts, AppError> {
    let mut counts = WriteCounts::default();
    let raw_count = job
        .batch
        .get("events")
        .and_then(Value::as_array)
        .map_or(0, |a| a.len() as u64);

    let site: Option<(Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT office_networks, enabled FROM marketing_tracked_site \
         WHERE site_key = $1 AND is_active IS NOT FALSE",
    )
    .bind(job.site_key.trim())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((office_networks, Some(true))) = site else {
        counts.dropped_invalid = raw_count;
        return Ok(counts);
    };
    let Some(parsed) = parse(job.site_key.trim(), &job.batch, Utc::now()) else {
        counts.dropped_invalid = raw_count;
        return Ok(counts);
    };
    counts.dropped_invalid = parsed.invalid;
    let kept = parsed.events.len() as u64;
    match drop_reason(
        &job.user_agent_class,
        &job.ip_prefix,
        parsed.staff,
        office_networks.as_deref().unwrap_or(""),
    ) {
        Some(DropReason::Bot) => counts.dropped_bot = kept,
        Some(DropReason::Staff) => counts.dropped_staff = kept,
        Some(DropReason::Office) => counts.dropped_office = kept,
        None => {
            if !parsed.events.is_empty() {
                write_parsed(db, job, &parsed, &mut counts).await?;
            }
        }
    }
    Ok(counts)
}

async fn write_parsed(
    db: &DbPool,
    job: &WebEventBatch,
    parsed: &Parsed,
    counts: &mut WriteCounts,
) -> Result<(), AppError> {
    let events = &parsed.events;
    let ids: Vec<Uuid> = events.iter().map(|e| e.id).collect();
    let ats: Vec<DateTime<Utc>> = events.iter().map(|e| e.at).collect();
    let kinds: Vec<&str> = events.iter().map(|e| e.kind).collect();
    let types: Vec<Option<String>> = events.iter().map(|e| e.event_type.clone()).collect();
    let urls: Vec<Option<String>> = events.iter().map(|e| e.url.clone()).collect();
    let titles: Vec<Option<String>> = events.iter().map(|e| e.title.clone()).collect();
    let referrers: Vec<Option<String>> = events.iter().map(|e| e.referrer.clone()).collect();
    let times: Vec<Option<i32>> = events.iter().map(|e| e.time_on_page_ms).collect();
    let payloads: Vec<String> = events.iter().map(|e| e.payload.to_string()).collect();
    let site_key = job.site_key.trim();

    let mut tx = attome_db::tx::begin(db).await?;
    let inserted: Vec<String> = sqlx::query_scalar(
        "INSERT INTO marketing_web_event \
            (id, site_key, visitor_id, session_id, occurred_at, kind, event_type, url, title, \
             referrer, time_on_page_ms, device, country, ip_prefix, payload) \
         SELECT e.id, $1, $2, $3, e.at, e.kind, e.event_type, e.url, e.title, \
                e.referrer, e.top, $4, $5, $6, e.payload::jsonb \
           FROM UNNEST($7::uuid[], $8::timestamptz[], $9::text[], $10::text[], $11::text[], \
                       $12::text[], $13::text[], $14::int4[], $15::text[]) \
                AS e(id, at, kind, event_type, url, title, referrer, top, payload) \
         ON CONFLICT (id, occurred_at) DO NOTHING \
         RETURNING kind",
    )
    .bind(site_key)
    .bind(parsed.visitor)
    .bind(parsed.session)
    .bind(device(&job.user_agent_class))
    .bind(country(job.country.as_deref()))
    .bind(job.ip_prefix.chars().take(64).collect::<String>())
    .bind(&ids)
    .bind(&ats)
    .bind(&kinds)
    .bind(&types)
    .bind(&urls)
    .bind(&titles)
    .bind(&referrers)
    .bind(&times)
    .bind(&payloads)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    counts.written = inserted.len() as u64;
    counts.duplicates = events.len() as u64 - counts.written;

    if counts.written > 0 {
        let page_views = inserted.iter().filter(|k| *k == "page_view").count() as i32;
        let started = ats.iter().min().copied().unwrap_or_else(Utc::now);
        let last_seen = ats.iter().max().copied().unwrap_or(started);
        // The first page view in the batch is the session's landing page.
        let first_view = events
            .iter()
            .filter(|e| e.kind == "page_view")
            .min_by_key(|e| e.at);
        let landing = first_view.map(|e| &e.landing);
        let utm = |key: &str| {
            landing
                .and_then(|l| l.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let click_ids: Map<String, Value> = landing
            .map(|l| {
                l.iter()
                    .filter(|(k, _)| !UTM.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        sqlx::query(
            "INSERT INTO marketing_web_session AS s \
                (id, site_key, visitor_id, started_at, last_seen_at, landing_url, referrer, \
                 utm_source, utm_medium, utm_campaign, utm_term, utm_content, click_ids, page_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (id) DO UPDATE SET \
                started_at = LEAST(s.started_at, EXCLUDED.started_at), \
                last_seen_at = GREATEST(s.last_seen_at, EXCLUDED.last_seen_at), \
                landing_url = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.landing_url ELSE s.landing_url END, \
                referrer = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.referrer ELSE s.referrer END, \
                utm_source = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.utm_source ELSE s.utm_source END, \
                utm_medium = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.utm_medium ELSE s.utm_medium END, \
                utm_campaign = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.utm_campaign ELSE s.utm_campaign END, \
                utm_term = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.utm_term ELSE s.utm_term END, \
                utm_content = CASE WHEN s.landing_url IS NULL THEN EXCLUDED.utm_content ELSE s.utm_content END, \
                click_ids = EXCLUDED.click_ids || s.click_ids, \
                page_count = s.page_count + EXCLUDED.page_count \
             WHERE s.site_key = EXCLUDED.site_key",
        )
        .bind(parsed.session)
        .bind(site_key)
        .bind(parsed.visitor)
        .bind(started)
        .bind(last_seen)
        .bind(first_view.and_then(|e| e.url.clone()))
        .bind(first_view.and_then(|e| e.referrer.clone()))
        .bind(utm("utm_source"))
        .bind(utm("utm_medium"))
        .bind(utm("utm_campaign"))
        .bind(utm("utm_term"))
        .bind(utm("utm_content"))
        .bind(Value::Object(click_ids))
        .bind(page_views)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        "2026-10-20T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn bot_user_agents_are_dropped() {
        for ua in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0)",
            "Mozilla/5.0 HeadlessChrome/120.0",
            "curl/8.4.0",
            "python-requests/2.31",
            "bot",
            "",
        ] {
            assert_eq!(
                drop_reason(ua, "203.0.113.0", false, ""),
                Some(DropReason::Bot),
                "{ua}"
            );
        }
        let person = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36";
        assert_eq!(drop_reason(person, "203.0.113.0", false, ""), None);
        assert_eq!(drop_reason("desktop", "203.0.113.0", false, ""), None);
        assert_eq!(
            drop_reason("desktop", "203.0.113.0", true, ""),
            Some(DropReason::Staff)
        );
    }

    #[test]
    fn office_network_prefix_is_dropped() {
        let offices = "198.51.100.0/24, 10.20.\n2001:db8::/32";
        assert!(in_office_network("198.51.100.0", offices));
        assert!(in_office_network("198.51.100.0/24", offices));
        assert!(in_office_network("10.20.30.0", offices));
        assert!(in_office_network("2001:db8:1::", offices));
        assert!(!in_office_network("198.51.101.0", offices));
        assert!(!in_office_network("2001:db9::", offices));
        assert!(!in_office_network("", offices));
        assert!(!in_office_network("198.51.100.0", ""));
        assert_eq!(
            drop_reason("desktop", "198.51.100.0", false, offices),
            Some(DropReason::Office)
        );
    }

    fn body() -> Value {
        json!({
            "site": "main",
            "visitor": "0190f5a4-0000-7000-8000-000000000001",
            "session": "0190f5a4-0000-7000-8000-000000000002",
            "events": [
                {"kind": "page_view", "at": "2026-10-20T11:59:00Z", "url": "https://x.test/a",
                 "title": "A", "referrer": "", "landing": {"utm_source": "news", "gclid": "abc"}},
                {"kind": "page_leave", "at": "2026-10-20T11:59:30Z", "url": "https://x.test/a",
                 "time_on_page_ms": 30000},
                {"kind": "custom", "at": "2026-10-20T11:59:40Z", "event_type": "signup",
                 "payload": {"plan": "pro"}},
                {"kind": "page_view", "at": "2026-10-01T00:00:00Z", "url": "https://x.test/old"},
                {"kind": "teleport", "at": "2026-10-20T11:59:40Z"}
            ]
        })
    }

    #[test]
    fn parse_keeps_valid_events_with_stable_ids() {
        let parsed = parse("main", &body(), now()).expect("parses");
        assert_eq!(parsed.events.len(), 3);
        assert_eq!(parsed.invalid, 2, "too old and unknown kind");
        assert_eq!(parsed.events[1].kind, "custom");
        assert_eq!(parsed.events[1].event_type.as_deref(), Some("$page_leave"));
        assert_eq!(parsed.events[1].time_on_page_ms, Some(30_000));
        assert_eq!(parsed.events[0].landing.get("gclid"), Some(&json!("abc")));
        let again = parse("main", &body(), now()).expect("parses");
        assert_eq!(
            parsed.events.iter().map(|e| e.id).collect::<Vec<_>>(),
            again.events.iter().map(|e| e.id).collect::<Vec<_>>(),
            "the same batch derives the same ids"
        );
    }

    #[test]
    fn anonymous_visitor_is_its_session_and_bad_session_is_refused() {
        let mut b = body();
        b["visitor"] = Value::Null;
        let parsed = parse("main", &b, now()).expect("parses");
        assert_eq!(parsed.visitor, parsed.session);
        b["session"] = json!("not-a-uuid");
        assert!(parse("main", &b, now()).is_none());
    }

    #[test]
    fn country_and_device_are_normalised() {
        assert_eq!(country(Some("sa")), Some("SA".into()));
        assert_eq!(country(Some("SAU")), None);
        assert_eq!(country(None), None);
        assert_eq!(device("Mobile"), Some("mobile".into()));
        assert_eq!(device("Mozilla/5.0"), None);
    }
}
