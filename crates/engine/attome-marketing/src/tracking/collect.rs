//! The public collection endpoint (roadmap E14-T6):
//! `POST /api/v1/track/collect`, where the tracking script posts its
//! batches. It writes no event on the request path: it checks the batch
//! and queues one `marketing_web_event_batch` job, which the writer
//! (`writer.rs`) runs.
//!
//! In order: marketing licensed and `marketing.tracking` on; at most
//! [`PER_VISITOR_PER_MINUTE`] batches a minute from one visitor and
//! [`PER_ADDRESS_PER_MINUTE`] from one truncated address (the limiter
//! counts calls, so the visitor bound is on batches of at most
//! [`MAX_EVENTS`] events, not on events); the site is known and enabled;
//! the request's `Origin` is one of the site's domains. Every refusal but
//! the rate limit is the same 204, so the endpoint reveals nothing about a
//! deployment's sites. The client IP never leaves the handler whole: IPv4
//! is cut to its /24 and IPv6 to its /48 before anything else sees it, and
//! the country comes only from a trusted edge's header.
//!
//! The script posts with a `text/plain` body, which a browser sends
//! cross-site without a CORS preflight; the body is read as JSON whatever
//! its declared type.
//!
//! **Site cache.** Source of truth: `marketing_tracked_site`. Key: the site
//! key. TTL 60 s, at most 10,000 keys, an unknown key cached as absent so a
//! flood of made-up keys reads the database once per key a minute. No
//! invalidation: an edited site applies within the TTL on every node. A
//! failed read is returned and not cached. Cold start: the first batch for
//! a site reads it.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{bots, writer};

/// The most events one batch may carry.
pub const MAX_EVENTS: usize = 50;
/// The largest body the route reads.
pub const BODY_LIMIT_BYTES: usize = 32 * 1024;
/// Batches a minute from one visitor (the script sends one every 5 s).
pub const PER_VISITOR_PER_MINUTE: i32 = 30;
/// Batches a minute from one truncated address (an office or a carrier NAT
/// shares one).
pub const PER_ADDRESS_PER_MINUTE: i32 = 600;

/// One request, as the handler read it.
#[derive(Debug, Clone)]
pub struct CollectRequest {
    pub origin: Option<String>,
    pub client_ip: IpAddr,
    /// From a trusted edge's country header only.
    pub country: Option<String>,
    pub user_agent: String,
    pub body: Value,
}

/// What became of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collected {
    Queued,
    Dropped,
}

/// IPv4 to its /24, IPv6 to its /48, as an address string. Pure.
pub fn truncate_ip(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0")
        }
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 80);
            std::net::Ipv6Addr::from(masked).to_string()
        }
    }
}

/// The user agent's class: `bot`, `tablet`, `mobile` or `desktop`. Only
/// the class is queued, never the user agent. Pure.
pub fn user_agent_class(user_agent: &str) -> &'static str {
    let ua = user_agent.to_ascii_lowercase();
    if bots::is_bot(&ua) {
        "bot"
    } else if ua.contains("ipad") || ua.contains("tablet") {
        "tablet"
    } else if ua.contains("mobi") || ua.contains("iphone") || ua.contains("android") {
        "mobile"
    } else {
        "desktop"
    }
}

/// The host of an `Origin` header value, lower-cased. Pure.
fn origin_host(origin: &str) -> Option<String> {
    let rest = origin.trim().split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// True when `origin` is one of `domains` (separated by commas or white
/// space; an entry also admits its subdomains). Pure.
pub fn origin_allowed(origin: Option<&str>, domains: &str) -> bool {
    let Some(host) = origin.and_then(origin_host) else {
        return false;
    };
    domains
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(|d| {
            let d = d.trim().to_ascii_lowercase();
            let d = d
                .split_once("://")
                .map_or(d.as_str(), |(_, r)| r)
                .to_owned();
            d.trim_end_matches('/').to_owned()
        })
        .filter(|d| !d.is_empty())
        .any(|d| host == d || host.ends_with(&format!(".{d}")))
}

#[derive(Debug)]
struct Site {
    domains: String,
}

fn site_cache() -> &'static moka::future::Cache<String, Option<Arc<Site>>> {
    static CACHE: OnceLock<moka::future::Cache<String, Option<Arc<Site>>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(60))
            .build()
    })
}

async fn site(state: &EngineState, key: &str) -> Result<Option<Arc<Site>>, AppError> {
    if let Some(hit) = site_cache().get(key).await {
        return Ok(hit);
    }
    let row: Option<(Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT domains, enabled FROM marketing_tracked_site \
         WHERE site_key = $1 AND is_active IS NOT FALSE",
    )
    .bind(key)
    .fetch_optional(&state.base.db_readonly)
    .await
    .map_err(AppError::internal)?;
    let site = match row {
        Some((domains, Some(true))) => Some(Arc::new(Site {
            domains: domains.unwrap_or_default(),
        })),
        _ => None,
    };
    site_cache().insert(key.to_owned(), site.clone()).await;
    Ok(site)
}

/// The batch's visitor (or, anonymous, its session) for the rate limit.
fn visitor_key(body: &Value) -> Option<Uuid> {
    ["visitor", "session"].iter().find_map(|k| {
        body.get(*k)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
    })
}

/// The route's work: gates, then [`queue`].
pub async fn collect(state: &EngineState, req: CollectRequest) -> Result<Collected, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_MARKETING)
        || !state
            .feature_flags()
            .is_on_for_deployment("marketing.tracking")
    {
        return Ok(Collected::Dropped);
    }
    queue(state, req).await
}

/// Rate limit, site, origin, then one queued job. The gate-free half of
/// [`collect`], for tests.
pub async fn queue(state: &EngineState, req: CollectRequest) -> Result<Collected, AppError> {
    let ip_prefix = truncate_ip(req.client_ip);
    let Some(visitor) = visitor_key(&req.body) else {
        return Ok(Collected::Dropped);
    };
    for (key, limit) in [
        (
            format!("marketing:rl:track:visitor:{visitor}"),
            PER_VISITOR_PER_MINUTE,
        ),
        (
            format!("marketing:rl:track:address:{ip_prefix}"),
            PER_ADDRESS_PER_MINUTE,
        ),
    ] {
        let outcome =
            attome_cache::rate_limit::check(&state.base.redis_coordination, &key, limit).await?;
        if !outcome.allowed {
            return Err(AppError::TooManyRequests {
                retry_after_secs: None,
            });
        }
    }

    let site_key = req
        .body
        .get("site")
        .or_else(|| req.body.get("site_key"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if site_key.is_empty() || site_key.len() > 64 {
        return Ok(Collected::Dropped);
    }
    let Some(site) = site(state, site_key).await? else {
        return Ok(Collected::Dropped);
    };
    if !origin_allowed(req.origin.as_deref(), &site.domains) {
        return Ok(Collected::Dropped);
    }
    let events = req.body.get("events").and_then(Value::as_array);
    if events.is_none_or(|e| e.is_empty() || e.len() > MAX_EVENTS) {
        return Ok(Collected::Dropped);
    }

    let batch = writer::WebEventBatch {
        site_key: site_key.to_owned(),
        ip_prefix,
        country: req.country,
        user_agent_class: user_agent_class(&req.user_agent).to_owned(),
        batch: req.body,
    };
    let job = attome_core::jobs::JOB_TYPES
        .job(writer::JOB, &batch)
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Collected::Queued)
}

#[utoipa::path(
    post,
    path = "/api/v1/track/collect",
    operation_id = "collect_tracking_events",
    tag = "marketing",
    request_body(content = String, content_type = "text/plain", description = "The script's batch, as JSON: {site, visitor, session, events}"),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "public visitor telemetry",
    )))),
    responses(
        (status = 202, description = "Queued"),
        (status = 204, description = "Not taken (the same answer for every reason)"),
        (status = 429, description = "Too many batches from this visitor or address", body = attome_types::ErrorResponse),
    ),
)]
/// Collect tracking events.
///
/// Public: the tracking script's batches. Queues them and writes nothing
/// else; a batch for an unknown or disabled site, from another origin, or
/// malformed is dropped with the same 204.
async fn post_collect(
    axum::extract::State(state): axum::extract::State<EngineState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::http::StatusCode, AppError> {
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return Ok(axum::http::StatusCode::NO_CONTENT);
    };
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let client_ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer.ip(),
        &headers,
        &state.base.config,
    );
    // The edge's country, only from a proxy this deployment trusts.
    let country = state
        .base
        .config
        .is_trusted_proxy(peer.ip())
        .then(|| header("cf-ipcountry").or_else(|| header("x-country-code")))
        .flatten();
    let outcome = collect(
        &state,
        CollectRequest {
            origin: header("origin"),
            client_ip,
            country,
            user_agent: header("user-agent").unwrap_or_default(),
            body,
        },
    )
    .await?;
    Ok(match outcome {
        Collected::Queued => axum::http::StatusCode::ACCEPTED,
        Collected::Dropped => axum::http::StatusCode::NO_CONTENT,
    })
}

/// The public collect route with its own body limit.
pub fn public_routes() -> axum::Router<EngineState> {
    axum::Router::new().route(
        "/api/v1/track/collect",
        axum::routing::post(post_collect)
            .layer(axum::extract::DefaultBodyLimit::max(BODY_LIMIT_BYTES)),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_collect))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_is_truncated() {
        assert_eq!(truncate_ip("203.0.113.77".parse().unwrap()), "203.0.113.0");
        assert_eq!(
            truncate_ip("2001:db8:abcd:1234::1".parse().unwrap()),
            "2001:db8:abcd::"
        );
        assert_eq!(
            truncate_ip("::ffff:198.51.100.9".parse().unwrap()),
            "198.51.100.0"
        );
    }

    #[test]
    fn origin_must_be_a_site_domain() {
        let domains = "example.com, https://shop.example.org/";
        assert!(origin_allowed(Some("https://example.com"), domains));
        assert!(origin_allowed(
            Some("https://www.example.com:8443"),
            domains
        ));
        assert!(origin_allowed(Some("https://shop.example.org"), domains));
        assert!(!origin_allowed(Some("https://example.org"), domains));
        assert!(!origin_allowed(Some("https://notexample.com"), domains));
        assert!(!origin_allowed(None, domains));
        assert!(!origin_allowed(Some("null"), domains));
        assert!(!origin_allowed(Some("https://example.com"), ""));
    }

    #[test]
    fn user_agents_are_classed() {
        assert_eq!(
            user_agent_class("Mozilla/5.0 (compatible; Googlebot/2.1)"),
            "bot"
        );
        assert_eq!(
            user_agent_class("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148"),
            "mobile"
        );
        assert_eq!(
            user_agent_class("Mozilla/5.0 (iPad; CPU OS 17_0)"),
            "tablet"
        );
        assert_eq!(
            user_agent_class("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
            "desktop"
        );
    }
}
