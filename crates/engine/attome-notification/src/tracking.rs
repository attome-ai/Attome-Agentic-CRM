//! D16-T1: email open and click tracking.
//!
//! When `email.tracking.enabled` is on and the record the email is about
//! has not opted out (the E27 ledger's `email_tracking` purpose withdrawn
//! for that contact, lead or account), an outgoing email gets an HTML part:
//! its links pass through `GET /api/v1/track/click/{token}` and a one-pixel
//! image loads `GET /api/v1/track/open/{token}`. Each token is signed with
//! the active token key under its own domain and names the communication,
//! when it was sent and, for a click, the one URL it may send the reader
//! to: the click route redirects only there, so it cannot be used to send
//! anyone anywhere else.
//!
//! Opens and clicks become `communication_event` rows (`opened`,
//! `clicked`). A hit within two seconds of sending, or from a known mail
//! scanner, is not counted: scanners fetch links before a person reads.

use attome_core::EngineState;
use attome_types::AppError;
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The domain tracking tokens are signed under.
pub const DOMAIN: &str = "attome-email-tracking";
/// How long a tracking token works.
pub const LIFETIME_DAYS: i64 = 365;
/// The consent purpose whose withdrawal turns tracking off for a person.
pub const OPT_OUT_PURPOSE: &str = "email_tracking";
/// Hits sooner than this after sending are a scanner's.
pub const SCANNER_WINDOW_SECONDS: i64 = 2;

/// User agents of mail security scanners that fetch links and images
/// before (or instead of) a person.
const SCANNERS: &[&str] = &[
    "barracuda",
    "bitdefender",
    "checkpoint",
    "cisco",
    "forcepoint",
    "fortinet",
    "ironport",
    "messagelabs",
    "mimecast",
    "proofpoint",
    "safelinks",
    "safe links",
    "sophos",
    "symantec",
    "trend micro",
    "trendmicro",
    "zscaler",
    "microsoft office protection",
];

/// A 1×1 transparent GIF.
const PIXEL: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

/// What a tracking token names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    pub communication_id: Uuid,
    pub sent_at: i64,
    /// The link a click goes to; `None` for the open pixel.
    pub url: Option<String>,
}

/// The signed claim for an open (`o|comm|sent`) or a click
/// (`c|comm|sent|url`). Pure.
pub fn claim(t: &Tracked) -> String {
    match &t.url {
        Some(url) => format!("c|{}|{}|{url}", t.communication_id, t.sent_at),
        None => format!("o|{}|{}", t.communication_id, t.sent_at),
    }
}

/// The claim a verified token carries, read back. Pure.
pub fn parse_claim(raw: &str) -> Option<Tracked> {
    let mut parts = raw.splitn(4, '|');
    let kind = parts.next()?;
    let communication_id = Uuid::parse_str(parts.next()?).ok()?;
    let sent_at = parts.next()?.parse().ok()?;
    let url = match (kind, parts.next()) {
        ("o", None) => None,
        ("c", Some(url)) if safe_url(url) => Some(url.to_owned()),
        _ => return None,
    };
    Some(Tracked {
        communication_id,
        sent_at,
        url,
    })
}

/// Whether a link may be redirected to: http or https, nothing else. Pure.
pub fn safe_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://"))
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Whether a hit is a scanner's, not a person's. Pure.
pub fn is_scanner(user_agent: Option<&str>, sent_at: i64, now: DateTime<Utc>) -> bool {
    if now.timestamp() - sent_at < SCANNER_WINDOW_SECONDS {
        return true;
    }
    let agent = user_agent.unwrap_or_default().to_ascii_lowercase();
    SCANNERS.iter().any(|s| agent.contains(s))
}

fn escape(text: &str) -> String {
    attome_html::escape_html(text)
}

/// The tracked HTML part of a plain-text email: the text escaped, its
/// http(s) links routed through the click route, line breaks kept, and the
/// open pixel at the end. `sign` turns a claim into a token. Pure but for
/// `sign`.
pub fn tracked_html(
    text: &str,
    base_url: &str,
    communication_id: Uuid,
    sent_at: i64,
    sign: impl Fn(&str) -> Option<String>,
) -> String {
    let base = base_url.trim_end_matches('/');
    let mut out = String::from("<!doctype html><html><body><div>");
    for (n, line) in text.lines().enumerate() {
        if n > 0 {
            out.push_str("<br>");
        }
        let mut first = true;
        for word in line.split(' ') {
            if !first {
                out.push(' ');
            }
            first = false;
            let trimmed = word.trim_end_matches(['.', ',', ')', ';', '!', '?']);
            let tail = &word[trimmed.len()..];
            if safe_url(trimmed) {
                let token = sign(&claim(&Tracked {
                    communication_id,
                    sent_at,
                    url: Some(trimmed.to_owned()),
                }));
                match token {
                    Some(token) => out.push_str(&format!(
                        "<a href=\"{base}/api/v1/track/click/{token}\">{}</a>{}",
                        escape(trimmed),
                        escape(tail)
                    )),
                    None => out.push_str(&escape(word)),
                }
            } else {
                out.push_str(&escape(word));
            }
        }
    }
    out.push_str("</div>");
    if let Some(token) = sign(&claim(&Tracked {
        communication_id,
        sent_at,
        url: None,
    })) {
        out.push_str(&format!(
            "<img src=\"{base}/api/v1/track/open/{token}\" width=\"1\" height=\"1\" alt=\"\">"
        ));
    }
    out.push_str("</body></html>");
    out
}

/// D16-T2: whether an email body is HTML rather than plain text: it carries
/// one of the tags a composer or template writes. Pure.
pub fn looks_like_html(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    [
        "<p>", "<p ", "<br", "<div", "<a ", "<table", "<html", "<body", "<ul", "<ol", "<h1", "<h2",
        "<h3", "<strong", "<em>", "<span",
    ]
    .iter()
    .any(|tag| lower.contains(tag))
}

/// D16-T2: an HTML part with tracking: every `href` to an http(s) address
/// routed through the click route (other links, such as `mailto:` or an
/// in-page `#anchor`, kept), and the open pixel before `</body>`, or at the
/// end without one. `sign` turns a claim into a token; a link it cannot sign
/// is kept as it was. Pure but for `sign`.
pub fn tracked_rewrite(
    html: &str,
    base_url: &str,
    communication_id: Uuid,
    sent_at: i64,
    sign: impl Fn(&str) -> Option<String>,
) -> String {
    let base = base_url.trim_end_matches('/');
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len() + 256);
    let mut at = 0;
    while let Some(found) = lower[at..].find("href=") {
        let attr = at + found + "href=".len();
        let Some(quote) = html[attr..]
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
        else {
            out.push_str(&html[at..attr]);
            at = attr;
            continue;
        };
        let start = attr + 1;
        let Some(len) = html[start..].find(quote) else {
            break;
        };
        let raw = &html[start..start + len];
        let url = raw.replace("&amp;", "&");
        out.push_str(&html[at..start]);
        let token = safe_url(&url)
            .then(|| {
                sign(&claim(&Tracked {
                    communication_id,
                    sent_at,
                    url: Some(url.trim().to_owned()),
                }))
            })
            .flatten();
        match token {
            Some(token) => out.push_str(&format!("{base}/api/v1/track/click/{token}")),
            None => out.push_str(raw),
        }
        at = start + len;
    }
    out.push_str(&html[at..]);
    let Some(token) = sign(&claim(&Tracked {
        communication_id,
        sent_at,
        url: None,
    })) else {
        return out;
    };
    let pixel =
        format!("<img src=\"{base}/api/v1/track/open/{token}\" width=\"1\" height=\"1\" alt=\"\">");
    match out.to_ascii_lowercase().rfind("</body>") {
        Some(end) => out.insert_str(end, &pixel),
        None => out.push_str(&pixel),
    }
    out
}

/// Whether tracking is on for this deployment.
pub fn enabled(state: &EngineState) -> bool {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get("email.tracking.enabled")
        .map(|d| settings.resolve(d, None, None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The signing key.
pub fn signing_secret(state: &EngineState) -> Option<String> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
}

/// A token for `claim`, valid [`LIFETIME_DAYS`] days.
pub fn sign(secret: &str, claim: &str) -> Option<String> {
    let expires = (Utc::now() + chrono::Duration::days(LIFETIME_DAYS)).timestamp();
    attome_auth::signed_link::sign(secret, DOMAIN, claim, expires)
}

/// Whether the person the email is about withdrew tracking (E27 ledger,
/// purpose [`OPT_OUT_PURPOSE`]).
pub async fn opted_out(
    conn: &mut sqlx::PgConnection,
    entity_name: &str,
    record_id: Uuid,
) -> Result<bool, AppError> {
    if !matches!(entity_name, "contact" | "lead" | "account") {
        return Ok(false);
    }
    let decision = attome_core::consent_rules::gate(
        conn,
        (entity_name, record_id),
        None,
        OPT_OUT_PURPOSE,
        "email",
        None,
    )
    .await?;
    Ok(matches!(
        decision,
        attome_core::consent_rules::Decision::Withdrawn
            | attome_core::consent_rules::Decision::AccountOptOut
    ))
}

async fn record(state: &EngineState, tracked: &Tracked, event_type: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO communication_event (communication_id, event_type, detail, occurred_at) \
         SELECT c.id, $2, $3, NOW() FROM communication c WHERE c.id = $1",
    )
    .bind(tracked.communication_id)
    .bind(event_type)
    .bind(tracked.url.as_deref())
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

fn verify(state: &EngineState, token: &str) -> Option<Tracked> {
    let secret = signing_secret(state)?;
    attome_auth::signed_link::verify(&secret, DOMAIN, token, Utc::now().timestamp())
        .and_then(|c| parse_claim(&c))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Counts an open (D16-T1). Always answers the pixel, whatever the token.
#[utoipa::path(
    get,
    path = "/api/v1/track/open/{token}",
    tag = "notification",
    params(("token" = String, Path, description = "The signed open token")),
    responses((status = 200, description = "A 1x1 GIF", content_type = "image/gif")),
)]
async fn track_open(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = token.trim_end_matches(".gif");
    if enabled(&state)
        && let Some(tracked) = verify(&state, token).filter(|t| t.url.is_none())
        && !is_scanner(user_agent(&headers).as_deref(), tracked.sent_at, Utc::now())
        && let Err(error) = record(&state, &tracked, "opened").await
    {
        tracing::warn!(?error, "email tracking: open not recorded");
    }
    (
        [
            (header::CONTENT_TYPE, "image/gif"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
        ],
        PIXEL,
    )
        .into_response()
}

/// Counts a click and sends the reader on (D16-T1).
///
/// Redirects only to the link the signed token names; any other token
/// answers 404.
#[utoipa::path(
    get,
    path = "/api/v1/track/click/{token}",
    tag = "notification",
    params(("token" = String, Path, description = "The signed click token")),
    responses(
        (status = 302, description = "To the link the token names"),
        (status = 404, description = "Not a valid click token"),
    ),
)]
async fn track_click(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(tracked) = verify(&state, &token) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(url) = tracked.url.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if enabled(&state)
        && !is_scanner(user_agent(&headers).as_deref(), tracked.sent_at, Utc::now())
        && let Err(error) = record(&state, &tracked, "clicked").await
    {
        tracing::warn!(?error, "email tracking: click not recorded");
    }
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, url),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

/// The public tracking routes, bypass-listed by their path shape.
pub fn public_routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/track/open/{token}", get(track_open))
        .route("/api/v1/track/click/{token}", get(track_click))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(track_open, track_click))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod email_tracking {

    #[test]
    fn tracking_rewrite_routes_http_links_and_adds_the_pixel() {
        let id = Uuid::from_u128(9);
        let sign = |claim: &str| Some(format!("t{}", claim.len()));
        let html = "<html><body><p>See <a href=\"https://example.sa/offer?a=1&amp;b=2\">the offer</a>, \
                    <a href='mailto:sales@example.sa'>mail us</a> or <a href=\"#top\">top</a>.</p></body></html>";
        let out = tracked_rewrite(html, "https://crm.example.sa/", id, 1_800_000_000, sign);
        assert!(out.contains("href=\"https://crm.example.sa/api/v1/track/click/t"));
        assert!(!out.contains("https://example.sa/offer"));
        assert!(out.contains("href='mailto:sales@example.sa'"));
        assert!(out.contains("href=\"#top\""));
        assert!(out.contains("/api/v1/track/open/"));
        assert!(out.ends_with("></body></html>"));
        // The claim carries the decoded address.
        let claimed = std::cell::RefCell::new(Vec::new());
        tracked_rewrite(html, "https://crm.example.sa", id, 1, |c| {
            claimed.borrow_mut().push(c.to_owned());
            None
        });
        assert!(
            claimed
                .borrow()
                .iter()
                .filter_map(|c| parse_claim(c))
                .any(|t| t.url.as_deref() == Some("https://example.sa/offer?a=1&b=2"))
        );
        // Unsignable: unchanged, and no pixel.
        assert_eq!(tracked_rewrite(html, "https://x", id, 1, |_| None), html);
    }

    #[test]
    fn tracking_rewrite_tells_html_from_text() {
        assert!(looks_like_html("<p>Hello</p>"));
        assert!(looks_like_html("Line one<br>Line two"));
        assert!(!looks_like_html(
            "Price < 5 and > 2, see https://example.sa"
        ));
    }

    use super::*;

    fn signer(claim: &str) -> Option<String> {
        attome_auth::signed_link::sign("secret", DOMAIN, claim, Utc::now().timestamp() + 60)
    }

    #[test]
    fn email_tracking_claims_round_trip_and_name_one_url() {
        let open = Tracked {
            communication_id: Uuid::now_v7(),
            sent_at: 1_700_000_000,
            url: None,
        };
        assert_eq!(parse_claim(&claim(&open)), Some(open.clone()));
        let click = Tracked {
            url: Some("https://example.com/a?b=1|2".to_owned()),
            ..open.clone()
        };
        assert_eq!(parse_claim(&claim(&click)), Some(click));
        let bad = format!("c|{}|1|javascript:alert(1)", open.communication_id);
        assert_eq!(
            parse_claim(&bad),
            None,
            "only http(s) links are redirected to"
        );
        assert_eq!(parse_claim("x|y|z"), None);
    }

    #[test]
    fn email_tracking_skips_scanners_and_instant_hits() {
        let sent = Utc::now().timestamp() - 3600;
        assert!(!is_scanner(Some("Mozilla/5.0"), sent, Utc::now()));
        assert!(is_scanner(
            Some("Mozilla/5.0 (compatible; Barracuda)"),
            sent,
            Utc::now()
        ));
        assert!(is_scanner(
            Some("Mozilla/5.0"),
            Utc::now().timestamp(),
            Utc::now()
        ));
    }

    #[test]
    fn email_tracking_html_routes_links_and_adds_the_pixel() {
        let comm = Uuid::now_v7();
        let html = tracked_html(
            "Hello <you>,\nsee https://example.com/offer. Thanks",
            "https://crm.example.com/",
            comm,
            1_700_000_000,
            signer,
        );
        assert!(html.contains("&lt;you&gt;"), "{html}");
        assert!(
            html.contains("https://crm.example.com/api/v1/track/click/"),
            "{html}"
        );
        assert!(html.contains(">https://example.com/offer</a>."), "{html}");
        assert!(html.contains("/api/v1/track/open/"), "{html}");
        assert!(html.contains("<br>"), "{html}");
    }
}
