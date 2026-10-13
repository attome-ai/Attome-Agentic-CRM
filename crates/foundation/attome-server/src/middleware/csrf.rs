//! Origin/Fetch-Metadata CSRF check (P-cookie-csrf-hardening) for
//! cookie-authenticated unsafe-method requests.
//!
//! CSRF is a browser-cookie problem only: a request carrying `Authorization:
//! ApiKey ...` or authenticated by the S2S HMAC layer never has a browser
//! silently attaching credentials to it, so this middleware only ever acts on
//! a request that presents a session cookie or a refresh cookie (D-305 — the
//! latter is what `/api/v1/auth/refresh` actually runs on, and it commonly
//! arrives without the former). Runs in `apply_inner_layers`
//! *after* `authn` (`attome-server/src/app.rs`) so a request that failed cookie
//! validation there never reaches this code at all — order is load-bearing,
//! see `coding-guidelines.md` §3.
//!
//! Logic (per `document/base/auth/plans/P-cookie-csrf-hardening.md` §4, as
//! narrowed by D-585): allow when `Sec-Fetch-Site` is `same-origin`/`none`, OR
//! when `Origin` is in the CORS allow-list (`AppConfig::allowed_origins`);
//! otherwise reject. `same-site` alone is **not** enough: a sibling host of
//! the same registrable domain (a portal host, D-585) is same-site, so a
//! script there would ride the staff cookie. The split-port dev setup
//! (`:4199` app / `:7865` API) passes through the `Origin` branch instead,
//! because its origin is on the dev allow-list.
//! `Sec-Fetch-Site: none` (address bar, bookmarks) is allowed deliberately —
//! unsafe methods don't originate from the address bar in practice. A request
//! with neither header (e.g. curl replaying a stolen cookie) fails both checks
//! and is rejected — the intended fix for a legitimate non-browser client that
//! needs to carry credentials is an API key, not a cookie.

use attome_types::AppError;
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    middleware::{bypass::is_csrf_exempt, is_mutating},
    state::AppState,
};

const SEC_FETCH_SITE: &str = "sec-fetch-site";

fn sec_fetch_site_is_safe(value: Option<&str>) -> bool {
    matches!(value, Some("same-origin") | Some("none"))
}

/// Exact-match an `Origin` header against the configured allow-list.
///
/// `pub` because a protocol surface needs the *same* notion of "allowed" this
/// module uses. The MCP endpoint must validate `Origin` for every credential
/// type, not only the cookie-authenticated mutating requests
/// [`csrf_protect`] covers, and a second origin parser living over in `xrm-ai`
/// would drift from this one — at which point "allowed" means two different
/// things depending on which door a request came through.
///
/// Exact string match, never a prefix or suffix test: `https://attome.example`
/// must not admit `https://attome.example.evil.test`.
pub fn origin_is_allowed(origin: Option<&str>, allowed_origins: &[String]) -> bool {
    origin.is_some_and(|o| allowed_origins.iter().any(|a| a == o))
}

/// True when the request presents a cookie a browser would have attached by
/// itself — the precondition for CSRF being possible at all.
///
/// EITHER cookie counts. Checking only the session cookie would leave
/// `/api/v1/auth/refresh` (D-305) unprotected in exactly the case it needs
/// protecting: `session::refresh_session` reads only the refresh cookie, and
/// the session cookie's `Max-Age` is the access token's own lifetime, so by the
/// time the SPA refreshes, the session cookie is normally already gone from the
/// jar and this would find no credential at all.
///
/// Widening this costs nothing elsewhere: the refresh cookie is scoped
/// `Path=/api/v1/auth` (`REFRESH_COOKIE_PATH`), so a browser never attaches it
/// to any other route, and every genuinely pre-auth path under that prefix has
/// already returned via `is_csrf_exempt` before this is reached.
fn carries_cookie_credential(headers: &HeaderMap, secure: bool) -> bool {
    attome_auth::cookie::extract_session(headers, secure)
        .or_else(|| attome_auth::cookie::extract_refresh(headers, secure))
        .is_some()
}

/// Pure decision, isolated from axum/`AppState` so the (method ×
/// Sec-Fetch-Site × Origin × cookie-presence) matrix can be unit tested
/// without a live DB/Redis-backed `AppState` — see `mod tests` below.
fn should_reject(
    method_is_unsafe: bool,
    carries_cookie_credential: bool,
    sec_fetch_site: Option<&str>,
    origin: Option<&str>,
    allowed_origins: &[String],
) -> bool {
    if !method_is_unsafe || !carries_cookie_credential {
        return false;
    }
    let allowed =
        sec_fetch_site_is_safe(sec_fetch_site) || origin_is_allowed(origin, allowed_origins);
    !allowed
}

pub async fn csrf_protect(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    if is_csrf_exempt(&path) {
        // Pre-auth by definition (login/register/health/...) — no session
        // exists yet for a cross-site request to ride along with.
        //
        // Deliberately NOT `is_bypass`: `/api/v1/auth/logout` and
        // `/api/v1/auth/refresh` skip authn but act on a live browser cookie,
        // so exempting them here let any attacker-controlled page force-log-out
        // an authenticated user or force-rotate their refresh family. See
        // `bypass::CSRF_ENFORCED_BYPASS_PATHS` for the full reasoning.
        return next.run(req).await;
    }

    let secure_cookies = state.config.auth.secure_cookies;
    let method_is_unsafe = is_mutating(req.method());
    let carries_cookie_credential = carries_cookie_credential(req.headers(), secure_cookies);

    // Cheapest checks first: skip header parsing entirely for the common
    // case (GET/HEAD, or a non-cookie-authenticated request).
    if !method_is_unsafe || !carries_cookie_credential {
        return next.run(req).await;
    }

    let sec_fetch_site = req
        .headers()
        .get(SEC_FETCH_SITE)
        .and_then(|v| v.to_str().ok());
    let origin = req
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    let allowed_origins = state.config.allowed_origins();

    if !should_reject(
        method_is_unsafe,
        carries_cookie_credential,
        sec_fetch_site,
        origin,
        &allowed_origins,
    ) {
        return next.run(req).await;
    }

    if !state.config.security.csrf_enforce {
        tracing::warn!(
            path = %path,
            sec_fetch_site = ?sec_fetch_site,
            origin = ?origin,
            "csrf: would reject (security.csrf_enforce=false, log-only mode) — \
             cross-site cookie-authenticated request on an unsafe method"
        );
        return next.run(req).await;
    }

    tracing::warn!(
        path = %path,
        sec_fetch_site = ?sec_fetch_site,
        origin = ?origin,
        "csrf: rejected cross-site cookie-authenticated request on an unsafe method \
         — non-browser clients carrying a cookie should use an API key instead"
    );
    // P-observability-completion — SecurityAnomalyRateHigh alert source; only
    // the real-enforcement path counts (the log-only branch above already
    // returned), never the log-only report-mode path.
    metrics::counter!("security_rejection_total", "reason" => "csrf").increment(1);
    AppError::Forbidden.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec!["https://app.example.com".to_owned()]
    }

    // ── should_reject matrix ────────────────────────────────────────────────

    #[test]
    fn safe_method_always_passes_regardless_of_headers() {
        assert!(!should_reject(
            false,
            true,
            Some("cross-site"),
            Some("https://evil.example"),
            &allowed(),
        ));
    }

    #[test]
    fn non_cookie_request_always_passes_eg_apikey_or_s2s() {
        assert!(!should_reject(
            true,
            false,
            Some("cross-site"),
            Some("https://evil.example"),
            &allowed(),
        ));
    }

    #[test]
    fn same_origin_sec_fetch_site_is_allowed() {
        assert!(!should_reject(
            true,
            true,
            Some("same-origin"),
            None,
            &allowed()
        ));
    }

    #[test]
    fn same_site_alone_is_rejected_d585() {
        // A portal host under the same registrable domain is same-site: its
        // script must not ride the staff cookie (D-585 item 2).
        assert!(should_reject(
            true,
            true,
            Some("same-site"),
            None,
            &allowed()
        ));
        assert!(should_reject(
            true,
            true,
            Some("same-site"),
            Some("https://portal.example.com"),
            &allowed()
        ));
    }

    #[test]
    fn same_site_with_an_allow_listed_origin_passes() {
        assert!(!should_reject(
            true,
            true,
            Some("same-site"),
            Some("https://app.example.com"),
            &allowed()
        ));
    }

    #[test]
    fn none_sec_fetch_site_is_allowed_address_bar_bookmarks() {
        assert!(!should_reject(true, true, Some("none"), None, &allowed()));
    }

    #[test]
    fn cross_site_sec_fetch_site_falls_back_to_the_origin_allow_list() {
        assert!(!should_reject(
            true,
            true,
            Some("cross-site"),
            Some("https://app.example.com"),
            &allowed(),
        ));
    }

    #[test]
    fn an_allow_listed_origin_passes_even_without_sec_fetch_site() {
        assert!(!should_reject(
            true,
            true,
            None,
            Some("https://app.example.com"),
            &allowed(),
        ));
    }

    #[test]
    fn a_foreign_origin_is_blocked() {
        assert!(should_reject(
            true,
            true,
            None,
            Some("https://evil.example"),
            &allowed(),
        ));
    }

    #[test]
    fn cookie_present_unsafe_method_no_metadata_at_all_is_blocked() {
        // No Sec-Fetch-Site, no Origin: a cookie-bearing non-browser client
        // (e.g. curl replaying a stolen cookie) on an unsafe method.
        assert!(should_reject(true, true, None, None, &allowed()));
    }

    #[test]
    fn cross_site_sec_fetch_site_with_no_matching_origin_is_blocked() {
        assert!(should_reject(
            true,
            true,
            Some("cross-site"),
            Some("https://evil.example"),
            &allowed(),
        ));
    }

    // ── carries_cookie_credential (D-305) ───────────────────────────────────

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn a_refresh_cookie_alone_is_a_credential_so_refresh_is_actually_protected() {
        // THE test for D-305. `session::refresh_session` redeems the refresh
        // cookie and never reads the session cookie, and the session cookie's
        // Max-Age is the access token's own lifetime — so the realistic jar at
        // refresh time holds ONLY this cookie. Were this false, adding
        // `/api/v1/auth/refresh` to `CSRF_ENFORCED_BYPASS_PATHS` would be inert:
        // `csrf_protect` would early-out at the cookie check and never look at
        // Sec-Fetch-Site/Origin.
        assert!(carries_cookie_credential(
            &headers_with_cookie("__Secure-refresh_token=abc"),
            true
        ));
        assert!(carries_cookie_credential(
            &headers_with_cookie("refresh_token=abc"),
            false
        ));
    }

    #[test]
    fn a_refresh_only_jar_on_a_cross_site_post_is_rejected() {
        // The end-to-end shape of the forced-rotation attack: attacker page
        // POSTs /api/v1/auth/refresh, browser attaches only the refresh cookie.
        let carries = carries_cookie_credential(&headers_with_cookie("refresh_token=abc"), false);
        assert!(should_reject(
            true,
            carries,
            Some("cross-site"),
            Some("https://evil.example"),
            &allowed(),
        ));
    }

    #[test]
    fn the_spa_same_origin_refresh_still_passes() {
        // The compatibility half: a real browser XHR from the app origin sets
        // Sec-Fetch-Site itself, so withdrawing the exemption must not break
        // the SPA's own refresh. The split-port dev setup (:4199 app / :7865
        // API — same site, different origin) passes on its allow-listed
        // Origin, not on `same-site` (D-585).
        let carries = carries_cookie_credential(&headers_with_cookie("refresh_token=abc"), false);
        assert!(!should_reject(
            true,
            carries,
            Some("same-origin"),
            None,
            &allowed()
        ));
        assert!(!should_reject(
            true,
            carries,
            Some("same-site"),
            Some("https://app.example.com"),
            &allowed()
        ));
    }

    #[test]
    fn an_unprefixed_refresh_cookie_is_not_a_credential_when_secure() {
        // Contract I1: with secure cookies on, attome_auth::cookie reads only
        // __Secure-refresh_token. An unprefixed cookie authenticates nothing
        // (authn and refresh both ignore it), so it is not a credential the
        // CSRF check has to protect.
        assert!(!carries_cookie_credential(
            &headers_with_cookie("refresh_token=old"),
            true
        ));
    }

    #[test]
    fn a_session_cookie_alone_is_still_a_credential() {
        // Regression guard: widening to the refresh cookie must not have
        // replaced the session-cookie check.
        assert!(carries_cookie_credential(
            &headers_with_cookie("session_token=abc"),
            false
        ));
    }

    #[test]
    fn no_cookies_at_all_is_not_a_credential() {
        assert!(!carries_cookie_credential(&HeaderMap::new(), false));
        assert!(!carries_cookie_credential(
            &headers_with_cookie("unrelated=1"),
            false
        ));
    }

    // ── header-parsing helpers ──────────────────────────────────────────────

    #[test]
    fn sec_fetch_site_is_safe_rejects_unrecognized_values() {
        assert!(!sec_fetch_site_is_safe(Some("cross-site")));
        assert!(!sec_fetch_site_is_safe(None));
    }

    #[test]
    fn origin_is_allowed_requires_an_exact_match() {
        assert!(!origin_is_allowed(
            Some("https://app.example.com.evil.example"),
            &allowed()
        ));
        assert!(origin_is_allowed(
            Some("https://app.example.com"),
            &allowed()
        ));
    }
}
