//! Response security headers (`P-frontend-hardening` §4(d)/step 7):
//! `Content-Security-Policy` (or its report-only variant, gated by
//! `AppConfig.security.csp_enforce`), `X-Content-Type-Options`,
//! `Referrer-Policy`, and `Strict-Transport-Security` (gated by
//! `AppConfig.security.hsts_max_age_secs`/`hsts_include_subdomains`),
//! applied to every response this process serves.
//!
//! The plan's design keeps this policy in lockstep with the Angular SPA's
//! own page-level CSP (`deploy/frontend/nginx.conf`, a separate nginx
//! process that serves the built static files — this Rust process never
//! renders HTML) rather than treating the two as independent surfaces, so
//! the two policy strings should be changed together; see that file's
//! header comment.
//!
//! **Correction versus the plan's literal §4(d) policy string.** The plan
//! states "No third-party host appears in any directive — the whole point
//! of (a)/(b) [font/icon self-hosting] landing first is that there is
//! nothing external left to allow-list." That's not quite right:
//! `angular/src/app/components/auth-modal/auth-modal.component.ts`'s
//! `loadGoogleScript()` injects `<script src="https://accounts.google.com/
//! gsi/client">` at runtime (only when a deployment configures Google
//! Sign-In's `client_id` — an air-gapped deployment that never sets one
//! never loads it), consistent with D-072's "Google de-emphasis, not
//! removal." A literal `script-src 'self'` with no exception would silently
//! break Google Sign-In for every deployment that *does* enable it, the
//! first time `csp_enforce` is flipped on. `https://accounts.google.com` is
//! therefore allow-listed in `script-src`/`frame-src` below (and in the
//! nginx conf) — flagged here, not silently added, since it's a real
//! deviation from the plan's written design that a reader diffing against
//! §4(d) would otherwise have to reverse-engineer.
use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// Kept in lockstep with `deploy/frontend/nginx.conf`'s `Content-Security-Policy`
/// value — see this module's doc comment for the one intentional deviation
/// from the plan's literal §4(d) string (the `accounts.google.com` allowance).
pub(crate) const CSP_POLICY: &str = "default-src 'self'; script-src 'self' https://accounts.google.com; \
     style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; \
     connect-src 'self'; frame-src https://accounts.google.com; \
     frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/// Q21-T3: browser features a page may use. The app is one page for every
/// route, so the features its own screens need (camera for scanning, B15;
/// microphone for calls, J7; location for check-in) are allowed to this
/// origin only, never to a frame from elsewhere; everything else is off.
pub(crate) const PAGE_PERMISSIONS_POLICY: &str = "camera=(self), microphone=(self), geolocation=(self), payment=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), display-capture=(), xr-spatial-tracking=(), browsing-topics=()";

/// Q21-T3: an API response or a file uses no browser feature at all.
pub(crate) const API_PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), display-capture=()";

/// Q21-T3: a page keeps its own browsing context group. `same-origin-allow-popups`
/// rather than `same-origin`: the optional Google sign-in (see the module
/// comment) opens a popup that must reach back to the page; any page that
/// opens this one from another origin still loses its handle on it.
pub(crate) const PAGE_OPENER_POLICY: &str = "same-origin-allow-popups";

/// Z5-T10: which kind of response a path serves, for its header set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// A page of the signed-in app (and, until Q21-T2 gives them their own
    /// policy, a web portal's pages): the CSP applies.
    App,
    /// A web portal page. Shares the app's header set today.
    Portal,
    /// A JSON API response: no CSP (a JSON body runs no script), but
    /// `X-Frame-Options: DENY` so no page may frame it.
    Api,
}

/// The surface a request path is served on: `/api/` is the API, everything
/// else a page. Portal pages are not told apart here yet (they share the
/// page set), so this never answers `Portal`.
pub fn surface_for(path: &str) -> Surface {
    if path == "/api" || path.starts_with("/api/") {
        Surface::Api
    } else {
        Surface::App
    }
}

/// API resources other websites embed: the website tracking script (E14-T4,
/// a `<script>` on a customer's site) and the email open pixel (D16-T1, an
/// `<img>` in a webmail page). `Cross-Origin-Resource-Policy: same-origin`
/// would make a browser refuse to load them, so they say `cross-origin`.
/// Exact paths and one fixed prefix, never a broader `/api/` subtree.
pub fn is_cross_origin_resource(path: &str) -> bool {
    path == "/api/v1/track/script.js" || path.starts_with("/api/v1/track/open/")
}

/// Precomputed once at server boot (`app::apply_outer_layers`) from
/// `AppConfig.security.csp_enforce` — never rebuilt per request.
#[derive(Clone)]
pub struct SecurityHeaderValues {
    csp_header_name: &'static str,
    csp: HeaderValue,
    x_content_type_options: HeaderValue,
    referrer_policy: HeaderValue,
    /// `None` when `security.hsts_max_age_secs` is 0 — the header is then
    /// omitted rather than sent with `max-age=0`, which is an active
    /// instruction to *forget* a previously-known HSTS host.
    strict_transport_security: Option<HeaderValue>,
}

impl std::fmt::Debug for SecurityHeaderValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityHeaderValues")
            .finish_non_exhaustive()
    }
}

impl SecurityHeaderValues {
    /// `csp_enforce` mirrors `AppConfig.security.csp_enforce` — see that
    /// field's doc comment (`attome-config/src/config.rs`) for the rollout
    /// guidance (ship `false`/report-only first in any real deployment).
    /// `hsts_max_age_secs`/`hsts_include_subdomains` mirror the two
    /// `security.hsts_*` fields alongside it.
    pub fn new(csp_enforce: bool, hsts_max_age_secs: u64, hsts_include_subdomains: bool) -> Self {
        Self {
            csp_header_name: if csp_enforce {
                "content-security-policy"
            } else {
                "content-security-policy-report-only"
            },
            csp: HeaderValue::from_static(CSP_POLICY),
            x_content_type_options: HeaderValue::from_static("nosniff"),
            referrer_policy: HeaderValue::from_static("strict-origin-when-cross-origin"),
            strict_transport_security: hsts_header_value(
                hsts_max_age_secs,
                hsts_include_subdomains,
            ),
        }
    }
}

/// `None` for a zero max-age. Never fails to parse for any `u64`/bool pair —
/// the value is digits plus a fixed suffix — but builds through the checked
/// constructor anyway rather than asserting that by hand.
fn hsts_header_value(max_age_secs: u64, include_subdomains: bool) -> Option<HeaderValue> {
    if max_age_secs == 0 {
        return None;
    }
    let value = if include_subdomains {
        format!("max-age={max_age_secs}; includeSubDomains")
    } else {
        format!("max-age={max_age_secs}")
    };
    HeaderValue::from_str(&value).ok()
}

/// Applied as the outermost layer in `apply_outer_layers` (added last, so it
/// wraps every other layer) — every response gets these headers regardless
/// of which layer produced it (a 2xx from a handler, a 401 from `authn`, a
/// 413 from the body-limit guard, a 503 from `mutation_gate`, etc.).
///
/// Z5-T10: the set depends on the surface ([`surface_for`]), decided from
/// the request path before the inner layers run; the values themselves were
/// built once at boot.
pub async fn security_headers(values: SecurityHeaderValues, req: Request, next: Next) -> Response {
    let surface = surface_for(req.uri().path());
    let embeddable = is_cross_origin_resource(req.uri().path());
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    match surface {
        Surface::App | Surface::Portal => {
            headers.insert(values.csp_header_name, values.csp);
            headers.insert(
                "permissions-policy",
                HeaderValue::from_static(PAGE_PERMISSIONS_POLICY),
            );
            headers.insert(
                "cross-origin-opener-policy",
                HeaderValue::from_static(PAGE_OPENER_POLICY),
            );
        }
        Surface::Api => {
            headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
            headers.insert(
                "permissions-policy",
                HeaderValue::from_static(API_PERMISSIONS_POLICY),
            );
            headers.insert(
                "cross-origin-resource-policy",
                HeaderValue::from_static(if embeddable {
                    "cross-origin"
                } else {
                    "same-origin"
                }),
            );
        }
    }
    headers.insert("x-content-type-options", values.x_content_type_options);
    headers.insert("referrer-policy", values.referrer_policy);
    if let Some(hsts) = values.strict_transport_security {
        headers.insert("strict-transport-security", hsts);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, routing::get};
    use tower::ServiceExt;

    fn app_with(values: SecurityHeaderValues) -> Router {
        Router::new()
            .route("/", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(move |req, next| {
                security_headers(values.clone(), req, next)
            }))
    }

    /// The two CSP-focused tests below predate HSTS and only care about the
    /// CSP header name, so they keep using the production default pair
    /// rather than restating it at each call site.
    fn values(csp_enforce: bool) -> SecurityHeaderValues {
        SecurityHeaderValues::new(csp_enforce, 31_536_000, false)
    }

    fn get_request() -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn csp_enforce_true_sends_the_enforcing_header_name_not_the_report_only_one() {
        let app = app_with(values(true));
        let response = app.oneshot(get_request()).await.unwrap();
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(
            !response
                .headers()
                .contains_key("content-security-policy-report-only")
        );
    }

    #[tokio::test]
    async fn csp_enforce_false_sends_the_report_only_header_name_not_the_enforcing_one() {
        let app = app_with(values(false));
        let response = app.oneshot(get_request()).await.unwrap();
        assert!(
            response
                .headers()
                .contains_key("content-security-policy-report-only")
        );
        assert!(!response.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn every_response_carries_the_full_fixed_header_set() {
        let app = app_with(values(true));
        let response = app.oneshot(get_request()).await.unwrap();
        let headers = response.headers();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(
            headers.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        let csp = headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn hsts_is_sent_with_the_configured_max_age() {
        let app = app_with(SecurityHeaderValues::new(true, 31_536_000, false));
        let response = app.oneshot(get_request()).await.unwrap();
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000"
        );
    }

    #[tokio::test]
    async fn hsts_include_subdomains_appends_the_directive() {
        let app = app_with(SecurityHeaderValues::new(true, 15_552_000, true));
        let response = app.oneshot(get_request()).await.unwrap();
        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=15552000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn hsts_zero_max_age_omits_the_header_entirely() {
        // Not "max-age=0": that directive actively tells a browser to FORGET
        // this host, which is a different (and worse) thing than never
        // asserting HSTS in the first place.
        let app = app_with(SecurityHeaderValues::new(true, 0, true));
        let response = app.oneshot(get_request()).await.unwrap();
        assert!(!response.headers().contains_key("strict-transport-security"));
    }

    fn request_for(path: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// Z5-T10: an API response carries no CSP but may not be framed.
    #[tokio::test]
    async fn api_surface_has_no_csp() {
        let app = Router::new()
            .route("/api/v1/things", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(move |req, next| {
                security_headers(values(true), req, next)
            }));
        let response = app.oneshot(request_for("/api/v1/things")).await.unwrap();
        let headers = response.headers();
        assert!(!headers.contains_key("content-security-policy"));
        assert!(!headers.contains_key("content-security-policy-report-only"));
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert!(headers.contains_key("strict-transport-security"));
    }

    /// Z5-T10: a page keeps the CSP and is not given the API's frame header.
    #[tokio::test]
    async fn app_surface_keeps_csp() {
        let app = app_with(values(true));
        let response = app.oneshot(request_for("/")).await.unwrap();
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(!response.headers().contains_key("x-frame-options"));
        assert_eq!(surface_for("/xrm/dashboard"), Surface::App);
        assert_eq!(surface_for("/api/v1/live"), Surface::Api);
        assert_eq!(surface_for("/apiary"), Surface::App);
    }

    /// Q21-T3: a page may use the camera, microphone and location for its
    /// own screens only, and keeps its own browsing context group; an API
    /// response may use no browser feature and is readable same-origin only.
    #[tokio::test]
    async fn isolation_headers_on_pages_and_api_responses() {
        let app = app_with(values(true));
        let response = app.oneshot(request_for("/")).await.unwrap();
        let headers = response.headers();
        let policy = headers.get("permissions-policy").unwrap().to_str().unwrap();
        assert!(policy.contains("camera=(self)"), "{policy}");
        assert!(policy.contains("payment=()"), "{policy}");
        assert_eq!(
            headers.get("cross-origin-opener-policy").unwrap(),
            "same-origin-allow-popups"
        );

        let app = Router::new()
            .route("/api/v1/files", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(move |req, next| {
                security_headers(values(true), req, next)
            }));
        let response = app.oneshot(request_for("/api/v1/files")).await.unwrap();
        let headers = response.headers();
        let policy = headers.get("permissions-policy").unwrap().to_str().unwrap();
        assert!(policy.contains("camera=()"), "{policy}");
        assert!(!policy.contains("(self)"), "{policy}");
        assert_eq!(
            headers.get("cross-origin-resource-policy").unwrap(),
            "same-origin"
        );
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");

        // The tracking script and the open pixel are embedded by other sites.
        let app = Router::new()
            .route("/api/v1/track/script.js", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(move |req, next| {
                security_headers(values(true), req, next)
            }));
        let response = app
            .oneshot(request_for("/api/v1/track/script.js"))
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .unwrap(),
            "cross-origin"
        );
        assert!(is_cross_origin_resource("/api/v1/track/open/abc.gif"));
        assert!(!is_cross_origin_resource("/api/v1/track/collect"));
        assert!(!is_cross_origin_resource("/api/v1/track/script.jsx"));
    }

    #[tokio::test]
    async fn headers_are_present_even_on_a_non_2xx_response() {
        // Guards the reason this middleware must be the OUTERMOST layer in
        // apply_outer_layers: a rejection from any inner layer (auth, CSRF,
        // rate-limit, body-limit, mutation-gate) must still carry these
        // headers. Simulated here with a handler that returns 404 directly,
        // since this module has no access to those inner layers standalone.
        let app = Router::new()
            .route("/missing-on-purpose", get(|| async {}))
            .layer(axum::middleware::from_fn(move |req, next| {
                security_headers(values(true), req, next)
            }));
        let req = axum::http::Request::builder()
            .uri("/not-a-real-route")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(response.headers().contains_key("strict-transport-security"));
    }
}
