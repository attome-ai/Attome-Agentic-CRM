use attome_auth::session::SessionClaims;
use attome_cache::RedisPool;
use attome_cache::rate_limit::RateLimitOutcome;
use attome_types::AppError;
use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::api_usage::{self, Identity};
use crate::middleware::auth::ApiKeyIdentity;
use crate::middleware::client_ip::{client_ip, rate_limit_subject};
use crate::state::AppState;

/// (method, route template, category) — route template is the literal axum
/// route pattern (curly-brace params, e.g. `/api/v1/{entity}`), matched
/// against `axum::extract::MatchedPath`, NOT the concrete request path.
/// Plain string literals only (same convention as `bypass.rs`'s
/// `EXACT_BYPASS_PATHS`) — some of these routes are owned by `xrm-*` crates,
/// but naming their path as a string here creates no `xrm-*` dependency
/// (guidelines §1).
///
/// An unlisted (method, route) pair falls back to `DEFAULT_CATEGORY`, never
/// to zero enforcement — same fail-safe direction `bypass.rs` documents for
/// its own table (a route missing here just gets the loose default budget,
/// not no budget at all).
pub const RATE_LIMIT_CATEGORIES: &[(&str, &str, &str)] = &[
    ("POST", "/api/v1/auth/login", "credential"),
    ("POST", "/api/v1/auth/register", "credential"),
    ("POST", "/api/v1/auth/google", "credential"),
    ("GET", "/api/v1/auth/oidc/{provider}/callback", "credential"),
    ("POST", "/api/v1/auth/refresh", "credential"),
    ("POST", "/api/v1/auth/mfa/verify", "mfa"),
    ("POST", "/api/v1/auth/mfa/verify-recovery", "mfa"),
    ("POST", "/api/v1/auth/mfa/pending-enroll", "mfa"),
    ("POST", "/api/v1/auth/mfa/pending-confirm", "mfa"),
    ("POST", "/api/v1/auth/mfa/enroll", "mfa"),
    ("POST", "/api/v1/auth/mfa/confirm", "mfa"),
    ("POST", "/api/v1/auth/mfa/disable", "mfa"),
    // attome-auth hardening 1.5: regeneration takes a second-factor code too,
    // so it shares the MFA budget instead of the blanket `api` one.
    ("POST", "/api/v1/auth/mfa/recovery-codes/regenerate", "mfa"),
    // attome-auth hardening 2.1b (D-510): step-up verifies a password or a
    // second-factor code, so both of its routes share the MFA budget.
    ("POST", "/api/v1/auth/step-up/{operation}", "mfa"),
    ("POST", "/api/v1/auth/step-up/{operation}/verify", "mfa"),
    // attome-auth plan BAU-8c: the Google step-up is a second-factor attempt too.
    ("POST", "/api/v1/auth/step-up/{operation}/google", "mfa"),
    // attome-auth hardening 2.1c (D-510 rule 5): federated step-up starts share
    // the MFA budget; the IdP callbacks are credential-class, like the login
    // callbacks.
    (
        "GET",
        "/api/v1/auth/step-up/{operation}/oidc/{provider}",
        "mfa",
    ),
    (
        "GET",
        "/api/v1/auth/step-up-callback/oidc/{provider}",
        "credential",
    ),
    ("POST", "/api/v1/auth/reset-request", "password_reset"),
    ("POST", "/api/v1/auth/reset-confirm", "password_reset"),
    // attome-auth hardening 1.8: the email-verification confirm route is the
    // same anonymous bearer-token-guessing class as reset-confirm, so it
    // shares that tighter budget instead of falling to the blanket `api` one.
    // (Invitation tokens are redeemed only through /api/v1/auth/register,
    // which is already `credential`.)
    (
        "POST",
        "/api/v1/auth/verify-email/confirm",
        "password_reset",
    ),
    ("POST", "/api/v1/query/execute", "expensive_query"),
    // item 26 remediation: each presigned PUT hands out quarantine-storage
    // write capacity the object-store layer itself cannot bound (see
    // attome-storage/src/presign.rs — the `object_store` Signer trait has no
    // content-length/policy constraint), so session creation gets its own
    // tight budget rather than sharing the blanket `api` category.
    (
        "POST",
        "/api/v1/{entity}/{id}/files/{field}/upload-session",
        "presign",
    ),
    // Work Intake self-service portal (M70, D-423): anonymous, no auth
    // beyond the presented token itself, so it gets its own tighter budget
    // rather than the blanket `api` default — same token-guessing-resistance
    // reasoning `password_reset`/`mfa` already apply to their own bearer
    // checks.
    ("GET", "/api/v1/service-portal/status", "portal_status"),
    // Consent Management (M24, D-428): the public, anonymous capture route
    // gets its own budget rather than the blanket `api` default — same
    // token/enumeration-resistance reasoning as `portal_status` above, since
    // it's the one route in this crate an unauthenticated caller can write
    // through at all.
    ("POST", "/api/v1/consents/capture", "consent_capture"),
    // Omnichannel web chat widget (M53 Phase 1, D-474): anonymous, bearer-
    // token-scoped, same token/enumeration-resistance reasoning as
    // `portal_status`/`consent_capture` above — this is the one surface an
    // unauthenticated visitor can both read and write through in this crate.
    // `server::omnichannel` additionally rate-limits per caller IP and per
    // resumed session directly (`attome_cache::rate_limit`, mirroring
    // `content_public.rs::vote_on_page`'s belt-and-suspenders shape), so this
    // category is the same defense-in-depth second layer those two routes
    // get, not the only control.
    ("POST", "/api/v1/omnichannel/webchat/message", "webchat"),
    ("GET", "/api/v1/omnichannel/webchat/poll", "webchat"),
];
pub(crate) const DEFAULT_CATEGORY: &str = "api";

fn category_for(method: &str, route_template: &str) -> &'static str {
    RATE_LIMIT_CATEGORIES
        .iter()
        .find(|(m, r, _)| *m == method && *r == route_template)
        .map(|(_, _, category)| *category)
        .unwrap_or(DEFAULT_CATEGORY)
}

#[expect(
    clippy::expect_used,
    reason = "a decimal digit string is always a valid header value"
)]
fn header_value_from_u64(n: u64) -> HeaderValue {
    HeaderValue::from_str(&n.to_string())
        .expect("a decimal digit string is always a valid header value")
}

/// Sets `X-RateLimit-Limit`/`X-RateLimit-Remaining` on every response (2xx or
/// 429) and `X-RateLimit-Reset`/`Retry-After` only on a rejected one — all
/// four computed from the same atomic read the admit/reject decision came
/// from (P-rate-limit-atomicity §4.1/§4.3), never a separately-timed lookup
/// that could disagree with it.
fn apply_rate_limit_headers(headers: &mut HeaderMap, outcome: RateLimitOutcome) {
    headers.insert(
        "x-ratelimit-limit",
        header_value_from_u64(outcome.limit as u64),
    );
    headers.insert(
        "x-ratelimit-remaining",
        header_value_from_u64(outcome.remaining as u64),
    );
    if !outcome.allowed {
        headers.insert(
            "x-ratelimit-reset",
            header_value_from_u64(outcome.reset_unix.max(0) as u64),
        );
        headers.insert(
            axum::http::header::RETRY_AFTER,
            header_value_from_u64(outcome.retry_after_secs),
        );
    }
}

/// Per-account attempt budget shared by every second-factor route: login-time
/// verify and verify-recovery, and self-service disable and recovery-code
/// regeneration. One bucket per account, so alternating routes never
/// multiplies the budget (attome-auth hardening 1.5). A constant, not config:
/// a budget a deployment could raise is one a misconfiguration could disable.
pub const MFA_ATTEMPTS_PER_ACCOUNT_RPM: i32 = 10;

/// The shared MFA bucket for `user_id`, `server:rl:account:{user_id}:mfa` —
/// the key the login-time routes have always used, so live buckets carry over.
pub fn mfa_account_key(user_id: Uuid) -> String {
    attome_cache::rate_limit::account_key(&user_id.to_string(), "mfa")
}

/// Checks a per-account budget before any credential work. `Ok(None)` admits
/// the request; `Ok(Some(_))` is the finished 429 to return as-is; `Err(_)`
/// means Redis failed or timed out, and the caller fails closed by returning
/// it, exactly like the category middleware's error arm.
///
/// The 429 carries `Retry-After` and `X-RateLimit-Reset` from the same atomic
/// read as the decision. `X-RateLimit-Limit`/`-Remaining` are left to the
/// category middleware, which stamps its own per-IP numbers on the way out.
/// `key` is a hash or a user id, never an email, so it is safe to log.
pub async fn enforce_account_budget(
    redis: &RedisPool,
    key: &str,
    limit_rpm: i32,
    route: &'static str,
) -> Result<Option<Response>, AppError> {
    let outcome = attome_cache::rate_limit::check(redis, key, limit_rpm).await?;
    if outcome.allowed {
        return Ok(None);
    }
    tracing::warn!(
        route,
        bucket = key,
        retry_after_secs = outcome.retry_after_secs,
        "per-account throttle tripped"
    );
    let mut resp = AppError::TooManyRequests {
        retry_after_secs: Some(outcome.retry_after_secs),
    }
    .into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::RETRY_AFTER,
        header_value_from_u64(outcome.retry_after_secs),
    );
    headers.insert(
        "x-ratelimit-reset",
        header_value_from_u64(outcome.reset_unix.max(0) as u64),
    );
    Ok(Some(resp))
}

/// Redis-backed sliding-window rate limit, keyed on identity when available and on
/// IP otherwise, further scoped by a compile-time (method, route) → category
/// classification (`RATE_LIMIT_CATEGORIES`) — a request to one category never
/// draws down another category's budget for the same caller, and a
/// parameterized route (`/api/v1/{entity}`) gets a real, correctly-applied
/// limit instead of silently falling through to the blanket default
/// (P-rate-limit-atomicity, closing ENTERPRISE-AUDIT-2026-07-24.md #7's
/// "unrelated endpoints share one quota" half). Deliberately runs regardless
/// of the auth bypass list — anonymous routes (login/register) have no
/// `SessionClaims` yet, so they fall back to IP-based limiting, which is
/// exactly where credential-stuffing protection is needed (Plan 1.3b).
pub async fn rate_limit(
    State(state): State<AppState>,
    matched_path: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let cfg = &state.config.rate_limit;
    // A4 (BSV-F10) — `MatchedPath` exists only on a real (non-fallback) route,
    // so an unmatched path's template here is the raw request path. That is
    // the right input for the category decision (an unlisted route falls safe
    // to `api`), but it must never reach `api_usage::record`: an authenticated
    // scanner would create one usage row per random path per day. The metric
    // label has the same problem and is bounded in `metrics.rs`.
    let matched = matched_path.as_ref().map(MatchedPath::as_str);
    let route_template = matched.unwrap_or_else(|| req.uri().path());
    let category = category_for(req.method().as_str(), route_template);

    let (bucket, is_authenticated) = match req.extensions().get::<SessionClaims>() {
        Some(claims) => (format!("user:{}", claims.sub), true),
        None => {
            let ip = client_ip(&req, &state.config)
                .map(|ip| rate_limit_subject(ip, state.config.rate_limit.ipv6_bucket_prefix))
                .unwrap_or_else(|| "unknown".to_owned());
            (format!("ip:{ip}"), false)
        }
    };

    // M61 Phase 1 (API Management, D-438) — per-route/per-identity usage
    // counter. Reuses the (route_template, identity) this middleware already
    // resolved above rather than re-deriving it; distinguishes an api-key
    // caller from a session caller via `ApiKeyIdentity` (set by `authn` only
    // on the API-key branch), which `SessionClaims.sub` alone can't do — see
    // that type's doc comment. Best-effort: a Redis hiccup here must never
    // fail or slow down the actual request beyond `write_coalesce::incr`'s
    // own bounded timeout.
    let identity = match req.extensions().get::<ApiKeyIdentity>() {
        Some(key) => Identity::ApiKey(key.0),
        None => match req.extensions().get::<SessionClaims>() {
            Some(claims) => Identity::User(claims.sub),
            None => Identity::Anonymous,
        },
    };
    if let Some(matched) = matched
        && let Err(e) = api_usage::record(
            &state.redis_coordination,
            chrono::Utc::now().date_naive(),
            req.method().as_str(),
            matched,
            &identity,
        )
        .await
    {
        tracing::warn!(error = %e, "api usage analytics: record failed");
    }

    let (anonymous_rpm, authenticated_rpm) = cfg.limits_for(category);
    let limit = if is_authenticated {
        authenticated_rpm
    } else {
        anonymous_rpm
    };

    let key = format!("base:rl:{bucket}:{category}");
    match attome_cache::rate_limit::check(&state.redis_coordination, &key, limit as i32).await {
        Ok(outcome) if outcome.allowed => {
            let mut resp = next.run(req).await;
            apply_rate_limit_headers(resp.headers_mut(), outcome);
            resp
        }
        Ok(outcome) => {
            // P-observability-completion — SecurityAnomalyRateHigh alert
            // source; no-op if no recorder was ever installed.
            metrics::counter!("security_rejection_total", "reason" => "rate_limit").increment(1);
            let mut resp = AppError::TooManyRequests {
                retry_after_secs: Some(outcome.retry_after_secs),
            }
            .into_response();
            apply_rate_limit_headers(resp.headers_mut(), outcome);
            resp
        }
        Err(e) => e.into_response(),
    }
}

/// Coarse, IP-only rate limit that runs BEFORE `s2s_authn`/`authn` (unlike
/// `rate_limit` above, which runs after — see `apply_pre_auth_rate_limit` for
/// where this is layered). Closes an asymmetric-DoS gap: without this, a flood
/// of garbage JWTs or bad HMAC signatures burns crypto verification + a Redis
/// denylist/nonce lookup per request before `rate_limit` (keyed on
/// `SessionClaims`, which doesn't exist yet at this point in the pipeline)
/// ever gets a chance to reject it. No identity is available here by
/// definition, so this is IP-only regardless of the bypass list or
/// `SessionClaims`.
///
/// Deliberately NOT split by category or route (P-rate-limit-atomicity
/// §4.4, D-050 unchanged) — this layer's entire job is a blunt pre-crypto
/// backstop against a flood targeting *any* route, not a business-logic
/// limit; splitting it by route would let an attacker spread the same flood
/// across several routes/methods to multiply the effective ceiling this
/// layer is meant to cap in aggregate.
pub async fn pre_auth_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // BSV-F16: an IPv6 client is bucketed by its /64 (configurable).
    let ip = client_ip(&req, &state.config)
        .map(|ip| rate_limit_subject(ip, state.config.rate_limit.ipv6_bucket_prefix))
        .unwrap_or_else(|| "unknown".to_owned());
    let key = format!("base:rl:preauth-ip:{ip}");
    let limit = state.config.rate_limit.pre_auth_rpm;

    match attome_cache::rate_limit::check(&state.redis_coordination, &key, limit as i32).await {
        // Deliberately does NOT set X-RateLimit-*/Retry-After on the
        // passthrough path: this layer wraps *outside* `rate_limit` in the
        // pipeline, so by the time control returns here the inner layer has
        // already set its own (category-scoped, more meaningful) headers on
        // the response — overwriting them with this coarse backstop's own
        // numbers would silently clobber the real quota signal. Only set
        // headers when THIS layer is the one rejecting, since then no inner
        // response/headers exist yet to clobber.
        Ok(outcome) if outcome.allowed => next.run(req).await,
        Ok(outcome) => {
            let mut resp = AppError::TooManyRequests {
                retry_after_secs: Some(outcome.retry_after_secs),
            }
            .into_response();
            apply_rate_limit_headers(resp.headers_mut(), outcome);
            resp
        }
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_credential_routes_classify_correctly() {
        assert_eq!(category_for("POST", "/api/v1/auth/login"), "credential");
        assert_eq!(category_for("POST", "/api/v1/auth/register"), "credential");
        assert_eq!(
            category_for("GET", "/api/v1/auth/oidc/{provider}/callback"),
            "credential"
        );
    }

    #[test]
    fn known_mfa_and_reset_routes_classify_correctly() {
        assert_eq!(category_for("POST", "/api/v1/auth/mfa/verify"), "mfa");
        assert_eq!(category_for("POST", "/api/v1/auth/mfa/enroll"), "mfa");
        assert_eq!(category_for("POST", "/api/v1/auth/mfa/disable"), "mfa");
        assert_eq!(
            category_for("POST", "/api/v1/auth/mfa/recovery-codes/regenerate"),
            "mfa"
        );
        assert_eq!(
            category_for("POST", "/api/v1/auth/step-up/{operation}"),
            "mfa"
        );
        assert_eq!(
            category_for("POST", "/api/v1/auth/step-up/{operation}/verify"),
            "mfa"
        );
        assert_eq!(
            category_for("POST", "/api/v1/auth/step-up/{operation}/google"),
            "mfa"
        );
        assert_eq!(
            category_for("POST", "/api/v1/auth/reset-request"),
            "password_reset"
        );
        assert_eq!(
            category_for("POST", "/api/v1/auth/verify-email/confirm"),
            "password_reset"
        );
    }

    #[test]
    fn the_shared_mfa_bucket_keeps_the_login_time_key() {
        let user_id = Uuid::parse_str("0190c3a4-0000-7000-8000-000000000001").unwrap();
        assert_eq!(
            mfa_account_key(user_id),
            "server:rl:account:0190c3a4-0000-7000-8000-000000000001:mfa"
        );
    }

    /// Security contract §6: a per-account budget that cannot reach Redis
    /// rejects instead of admitting.
    #[tokio::test]
    async fn an_unreachable_redis_fails_the_account_budget_closed() {
        use fred::prelude::{Builder, RedisConfig};
        let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
        let pool = Builder::from_config(config).build_pool(1).unwrap();
        let result = enforce_account_budget(
            &pool,
            &mfa_account_key(Uuid::nil()),
            MFA_ATTEMPTS_PER_ACCOUNT_RPM,
            "test",
        )
        .await;
        assert!(
            result.is_err(),
            "an unreachable Redis must fail the budget closed"
        );
    }

    #[test]
    fn a_parameterized_route_classifies_by_template_not_concrete_path() {
        assert_eq!(
            category_for("POST", "/api/v1/query/execute"),
            "expensive_query"
        );
    }

    #[test]
    fn an_unlisted_method_or_route_falls_back_to_the_default_category() {
        assert_eq!(category_for("GET", "/api/v1/contact/{id}"), "api");
        // Same route, wrong method — must not accidentally match a
        // different (method, route) entry.
        assert_eq!(category_for("DELETE", "/api/v1/auth/login"), "api");
    }

    #[test]
    fn the_upload_session_route_classifies_as_presign_not_the_default() {
        assert_eq!(
            category_for("POST", "/api/v1/{entity}/{id}/files/{field}/upload-session"),
            "presign"
        );
        // A different files sub-route (finalize/status/download-url) must
        // not accidentally pick up the tighter presign budget — only
        // session creation itself hands out quarantine-storage capacity.
        assert_eq!(
            category_for(
                "POST",
                "/api/v1/{entity}/{id}/files/{field}/upload-session/{session_id}/finalize"
            ),
            "api"
        );
    }

    #[test]
    fn every_category_referenced_by_the_table_has_a_stable_name() {
        // Regression guard: a typo'd category name here silently falls back
        // to the top-level anonymous_rpm/authenticated_rpm at the config
        // layer (RateLimitSection::limits_for) rather than erroring — this
        // pins the exact set so a rename is a deliberate, reviewed edit.
        let mut categories: Vec<&str> = RATE_LIMIT_CATEGORIES
            .iter()
            .map(|(_, _, category)| *category)
            .collect();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(
            categories,
            [
                "consent_capture",
                "credential",
                "expensive_query",
                "mfa",
                "password_reset",
                "portal_status",
                "presign",
                "webchat",
            ]
        );
    }

    #[test]
    fn the_consent_capture_route_classifies_correctly() {
        assert_eq!(
            category_for("POST", "/api/v1/consents/capture"),
            "consent_capture"
        );
        // The authenticated withdraw endpoint is deliberately NOT in this
        // table — it requires a session/API key, so it gets the ordinary
        // blanket `api` budget like any other authenticated write.
        assert_eq!(category_for("POST", "/api/v1/consents/withdraw"), "api");
    }

    #[test]
    fn the_webchat_routes_classify_correctly() {
        assert_eq!(
            category_for("POST", "/api/v1/omnichannel/webchat/message"),
            "webchat"
        );
        assert_eq!(
            category_for("GET", "/api/v1/omnichannel/webchat/poll"),
            "webchat"
        );
        // The admin metrics surface (`xrm_server::omnichannel_metrics`)
        // requires a session/API key — it must not share the anonymous
        // widget's budget.
        assert_eq!(
            category_for("GET", "/api/v1/admin/omnichannel/metrics"),
            "api"
        );
    }

    #[test]
    fn the_portal_status_route_classifies_correctly() {
        assert_eq!(
            category_for("GET", "/api/v1/service-portal/status"),
            "portal_status"
        );
        // The public offerings list is deliberately NOT in this table — it
        // is anonymous browsing, not a credential-guessing surface, so it
        // gets the ordinary blanket `api` budget.
        assert_eq!(
            category_for("GET", "/api/v1/service-portal/offerings"),
            "api"
        );
    }
}
