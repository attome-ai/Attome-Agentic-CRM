use attome_auth::session::SessionClaims;
use attome_cache::Store;
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
    // E26-T1: anonymous, token-guessing class like the capture.
    ("GET", "/api/v1/consents/preferences", "consent_capture"),
    ("POST", "/api/v1/consents/preferences", "consent_capture"),
    ("GET", "/api/v1/consents/confirm", "consent_capture"),
    // D16-T1: anonymous, token-carrying like the portal status.
    ("GET", "/api/v1/track/open/{token}", "portal_status"),
    ("GET", "/api/v1/track/click/{token}", "portal_status"),
    // J4-T1: SMS delivery receipts from the providers.
    ("POST", "/api/v1/sms/receipts/{token}", "portal_status"),
    ("POST", "/api/v1/consents/confirm", "consent_capture"),
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
    // K1-T1: anonymous, token-guessing class like `portal_status`; the
    // password POST also checks a person-chosen secret.
    ("GET", "/api/v1/shared-files/{token}", "portal_status"),
    ("POST", "/api/v1/shared-files/{token}", "password_reset"),
    ("GET", "/api/v1/omnichannel/webchat/poll", "webchat"),
    // J3-T1: the same widget, as a live stream.
    ("GET", "/api/v1/omnichannel/webchat/stream", "webchat"),
    // J9-T2: the customer's side of co-browse, anonymous like web chat.
    ("POST", "/api/v1/cobrowse/join", "portal_status"),
    ("GET", "/api/v1/cobrowse/visitor/messages", "webchat"),
    ("POST", "/api/v1/cobrowse/visitor/messages", "webchat"),
    ("POST", "/api/v1/cobrowse/visitor/end", "webchat"),
];
pub(crate) const DEFAULT_CATEGORY: &str = "api";

/// The rate-limit category of `method` on `route_template`: its
/// `RATE_LIMIT_CATEGORIES` entry, else `api`. Q20-T1: the API document
/// declares the same value as each operation's `x-rate-class`.
pub fn category_for(method: &str, route_template: &str) -> &'static str {
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
fn apply_rate_limit_headers(headers: &mut HeaderMap, outcome: RateLimitOutcome, policy: &str) {
    apply_ietf_headers(headers, outcome, policy);
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

/// Q20-T4: the IETF `RateLimit-Policy` / `RateLimit` pair
/// (draft-ietf-httpapi-ratelimit-headers) beside the older `X-RateLimit-*`
/// set: the policy names the category, its quota and its 60-second window;
/// `RateLimit` carries what is left and when the window frees up.
fn apply_ietf_headers(headers: &mut HeaderMap, outcome: RateLimitOutcome, policy: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{policy}\";q={};w=60", outcome.limit)) {
        headers.insert("ratelimit-policy", value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!(
        "\"{policy}\";r={};t={}",
        outcome.remaining, outcome.retry_after_secs
    )) {
        headers.insert("ratelimit", value);
    }
}

/// Q20-T4: a caller (a user, or an address when anonymous) that trips a
/// limit in this many separate windows within [`TRIP_MEMORY`] is refused
/// outright for [`BAN_DURATION`]. Only the first refusal of a window counts,
/// so one burst is one trip, not one per refused request. Constants, like the
/// MFA budget below: a threshold a deployment could raise is one a
/// misconfiguration could disable.
pub const BAN_AFTER_TRIPPED_WINDOWS: i64 = 5;
/// How long tripped windows are remembered toward a ban.
pub const TRIP_MEMORY: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// How long a temporary ban lasts.
pub const BAN_DURATION: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// Every bucket banned since the set was last read, for the admin screen
/// (Q20-T5); a member whose ban key has expired is no longer banned.
pub const BANNED_SET: &str = "base:rl:banned";

/// The key holding `bucket`'s ban (`user:{id}` or `ip:{address}`); its value
/// is the category that tripped last, its TTL what remains of the ban.
pub fn ban_key(bucket: &str) -> String {
    attome_cache::rate_limit::storage_key(&format!("base:rl:ban:{bucket}"))
}

/// Seconds left on `bucket`'s ban, or `None` when it is not banned.
pub async fn active_ban(redis: &Store, bucket: &str) -> Result<Option<u64>, AppError> {
    Ok(redis
        .ttl_secs(ban_key(bucket))
        .await?
        .map(|left| left.max(1) as u64))
}

/// Q20-T5: one active temporary ban.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct ActiveBan {
    /// `user:{id}` or `ip:{address}`.
    pub bucket: String,
    /// The limit category that tripped last.
    pub category: Option<String>,
    pub seconds_left: u64,
}

/// Q20-T5: every ban still in force; members whose ban ran out are dropped
/// from the set as they are found.
pub async fn list_bans(redis: &Store) -> Result<Vec<ActiveBan>, AppError> {
    let mut out = Vec::new();
    let mut members: Vec<String> = redis.smembers(BANNED_SET).await?.into_iter().collect();
    members.sort();
    for bucket in members {
        match active_ban(redis, &bucket).await? {
            Some(seconds_left) => {
                let category = redis.get(ban_key(&bucket)).await?;
                out.push(ActiveBan {
                    bucket,
                    category,
                    seconds_left,
                });
            }
            None => {
                redis.srem(BANNED_SET, &bucket).await?;
            }
        }
    }
    Ok(out)
}

/// Q20-T5: lifts `bucket`'s ban and forgets its tripped windows; `false`
/// when it was not banned.
pub async fn lift_ban(redis: &Store, bucket: &str) -> Result<bool, AppError> {
    let was = active_ban(redis, bucket).await?.is_some();
    redis.del(ban_key(bucket)).await?;
    redis
        .del(attome_cache::rate_limit::storage_key(&format!(
            "base:rl:trips:{bucket}"
        )))
        .await?;
    redis.srem(BANNED_SET, bucket).await?;
    Ok(was)
}

/// Counts a refused request toward a ban (see [`BAN_AFTER_TRIPPED_WINDOWS`]).
/// Best-effort: the refusal itself already happened, so a store failure here
/// is logged and changes nothing the caller sees.
async fn note_trip(redis: &Store, bucket: &str, category: &str, retry_after_secs: u64) {
    let result: Result<(), AppError> = async {
        let window =
            attome_cache::rate_limit::storage_key(&format!("base:rl:tripped:{bucket}:{category}"));
        let ttl = std::time::Duration::from_secs(retry_after_secs.max(1));
        if !redis.set_nx(&window, "1", Some(ttl)).await? {
            return Ok(());
        }
        let trips_key = attome_cache::rate_limit::storage_key(&format!("base:rl:trips:{bucket}"));
        let trips = redis.incr_with_ttl(&trips_key, TRIP_MEMORY).await?;
        if trips >= BAN_AFTER_TRIPPED_WINDOWS {
            redis
                .set(ban_key(bucket), category, Some(BAN_DURATION))
                .await?;
            redis.del(&trips_key).await?;
            redis.sadd(BANNED_SET, bucket).await?;
            metrics::counter!("security_rejection_total", "reason" => "temporary_ban").increment(1);
            tracing::warn!(
                bucket,
                category,
                ban_secs = BAN_DURATION.as_secs(),
                "rate limit: temporary ban after repeated limit trips"
            );
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, bucket, "rate limit: trip not counted toward a ban");
    }
}

/// AA9-T5: the caller as `limit_usage` counts it.
fn principal(identity: &Identity) -> (&'static str, Option<uuid::Uuid>) {
    match identity {
        Identity::ApiKey(id) => ("api_key", Some(*id)),
        Identity::User(id) => ("user", Some(*id)),
        Identity::Anonymous => ("anonymous", None),
    }
}

/// The 429 a banned caller gets: no handler runs, and `Retry-After` is what
/// is left of the ban.
fn banned_response(layer: &'static str, left_secs: u64) -> Response {
    crate::metrics::record_rejection(layer, "temporary_ban");
    let mut resp = AppError::TooManyRequests {
        retry_after_secs: Some(left_secs),
    }
    .into_response();
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::RETRY_AFTER,
        header_value_from_u64(left_secs),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("\"ban\";r=0;t={left_secs}")) {
        headers.insert("ratelimit", value);
    }
    resp
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
    redis: &Store,
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
    crate::metrics::record_rejection("rate_limit", "account_budget");
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

    // Q20-T4: a banned caller is refused before its budget is even read.
    // Fails closed on a store error, like the budget check itself.
    match active_ban(&state.redis_coordination, &bucket).await {
        Ok(Some(left)) => return banned_response("rate_limit", left),
        Ok(None) => {}
        Err(e) => return e.into_response(),
    }

    let key = format!("base:rl:{bucket}:{category}");
    let (principal_kind, principal_id) = principal(&identity);
    match attome_cache::rate_limit::check(&state.redis_coordination, &key, limit as i32).await {
        Ok(outcome) if outcome.allowed => {
            // AA9-T7: a signed-in caller past half its minute's budget is
            // noted, so the daily check can warn before anyone is refused.
            let used = outcome.limit.saturating_sub(outcome.remaining);
            if is_authenticated && used.saturating_mul(2) >= outcome.limit {
                crate::limit_usage::record_limit_use(
                    &format!("rate_limit.{category}"),
                    principal_kind,
                    principal_id,
                    i64::from(used),
                );
            }
            let mut resp = next.run(req).await;
            // AA9-T5: a limit the handler refused at, counted for this caller.
            if let Some(hit) = resp.extensions().get::<crate::limit_usage::LimitHit>() {
                crate::limit_usage::record_limit_hit(
                    hit.limit,
                    principal_kind,
                    principal_id,
                    hit.value,
                );
            }
            apply_rate_limit_headers(resp.headers_mut(), outcome, category);
            resp
        }
        Ok(outcome) => {
            // P-observability-completion — SecurityAnomalyRateHigh alert
            // source; no-op if no recorder was ever installed.
            metrics::counter!("security_rejection_total", "reason" => "rate_limit").increment(1);
            crate::metrics::record_rejection("rate_limit", "limit");
            crate::limit_usage::record_limit_hit(
                &format!("rate_limit.{category}"),
                principal_kind,
                principal_id,
                i64::from(outcome.limit),
            );
            note_trip(
                &state.redis_coordination,
                &bucket,
                category,
                outcome.retry_after_secs,
            )
            .await;
            let mut resp = AppError::TooManyRequests {
                retry_after_secs: Some(outcome.retry_after_secs),
            }
            .into_response();
            apply_rate_limit_headers(resp.headers_mut(), outcome, category);
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
    // Q20-T4: the same address bucket the category middleware bans.
    let bucket = format!("ip:{ip}");
    match active_ban(&state.redis_coordination, &bucket).await {
        Ok(Some(left)) => return banned_response("pre_auth_rate_limit", left),
        Ok(None) => {}
        Err(e) => return e.into_response(),
    }
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
            crate::limit_usage::record_limit_hit("rate_limit.pre_auth", "anonymous", None, 0);
            crate::metrics::record_rejection("pre_auth_rate_limit", "limit");
            note_trip(
                &state.redis_coordination,
                &bucket,
                "pre_auth",
                outcome.retry_after_secs,
            )
            .await;
            let mut resp = AppError::TooManyRequests {
                retry_after_secs: Some(outcome.retry_after_secs),
            }
            .into_response();
            apply_rate_limit_headers(resp.headers_mut(), outcome, "pre_auth");
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
            &attome_cache::Store::Redis(pool.clone()),
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

    /// Q20-T4: one burst is one trip however many requests it refuses;
    /// trips in five separate windows ban the caller, and the ban's 429
    /// carries what is left of it.
    #[tokio::test]
    async fn repeated_trips_in_separate_windows_ban_the_caller() {
        let store = attome_cache::Store::memory();
        let bucket = format!("ip:test-{}", Uuid::now_v7());
        for _ in 0..10 {
            note_trip(&store, &bucket, "api", 30).await;
        }
        assert_eq!(active_ban(&store, &bucket).await.unwrap(), None);
        for category in ["credential", "mfa", "presign", "webchat"] {
            note_trip(&store, &bucket, category, 30).await;
        }
        let left = active_ban(&store, &bucket)
            .await
            .unwrap()
            .expect("five tripped windows ban the caller");
        assert!(left > 0 && left <= BAN_DURATION.as_secs(), "{left}");
        let other = format!("ip:test-{}", Uuid::now_v7());
        assert_eq!(active_ban(&store, &other).await.unwrap(), None);

        let resp = banned_response("rate_limit", left);
        assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("retry-after").unwrap(),
            left.to_string().as_str()
        );
        assert_eq!(
            resp.headers().get("ratelimit").unwrap(),
            format!("\"ban\";r=0;t={left}").as_str()
        );
    }

    /// Q20-T4: the IETF pair names the category, its quota and window, and
    /// what is left.
    #[test]
    fn ietf_rate_limit_headers_name_the_policy() {
        let mut headers = HeaderMap::new();
        let outcome = RateLimitOutcome {
            allowed: false,
            limit: 10,
            remaining: 0,
            retry_after_secs: 42,
            reset_unix: 0,
        };
        apply_rate_limit_headers(&mut headers, outcome, "credential");
        assert_eq!(
            headers.get("ratelimit-policy").unwrap(),
            "\"credential\";q=10;w=60"
        );
        assert_eq!(headers.get("ratelimit").unwrap(), "\"credential\";r=0;t=42");
        assert_eq!(headers.get("retry-after").unwrap(), "42");
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
        assert_eq!(
            category_for("GET", "/api/v1/omnichannel/webchat/stream"),
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
