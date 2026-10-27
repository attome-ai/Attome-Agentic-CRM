use attome_auth::{
    apikey_hash::{VerifyOutcome, dummy_hmac_hash, verify_api_key_secret},
    epoch,
    jwt::validate_session_token,
    revocation,
    session::{SessionClaims, TokenType},
};
use attome_types::AppError;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::net::IpAddr;
use uuid::Uuid;

use crate::{
    authz::AuthorizedContext,
    middleware::{bypass::is_bypass, ip_allowlist},
    state::AppState,
};

// ── Cookie auth ───────────────────────────────────────────────────────────────

fn extract_session_cookie(req: &Request, secure_cookies: bool) -> Option<String> {
    attome_auth::cookie::extract_session(req.headers(), secure_cookies)
}

// ── API key auth ──────────────────────────────────────────────────────────────

/// Parses `Authorization: ApiKey <pub>:<secret>` → `(public_key, secret)`.
fn extract_api_key(req: &Request) -> Option<(String, String)> {
    let value = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;

    let rest = value.strip_prefix("ApiKey ")?;
    let (pub_key, secret) = rest.split_once(':')?;
    Some((pub_key.to_owned(), secret.to_owned()))
}

/// M61 Phase 1 (API Management, D-438) — the api key's row id (`xrm_core_
/// apikey.id`), attached to request extensions only on the API-key auth
/// branch below (never the cookie-session branch), so a later middleware
/// (`rate_limit`'s per-route/per-key usage counter, `attome_server::api_usage`)
/// can attribute a request to the specific key that authenticated it.
/// `SessionClaims.sub` alone can't do this: the API-key branch synthesizes
/// `sub = user_id`, the key's *owning user*, not the key itself — two keys
/// held by the same user would otherwise be indistinguishable.
#[derive(Debug, Clone, Copy)]
pub struct ApiKeyIdentity(pub Uuid);

/// S10-T1: the authenticating key's own request budget per minute
/// (`api_key.requests_per_minute`), attached next to [`ApiKeyIdentity`] only
/// when the key has one; `rate_limit` enforces it across every route.
#[derive(Debug, Clone, Copy)]
pub struct ApiKeyQuota(pub u32);

/// Base-auth hardening 2.1b (D-510 rule 7) — attached only on the cookie-session
/// branch below, after the token and every check on it passed. It is what tells
/// a cookie session apart from an API-key or S2S caller, which never have a
/// refresh family and so can never step up. Read through
/// `crate::step_up::StepUpCaller`, never set anywhere else.
#[derive(Debug, Clone, Copy)]
pub struct CookieSession;

/// The `user_account` JOIN (P-account-state-enforcement, audit finding #2)
/// is what stops an API-key request from outliving the owning user's
/// disable — previously only `api_key.is_active`/`expires_at` were
/// checked, never the user row itself. `is_active IS NULL` is legacy-active
/// (D-005, matches `0024_partial_unique_soft_delete.sql`'s index predicate).
///
/// Returns `(user_id, key_id, quota)` — `key_id` exists only so `authn`
/// below can attach `ApiKeyIdentity` for usage analytics, and `quota` (S10-T1)
/// is the key's own per-minute budget; every check this function performs is
/// unchanged and still keyed on `user_id`/the row it resolves internally.
async fn resolve_api_key(
    state: &AppState,
    public_key: &str,
    secret: &str,
    caller_ip: Option<IpAddr>,
) -> Result<(Uuid, Uuid, Option<u32>), AppError> {
    /// id, user_ref, secret_hash, ip_allowlist, requests_per_minute.
    type KeyRow = (Uuid, Uuid, String, Option<Vec<String>>, Option<i32>);
    let row: Option<KeyRow> = sqlx::query_as(
        "SELECT k.id, k.user_ref, k.secret_hash, k.ip_allowlist, k.requests_per_minute
         FROM api_key k
         JOIN user_account u ON u.id = k.user_ref
             AND (u.is_active IS NULL OR u.is_active = TRUE)
         WHERE k.public_key = $1 AND k.is_active = true
           AND (k.expires_at IS NULL OR k.expires_at > NOW())",
    )
    .bind(public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;
    let ip_allowlist_for_key = row
        .as_ref()
        .and_then(|(_, _, _, allowlist, _)| allowlist.clone());
    let quota = row
        .as_ref()
        .and_then(|(_, _, _, _, rpm)| rpm.and_then(|n| u32::try_from(n).ok()))
        .filter(|n| *n > 0);
    let row = row.map(|(id, user_id, secret_hash, _, _)| (id, user_id, secret_hash));

    // P-api-key-hashing (D-112, revised): both the hit and miss paths run
    // through verify_api_key_secret so the cost/shape doesn't leak whether
    // public_key exists (timing/enumeration oracle) — the miss path verifies
    // against a fixed dummy hmac256:v0$ value. Built fresh per call — cheap (a
    // handful of string clones), not worth a dedicated AppState field.
    //
    // D-120: the pepper + previous-peppers come from state.secrets.load()
    // (config-sourced, D-549 — no live rotation without a restart) — same
    // pattern as xrm-s2s reading state.secrets.load().s2s_key_encryption_key.
    // apikey_hash_pepper_id stays on the cold AppConfig: it is structural
    // rotation state, not secret material.
    let ring = state.pepper_ring();
    let (key_id, user_id, stored_hash, outcome) = match row {
        Some((key_id, user_id, secret_hash)) => {
            let outcome = verify_api_key_secret(&ring, secret, &secret_hash).await?;
            if outcome == VerifyOutcome::Fail {
                return Err(AppError::Unauthorized);
            }
            (key_id, user_id, secret_hash, outcome)
        }
        None => {
            let _ = verify_api_key_secret(&ring, secret, dummy_hmac_hash()).await?;
            return Err(AppError::Unauthorized);
        }
    };

    // M03 gap 2 / D-434: the api-key-scoped IP allow-list is checked only
    // once the secret itself has verified — deliberately AFTER
    // `verify_api_key_secret` rather than right after the row lookup above,
    // so a caller who doesn't hold the real secret always sees the same
    // `Unauthorized` outcome/timing regardless of which IP they call from
    // (never leaking "this key exists and is IP-restricted" to someone
    // without the secret, preserving the hit/miss timing-equalization this
    // function already established, D-112). An absent/empty list means "no
    // restriction," unchanged from before this column existed.
    if let Some(allowlist) = &ip_allowlist_for_key
        && !allowlist.is_empty()
    {
        let allowed = caller_ip.is_some_and(|ip| ip_allowlist::ip_in_any(ip, allowlist));
        if !allowed {
            metrics::counter!("security_rejection_total", "reason" => "ip_not_allowed")
                .increment(1);
            tracing::warn!(
                public_key = %public_key,
                caller_ip = ?caller_ip,
                "auth: api-key request rejected — caller IP not in this key's allow-list"
            );
            return Err(AppError::Forbidden);
        }
    }

    // Rehash-on-successful-use: a legacy Argon2 row, or a row hashed under a
    // retired (non-current) pepper id, converges to the current hmac256:v{id}$
    // format the first time it's verified, no operator action needed. One
    // idempotent, guarded UPDATE — a lost race (rows_affected == 0, another
    // request beat this one to it) is harmless, the row already carries the
    // new hash.
    if outcome == VerifyOutcome::OkNeedsRehash {
        let new_hash = ring.hash(secret);
        if let Err(e) =
            sqlx::query("UPDATE api_key SET secret_hash = $1 WHERE id = $2 AND secret_hash = $3")
                .bind(&new_hash)
                .bind(key_id)
                .bind(&stored_hash)
                .execute(&state.db)
                .await
        {
            tracing::warn!("auth: failed to rehash api-key {key_id} to current pepper: {e}");
        }
    }

    // last_used_at touch (P-job-system-hardening (b), was the P1.4 durable
    // TouchApiKey queue job): coalesced into a Redis hash and periodically
    // bulk-flushed (`attome_server::apikey_touch`) rather than a Postgres queue
    // row per request — this value doesn't need replay-safe delivery, only
    // "eventually accurate to within one flush interval." Best-effort, same
    // as before: log and continue rather than fail the request over it.
    if let Err(e) =
        crate::apikey_touch::record_touch(&state.redis_coordination, key_id, Utc::now()).await
    {
        tracing::warn!("auth: failed to record api-key last_used touch: {e}");
    }

    Ok((user_id, key_id, quota))
}

/// Role-scoped IP allow-list for the cookie-session branch. A caller holding
/// no role with a restriction is unaffected; a caller holding at least one is
/// allowed only from an address in at least one such role's list (union across
/// restrictive roles: an unrestricted role never loosens a restricted one, but
/// two restricted roles' lists add up). The lists come from the security
/// resolver, uncached, so an edit applies to the next request.
async fn check_role_ip_allowlist(
    state: &AppState,
    user_id: Uuid,
    caller_ip: Option<IpAddr>,
) -> Result<(), AppError> {
    let lists = state.security.session_ip_allowlists(user_id).await?;
    check_ip_against_role_lists(user_id, caller_ip, &lists)
}

/// The decision behind [`check_role_ip_allowlist`], over lists already read.
/// An unknown caller address fails closed against any restriction.
fn check_ip_against_role_lists(
    user_id: Uuid,
    caller_ip: Option<IpAddr>,
    restrictive_lists: &[Vec<String>],
) -> Result<(), AppError> {
    let restrictive: Vec<&Vec<String>> = restrictive_lists
        .iter()
        .filter(|list| !list.is_empty())
        .collect();
    if restrictive.is_empty() {
        return Ok(());
    }
    let allowed = caller_ip.is_some_and(|ip| {
        restrictive
            .iter()
            .any(|list| ip_allowlist::ip_in_any(ip, list))
    });
    if !allowed {
        metrics::counter!("security_rejection_total", "reason" => "ip_not_allowed").increment(1);
        tracing::warn!(
            user_id = %user_id,
            caller_ip = ?caller_ip,
            "auth: session request rejected — caller IP not in any held role's allow-list"
        );
        return Err(AppError::Forbidden);
    }
    Ok(())
}

// ── Middleware ────────────────────────────────────────────────────────────────

/// Authenticates the request via:
/// 1. `session_token` JWT cookie (browser/web)
/// 2. `Authorization: ApiKey <pub>:<secret>` header (scripts/agents)
///
/// Bypass paths (auth endpoints, health) skip this check entirely.
pub async fn authn(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    if is_bypass(req.uri().path()) {
        return next.run(req).await;
    }

    // If SessionClaims already set (e.g. by xrm-s2s middleware upstream), skip
    if req.extensions().get::<SessionClaims>().is_some() {
        return next.run(req).await;
    }

    // M03 gap 2 / D-434: resolved once per request, consulted by both
    // branches below (role-based check on the cookie branch, key-based check
    // inside `resolve_api_key` on the api-key branch). `None` only when this
    // process wasn't served with `into_make_service_with_connect_info` (every
    // deployment profile is) — an allow-list-restricted identity fails closed
    // in that case, same posture as every other fail-closed check here.
    let caller_ip = crate::middleware::client_ip::client_ip(&req, &state.config);

    // ── Try JWT cookie first ──────────────────────────────────────────────────
    if let Some(token) = extract_session_cookie(&req, state.config.auth.secure_cookies) {
        match validate_session_token(
            &token,
            &state.secrets.load().jwt_secret,
            &state.config.auth.jwt_issuer,
            state.config.jwt_audience(),
        ) {
            Ok((claims, sid)) => {
                // Plan 1.6a: one Redis GET, fail-closed — a logged-out or
                // admin-revoked jti must never reach a handler even though its
                // exp hasn't naturally passed yet.
                //
                // BAU-9 / OD-1 (D-625): the **coordination** pool, matching the
                // two writers (`crates/server/src/auth/session.rs`,
                // `xrm-security/src/admin/sessions.rs`). The check is
                // fail-closed on a store *error*, but it cannot fail closed on
                // absence — so the pool it reads must be the one no eviction
                // policy or `FLUSHDB` is ever pointed at. The epoch check just
                // below deliberately stays on `state.redis`: a miss there
                // re-reads Postgres, so absence is safe.
                if revocation::is_revoked(
                    revocation::RevocationStore::choose(&state.redis_coordination, &state.db),
                    claims.jti,
                )
                .await
                {
                    // P-observability-completion — SecurityAnomalyRateHigh
                    // alert source; no-op if no recorder was ever installed.
                    metrics::counter!("security_rejection_total", "reason" => "revoked_token")
                        .increment(1);
                    return refuse(AppError::Unauthorized, "revoked_token");
                }
                // D-113 Phase 2 (wired D-121; P-session-refresh-hardening,
                // D-129): a disabled account's already-issued, not-yet-
                // expired access token must stop working within (at most)
                // the epoch cache's short TTL, not just once the refresh/
                // authz-cache paths eventually catch it. Uses `state.redis`
                // (not `redis_coordination`) — this is a per-request auth
                // check cache, the same class as the JWT denylist check
                // above, not S2S nonce/rate-limit/idempotency coordination
                // state (guidelines' Redis role split). Fail-closed on a
                // Redis error/timeout, same posture as the denylist check.
                // Not applied to the API-key branch below — that auth method
                // has its own is_active/expires_at gate on every request
                // already.
                if let Err(e) =
                    epoch::check(&state.redis, &state.db, claims.sub, claims.epoch).await
                {
                    metrics::counter!("security_rejection_total", "reason" => "epoch_stale")
                        .increment(1);
                    return refuse(e, "epoch_stale");
                }
                // M03 gap 2 / D-434: role-scoped IP allow-list, checked last
                // on this branch — after the token itself is already known
                // good — so a caller with a stale/invalid token still always
                // sees `Unauthorized`, never a `Forbidden` that would leak
                // "your token was fine, only your network wasn't."
                if let Err(e) = check_role_ip_allowlist(&state, claims.sub, caller_ip).await {
                    return refuse(e, "ip_not_allowed");
                }
                req.extensions_mut().insert(claims);
                // D-510 rule 7: marks a validated cookie session, the only
                // caller that can ever step up.
                req.extensions_mut().insert(CookieSession);
                // Q8-T3: a person's request (not a poller's) keeps the
                // session alive; buffered, flushed once a minute.
                if !crate::session_activity::is_background(req.headers())
                    && let Err(e) =
                        crate::session_activity::record(&state.redis, sid.0, Utc::now()).await
                {
                    tracing::debug!(error = %e, "session activity not recorded");
                }
                // D-510 rule 2: the refresh family this session belongs to,
                // taken only from the validated token. Never set on the
                // API-key or S2S paths, which have no refresh family.
                req.extensions_mut().insert(sid);
                return next.run(req).await;
            }
            Err(e) => return refuse(e, "invalid_session"),
        }
    }

    // ── Try API key header ────────────────────────────────────────────────────
    if let Some((pub_key, secret)) = extract_api_key(&req) {
        match resolve_api_key(&state, &pub_key, &secret, caller_ip).await {
            Ok((user_id, key_id, quota)) => {
                let now = Utc::now().timestamp();
                let claims = SessionClaims {
                    sub: user_id,
                    iat: now,
                    exp: now + 3600, // 1-hour synthetic session for this request
                    // Never persisted/denylisted — API-key auth is revoked via
                    // api_key.is_active, not the JWT denylist — so a fresh
                    // id per request is fine, nothing depends on it repeating.
                    jti: Uuid::now_v7(),
                    // Not epoch-checked (epoch::check only runs on the
                    // cookie-session branch above) — resolve_api_key already
                    // re-derives liveness from api_key.is_active/
                    // user_account.is_active fresh on every call, so there
                    // is no cached staleness for an epoch to correct here
                    // (D-113/D-121/D-129).
                    epoch: 0,
                    // Not a real JWT (never encoded/decoded, fabricated
                    // in-process to satisfy downstream extractors) — iss/aud
                    // are irrelevant since `jwt::validate_token`'s checks
                    // never run against this value (same reasoning as
                    // xrm-s2s's synthetic SessionClaims insert).
                    iss: state.config.auth.jwt_issuer.clone(),
                    aud: state.config.jwt_audience().to_string(),
                    typ: TokenType::Session,
                };
                req.extensions_mut().insert(claims);
                req.extensions_mut().insert(ApiKeyIdentity(key_id));
                if let Some(quota) = quota {
                    req.extensions_mut().insert(ApiKeyQuota(quota));
                }
                return next.run(req).await;
            }
            Err(e) => return refuse(e, "invalid_api_key"),
        }
    }

    refuse(AppError::Unauthorized, "no_credential")
}

/// Z5-T11: counts an authentication refusal in `http_rejections_total`
/// (`layer="auth"`) and answers it. A `Forbidden` is an IP allow-list
/// refusal whichever branch raised it; an error that is not a refusal at all
/// (a store outage) counts as `unavailable`.
fn refuse(error: AppError, reason: &'static str) -> Response {
    let reason = match &error {
        AppError::Forbidden => "ip_not_allowed",
        AppError::Unauthorized => reason,
        _ => "unavailable",
    };
    crate::metrics::record_rejection("auth", reason);
    error.into_response()
}

/// Resolves `SessionClaims.sub` into a `SecurityContext` (roles + privileges)
/// via the injected `xrm-security` resolver and attaches it as an extension.
///
/// The context is wrapped in [`AuthorizedContext`], whose inner field is
/// private, so `Extension<SecurityContext>` resolves to nothing and a handler's
/// only route to the caller's identity is `Authorized<P>` — an extractor that
/// runs `P::authorize` before it can be constructed (see `crate::authz`).
/// This middleware still only *resolves*; the authorization decision belongs to
/// the policy the handler names in its own signature.
pub async fn authz(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    if is_bypass(req.uri().path()) {
        return next.run(req).await;
    }

    let Some(claims) = req.extensions().get::<SessionClaims>().cloned() else {
        // authn runs before authz in the pipeline and always attaches claims
        // on a non-bypass path (or short-circuits with 401) — reaching here
        // without claims means the pipeline order was violated.
        return AppError::Unauthorized.into_response();
    };

    // Q13-T1: a view-as or act-as session runs the request as its subject.
    let requested = req
        .headers()
        .get(crate::impersonation::HEADER)
        .map(|v| v.to_str().map(str::to_owned).unwrap_or_default());
    let cookie_session = req.extensions().get::<CookieSession>().is_some();
    let (method, path) = (req.method().clone(), req.uri().path().to_owned());
    let session = match impersonation(requested, cookie_session, &method, &path, claims.sub).await {
        Ok(session) => session,
        Err(e) => return e.into_response(),
    };
    let user = session.as_ref().map_or(claims.sub, |s| s.subject_id);

    match state.security.resolve(user).await {
        Ok(ctx) => {
            if session.is_some() && (ctx.is_admin || ctx.service_principal) {
                // Never as an administrator or a machine identity; the start
                // route refuses this too, and the subject may have changed.
                return AppError::Forbidden.into_response();
            }
            // D-766: a delegated caller's entity ceiling narrows the context
            // before any handler or policy can read it.
            let ctx = AuthorizedContext::for_request(req.extensions(), ctx);
            // AA1-T5: `observability.server_timing = "admins"` reads this.
            attome_types::server_timing::note_admin(ctx.get().is_admin);
            req.extensions_mut().insert(ctx);
            match session {
                Some(session) => {
                    req.extensions_mut().insert(session.clone());
                    crate::impersonation::scope(session, next.run(req)).await
                }
                None => next.run(req).await,
            }
        }
        Err(e) => e.into_response(),
    }
}

/// Q13-T1: the live session the request names in
/// [`crate::impersonation::HEADER`], checked and logged, or `None` when it
/// names none. See [`crate::impersonation`] for the rules.
async fn impersonation(
    requested: Option<String>,
    cookie_session: bool,
    method: &axum::http::Method,
    path: &str,
    actor_id: Uuid,
) -> Result<Option<crate::impersonation::Impersonation>, AppError> {
    use crate::impersonation::{
        ImpersonationMode, MANAGEMENT_PREFIX, act_allows, store, view_allows,
    };
    let Some(raw) = requested else {
        return Ok(None);
    };
    if path.starts_with(MANAGEMENT_PREFIX) {
        return Ok(None);
    }
    // A browser session only: an API key or a machine never impersonates.
    if !cookie_session {
        return Err(AppError::Forbidden);
    }
    // An unknown or ended session is its own answer, not a 401: the client
    // must not read it as an expired sign-in and refresh.
    let ended =
        || AppError::Validation("impersonation_ended: the impersonation session has ended".into());
    let session_id = Uuid::parse_str(raw.trim()).map_err(|_| ended())?;
    let store = store().ok_or(AppError::Forbidden)?;
    let session = store
        .active(session_id, actor_id)
        .await?
        .filter(|s| s.expires_at > Utc::now())
        .ok_or_else(ended)?;
    let allowed = match session.mode {
        ImpersonationMode::View => view_allows(method, path),
        ImpersonationMode::Act => act_allows(path),
    };
    if !allowed {
        return Err(AppError::Validation(match session.mode {
            ImpersonationMode::View => {
                "impersonation_read_only: viewing as someone changes nothing".into()
            }
            ImpersonationMode::Act => {
                "impersonation_refused: this is never done as someone else".into()
            }
        }));
    }
    store.log_request(&session, method.as_str(), path).await?;
    Ok(Some(session))
}

/// P-account-lifecycle: `resolve_api_key` is private to this module, so its
/// DB-backed test lives here (a child module can see a parent module's
/// private items) rather than in `tests/`, which only sees the public API.
///
/// These tests need PostgreSQL and Redis. They run on attome-testkit's
/// migrated throwaway database and skip without `DATABASE_URL`:
///
/// ```powershell
/// $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5432/postgres"
/// cargo test -p attome-server --lib middleware::auth::db_tests
/// ```
#[cfg(test)]
mod db_tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use rand::distributions::{Alphanumeric, DistString};

    use attome_testkit::migrated_pool_or_skip;

    /// A pool on the migrated test database, or a SKIP. Three connections:
    /// these tests never race a pool.
    macro_rules! db_pool {
        ($n:expr) => {{ migrated_pool_or_skip!($n) }};
    }

    fn test_config() -> attome_config::AppConfig {
        let json = format!(
            r#"{{
                "app": {{
                    "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                    "frontend_port": 4200, "log_level": "error", "threads": 1,
                    "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                    "enable_session": true, "max_connection_num": 64,
                    "max_connection_num_per_ip": 16, "use_gzip": false,
                    "enable_compression": false, "gzip_level": 1, "br_level": 1,
                    "idle_connection_timeout": 30, "keepalive_requests": 100,
                    "static_files_cache_time": 0, "server_header_field": "attome-test"
                }},
                "database": {{
                    "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                    "user": "unused", "password": "unused", "schema": "public",
                    "connection_number": 5, "timeout": 5.0
                }},
                "cache": {{
                    "host": "{redis_host}", "port": {redis_port}, "password": "",
                    "db": 0, "connection_pool_size": 4, "timeout": 2000,
                    "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                    "metadata_registry_enabled": true
                }},
                "storage": {{
                    "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                    "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                    "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
                }},
                "auth": {{
                    "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "attome-test",
                    "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
                }},
                "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
                "observability": {{
                    "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                    "enable_distributed_tracing": false
                }},
                "email": {{
                    "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                    "smtp_password": "", "smtp_from_address": "test@test.local",
                    "smtp_from_name": "test", "smtp_use_tls": false,
                    "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
                }},
                "google_ai": {{
                    "api_key": "", "base_url": "https://example.invalid",
                    "default_model": "none", "timeout_seconds": 1
                }}
            }}"#,
            redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
            redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        );
        attome_testkit::with_test_database(
            serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
            true,
        )
    }

    async fn test_state(db: attome_db::DbPool) -> AppState {
        let config = test_config();
        let redis = attome_cache::create_redis_pool(&config)
            .await
            .expect("connect redis");
        let redis_coordination = attome_cache::create_role_redis_pool(
            &config,
            attome_cache::CacheRole::Coordination,
            &redis,
        )
        .await
        .expect("connect coordination redis");
        let storage = attome_storage::create_storage_client(&config)
            .await
            .expect("build storage client");

        AppState::new(
            config,
            db.clone(),
            db.clone(),
            db,
            redis,
            redis_coordination,
            storage,
        )
    }

    const TEST_PEPPER: &str = "test-only-throwaway-pepper-32-bytes-min";

    /// Inserts a throwaway user row, returning its id.
    async fn create_test_user(db: &attome_db::DbPool) -> Uuid {
        let user_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_account (id, email, created_at, is_active)
             VALUES ($1, $2, now(), true)",
        )
        .bind(user_id)
        .bind(format!("apikey-expiry-test-{user_id}@example.invalid"))
        .execute(db)
        .await
        .expect("insert test user");
        user_id
    }

    /// Inserts a throwaway user + an HMAC-hashed api-key row with an optional
    /// expiry, returning (public_key, secret).
    async fn create_test_api_key(
        db: &attome_db::DbPool,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> (String, String) {
        let user_id = create_test_user(db).await;

        let public_key = format!(
            "atk_pub_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
        );
        let secret = format!(
            "atk_sec_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
        );
        let secret_hash = attome_auth::PepperRing::new(0, TEST_PEPPER, &[]).hash(&secret);

        sqlx::query(
            "INSERT INTO api_key (user_ref, name, public_key, secret_hash, expires_at)
             VALUES ($1, 'expiry-test-key', $2, $3, $4)",
        )
        .bind(user_id)
        .bind(&public_key)
        .bind(&secret_hash)
        .bind(expires_at)
        .execute(db)
        .await
        .expect("insert test api key");

        (public_key, secret)
    }

    /// A non-expiring key in the HMAC format every newly-created key gets
    /// (`xrm_security::api_keys::create_api_key`). `test_config`'s
    /// `auth` block leaves `apikey_hash_pepper_id` at 0, matching
    /// `TEST_PEPPER`'s use here as pepper id 0, so this writes what
    /// `resolve_api_key`'s own ring would produce against the same config.
    async fn create_test_hmac_api_key(db: &attome_db::DbPool) -> (String, String) {
        let user_id = create_test_user(db).await;

        let public_key = format!(
            "atk_pub_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
        );
        let secret = format!(
            "atk_sec_{}",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
        );
        let ring = attome_auth::PepperRing::new(0, TEST_PEPPER, &[]);
        let secret_hash = ring.hash(&secret);

        sqlx::query(
            "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
             VALUES ($1, 'hmac-test-key', $2, $3)",
        )
        .bind(user_id)
        .bind(&public_key)
        .bind(&secret_hash)
        .execute(db)
        .await
        .expect("insert test api key");

        (public_key, secret)
    }

    #[tokio::test]
    async fn a_key_with_no_expiry_is_accepted() {
        let db = db_pool!(3);
        let (public_key, secret) = create_test_api_key(&db, None).await;
        let state = test_state(db).await;

        let result = resolve_api_key(&state, &public_key, &secret, None).await;
        assert!(
            result.is_ok(),
            "a key with no expiry must be accepted: {result:?}"
        );
    }

    #[tokio::test]
    async fn an_expired_key_is_rejected() {
        let db = db_pool!(3);
        let expired = Utc::now() - ChronoDuration::days(1);
        let (public_key, secret) = create_test_api_key(&db, Some(expired)).await;
        let state = test_state(db).await;

        let result = resolve_api_key(&state, &public_key, &secret, None).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn a_not_yet_expired_key_is_accepted() {
        let db = db_pool!(3);
        let future = Utc::now() + ChronoDuration::days(1);
        let (public_key, secret) = create_test_api_key(&db, Some(future)).await;
        let state = test_state(db).await;

        let result = resolve_api_key(&state, &public_key, &secret, None).await;
        assert!(
            result.is_ok(),
            "a not-yet-expired key must be accepted: {result:?}"
        );
    }

    /// P-account-state-enforcement (audit finding #2): a disabled user's
    /// still-active, still-unexpired API key must be rejected — previously
    /// only `api_key.is_active`/`expires_at` gated this lookup, never the
    /// owning user's `is_active`.
    #[tokio::test]
    async fn a_key_owned_by_a_disabled_user_is_rejected() {
        let db = db_pool!(3);
        let (public_key, secret) = create_test_api_key(&db, None).await;
        let user_id: Uuid =
            sqlx::query_scalar("SELECT user_ref FROM api_key WHERE public_key = $1")
                .bind(&public_key)
                .fetch_one(&db)
                .await
                .expect("fetch owning user_id");
        sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
            .bind(user_id)
            .execute(&db)
            .await
            .expect("disable the owning user");
        let state = test_state(db).await;

        let result = resolve_api_key(&state, &public_key, &secret, None).await;
        assert!(
            matches!(result, Err(AppError::Unauthorized)),
            "a key owned by a disabled user must be rejected, got {result:?}"
        );
    }

    /// A key created via the current HMAC scheme authenticates, and a wrong
    /// secret against it is rejected.
    #[tokio::test]
    async fn a_new_hmac_key_authenticates_and_wrong_secret_is_rejected() {
        let db = db_pool!(3);
        let (public_key, secret) = create_test_hmac_api_key(&db).await;
        let state = test_state(db).await;

        let ok = resolve_api_key(&state, &public_key, &secret, None).await;
        assert!(ok.is_ok(), "a valid hmac256$ key must authenticate: {ok:?}");

        let bad = resolve_api_key(&state, &public_key, "not-the-secret", None).await;
        assert!(matches!(bad, Err(AppError::Unauthorized)));
    }

    // ── M03 gap 2 / D-434: IP allow-list ────────────────────────────────────

    /// Baseline: a key with no `ip_allowlist` set (the default, and the
    /// state of every key created before this column existed) is accepted
    /// from any caller IP, or from none at all (`caller_ip: None`).
    #[tokio::test]
    async fn a_key_with_no_ip_allowlist_is_accepted_from_any_ip() {
        let db = db_pool!(3);
        let (public_key, secret) = create_test_hmac_api_key(&db).await;
        let state = test_state(db).await;

        let result = resolve_api_key(
            &state,
            &public_key,
            &secret,
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "unrestricted key must accept any IP: {result:?}"
        );
    }

    /// Negative path: a key restricted to a CIDR that does not cover the
    /// caller's IP is rejected `Forbidden` even though the secret is
    /// correct — a wrong-network valid credential must not authenticate.
    #[tokio::test]
    async fn a_key_with_an_ip_allowlist_rejects_a_disallowed_caller_ip() {
        let db = db_pool!(3);
        let (public_key, secret) = create_test_hmac_api_key(&db).await;
        sqlx::query("UPDATE api_key SET ip_allowlist = $1 WHERE public_key = $2")
            .bind(vec!["10.0.0.0/8".to_string()])
            .bind(&public_key)
            .execute(&db)
            .await
            .expect("set ip_allowlist");
        let state = test_state(db).await;

        let result = resolve_api_key(
            &state,
            &public_key,
            &secret,
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Forbidden)),
            "a disallowed caller IP must be rejected Forbidden, got {result:?}"
        );
    }

    /// A caller IP that DOES fall inside the key's allow-list still
    /// authenticates normally.
    #[tokio::test]
    async fn a_key_with_an_ip_allowlist_accepts_an_allowed_caller_ip() {
        let db = db_pool!(3);
        let (public_key, secret) = create_test_hmac_api_key(&db).await;
        sqlx::query("UPDATE api_key SET ip_allowlist = $1 WHERE public_key = $2")
            .bind(vec!["10.0.0.0/8".to_string()])
            .bind(&public_key)
            .execute(&db)
            .await
            .expect("set ip_allowlist");
        let state = test_state(db).await;

        let result = resolve_api_key(
            &state,
            &public_key,
            &secret,
            Some("10.1.2.3".parse().unwrap()),
        )
        .await;
        assert!(
            result.is_ok(),
            "an allowed caller IP must authenticate: {result:?}"
        );
    }

    /// A wrong secret against an IP-restricted key still surfaces as the
    /// same `Unauthorized` a wrong secret against an unrestricted key would
    /// — the IP check must never run (or leak anything) before the secret
    /// itself has verified.
    #[tokio::test]
    async fn a_wrong_secret_against_an_ip_restricted_key_is_unauthorized_not_forbidden() {
        let db = db_pool!(3);
        let (public_key, _secret) = create_test_hmac_api_key(&db).await;
        sqlx::query("UPDATE api_key SET ip_allowlist = $1 WHERE public_key = $2")
            .bind(vec!["10.0.0.0/8".to_string()])
            .bind(&public_key)
            .execute(&db)
            .await
            .expect("set ip_allowlist");
        let state = test_state(db).await;

        let result = resolve_api_key(
            &state,
            &public_key,
            "definitely-not-the-secret",
            Some("203.0.113.9".parse().unwrap()),
        )
        .await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    fn ip(addr: &str) -> Option<IpAddr> {
        addr.parse().ok()
    }

    #[test]
    fn role_ip_check_allows_a_user_with_no_restrictive_roles() {
        let user = Uuid::now_v7();
        assert!(check_ip_against_role_lists(user, ip("203.0.113.9"), &[]).is_ok());
        assert!(check_ip_against_role_lists(user, ip("203.0.113.9"), &[Vec::new()]).is_ok());
    }

    #[test]
    fn role_ip_check_rejects_a_disallowed_ip_for_a_restricted_role() {
        let lists = vec![vec!["10.0.0.0/8".to_owned()]];
        let result = check_ip_against_role_lists(Uuid::now_v7(), ip("203.0.113.9"), &lists);
        assert!(matches!(result, Err(AppError::Forbidden)), "got {result:?}");
    }

    #[test]
    fn role_ip_check_accepts_an_allowed_ip_for_a_restricted_role() {
        let lists = vec![vec!["10.0.0.0/8".to_owned()]];
        assert!(check_ip_against_role_lists(Uuid::now_v7(), ip("10.4.5.6"), &lists).is_ok());
    }

    #[test]
    fn role_ip_check_unions_the_lists_of_restrictive_roles() {
        let lists = vec![
            vec!["10.0.0.0/8".to_owned()],
            vec!["192.168.1.0/24".to_owned()],
        ];
        assert!(check_ip_against_role_lists(Uuid::now_v7(), ip("192.168.1.7"), &lists).is_ok());
    }

    /// An address the server could not resolve (no `ConnectInfo`) fails
    /// closed against a restricted role, never counts as allowed.
    #[test]
    fn role_ip_check_fails_closed_when_caller_ip_is_unknown() {
        let lists = vec![vec!["10.0.0.0/8".to_owned()]];
        let result = check_ip_against_role_lists(Uuid::now_v7(), None, &lists);
        assert!(matches!(result, Err(AppError::Forbidden)));
    }
}

#[cfg(test)]
mod extract_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    fn request_with_auth_header(value: Option<&str>) -> Request {
        let mut builder = HttpRequest::builder().uri("/");
        if let Some(v) = value {
            builder = builder.header(axum::http::header::AUTHORIZATION, v);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn extract_api_key_parses_a_well_formed_header() {
        let req = request_with_auth_header(Some("ApiKey abc123:secretvalue"));
        assert_eq!(
            extract_api_key(&req),
            Some(("abc123".to_owned(), "secretvalue".to_owned()))
        );
    }

    #[test]
    fn extract_api_key_is_none_without_the_apikey_prefix() {
        let req = request_with_auth_header(Some("Bearer abc123:secretvalue"));
        assert_eq!(extract_api_key(&req), None);
    }

    #[test]
    fn extract_api_key_is_none_without_a_colon_separator() {
        let req = request_with_auth_header(Some("ApiKey abc123secretvalue"));
        assert_eq!(extract_api_key(&req), None);
    }

    #[test]
    fn extract_api_key_is_none_when_the_header_is_absent() {
        let req = request_with_auth_header(None);
        assert_eq!(extract_api_key(&req), None);
    }

    #[test]
    fn extract_api_key_splits_on_the_first_colon_only() {
        // A secret containing a colon must stay intact in the second half.
        let req = request_with_auth_header(Some("ApiKey pub:sec:ret"));
        assert_eq!(
            extract_api_key(&req),
            Some(("pub".to_owned(), "sec:ret".to_owned()))
        );
    }
}
