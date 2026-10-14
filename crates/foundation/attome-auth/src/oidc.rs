//! Generic OIDC authorization-code + PKCE flow (P2.8, D-065). Backs
//! `GET /api/v1/auth/oidc/{provider}/login|callback`. Providers are
//! config-driven (`AppConfig.oidc.providers`, D-065) — this module never
//! touches `user_account`; the caller (website route wiring) hands the
//! verified [`OidcIdentity`] to `xrm_security::accounts::link_oidc_identity`,
//! same split as the existing Google flow (`accounts::verify_google_id_token`
//! / `xrm_security::accounts::link_google_account`).
//!
//! Redis keys (guidelines §5 `{crate}:{purpose}:{id}` shape):
//! - `oidc:state:{state_id}` — single-use PKCE verifier + nonce, TTL 300s.
//! - `oidc:discovery:{provider_key}` — cached `.well-known/openid-configuration`, TTL 1h.
//! - `oidc:jwks:{provider_key}` — cached JWKS document, TTL 1h.
//! - `oidc:jwks-refetch:{provider_key}` — single-flight gate for refetching
//!   the JWKS when a token names an unknown `kid`, TTL 60s.
//!
//! Cache-vs-security-control split (D-027): a Redis miss/error on discovery
//! or JWKS falls back to a live HTTPS fetch (degrade-and-recover — these are
//! just caches). Signature verification itself fails closed: if no JWKS can
//! be obtained from cache OR a live fetch, or the signature/claims don't
//! check out, the login is rejected — never treated as "skip verification."

use std::time::Duration;

use attome_cache::Store;
use attome_config::OidcProviderConfig;
use attome_types::AppError;
use fred::prelude::*;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};

const REDIS_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const STATE_TTL_SECS: i64 = 300;
const DISCOVERY_CACHE_TTL_SECS: i64 = 3600;
const JWKS_CACHE_TTL_SECS: i64 = 3600;
/// At most one unknown-`kid` refetch per provider per window (plan 1.7).
const JWKS_REFETCH_GATE_SECS: i64 = 60;
/// BAU-6 (finding BAU-F3) — outbound response size caps. A discovery document
/// and a JWKS are small JSON documents; a token response is a couple of tokens.
/// Anything larger is a hostile or broken endpoint, not a document to buffer.
const DISCOVERY_MAX_BYTES: usize = 256 * 1024;
const JWKS_MAX_BYTES: usize = 256 * 1024;
const TOKEN_RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// One process-lifetime client shared by both outbound call sites below.
///
/// `reqwest::Client` owns the connection pool and the TLS session cache, and
/// is designed to be created once and cloned; building a fresh one per call
/// (as this module used to) threw both away every time, so every discovery,
/// JWKS fetch, and token exchange paid a new TCP connect plus a full TLS
/// handshake against the IdP. These run on the login path, where that
/// latency is directly user-visible.
///
/// `connect_timeout` is belt-and-braces alongside the `tokio::time::timeout`
/// each call site already wraps `send()` in: the outer timeout bounds the
/// whole request, this one fails a dead IdP host fast instead of letting it
/// consume the entire budget in the connect phase.
///
/// BAU-6 (G-10, findings BAU-F3/F4):
/// - `redirect(Policy::none())`. The default policy follows up to ten
///   redirects, and on a 307/308 tower-http re-sends the method *and the body*
///   — so a redirecting token endpoint would receive `client_secret`, `code`
///   and `code_verifier` again at whatever host the redirect names. Nothing
///   here is a browser flow, so no redirect is ever legitimate.
/// - `timeout` on the client as a whole-request ceiling (connect, send **and**
///   body), so a body that trickles in after the headers cannot outlive the
///   per-call `tokio::time::timeout` budget.
///
/// `pub(crate)` so `accounts::verify_google_id_token` and `captcha` share the
/// same pool (attome-auth hardening 1.6, BAU-6).
#[expect(
    clippy::expect_used,
    reason = "a builder with only timeouts and a redirect policy cannot fail; a TLS backend failure is unrecoverable"
)]
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(HTTP_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            // Only timeouts and a redirect policy are configured, none of
            // which can fail to apply; a builder failure here would mean the
            // TLS backend itself failed to initialize, which is not
            // recoverable and must not be silently downgraded to a default
            // client.
            .expect("reqwest::Client::builder with only timeouts and a policy set cannot fail")
    })
}

/// A verified OIDC identity — signature, issuer/audience, and nonce have
/// already been checked by the time a caller receives this; only account
/// linking remains (mirrors `attome_auth::accounts::GoogleIdentity`).
pub struct OidcIdentity {
    pub sub: String,
    pub email: String,
    /// P-federation-linking-policy §4.3(a) — `Some(user_id)` when this flow
    /// was started via the session-gated self-service linking route (not the
    /// ordinary bypass-listed login route), carried across the IdP redirect
    /// round trip inside the single-use, server-side `OidcState` (never a
    /// client-controlled query/form value — see `start_login`'s doc comment
    /// for why it can't ride the session cookie instead). The caller must
    /// branch on this: `Some` means call `xrm_security::accounts::
    /// link_identity_to_user`, never `link_oidc_identity` (no email-matching
    /// JIT logic should run for an explicit self-service link).
    pub linking_user_id: Option<Uuid>,
    /// The validated ID token's own `auth_time` claim (D-510 rule 2): when the
    /// user actually authenticated at the provider. `None` when the provider
    /// sent none, or sent one later than the token's own validation allows.
    /// Never the callback time.
    pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
    /// The validated ID token's own `exp`. The Google credential flow has no
    /// nonce, so it bounds its single-use marker's lifetime by this
    /// (`accounts::verify_google_id_token`).
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Base-auth hardening 2.1c (D-510 rule 5) — `Some` when this flow was a
    /// federated step-up, carried back from the single-use server-side
    /// `OidcState` exactly as `linking_user_id` is. Never client input.
    pub step_up: Option<crate::step_up::FederatedStepUp>,
}

impl std::fmt::Debug for OidcIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcIdentity")
            .field("linking_user_id", &self.linking_user_id)
            .field("auth_time", &self.auth_time)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Clock-skew allowance for an ID token's `auth_time`, matching the leeway
/// `jsonwebtoken` applies to `exp`.
const AUTH_TIME_LEEWAY_SECS: i64 = crate::step_up::FEDERATED_AUTH_TIME_LEEWAY_SECS;

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    /// OIDC Discovery §4.3 — the issuer the document claims to describe. It
    /// MUST equal the issuer the well-known URL was built from. `Option` only
    /// so a cache entry written by a fixture (or before this check existed)
    /// still parses; when it is present it is enforced by
    /// `validate_discovery`. Requiring its presence outright would fail
    /// those fixtures, which live outside this crate.
    #[serde(default)]
    issuer: Option<String>,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// BAU-7 (G-10, finding BAU-F4) — the discovery document's own cross-checks,
/// re-applied on every read (cache and live fetch alike):
///
/// - When the document names an `issuer`, it must be the configured one.
///   A document fetched from `{issuer}/.well-known/openid-configuration` that
///   describes a different issuer is a mis-configured or hijacked response.
/// - Every endpoint must be `https` **unless the configured issuer is itself
///   plain `http`**. That is the local-development shape (a mock IdP on
///   `127.0.0.1`, `auth.secure_cookies = false`): configuring an `http`
///   issuer is already an explicit acceptance of plaintext for that provider,
///   so it is the signal used here rather than threading `secure_cookies`
///   through a module that never otherwise reads configuration. A production
///   (`https`) issuer therefore can never be redirected to a plaintext
///   endpoint by the document it serves.
fn validate_discovery(doc: &DiscoveryDocument, issuer: &str) -> Result<(), AppError> {
    if let Some(doc_issuer) = doc.issuer.as_deref()
        && doc_issuer != issuer
    {
        tracing::warn!(
            "oidc discovery document names an issuer that does not match the \
             configured one; refusing"
        );
        return Err(AppError::internal(
            "oidc discovery document failed validation",
        ));
    }
    if issuer.starts_with("https://") {
        for endpoint in [
            &doc.authorization_endpoint,
            &doc.token_endpoint,
            &doc.jwks_uri,
        ] {
            if !endpoint.starts_with("https://") {
                tracing::warn!("oidc discovery endpoint is not https; refusing");
                return Err(AppError::internal(
                    "oidc discovery document failed validation",
                ));
            }
        }
    }
    Ok(())
}

/// Single-use state persisted server-side across the redirect round-trip —
/// the PKCE verifier and nonce must never be exposed to the browser (unlike
/// `state` itself, which the IdP echoes back and is safe to see).
#[derive(Serialize, Deserialize)]
struct OidcState {
    code_verifier: String,
    nonce: String,
    redirect_uri: String,
    /// P-federation-linking-policy §4.3(a) — set only by the session-gated
    /// self-service linking start route; `None` for an ordinary login. Must
    /// live in this single-use, server-side, Redis-backed state rather than
    /// (say) a cookie: session cookies here are `SameSite=Strict`
    /// (`attome_auth::cookie::build`), so the browser never re-attaches one on
    /// the cross-site redirect back from the IdP — this is the only value
    /// that survives the round trip.
    #[serde(default)]
    linking_user_id: Option<Uuid>,
    /// Base-auth hardening 2.1c (D-510 rule 5) — the federated step-up this
    /// flow completes, set only by the session-gated step-up start route
    /// (`start_step_up_login`). Same single-use, server-side reasoning as
    /// `linking_user_id`: the session cookie never survives the IdP redirect.
    #[serde(default)]
    step_up: Option<crate::step_up::FederatedStepUp>,
}

fn state_key(state_id: &str) -> String {
    format!("oidc:state:{state_id}")
}

/// `KEYS[1]` = the state key. Returns the value and deletes the key in one
/// atomic step, or nil when it is already gone (BAU-5, finding BAU-F2).
///
/// `GET` then `DEL` was two round trips: two concurrent callbacks on one
/// state both read it before either deleted it, and a failed or timed-out
/// `DEL` was ignored, so the state stayed replayable for the rest of its
/// 300 s TTL. A Lua script is used rather than `GETDEL` because it is atomic
/// on every pinned Redis/Dragonfly image without a server-version check —
/// the same shape `step_up`'s challenge step already relies on.
const CONSUME_STATE_SCRIPT: &str = r#"
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
end
return value
"#;

/// Reads and invalidates the single-use state in one atomic step. A Redis
/// error or timeout is an `Err`, which `complete_login` turns into a
/// rejection before the token endpoint is ever contacted.
async fn consume_state(redis: &Store, state_id: &str) -> Result<Option<String>, AppError> {
    let redis = match redis {
        Store::Redis(pool) => pool,
        // The in-process form of CONSUME_STATE_SCRIPT: read and delete under
        // one lock, so a state can be redeemed once.
        Store::Memory(memory) => {
            return memory
                .transaction(|ks| {
                    let value = ks.get_str(&state_key(state_id))?;
                    if value.is_some() {
                        ks.del(&state_key(state_id));
                    }
                    Ok(value)
                })
                .map_err(|_: attome_cache::memory::WrongType| {
                    AppError::internal("oidc state key holds a non-string value")
                });
        }
    };
    tokio::time::timeout(
        REDIS_TIMEOUT,
        redis.eval::<Option<String>, _, _, _>(
            CONSUME_STATE_SCRIPT,
            vec![state_key(state_id)],
            Vec::<String>::new(),
        ),
    )
    .await
    .map_err(|_| AppError::internal("oidc state consume timed out"))?
    .map_err(AppError::internal)
}
fn discovery_key(provider_key: &str) -> String {
    format!("oidc:discovery:{provider_key}")
}
fn jwks_key(provider_key: &str) -> String {
    format!("oidc:jwks:{provider_key}")
}
fn jwks_refetch_gate_key(provider_key: &str) -> String {
    format!("oidc:jwks-refetch:{provider_key}")
}

/// RFC 7636 PKCE pair: a 256-bit random verifier and its S256 challenge.
fn generate_pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let verifier = B64URL.encode(bytes);
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

async fn fetch_discovery(
    redis: &Store,
    provider_key: &str,
    issuer: &str,
) -> Result<DiscoveryDocument, AppError> {
    let cache_key = discovery_key(provider_key);
    if let Ok(Ok(Some(cached))) = tokio::time::timeout(REDIS_TIMEOUT, redis.get(&cache_key)).await
        && let Ok(doc) = serde_json::from_str::<DiscoveryDocument>(&cached)
    {
        validate_discovery(&doc, issuer)?;
        return Ok(doc);
    }

    let url = format!("{issuer}/.well-known/openid-configuration");
    let body = http_get_text(&url, DISCOVERY_MAX_BYTES).await?;
    let doc: DiscoveryDocument = serde_json::from_str(&body)
        .map_err(|_| AppError::internal("oidc discovery document is not valid JSON"))?;
    validate_discovery(&doc, issuer)?;

    let _ = tokio::time::timeout(
        REDIS_TIMEOUT,
        redis.set(
            &cache_key,
            &body,
            Some(Duration::from_secs(DISCOVERY_CACHE_TTL_SECS as u64)),
        ),
    )
    .await;

    Ok(doc)
}

/// Fail-closed by construction: any error here (Redis AND live fetch both
/// unavailable, or a malformed document) propagates as `AppError` — there is
/// no fallback that lets a token through unverified. The `bool` is `true`
/// when the set came from the cache, which may predate a key rotation.
async fn fetch_jwks(
    redis: &Store,
    provider_key: &str,
    jwks_uri: &str,
) -> Result<(JwkSet, bool), AppError> {
    if let Ok(Ok(Some(cached))) =
        tokio::time::timeout(REDIS_TIMEOUT, redis.get(&jwks_key(provider_key))).await
        && let Ok(jwks) = serde_json::from_str::<JwkSet>(&cached)
    {
        return Ok((jwks, true));
    }
    let jwks = fetch_and_cache_jwks(redis, provider_key, jwks_uri).await?;
    Ok((jwks, false))
}

/// Fetches the provider's JWKS live and overwrites the cached copy only once
/// the document parses, so a malformed or unfetchable document leaves the
/// cache as it was.
async fn fetch_and_cache_jwks(
    redis: &Store,
    provider_key: &str,
    jwks_uri: &str,
) -> Result<JwkSet, AppError> {
    let body = http_get_text(jwks_uri, JWKS_MAX_BYTES).await?;
    let jwks: JwkSet = serde_json::from_str(&body)
        .map_err(|_| AppError::internal("oidc jwks document is not valid JSON"))?;

    let _ = tokio::time::timeout(
        REDIS_TIMEOUT,
        redis.set(
            &jwks_key(provider_key),
            &body,
            Some(Duration::from_secs(JWKS_CACHE_TTL_SECS as u64)),
        ),
    )
    .await;

    Ok(jwks)
}

/// What [`resolve_signing_key`] does when `kid` is not in the set it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnknownKid {
    Refetch,
    Reject,
}

/// The pure half of the unknown-`kid` decision (security contract I10). A set
/// fetched live for this request is already current, so a missing `kid` is
/// rejected. A cached set may predate a key rotation, so it is refetched, but
/// only by the caller that won the per-provider gate; every other caller
/// rejects at once instead of waiting for the winner.
fn on_unknown_kid(served_from_cache: bool, won_refetch_gate: bool) -> UnknownKid {
    if served_from_cache && won_refetch_gate {
        UnknownKid::Refetch
    } else {
        UnknownKid::Reject
    }
}

/// `SET NX EX` on the provider's refetch gate: `true` only when this caller
/// set it. A Redis error or timeout counts as losing, so an outage can never
/// turn unknown-`kid` tokens into unbounded upstream fetches.
async fn try_acquire_refetch_gate(redis: &Store, provider_key: &str) -> bool {
    let acquired = tokio::time::timeout(
        REDIS_TIMEOUT,
        redis.set_nx(
            &jwks_refetch_gate_key(provider_key),
            "1",
            Some(Duration::from_secs(JWKS_REFETCH_GATE_SECS as u64)),
        ),
    )
    .await;
    matches!(acquired, Ok(Ok(true)))
}

/// The provider's signing key for `kid` (attome-auth hardening 1.7).
///
/// A `kid` in the cached set resolves with no fetch. A `kid` missing from a
/// cached set triggers at most one refetch per provider per
/// `JWKS_REFETCH_GATE_SECS`, taken by whichever caller wins the gate: the
/// winner fetches under the usual HTTP timeout, replaces the cache, and looks
/// the `kid` up exactly once more. Callers that lose the gate reject at once
/// rather than wait, and so does the winner when the refetch fails or still
/// lacks the `kid`; a client retry picks up the refreshed set. The refetch
/// never replaces the cache with a document that fails to parse.
///
/// Public so the refetch bound can be tested against a real Redis from
/// `tests/`; `verify_id_token` is its only production caller.
pub async fn resolve_signing_key(
    redis: &Store,
    provider_key: &str,
    jwks_uri: &str,
    kid: &str,
) -> Result<Jwk, AppError> {
    let (jwks, served_from_cache) = fetch_jwks(redis, provider_key, jwks_uri).await?;
    if let Some(jwk) = jwks.find(kid) {
        return Ok(jwk.clone());
    }

    let won_refetch_gate = served_from_cache && try_acquire_refetch_gate(redis, provider_key).await;
    if on_unknown_kid(served_from_cache, won_refetch_gate) == UnknownKid::Reject {
        return Err(AppError::Unauthorized);
    }

    let Ok(refreshed) = fetch_and_cache_jwks(redis, provider_key, jwks_uri).await else {
        tracing::warn!(
            provider_key,
            "oidc jwks refetch for an unknown kid failed; the cached set is unchanged"
        );
        return Err(AppError::Unauthorized);
    };
    refreshed.find(kid).cloned().ok_or(AppError::Unauthorized)
}

/// P-observability-completion — the current ambient span's W3C `traceparent`,
/// for the two outbound HTTP call sites below (discovery/JWKS GET, token
/// exchange POST — "the only outbound HTTP call sites in the codebase today"
/// per this plan's design). `None` whenever there's no valid ambient OTel
/// span context, which is every request today while
/// `observability.enable_distributed_tracing = false` — so adding the header
/// is a pure no-op until tracing is actually enabled.
fn traceparent_header() -> Option<String> {
    attome_types::w3c_trace::format_current_traceparent(&tracing::Span::current().context())
}

/// Reads at most `max_bytes` of a response body, refusing anything larger
/// (BAU-6, finding BAU-F3). A `Content-Length` already over the cap is
/// refused before a byte is read; a chunked or lying one is refused as soon as
/// the running total crosses it, so an oversized body is never fully buffered.
async fn read_bounded(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, AppError> {
    if let Some(len) = response.content_length()
        && len > max_bytes as u64
    {
        return Err(AppError::internal("oidc response exceeds the size cap"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(AppError::internal)? {
        if body.len() + chunk.len() > max_bytes {
            return Err(AppError::internal("oidc response exceeds the size cap"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// `GET` a document with the send **and** the body inside one timeout, and a
/// size cap (BAU-6). The previous shape put only `send()` inside the timeout
/// and then read with `response.text()` outside it, so an endpoint that
/// answered its headers and then stalled or streamed held the request for as
/// long as it liked. Errors carry no URL: `jwks_uri` comes from the provider's
/// own discovery document, so it is provider-influenced text.
async fn http_get_text(url: &str, max_bytes: usize) -> Result<String, AppError> {
    let client = http_client();
    let mut request = client.get(url);
    if let Some(traceparent) = traceparent_header() {
        request = request.header("traceparent", traceparent);
    }
    let body = tokio::time::timeout(HTTP_TIMEOUT, async {
        let response = request
            .send()
            .await
            .map_err(|e| AppError::internal(e.without_url()))?
            .error_for_status()
            .map_err(|_| AppError::internal("oidc GET returned an error status"))?;
        read_bounded(response, max_bytes).await
    })
    .await
    .map_err(|_| AppError::internal("oidc GET timed out"))??;
    String::from_utf8(body).map_err(|_| AppError::internal("oidc response is not valid UTF-8"))
}

/// Starts the authorization-code + PKCE flow: generates state/nonce/PKCE,
/// persists them server-side (single-use, `STATE_TTL_SECS`), and returns the
/// URL to redirect the browser to. `redirect_uri` MUST be the caller's own
/// callback route — stored alongside the state so `complete_login` sends the
/// exact same value to the token endpoint (required by RFC 6749 §4.1.3).
///
/// `state_redis` MUST be the coordination-role pool (`AppState.redis_coordination`)
/// — the single-use `SET NX` state gate is the same class of correctness-critical
/// key as the S2S nonce guard/idempotency gate (guidelines §5 P1.15). `cache_redis`
/// (`AppState.redis`) is only ever used for the discovery-document/JWKS TTL
/// caches, which degrade-and-recover on a miss (D-027) — never the state gate.
///
/// `linking_user_id`: `None` for an ordinary login (`oidc_login`); `Some(user_id)`
/// only from the session-gated self-service linking start route
/// (P-federation-linking-policy §4.3(a)) — the caller must have already
/// authenticated `user_id` via a live session before calling this with `Some`.
pub async fn start_login(
    state_redis: &Store,
    cache_redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    redirect_uri: &str,
    linking_user_id: Option<Uuid>,
) -> Result<String, AppError> {
    start_authorization(
        state_redis,
        cache_redis,
        provider,
        provider_key,
        redirect_uri,
        linking_user_id,
        None,
    )
    .await
}

/// Base-auth hardening 2.1c (D-510 rule 5) — starts the same flow for a
/// federated step-up bound to `step_up` (built only by
/// `step_up::begin_federated_step_up`). Adds `prompt=login` and `max_age` set
/// to the operation's max age. Both are only requests the provider may ignore,
/// so `step_up::complete_federated_step_up` accepts nothing but the validated
/// ID token's own `auth_time`.
pub async fn start_step_up_login(
    state_redis: &Store,
    cache_redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    redirect_uri: &str,
    step_up: crate::step_up::FederatedStepUp,
) -> Result<String, AppError> {
    start_authorization(
        state_redis,
        cache_redis,
        provider,
        provider_key,
        redirect_uri,
        None,
        Some(step_up),
    )
    .await
}

/// The authorization parameters a federated step-up adds (OIDC Core §3.1.2.1):
/// force re-authentication, and cap the acceptable authentication age. Empty
/// for a sign-in or a link.
fn step_up_params(step_up: Option<&crate::step_up::FederatedStepUp>) -> String {
    step_up
        .map(|step_up| format!("&prompt=login&max_age={}", step_up.max_age_secs()))
        .unwrap_or_default()
}

async fn start_authorization(
    state_redis: &Store,
    cache_redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    redirect_uri: &str,
    linking_user_id: Option<Uuid>,
    step_up: Option<crate::step_up::FederatedStepUp>,
) -> Result<String, AppError> {
    let (code_verifier, code_challenge) = generate_pkce();
    let nonce = generate_nonce();
    let state_id = Uuid::now_v7().to_string();
    let extra_params = step_up_params(step_up.as_ref());

    let state = OidcState {
        code_verifier,
        nonce: nonce.clone(),
        redirect_uri: redirect_uri.to_string(),
        linking_user_id,
        step_up,
    };
    let state_json = serde_json::to_string(&state).map_err(AppError::internal)?;

    tokio::time::timeout(
        REDIS_TIMEOUT,
        state_redis.set_nx(
            &state_key(&state_id),
            &state_json,
            Some(Duration::from_secs(STATE_TTL_SECS as u64)),
        ),
    )
    .await
    .map_err(|_| AppError::internal("oidc state write timed out"))??;

    let discovery = fetch_discovery(cache_redis, provider_key, &provider.issuer).await?;

    let scopes = provider.scopes.join(" ");
    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256{extra_params}",
        discovery.authorization_endpoint,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&state_id),
        urlencoding::encode(&nonce),
        urlencoding::encode(&code_challenge),
    );
    Ok(url)
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// The browser-binding decision every OIDC callback shares (BAU-4b, G-10,
/// finding BAU-F1). `presented` is the value of the flow's binding cookie —
/// the `state` id the flow's own start route put there and the IdP echoed
/// back — and `echoed_state` is the `state` query value. Both must be
/// present and equal: the state id is a platform-minted 128-bit UUIDv7 the
/// IdP echoes in the URL, not a secret, so a plain comparison leaks nothing.
///
/// Lives here rather than in the HTTP layer because the binding is a property
/// of the flow `start_login`/`complete_login` implement, not of any one
/// transport: an empty `echoed_state` is a flow that never went through
/// `start_login` (or a malformed callback) and must never match an empty
/// cookie.
///
/// This is the comparison; `bind_to_browser` is what turns it into the proof
/// `complete_login` now requires (BAU-4b).
pub fn browser_binding_matches(presented: Option<&str>, echoed_state: &str) -> bool {
    matches!(presented, Some(presented) if !echoed_state.is_empty() && presented == echoed_state)
}

/// Proof that a callback arrived in the browser that started its flow — the
/// structural half of BAU-4b (G-10, finding BAU-F1).
///
/// The state id is private and `bind_to_browser` is its only constructor, so
/// `complete_login` cannot be reached without `bind_to_browser` having
/// compared the echoed state with a value the caller *says* it read from the
/// binding cookie. What the type guarantees is that the comparison ran and
/// matched; it cannot guarantee where `presented` came from —
/// `bind_to_browser` is public and takes any `Option<&str>`. Passing the
/// cookie's value, and nothing else, remains the route handler's obligation
/// (`crates/server/src/auth/oidc.rs`), checked by review, not by the compiler.
#[derive(Debug)]
pub struct BoundState(String);

impl BoundState {
    /// The single-use state this flow consumes.
    pub fn state_id(&self) -> &str {
        &self.0
    }
}

/// Binds a callback to the browser that started its flow (BAU-4b).
/// `presented` is the value of the flow's own binding cookie — the state id
/// its start route put there and the IdP echoed back — and `echoed_state` is
/// the `state` query value. The comparison itself is
/// `browser_binding_matches`.
pub fn bind_to_browser(
    presented: Option<&str>,
    echoed_state: &str,
) -> Result<BoundState, AppError> {
    if browser_binding_matches(presented, echoed_state) {
        Ok(BoundState(echoed_state.to_owned()))
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Completes the flow: retrieves+invalidates the single-use state (a
/// missing/expired `state_id` is `AppError::Unauthorized` — replay or a
/// stale link), exchanges `code` for an ID token, and verifies it (signature
/// via cached/fetched JWKS, issuer, audience, expiry, and nonce match).
/// Returns the verified identity for the caller to JIT-link into
/// `user_account` (`xrm_security::accounts::link_oidc_identity`). See
/// `start_login` for the `state_redis`/`cache_redis` split.
///
/// BAU-4b (G-10, finding BAU-F1): the browser binding is a *parameter type*.
/// `bound` can only be produced by `bind_to_browser`, so no caller can reach
/// this function without the comparison having run, and the state it consumes
/// is the same one the comparison matched. That the compared value really was
/// the cookie the flow's start route set is the caller's obligation (see
/// [`BoundState`]).
///
/// It consumes the single-use state unconditionally once it is reached.
pub async fn complete_login(
    state_redis: &Store,
    cache_redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    code: &str,
    bound: BoundState,
) -> Result<OidcIdentity, AppError> {
    // BAU-5 (G-10, finding BAU-F2): one atomic consume, so exactly one of any
    // concurrent callbacks on this state gets past the gate, and a genuine
    // state is single-use regardless of what happens next. A missing state is
    // Unauthorized; a store error or timeout is an Err — never "proceed".
    let raw_state = consume_state(state_redis, bound.state_id())
        .await?
        .ok_or(AppError::Unauthorized)?;

    let state: OidcState = serde_json::from_str(&raw_state)
        .map_err(|_| AppError::internal("corrupt oidc state entry"))?;

    let discovery = fetch_discovery(cache_redis, provider_key, &provider.issuer).await?;

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
        ("code_verifier", state.code_verifier.as_str()),
    ];
    let client = http_client();
    let mut token_request = client.post(&discovery.token_endpoint).form(&params);
    if let Some(traceparent) = traceparent_header() {
        token_request = token_request.header("traceparent", traceparent);
    }
    // BAU-6 (findings BAU-F3/F4): the send and the body share one timeout, the
    // body is size-capped, and the shared client follows no redirect — so a
    // redirecting or stalling token endpoint cannot re-receive the client
    // secret at another host, nor hold the request open, nor buffer an
    // unbounded body.
    let token_response = tokio::time::timeout(HTTP_TIMEOUT, async {
        let response = token_request
            .send()
            .await
            .map_err(|e| AppError::internal(e.without_url()))?
            .error_for_status()
            .map_err(|_| AppError::Unauthorized)?; // bad code/verifier — never leak why to the client
        let body = read_bounded(response, TOKEN_RESPONSE_MAX_BYTES).await?;
        serde_json::from_slice::<TokenResponse>(&body)
            .map_err(|_| AppError::internal("oidc token response is not valid JSON"))
    })
    .await
    .map_err(|_| AppError::internal("oidc token exchange timed out"))??;

    let mut identity = verify_id_token(
        cache_redis,
        provider,
        provider_key,
        &token_response.id_token,
        &state.nonce,
    )
    .await?;
    identity.linking_user_id = state.linking_user_id;
    identity.step_up = state.step_up;
    Ok(identity)
}

async fn verify_id_token(
    redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    id_token: &str,
    expected_nonce: &str,
) -> Result<OidcIdentity, AppError> {
    verify_id_token_inner(
        redis,
        provider,
        provider_key,
        id_token,
        Some(expected_nonce),
    )
    .await
}

/// BAU-8b (OD-7a) — verify an ID token against a provider's published JWKS
/// with **no nonce** to check. Google Identity Services hands the browser an ID
/// token directly (no authorization-code round trip), so there is no nonce in
/// the flow to bind; every other guarantee is identical, because this is the
/// same discovery cache, single-flight JWKS refetch and `verify_claims` the
/// generic OIDC flow uses.
///
/// Without a nonce nothing here binds the token to a browser, a session or a
/// single use: a captured token verifies again, by anyone, until its `exp`.
/// This function therefore proves only that the token is genuine. Its one
/// caller, `accounts::verify_google_id_token`, adds the replay protection
/// itself by consuming a single-use marker per credential on the coordination
/// pool, failing closed. Never call this from a path that skips that marker.
pub(crate) async fn verify_id_token_without_nonce(
    redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    id_token: &str,
) -> Result<OidcIdentity, AppError> {
    verify_id_token_inner(redis, provider, provider_key, id_token, None).await
}

async fn verify_id_token_inner(
    redis: &Store,
    provider: &OidcProviderConfig,
    provider_key: &str,
    id_token: &str,
    expected_nonce: Option<&str>,
) -> Result<OidcIdentity, AppError> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|_| AppError::Unauthorized)?;
    let kid = header.kid.clone().ok_or(AppError::Unauthorized)?;

    let discovery = fetch_discovery(redis, provider_key, &provider.issuer).await?;
    let jwk = resolve_signing_key(redis, provider_key, &discovery.jwks_uri, &kid).await?;

    verify_claims(&jwk, &header, provider, id_token, expected_nonce)
}

/// The pure (no I/O) half of ID-token verification — split out from
/// `verify_id_token` so it's directly unit-testable without a live JWKS
/// endpoint (see the tests below, which sign a throwaway token and drive
/// this function end-to-end). Given the already-selected JWK for the
/// token's `kid`, checks signature, alg (asymmetric only — see the
/// alg-confusion comment below), audience, issuer, expiry and
/// `email_verified`, and extracts `sub`/`email`/`auth_time`.
///
/// `expected_nonce` is `Some(nonce)` for an authorization-code/redirect flow
/// (the nonce the start route minted must be the token's own). It is `None`
/// only for a flow with no redirect to bind — BAU-8b's Google path, where
/// Google Identity Services hands the browser the token directly — and the
/// check is skipped there rather than loosened for anyone else.
fn verify_claims(
    jwk: &jsonwebtoken::jwk::Jwk,
    header: &jsonwebtoken::Header,
    provider: &OidcProviderConfig,
    id_token: &str,
    expected_nonce: Option<&str>,
) -> Result<OidcIdentity, AppError> {
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| AppError::Unauthorized)?;

    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        // Never accept a symmetric alg here — HS256 with the wrong key would
        // let a caller who knows the client_secret self-sign a token
        // (the classic "alg confusion" attack); ID tokens are always
        // asymmetric-signed by a real OIDC provider.
        return Err(AppError::Unauthorized);
    }
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[&provider.client_id]);
    validation.set_issuer(&[&provider.issuer]);
    // jsonwebtoken only enforces aud/iss when the claim is PRESENT — a token
    // that omits either claim entirely would otherwise sail through
    // (`options.iss`/`options.aud` match arms fall through silently on
    // `TryParse::NotPresent`). Force presence explicitly; "exp" is already
    // required by `Validation::new`.
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    let data = jsonwebtoken::decode::<serde_json::Value>(id_token, &decoding_key, &validation)
        .map_err(|_| AppError::Unauthorized)?;

    let claims = data.claims;

    // BAU-7 (G-10, finding BAU-F4) — OIDC Core §3.1.3.7. `set_audience` above
    // already requires `client_id` to be *among* `aud`; what it does not do is
    // ask who the token was actually issued to when `aud` names more than one
    // party. A present `azp` must name this client, and an `aud` array longer
    // than one entry must carry one — otherwise a token minted for a different
    // client that merely lists this one as a secondary audience is accepted.
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(serde_json::Value::String(single)) => vec![single.as_str()],
        Some(serde_json::Value::Array(many)) => {
            many.iter().filter_map(|value| value.as_str()).collect()
        }
        _ => Vec::new(),
    };
    let authorized_party = claims.get("azp").and_then(|v| v.as_str());
    if let Some(azp) = authorized_party {
        if azp != provider.client_id {
            return Err(AppError::Unauthorized);
        }
    } else if audiences.len() > 1 {
        return Err(AppError::Unauthorized);
    }

    if let Some(expected_nonce) = expected_nonce {
        let nonce = claims.get("nonce").and_then(|v| v.as_str());
        if nonce != Some(expected_nonce) {
            return Err(AppError::Unauthorized);
        }
    }

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Unauthorized)?
        .to_string();
    let email = claims
        .get(provider.email_claim.as_str())
        .and_then(|v| v.as_str())
        .ok_or(AppError::Unauthorized)?
        .to_string();
    let email_verified = claims.get("email_verified").and_then(|v| v.as_bool());
    let accepted = match email_verified {
        Some(verified) => verified,
        // Absent claim: by default the provider doesn't assert it either
        // way, so it's accepted (matches the "email" scope's spec default of
        // no explicit claim) — unless this provider has opted into strict
        // enforcement (`require_email_verified_claim`, Phase 2.2 remediation),
        // in which case an absent claim is treated the same as an explicit
        // `false`.
        None => !provider.require_email_verified_claim,
    };
    if !accepted {
        return Err(AppError::Unauthorized);
    }

    // D-510 rule 2: the provider's own authentication time, from the token
    // whose signature, issuer, audience and expiry were just validated. A value
    // in the future beyond clock-skew leeway is not usable, so it reads as
    // absent rather than as fresh.
    let auth_time = claims
        .get("auth_time")
        .and_then(|v| v.as_i64())
        .and_then(|secs| chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0))
        .filter(|at| *at <= chrono::Utc::now() + chrono::Duration::seconds(AUTH_TIME_LEEWAY_SECS));

    // `exp` is a required claim that `decode` has just validated, so it is
    // present and numeric; a fractional NumericDate is truncated.
    let expires_at = claims
        .get("exp")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .and_then(|secs| chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0))
        .ok_or(AppError::Unauthorized)?;

    // Overwritten by complete_login right after this returns — this pure
    // half has no `OidcState` (and thus no linking_user_id) to draw from.
    Ok(OidcIdentity {
        sub,
        email,
        linking_user_id: None,
        auth_time,
        expires_at,
        step_up: None,
    })
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                out.push(b as char);
            } else {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-510 rule 5: a step-up asks for re-authentication within the
    /// operation's max age; a sign-in or link asks for nothing extra.
    #[test]
    fn only_a_step_up_asks_for_prompt_login_and_max_age() {
        use crate::step_up::{FederatedProtocol, FederatedStepUp, Operation};
        assert_eq!(step_up_params(None), "");
        for (operation, max_age) in [
            (Operation::IdentityLink, 300),
            (Operation::ApiKeyCreate, 900),
        ] {
            let binding = FederatedStepUp {
                challenge_id: Uuid::now_v7(),
                user_id: Uuid::now_v7(),
                family_id: Uuid::now_v7(),
                operation,
                protocol: FederatedProtocol::Oidc,
                provider_key: "entra".into(),
            };
            assert_eq!(
                step_up_params(Some(&binding)),
                format!("&prompt=login&max_age={max_age}")
            );
        }
    }

    // ── BAU-6 (G-10, findings BAU-F3/F4): bounded outbound calls ──────────

    /// A one-connection endpoint that reads the request line, writes `reply`,
    /// and then holds the connection open without closing it.
    async fn stalling_endpoint(reply: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/document", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = socket.write_all(reply.as_bytes()).await;
            // Hold the connection open: no close, no further bytes.
            std::future::pending::<()>().await;
        });
        url
    }

    /// P0.5 (finding BAU-F3) — an endpoint that answers its headers and one
    /// byte of body, then stalls, must fail inside the module's own timeout.
    /// The 15 s bound is deliberately far above `HTTP_TIMEOUT` (5 s): before
    /// this fix only `send()` was inside a timeout and `response.text()` was
    /// awaited outside one, so this test hung until its own outer bound.
    #[tokio::test]
    async fn a_stalled_body_after_headers_fails_within_the_timeout() {
        let url = stalling_endpoint(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{",
        )
        .await;

        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            http_get_text(&url, DISCOVERY_MAX_BYTES),
        )
        .await;
        let elapsed = started.elapsed();

        let inner = result.expect(
            "http_get_text must fail on its own timeout, not hang until this test's 15 s bound",
        );
        assert!(
            inner.is_err(),
            "a body that never completes must be an error, never a partial document"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(15),
            "took {elapsed:?}, which is outside the module's own bound"
        );
    }

    /// BAU-6 — a document whose `Content-Length` is over the cap is refused
    /// before it is buffered.
    #[tokio::test]
    async fn an_oversized_document_is_refused() {
        let url = stalling_endpoint(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n{}",
        )
        .await;

        let result = http_get_text(&url, 1024).await;

        assert!(
            result.is_err(),
            "a body larger than the cap must be refused, not read into memory"
        );
    }

    /// BAU-6 (finding BAU-F4) — `redirect(Policy::none())`: a 307 is returned
    /// to the caller as-is and its target is never contacted. Following it
    /// would re-send the request — method and body included — to whatever host
    /// the redirect named, which for a token endpoint means the client secret.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The redirect target: counts every connection it receives.
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/stolen", target.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = target.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                    .await;
            }
        });

        // The redirector.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/document", listener.local_addr().unwrap());
        let location = target_url.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let reply = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            );
            let _ = socket.write_all(reply.as_bytes()).await;
        });

        let _ = http_get_text(&url, DISCOVERY_MAX_BYTES).await;

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a redirect must not be followed: the request (and its body) must              never reach the redirect target"
        );
    }

    /// BAU-4b (G-10, finding BAU-F1) — the browser-binding matrix every OIDC
    /// callback shares. A missing cookie, a mismatched one, and an empty
    /// echoed state (a callback that never went through `start_login`) all
    /// fail; only an exact, non-empty match passes.
    #[test]
    fn browser_binding_requires_a_present_non_empty_match() {
        assert!(browser_binding_matches(Some("state-1"), "state-1"));
        assert!(!browser_binding_matches(None, "state-1"));
        assert!(!browser_binding_matches(Some("state-2"), "state-1"));
        assert!(!browser_binding_matches(Some(""), ""));
        assert!(!browser_binding_matches(Some("state-1"), ""));
        assert!(!browser_binding_matches(None, ""));
    }

    /// BAU-4b — the proof `complete_login` requires is produced only by the
    /// binding check, and only for a non-empty exact match.
    #[test]
    fn bind_to_browser_yields_the_state_only_for_a_presented_match() {
        let bound = bind_to_browser(Some("state-1"), "state-1").expect("an exact match");
        assert_eq!(bound.state_id(), "state-1");

        for (presented, echoed) in [
            (None, "state-1"),
            (Some("state-2"), "state-1"),
            (Some(""), ""),
            (Some("state-1"), ""),
        ] {
            assert!(
                bind_to_browser(presented, echoed).is_err(),
                "({presented:?}, {echoed:?}) must not produce a bound state"
            );
        }
    }

    /// A state written before 2.1c has no `step_up` and reads as none, so an
    /// in-flight sign-in across a deploy never turns into a step-up.
    #[test]
    fn a_state_without_a_step_up_binding_reads_as_none() {
        let legacy = r#"{"code_verifier":"v","nonce":"n","redirect_uri":"https://app/cb"}"#;
        let state: OidcState = serde_json::from_str(legacy).unwrap();
        assert!(state.step_up.is_none());
        assert!(state.linking_user_id.is_none());
    }

    #[test]
    fn generate_pkce_challenge_is_the_s256_hash_of_the_verifier() {
        let (verifier, challenge) = generate_pkce();
        let expected = B64URL.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        // RFC 7636 §4.1: verifier must be 43-128 chars from the unreserved set.
        assert!(verifier.len() >= 43 && verifier.len() <= 128);
    }

    #[test]
    fn generate_pkce_is_random_across_calls() {
        let (v1, _) = generate_pkce();
        let (v2, _) = generate_pkce();
        assert_ne!(v1, v2);
    }

    #[test]
    fn urlencoding_escapes_reserved_characters() {
        assert_eq!(urlencoding::encode("a b"), "a%20b");
        assert_eq!(urlencoding::encode("state&id=1"), "state%26id%3D1");
        assert_eq!(urlencoding::encode("safe-._~"), "safe-._~");
    }

    fn test_provider() -> OidcProviderConfig {
        OidcProviderConfig {
            display_name: "Test IdP".into(),
            issuer: "https://idp.example.com".into(),
            client_id: "client-123".into(),
            client_secret: "shhh".into(),
            scopes: vec!["openid".into(), "email".into()],
            email_claim: "email".into(),
            require_email_verified_claim: false,
        }
    }

    /// The two throwaway 2048-bit RSA keypairs these tests sign with,
    /// generated once per test process.
    ///
    /// [`sign_test_token`] used to generate a fresh key on every call. Nine
    /// calls, each a 2048-bit keygen in an unoptimized build, made this one
    /// module the largest single item in the fast tier's budget (TODO-017 /
    /// M-15) — two of its tests were still running after 60 seconds. Nothing
    /// here needs a *unique* key per call: eight of the nine only need "the key
    /// the JWKS publishes", and the ninth
    /// (`verify_claims_rejects_a_token_signed_by_a_different_key`) needs
    /// exactly one key that is not that one, which is what the second entry is
    /// for. `OnceLock` rather than a lazily-cloned pair because the tests in
    /// this binary run in parallel by default.
    fn test_keys() -> &'static (rsa::RsaPrivateKey, rsa::RsaPrivateKey) {
        static KEYS: std::sync::OnceLock<(rsa::RsaPrivateKey, rsa::RsaPrivateKey)> =
            std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let mut rng = rand::rngs::OsRng;
            (
                rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate a test RSA keypair"),
                rsa::RsaPrivateKey::new(&mut rng, 2048)
                    .expect("generate the second test RSA keypair"),
            )
        })
    }

    /// Builds a JWKS-published-vs-signed keypair and signs a claims payload
    /// with the private half — lets the tests below drive the real
    /// `verify_claims` (the pure half of `verify_id_token`) end-to-end
    /// without a live IdP (deferred per the plan's own "one real Entra ID
    /// tenant" manual-verification step).
    fn sign_test_token(
        claims: &serde_json::Value,
    ) -> (String, jsonwebtoken::Header, jsonwebtoken::jwk::JwkSet) {
        sign_with(&test_keys().0, claims)
    }

    /// Same shape as [`sign_test_token`], signed by — and publishing — the
    /// *other* keypair. The `kid` is deliberately identical, so pairing one
    /// function's token with the other's JWK gives "matching kid, wrong key".
    fn sign_test_token_with_a_different_key(
        claims: &serde_json::Value,
    ) -> (String, jsonwebtoken::Header, jsonwebtoken::jwk::JwkSet) {
        sign_with(&test_keys().1, claims)
    }

    fn sign_with(
        private_key: &rsa::RsaPrivateKey,
        claims: &serde_json::Value,
    ) -> (String, jsonwebtoken::Header, jsonwebtoken::jwk::JwkSet) {
        use jsonwebtoken::EncodingKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;

        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

        let kid = "test-key-1".to_string();
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.clone());
        let token = jsonwebtoken::encode(&header, claims, &encoding_key).unwrap();

        let n = B64URL.encode(private_key.n().to_bytes_be());
        let e = B64URL.encode(private_key.e().to_bytes_be());
        let jwk_json = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "alg": "RS256",
                "n": n,
                "e": e,
            }]
        });
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwk_json).unwrap();
        (token, header, jwks)
    }

    #[test]
    fn verify_claims_accepts_a_correctly_signed_token_and_extracts_claims() {
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "email_verified": true,
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
            "iat": chrono::Utc::now().timestamp(),
        });
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let identity =
            verify_claims(jwk, &header, &provider, &token, Some("expected-nonce")).unwrap();
        assert_eq!(identity.sub, "user-sub-42");
        assert_eq!(identity.email, "person@example.com");
        assert_eq!(
            identity.auth_time, None,
            "a token without auth_time asserts no authentication time"
        );
    }

    fn claims_with_auth_time(provider: &OidcProviderConfig, auth_time: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "email_verified": true,
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
            "iat": chrono::Utc::now().timestamp(),
            "auth_time": auth_time,
        })
    }

    /// D-510 rule 2: the validated token's own `auth_time` is surfaced exactly.
    #[test]
    fn verify_claims_extracts_the_tokens_auth_time() {
        let provider = test_provider();
        let authenticated_at = chrono::Utc::now().timestamp() - 180;
        let (token, header, jwks) =
            sign_test_token(&claims_with_auth_time(&provider, authenticated_at));
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let identity =
            verify_claims(jwk, &header, &provider, &token, Some("expected-nonce")).unwrap();
        assert_eq!(
            identity.auth_time.map(|at| at.timestamp()),
            Some(authenticated_at)
        );
    }

    /// An `auth_time` in the future beyond clock-skew leeway is not usable, so
    /// it reads as absent rather than as fresh.
    #[test]
    fn verify_claims_ignores_an_auth_time_in_the_future() {
        let provider = test_provider();
        let future = chrono::Utc::now().timestamp() + AUTH_TIME_LEEWAY_SECS + 600;
        let (token, header, jwks) = sign_test_token(&claims_with_auth_time(&provider, future));
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let identity =
            verify_claims(jwk, &header, &provider, &token, Some("expected-nonce")).unwrap();
        assert_eq!(identity.auth_time, None);
    }

    #[test]
    fn verify_claims_rejects_a_mismatched_nonce() {
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "nonce": "actual-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    // ── BAU-7 (G-10, finding BAU-F4): discovery and `azp` ────────────────

    fn discovery(
        issuer: Option<&str>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        jwks_uri: &str,
    ) -> DiscoveryDocument {
        DiscoveryDocument {
            issuer: issuer.map(str::to_owned),
            authorization_endpoint: authorization_endpoint.to_owned(),
            token_endpoint: token_endpoint.to_owned(),
            jwks_uri: jwks_uri.to_owned(),
        }
    }

    #[test]
    fn validate_discovery_refuses_an_issuer_that_is_not_the_configured_one() {
        let doc = discovery(
            Some("https://evil.example"),
            "https://idp.example/authorize",
            "https://idp.example/token",
            "https://idp.example/jwks",
        );
        assert!(validate_discovery(&doc, "https://idp.example").is_err());
    }

    #[test]
    fn validate_discovery_accepts_a_matching_issuer() {
        let doc = discovery(
            Some("https://idp.example"),
            "https://idp.example/authorize",
            "https://idp.example/token",
            "https://idp.example/jwks",
        );
        assert!(validate_discovery(&doc, "https://idp.example").is_ok());
    }

    /// An `https` issuer may never be served plaintext endpoints — that is the
    /// redirect-the-client-secret-to-another-host shape BAU-F4 records.
    #[test]
    fn validate_discovery_refuses_plaintext_endpoints_under_an_https_issuer() {
        for (authorization, token, jwks) in [
            (
                "http://idp.example/authorize",
                "https://idp.example/token",
                "https://idp.example/jwks",
            ),
            (
                "https://idp.example/authorize",
                "http://idp.example/token",
                "https://idp.example/jwks",
            ),
            (
                "https://idp.example/authorize",
                "https://idp.example/token",
                "http://idp.example/jwks",
            ),
        ] {
            let doc = discovery(Some("https://idp.example"), authorization, token, jwks);
            assert!(
                validate_discovery(&doc, "https://idp.example").is_err(),
                "plaintext endpoint accepted under an https issuer: {authorization} {token} {jwks}"
            );
        }
    }

    /// The local-dev shape: a plain-`http` configured issuer has already
    /// accepted plaintext for this provider, so its mock IdP on `127.0.0.1`
    /// is not refused.
    #[test]
    fn validate_discovery_allows_plaintext_endpoints_under_an_http_issuer() {
        let doc = discovery(
            Some("http://127.0.0.1:9"),
            "http://127.0.0.1:9/authorize",
            "http://127.0.0.1:9/token",
            "http://127.0.0.1:9/jwks",
        );
        assert!(validate_discovery(&doc, "http://127.0.0.1:9").is_ok());
    }

    fn claims_with_audience(
        provider: &OidcProviderConfig,
        aud: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "iss": provider.issuer,
            "aud": aud,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "email_verified": true,
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
            "iat": chrono::Utc::now().timestamp(),
        })
    }

    /// A single-valued `aud` still needs no `azp`.
    #[test]
    fn verify_claims_accepts_a_single_audience_without_azp() {
        let provider = test_provider();
        let (token, header, jwks) = sign_test_token(&claims_with_audience(
            &provider,
            serde_json::json!(provider.client_id),
        ));
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        assert!(verify_claims(jwk, &header, &provider, &token, Some("expected-nonce")).is_ok());
    }

    /// OIDC Core §3.1.3.7 — more than one audience requires `azp`.
    #[test]
    fn verify_claims_refuses_a_multi_audience_token_without_azp() {
        let provider = test_provider();
        let (token, header, jwks) = sign_test_token(&claims_with_audience(
            &provider,
            serde_json::json!([provider.client_id, "another-client"]),
        ));
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn verify_claims_accepts_a_multi_audience_token_with_the_right_azp() {
        let provider = test_provider();
        let mut claims = claims_with_audience(
            &provider,
            serde_json::json!([provider.client_id, "another-client"]),
        );
        claims["azp"] = serde_json::json!(provider.client_id);
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        assert!(verify_claims(jwk, &header, &provider, &token, Some("expected-nonce")).is_ok());
    }

    /// A present `azp` naming someone else is refused even for a single-valued
    /// `aud` that happens to list this client.
    #[test]
    fn verify_claims_refuses_an_azp_for_another_client() {
        let provider = test_provider();
        let mut claims = claims_with_audience(&provider, serde_json::json!(provider.client_id));
        claims["azp"] = serde_json::json!("another-client");
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn verify_claims_rejects_email_verified_false() {
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "email_verified": false,
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn verify_claims_rejects_a_token_signed_by_a_different_key() {
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        let (token, header, _jwks) = sign_test_token(&claims);
        // A second, unrelated keypair's JWK — same kid claimed, different key.
        let (_, _, other_jwks) = sign_test_token_with_a_different_key(&claims);
        let wrong_jwk = other_jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let result = verify_claims(
            wrong_jwk,
            &header,
            &provider,
            &token,
            Some("expected-nonce"),
        );
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn validation_rejects_a_token_with_no_aud_claim_at_all() {
        // Regression test for the jsonwebtoken gotcha this module works
        // around: `options.aud`/`options.iss` only fire when the claim is
        // PRESENT, so a token omitting "aud" entirely would otherwise pass
        // silently unless required_spec_claims explicitly demands it.
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            // "aud" deliberately omitted
            "sub": "user-sub-42",
            "email": "person@example.com",
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn verify_claims_rejects_hs256_even_with_a_matching_kid() {
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        // Sign with the real (asymmetric) key/header, then lie about the alg
        // in the header the way an attacker attempting alg-confusion would —
        // proves the check runs before any signature verification is even
        // attempted.
        let (token, mut header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        header.alg = Algorithm::HS256;

        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    /// Enterprise-audit remediation (Phase 2.2): a provider opted into
    /// `require_email_verified_claim` must reject a token with no
    /// `email_verified` claim at all, not silently accept it.
    #[test]
    fn verify_claims_rejects_a_missing_email_verified_when_provider_requires_it() {
        let mut provider = test_provider();
        provider.require_email_verified_claim = true;
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let result = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"));
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    /// A provider that has explicitly opted out
    /// (`require_email_verified_claim: false`) must still accept a missing
    /// claim — the flag now defaults to `true` (strict), but an explicit
    /// per-provider opt-out remains fully supported.
    #[test]
    fn verify_claims_accepts_a_missing_email_verified_when_provider_opts_out() {
        let provider = test_provider();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "aud": provider.client_id,
            "sub": "user-sub-42",
            "email": "person@example.com",
            "nonce": "expected-nonce",
            "exp": (chrono::Utc::now().timestamp() + 300),
        });
        let (token, header, jwks) = sign_test_token(&claims);
        let jwk = jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let identity = verify_claims(jwk, &header, &provider, &token, Some("expected-nonce"))
            .expect(
                "missing claim must still be accepted when require_email_verified_claim is false",
            );
        assert_eq!(identity.sub, "user-sub-42");
    }

    /// Security contract I10 (attome-auth hardening 1.7): only a cached set is
    /// ever refetched, and only by the caller that won the gate.
    #[test]
    fn an_unknown_kid_is_refetched_only_from_a_cached_set_by_the_gate_winner() {
        assert_eq!(on_unknown_kid(true, true), UnknownKid::Refetch);
        assert_eq!(on_unknown_kid(true, false), UnknownKid::Reject);
        assert_eq!(on_unknown_kid(false, true), UnknownKid::Reject);
        assert_eq!(on_unknown_kid(false, false), UnknownKid::Reject);
    }
}
