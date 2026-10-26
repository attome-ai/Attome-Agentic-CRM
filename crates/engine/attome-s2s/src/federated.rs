//! S11-T2: access tokens for tokens from the customer's own identity
//! provider (Entra ID workload identity, Google service accounts, AWS
//! through an OIDC provider, any OIDC issuer).
//!
//! An administrator registers a trust on an S2S client: an issuer, the
//! audience its tokens must carry, the exact `sub` of the workload, and the
//! issuer's JWKS URL. The workload then asks `POST /api/v1/oauth/token` with
//! `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and its own
//! identity token as `assertion` (RFC 7523 §2.1), and gets this
//! deployment's ten-minute access token for the client's service account,
//! exactly as if the client had authenticated itself. No secret of ours is
//! held by the workload.
//!
//! The token is accepted only when its signature verifies with a key from the
//! trust's JWKS (an asymmetric algorithm only), its `iss` is exactly the
//! trust's issuer, its `aud` holds exactly the trust's audience, its `sub` is
//! exactly the trust's subject, and it has not expired (30 s leeway).
//!
//! The JWKS cache is process-local (guidelines §5: read-only, rebuilt from
//! the issuer, one entry per configured JWKS URL): a set is trusted for ten
//! minutes; a `kid` missing from a cached set refetches it at most once a
//! minute per URL. When the set cannot be fetched and no fresh cached set
//! holds the key, the token is refused (fail closed).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_db::DbPool;
use attome_types::AppError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use uuid::Uuid;

/// The RFC 7523 §2.1 grant type.
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// How long a fetched key set is trusted.
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);
/// How often an unknown `kid` may refetch one URL's set.
const REFETCH_GATE: Duration = Duration::from_secs(60);
/// The whole JWKS fetch, connect to last byte.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest key set read.
const JWKS_MAX_BYTES: usize = 256 * 1024;
/// Clock skew allowed on `exp` and `nbf`.
const LEEWAY_SECS: u64 = 30;

/// One registered trust: tokens from `issuer` for `audience` whose `sub` is
/// `subject` act as the S2S client `client_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    pub id: Uuid,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub jwks_uri: String,
    pub client_id: String,
}

/// Why an identity token was refused. Neither names the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FederatedError {
    /// No trust matches, or the token fails a check.
    #[error("the assertion is not a token this deployment trusts")]
    Untrusted,
    /// The issuer's keys could not be fetched and none is cached.
    #[error("the issuer's signing keys are unavailable")]
    KeysUnavailable,
}

struct Cached {
    keys: JwkSet,
    fetched: Instant,
    refetched: Option<Instant>,
}

static JWKS: LazyLock<Mutex<HashMap<String, Cached>>> = LazyLock::new(Default::default);

static CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
});

/// The `iss` of a JWT, read without verifying it, to pick the trusts whose
/// keys verify it.
pub fn unverified_issuer(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Peek {
        iss: String,
    }
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Peek>(&bytes).ok().map(|p| p.iss)
}

/// The active trusts for `issuer`, each with its client's id.
pub async fn trusts_for_issuer(db: &DbPool, issuer: &str) -> Result<Vec<Trust>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, String, String)>(
        r#"
        SELECT t.id, t.issuer, t.audience, t.subject, t.jwks_uri, c.client_id
        FROM s2s_federated_trust t
        JOIN s2s_client c ON c.id = t.client_ref
        WHERE t.issuer = $1 AND t.is_deleted = FALSE AND c.is_deleted = FALSE
        ORDER BY t.created_at
        "#,
    )
    .bind(issuer)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|r| Trust {
            id: r.0,
            issuer: r.1,
            audience: r.2,
            subject: r.3,
            jwks_uri: r.4,
            client_id: r.5,
        })
        .collect())
}

/// The trust `assertion` satisfies, among `trusts`.
pub async fn verify(trusts: &[Trust], assertion: &str) -> Result<Trust, FederatedError> {
    let header = decode_header(assertion).map_err(|_| FederatedError::Untrusted)?;
    // A shared-secret algorithm would let anyone holding the public key
    // forge a token.
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    ) {
        return Err(FederatedError::Untrusted);
    }
    let issuer = unverified_issuer(assertion).ok_or(FederatedError::Untrusted)?;
    let mut outcome = Err(FederatedError::Untrusted);
    for trust in trusts.iter().filter(|t| t.issuer == issuer) {
        let jwk = match signing_key(&trust.jwks_uri, header.kid.as_deref()).await {
            Ok(jwk) => jwk,
            Err(e) => {
                outcome = Err(e);
                continue;
            }
        };
        let Ok(key) = DecodingKey::from_jwk(&jwk) else {
            continue;
        };
        if let Some(subject) = verified_subject(assertion, &key, header.alg, trust)
            && subject == trust.subject
        {
            return Ok(trust.clone());
        }
        outcome = Err(FederatedError::Untrusted);
    }
    outcome
}

/// The `sub` of `assertion` when its signature, issuer, audience and expiry
/// check out against `trust`.
fn verified_subject(
    assertion: &str,
    key: &DecodingKey,
    alg: Algorithm,
    trust: &Trust,
) -> Option<String> {
    #[derive(Deserialize)]
    struct Claims {
        sub: String,
    }
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[trust.issuer.as_str()]);
    validation.set_audience(&[trust.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = LEEWAY_SECS;
    validation.validate_nbf = true;
    decode::<Claims>(assertion, key, &validation)
        .ok()
        .map(|data| data.claims.sub)
}

/// The key `kid` names in the set at `jwks_uri` (or its only key when the
/// token names none), from the cache when it is fresh.
async fn signing_key(jwks_uri: &str, kid: Option<&str>) -> Result<Jwk, FederatedError> {
    let cached = JWKS.lock().ok().and_then(|cache| {
        cache
            .get(jwks_uri)
            .filter(|c| c.fetched.elapsed() < JWKS_TTL)
            .map(|c| c.keys.clone())
    });
    let (keys, from_cache) = match cached {
        Some(keys) => (keys, true),
        None => (fetch_and_store(jwks_uri).await?, false),
    };
    if let Some(jwk) = find(&keys, kid) {
        return Ok(jwk);
    }
    // A cached set may predate a key rotation; a fresh one is current.
    if !from_cache || !take_refetch_gate(jwks_uri) {
        return Err(FederatedError::Untrusted);
    }
    let keys = fetch_and_store(jwks_uri).await?;
    find(&keys, kid).ok_or(FederatedError::Untrusted)
}

fn find(keys: &JwkSet, kid: Option<&str>) -> Option<Jwk> {
    match kid {
        Some(kid) => keys.find(kid).cloned(),
        None => match keys.keys.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        },
    }
}

/// Whether this caller may refetch `jwks_uri` now (at most once per
/// [`REFETCH_GATE`]).
fn take_refetch_gate(jwks_uri: &str) -> bool {
    let Ok(mut cache) = JWKS.lock() else {
        return false;
    };
    let Some(entry) = cache.get_mut(jwks_uri) else {
        return false;
    };
    if entry
        .refetched
        .is_some_and(|at| at.elapsed() < REFETCH_GATE)
    {
        return false;
    }
    entry.refetched = Some(Instant::now());
    true
}

async fn fetch_and_store(jwks_uri: &str) -> Result<JwkSet, FederatedError> {
    let keys = match fetch(jwks_uri).await {
        Some(keys) => keys,
        None => {
            tracing::warn!(jwks_uri, "s2s: federated JWKS fetch failed; refusing");
            return Err(FederatedError::KeysUnavailable);
        }
    };
    if let Ok(mut cache) = JWKS.lock() {
        let refetched = cache.get(jwks_uri).and_then(|c| c.refetched);
        cache.insert(
            jwks_uri.to_owned(),
            Cached {
                keys: keys.clone(),
                fetched: Instant::now(),
                refetched,
            },
        );
    }
    Ok(keys)
}

/// `GET` the set, bounded in time and size; `None` on any failure.
async fn fetch(jwks_uri: &str) -> Option<JwkSet> {
    let client = CLIENT.as_ref()?;
    let mut response = client
        .get(jwks_uri)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    if response
        .content_length()
        .is_some_and(|len| len > JWKS_MAX_BYTES as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > JWKS_MAX_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Json, Router, extract::State, routing::get};
    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;

    // Throwaway Ed25519 keys made for these tests; they protect nothing.
    const KEY_A: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKGvSH4icPxR6aIiP1dp9oGC8y57WLtjurzxr3lMhll2
-----END PRIVATE KEY-----
";
    const KEY_A_X: &str = "Nn39cFB4V0iCg9q-3xjQH675UnqR52iOp-L_zZqNB0E";
    const KEY_B: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEzaX7RMboXhb3ANfYp6ZypgD78JONG/r7DXDYYEeWmh
-----END PRIVATE KEY-----
";
    const KEY_B_X: &str = "RGtRpmpl7wHNuWrDtZfZsuegLrIjpQ22lkN10_hlT00";
    const ISSUER: &str = "https://login.example.com/tenant-1/v2.0";
    const AUDIENCE: &str = "api://attome-crm";
    const SUBJECT: &str = "workload-erp-sync";

    fn jwk(kid: &str, x: &str) -> serde_json::Value {
        serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig" })
    }

    /// A local JWKS server answering whatever `keys` holds now, counting
    /// fetches.
    struct Server {
        url: String,
        keys: Arc<Mutex<serde_json::Value>>,
        hits: Arc<AtomicUsize>,
    }

    async fn jwks_server(keys: serde_json::Value) -> Server {
        let keys = Arc::new(Mutex::new(serde_json::json!({ "keys": keys })));
        let hits = Arc::new(AtomicUsize::new(0));
        let state = (keys.clone(), hits.clone());
        let app = Router::new()
            .route(
                "/jwks",
                get(
                    |State((keys, hits)): State<(
                        Arc<Mutex<serde_json::Value>>,
                        Arc<AtomicUsize>,
                    )>| async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Json(keys.lock().unwrap().clone())
                    },
                ),
            )
            .with_state(state);
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", tcp.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(tcp, app).await });
        Server { url, keys, hits }
    }

    fn trust(jwks_uri: &str) -> Trust {
        Trust {
            id: Uuid::now_v7(),
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            subject: SUBJECT.into(),
            jwks_uri: jwks_uri.into(),
            client_id: "erp-sync".into(),
        }
    }

    fn token(key: &str, kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(key.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn claims() -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": SUBJECT, "iat": now, "exp": now + 300 })
    }

    fn with(field: &str, value: serde_json::Value) -> serde_json::Value {
        let mut claims = claims();
        claims[field] = value;
        claims
    }

    #[tokio::test]
    async fn federated_trusted_token_maps_to_its_client() {
        let server = jwks_server(serde_json::json!([jwk("k1", KEY_A_X)])).await;
        let trusts = [trust(&server.url)];
        let found = verify(&trusts, &token(KEY_A, "k1", claims())).await;
        assert_eq!(found.map(|t| t.client_id), Ok("erp-sync".to_owned()));
        // An array audience holding ours is accepted too.
        let array = with("aud", serde_json::json!(["other", AUDIENCE]));
        assert!(verify(&trusts, &token(KEY_A, "k1", array)).await.is_ok());
        // The set is cached: one fetch for both.
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn federated_other_tokens_are_refused() {
        let server = jwks_server(serde_json::json!([jwk("k1", KEY_A_X)])).await;
        let trusts = [trust(&server.url)];
        let refused = |claims| {
            let assertion = token(KEY_A, "k1", claims);
            let trusts = trusts.clone();
            async move { verify(&trusts, &assertion).await }
        };
        assert_eq!(
            refused(with("aud", "api://other".into())).await,
            Err(FederatedError::Untrusted),
            "another audience"
        );
        assert_eq!(
            refused(with("sub", "workload-other".into())).await,
            Err(FederatedError::Untrusted),
            "another subject"
        );
        assert_eq!(
            refused(with("iss", "https://evil.example.com".into())).await,
            Err(FederatedError::Untrusted),
            "another issuer"
        );
        let past = chrono::Utc::now().timestamp() - 3600;
        assert_eq!(
            refused(with("exp", past.into())).await,
            Err(FederatedError::Untrusted),
            "expired"
        );
        assert_eq!(
            verify(&trusts, &token(KEY_B, "k1", claims())).await,
            Err(FederatedError::Untrusted),
            "signed by a key the issuer does not publish"
        );
        // A shared-secret token, even with the right claims.
        let hs = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(KEY_A_X.as_bytes()),
        )
        .unwrap();
        assert_eq!(verify(&trusts, &hs).await, Err(FederatedError::Untrusted));
        assert_eq!(
            verify(&[], &token(KEY_A, "k1", claims())).await,
            Err(FederatedError::Untrusted)
        );
    }

    #[tokio::test]
    async fn federated_unreachable_jwks_fails_closed() {
        // A port nothing listens on.
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/jwks", tcp.local_addr().unwrap());
        drop(tcp);
        assert_eq!(
            verify(&[trust(&url)], &token(KEY_A, "k1", claims())).await,
            Err(FederatedError::KeysUnavailable)
        );
    }

    #[tokio::test]
    async fn federated_rotated_key_is_refetched_once() {
        let server = jwks_server(serde_json::json!([jwk("k1", KEY_A_X)])).await;
        let trusts = [trust(&server.url)];
        assert!(verify(&trusts, &token(KEY_A, "k1", claims())).await.is_ok());
        // The issuer rotates to k2; the cached set lacks it and is fetched
        // again.
        *server.keys.lock().unwrap() = serde_json::json!({ "keys": [jwk("k2", KEY_B_X)] });
        assert!(verify(&trusts, &token(KEY_B, "k2", claims())).await.is_ok());
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
        // An unknown kid now refetches no more within the gate.
        assert_eq!(
            verify(&trusts, &token(KEY_A, "k3", claims())).await,
            Err(FederatedError::Untrusted)
        );
        assert_eq!(
            verify(&trusts, &token(KEY_A, "k4", claims())).await,
            Err(FederatedError::Untrusted)
        );
        assert!(
            server.hits.load(Ordering::SeqCst) <= 3,
            "the refetch is gated"
        );
    }
}
