//! S11-T1: the OAuth 2.0 token endpoint's core, client credentials grant.
//!
//! A server-to-server client asks for a short-lived access token instead of
//! signing every request. It proves who it is one of two ways:
//!
//! - `private_key_jwt` (RFC 7523): a JWT it signed with its own private key
//!   (RS256, ES256 or EdDSA; never an HMAC), whose `iss` and `sub` are its
//!   client id, whose `aud` is this token endpoint, which expires within five
//!   minutes, and whose `jti` is used once;
//! - `client_secret_basic` (RFC 6749 §2.3.1): its client id and secret in the
//!   `Authorization: Basic` header, checked by the directory against the
//!   stored hash.
//!
//! It gets a ten-minute access token for its service account, with the
//! scopes it asked for (or all it holds), signed with the deployment's JWT
//! keys and typed `s2s_access`, so no other validator accepts it and it
//! accepts no other token ([`validate_access_token`]).
//!
//! This crate knows no client table: the clients come from a
//! [`ClientDirectory`] the S2S engine implements, so the dependency points
//! down (guidelines §1).

use std::future::Future;

use attome_config::KeyRing;
use attome_types::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::session::{SessionClaims, TokenType};

/// How long an issued access token lives.
pub const ACCESS_TOKEN_TTL_SECS: i64 = 600;

/// The longest a client assertion may live (RFC 7523 asks for short).
pub const MAX_ASSERTION_LIFETIME_SECS: i64 = 300;

/// Clock skew allowed on an assertion's times.
const LEEWAY_SECS: u64 = 30;

/// The `client_assertion_type` of a JWT client assertion.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A client, as the directory knows it.
#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub client_id: String,
    /// The service account the client acts as.
    pub service_user_id: Uuid,
    /// The scopes it may be granted.
    pub scopes: Vec<String>,
    /// Its public key (PEM), for `private_key_jwt`; `None` when it uses a
    /// secret only.
    pub public_key_pem: Option<String>,
    /// Whether it may get tokens now (not suspended or revoked).
    pub active: bool,
}

/// Where the token endpoint finds clients. Implemented by the S2S engine.
pub trait ClientDirectory: Send + Sync {
    /// The client `client_id` names, or `None`.
    fn find(
        &self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<ClientRecord>, AppError>> + Send;

    /// Whether `secret` is `client_id`'s secret, compared in constant time.
    fn secret_matches(
        &self,
        client_id: &str,
        secret: &str,
    ) -> impl Future<Output = Result<bool, AppError>> + Send;

    /// Records assertion `jti` of `client_id` as used until `until` (unix
    /// seconds); `false` when it was used already. Fails closed: an error is
    /// a refusal.
    fn claim_jti(
        &self,
        client_id: &str,
        jti: &str,
        until: i64,
    ) -> impl Future<Output = Result<bool, AppError>> + Send;
}

/// A token request, as the route parsed it.
#[derive(Debug, Clone, Default)]
pub struct TokenRequest {
    pub grant_type: String,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    /// `Authorization: Basic` credentials, decoded.
    pub basic: Option<(String, String)>,
}

/// An RFC 6749 §5.1 token response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

/// An RFC 6749 §5.2 error. Its text is fixed: it never says which check an
/// assertion failed, which would help a forger.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid_request")]
    InvalidRequest(&'static str),
    #[error("invalid_client")]
    InvalidClient,
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_scope")]
    InvalidScope,
    #[error("server_error")]
    Server,
}

impl OAuthError {
    /// The RFC 6749 error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::Server => "server_error",
        }
    }

    /// The HTTP status RFC 6749 gives it.
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidClient => 401,
            Self::Server => 500,
            _ => 400,
        }
    }
}

/// The deployment values a token is issued against.
#[derive(Debug, Clone, Copy)]
pub struct Issuer<'a> {
    /// The JWT `iss` of access tokens (`auth.jwt_issuer`).
    pub issuer: &'a str,
    /// The `aud` an access token carries.
    pub access_audience: &'a str,
    /// What a client assertion's `aud` may name: this token endpoint's URL,
    /// or the issuer (RFC 7523 §3 allows either).
    pub token_audiences: &'a [&'a str],
    pub ring: &'a KeyRing,
    /// Now, in unix seconds.
    pub now: i64,
}

#[derive(Debug, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    jti: Option<String>,
}

/// An access token's claims: a session-shaped token typed `s2s_access`,
/// plus the client and its scopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    #[serde(flatten)]
    pub claims: SessionClaims,
    /// The client the token was issued to.
    pub client_id: String,
    /// Space-separated scopes.
    pub scope: String,
}

fn decoding_key(alg: Algorithm, pem: &str) -> Option<DecodingKey> {
    match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::PS256 => {
            DecodingKey::from_rsa_pem(pem.as_bytes()).ok()
        }
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(pem.as_bytes()).ok(),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(pem.as_bytes()).ok(),
        // A shared-secret algorithm would let anyone holding the public key
        // forge an assertion.
        _ => None,
    }
}

/// Whether `pem` is a public key an assertion can be checked with (RSA,
/// P-256 or P-384, Ed25519). The admin API refuses any other before storing it.
pub fn public_key_is_usable(pem: &str) -> bool {
    [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA]
        .into_iter()
        .any(|alg| decoding_key(alg, pem).is_some())
}

/// Checks a `private_key_jwt` assertion; answers the client it names.
async fn authenticate_assertion<D: ClientDirectory>(
    dir: &D,
    assertion: &str,
    claimed_client: Option<&str>,
    at: &Issuer<'_>,
) -> Result<ClientRecord, OAuthError> {
    let header = decode_header(assertion).map_err(|_| OAuthError::InvalidClient)?;
    // The client is named by the assertion itself; read `iss` before the
    // signature is checked only to find which key checks it.
    let unverified: AssertionClaims = {
        let mut peek = Validation::new(header.alg);
        peek.insecure_disable_signature_validation();
        peek.validate_exp = false;
        peek.validate_aud = false;
        decode::<AssertionClaims>(assertion, &DecodingKey::from_secret(&[]), &peek)
            .map_err(|_| OAuthError::InvalidClient)?
            .claims
    };
    if claimed_client.is_some_and(|c| c != unverified.iss) {
        return Err(OAuthError::InvalidClient);
    }
    let client = dir
        .find(&unverified.iss)
        .await
        .map_err(|_| OAuthError::Server)?
        .filter(|c| c.active)
        .ok_or(OAuthError::InvalidClient)?;
    let pem = client
        .public_key_pem
        .as_deref()
        .ok_or(OAuthError::InvalidClient)?;
    let key = decoding_key(header.alg, pem).ok_or(OAuthError::InvalidClient)?;

    let mut validation = Validation::new(header.alg);
    validation.set_audience(at.token_audiences);
    validation.set_issuer(&[client.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation.leeway = LEEWAY_SECS;
    let claims = decode::<AssertionClaims>(assertion, &key, &validation)
        .map_err(|_| OAuthError::InvalidClient)?
        .claims;
    if claims.sub != client.client_id || claims.iss != client.client_id {
        return Err(OAuthError::InvalidClient);
    }
    // A long-lived assertion is a reusable credential; refuse it.
    let issued = claims.iat.unwrap_or(at.now).min(at.now);
    if claims.exp - issued > MAX_ASSERTION_LIFETIME_SECS + LEEWAY_SECS as i64 {
        return Err(OAuthError::InvalidClient);
    }
    let jti = claims
        .jti
        .as_deref()
        .filter(|j| !j.is_empty() && j.len() <= 256)
        .ok_or(OAuthError::InvalidClient)?;
    let fresh = dir
        .claim_jti(&client.client_id, jti, claims.exp + LEEWAY_SECS as i64)
        .await
        .map_err(|_| OAuthError::Server)?;
    if !fresh {
        return Err(OAuthError::InvalidClient);
    }
    Ok(client)
}

/// Checks `client_secret_basic` credentials.
async fn authenticate_secret<D: ClientDirectory>(
    dir: &D,
    client_id: &str,
    secret: &str,
) -> Result<ClientRecord, OAuthError> {
    let client = dir
        .find(client_id)
        .await
        .map_err(|_| OAuthError::Server)?
        .filter(|c| c.active);
    let matches = dir
        .secret_matches(client_id, secret)
        .await
        .map_err(|_| OAuthError::Server)?;
    match client {
        Some(client) if matches => Ok(client),
        _ => Err(OAuthError::InvalidClient),
    }
}

/// The scopes granted: the requested ones, each held by the client, or all
/// it holds when it asked for none.
fn grant_scopes(requested: Option<&str>, held: &[String]) -> Result<Vec<String>, OAuthError> {
    let asked: Vec<&str> = requested
        .map(|s| s.split_whitespace().collect())
        .unwrap_or_default();
    if asked.is_empty() {
        return Ok(held.to_vec());
    }
    if asked.iter().any(|s| !held.iter().any(|h| h == s)) {
        return Err(OAuthError::InvalidScope);
    }
    Ok(asked.into_iter().map(str::to_owned).collect())
}

/// Answers a client credentials token request.
pub async fn issue<D: ClientDirectory>(
    dir: &D,
    request: &TokenRequest,
    at: &Issuer<'_>,
) -> Result<TokenResponse, OAuthError> {
    if request.grant_type != "client_credentials" {
        return Err(OAuthError::UnsupportedGrantType);
    }
    let client = match (&request.client_assertion, &request.basic) {
        (Some(_), Some(_)) => {
            return Err(OAuthError::InvalidRequest(
                "use one client authentication method",
            ));
        }
        (Some(assertion), None) => {
            if request.client_assertion_type.as_deref() != Some(JWT_BEARER) {
                return Err(OAuthError::InvalidRequest(
                    "unsupported client_assertion_type",
                ));
            }
            authenticate_assertion(dir, assertion, request.client_id.as_deref(), at).await?
        }
        (None, Some((id, secret))) => authenticate_secret(dir, id, secret).await?,
        (None, None) => return Err(OAuthError::InvalidClient),
    };
    let scopes = grant_scopes(request.scope.as_deref(), &client.scopes)?;
    let scope = scopes.join(" ");
    let claims = AccessClaims {
        claims: SessionClaims {
            sub: client.service_user_id,
            iat: at.now,
            exp: at.now + ACCESS_TOKEN_TTL_SECS,
            jti: Uuid::now_v7(),
            epoch: 0,
            iss: at.issuer.to_owned(),
            aud: at.access_audience.to_owned(),
            typ: TokenType::S2sAccess,
        },
        client_id: client.client_id,
        scope: scope.clone(),
    };
    let access_token =
        crate::jwt::encode_claims(&claims, at.ring).map_err(|_| OAuthError::Server)?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_owned(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope,
    })
}

/// Validates an access token from [`issue`]: signature, type `s2s_access`,
/// issuer and audience, and expiry. Any other token type is refused, and no
/// other validator accepts this one.
pub fn validate_access_token(
    token: &str,
    ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<AccessClaims, AppError> {
    let claims: AccessClaims = crate::jwt::decode_claims(token, ring)?;
    if claims.claims.typ != TokenType::S2sAccess
        || claims.claims.iss != issuer
        || claims.claims.aud != audience
    {
        return Err(AppError::Unauthorized);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;

    /// Test-only P-256 keys, made for these tests.
    const CLIENT_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCim2L/EAbV3IT+UZ
2ZPOXmlce20TE7w+XhmJ0Q/8sFOhRANCAASLPmyRKpW2abVhAo3+Czge8Rj7QJaY
RIzstuFq0oxqQPo+BcrfBcR1mj+Nx1qOsx7SjaHtS9+aXpuzf/lcdEmV
-----END PRIVATE KEY-----
";
    const CLIENT_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiz5skSqVtmm1YQKN/gs4HvEY+0CW
mESM7LbhatKMakD6PgXK3wXEdZo/jcdajrMe0o2h7Uvfml6bs3/5XHRJlQ==
-----END PUBLIC KEY-----
";
    const OTHER_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDLpcRQrV5eW5e1G2
jEF5I/bRRwAjR1xqoMwi0bwPKO+hRANCAATUXpuihvjI64FG0RJ+VJoQu3jenCaI
nJq+v4xau8PWz8TvW3qRj14fdpYjEVoaZQ8F5LeLoV3ItjnD7qvJaKmU
-----END PRIVATE KEY-----
";
    const ENDPOINT: &str = "https://crm.example.com/oauth/token";
    const NOW: i64 = 1_800_000_000;

    struct Directory {
        client: ClientRecord,
        used: Mutex<HashSet<String>>,
    }

    impl ClientDirectory for Directory {
        async fn find(&self, client_id: &str) -> Result<Option<ClientRecord>, AppError> {
            Ok((client_id == self.client.client_id).then(|| self.client.clone()))
        }
        async fn secret_matches(&self, client_id: &str, secret: &str) -> Result<bool, AppError> {
            Ok(client_id == self.client.client_id && secret == "s3cret-value")
        }
        async fn claim_jti(
            &self,
            client_id: &str,
            jti: &str,
            _until: i64,
        ) -> Result<bool, AppError> {
            Ok(self
                .used
                .lock()
                .unwrap()
                .insert(format!("{client_id}:{jti}")))
        }
    }

    fn directory() -> Directory {
        Directory {
            client: ClientRecord {
                client_id: "erp-sync".into(),
                service_user_id: Uuid::now_v7(),
                scopes: vec!["records.read".into(), "records.write".into()],
                public_key_pem: Some(CLIENT_PUBLIC.into()),
                active: true,
            },
            used: Mutex::new(HashSet::new()),
        }
    }

    fn ring() -> KeyRing {
        KeyRing::single("test-only-throwaway-secret-32-bytes-min".into())
    }

    fn at(ring: &KeyRing) -> Issuer<'_> {
        Issuer {
            issuer: "attome-test",
            access_audience: "attome-test",
            token_audiences: &[ENDPOINT],
            ring,
            now: NOW,
        }
    }

    fn assertion(key: &str, aud: &str, exp: i64, jti: &str) -> String {
        let claims = serde_json::json!({
            "iss": "erp-sync", "sub": "erp-sync", "aud": aud,
            "iat": NOW, "exp": exp, "jti": jti,
        });
        encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &EncodingKey::from_ec_pem(key.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn jwt_request(assertion: String) -> TokenRequest {
        TokenRequest {
            grant_type: "client_credentials".into(),
            client_assertion_type: Some(JWT_BEARER.into()),
            client_assertion: Some(assertion),
            ..TokenRequest::default()
        }
    }

    #[tokio::test]
    async fn oauth_token_valid_jwt_assertion_issues_a_typed_token() {
        // The real clock: `jsonwebtoken` checks `exp` against now.
        let now = chrono::Utc::now().timestamp();
        let ring = ring();
        let mut at = at(&ring);
        at.now = now;
        let dir = directory();
        let mut request = jwt_request(assertion(CLIENT_KEY, ENDPOINT, now + 120, "a-1"));
        request.scope = Some("records.read".into());
        let response = issue(&dir, &request, &at).await.expect("a token");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 600);
        assert_eq!(response.scope, "records.read");

        let claims =
            validate_access_token(&response.access_token, &ring, "attome-test", "attome-test")
                .unwrap();
        assert_eq!(claims.claims.sub, dir.client.service_user_id);
        assert_eq!(claims.client_id, "erp-sync");
        assert_eq!(claims.claims.typ, TokenType::S2sAccess);
        assert!(
            crate::jwt::validate_token(&response.access_token, &ring, "attome-test", "attome-test")
                .is_err(),
            "a session validator never accepts an s2s token"
        );
        assert!(
            validate_access_token(&response.access_token, &ring, "attome-test", "other").is_err()
        );
    }

    #[tokio::test]
    async fn oauth_token_replayed_jti_is_refused() {
        let now = chrono::Utc::now().timestamp();
        let ring = ring();
        let mut at = at(&ring);
        at.now = now;
        let dir = directory();
        let first = assertion(CLIENT_KEY, ENDPOINT, now + 120, "same-jti");
        assert!(issue(&dir, &jwt_request(first.clone()), &at).await.is_ok());
        assert_eq!(
            issue(&dir, &jwt_request(first), &at).await,
            Err(OAuthError::InvalidClient)
        );
    }

    #[tokio::test]
    async fn oauth_token_expired_or_long_lived_assertion_is_refused() {
        let now = chrono::Utc::now().timestamp();
        let ring = ring();
        let mut at = at(&ring);
        at.now = now;
        let dir = directory();
        let expired = assertion(CLIENT_KEY, ENDPOINT, now - 120, "e-1");
        assert_eq!(
            issue(&dir, &jwt_request(expired), &at).await,
            Err(OAuthError::InvalidClient)
        );
        let long = assertion(CLIENT_KEY, ENDPOINT, now + 3_600, "e-2");
        assert_eq!(
            issue(&dir, &jwt_request(long), &at).await,
            Err(OAuthError::InvalidClient)
        );
    }

    #[tokio::test]
    async fn oauth_token_wrong_audience_or_key_is_refused() {
        let now = chrono::Utc::now().timestamp();
        let ring = ring();
        let mut at = at(&ring);
        at.now = now;
        let dir = directory();
        let wrong_aud = assertion(
            CLIENT_KEY,
            "https://elsewhere.example/token",
            now + 60,
            "w-1",
        );
        assert_eq!(
            issue(&dir, &jwt_request(wrong_aud), &at).await,
            Err(OAuthError::InvalidClient)
        );
        let wrong_key = assertion(OTHER_KEY, ENDPOINT, now + 60, "w-2");
        assert_eq!(
            issue(&dir, &jwt_request(wrong_key), &at).await,
            Err(OAuthError::InvalidClient)
        );
    }

    #[tokio::test]
    async fn oauth_token_secret_basic_scopes_and_grant_type() {
        let ring = ring();
        let at = at(&ring);
        let dir = directory();
        let basic = |secret: &str| TokenRequest {
            grant_type: "client_credentials".into(),
            basic: Some(("erp-sync".into(), secret.into())),
            ..TokenRequest::default()
        };
        let response = issue(&dir, &basic("s3cret-value"), &at).await.unwrap();
        assert_eq!(response.scope, "records.read records.write");
        assert_eq!(
            issue(&dir, &basic("wrong"), &at).await,
            Err(OAuthError::InvalidClient)
        );
        let mut asking_more = basic("s3cret-value");
        asking_more.scope = Some("records.read admin".into());
        assert_eq!(
            issue(&dir, &asking_more, &at).await,
            Err(OAuthError::InvalidScope)
        );
        let mut other_grant = basic("s3cret-value");
        other_grant.grant_type = "password".into();
        assert_eq!(
            issue(&dir, &other_grant, &at).await,
            Err(OAuthError::UnsupportedGrantType)
        );
        assert_eq!(OAuthError::InvalidClient.status(), 401);
        assert!(public_key_is_usable(CLIENT_PUBLIC));
        assert!(!public_key_is_usable("not a key"));
    }
}
