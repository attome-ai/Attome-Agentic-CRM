//! S11-T1: the OAuth 2.0 token endpoint for S2S clients.
//!
//! `POST /api/v1/oauth/token` (client credentials grant) answers a client
//! with a ten-minute access token for its service user; the client then
//! sends `Authorization: Bearer <token>` instead of signing each request,
//! and [`crate::middleware::s2s_authn`] accepts it with the same checks as a
//! signed call (status, idle limit, IP allow-list, rate and concurrency
//! limits, entity ceiling).
//!
//! The checks themselves are `attome_auth::oauth_token`; this module is the
//! [`ClientDirectory`] it reads `s2s_client` through, and the route. A
//! client proves itself with a JWT signed by the key in
//! `s2s_client.oauth_public_key_pem` (private_key_jwt), or with one of its
//! active keys' secrets in `Authorization: Basic` (client_secret_basic).
//! The scopes it may be granted are `s2s_client.oauth_scopes`.

use attome_audit::security::{MandatoryCategory, SecurityAuditor, SecurityEvent, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_auth::oauth_token::{
    self, AccessClaims, ClientDirectory, ClientRecord, Issuer, OAuthError, TokenRequest,
};
use attome_cache::Store;
use attome_config::KeyRing;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{crypto, rate_limit};

/// The token endpoint's path (public: in `EXACT_BYPASS_PATHS`).
pub const TOKEN_PATH: &str = "/api/v1/oauth/token";

/// The message both secrets are keyed over, so comparing them is one
/// constant-time MAC check.
const SECRET_CONTEXT: &[u8] = b"attome-s2s/oauth-client-secret";

/// `s2s_client` as the token endpoint sees it.
pub struct PgClientDirectory<'a> {
    pub db: &'a DbPool,
    pub redis: &'a Store,
    /// Opens the stored key secrets (`s2s_key_encryption_key`).
    pub key_ring: &'a KeyRing,
}

impl std::fmt::Debug for PgClientDirectory<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgClientDirectory").finish_non_exhaustive()
    }
}

/// Whether a client last used `idle_days` ago is past its limit.
fn idle_too_long(last_used: Option<DateTime<Utc>>, limit_days: i32) -> bool {
    last_used.is_some_and(|last| (Utc::now() - last).num_days() >= i64::from(limit_days))
}

/// Whether `given` is `stored`, without a timing difference: each keys the
/// same MAC, and the MACs are compared in constant time.
fn secrets_equal(stored: &str, given: &str) -> bool {
    crypto::sign_hmac(stored, SECRET_CONTEXT)
        .is_some_and(|mac| crypto::verify_hmac(given, SECRET_CONTEXT, &mac))
}

impl ClientDirectory for PgClientDirectory<'_> {
    async fn find(&self, client_id: &str) -> Result<Option<ClientRecord>, AppError> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<Uuid>,
                Vec<String>,
                Option<String>,
                Option<DateTime<Utc>>,
                i32,
            ),
        >(
            r#"
            SELECT client_id, status, service_user_ref, oauth_scopes,
                   oauth_public_key_pem, last_used_at, auto_disable_days
            FROM s2s_client
            WHERE client_id = $1 AND is_deleted = FALSE
            "#,
        )
        .bind(client_id)
        .fetch_optional(self.db)
        .await
        .map_err(AppError::internal)?;
        // A client with no service user has no principal to issue a token
        // for (B9), as on the signed path.
        Ok(row.and_then(|r| {
            Some(ClientRecord {
                active: r.1 == "active" && !idle_too_long(r.5, r.6),
                client_id: r.0,
                service_user_id: r.2?,
                scopes: r.3,
                public_key_pem: r.4,
            })
        }))
    }

    async fn secret_matches(&self, client_id: &str, secret: &str) -> Result<bool, AppError> {
        let keys = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT k.id, k.secret_encrypted
            FROM s2s_client_key k
            JOIN s2s_client c ON c.id = k.client_ref
            WHERE c.client_id = $1
              AND c.is_deleted = FALSE
              AND k.is_deleted = FALSE
              AND k.status = 'active'
              AND (k.expires_at IS NULL OR k.expires_at > now())
            "#,
        )
        .bind(client_id)
        .fetch_all(self.db)
        .await
        .map_err(AppError::internal)?;
        let mut matched = false;
        // Every key is checked, so the answer takes as long either way.
        for (key_id, encrypted) in keys {
            let stored = crypto::decrypt_key_secret(self.key_ring, key_id, &encrypted)?;
            matched |= secrets_equal(&stored, secret);
        }
        Ok(matched)
    }

    async fn claim_jti(&self, client_id: &str, jti: &str, _until: i64) -> Result<bool, AppError> {
        // The signed path's nonce guard: its TTL (`NONCE_TTL_SECS`, ten
        // minutes) outlives any assertion the token endpoint accepts (at
        // most five minutes plus leeway). The request counts in the
        // client's per-minute window like a signed call; the endpoint's own
        // limit is its pre-auth budget, so no limit is checked here.
        match rate_limit::check_with_nonce(self.redis, client_id, &format!("jwt:{jti}"), i32::MAX)
            .await
        {
            Ok(()) => Ok(true),
            Err(AppError::Conflict(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// A token request (RFC 6749 §4.4.2, RFC 7523 §2.2), form-encoded.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenForm {
    /// Always `client_credentials`.
    grant_type: String,
    /// Space-separated scopes; omit for every scope the client holds.
    scope: Option<String>,
    client_id: Option<String>,
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
    client_assertion_type: Option<String>,
    /// The client's signed JWT.
    client_assertion: Option<String>,
}

/// An issued access token (RFC 6749 §5.1).
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenBody {
    access_token: String,
    /// Always `Bearer`.
    token_type: String,
    /// Seconds until it expires.
    expires_in: i64,
    scope: String,
}

/// A refused token request (RFC 6749 §5.2).
#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthErrorBody {
    /// `invalid_request`, `invalid_client`, `unsupported_grant_type`,
    /// `invalid_scope` or `server_error`.
    error: String,
}

/// `Authorization: Basic` credentials; `None` without the header, an error
/// when it is malformed.
fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let Some(encoded) = value.to_str().ok().and_then(|v| v.strip_prefix("Basic ")) else {
        return Err(OAuthError::InvalidClient);
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(OAuthError::InvalidClient)?;
    let (id, secret) = decoded.split_once(':').ok_or(OAuthError::InvalidClient)?;
    Ok(Some((id.to_owned(), secret.to_owned())))
}

/// A token response or error never sits in a cache (RFC 6749 §5.1).
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn oauth_error(error: &OAuthError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (
        status,
        Json(OAuthErrorBody {
            error: error.code().to_owned(),
        }),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"attome\""),
        );
    }
    no_store(response)
}

/// Writes the issuance's security event; a token is never handed out
/// without one.
async fn audit_issue(state: &EngineState, claims: &AccessClaims) -> Result<(), AppError> {
    let event = SecurityEvent::new(
        MandatoryCategory::Credential,
        AuditOperation::Create,
        claims.claims.sub,
        "s2s_client",
        None,
    )
    .named("s2s_token_issued")
    .comment(format!(
        "client {} scope [{}] token {}",
        claims.client_id, claims.scope, claims.claims.jti
    ));
    let auditor = SecurityAuditor::from_state(state);
    auditor.write(event).await.map(|_| ())
}

#[utoipa::path(
    post,
    path = "/api/v1/oauth/token",
    tag = "auth",
    request_body(content = TokenForm, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "An access token", body = TokenBody),
        (status = 400, description = "Malformed request, grant type or scope", body = OAuthErrorBody),
        (status = 401, description = "The client could not be authenticated", body = OAuthErrorBody),
        (status = 500, description = "The token could not be issued", body = OAuthErrorBody),
    ),
)]
async fn token(
    State(state): State<EngineState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let basic = match basic_credentials(&headers) {
        Ok(basic) => basic,
        Err(e) => return oauth_error(&e),
    };
    let request = TokenRequest {
        grant_type: form.grant_type,
        scope: form.scope,
        client_id: form.client_id,
        client_assertion_type: form.client_assertion_type,
        client_assertion: form.client_assertion,
        basic,
    };
    let base = &state.base;
    let secrets = base.secrets.load();
    let issuer = base.config.auth.jwt_issuer.as_str();
    let endpoint = base
        .config
        .app
        .public_frontend_url
        .as_deref()
        .map(|url| format!("{}{TOKEN_PATH}", url.trim_end_matches('/')));
    let mut audiences = vec![issuer];
    audiences.extend(endpoint.as_deref());
    let at = Issuer {
        issuer,
        access_audience: base.config.jwt_audience(),
        token_audiences: &audiences,
        ring: &secrets.jwt_secret,
        now: Utc::now().timestamp(),
    };
    let directory = PgClientDirectory {
        db: &base.db,
        redis: &base.redis_coordination,
        key_ring: &secrets.s2s_key_encryption_key,
    };
    let issued = match oauth_token::issue(&directory, &request, &at).await {
        Ok(issued) => issued,
        Err(e) => {
            // The client is named only by what it sent; nothing secret.
            tracing::warn!(
                error = e.code(),
                client = request
                    .client_id
                    .as_deref()
                    .or(request.basic.as_ref().map(|(id, _)| id.as_str()))
                    .unwrap_or("-"),
                "s2s: OAuth token refused"
            );
            return oauth_error(&e);
        }
    };
    let claims = match oauth_token::validate_access_token(
        &issued.access_token,
        &secrets.jwt_secret,
        at.issuer,
        at.access_audience,
    ) {
        Ok(claims) => claims,
        Err(e) => {
            tracing::error!(error = %e, "s2s: an issued OAuth token does not validate");
            return oauth_error(&OAuthError::Server);
        }
    };
    if let Err(e) = audit_issue(&state, &claims).await {
        tracing::error!(error = %e, client = %claims.client_id, "s2s: OAuth token issue not audited");
        return oauth_error(&OAuthError::Server);
    }
    tracing::info!(client = %claims.client_id, scope = %claims.scope, "s2s: OAuth token issued");
    no_store(
        Json(TokenBody {
            access_token: issued.access_token,
            token_type: issued.token_type,
            expires_in: issued.expires_in,
            scope: issued.scope,
        })
        .into_response(),
    )
}

pub fn routes() -> Router<EngineState> {
    // A literal path, so the route-authorization scanner sees it.
    Router::new().route("/api/v1/oauth/token", post(token))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(token))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_compare_by_value() {
        let secret = crypto::generate_secret();
        assert!(secrets_equal(&secret, &secret));
        assert!(!secrets_equal(&secret, &crypto::generate_secret()));
        assert!(!secrets_equal(&secret, "not hex"));
    }

    #[test]
    fn basic_credentials_parse() {
        let mut headers = HeaderMap::new();
        assert_eq!(basic_credentials(&headers), Ok(None));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic ZXJwLXN5bmM6czNjcmV0"),
        );
        assert_eq!(
            basic_credentials(&headers),
            Ok(Some(("erp-sync".into(), "s3cret".into())))
        );
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert_eq!(basic_credentials(&headers), Err(OAuthError::InvalidClient));
    }

    #[test]
    fn idle_limit_matches_the_signed_path() {
        assert!(!idle_too_long(None, 90));
        assert!(!idle_too_long(Some(Utc::now()), 90));
        assert!(idle_too_long(
            Some(Utc::now() - chrono::Duration::days(91)),
            90
        ));
    }
}
