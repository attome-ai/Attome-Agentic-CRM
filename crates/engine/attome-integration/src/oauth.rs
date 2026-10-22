//! Z1-T11: OAuth 2.0 tokens for integration systems, stored encrypted and
//! renewed before they expire.
//!
//! Two auth types use it:
//!
//! - `oauth2_client_credentials`: the system's credential is the client's
//!   `{"client_id", "client_secret"}`; a token is asked for with the client
//!   credentials grant.
//! - `oauth2_refresh_token`: the credential also carries the first
//!   `refresh_token` (obtained once, outside Attome, from the provider's
//!   consent screen); each refresh uses the newest refresh token, and a
//!   provider that rotates it gets the new one stored.
//!
//! The system's `config` names the provider's `token_url` and an optional
//! `scope`. Tokens live in `integration_oauth_token`, each column encrypted
//! under `integration.credential_encryption_key` and bound to its system and
//! column ([`crate::crypto::encrypt_token`]).
//!
//! **Concurrency.** A refresh is claimed in a short transaction under
//! `pg_try_advisory_xact_lock(17, hashtext('attome-integration/oauth_refresh:{system}'))`
//! that sets `refresh_claimed_until` 30 seconds ahead; the HTTP call to the
//! provider then runs outside any transaction, and a second short transaction
//! stores the result and clears the claim. A node that finds the lock held or
//! the claim live does not call the provider: it waits briefly for the token
//! the other node is fetching. A refresher that crashes leaves only a claim
//! that expires.
//!
//! **Failure.** A failed refresh stores a masked reason in
//! `last_refresh_error` (the HTTP status and the provider's `error` code, never
//! a body or a token), counts `integration_oauth_refresh_failures_total{system}`
//! and logs `integration.oauth.refresh_failed` at `error`.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::connection::Connection;
use crate::credential::Credential;
use crate::crypto;

/// The OAuth auth types.
pub const OAUTH_AUTH_TYPES: [&str; 2] = ["oauth2_client_credentials", "oauth2_refresh_token"];

/// A token is used only while it has at least this long left.
const USE_MARGIN_SECS: i64 = 60;

/// The scheduled refresh renews tokens with less than this long left.
pub const RENEW_AHEAD: Duration = Duration::from_secs(10 * 60);

/// How long one node's claim on a refresh lasts.
const CLAIM_SECS: i64 = 30;

/// The provider's token endpoint must answer within this.
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a node waits for another node's refresh to land.
const WAIT_FOR_OTHER: Duration = Duration::from_secs(5);

/// The lifetime assumed when a provider names none.
const DEFAULT_EXPIRES_IN: i64 = 3600;

/// A token response, sealed: the tokens are zeroed on drop and never printed.
pub struct TokenGrant {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    expires_in: i64,
}

impl std::fmt::Debug for TokenGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenGrant")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// Why a token request failed, masked: safe to store and to log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TokenError(pub String);

/// The boxed future a [`TokenEndpoint`] answers with.
pub type TokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TokenGrant, TokenError>> + Send + 'a>>;

/// Posts a token request form to a provider's token URL.
pub trait TokenEndpoint: Send + Sync {
    fn request<'a>(
        &'a self,
        token_url: &'a str,
        form: Vec<(&'static str, String)>,
    ) -> TokenFuture<'a>;
}

/// Reads a provider's answer: the tokens from a 2xx, a masked reason from
/// anything else.
pub fn parse_token_response(status: u16, body: &[u8]) -> Result<TokenGrant, TokenError> {
    #[derive(Deserialize)]
    struct Answer {
        access_token: Option<String>,
        refresh_token: Option<String>,
        expires_in: Option<Value>,
        error: Option<String>,
    }
    let answer: Option<Answer> = serde_json::from_slice(body).ok();
    if !(200..300).contains(&status) {
        // Only the provider's short error code, which names no secret.
        let code = answer
            .and_then(|a| a.error)
            .filter(|e| e.len() <= 64 && e.bytes().all(|b| b.is_ascii_graphic()))
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(TokenError(format!(
            "token endpoint answered {status} ({code})"
        )));
    }
    let answer = answer.ok_or_else(|| TokenError("token endpoint answered no JSON".into()))?;
    let access_token = answer
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| TokenError("token endpoint answered no access_token".into()))?;
    // Some providers send `expires_in` as a string.
    let expires_in = match answer.expires_in {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|secs| *secs > 0)
    .unwrap_or(DEFAULT_EXPIRES_IN);
    Ok(TokenGrant {
        access_token: Zeroizing::new(access_token),
        refresh_token: answer
            .refresh_token
            .filter(|t| !t.is_empty())
            .map(Zeroizing::new),
        expires_in,
    })
}

/// The production endpoint: the token URL is checked by the same address
/// guard as every outbound call and dialled through the guarded client.
pub struct GuardedEndpoint {
    client: attome_server::ssrf_guard::GuardedClient,
}

impl std::fmt::Debug for GuardedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedEndpoint").finish_non_exhaustive()
    }
}

impl GuardedEndpoint {
    pub fn new() -> Result<Self, AppError> {
        attome_server::ssrf_guard::GuardedClient::new(TOKEN_TIMEOUT.as_secs())
            .map(|client| Self { client })
            .map_err(AppError::internal)
    }
}

impl TokenEndpoint for GuardedEndpoint {
    fn request<'a>(
        &'a self,
        token_url: &'a str,
        form: Vec<(&'static str, String)>,
    ) -> TokenFuture<'a> {
        Box::pin(async move {
            let url = reqwest::Url::parse(token_url)
                .map_err(|_| TokenError("token_url is not a valid URL".into()))?;
            attome_server::ssrf_guard::validate_url(&url)
                .await
                .map_err(|_| TokenError("token_url is not an allowed address".into()))?;
            let request = self
                .client
                .post(url)
                .map_err(|_| TokenError("token_url is not an allowed address".into()))?
                .form(&form)
                .timeout(TOKEN_TIMEOUT);
            let response = request.send().await.map_err(|e| {
                TokenError(if e.is_timeout() {
                    "token endpoint timed out".into()
                } else {
                    "token endpoint unreachable".into()
                })
            })?;
            let status = response.status().as_u16();
            let body = response
                .bytes()
                .await
                .map_err(|_| TokenError("token endpoint answer unreadable".into()))?;
            parse_token_response(status, &body)
        })
    }
}

/// The provider settings from the system's `config`.
fn settings(config: Option<&str>) -> Result<(String, Option<String>), AppError> {
    let config: Value = config
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(Value::Null);
    let token_url = config
        .get("token_url")
        .and_then(Value::as_str)
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        .ok_or_else(|| AppError::Validation("an OAuth system's config needs a token_url".into()))?
        .to_owned();
    let scope = config
        .get("scope")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((token_url, scope))
}

/// The client's id and secret, and the first refresh token, from the
/// credential JSON.
struct ClientSecrets {
    client_id: String,
    client_secret: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
}

fn client_secrets(credential: &Credential) -> Result<ClientSecrets, AppError> {
    #[derive(Deserialize)]
    struct Raw {
        client_id: String,
        client_secret: String,
        refresh_token: Option<String>,
    }
    let raw: Raw = credential
        .with_value(|v| serde_json::from_str(v))
        .map_err(|_| {
            AppError::Validation(
                "an OAuth system's credential is {\"client_id\", \"client_secret\"} \
                 (and \"refresh_token\" for oauth2_refresh_token)"
                    .into(),
            )
        })?;
    Ok(ClientSecrets {
        client_id: raw.client_id,
        client_secret: Zeroizing::new(raw.client_secret),
        refresh_token: raw.refresh_token.map(Zeroizing::new),
    })
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    access_token_encrypted: Option<String>,
    fresh: bool,
    claimed: bool,
}

async fn read_row(db: &DbPool, system_id: Uuid) -> Result<Option<TokenRow>, AppError> {
    sqlx::query_as(
        "SELECT access_token_encrypted, \
                access_token_encrypted IS NOT NULL \
                  AND expires_at > now() + make_interval(secs => $2) AS fresh, \
                coalesce(refresh_claimed_until > now(), false) AS claimed \
           FROM integration_oauth_token WHERE system_id = $1",
    )
    .bind(system_id)
    .bind(USE_MARGIN_SECS as f64)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

fn decrypt_access(
    ring: &KeyRing,
    system_id: Uuid,
    row: &TokenRow,
) -> Result<Option<Credential>, AppError> {
    row.access_token_encrypted
        .as_deref()
        .map(|e| crypto::decrypt_token(ring, system_id, "access_token_encrypted", e))
        .transpose()
        .map(|t| t.map(Credential::new))
}

/// The access token to call `connection` with: the stored one while it has
/// more than a minute left, otherwise a fresh one.
pub async fn access_token(
    db: &DbPool,
    ring: &KeyRing,
    connection: &Connection,
    config: Option<&str>,
    credential: &Credential,
    endpoint: &dyn TokenEndpoint,
) -> Result<Credential, AppError> {
    if let Some(row) = read_row(db, connection.id).await?
        && row.fresh
        && let Some(token) = decrypt_access(ring, connection.id, &row)?
    {
        return Ok(token);
    }
    refresh(db, ring, connection, config, credential, endpoint).await
}

/// What a claim attempt found.
enum Claim {
    /// This node refreshes; the refresh token to use, if any.
    Mine(Option<Zeroizing<String>>),
    /// Another node is refreshing.
    Theirs,
}

async fn claim(db: &DbPool, ring: &KeyRing, system_id: Uuid) -> Result<Claim, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-integration/oauth_refresh:{system_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(Claim::Theirs);
    }
    // Claim the refresh unless a live claim exists; the row is made on the
    // first refresh.
    let claimed: Option<Option<String>> = sqlx::query_scalar(
        "INSERT INTO integration_oauth_token (system_id, refresh_claimed_until) \
         VALUES ($1, now() + make_interval(secs => $2)) \
         ON CONFLICT (system_id) DO UPDATE \
            SET refresh_claimed_until = EXCLUDED.refresh_claimed_until \
          WHERE integration_oauth_token.refresh_claimed_until IS NULL \
             OR integration_oauth_token.refresh_claimed_until <= now() \
         RETURNING refresh_token_encrypted",
    )
    .bind(system_id)
    .bind(CLAIM_SECS as f64)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    match claimed {
        None => Ok(Claim::Theirs),
        Some(refresh) => Ok(Claim::Mine(
            refresh
                .map(|e| crypto::decrypt_token(ring, system_id, "refresh_token_encrypted", &e))
                .transpose()?
                .map(Zeroizing::new),
        )),
    }
}

/// Fetches a new token now, stores it and answers it. While another node is
/// already refreshing, waits for its token instead.
pub async fn refresh(
    db: &DbPool,
    ring: &KeyRing,
    connection: &Connection,
    config: Option<&str>,
    credential: &Credential,
    endpoint: &dyn TokenEndpoint,
) -> Result<Credential, AppError> {
    if !OAUTH_AUTH_TYPES.contains(&connection.auth_type.as_str()) {
        return Err(AppError::internal(
            "refresh called for a non-OAuth connection",
        ));
    }
    let (token_url, scope) = settings(config)?;
    let secrets = client_secrets(credential)?;
    let stored_refresh = match claim(db, ring, connection.id).await? {
        Claim::Mine(refresh) => refresh,
        Claim::Theirs => return wait_for_other(db, ring, connection.id).await,
    };

    let mut form: Vec<(&'static str, String)> = vec![
        ("client_id", secrets.client_id.clone()),
        ("client_secret", secrets.client_secret.to_string()),
    ];
    if connection.auth_type == "oauth2_refresh_token" {
        let refresh = stored_refresh.or(secrets.refresh_token).ok_or_else(|| {
            AppError::Validation(
                "an oauth2_refresh_token system's credential needs a refresh_token".into(),
            )
        })?;
        form.push(("grant_type", "refresh_token".into()));
        form.push(("refresh_token", refresh.to_string()));
    } else {
        form.push(("grant_type", "client_credentials".into()));
    }
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }

    // Outside any transaction: the provider's answer can take seconds.
    let outcome = endpoint.request(&token_url, form).await;
    match outcome {
        Ok(grant) => store(db, ring, connection.id, &grant)
            .await
            .map(|()| Credential::new(grant.access_token.to_string())),
        Err(error) => {
            record_failure(db, connection, &error).await?;
            Err(AppError::Validation(format!(
                "OAuth token refresh for {} failed: {error}",
                connection.name
            )))
        }
    }
}

async fn store(
    db: &DbPool,
    ring: &KeyRing,
    system_id: Uuid,
    grant: &TokenGrant,
) -> Result<(), AppError> {
    let access = crypto::encrypt_token(
        ring,
        system_id,
        "access_token_encrypted",
        &grant.access_token,
    )?;
    let refresh = grant
        .refresh_token
        .as_deref()
        .map(|t| crypto::encrypt_token(ring, system_id, "refresh_token_encrypted", t))
        .transpose()?;
    sqlx::query(
        "UPDATE integration_oauth_token \
            SET access_token_encrypted = $2, \
                refresh_token_encrypted = coalesce($3, refresh_token_encrypted), \
                expires_at = now() + make_interval(secs => $4), \
                last_refreshed_at = now(), last_refresh_error = NULL, \
                refresh_claimed_until = NULL, row_version = row_version + 1 \
          WHERE system_id = $1",
    )
    .bind(system_id)
    .bind(access)
    .bind(refresh)
    .bind(grant.expires_in as f64)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn record_failure(
    db: &DbPool,
    connection: &Connection,
    error: &TokenError,
) -> Result<(), AppError> {
    metrics::counter!(
        "integration_oauth_refresh_failures_total",
        "system" => connection.name.clone()
    )
    .increment(1);
    tracing::error!(
        event = "integration.oauth.refresh_failed",
        system = %connection.name,
        system_id = %connection.id,
        reason = %error,
        "integration OAuth token refresh failed"
    );
    sqlx::query(
        "UPDATE integration_oauth_token \
            SET last_refresh_error = $2, refresh_claimed_until = NULL, \
                row_version = row_version + 1 \
          WHERE system_id = $1",
    )
    .bind(connection.id)
    .bind(&error.0)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Waits a little for another node's refresh to land, then answers its
/// token, or that the token is not available yet.
async fn wait_for_other(
    db: &DbPool,
    ring: &KeyRing,
    system_id: Uuid,
) -> Result<Credential, AppError> {
    let deadline = tokio::time::Instant::now() + WAIT_FOR_OTHER;
    loop {
        if let Some(row) = read_row(db, system_id).await? {
            if row.fresh
                && let Some(token) = decrypt_access(ring, system_id, &row)?
            {
                return Ok(token);
            }
            if !row.claimed {
                // The other node finished without a token.
                return Err(AppError::Overloaded(
                    "integration OAuth token refresh failed",
                ));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AppError::Overloaded(
                "integration OAuth token refresh in progress",
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// What a scheduled run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshSummary {
    pub refreshed: u32,
    pub failed: u32,
}

/// Renews every OAuth token with less than [`RENEW_AHEAD`] left (the
/// scheduled job, every five minutes). One system's failure is recorded and
/// the run goes on.
pub async fn refresh_due(
    db: &DbPool,
    ring: &KeyRing,
    endpoint: &dyn TokenEndpoint,
) -> Result<RefreshSummary, AppError> {
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT system_id FROM integration_oauth_token \
          WHERE expires_at < now() + make_interval(secs => $1) \
            AND (refresh_claimed_until IS NULL OR refresh_claimed_until <= now()) \
          ORDER BY expires_at LIMIT 500",
    )
    .bind(RENEW_AHEAD.as_secs() as f64)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut summary = RefreshSummary::default();
    for system_id in due {
        let Some(system) = crate::system::load(db, system_id).await? else {
            continue;
        };
        if !OAUTH_AUTH_TYPES.contains(&system.auth_type.as_str()) {
            continue;
        }
        let connection = Connection::of(&system);
        let Some(credential) = connection.credential(db, ring).await? else {
            continue;
        };
        match refresh(
            db,
            ring,
            &connection,
            system.config.as_deref(),
            &credential,
            endpoint,
        )
        .await
        {
            Ok(_) => summary.refreshed += 1,
            Err(_) => summary.failed += 1,
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_answer_is_read_and_an_error_is_masked() {
        let grant = parse_token_response(
            200,
            br#"{"access_token":"at-1","refresh_token":"rt-2","expires_in":"1800"}"#,
        )
        .unwrap();
        assert_eq!(&*grant.access_token, "at-1");
        assert_eq!(
            grant.refresh_token.as_deref().map(String::as_str),
            Some("rt-2")
        );
        assert_eq!(grant.expires_in, 1800);
        assert!(!format!("{grant:?}").contains("at-1"));

        let default = parse_token_response(200, br#"{"access_token":"x"}"#).unwrap();
        assert_eq!(default.expires_in, DEFAULT_EXPIRES_IN);

        let err = parse_token_response(
            400,
            br#"{"error":"invalid_grant","error_description":"refresh token rt-2 revoked"}"#,
        )
        .unwrap_err();
        assert_eq!(err.0, "token endpoint answered 400 (invalid_grant)");
        assert!(!err.0.contains("rt-2"), "the description is not kept");
        assert!(parse_token_response(200, b"{}").is_err());
        assert_eq!(
            parse_token_response(502, b"<html>").unwrap_err().0,
            "token endpoint answered 502 (unknown)"
        );
    }

    #[test]
    fn settings_and_secrets_are_read_from_config_and_credential() {
        let (url, scope) = settings(Some(
            r#"{"token_url":"https://id.example.com/token","scope":"api"}"#,
        ))
        .unwrap();
        assert_eq!(url, "https://id.example.com/token");
        assert_eq!(scope.as_deref(), Some("api"));
        assert!(settings(Some("{}")).is_err());
        assert!(settings(Some(r#"{"token_url":"ftp://x"}"#)).is_err());

        let secrets = client_secrets(&Credential::for_test(
            r#"{"client_id":"c","client_secret":"s"}"#,
        ))
        .unwrap();
        assert_eq!(secrets.client_id, "c");
        assert!(secrets.refresh_token.is_none());
        assert!(client_secrets(&Credential::for_test("c:s")).is_err());
    }
}
