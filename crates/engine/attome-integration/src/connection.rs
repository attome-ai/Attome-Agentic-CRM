//! Named connections (roadmap Z1-T10): a caller names an integration system
//! and gets a [`Connection`] that authenticates its requests, never the
//! secret. The credential is decrypted inside [`Connection::apply_auth`] (or
//! handed in sealed, as a [`Credential`], by a caller that already resolved
//! it) and goes straight into the request.
//!
//! Auth types: `api_key` (`X-Api-Key`), `api_key_header` (the header named by
//! the system's `config.auth_header`, `X-Api-Key` when unset), `bearer`,
//! `basic` (the credential is `user:password`), `hmac` (`X-Signature`, the
//! HMAC-SHA256 of the body) and `client_certificate` (the credential is a
//! PEM certificate and private key, presented as the TLS client identity, so
//! it needs [`Connection::client`] rather than a header). Under A30 each
//! deployment is one environment, so a connection is found by its unique
//! name alone.

use std::time::Duration;

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::credential::{self, Credential};
use crate::system::IntegrationSystem;

/// The auth types a connection can apply.
pub const AUTH_TYPES: [&str; 8] = [
    "api_key",
    "api_key_header",
    "bearer",
    "basic",
    "hmac",
    "client_certificate",
    "oauth2_client_credentials",
    "oauth2_refresh_token",
];

/// The header an `api_key_header` connection uses when its config names
/// none.
pub const DEFAULT_KEY_HEADER: &str = "X-Api-Key";

/// An integration system as a caller uses it: where it is and how it
/// authenticates. It carries no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: Uuid,
    pub name: String,
    pub auth_type: String,
    pub base_url: String,
    /// `api_key_header`: the header the key goes in.
    pub auth_header: Option<String>,
    credential_ref: Option<String>,
    /// The system's raw `config`: OAuth reads its `token_url` and `scope`.
    config: Option<String>,
}

fn header_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Connection {
    /// The connection an already-loaded system row describes.
    pub fn of(system: &IntegrationSystem) -> Self {
        let auth_header = system
            .config
            .as_deref()
            .and_then(|c| serde_json::from_str::<Value>(c).ok())
            .and_then(|c| {
                c.get("auth_header")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .filter(|h| header_name_ok(h));
        Self {
            id: system.id,
            name: system.name.clone(),
            auth_type: system.auth_type.clone(),
            base_url: system.base_url.clone(),
            auth_header,
            credential_ref: system.credential_ref.clone(),
            config: system.config.clone(),
        }
    }

    /// The live connection named `name`; not found when there is none.
    pub async fn resolve(db: &DbPool, name: &str) -> Result<Self, AppError> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM integration_system WHERE name = $1 AND is_active IS NOT FALSE",
        )
        .bind(name)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let id = id.ok_or(AppError::NotFound)?;
        let system = crate::system::load(db, id)
            .await?
            .ok_or(AppError::NotFound)?;
        Ok(Self::of(&system))
    }

    /// This connection's credential, sealed; `None` when none is set.
    pub async fn credential(
        &self,
        db: &DbPool,
        ring: &KeyRing,
    ) -> Result<Option<Credential>, AppError> {
        credential::resolve(db, ring, self.credential_ref.as_deref()).await
    }

    /// Authenticates `request` (whose body, for `hmac`, is `body`):
    /// decrypts the credential and sets it on the request, returning only
    /// the request.
    pub async fn apply_auth(
        &self,
        db: &DbPool,
        ring: &KeyRing,
        request: reqwest::RequestBuilder,
        body: &[u8],
    ) -> Result<reqwest::RequestBuilder, AppError> {
        let credential = self.credential(db, ring).await?;
        if crate::oauth::OAUTH_AUTH_TYPES.contains(&self.auth_type.as_str()) {
            // Z1-T11: the stored access token, renewed first when it has
            // less than a minute left.
            let endpoint = crate::oauth::GuardedEndpoint::new()?;
            let token = crate::oauth::access_token(
                db,
                ring,
                self,
                self.config.as_deref(),
                self.needs(credential.as_ref())?,
                &endpoint,
            )
            .await?;
            return Ok(token.bearer(request));
        }
        self.authorize(request, credential.as_ref(), body)
    }

    /// [`Connection::apply_auth`] with a credential already resolved.
    pub fn authorize(
        &self,
        request: reqwest::RequestBuilder,
        credential: Option<&Credential>,
        body: &[u8],
    ) -> Result<reqwest::RequestBuilder, AppError> {
        match self.auth_type.as_str() {
            "api_key" => Ok(self.needs(credential)?.header(request, DEFAULT_KEY_HEADER)),
            "api_key_header" => Ok(self.needs(credential)?.header(
                request,
                self.auth_header.as_deref().unwrap_or(DEFAULT_KEY_HEADER),
            )),
            "bearer" => Ok(self.needs(credential)?.bearer(request)),
            "basic" => Ok(self.needs(credential)?.basic(request)),
            "hmac" => {
                let signature = self.needs(credential)?.hmac_sha256_hex(body);
                Ok(request.header("X-Signature", signature))
            }
            // The identity is on the client (`Connection::client`), not a header.
            "client_certificate" => {
                self.needs(credential)?;
                Ok(request)
            }
            // Z1-T11: the token comes from the database, so only
            // `apply_auth` can authorize these.
            "oauth2_client_credentials" | "oauth2_refresh_token" => {
                Err(AppError::Validation(format!(
                    "auth_type = {} needs its stored token: call the system through a named \
                     connection (Connection::apply_auth); the connector adapters do not \
                     support OAuth yet",
                    self.auth_type
                )))
            }
            other => Err(AppError::internal(format!(
                "unknown auth_type {other:?} reached a connection; admin.rs should have rejected it"
            ))),
        }
    }

    /// The system's raw `config` (A24: a migration source reads its `migration` part).
    pub(crate) fn config(&self) -> Option<&str> {
        self.config.as_deref()
    }

    pub(crate) fn needs<'c>(
        &self,
        credential: Option<&'c Credential>,
    ) -> Result<&'c Credential, AppError> {
        credential.ok_or_else(|| {
            AppError::Validation(format!(
                "system has no credential configured for auth_type = {}",
                self.auth_type
            ))
        })
    }

    /// The HTTP client to call this connection with: for
    /// `client_certificate`, one presenting the credential (PEM certificate
    /// and key) as its TLS identity, behind the same address guard as every
    /// outbound call; `None` for every other auth type, which uses the
    /// shared guarded client.
    pub fn client(
        &self,
        credential: Option<&Credential>,
        timeout: Duration,
    ) -> Result<Option<attome_outbound::http::Outbound>, AppError> {
        if self.auth_type != "client_certificate" {
            return Ok(None);
        }
        let credential = credential.ok_or_else(|| {
            AppError::Validation(
                "system has no credential configured for auth_type = client_certificate".into(),
            )
        })?;
        let identity = credential.with_value(|pem| reqwest::Identity::from_pem(pem.as_bytes()));
        let identity = identity.map_err(|_| {
            AppError::Validation(
                "the client certificate credential is not a PEM certificate and private key".into(),
            )
        })?;
        let purpose = attome_outbound::http::Purpose::public("integration").no_redirects();
        attome_outbound::http::client(purpose, |b| b.identity(identity).timeout(timeout))
            .map(Some)
            .map_err(AppError::internal)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;

    fn connection(auth_type: &str, config: Option<&str>) -> Connection {
        Connection::of(&IntegrationSystem {
            id: Uuid::nil(),
            name: "erp".into(),
            kind: "rest".into(),
            base_url: "https://erp.example.com".into(),
            auth_type: auth_type.into(),
            credential_ref: Some(Uuid::nil().to_string()),
            rate_limit: None,
            status: "active".into(),
            health_last_ok_at: None,
            health_last_error: None,
            service_principal_ref: Uuid::nil().to_string(),
            config: config.map(str::to_owned),
            row_version: 1,
        })
    }

    fn built(request: reqwest::RequestBuilder) -> reqwest::Request {
        request.build().unwrap()
    }

    fn get() -> reqwest::RequestBuilder {
        reqwest::Client::new().get("https://erp.example.com/items")
    }

    #[test]
    fn apply_auth_sets_header_without_exposing_value() {
        let secret = Credential::new("s3cret-value".into());
        let named = connection("api_key_header", Some(r#"{"auth_header": "X-Erp-Key"}"#));
        let request = built(named.authorize(get(), Some(&secret), b"").unwrap());
        let value = request.headers().get("X-Erp-Key").unwrap();
        assert_eq!(value.to_str().unwrap(), "s3cret-value");
        assert!(value.is_sensitive(), "the header is marked sensitive");
        // Neither the connection nor the credential prints the secret.
        assert!(!format!("{named:?}").contains("s3cret"));
        assert!(!format!("{secret:?}").contains("s3cret"));

        let bearer = built(
            connection("bearer", None)
                .authorize(get(), Some(&secret), b"")
                .unwrap(),
        );
        assert_eq!(
            bearer
                .headers()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer s3cret-value"
        );
        let user = Credential::new("ana:pw".into());
        let basic = built(
            connection("basic", None)
                .authorize(get(), Some(&user), b"")
                .unwrap(),
        );
        assert_eq!(
            basic
                .headers()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Basic YW5hOnB3"
        );
        let hmac = built(
            connection("hmac", None)
                .authorize(get(), Some(&secret), b"{}")
                .unwrap(),
        );
        assert_eq!(
            hmac.headers().get("X-Signature").unwrap().to_str().unwrap(),
            secret.hmac_sha256_hex(b"{}")
        );
    }

    #[test]
    fn apply_auth_refuses_a_missing_credential_and_oauth2() {
        let err = connection("bearer", None)
            .authorize(get(), None, b"")
            .unwrap_err();
        assert!(err.to_string().contains("no credential configured"));
        let secret = Credential::new("x".into());
        assert!(
            connection("oauth2_client_credentials", None)
                .authorize(get(), Some(&secret), b"")
                .is_err()
        );
        let bad_header = connection("api_key_header", Some(r#"{"auth_header": "X Bad: 1"}"#));
        assert_eq!(
            bad_header.auth_header, None,
            "an unusable header name falls back"
        );
    }

    #[test]
    fn client_certificate_needs_a_pem_identity() {
        let cert = connection("client_certificate", None);
        assert!(cert.client(None, Duration::from_secs(5)).is_err());
        let not_pem = Credential::new("not a certificate".into());
        assert!(cert.client(Some(&not_pem), Duration::from_secs(5)).is_err());
        assert!(
            connection("bearer", None)
                .client(Some(&not_pem), Duration::from_secs(5))
                .unwrap()
                .is_none()
        );
    }
}
