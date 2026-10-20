//! Reads/writes for `integration_credential` (migration 0195) — the ONLY
//! place the plaintext credential value ever exists outside a request's own
//! stack. Envelope-encrypted under `integration.credential_encryption_key`
//! (its own D-069 trust domain — see `crate::crypto`).
//!
//! Every write here happens inside the SAME transaction as the
//! `integration_system.credential_ref` update that points at it
//! (`admin.rs`), so a partial write is never observable.

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::crypto;

/// D-424/D-425: never returned by any API after creation. `secret_last4` is
/// the only thing an admin GET is allowed to show.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct CredentialMeta {
    pub id: Uuid,
    pub secret_last4: Option<String>,
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Encrypts `plaintext` and inserts a new `integration_credential` row.
/// The caller (`admin.rs`) is responsible for pointing
/// `integration_system.credential_ref` at the returned id, in the same
/// transaction.
pub async fn store(
    tx: &mut Transaction<'_, Postgres>,
    ring: &KeyRing,
    system_id: Uuid,
    plaintext: &str,
) -> Result<Uuid, AppError> {
    if ring.is_empty() {
        return Err(AppError::internal(
            "integration.credential_encryption_key has no active key configured",
        ));
    }
    // Q18-T2: the id is chosen first so the ciphertext can be bound to it.
    let new_id = Uuid::now_v7();
    let encrypted = crypto::encrypt_credential(ring, new_id, plaintext)?;
    let last4 = crypto::last4(plaintext);

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO integration_credential (id, system_ref, secret_encrypted, secret_last4) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id",
    )
    .bind(new_id)
    .bind(system_id)
    .bind(&encrypted)
    .bind(&last4)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Supersedes every existing (non-deleted) credential row for `system_id`
/// with a freshly-encrypted one — a rotation, not an update-in-place, so a
/// superseded value is never silently overwritten before the new one is
/// confirmed persisted. Returns the new row's id.
pub async fn rotate(
    tx: &mut Transaction<'_, Postgres>,
    ring: &KeyRing,
    system_id: Uuid,
    plaintext: &str,
) -> Result<Uuid, AppError> {
    sqlx::query(
        "UPDATE integration_credential SET is_deleted = TRUE, rotated_at = NOW() \
         WHERE system_ref = $1 AND is_deleted = FALSE",
    )
    .bind(system_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    store(tx, ring, system_id, plaintext).await
}

/// Z1-T10: a decrypted credential, sealed. No public function returns its
/// value: it goes into a request ([`Credential::header`],
/// [`Credential::bearer`], [`Credential::basic`], [`Credential::hmac_sha256_hex`])
/// or is lent to a closure for the call that needs it (an IMAP login, a
/// provider's JSON of keys) with [`Credential::with_value`]. The value is
/// zeroed on drop, and `Debug` never prints it.
#[derive(Clone)]
pub struct Credential(zeroize::Zeroizing<String>);

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}

impl Credential {
    /// Seals a value just decrypted (or, in a test, made up).
    pub(crate) fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    /// A credential from a known value, for tests in other crates.
    #[doc(hidden)]
    pub fn for_test(value: &str) -> Self {
        Self::new(value.to_owned())
    }

    /// Lends the value to `use_it` for one call; whatever `use_it` returns
    /// is the caller's. Keep the value inside the closure.
    pub fn with_value<R>(&self, use_it: impl FnOnce(&str) -> R) -> R {
        use_it(&self.0)
    }

    /// The value as the named request header.
    pub fn header(&self, builder: reqwest::RequestBuilder, name: &str) -> reqwest::RequestBuilder {
        let mut value = reqwest::header::HeaderValue::from_str(&self.0)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
        value.set_sensitive(true);
        builder.header(name, value)
    }

    /// `Authorization: Bearer <value>`.
    pub fn bearer(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.bearer_auth(&*self.0)
    }

    /// `Authorization: Basic`, the value being `user:password`.
    pub fn basic(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.0.split_once(':') {
            Some((user, password)) => builder.basic_auth(user, Some(password)),
            None => builder.basic_auth(&*self.0, None::<&str>),
        }
    }

    /// The HMAC-SHA256 of `message` keyed by the value, as hex.
    pub fn hmac_sha256_hex(&self, message: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        // HMAC takes a key of any length, so this never fails.
        let Ok(mut mac) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(self.0.as_bytes()) else {
            return String::new();
        };
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// The live key ring credentials are sealed under (rotated without a
/// restart through the secrets reload).
pub fn ring(state: &attome_core::EngineState) -> KeyRing {
    state.base.secrets.load().integration_credential_key.clone()
}

/// Decrypts the current credential for a system, given its
/// `credential_ref` (the `integration_credential.id` string stored on
/// the `integration_system` row). `Ok(None)` when the ref is absent or
/// unresolvable — never an error, since "no credential configured yet" is a
/// normal state every `Connector` method accepts as `credential: None`.
pub async fn resolve(
    db: &DbPool,
    ring: &KeyRing,
    credential_ref: Option<&str>,
) -> Result<Option<Credential>, AppError> {
    let Some(credential_ref) = credential_ref else {
        return Ok(None);
    };
    let Ok(id) = Uuid::parse_str(credential_ref) else {
        return Ok(None);
    };
    let encrypted: Option<String> = sqlx::query_scalar(
        "SELECT secret_encrypted FROM integration_credential \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match encrypted {
        Some(encrypted) => Ok(Some(Credential::new(crypto::decrypt_credential(
            ring, id, &encrypted,
        )?))),
        None => Ok(None),
    }
}

pub async fn meta(db: &DbPool, credential_ref: &str) -> Result<Option<CredentialMeta>, AppError> {
    let Ok(id) = Uuid::parse_str(credential_ref) else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT id, secret_last4, rotated_at, created_at FROM integration_credential \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// [`resolve`] for an adapter inside this crate that needs the value itself
/// (an IMAP login, a provider's JSON of keys, a signing key). Never public.
pub(crate) async fn resolve_value(
    db: &DbPool,
    ring: &KeyRing,
    credential_ref: Option<&str>,
) -> Result<Option<String>, AppError> {
    Ok(resolve(db, ring, credential_ref)
        .await?
        .map(|credential| credential.with_value(str::to_owned)))
}
