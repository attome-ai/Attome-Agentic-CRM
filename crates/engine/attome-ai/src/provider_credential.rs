//! Reads/writes for `ai_provider_credential` (migration 0478) — the ONLY
//! place an AI provider's API key exists outside a request's own stack.
//!
//! Envelope-encrypted under `inference.provider_credential_key`, its own
//! D-069 trust domain: never `integration.credential_encryption_key`, never
//! `s2s.key_encryption_key`. The same versioned wire format
//! `attome_integration::crypto` and `attome_s2s::crypto` use, so there is one
//! envelope implementation in this workspace and not four.
//!
//! The separation is carried by the *key material*, not by [`FIELD_NAME`]:
//! `attome_auth::envelope` uses the field name for error messages only, never
//! as AAD (see its `encrypt_bytes` doc comment). Configuring two rings with
//! the same secret therefore collapses the two trust domains into one, which
//! is a deployment mistake this crate cannot detect —
//! `the_field_name_is_not_a_second_line_of_defence` below pins that fact so
//! nobody later reads more protection into this module than it has.
//!
//! **The key is never returned by any API after it is set.** `secret_last4`
//! is the only thing a read is allowed to show, exactly as D-424/D-425
//! established for integration credentials. Nothing in this module has a
//! `Serialize` impl that can reach a plaintext secret: [`CredentialMeta`] does
//! not hold one, and [`resolve`] returns a bare `String` that only the
//! outbound model-discovery call consumes.

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const FIELD_NAME: &str = "inference.provider_credential_key";

pub fn encrypt_secret(ring: &KeyRing, plaintext: &str) -> Result<String, AppError> {
    attome_auth::envelope::encrypt(FIELD_NAME, ring, plaintext)
}

pub fn decrypt_secret(ring: &KeyRing, encoded: &str) -> Result<String, AppError> {
    attome_auth::envelope::decrypt(FIELD_NAME, ring, encoded)
}

/// Last 4 characters of a plaintext secret, for the "configured, ending in
/// ****1234" admin-UI display — never the full value.
///
/// `None` below 4 characters rather than a shorter hint: for a 3-character
/// secret the "hint" would be the secret. Counted in `char`s, not bytes, so a
/// multi-byte key cannot panic on a non-char-boundary slice.
pub fn last4(secret: &str) -> Option<String> {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() < 4 {
        return None;
    }
    Some(chars[chars.len() - 4..].iter().collect())
}

/// What a read of a provider's credential may disclose. Deliberately carries
/// no plaintext field at all, so no future `Serialize` of this type can leak
/// one.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct CredentialMeta {
    pub id: Uuid,
    pub secret_last4: Option<String>,
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Encrypts `plaintext` and inserts a new row. The caller points
/// `ai_provider.credential_ref` at the returned id.
pub async fn store(
    tx: &mut Transaction<'_, Postgres>,
    ring: &KeyRing,
    provider_id: Uuid,
    plaintext: &str,
) -> Result<Uuid, AppError> {
    if ring.is_empty() {
        // Operator-actionable, and deliberately not an encryption attempt
        // under an absent key: storing a "secret" nothing can decrypt would
        // look like success and fail at first use. A 503 that names the
        // missing setting (D-344) rather than a masked 500, so the operator
        // seeing the form's banner knows what to configure.
        tracing::error!(
            "inference.provider_credential_key has no active key configured; \
             refusing to store an AI provider API key"
        );
        return Err(AppError::CapabilityUnavailable(
            "inference.provider_credential_key",
        ));
    }
    let encrypted = encrypt_secret(ring, plaintext)?;
    let last4 = last4(plaintext);

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_provider_credential (provider_ref, secret_encrypted, secret_last4) \
         VALUES ($1, $2, $3) \
         RETURNING id",
    )
    .bind(provider_id)
    .bind(&encrypted)
    .bind(&last4)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Supersedes every live credential row for `provider_id` with a freshly
/// encrypted one — a rotation, not an update in place, so a superseded value
/// is never overwritten before the new one is confirmed persisted. Returns the
/// new row's id.
///
/// Both statements run in the caller's transaction, and the caller holds a
/// per-provider advisory lock (D-351), so two concurrent rotations can never
/// interleave and leave two live rows.
pub async fn rotate(
    tx: &mut Transaction<'_, Postgres>,
    ring: &KeyRing,
    provider_id: Uuid,
    plaintext: &str,
) -> Result<Uuid, AppError> {
    sqlx::query(
        "UPDATE ai_provider_credential SET is_deleted = TRUE, rotated_at = NOW() \
         WHERE provider_ref = $1 AND is_deleted = FALSE",
    )
    .bind(provider_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    store(tx, ring, provider_id, plaintext).await
}

/// Decrypts the credential `credential_ref` names, for the one caller that
/// needs the plaintext: the outbound model-discovery request.
///
/// `None` when the provider has no credential configured — a provider that
/// needs no key (a local vLLM with open access) is a supported configuration,
/// so this is not an error.
pub async fn resolve(
    db: &DbPool,
    ring: &KeyRing,
    credential_ref: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(reference) = credential_ref.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let Ok(id) = Uuid::parse_str(reference) else {
        // The column is written only by this crate's own rotate handler, so a
        // value that is not a UUID is an internal-consistency bug, not caller
        // input. Refuse rather than silently proceeding keyless — proceeding
        // would turn "the key is unreadable" into a confusing 401 from the
        // provider.
        return Err(AppError::internal(
            "ai_provider.credential_ref is not a UUID",
        ));
    };
    let encrypted: Option<String> = sqlx::query_scalar(
        "SELECT secret_encrypted FROM ai_provider_credential \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    encrypted.map(|e| decrypt_secret(ring, &e)).transpose()
}

/// The disclosable metadata for one credential id.
pub async fn meta(db: &DbPool, credential_ref: &str) -> Result<Option<CredentialMeta>, AppError> {
    let Ok(id) = Uuid::parse_str(credential_ref.trim()) else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT id, secret_last4, rotated_at, created_at FROM ai_provider_credential \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrips_and_a_wrong_key_cannot_decrypt() {
        let ring_a = KeyRing::single("11".repeat(32));
        let ring_b = KeyRing::single("22".repeat(32));
        let secret = "sk-provider-api-key-value";

        let encrypted = encrypt_secret(&ring_a, secret).unwrap();
        assert_eq!(decrypt_secret(&ring_a, &encrypted).unwrap(), secret);
        assert!(
            decrypt_secret(&ring_b, &encrypted).is_err(),
            "a different trust domain's ring must not decrypt this one's ciphertext"
        );
    }

    /// Pins what the D-069 separation actually rests on, so a later reader
    /// does not assume more than is true. `attome_auth::envelope` uses
    /// `field_name` for error messages ONLY — it is not AAD — so ciphertext
    /// written under `integration.credential_encryption_key` decrypts fine
    /// here whenever the key material happens to match. The separation is
    /// that the two rings hold *different* material, which is a configuration
    /// property this crate cannot assert. Hence `encrypt_decrypt_roundtrips_
    /// and_a_wrong_key_cannot_decrypt` above is the real guarantee, and this
    /// test documents the non-guarantee rather than pretending otherwise.
    #[test]
    fn the_field_name_is_not_a_second_line_of_defence() {
        let ring = KeyRing::single("33".repeat(32));
        let integration_ciphertext = attome_auth::envelope::encrypt(
            "integration.credential_encryption_key",
            &ring,
            "secret",
        )
        .unwrap();
        assert_eq!(
            decrypt_secret(&ring, &integration_ciphertext).unwrap(),
            "secret",
            "if this ever fails, attome_auth::envelope started binding field_name as AAD — update this module's doc comment, which currently promises only key separation"
        );
    }

    #[test]
    fn last4_never_discloses_a_short_secret() {
        assert_eq!(last4("abcd1234").as_deref(), Some("1234"));
        assert_eq!(last4("abc"), None);
        assert_eq!(last4(""), None);
    }

    /// A multi-byte secret must not panic on a non-char-boundary slice.
    #[test]
    fn last4_counts_characters_not_bytes() {
        assert_eq!(last4("key-aaéééé").as_deref(), Some("éééé"));
    }
}
