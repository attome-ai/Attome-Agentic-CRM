//! Envelope-encryption helpers for `integration_credential.secret_encrypted`
//! — the exact same versioned wire format `attome-s2s::crypto` and
//! `attome-events::crypto` use, applied to `integration.credential_encryption_key`
//! (its own trust domain, D-069: never `s2s.key_encryption_key`, never
//! `events.webhook_signing_key`).

use attome_config::KeyRing;
use attome_types::AppError;

const FIELD_NAME: &str = "integration.credential_encryption_key";

/// Q18-T2: `integration_credential.secret_encrypted` is bound to its row.
fn binding(credential_id: uuid::Uuid) -> attome_auth::envelope::RowBinding<'static> {
    attome_auth::envelope::RowBinding {
        table: "integration_credential",
        column: "secret_encrypted",
        row_id: credential_id,
    }
}

pub fn encrypt_credential(
    ring: &KeyRing,
    credential_id: uuid::Uuid,
    plaintext: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::encrypt_bound(FIELD_NAME, ring, plaintext, binding(credential_id))
}

pub fn decrypt_credential(
    ring: &KeyRing,
    credential_id: uuid::Uuid,
    encoded: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::decrypt_bound(FIELD_NAME, ring, encoded, binding(credential_id))
        .map(attome_types::secret::SecretString::into_exposed)
}

/// Z1-T11: an OAuth token column of `integration_oauth_token`, bound to its
/// system's row and its column, so an access token's ciphertext never
/// decrypts as a refresh token or as another system's.
fn token_binding(
    system_id: uuid::Uuid,
    column: &'static str,
) -> attome_auth::envelope::RowBinding<'static> {
    attome_auth::envelope::RowBinding {
        table: "integration_oauth_token",
        column,
        row_id: system_id,
    }
}

pub fn encrypt_token(
    ring: &KeyRing,
    system_id: uuid::Uuid,
    column: &'static str,
    plaintext: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::encrypt_bound(
        FIELD_NAME,
        ring,
        plaintext,
        token_binding(system_id, column),
    )
}

pub fn decrypt_token(
    ring: &KeyRing,
    system_id: uuid::Uuid,
    column: &'static str,
    encoded: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::decrypt_bound(
        FIELD_NAME,
        ring,
        encoded,
        token_binding(system_id, column),
    )
    .map(attome_types::secret::SecretString::into_exposed)
}

/// Last 4 characters of a plaintext secret, for the "configured, ending in
/// ****1234" admin-UI display — never the full value.
pub fn last4(secret: &str) -> Option<String> {
    if secret.len() < 4 {
        return None;
    }
    Some(secret[secret.len() - 4..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_secret_roundtrips_and_detects_wrong_key() {
        let ring_a = KeyRing::single("11".repeat(32));
        let ring_b = KeyRing::single("22".repeat(32));
        let secret = "super-secret-api-key-value";

        let id = uuid::Uuid::now_v7();
        let encrypted = encrypt_credential(&ring_a, id, secret).unwrap();
        assert_eq!(decrypt_credential(&ring_a, id, &encrypted).unwrap(), secret);
        assert!(
            decrypt_credential(&ring_b, id, &encrypted).is_err(),
            "wrong key must not decrypt"
        );
        assert!(
            decrypt_credential(&ring_a, uuid::Uuid::now_v7(), &encrypted).is_err(),
            "Q18-T2: another row's id must not decrypt"
        );
    }

    #[test]
    fn last4_returns_the_trailing_four_characters() {
        assert_eq!(last4("abcd1234").as_deref(), Some("1234"));
        assert_eq!(last4("ab"), None);
    }
}
