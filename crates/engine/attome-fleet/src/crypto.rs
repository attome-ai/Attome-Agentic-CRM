//! Rollout-secret encryption at rest (design §4.2): the D-069 envelope
//! (`attome_auth::envelope`) under `fleet.credential_encryption_key`, with the
//! deployment's row id as additional authenticated data, so a ciphertext
//! copied onto another deployment's row does not decrypt.
//!
//! The plaintext lives only in a [`RolloutSecret`]: no `Display`, no
//! `Serialize`, a redacted `Debug`. It is decrypted inside `client.rs` for
//! the one request being signed and never logged or returned by a route.

use attome_config::KeyRing;
use attome_types::AppError;
use uuid::Uuid;

/// The envelope's field label (it names the trust domain in error messages
/// and in the blob's header handling).
const FIELD: &str = "fleet.credential_encryption_key";

/// The shortest secret accepted: 16 bytes of hex. A customer's S2S admin
/// generates 32 bytes (`attome_s2s::crypto::generate_secret`).
const MIN_SECRET_HEX: usize = 32;
/// The longest secret accepted (a bound, not a format rule).
const MAX_SECRET_HEX: usize = 256;

/// A customer's rollout S2S secret: the hex string the customer's S2S admin
/// screen showed once. The HMAC key is its hex-decoded bytes
/// (`attome_s2s::crypto::sign_hmac`).
#[derive(Clone, PartialEq, Eq)]
pub struct RolloutSecret(String);

impl std::fmt::Debug for RolloutSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RolloutSecret([REDACTED])")
    }
}

impl RolloutSecret {
    /// Accepts the pasted value after trimming: even-length hex of a sane
    /// length. A 422 names the rule, never the value.
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let value = raw.trim();
        let hex = value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex || !(MIN_SECRET_HEX..=MAX_SECRET_HEX).contains(&value.len()) {
            return Err(AppError::Validation(format!(
                "secret: must be the hex S2S secret the customer's S2S admin screen showed \
                 ({MIN_SECRET_HEX}-{MAX_SECRET_HEX} hex characters)"
            )));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The last four characters, the only part any route shows.
    pub fn last4(&self) -> String {
        let start = self.0.len().saturating_sub(4);
        self.0[start..].to_string()
    }

    /// The hex secret, for signing only.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// Encrypts `secret` for the `fleet_deployment` row `deployment_id`.
pub fn seal(
    ring: &KeyRing,
    deployment_id: Uuid,
    secret: &RolloutSecret,
) -> Result<Vec<u8>, AppError> {
    attome_auth::envelope::encrypt_bytes_with_aad(
        FIELD,
        ring,
        secret.expose().as_bytes(),
        deployment_id.as_bytes(),
    )
}

/// Decrypts the `secret_enc` of the row `deployment_id`. A wrong key, a
/// tampered blob or a blob from another row fails (masked 500 upstream).
pub fn unseal(
    ring: &KeyRing,
    deployment_id: Uuid,
    sealed: &[u8],
) -> Result<RolloutSecret, AppError> {
    let plain = attome_auth::envelope::decrypt_bytes_with_aad(
        FIELD,
        ring,
        sealed,
        deployment_id.as_bytes(),
    )?;
    let text = String::from_utf8(plain)
        .map_err(|_| AppError::internal("a fleet rollout secret decrypted to invalid UTF-8"))?;
    RolloutSecret::parse(&text)
        .map_err(|_| AppError::internal("a fleet rollout secret decrypted to a malformed value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(byte: &str) -> KeyRing {
        KeyRing::single(byte.repeat(32))
    }

    fn secret() -> RolloutSecret {
        RolloutSecret::parse(&"0a1b".repeat(16)).expect("64 hex characters")
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_own_row_and_key() {
        let id = Uuid::now_v7();
        let sealed = seal(&ring("11"), id, &secret()).expect("seal");
        assert_eq!(unseal(&ring("11"), id, &sealed).expect("unseal"), secret());
        assert!(
            unseal(&ring("22"), id, &sealed).is_err(),
            "another key must not open it"
        );
        assert!(
            unseal(&ring("11"), Uuid::now_v7(), &sealed).is_err(),
            "a blob copied to another deployment row must not open"
        );
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_secret() {
        let sealed = seal(&ring("11"), Uuid::now_v7(), &secret()).expect("seal");
        let needle = secret().expose().as_bytes().to_vec();
        assert!(!sealed.windows(needle.len()).any(|w| w == needle.as_slice()));
    }

    #[test]
    fn parse_accepts_hex_and_refuses_anything_else() {
        assert!(RolloutSecret::parse(&format!("  {}  ", "AB".repeat(16))).is_ok());
        assert!(RolloutSecret::parse("abc").is_err(), "too short");
        assert!(RolloutSecret::parse(&"zz".repeat(16)).is_err(), "not hex");
        assert!(RolloutSecret::parse(&"a".repeat(33)).is_err(), "odd length");
        assert!(RolloutSecret::parse(&"ab".repeat(200)).is_err(), "too long");
    }

    #[test]
    fn only_the_last_four_characters_are_ever_shown() {
        assert_eq!(secret().last4(), "0a1b");
        assert_eq!(format!("{:?}", secret()), "RolloutSecret([REDACTED])");
    }
}
