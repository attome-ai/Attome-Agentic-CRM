//! Webhook secret custody + HMAC signing — mirrors `attome-s2s::crypto`'s
//! canonical-signing discipline (M62 plan §3/§5) but for the opposite
//! direction: `attome-s2s` verifies an *inbound* caller's signature, this signs
//! an *outbound* delivery this deployment sends to a subscriber-controlled
//! URL. Kept as a near-duplicate rather than a shared helper for the same
//! reason `attome_auth::mfa`'s AES helper stays local (D-069's envelope doc):
//! `attome-events` and `attome-s2s` are peer engine crates, and ~40 lines of
//! well-tested crypto is cheaper than a premature shared-crypto abstraction
//! between two call sites that must stay independently rotatable anyway.

use attome_config::KeyRing;
use attome_types::AppError;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// `attome_auth::envelope`'s `field_name` — shapes error messages only, never
/// key material (see that module's doc comment).
const FIELD_NAME: &str = "events.webhook_signing_key";

/// The header a delivery is signed under (M62 plan §3).
pub const SIGNATURE_HEADER: &str = "X-Attome-Signature";

pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// D-069: `events.webhook_signing_key` is a separate trust domain from
/// `s2s.key_encryption_key` — see that config field's doc comment.
pub fn encrypt_secret(ring: &KeyRing, plaintext: &str) -> Result<String, AppError> {
    attome_auth::envelope::encrypt(FIELD_NAME, ring, plaintext)
}

pub fn decrypt_secret(ring: &KeyRing, encoded: &str) -> Result<String, AppError> {
    attome_auth::envelope::decrypt(FIELD_NAME, ring, encoded)
        .map(attome_types::secret::SecretString::into_exposed)
}

/// Q18-T2: `event_subscription.webhook_secret_encrypted` is bound to its row.
fn binding(subscription_id: uuid::Uuid) -> attome_auth::envelope::RowBinding<'static> {
    attome_auth::envelope::RowBinding {
        table: "event_subscription",
        column: "webhook_secret_encrypted",
        row_id: subscription_id,
    }
}

pub fn encrypt_webhook_secret(
    ring: &KeyRing,
    subscription_id: uuid::Uuid,
    plaintext: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::encrypt_bound(FIELD_NAME, ring, plaintext, binding(subscription_id))
}

pub fn decrypt_webhook_secret(
    ring: &KeyRing,
    subscription_id: uuid::Uuid,
    encoded: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::decrypt_bound(FIELD_NAME, ring, encoded, binding(subscription_id))
        .map(attome_types::secret::SecretString::into_exposed)
}

/// `{timestamp_ms}.{body}` — the exact bytes HMAC'd and the exact bytes a
/// receiver must reconstruct to verify. Timestamp-prefixed (not merely
/// carried in a header) so the signature itself binds the two together —
/// swapping either the body or the `t=` value in the header without
/// re-signing fails verification, the same tamper-evidence property
/// `attome-s2s::crypto::canonical_message` gives its own five-field message.
pub fn canonical_message(timestamp_ms: &str, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(timestamp_ms.len() + 1 + body.len());
    msg.extend_from_slice(timestamp_ms.as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(body);
    msg
}

/// Signs `message` and formats the header value: `t=<ms>,v1=<hex hmac>` —
/// Stripe-webhook-shaped, so a receiver already familiar with that
/// convention needs no new mental model. `secret_hex` is the *decrypted*
/// per-subscription secret (never logged — callers must not `Debug`/log it).
pub fn sign_header(secret_hex: &str, timestamp_ms: &str, body: &[u8]) -> Result<String, AppError> {
    let secret_bytes = hex::decode(secret_hex)
        .map_err(|_| AppError::internal("webhook secret is not valid hex"))?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&secret_bytes)
        .map_err(|_| AppError::internal("HMAC accepts any key length"))?;
    mac.update(&canonical_message(timestamp_ms, body));
    let sig_hex = hex::encode(mac.finalize().into_bytes());
    Ok(format!("t={timestamp_ms},v1={sig_hex}"))
}

/// Constant-time verification counterpart — not on the sending path (nothing
/// in this deployment verifies its own outbound signatures), but proves
/// `sign_header`'s output actually matches what a receiver reconstructs,
/// which is the whole point of shipping a signature at all.
#[cfg(test)]
pub fn verify_header(secret_hex: &str, header: &str, body: &[u8]) -> bool {
    let Some((t_part, v1_part)) = header.split_once(',') else {
        return false;
    };
    let Some(timestamp_ms) = t_part.strip_prefix("t=") else {
        return false;
    };
    let Some(provided_sig_hex) = v1_part.strip_prefix("v1=") else {
        return false;
    };
    let Ok(secret_bytes) = hex::decode(secret_hex) else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(provided_sig_hex) else {
        return false;
    };
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(&secret_bytes) else {
        return false;
    };
    mac.update(&canonical_message(timestamp_ms, body));
    mac.verify_slice(&expected_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_matches_the_documented_dot_format() {
        let msg = canonical_message("1720000000000", b"{\"a\":1}");
        assert_eq!(msg, b"1720000000000.{\"a\":1}".to_vec());
    }

    #[test]
    fn sign_header_round_trips_through_verify_header() {
        let secret = generate_secret();
        let body = b"{\"event_id\":\"abc\"}";
        let header = sign_header(&secret, "1720000000000", body).unwrap();
        assert!(header.starts_with("t=1720000000000,v1="));
        assert!(verify_header(&secret, &header, body));
    }

    #[test]
    fn verify_header_rejects_a_tampered_body() {
        let secret = generate_secret();
        let header = sign_header(&secret, "100", b"original").unwrap();
        assert!(!verify_header(&secret, &header, b"tampered"));
    }

    #[test]
    fn verify_header_rejects_a_different_secret() {
        let secret_a = generate_secret();
        let secret_b = generate_secret();
        let header = sign_header(&secret_a, "100", b"body").unwrap();
        assert!(!verify_header(&secret_b, &header, b"body"));
    }

    #[test]
    fn verify_header_rejects_a_tampered_timestamp() {
        let secret = generate_secret();
        let header = sign_header(&secret, "100", b"body").unwrap();
        let tampered = header.replace("t=100", "t=200");
        assert!(!verify_header(&secret, &tampered, b"body"));
    }

    #[test]
    fn encrypt_decrypt_secret_roundtrips_and_detects_wrong_key() {
        let ring_a = KeyRing::single("11".repeat(32));
        let ring_b = KeyRing::single("22".repeat(32));
        let secret = generate_secret();

        let encrypted = encrypt_secret(&ring_a, &secret).unwrap();
        assert_eq!(decrypt_secret(&ring_a, &encrypted).unwrap(), secret);
        assert!(
            decrypt_secret(&ring_b, &encrypted).is_err(),
            "wrong key must not decrypt"
        );
    }
}
