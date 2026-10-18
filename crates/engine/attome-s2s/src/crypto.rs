use attome_config::KeyRing;
use attome_types::AppError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const FIELD_NAME: &str = "s2s.key_encryption_key";

pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// P-key-rotation-and-jwt (a): versioned envelope over `ring` — see
/// `attome_auth::envelope`'s doc for the wire format and rotation/overlap-window
/// semantics. `s2s_client_key.secret_encrypted` carries the key id
/// inline, so no schema change was needed to support this.
pub fn encrypt_secret(ring: &KeyRing, plaintext: &str) -> Result<String, AppError> {
    attome_auth::envelope::encrypt(FIELD_NAME, ring, plaintext)
}

pub fn decrypt_secret(ring: &KeyRing, encoded: &str) -> Result<String, AppError> {
    attome_auth::envelope::decrypt(FIELD_NAME, ring, encoded)
}

/// Q18-T2: `s2s_client_key.secret_encrypted` is bound to its row.
fn binding(key_id: uuid::Uuid) -> attome_auth::envelope::RowBinding<'static> {
    attome_auth::envelope::RowBinding {
        table: "s2s_client_key",
        column: "secret_encrypted",
        row_id: key_id,
    }
}

/// Q18-T2: a client key's secret, bound to the key row `key_id`.
pub fn encrypt_key_secret(
    ring: &KeyRing,
    key_id: uuid::Uuid,
    plaintext: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::encrypt_bound(FIELD_NAME, ring, plaintext, binding(key_id))
}

/// Q18-T2: opens a key row's secret, bound or written before binding.
pub fn decrypt_key_secret(
    ring: &KeyRing,
    key_id: uuid::Uuid,
    encoded: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::decrypt_bound(FIELD_NAME, ring, encoded, binding(key_id))
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn canonical_message(
    method: &str,
    path_and_query: &str,
    body_sha256_hex: &str,
    timestamp_ms: &str,
    nonce: &str,
) -> Vec<u8> {
    format!("{method}\n{path_and_query}\n{body_sha256_hex}\n{timestamp_ms}\n{nonce}").into_bytes()
}

/// S1-T10: [`canonical_message`] for a request that names a user to act as
/// (`x-attome-act-as`): the user id is a sixth line, so a signature made
/// without it cannot carry one, and a request without the header signs
/// exactly what it always did (every deployed client keeps working).
pub fn canonical_message_with_act_as(
    method: &str,
    path_and_query: &str,
    body_sha256_hex: &str,
    timestamp_ms: &str,
    nonce: &str,
    act_as: Option<&str>,
) -> Vec<u8> {
    let mut message =
        canonical_message(method, path_and_query, body_sha256_hex, timestamp_ms, nonce);
    if let Some(user) = act_as {
        message.push(b'\n');
        message.extend_from_slice(user.as_bytes());
    }
    message
}

/// The caller's side of [`verify_hmac`]: the hex HMAC-SHA256 of `message`
/// keyed by the hex-decoded secret (D-779: S2S callers and tests that sign
/// requests). `None` if `secret_hex` isn't hex.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn sign_hmac(secret_hex: &str, message: &[u8]) -> Option<String> {
    let secret_bytes = hex::decode(secret_hex).ok()?;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&secret_bytes).expect("HMAC accepts any key length");
    mac.update(message);
    Some(hex::encode(mac.finalize().into_bytes()))
}

#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn verify_hmac(secret_hex: &str, message: &[u8], provided_sig_hex: &str) -> bool {
    let Ok(secret_bytes) = hex::decode(secret_hex) else {
        return false;
    };
    let Ok(expected_bytes) = hex::decode(provided_sig_hex) else {
        return false;
    };

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&secret_bytes).expect("HMAC accepts any key length");
    mac.update(message);
    mac.verify_slice(&expected_bytes).is_ok()
}

// ── Tests (P1.8 money-path #1 — S2S verification matrix, pure-fn half) ───────
// This is the ACTIVE implementation the s2s_authn middleware calls
// (`crate::crypto` in middleware.rs). `base-s2s` in attome-base carried an
// unused duplicate of this file and was deleted (D-023) — this crate is now
// the sole S2S implementation, resolving audit finding #17.
#[cfg(test)]
mod tests {
    use super::*;

    fn sign_hmac(secret_hex: &str, message: &[u8]) -> String {
        let secret_bytes = hex::decode(secret_hex).unwrap();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&secret_bytes).unwrap();
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn canonical_message_matches_the_documented_newline_format() {
        let msg = canonical_message(
            "POST",
            "/api/v1/widgets?x=1",
            "deadbeef",
            "1720000000000",
            "abc-nonce",
        );
        assert_eq!(
            msg,
            b"POST\n/api/v1/widgets?x=1\ndeadbeef\n1720000000000\nabc-nonce".to_vec()
        );
    }

    #[test]
    fn act_as_is_a_signed_sixth_line_only_when_present() {
        let plain = canonical_message("GET", "/api/v1/x", "h", "1", "n");
        assert_eq!(
            canonical_message_with_act_as("GET", "/api/v1/x", "h", "1", "n", None),
            plain
        );
        let acting = canonical_message_with_act_as("GET", "/api/v1/x", "h", "1", "n", Some("u-1"));
        assert_eq!(acting, b"GET\n/api/v1/x\nh\n1\nn\nu-1".to_vec());
        assert_ne!(acting, plain);
    }

    #[test]
    fn canonical_message_is_stable_across_calls_with_the_same_inputs() {
        let a = canonical_message("GET", "/api/v1/x", "hash1", "100", "nonce1");
        let b = canonical_message("GET", "/api/v1/x", "hash1", "100", "nonce1");
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_message_changes_if_any_single_field_changes() {
        let base = canonical_message("GET", "/api/v1/x", "hash1", "100", "nonce1");
        assert_ne!(
            base,
            canonical_message("POST", "/api/v1/x", "hash1", "100", "nonce1")
        );
        assert_ne!(
            base,
            canonical_message("GET", "/api/v1/y", "hash1", "100", "nonce1")
        );
        assert_ne!(
            base,
            canonical_message("GET", "/api/v1/x", "hash2", "100", "nonce1")
        );
        assert_ne!(
            base,
            canonical_message("GET", "/api/v1/x", "hash1", "101", "nonce1")
        );
        assert_ne!(
            base,
            canonical_message("GET", "/api/v1/x", "hash1", "100", "nonce2")
        );
    }

    #[test]
    fn sha256_hex_is_deterministic_and_input_sensitive() {
        assert_eq!(sha256_hex(b"abc").len(), 64, "must be 32 bytes hex-encoded");
        assert_eq!(sha256_hex(b"abc"), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
        assert_ne!(sha256_hex(b""), sha256_hex(b"abc"));
    }

    #[test]
    fn verify_hmac_accepts_a_correctly_signed_message() {
        let secret = generate_secret();
        let message = canonical_message("GET", "/api/v1/x", "hash", "100", "nonce");
        let sig = sign_hmac(&secret, &message);
        assert!(verify_hmac(&secret, &message, &sig));
    }

    #[test]
    fn the_public_signer_is_what_verify_accepts() {
        let secret = generate_secret();
        let message = canonical_message("POST", "/api/v1/s2s/x", "hash", "100", "nonce");
        let sig = super::sign_hmac(&secret, &message).expect("hex secret");
        assert_eq!(sig, sign_hmac(&secret, &message));
        assert!(verify_hmac(&secret, &message, &sig));
        assert_eq!(super::sign_hmac("not hex", &message), None);
    }

    #[test]
    fn verify_hmac_rejects_a_single_flipped_byte_in_the_signature() {
        let secret = generate_secret();
        let message = canonical_message("GET", "/api/v1/x", "hash", "100", "nonce");
        let mut sig_bytes = hex::decode(sign_hmac(&secret, &message)).unwrap();
        sig_bytes[0] ^= 0x01; // flip one bit of the first byte
        let tampered_sig = hex::encode(sig_bytes);
        assert!(!verify_hmac(&secret, &message, &tampered_sig));
    }

    #[test]
    fn verify_hmac_rejects_a_message_signed_with_a_different_secret() {
        let secret_a = generate_secret();
        let secret_b = generate_secret();
        let message = canonical_message("GET", "/api/v1/x", "hash", "100", "nonce");
        let sig = sign_hmac(&secret_a, &message);
        assert!(!verify_hmac(&secret_b, &message, &sig));
    }

    #[test]
    fn verify_hmac_rejects_a_tampered_message_body_hash() {
        let secret = generate_secret();
        let signed_message =
            canonical_message("POST", "/api/v1/x", "hash-of-original-body", "100", "nonce");
        let sig = sign_hmac(&secret, &signed_message);

        // Same signature, but the body hash embedded in the canonical message
        // now reflects a different (tampered) body — this is exactly what
        // the middleware recomputes server-side from the actual bytes it
        // reads, so a body swap after signing must fail verification.
        let tampered_message =
            canonical_message("POST", "/api/v1/x", "hash-of-tampered-body", "100", "nonce");
        assert!(!verify_hmac(&secret, &tampered_message, &sig));
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
