//! P-key-rotation-and-jwt (a) — versioned envelope encryption shared by every
//! AES-256-GCM-at-rest secret in the platform: `mfa::encrypt_secret`/
//! `decrypt_secret` (`config.auth.mfa_encryption_key`), `xrm_s2s::crypto`
//! (`config.s2s.key_encryption_key`), and `xrm_audit::erasure`'s DEK-wrapping
//! (`config.audit.erasure_key_encryption_key`) all call through here instead
//! of each hand-rolling the same `nonce || ciphertext` shape with no key
//! identity, which is exactly what made rotating any of those three keys
//! destructive before this feature (ENTERPRISE-AUDIT-2026-07-24.md #4).
//!
//! Each of MFA/S2S/erasure stays its own [`attome_config::KeyRing`] — a
//! *separate trust domain*, per D-069 — this module only supplies the shared
//! wire format and key-selection logic; it never mixes key material across
//! domains.
//!
//! ## Wire format
//!
//! `base64( 0x01 || key_id_len(u8) || key_id(utf8) || nonce(12) || ciphertext )`
//!
//! A blob that does not parse as this format, or names a key id the ring does
//! not hold, fails to decrypt.

use attome_config::KeyRing;
use attome_types::AppError;
use base64::{Engine, engine::general_purpose::STANDARD as B64};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};

const FORMAT_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;

fn parse_key(field_name: &str, hex_key: &str) -> Result<[u8; 32], AppError> {
    let bytes = hex::decode(hex_key)
        .map_err(|_| AppError::internal(format!("{field_name} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::internal(format!("{field_name} must be 32 bytes (64 hex chars)")))
}

/// Encrypts `plaintext` under `ring`'s active key, tagging the ciphertext
/// with that key's id so a future rotation can tell which key to decrypt it
/// with. `field_name` only shapes error messages (mirrors every other
/// `parse_master_key`-style helper in this codebase) — never echoes key
/// material or ciphertext. Returns the raw envelope bytes — callers with a
/// `BYTEA` column (`xrm_audit::erasure`'s DEK-wrapping) store this directly;
/// [`encrypt`] is the `String`/base64 convenience wrapper for `TEXT` columns.
pub fn encrypt_bytes(
    field_name: &str,
    ring: &KeyRing,
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    encrypt_bytes_with_aad(field_name, ring, plaintext, &[])
}

/// [`encrypt_bytes`] with AES-GCM additional authenticated data: `aad` is
/// not stored, but the ciphertext only opens with the same `aad` (the
/// recovery archive binds each value to its `(attribute, record)` so a blob
/// moved to another row fails to decrypt). Same wire format, same key-id and
/// nonce versioning; an empty `aad` is exactly [`encrypt_bytes`].
pub fn encrypt_bytes_with_aad(
    field_name: &str,
    ring: &KeyRing,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AppError> {
    let active_id = ring.active_key_id.as_str();
    let active_hex = ring
        .active()
        .ok_or_else(|| AppError::internal(format!("{field_name} has no active key configured")))?;
    if active_id.len() > u8::MAX as usize {
        return Err(AppError::internal(format!(
            "{field_name} active_key_id is too long to encode"
        )));
    }

    let key_bytes = parse_key(field_name, active_hex)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AppError::internal(format!("{field_name} encryption failed")))?;

    let mut combined = Vec::with_capacity(2 + active_id.len() + NONCE_LEN + ciphertext.len());
    combined.push(FORMAT_VERSION);
    combined.push(active_id.len() as u8);
    combined.extend_from_slice(active_id.as_bytes());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    Ok(combined)
}

/// Inverse of [`encrypt_bytes`]. Dispatches on the ciphertext's own stored key id, so a
/// key retired from `ring.active_key_id` but still present in `ring.keys`
/// still decrypts; removing it from the ring entirely is what ends its
/// overlap window (and is exactly what the rewrap job exists to make safe to
/// do).
pub fn decrypt_bytes(
    field_name: &str,
    ring: &KeyRing,
    combined: &[u8],
) -> Result<Vec<u8>, AppError> {
    decrypt_bytes_with_aad(field_name, ring, combined, &[])
}

/// Inverse of [`encrypt_bytes_with_aad`]: fails (never returns a wrong
/// plaintext) unless `aad` is the one the value was sealed with.
pub fn decrypt_bytes_with_aad(
    field_name: &str,
    ring: &KeyRing,
    combined: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AppError> {
    let (key_id, nonce_and_ciphertext) = parse_versioned(combined).ok_or_else(|| {
        AppError::internal(format!(
            "{field_name} ciphertext is not in the versioned format"
        ))
    })?;
    let key_hex = ring.get(key_id).ok_or_else(|| {
        AppError::internal(format!(
            "{field_name} ciphertext names a key id the ring does not hold"
        ))
    })?;
    let key_bytes = parse_key(field_name, key_hex)?;
    decrypt_with_key(field_name, &key_bytes, nonce_and_ciphertext, aad)
}

/// Z3-T3: seals an `EncryptedInRedis` cache's values with
/// `cache.encryption_key`, through [`encrypt`] and [`decrypt`] (AES-256-GCM,
/// tagged with the key id).
pub struct CacheSealer {
    ring: KeyRing,
}

impl std::fmt::Debug for CacheSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheSealer").finish_non_exhaustive()
    }
}

impl CacheSealer {
    pub fn new(ring: KeyRing) -> Self {
        Self { ring }
    }

    /// The deployment's sealer, when `cache.encryption_key` is set.
    pub fn from_config(
        config: &attome_config::AppConfig,
    ) -> Option<std::sync::Arc<dyn attome_cache::tiered::ValueSealer>> {
        let ring = config.cache.encryption_key.clone()?;
        if ring.is_empty() {
            return None;
        }
        Some(std::sync::Arc::new(Self::new(ring)))
    }
}

impl attome_cache::tiered::ValueSealer for CacheSealer {
    fn seal(&self, plaintext: &str) -> Result<String, AppError> {
        encrypt("cache.encryption_key", &self.ring, plaintext)
    }

    fn open(&self, sealed: &str) -> Result<String, AppError> {
        decrypt("cache.encryption_key", &self.ring, sealed)
    }
}

/// `String`/base64 convenience wrapper over [`encrypt_bytes`] for `TEXT`
/// columns (`mfa.rs`, `xrm_s2s::crypto`).
pub fn encrypt(field_name: &str, ring: &KeyRing, plaintext: &str) -> Result<String, AppError> {
    Ok(B64.encode(encrypt_bytes(field_name, ring, plaintext.as_bytes())?))
}

/// `String`/base64 convenience wrapper over [`decrypt_bytes`].
pub fn decrypt(field_name: &str, ring: &KeyRing, encoded: &str) -> Result<String, AppError> {
    let combined = B64
        .decode(encoded)
        .map_err(|_| AppError::internal(format!("{field_name} ciphertext is not valid base64")))?;
    let plaintext = decrypt_bytes(field_name, ring, &combined)?;
    String::from_utf8(plaintext)
        .map_err(|_| AppError::internal(format!("{field_name} decrypted to invalid UTF-8")))
}

/// Returns `(key_id, nonce || ciphertext)` if `combined` parses as this
/// module's versioned format — purely structural, does not check the ring.
fn parse_versioned(combined: &[u8]) -> Option<(&str, &[u8])> {
    if combined.first() != Some(&FORMAT_VERSION) {
        return None;
    }
    let key_id_len = *combined.get(1)? as usize;
    let key_id_start: usize = 2;
    let key_id_end = key_id_start.checked_add(key_id_len)?;
    let key_id_bytes = combined.get(key_id_start..key_id_end)?;
    let key_id = std::str::from_utf8(key_id_bytes).ok()?;
    let rest = &combined[key_id_end..];
    if rest.len() < NONCE_LEN {
        return None;
    }
    Some((key_id, rest))
}

fn decrypt_with_key(
    field_name: &str,
    key_bytes: &[u8; 32],
    nonce_and_ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AppError> {
    if nonce_and_ciphertext.len() < NONCE_LEN {
        return Err(AppError::internal(format!(
            "{field_name} ciphertext too short"
        )));
    }
    let (nonce_bytes, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AppError::internal(format!("{field_name} decryption failed")))
}

/// Generates a fresh random 32-byte data-encryption key (DEK) — raw bytes,
/// not hex. `xrm_audit::erasure` keeps one per record and wraps it under its
/// key ring with [`encrypt_bytes`] before storing it.
pub fn generate_dek() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// AES-256-GCM under a raw DEK (no key ring, no key id): returns
/// `nonce(12) || ciphertext`. `xrm_audit::erasure` uses it for per-record
/// values, reading them back with [`open_with_dek`].
pub fn seal_with_dek(dek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AppError::internal("envelope encryption failed"))?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

/// Inverse of [`seal_with_dek`]. Errors are generic and never echo key or
/// ciphertext material.
pub fn open_with_dek(dek: &[u8; 32], combined: &[u8]) -> Result<Vec<u8>, AppError> {
    decrypt_with_key("envelope", dek, combined, &[])
}

/// Returns the key id a base64-encoded blob (produced by [`encrypt`]) is
/// tagged with, without decrypting anything — `None` for anything
/// unparseable. The rewrap job (`PlatformJob::RewrapSecrets`) uses
/// this to skip a row that's already under the ring's active key without
/// paying for a decrypt+re-encrypt round trip that would just reproduce an
/// equivalent (but not byte-identical, since the nonce is fresh every call)
/// ciphertext.
pub fn stored_key_id(encoded: &str) -> Option<String> {
    let combined = B64.decode(encoded).ok()?;
    parse_versioned(&combined).map(|(key_id, _)| key_id.to_string())
}

/// [`stored_key_id`]'s counterpart for a raw (non-base64) `BYTEA` blob
/// produced by [`encrypt_bytes`] — `xrm_audit::erasure`'s rewrap job uses
/// this for `xrm_audit_erasure_key.wrapped_dek`.
pub fn stored_key_id_bytes(combined: &[u8]) -> Option<String> {
    parse_versioned(combined).map(|(key_id, _)| key_id.to_string())
}

/// Self-check used by the boot canary (`crates/server/src/main.rs`): encrypts
/// and immediately decrypts a fixed literal under `ring`'s active key. A
/// misconfigured ring (bad hex, wrong length) fails this before the node ever
/// takes traffic (D-038 fail-closed) instead of surfacing as a runtime 500 on
/// the first real request that happens to touch this domain.
pub fn canary(field_name: &str, ring: &KeyRing) -> Result<(), AppError> {
    const CANARY_PLAINTEXT: &str = "P-key-rotation-and-jwt boot canary";
    let encrypted = encrypt(field_name, ring, CANARY_PLAINTEXT)?;
    let decrypted = decrypt(field_name, ring, &encrypted)?;
    if decrypted != CANARY_PLAINTEXT {
        return Err(AppError::internal(format!(
            "{field_name} boot canary round-trip produced the wrong plaintext"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn dek_seal_open_roundtrips_and_detects_wrong_key() {
        let dek_a = generate_dek();
        let dek_b = generate_dek();
        let plaintext = b"some sensitive audit field value";
        let sealed = seal_with_dek(&dek_a, plaintext).unwrap();
        assert_eq!(open_with_dek(&dek_a, &sealed).unwrap(), plaintext);
        assert!(
            open_with_dek(&dek_b, &sealed).is_err(),
            "wrong key must not decrypt"
        );
    }

    #[test]
    fn dek_seal_uses_a_fresh_nonce_each_call() {
        let dek = generate_dek();
        let a = seal_with_dek(&dek, b"same plaintext").unwrap();
        let b = seal_with_dek(&dek, b"same plaintext").unwrap();
        assert_ne!(a, b, "random nonce must vary each call");
    }

    #[test]
    fn dek_open_rejects_truncated_ciphertext() {
        let dek = generate_dek();
        assert!(open_with_dek(&dek, b"short").is_err());
    }

    /// Z3-T3: what reaches Redis for an encrypted cache is not the value.
    #[test]
    fn encrypted_value_not_plaintext_in_redis_bytes() {
        use attome_cache::tiered::ValueSealer;

        let value = r#"{"email":"layla@example.com","salary":18250}"#;
        let sealer = CacheSealer::new(single_ring("k1", &key_hex(7)));
        let sealed = sealer.seal(value).unwrap();
        assert!(!sealed.contains("layla"), "{sealed}");
        assert!(!sealed.contains("18250"), "{sealed}");
        assert_eq!(sealer.open(&sealed).unwrap(), value);
        let other = CacheSealer::new(single_ring("k2", &key_hex(9)));
        assert!(
            other.open(&sealed).is_err(),
            "another ring does not open it"
        );
    }

    fn single_ring(key_id: &str, key_hex_value: &str) -> KeyRing {
        let mut keys = std::collections::HashMap::new();
        keys.insert(key_id.to_string(), key_hex_value.to_string());
        KeyRing {
            keys,
            active_key_id: key_id.to_string(),
        }
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let ring = single_ring("k1", &key_hex(0x11));
        let encrypted = encrypt("test", &ring, "hello world").unwrap();
        assert_eq!(decrypt("test", &ring, &encrypted).unwrap(), "hello world");
    }

    #[test]
    fn ciphertext_carries_the_active_key_id() {
        let ring = single_ring("my-key-id", &key_hex(0x22));
        let encrypted = encrypt("test", &ring, "secret").unwrap();
        let combined = B64.decode(&encrypted).unwrap();
        let (key_id, _) = parse_versioned(&combined).expect("must parse as versioned");
        assert_eq!(key_id, "my-key-id");
    }

    #[test]
    fn a_retired_key_still_present_in_the_ring_still_decrypts() {
        let mut ring = single_ring("k1", &key_hex(0x33));
        let encrypted = encrypt("test", &ring, "old data").unwrap();

        // Rotate: k2 becomes active, k1 stays in the map (still decryptable).
        ring.keys.insert("k2".to_string(), key_hex(0x44));
        ring.active_key_id = "k2".to_string();

        assert_eq!(decrypt("test", &ring, &encrypted).unwrap(), "old data");
        // New writes now go out under k2.
        let new_encrypted = encrypt("test", &ring, "new data").unwrap();
        let combined = B64.decode(&new_encrypted).unwrap();
        let (key_id, _) = parse_versioned(&combined).unwrap();
        assert_eq!(key_id, "k2");
    }

    #[test]
    fn removing_a_key_from_the_ring_ends_its_overlap_window() {
        let mut ring = single_ring("k1", &key_hex(0x55));
        let encrypted = encrypt("test", &ring, "data").unwrap();

        ring.keys.remove("k1");
        ring.keys.insert("k2".to_string(), key_hex(0x66));
        ring.active_key_id = "k2".to_string();

        // k1 is gone, so the blob names a key the ring no longer holds.
        assert!(decrypt("test", &ring, &encrypted).is_err());
    }

    #[test]
    fn wrong_key_id_in_ring_is_rejected_not_silently_wrong() {
        let ring_a = single_ring("k1", &key_hex(0x77));
        let encrypted = encrypt("test", &ring_a, "data").unwrap();

        let ring_b = single_ring("k1", &key_hex(0x88)); // same id, different key material
        assert!(decrypt("test", &ring_b, &encrypted).is_err());
    }

    #[test]
    fn canary_passes_for_a_well_formed_ring_and_fails_for_a_malformed_one() {
        let good_ring = single_ring("k1", &key_hex(0xbb));
        assert!(canary("test", &good_ring).is_ok());

        let bad_ring = single_ring("k1", "not-hex");
        assert!(canary("test", &bad_ring).is_err());
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let ring = single_ring("k1", &key_hex(0xcc));
        let a = encrypt("test", &ring, "same plaintext").unwrap();
        let b = encrypt("test", &ring, "same plaintext").unwrap();
        assert_ne!(a, b, "random nonce must vary each call");
    }

    #[test]
    fn stored_key_id_reports_the_tagging_key_id_without_decrypting() {
        let ring = single_ring("my-key-id", &key_hex(0xdd));
        let encrypted = encrypt("test", &ring, "secret").unwrap();
        assert_eq!(stored_key_id(&encrypted).as_deref(), Some("my-key-id"));
    }

    #[test]
    fn encrypt_bytes_then_decrypt_bytes_roundtrips_non_utf8_data() {
        // A 32-byte DEK (xrm_audit::erasure's actual use case) is not valid
        // UTF-8 in general — the whole reason a bytes-native path exists
        // alongside the str/base64 one.
        let ring = single_ring("k1", &key_hex(0xdd));
        let dek: [u8; 32] = [0xff; 32];
        let wrapped = encrypt_bytes("test", &ring, &dek).unwrap();
        assert_eq!(decrypt_bytes("test", &ring, &wrapped).unwrap(), dek);
    }

    #[test]
    fn encrypt_bytes_output_matches_encrypt_bytes_decoded_from_base64() {
        let ring = single_ring("k1", &key_hex(0xee));
        let raw = encrypt_bytes("test", &ring, b"hello").unwrap();
        let (key_id, _) = parse_versioned(&raw).expect("must parse as versioned");
        assert_eq!(key_id, "k1");
    }

    #[test]
    fn aad_binds_the_ciphertext_to_its_context() {
        let ring = single_ring("k1", &key_hex(0x44));
        let sealed = encrypt_bytes_with_aad("test", &ring, b"value", b"row-a").unwrap();
        assert_eq!(
            decrypt_bytes_with_aad("test", &ring, &sealed, b"row-a").unwrap(),
            b"value"
        );
        assert!(decrypt_bytes_with_aad("test", &ring, &sealed, b"row-b").is_err());
        assert!(decrypt_bytes("test", &ring, &sealed).is_err());
        assert_eq!(stored_key_id_bytes(&sealed).as_deref(), Some("k1"));
        // An empty aad is exactly the plain envelope.
        let plain = encrypt_bytes("test", &ring, b"v").unwrap();
        assert_eq!(
            decrypt_bytes_with_aad("test", &ring, &plain, b"").unwrap(),
            b"v"
        );
    }
}
