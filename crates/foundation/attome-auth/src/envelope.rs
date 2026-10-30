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
//!
//! Q18-T2: version `0x02` has the same layout and is sealed with AES-GCM
//! associated data naming where the value lives, `table|column|row_id`
//! ([`RowBinding`]), so a ciphertext copied to another row or column does
//! not open. [`encrypt_bound`] writes it; [`decrypt_bound`] opens both
//! versions (a `0x01` value written before binding opens without one). The
//! version byte is not authenticated, but changing `0x02` to `0x01` only
//! makes the value open with no associated data, which fails its tag.
//!
//! Q19-T1: version `0x03` is deterministic, for an encrypted attribute that
//! must answer equality filters: the nonce is an HMAC of the value and its
//! context (`table|column`) instead of random, so one value in one column
//! always seals to the same bytes. Its key and its nonce key are derived from
//! the ring's key (HMAC-SHA256 with a fixed label), so the raw key never
//! seals a value both ways. [`blind_index`] is the keyed, truncated HMAC an
//! equality search compares instead of the value.

use attome_config::KeyRing;
use attome_types::AppError;
use attome_types::secret::SecretString;
use base64::{Engine, engine::general_purpose::STANDARD as B64};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};

const FORMAT_VERSION: u8 = 0x01;
/// Q18-T2: the row-bound version.
const FORMAT_BOUND: u8 = 0x02;
/// Q19-T1: the deterministic version.
const FORMAT_DETERMINISTIC: u8 = 0x03;
/// Q19-T1: the labels the deterministic and blind-index keys are derived
/// under. Changing one makes every stored value under it unreadable.
const LABEL_DETERMINISTIC_KEY: &[u8] = b"attome/envelope/deterministic-key/v1";
const LABEL_DETERMINISTIC_NONCE: &[u8] = b"attome/envelope/deterministic-nonce/v1";
const LABEL_BLIND_INDEX: &[u8] = b"attome/envelope/blind-index/v1";
/// Q19-T1: bytes of HMAC-SHA256 a blind index keeps (128 bits).
const BLIND_INDEX_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Q18-T2: where a bound ciphertext lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowBinding<'a> {
    pub table: &'a str,
    pub column: &'a str,
    pub row_id: uuid::Uuid,
}

impl RowBinding<'_> {
    /// The associated data a bound value is sealed against.
    pub fn aad(&self) -> Vec<u8> {
        format!("{}|{}|{}", self.table, self.column, self.row_id).into_bytes()
    }
}

/// Q18-T2: [`encrypt`] bound to `binding`: base64 of a `0x02` envelope.
pub fn encrypt_bound(
    field_name: &str,
    ring: &KeyRing,
    plaintext: &str,
    binding: RowBinding<'_>,
) -> Result<String, AppError> {
    let mut sealed =
        encrypt_bytes_with_aad(field_name, ring, plaintext.as_bytes(), &binding.aad())?;
    sealed[0] = FORMAT_BOUND;
    Ok(B64.encode(sealed))
}

/// Q18-T2: opens a value [`encrypt_bound`] wrote for `binding`, or a `0x01`
/// value written by [`encrypt`] before the column was bound. Q18-T5: the
/// plaintext comes back as a [`SecretString`].
pub fn decrypt_bound(
    field_name: &str,
    ring: &KeyRing,
    encoded: &str,
    binding: RowBinding<'_>,
) -> Result<SecretString, AppError> {
    let combined = B64
        .decode(encoded)
        .map_err(|_| AppError::internal(format!("{field_name} ciphertext is not valid base64")))?;
    let aad = if combined.first() == Some(&FORMAT_BOUND) {
        binding.aad()
    } else {
        Vec::new()
    };
    let plaintext = decrypt_bytes_with_aad(field_name, ring, &combined, &aad)?;
    String::from_utf8(plaintext)
        .map(SecretString::new)
        .map_err(|_| AppError::internal(format!("{field_name} decrypted to invalid UTF-8")))
}

/// Q18-T2: whether a base64 value is a row-bound (`0x02`) envelope; a rewrap
/// re-seals the ones that are not.
pub fn stored_is_bound(encoded: &str) -> bool {
    B64.decode(encoded)
        .is_ok_and(|combined| combined.first() == Some(&FORMAT_BOUND))
}

/// Q19-T1: HMAC-SHA256 of `parts` under `key`, each part length-prefixed so
/// `("ab", "c")` and `("a", "bc")` differ.
#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn hmac_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 takes a key of any length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Q19-T1: the deterministic encryption key and nonce key derived from one
/// ring key.
fn deterministic_keys(key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (
        hmac_parts(key, &[LABEL_DETERMINISTIC_KEY]),
        hmac_parts(key, &[LABEL_DETERMINISTIC_NONCE]),
    )
}

/// Q19-T1: seals `plaintext` under `ring`'s active key so the same value
/// with the same `context` always gives the same base64 (`0x03` envelope).
/// Use it only where equality on the ciphertext is wanted: it shows which
/// stored values are equal. `context` (for an attribute, `table|column`) is
/// both the associated data and part of the nonce, so a value sealed for one
/// column neither opens in nor matches another.
pub fn encrypt_deterministic(
    field_name: &str,
    ring: &KeyRing,
    plaintext: &str,
    context: &[u8],
) -> Result<String, AppError> {
    let active_id = ring.active_key_id.as_str();
    let active_hex = ring
        .active()
        .ok_or_else(|| AppError::internal(format!("{field_name} has no active key configured")))?;
    if active_id.len() > u8::MAX as usize {
        return Err(AppError::internal(format!(
            "{field_name} active_key_id is too long to encode"
        )));
    }
    let (enc_key, nonce_key) = deterministic_keys(&parse_key(field_name, active_hex)?);
    let synthetic = hmac_parts(&nonce_key, &[context, plaintext.as_bytes()]);
    let nonce = Nonce::from_slice(&synthetic[..NONCE_LEN]);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&enc_key));
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: context,
            },
        )
        .map_err(|_| AppError::internal(format!("{field_name} encryption failed")))?;

    let mut combined = Vec::with_capacity(2 + active_id.len() + NONCE_LEN + ciphertext.len());
    combined.push(FORMAT_DETERMINISTIC);
    combined.push(active_id.len() as u8);
    combined.extend_from_slice(active_id.as_bytes());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ciphertext);
    Ok(B64.encode(combined))
}

/// Q19-T1: opens a value [`encrypt_deterministic`] sealed for `context`.
pub fn decrypt_deterministic(
    field_name: &str,
    ring: &KeyRing,
    encoded: &str,
    context: &[u8],
) -> Result<SecretString, AppError> {
    let combined = B64
        .decode(encoded)
        .map_err(|_| AppError::internal(format!("{field_name} ciphertext is not valid base64")))?;
    if combined.first() != Some(&FORMAT_DETERMINISTIC) {
        return Err(AppError::internal(format!(
            "{field_name} ciphertext is not a deterministic envelope"
        )));
    }
    let plaintext = decrypt_bytes_with_aad(field_name, ring, &combined, context)?;
    String::from_utf8(plaintext)
        .map(SecretString::new)
        .map_err(|_| AppError::internal(format!("{field_name} decrypted to invalid UTF-8")))
}

/// Q19-T1: whether a base64 value is a deterministic (`0x03`) envelope.
pub fn stored_is_deterministic(encoded: &str) -> bool {
    B64.decode(encoded)
        .is_ok_and(|combined| combined.first() == Some(&FORMAT_DETERMINISTIC))
}

/// Q19-T1: the blind index of `value` in `context` under the ring key
/// `key_id`: `<key_id>:<32 hex>`, the first 128 bits of an HMAC-SHA256 keyed
/// by a key derived from that ring key. An equality search compares indexes,
/// never values. The key id is part of the index so a rotation can tell which
/// rows still carry an old one.
pub fn blind_index_with(
    field_name: &str,
    ring: &KeyRing,
    key_id: &str,
    context: &[u8],
    value: &str,
) -> Result<String, AppError> {
    let key_hex = ring.get(key_id).ok_or_else(|| {
        AppError::internal(format!("{field_name} has no key with the requested id"))
    })?;
    let index_key = hmac_parts(&parse_key(field_name, key_hex)?, &[LABEL_BLIND_INDEX]);
    let digest = hmac_parts(&index_key, &[context, value.as_bytes()]);
    Ok(format!(
        "{key_id}:{}",
        hex::encode(&digest[..BLIND_INDEX_LEN])
    ))
}

/// Q19-T1: [`blind_index_with`] under the ring's active key: what a write
/// stores.
pub fn blind_index(
    field_name: &str,
    ring: &KeyRing,
    context: &[u8],
    value: &str,
) -> Result<String, AppError> {
    blind_index_with(field_name, ring, &ring.active_key_id, context, value)
}

/// Q19-T1: the blind index of `value` under every key in the ring, sorted:
/// what an equality search matches, so a row still indexed under a key a
/// rotation has not reached yet is found.
pub fn blind_indexes(
    field_name: &str,
    ring: &KeyRing,
    context: &[u8],
    value: &str,
) -> Result<Vec<String>, AppError> {
    let mut ids: Vec<&String> = ring.keys.keys().collect();
    ids.sort();
    ids.into_iter()
        .map(|id| blind_index_with(field_name, ring, id, context, value))
        .collect()
}

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
    let mut key_bytes = parse_key(field_name, key_hex)?;
    if combined.first() == Some(&FORMAT_DETERMINISTIC) {
        key_bytes = deterministic_keys(&key_bytes).0;
    }
    decrypt_with_key(field_name, &key_bytes, nonce_and_ciphertext, aad)
}

/// Q18-T4: reseals one stored envelope (`combined`, either version) under
/// `ring`'s active key against the same `aad`, keeping its version byte, so
/// a rotation needs no knowledge of what the value means. `aad` is what the
/// value was sealed against (empty for an unbound `0x01` text value).
pub fn reseal_bytes(
    field_name: &str,
    ring: &KeyRing,
    combined: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AppError> {
    let version = *combined
        .first()
        .ok_or_else(|| AppError::internal(format!("{field_name} ciphertext is empty")))?;
    let plain = decrypt_bytes_with_aad(field_name, ring, combined, aad)?;
    if version == FORMAT_DETERMINISTIC {
        // Q19-T1: a deterministic value stays deterministic, or equality
        // on it would stop matching after a rotation.
        let text = String::from_utf8(plain)
            .map_err(|_| AppError::internal(format!("{field_name} decrypted to invalid UTF-8")))?;
        let encoded = encrypt_deterministic(field_name, ring, &text, aad)?;
        return B64.decode(encoded).map_err(|_| {
            AppError::internal(format!("{field_name} ciphertext is not valid base64"))
        });
    }
    let mut fresh = encrypt_bytes_with_aad(field_name, ring, &plain, aad)?;
    // A reader that opens without a binding must keep getting an unbound
    // value, and a bound one stays bound.
    fresh[0] = version;
    Ok(fresh)
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
        decrypt("cache.encryption_key", &self.ring, sealed).map(SecretString::into_exposed)
    }
}

/// `String`/base64 convenience wrapper over [`encrypt_bytes`] for `TEXT`
/// columns (`mfa.rs`, `xrm_s2s::crypto`).
pub fn encrypt(field_name: &str, ring: &KeyRing, plaintext: &str) -> Result<String, AppError> {
    Ok(B64.encode(encrypt_bytes(field_name, ring, plaintext.as_bytes())?))
}

/// `String`/base64 convenience wrapper over [`decrypt_bytes`]. Q18-T5: the
/// plaintext comes back as a [`SecretString`].
pub fn decrypt(field_name: &str, ring: &KeyRing, encoded: &str) -> Result<SecretString, AppError> {
    let combined = B64
        .decode(encoded)
        .map_err(|_| AppError::internal(format!("{field_name} ciphertext is not valid base64")))?;
    let plaintext = decrypt_bytes(field_name, ring, &combined)?;
    String::from_utf8(plaintext)
        .map(SecretString::new)
        .map_err(|_| AppError::internal(format!("{field_name} decrypted to invalid UTF-8")))
}

/// Returns `(key_id, nonce || ciphertext)` if `combined` parses as this
/// module's versioned format — purely structural, does not check the ring.
fn parse_versioned(combined: &[u8]) -> Option<(&str, &[u8])> {
    if !matches!(
        combined.first(),
        Some(&FORMAT_VERSION | &FORMAT_BOUND | &FORMAT_DETERMINISTIC)
    ) {
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
    if decrypted.expose_secret() != CANARY_PLAINTEXT {
        return Err(AppError::internal(format!(
            "{field_name} boot canary round-trip produced the wrong plaintext"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod deterministic_tests {
    use super::*;

    fn ring(ids: &[(&str, u8)], active: &str) -> KeyRing {
        KeyRing {
            keys: ids
                .iter()
                .map(|(id, byte)| (id.to_string(), hex::encode([*byte; 32])))
                .collect(),
            active_key_id: active.to_string(),
        }
    }

    #[test]
    fn deterministic_seal_is_stable_and_opens() {
        let ring = ring(&[("k1", 3)], "k1");
        let a = encrypt_deterministic("f", &ring, "layla@example.com", b"contact|email").unwrap();
        let b = encrypt_deterministic("f", &ring, "layla@example.com", b"contact|email").unwrap();
        assert_eq!(a, b, "same value, same context: same ciphertext");
        assert!(stored_is_deterministic(&a));
        assert!(!a.contains("layla"));
        assert_eq!(stored_key_id(&a).as_deref(), Some("k1"));
        assert_eq!(
            decrypt_deterministic("f", &ring, &a, b"contact|email")
                .unwrap()
                .expose_secret(),
            "layla@example.com"
        );
    }

    #[test]
    fn deterministic_seal_differs_by_value_and_context() {
        let ring = ring(&[("k1", 3)], "k1");
        let base = encrypt_deterministic("f", &ring, "a", b"contact|email").unwrap();
        assert_ne!(
            base,
            encrypt_deterministic("f", &ring, "b", b"contact|email").unwrap()
        );
        let other_column = encrypt_deterministic("f", &ring, "a", b"contact|phone").unwrap();
        assert_ne!(base, other_column);
        assert!(
            decrypt_deterministic("f", &ring, &base, b"contact|phone").is_err(),
            "a value moved to another column must not open"
        );
    }

    #[test]
    fn deterministic_value_is_not_a_random_one() {
        let ring = ring(&[("k1", 3)], "k1");
        let random = encrypt("f", &ring, "a").unwrap();
        assert!(decrypt_deterministic("f", &ring, &random, b"").is_err());
        assert!(!stored_is_deterministic(&random));
    }

    #[test]
    fn deterministic_reseal_moves_to_the_active_key_and_stays_deterministic() {
        let old = ring(&[("k1", 3)], "k1");
        let sealed = encrypt_deterministic("f", &old, "v", b"t|c").unwrap();
        let rotated = ring(&[("k1", 3), ("k2", 4)], "k2");
        let combined = B64.decode(&sealed).unwrap();
        let fresh = B64.encode(reseal_bytes("f", &rotated, &combined, b"t|c").unwrap());
        assert_eq!(stored_key_id(&fresh).as_deref(), Some("k2"));
        assert_eq!(
            fresh,
            encrypt_deterministic("f", &rotated, "v", b"t|c").unwrap(),
            "a resealed value still equals a fresh seal of the same value"
        );
    }

    #[test]
    fn blind_index_is_keyed_truncated_and_per_context() {
        let one = ring(&[("k1", 3)], "k1");
        let a = blind_index("f", &one, b"contact|email", "x@y.test").unwrap();
        assert_eq!(
            a,
            blind_index("f", &one, b"contact|email", "x@y.test").unwrap()
        );
        let (key_id, digest) = a.split_once(':').unwrap();
        assert_eq!(key_id, "k1");
        assert_eq!(digest.len(), BLIND_INDEX_LEN * 2);
        assert_ne!(
            a,
            blind_index("f", &one, b"contact|phone", "x@y.test").unwrap()
        );
        assert_ne!(
            a,
            blind_index("f", &one, b"contact|email", "x@y.tesu").unwrap()
        );
        let other_key = ring(&[("k1", 9)], "k1");
        assert_ne!(
            a,
            blind_index("f", &other_key, b"contact|email", "x@y.test").unwrap()
        );
    }

    #[test]
    fn blind_indexes_cover_every_ring_key() {
        let two = ring(&[("k2", 4), ("k1", 3)], "k2");
        let all = blind_indexes("f", &two, b"t|c", "v").unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].starts_with("k1:") && all[1].starts_with("k2:"));
        assert!(all.contains(&blind_index("f", &two, b"t|c", "v").unwrap()));
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    fn binding(row_id: uuid::Uuid) -> RowBinding<'static> {
        RowBinding {
            table: "s2s_client_key",
            column: "secret_encrypted",
            row_id,
        }
    }

    #[test]
    fn a_ciphertext_copied_to_another_row_fails_to_decrypt() {
        let ring = KeyRing::single("44".repeat(32));
        let row = uuid::Uuid::now_v7();
        let sealed = encrypt_bound("f", &ring, "secret", binding(row)).unwrap();
        assert!(stored_is_bound(&sealed));
        assert_eq!(
            decrypt_bound("f", &ring, &sealed, binding(row))
                .unwrap()
                .expose_secret(),
            "secret"
        );
        assert!(decrypt_bound("f", &ring, &sealed, binding(uuid::Uuid::now_v7())).is_err());
        let other_column = RowBinding {
            column: "other",
            ..binding(row)
        };
        assert!(decrypt_bound("f", &ring, &sealed, other_column).is_err());
        assert!(
            decrypt("f", &ring, &sealed).is_err(),
            "unbound decrypt refuses it"
        );
    }

    #[test]
    fn an_unbound_value_still_opens_and_a_downgraded_one_does_not() {
        let ring = KeyRing::single("55".repeat(32));
        let row = uuid::Uuid::now_v7();
        let legacy = encrypt("f", &ring, "old").unwrap();
        assert!(!stored_is_bound(&legacy));
        assert_eq!(
            decrypt_bound("f", &ring, &legacy, binding(row))
                .unwrap()
                .expose_secret(),
            "old"
        );
        assert_eq!(stored_key_id(&legacy), stored_key_id(&legacy));

        let sealed = encrypt_bound("f", &ring, "new", binding(row)).unwrap();
        let mut bytes = B64.decode(&sealed).unwrap();
        bytes[0] = FORMAT_VERSION;
        let downgraded = B64.encode(bytes);
        assert!(decrypt_bound("f", &ring, &downgraded, binding(row)).is_err());
        assert_eq!(
            stored_key_id(&sealed).as_deref(),
            Some(ring.active_key_id.as_str())
        );
    }
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
        assert_eq!(
            decrypt("test", &ring, &encrypted).unwrap().expose_secret(),
            "hello world"
        );
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

        assert_eq!(
            decrypt("test", &ring, &encrypted).unwrap().expose_secret(),
            "old data"
        );
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
