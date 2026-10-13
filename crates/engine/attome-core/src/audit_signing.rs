//! Ed25519 signing for the audit hash chain (P1.5b).
//!
//! This is a *dedicated* audit-signing keypair, unrelated to the license
//! verifier's Ed25519 code (`attome-modules/src/verifier.rs`, D-142): that key
//! is verify-only (a compiled-in public key checking license files; the
//! matching private key deliberately never exists in this binary). Signing
//! every audit event needs the private key present at write time, so it
//! cannot reuse the license key without breaking that key's threat model.
//! See D-016.
//!
//! ## Key registry (P-key-rotation-and-jwt (d))
//!
//! `AuditSigner::verify` (below) is a *self-check*: it can only verify a
//! signature against whichever seed happens to be configured right now, so a
//! signing-key rotation makes every historical signature "fail" even though
//! nothing was tampered with — the stored `signing_key_id` says exactly which
//! key produced it, but nothing looked it up. `audit_signing_key`
//! (migration `0048_audit_signing_key_registry.sql`) closes this: an
//! append-only-in-practice (D-005 infra-mutable class — `retired_at` is the
//! one column that ever changes) registry of `key_id -> public_key`, upserted
//! (insert-if-absent only) at boot from whatever `AuditSigner` the current
//! config produces. Chain verification then resolves the verifying key from
//! a signature's *own* stored `key_id` via [`lookup_signing_public_key`] +
//! [`verify_with_key`], falling back to the current signer's self-check only
//! when the registry has no row for that key_id (pre-migration history).

use attome_db::DbPool;
use attome_types::AppError;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Holds one Ed25519 keypair used to sign `(prev_hash || event_hash)` at
/// audit-write time. `key_id` is stored alongside every signature it
/// produces so old signatures stay attributable/verifiable after rotation.
pub struct AuditSigner {
    pub key_id: String,
    signing_key: SigningKey,
}

impl std::fmt::Debug for AuditSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSigner").finish_non_exhaustive()
    }
}

impl AuditSigner {
    /// `hex_seed` is a 64-hex-char (32-byte) Ed25519 seed, e.g. from
    /// `config.audit.signing_private_key` (`openssl rand -hex 32`).
    pub fn from_config(key_id: &str, hex_seed: &str) -> Result<Self, AppError> {
        let bytes = hex::decode(hex_seed)
            .map_err(|_| AppError::internal("audit.signing_private_key is not valid hex"))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            AppError::internal("audit.signing_private_key must be 32 bytes (64 hex chars)")
        })?;

        Ok(Self {
            key_id: key_id.to_owned(),
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// Signs `prev_hash|event_hash`, returning the base64-encoded signature.
    pub fn sign(&self, prev_hash: &str, event_hash: &str) -> String {
        let payload = format!("{prev_hash}|{event_hash}");
        let signature = self.signing_key.sign(payload.as_bytes());
        B64.encode(signature.to_bytes())
    }

    /// Verifies a base64 signature produced by `sign` (P1.13 stage 3). Only
    /// this deployment's own signing keypair can verify its own signatures —
    /// this is a self-check that the stored signature matches the stored
    /// hashes, not third-party public verification (there is no separate
    /// verify-only key for the audit chain, unlike the license verifier's).
    /// Used as the registry-lookup fallback (see module doc) —
    /// `verify_with_key` is the registry-driven counterpart.
    pub fn verify(&self, prev_hash: &str, event_hash: &str, signature_b64: &str) -> bool {
        let Ok(sig_bytes) = B64.decode(signature_b64) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        let signature = Signature::from_bytes(&sig_bytes);
        let payload = format!("{prev_hash}|{event_hash}");
        self.signing_key
            .verifying_key()
            .verify(payload.as_bytes(), &signature)
            .is_ok()
    }

    /// This signer's public key, base64-encoded — what gets registered under
    /// its `key_id` in `audit_signing_key` (`upsert_signing_key`).
    pub fn verifying_key_b64(&self) -> String {
        B64.encode(self.signing_key.verifying_key().to_bytes())
    }
}

/// Verifies a signature against an explicit public key (rather than a live
/// `AuditSigner`'s own configured seed) — the registry-driven counterpart to
/// `AuditSigner::verify`, usable after a signing-key rotation for a signature
/// made under a now-retired key, as long as that key's row is still in
/// `audit_signing_key` (rows are never deleted, only marked
/// `retired_at`).
pub fn verify_with_key(
    prev_hash: &str,
    event_hash: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> bool {
    let Ok(key_bytes) = B64.decode(public_key_b64) else {
        return false;
    };
    let Ok(key_bytes): Result<[u8; 32], _> = key_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(sig_bytes) = B64.decode(signature_b64) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let payload = format!("{prev_hash}|{event_hash}");
    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}

/// Registers `(key_id, public_key_b64)` in `audit_signing_key` if
/// absent. A `key_id` row is immutable once written (D-016/D-038 fail-closed
/// posture): if the id is already registered under a *different* public key —
/// an operator reusing a `signing_key_id` label for a genuinely different
/// keypair, which would silently corrupt the registry's meaning — this is a
/// boot error, never a silent overwrite. Called once at startup
/// (`attome-server::system::EngineSystemBuilder::build`) for the currently
/// configured signer, on the ordinary runtime pool (plain DML against an
/// already-migrated infra table, not schema work).
pub async fn upsert_signing_key(
    db: &DbPool,
    key_id: &str,
    public_key_b64: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO audit_signing_key (key_id, public_key) VALUES ($1, $2)
         ON CONFLICT (key_id) DO NOTHING",
    )
    .bind(key_id)
    .bind(public_key_b64)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    let stored: String =
        sqlx::query_scalar("SELECT public_key FROM audit_signing_key WHERE key_id = $1")
            .bind(key_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;

    if stored != public_key_b64 {
        return Err(AppError::internal(format!(
            "audit.signing_key_id {key_id:?} is already registered in audit_signing_key \
             under a different public key — refusing to boot; a rotated key needs a new, \
             never-before-used signing_key_id, never a reused label"
        )));
    }
    Ok(())
}

/// Looks up the registered public key for `key_id`, if any — `None` for a
/// signature made before this registry existed (pre-migration history); the
/// caller falls back to the current signer's self-check in that case.
pub async fn lookup_signing_public_key(
    db: &DbPool,
    key_id: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT public_key FROM audit_signing_key WHERE key_id = $1")
        .bind(key_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_hex() -> String {
        "11".repeat(32)
    }

    #[test]
    fn sign_is_deterministic_for_the_same_inputs() {
        let signer = AuditSigner::from_config("key-1", &seed_hex()).unwrap();
        assert_eq!(signer.sign("a", "b"), signer.sign("a", "b"));
    }

    #[test]
    fn sign_changes_if_either_hash_changes() {
        let signer = AuditSigner::from_config("key-1", &seed_hex()).unwrap();
        let base = signer.sign("a", "b");
        assert_ne!(base, signer.sign("a", "c"));
        assert_ne!(base, signer.sign("z", "b"));
    }

    #[test]
    fn from_config_rejects_non_hex_seed() {
        assert!(AuditSigner::from_config("key-1", "not-hex").is_err());
    }

    #[test]
    fn from_config_rejects_wrong_length_seed() {
        assert!(AuditSigner::from_config("key-1", "aabbcc").is_err());
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let signer_a = AuditSigner::from_config("key-1", &"11".repeat(32)).unwrap();
        let signer_b = AuditSigner::from_config("key-2", &"22".repeat(32)).unwrap();
        assert_ne!(signer_a.sign("a", "b"), signer_b.sign("a", "b"));
    }

    #[test]
    fn verify_accepts_a_genuine_signature_and_rejects_tampering() {
        let signer = AuditSigner::from_config("key-1", &seed_hex()).unwrap();
        let sig = signer.sign("a", "b");
        assert!(signer.verify("a", "b", &sig));
        assert!(!signer.verify("a", "c", &sig));
        assert!(!signer.verify("z", "b", &sig));
    }

    #[test]
    fn verify_rejects_a_signature_from_a_different_key() {
        let signer_a = AuditSigner::from_config("key-1", &"11".repeat(32)).unwrap();
        let signer_b = AuditSigner::from_config("key-2", &"22".repeat(32)).unwrap();
        let sig = signer_a.sign("a", "b");
        assert!(!signer_b.verify("a", "b", &sig));
    }

    #[test]
    fn verify_rejects_garbage_signature_text() {
        let signer = AuditSigner::from_config("key-1", &seed_hex()).unwrap();
        assert!(!signer.verify("a", "b", "not-valid-base64!!"));
    }

    // ── P-key-rotation-and-jwt (d): registry-driven verification ──────────────

    #[test]
    fn verify_with_key_accepts_a_signature_made_under_the_matching_public_key() {
        let signer = AuditSigner::from_config("key-1", &seed_hex()).unwrap();
        let sig = signer.sign("a", "b");
        assert!(verify_with_key("a", "b", &sig, &signer.verifying_key_b64()));
    }

    #[test]
    fn verify_with_key_is_what_lets_a_retired_keys_signature_still_verify() {
        // The whole point of the registry: sign under key A, "rotate" (drop
        // key A from the live config entirely — simulated here by just not
        // holding onto `signer_a` as the active signer), and still verify
        // against key A's public key alone, with no live `AuditSigner` for
        // it at all.
        let signer_a = AuditSigner::from_config("retired-key", &seed_hex()).unwrap();
        let retired_public_key = signer_a.verifying_key_b64();
        let historical_sig = signer_a.sign("prev", "event");
        drop(signer_a); // simulate the key no longer being configured live

        assert!(verify_with_key(
            "prev",
            "event",
            &historical_sig,
            &retired_public_key
        ));
    }

    #[test]
    fn verify_with_key_rejects_a_signature_against_the_wrong_public_key() {
        let signer_a = AuditSigner::from_config("key-1", &"11".repeat(32)).unwrap();
        let signer_b = AuditSigner::from_config("key-2", &"22".repeat(32)).unwrap();
        let sig = signer_a.sign("a", "b");
        assert!(!verify_with_key(
            "a",
            "b",
            &sig,
            &signer_b.verifying_key_b64()
        ));
    }

    #[test]
    fn verify_with_key_rejects_garbage_public_key_text() {
        let signer = AuditSigner::from_config("key-1", &seed_hex()).unwrap();
        let sig = signer.sign("a", "b");
        assert!(!verify_with_key("a", "b", &sig, "not-valid-base64!!"));
    }

    #[test]
    fn verifying_key_b64_is_stable_and_distinct_per_seed() {
        let signer_a = AuditSigner::from_config("key-1", &"11".repeat(32)).unwrap();
        let signer_b = AuditSigner::from_config("key-2", &"22".repeat(32)).unwrap();
        assert_eq!(signer_a.verifying_key_b64(), signer_a.verifying_key_b64());
        assert_ne!(signer_a.verifying_key_b64(), signer_b.verifying_key_b64());
    }
}
