//! P-api-key-hashing — HMAC-SHA256(pepper) for every platform-generated
//! bearer secret (API keys, refresh tokens, reset/verification/invitation and
//! portal tokens). These secrets are random 256-bit values, never human-chosen,
//! so a memory-hard KDF buys nothing against them while paying a CPU tax on
//! every request (D-112). User passwords stay Argon2 (`password.rs`).
//!
//! Stored format: `hmac256:v{pepper_id}$<hex>`. [`verify_peppered_secret`]
//! looks up pepper id `n` in the [`PepperRing`] and verifies with one cheap
//! HMAC. Any other stored value fails closed.
//!
//! **Rotation.** Add a new `{id, secret}` to `apikey_hash_previous_peppers`
//! for the *outgoing* current pepper, then set `apikey_hash_pepper`/
//! `apikey_hash_pepper_id` to the new one. Existing rows keep verifying
//! against their stored id (old pepper, still in the ring) and report
//! `OkNeedsRehash`, so the caller rewrites them under the current id on use.
//!
//! **Retiring an old pepper** (dropping it from
//! `apikey_hash_previous_peppers`) is safe only once no live row references
//! its id anymore. `crates/server`'s
//! `apikey_pepper_registry::check_referenced_peppers_present` counts live keys
//! per pepper id and refuses to start while one references an id missing
//! from the ring. The same count, to run by hand before a config change:
//!
//! ```sql
//! SELECT
//!   substring(secret_hash from '^hmac256:v(\d+)\$')::int AS pepper_id,
//!   count(*) AS live_keys
//! FROM api_key
//! WHERE is_active = true AND (expires_at IS NULL OR expires_at > now())
//! GROUP BY 1
//! ORDER BY 1;
//! ```
//!
//! **Pepper ids must never be reused — enforced, not just documented
//! (D-120).** `crates/server`'s `apikey_pepper_registry` module checks every
//! configured pepper id (current + previous) against
//! `api_key_pepper_registry` at every boot: a SHA-256 fingerprint of
//! each pepper is recorded on first sighting, and any later boot presenting
//! a *different* secret under an already-recorded id is a **boot error**,
//! not a silent, permanent verification failure for every row still hashed
//! under that id's original meaning. Only the fingerprint is ever
//! persisted — never the pepper itself.
//!
//! **Custody (D-120).** `apikey_hash_pepper` and `apikey_hash_previous_peppers`
//! are config-sourced, same custody class as `s2s.key_encryption_key`/
//! `mfa_encryption_key` — rotating either is a config edit plus a restart.
//! Real call sites (`resolve_api_key`, `create_api_key`) build their
//! `PepperRing` from `state.secrets.load()` (`attome_server::SecretRings`)
//! combined with `state.config.auth.apikey_hash_pepper_id`.
//! `PepperRing::from_auth_config` (cold-config-only) remains for tests.

use attome_types::AppError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

const HMAC_PREFIX: &str = "hmac256:v";
/// The pepper id [`dummy_hmac_hash`] is tagged with.
const DUMMY_PEPPER_ID: u32 = 0;

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn hmac_hex(pepper: &str, secret: &str) -> String {
    // HMAC accepts any key length, so `new_from_slice` on an already
    // `check_secret`-validated (>=32 byte) pepper cannot fail.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(secret.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// The current + previous api-key hash peppers, keyed by pepper id. Built
/// once from `AppConfig::auth` at startup (cheap — a handful of strings) and
/// held in `AppState`, same lifetime class as any other read-only
/// config-derived value (guidelines §"CRITICAL: Multi-Server Architecture" —
/// this is compiled-once config, not runtime-mutated state).
#[derive(Clone)]
pub struct PepperRing {
    current_id: u32,
    peppers: HashMap<u32, String>,
}

/// Hand-rolled: `peppers` is live secret material (every value is a real
/// api-key hash pepper) — the derived `Debug` this used to have would print
/// them all raw. Same pattern as `attome_server::SecretRings`'s hand-rolled
/// `Debug` (count, not values, for the secret-bearing collection field).
impl std::fmt::Debug for PepperRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PepperRing")
            .field("current_id", &self.current_id)
            .field(
                "peppers",
                &format!("[REDACTED; {} entries]", self.peppers.len()),
            )
            .finish()
    }
}

impl PepperRing {
    /// `previous` may be empty (the common case — no rotation has ever
    /// happened). `current_id` colliding with a `previous` entry's id is
    /// rejected by `AppConfig::validate()` before this is ever constructed
    /// (see `attome-config`'s `validate_rejects_a_duplicate_apikey_pepper_id`
    /// test) — this constructor itself does not re-check, and would silently
    /// let `current_secret` win a collision (insertion order) if it were
    /// ever called with unvalidated input.
    pub fn new(current_id: u32, current_secret: &str, previous: &[(u32, String)]) -> Self {
        let mut peppers = HashMap::with_capacity(previous.len() + 1);
        for (id, secret) in previous {
            peppers.insert(*id, secret.clone());
        }
        peppers.insert(current_id, current_secret.to_owned());
        Self {
            current_id,
            peppers,
        }
    }

    /// Builds from the cold, boot-time `AppConfig::auth` snapshot — use this
    /// only for tests and any other cold-path caller. **Real call sites
    /// (`resolve_api_key`, `create_api_key`) must instead build a
    /// `PepperRing` from `state.secrets.load()` (the pepper +
    /// previous-peppers, D-120) combined with `state.config.auth`'s
    /// `apikey_hash_pepper_id` via [`PepperRing::new`] directly** — see those
    /// call sites for the actual pattern.
    pub fn from_auth_config(auth: &attome_config::AuthSection) -> Self {
        let previous: Vec<(u32, String)> = auth
            .apikey_hash_previous_peppers
            .iter()
            .map(|p| (p.id, p.secret.expose().to_owned()))
            .collect();
        Self::new(
            auth.apikey_hash_pepper_id,
            auth.apikey_hash_pepper.expose(),
            &previous,
        )
    }

    fn get(&self, id: u32) -> Option<&str> {
        self.peppers.get(&id).map(String::as_str)
    }

    /// Hashes a newly issued/rehashed secret with the *current* pepper —
    /// rotation only ever produces rows for the newest id, never a previous one.
    #[expect(
        clippy::expect_used,
        reason = "PepperRing::new always inserts current_id into the ring"
    )]
    pub fn hash(&self, secret: &str) -> String {
        let current = self
            .get(self.current_id)
            .expect("current_id is always inserted into `peppers` by `PepperRing::new`");
        format!(
            "{HMAC_PREFIX}{}${}",
            self.current_id,
            hmac_hex(current, secret)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Verified under the current pepper — nothing else to do.
    Ok,
    /// Verified under a retired (non-current) pepper id — caller should
    /// rewrite `secret_hash` under the current id so the row converges.
    OkNeedsRehash,
    Fail,
}

fn parse_versioned(stored: &str) -> Option<(u32, &str)> {
    let rest = stored.strip_prefix(HMAC_PREFIX)?;
    let (id_str, hex_mac) = rest.split_once('$')?;
    let id = id_str.parse::<u32>().ok()?;
    Some((id, hex_mac))
}

/// Verifies `secret` against a stored `hmac256:v{n}$<hex>` row inline
/// (HMAC-SHA256 is cheap enough to run directly on the async runtime, same
/// reasoning as `xrm_s2s::crypto::verify_hmac`), looking up pepper id `n` in
/// the ring. A malformed row, or an id with no matching pepper in the ring
/// (a rotation retired it too early, or config drift), fails closed — same
/// "wrong secret" shape as any other verify failure, no separate error
/// variant an attacker could use to enumerate live ids (security contract
/// I17).
#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
pub async fn verify_peppered_secret(
    ring: &PepperRing,
    secret: &str,
    stored: &str,
) -> Result<VerifyOutcome, AppError> {
    let Some((pepper_id, hex_mac)) = parse_versioned(stored) else {
        return Ok(VerifyOutcome::Fail);
    };
    let Ok(expected) = hex::decode(hex_mac) else {
        return Ok(VerifyOutcome::Fail);
    };
    let Some(pepper) = ring.get(pepper_id) else {
        return Ok(VerifyOutcome::Fail);
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(secret.as_bytes());
    // `Mac::verify_slice` is constant-time (the `hmac`/`digest` family's
    // own guarantee) — no separate `subtle` dependency needed.
    if mac.verify_slice(&expected).is_err() {
        return Ok(VerifyOutcome::Fail);
    }
    Ok(if pepper_id == ring.current_id {
        VerifyOutcome::Ok
    } else {
        VerifyOutcome::OkNeedsRehash
    })
}

/// API-key verification. A thin wrapper over [`verify_peppered_secret`], kept
/// under its original name so every API-key call site reads as it always has.
pub async fn verify_api_key_secret(
    ring: &PepperRing,
    secret: &str,
    stored: &str,
) -> Result<VerifyOutcome, AppError> {
    verify_peppered_secret(ring, secret, stored).await
}

// ── Scheme-neutral peppered-secret API (D-500) ──────────────────────────────
//
// Every platform-generated bearer secret uses this scheme: API keys, refresh
// tokens, and since D-500 password-reset, email-verification, invitation and
// Work Intake portal tokens. The names say what the scheme is, not which token
// first used it.

/// Hashes a platform-generated bearer secret with the ring's current pepper.
/// Same stored format as [`PepperRing::hash`].
pub fn hash_peppered_secret(ring: &PepperRing, secret: &str) -> String {
    ring.hash(secret)
}

/// A stored-format hash, under the ring's *current* pepper, for a token type's
/// "no such token" branch. Verifying a presented secret against it runs the
/// same single HMAC compare as a wrong-secret hit on a current row (security
/// contract I17). Unlike [`dummy_hmac_hash`], which is fixed at pepper id 0, it
/// always uses a pepper the ring holds, so a rotation can never turn the dummy
/// compare into a cheaper short-circuit.
pub fn dummy_peppered_hash(ring: &PepperRing) -> String {
    ring.hash("attome-dummy-peppered-secret-never-issued")
}

static DUMMY_HMAC_HASH: OnceLock<String> = OnceLock::new();

/// A fixed `hmac256:v{DUMMY_PEPPER_ID}$`-format value with no matching
/// secret, for the "public_key doesn't exist" branch of `resolve_api_key` —
/// keeps that path running the exact same fast HMAC compare as a real hit,
/// preserving timing symmetry between "key doesn't exist" and "key exists,
/// wrong secret". Fixed at
/// pepper id 0: whether id 0 is still present in a given deployment's ring
/// or was retired by a rotation that dropped it from
/// `apikey_hash_previous_peppers` does not matter for this specific use — a
/// ring miss (`PepperRing::get` returns `None`) already resolves to
/// `VerifyOutcome::Fail`, the exact outcome this dummy path needs, so
/// whether the HMAC compare itself runs or is short-circuited by a missing
/// pepper is immaterial to the caller. (A *real* row referencing a
/// prematurely retired id would hit the same `Fail` — that is a config
/// hazard for an operator to avoid, documented on
/// `AuthSection::apikey_hash_previous_peppers`, not something this function
/// needs to guard against.)
pub fn dummy_hmac_hash() -> &'static str {
    DUMMY_HMAC_HASH.get_or_init(|| {
        format!(
            "{HMAC_PREFIX}{DUMMY_PEPPER_ID}${}",
            hex::encode([0u8; 32]) // fixed 32-byte all-zero "signature"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEPPER_A: &str = "test-pepper-at-least-32-bytes-long-aaaa";
    const PEPPER_B: &str = "different-pepper-at-least-32-bytes-bbbb";

    fn single_pepper_ring(id: u32, secret: &str) -> PepperRing {
        PepperRing::new(id, secret, &[])
    }

    #[tokio::test]
    async fn hmac_round_trip_verifies() {
        let ring = single_pepper_ring(0, PEPPER_A);
        let hash = ring.hash("s3cr3t");
        assert!(hash.starts_with(&format!("{HMAC_PREFIX}0$")));
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok);
    }

    #[tokio::test]
    async fn wrong_secret_fails() {
        let ring = single_pepper_ring(0, PEPPER_A);
        let hash = ring.hash("s3cr3t");
        let outcome = verify_api_key_secret(&ring, "wrong", &hash).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Fail);
    }

    #[tokio::test]
    async fn wrong_pepper_fails() {
        let ring_a = single_pepper_ring(0, PEPPER_A);
        let ring_b = single_pepper_ring(0, PEPPER_B);
        let hash = ring_a.hash("s3cr3t");
        let outcome = verify_api_key_secret(&ring_b, "s3cr3t", &hash)
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Fail);
    }

    #[tokio::test]
    async fn malformed_hex_after_prefix_fails_closed() {
        let ring = single_pepper_ring(0, PEPPER_A);
        let hash = format!("{HMAC_PREFIX}0$not-hex");
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Fail);
    }

    #[tokio::test]
    async fn unknown_pepper_id_fails_closed() {
        let ring = single_pepper_ring(0, PEPPER_A);
        // A row tagged with an id the ring doesn't carry — a rotation that
        // retired an id still referenced by a live row, or config drift.
        let hash = format!("{HMAC_PREFIX}99${}", hex::encode([0u8; 32]));
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Fail);
    }

    #[tokio::test]
    async fn dummy_hmac_hash_never_matches_any_secret() {
        let ring = single_pepper_ring(0, PEPPER_A);
        let outcome = verify_api_key_secret(&ring, "anything", dummy_hmac_hash())
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Fail);
    }

    #[test]
    fn dummy_hmac_hash_is_well_formed() {
        assert!(dummy_hmac_hash().starts_with(HMAC_PREFIX));
        assert_eq!(dummy_hmac_hash(), dummy_hmac_hash(), "must be stable");
    }

    #[test]
    fn debug_never_prints_a_raw_pepper_value() {
        let ring = PepperRing::new(1, PEPPER_A, &[(0, PEPPER_B.to_string())]);
        let debug_output = format!("{ring:?}");
        assert!(
            !debug_output.contains(PEPPER_A) && !debug_output.contains(PEPPER_B),
            "Debug output leaked a raw pepper value: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED; 2 entries]"),
            "expected a redacted entry count, got: {debug_output}"
        );
    }

    // ── Rotation-specific coverage (D-112 revision) ─────────────────────────

    #[tokio::test]
    async fn a_row_hashed_under_the_current_id_verifies_ok_with_no_rehash() {
        let ring = PepperRing::new(1, PEPPER_A, &[(0, PEPPER_B.to_string())]);
        let hash = ring.hash("s3cr3t"); // hashed with current id (1)
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok);
    }

    #[tokio::test]
    async fn a_row_hashed_under_a_retired_previous_id_verifies_and_requests_rehash() {
        // Simulates a key hashed before rotation (id 0 was current then),
        // now being verified after id 1 became current.
        let old_ring = single_pepper_ring(0, PEPPER_B);
        let hash = old_ring.hash("s3cr3t");

        let new_ring = PepperRing::new(1, PEPPER_A, &[(0, PEPPER_B.to_string())]);
        let outcome = verify_api_key_secret(&new_ring, "s3cr3t", &hash)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            VerifyOutcome::OkNeedsRehash,
            "a still-correct secret hashed under a retired id must converge, not just verify"
        );
    }

    #[tokio::test]
    async fn rotation_never_bricks_existing_keys_end_to_end() {
        // Full lifecycle: hash under id 0, rotate to id 1 keeping 0 as
        // previous, verify+rehash, then confirm the rehashed value verifies
        // cleanly with no further rehash needed.
        let secret = "rotation-e2e-secret";
        let ring_v0 = single_pepper_ring(0, PEPPER_A);
        let original_hash = ring_v0.hash(secret);

        let ring_v1 = PepperRing::new(1, PEPPER_B, &[(0, PEPPER_A.to_string())]);
        let first_outcome = verify_api_key_secret(&ring_v1, secret, &original_hash)
            .await
            .unwrap();
        assert_eq!(first_outcome, VerifyOutcome::OkNeedsRehash);

        let rehashed = ring_v1.hash(secret);
        let second_outcome = verify_api_key_secret(&ring_v1, secret, &rehashed)
            .await
            .unwrap();
        assert_eq!(second_outcome, VerifyOutcome::Ok);
    }

    #[tokio::test]
    async fn hash_emits_the_versioned_format() {
        let ring = PepperRing::new(0, PEPPER_A, &[]);
        let hash = ring.hash("s3cr3t");
        assert!(hash.starts_with(&format!("{HMAC_PREFIX}0$")));
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok);
    }

    #[tokio::test]
    async fn a_versioned_row_with_a_non_numeric_id_fails_closed_not_500() {
        let ring = single_pepper_ring(0, PEPPER_A);
        let hash = format!("{HMAC_PREFIX}abc${}", hex::encode([0u8; 32]));
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await;
        assert_eq!(outcome.unwrap(), VerifyOutcome::Fail);
    }

    #[tokio::test]
    async fn truncated_versioned_row_fails_closed_not_500() {
        let ring = single_pepper_ring(0, PEPPER_A);
        let hash = format!("{HMAC_PREFIX}0"); // no trailing '$<hex>' at all
        let outcome = verify_api_key_secret(&ring, "s3cr3t", &hash).await;
        assert_eq!(outcome.unwrap(), VerifyOutcome::Fail);
    }

    // ── Scheme-neutral peppered-secret API (D-500) ──────────────────────────

    #[tokio::test]
    async fn a_peppered_secret_round_trips_and_a_wrong_secret_fails() {
        let ring = PepperRing::new(1, PEPPER_A, &[(0, PEPPER_B.to_string())]);
        let stored = hash_peppered_secret(&ring, "bearer-secret");
        assert_eq!(
            verify_peppered_secret(&ring, "bearer-secret", &stored)
                .await
                .unwrap(),
            VerifyOutcome::Ok
        );
        assert_eq!(
            verify_peppered_secret(&ring, "other-secret", &stored)
                .await
                .unwrap(),
            VerifyOutcome::Fail
        );
    }

    #[tokio::test]
    async fn dummy_peppered_hash_uses_the_current_pepper_and_matches_nothing_real() {
        // Rotated ring: pepper id 0 is no longer current. The dummy must be
        // under the current id, so its compare actually runs.
        let ring = PepperRing::new(1, PEPPER_A, &[]);
        let dummy = dummy_peppered_hash(&ring);
        assert!(
            dummy.starts_with(&format!("{HMAC_PREFIX}1$")),
            "dummy must carry the current pepper id, got {dummy}"
        );
        assert_eq!(
            verify_peppered_secret(&ring, "any-presented-secret", &dummy)
                .await
                .unwrap(),
            VerifyOutcome::Fail
        );
    }
}
