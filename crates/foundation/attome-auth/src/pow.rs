//! Q20-T3: a self-hosted proof-of-work challenge, for deployments that will
//! not send their users' browsers to an outside CAPTCHA service.
//!
//! The server issues a challenge: a random nonce, a difficulty (leading zero
//! bits) and an expiry two minutes out, signed with HMAC-SHA256 so it needs
//! no storage until it is answered. The browser looks for an `answer` such
//! that SHA-256(`nonce` + `answer`) starts with that many zero bits, which
//! takes about 2^difficulty hashes (a fraction of a second to a few seconds
//! in a Web Worker at the default). [`verify`] checks the signature, the
//! expiry and the work, then spends the nonce in the shared store, so an
//! answer is accepted once.
//!
//! A sign-in or sign-up sends the solved challenge as its CAPTCHA token:
//! `{challenge}:{answer}` ([`token_parts`]). The signing key is the active
//! `auth.jwt_secret` entry, under its own `attome-pow|` domain prefix, so a
//! challenge signature can never stand in for a token signature.

use attome_cache::Store;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// About 260,000 hashes on average.
pub const DEFAULT_DIFFICULTY: u8 = 18;
/// The hardest challenge a deployment may set (a few seconds of work).
pub const MAX_DIFFICULTY: u8 = 24;
/// How long a challenge may be answered.
pub const TTL_SECS: i64 = 120;
const DOMAIN: &[u8] = b"attome-pow|";
const USED_PREFIX: &str = "attome-auth:pow-used";

/// A challenge as the client receives it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Challenge {
    /// Send this back, followed by `:` and the answer.
    pub challenge: String,
    /// Hex; hash `nonce` followed by the answer.
    pub nonce: String,
    /// Leading zero bits the hash must have.
    pub difficulty: u8,
    /// Unix seconds.
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    n: String,
    d: u8,
    e: i64,
}

/// Why an answer was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowError {
    Malformed,
    BadSignature,
    Expired,
    Insufficient,
    Reused,
    Unavailable,
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn mac(secret: &str) -> HmacSha256 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(DOMAIN);
    mac
}

/// A new challenge at `difficulty` (clamped to 1..=[`MAX_DIFFICULTY`]),
/// signed with `secret`, expiring [`TTL_SECS`] after `now` (unix seconds).
pub fn issue(secret: &str, difficulty: u8, now: i64) -> Challenge {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let payload = Payload {
        n: hex::encode(nonce),
        d: difficulty.clamp(1, MAX_DIFFICULTY),
        e: now + TTL_SECS,
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap_or_default());
    let mut signer = mac(secret);
    signer.update(encoded.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes());
    Challenge {
        challenge: format!("{encoded}.{signature}"),
        nonce: payload.n,
        difficulty: payload.d,
        expires_at: payload.e,
    }
}

/// The leading zero bits of `digest`.
pub fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Splits a CAPTCHA token `{challenge}:{answer}`.
pub fn token_parts(token: &str) -> Option<(&str, &str)> {
    token
        .rsplit_once(':')
        .filter(|(c, a)| !c.is_empty() && !a.is_empty())
}

/// Checks `answer` to `challenge` at `now` without spending it: the
/// signature, the expiry and the work. Returns the nonce and expiry.
pub fn check(
    secret: &str,
    challenge: &str,
    answer: &str,
    now: i64,
) -> Result<(String, i64), PowError> {
    let (encoded, signature) = challenge.split_once('.').ok_or(PowError::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| PowError::Malformed)?;
    let mut verifier = mac(secret);
    verifier.update(encoded.as_bytes());
    verifier
        .verify_slice(&signature)
        .map_err(|_| PowError::BadSignature)?;
    let payload: Payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(PowError::Malformed)?;
    if payload.e <= now {
        return Err(PowError::Expired);
    }
    if answer.len() > 64 {
        return Err(PowError::Malformed);
    }
    let digest = Sha256::digest(format!("{}{answer}", payload.n).as_bytes());
    if leading_zero_bits(&digest) < u32::from(payload.d) {
        return Err(PowError::Insufficient);
    }
    Ok((payload.n, payload.e))
}

/// [`check`], then spends the nonce in `store` until the challenge expires,
/// so the same answer is refused the second time. A store error refuses the
/// answer (fail closed).
pub async fn verify(
    store: &Store,
    secret: &str,
    challenge: &str,
    answer: &str,
    now: i64,
) -> Result<(), PowError> {
    let (nonce, expires_at) = check(secret, challenge, answer, now)?;
    let ttl = std::time::Duration::from_secs(u64::try_from(expires_at - now).unwrap_or(1).max(1));
    match store
        .set_nx(format!("{USED_PREFIX}:{nonce}"), "1", Some(ttl))
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(PowError::Reused),
        Err(error) => {
            tracing::warn!(%error, "proof-of-work: nonce store unavailable");
            Err(PowError::Unavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-only-pow-secret-32-bytes-minimum!";

    fn solve(challenge: &Challenge) -> String {
        (0u64..)
            .map(|n| n.to_string())
            .find(|answer| {
                let digest = Sha256::digest(format!("{}{answer}", challenge.nonce).as_bytes());
                leading_zero_bits(&digest) >= u32::from(challenge.difficulty)
            })
            .expect("an answer exists")
    }

    fn store() -> Store {
        Store::Memory(std::sync::Arc::new(attome_cache::memory::MemoryStore::new()))
    }

    #[tokio::test]
    async fn valid_answer_is_accepted_once() {
        let now = 1_800_000_000;
        let challenge = issue(SECRET, 8, now);
        let answer = solve(&challenge);
        let store = store();
        assert_eq!(
            verify(&store, SECRET, &challenge.challenge, &answer, now + 5).await,
            Ok(())
        );
        assert_eq!(
            verify(&store, SECRET, &challenge.challenge, &answer, now + 6).await,
            Err(PowError::Reused),
            "a reused answer is refused"
        );
    }

    #[test]
    fn expired_answer_is_refused() {
        let now = 1_800_000_000;
        let challenge = issue(SECRET, 8, now);
        let answer = solve(&challenge);
        assert_eq!(
            check(SECRET, &challenge.challenge, &answer, now + TTL_SECS),
            Err(PowError::Expired)
        );
    }

    #[test]
    fn work_signature_and_shape_are_checked() {
        let now = 1_800_000_000;
        let challenge = issue(SECRET, 12, now);
        let answer = solve(&challenge);
        assert!(check(SECRET, &challenge.challenge, &answer, now).is_ok());
        // Too little work: some answer below the difficulty.
        let weak = (0u64..)
            .map(|n| n.to_string())
            .find(|a| {
                let d = Sha256::digest(format!("{}{a}", challenge.nonce).as_bytes());
                leading_zero_bits(&d) < 12
            })
            .unwrap();
        assert_eq!(
            check(SECRET, &challenge.challenge, &weak, now),
            Err(PowError::Insufficient)
        );
        // Another key, or a raised expiry, breaks the signature.
        assert_eq!(
            check("another-secret", &challenge.challenge, &answer, now),
            Err(PowError::BadSignature)
        );
        let (_, signature) = challenge.challenge.split_once('.').unwrap();
        let forged = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Payload {
                n: challenge.nonce.clone(),
                d: 1,
                e: now + 9_999,
            })
            .unwrap(),
        );
        assert_eq!(
            check(SECRET, &format!("{forged}.{signature}"), &answer, now),
            Err(PowError::BadSignature)
        );
        assert_eq!(check(SECRET, "no-dot", "1", now), Err(PowError::Malformed));
    }

    #[test]
    fn token_parts_split_on_the_last_colon() {
        assert_eq!(token_parts("abc.def:123"), Some(("abc.def", "123")));
        assert_eq!(token_parts("abc.def:"), None);
        assert_eq!(token_parts("plain-captcha-token"), None);
    }

    #[test]
    fn leading_zero_bits_counts_across_bytes() {
        assert_eq!(leading_zero_bits(&[0, 0, 0b0001_0000]), 19);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
    }
}
