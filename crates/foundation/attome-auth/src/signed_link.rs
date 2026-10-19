//! K5-T2: short signed links. A link carries a subject (a page id, say) and an
//! expiry, signed with HMAC-SHA256 under a caller-chosen domain prefix, so it
//! needs no storage and one kind of link can never stand in for another.
//! Anyone holding the link until it expires may use it; nothing else is
//! needed, which is the point of a preview link.
//!
//! The token is `<base64url payload>.<base64url signature>`. [`verify`]
//! checks the signature in constant time before it reads the payload, then
//! the expiry.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Longest subject a link may carry.
pub const MAX_SUBJECT_CHARS: usize = 200;

#[derive(Serialize, Deserialize)]
struct Payload {
    /// The subject.
    s: String,
    /// Expiry, Unix seconds.
    e: i64,
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn mac(secret: &str, domain: &str) -> HmacSha256 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(domain.as_bytes());
    mac.update(b"|");
    mac
}

/// A link for `subject` until `expires_at` (Unix seconds), signed with
/// `secret` under `domain`. `None` when the subject is empty or too long.
pub fn sign(secret: &str, domain: &str, subject: &str, expires_at: i64) -> Option<String> {
    if subject.is_empty() || subject.chars().count() > MAX_SUBJECT_CHARS {
        return None;
    }
    let payload = serde_json::to_vec(&Payload {
        s: subject.to_owned(),
        e: expires_at,
    })
    .ok()?;
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    let mut signer = mac(secret, domain);
    signer.update(encoded.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes());
    Some(format!("{encoded}.{signature}"))
}

/// The subject of `token` when it was signed with `secret` under `domain`
/// and has not expired at `now` (Unix seconds); `None` for every other case.
pub fn verify(secret: &str, domain: &str, token: &str, now: i64) -> Option<String> {
    let (encoded, signature) = token.split_once('.')?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut verifier = mac(secret, domain);
    verifier.update(encoded.as_bytes());
    verifier.verify_slice(&signature).ok()?;
    let payload: Payload = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()?;
    (payload.e > now).then_some(payload.s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "a-test-secret-of-some-length";

    #[test]
    fn a_link_verifies_until_it_expires() {
        let token = sign(SECRET, "preview", "page-1", 1_000).unwrap_or_default();
        assert_eq!(
            verify(SECRET, "preview", &token, 999).as_deref(),
            Some("page-1")
        );
        assert_eq!(verify(SECRET, "preview", &token, 1_000), None);
    }

    #[test]
    fn another_key_domain_or_a_changed_payload_fails() {
        let token = sign(SECRET, "preview", "page-1", 1_000).unwrap_or_default();
        assert_eq!(verify("another-secret", "preview", &token, 1), None);
        assert_eq!(verify(SECRET, "share", &token, 1), None);
        let forged = sign(SECRET, "preview", "page-2", 1_000).unwrap_or_default();
        let (_, signature) = token.split_once('.').unwrap_or_default();
        let (payload, _) = forged.split_once('.').unwrap_or_default();
        assert_eq!(
            verify(SECRET, "preview", &format!("{payload}.{signature}"), 1),
            None
        );
        assert_eq!(verify(SECRET, "preview", "garbage", 1), None);
        assert_eq!(sign(SECRET, "preview", "", 1), None);
    }
}
