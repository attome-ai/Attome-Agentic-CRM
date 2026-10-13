//! Portal access token — a `{public_id}.{secret}` bearer, same shape
//! `attome_auth::reset` uses for password-reset tokens: `public_id` is a plain
//! lookup key (safe to `SELECT ... WHERE portal_public_id = $1`), and `secret`
//! is never stored — only its hash is.
//!
//! The hash is attome-auth's peppered HMAC (`attome_auth::apikey_hash`), not Argon2
//! (D-500, amending D-423's hashing choice). The status route that verifies
//! these tokens is anonymous, so an Argon2 verify let any caller spend a
//! memory-hard hash per guess, while a random secret gains nothing from a
//! memory-hard KDF.
use attome_auth::apikey_hash::{
    PepperRing, VerifyOutcome, dummy_peppered_hash, hash_peppered_secret, verify_peppered_secret,
};
use attome_types::AppError;
use uuid::Uuid;

/// A newly issued token, ready to hand back to the caller as `bearer` — the
/// raw secret is never persisted, only `secret_hash`.
pub struct IssuedToken {
    pub public_id: Uuid,
    pub secret_hash: String,
    pub bearer: String,
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedToken").finish_non_exhaustive()
    }
}

/// Mints a new public_id + random secret pair and hashes the secret with the
/// deployment's pepper ring.
pub async fn issue(ring: &PepperRing) -> Result<IssuedToken, AppError> {
    let public_id = Uuid::now_v7();
    // 122 bits of randomness from `Uuid::new_v4()` is ample for a bearer
    // secret — reuses the `uuid` crate this crate already depends on rather
    // than adding `rand` as a new dependency for one call site.
    let secret = Uuid::new_v4().to_string();
    let secret_hash = hash_peppered_secret(ring, &secret);
    Ok(IssuedToken {
        public_id,
        secret_hash,
        bearer: format!("{public_id}.{secret}"),
    })
}

/// Splits a presented bearer into `(public_id, secret)`. `None` on anything
/// malformed — callers must treat that identically to "not found", never a
/// distinguishable error (same discipline `attome_auth::reset::confirm`
/// applies to its own bearer parse).
pub fn parse_bearer(bearer: &str) -> Option<(Uuid, &str)> {
    let (id_str, secret) = bearer.split_once('.')?;
    let public_id: Uuid = id_str.parse().ok()?;
    Some((public_id, secret))
}

/// Verifies `secret` against `stored_hash`. `stored_hash: None` (the
/// "public_id not found" branch) still runs the same verifier work a real
/// wrong-secret check does, against a dummy hash under the ring's current
/// pepper, rather than short-circuiting — so "no such token" is no cheaper
/// than "wrong secret" (attome-auth security contract I17).
pub async fn verify(
    secret: &str,
    stored_hash: Option<&str>,
    ring: &PepperRing,
) -> Result<bool, AppError> {
    match stored_hash {
        Some(hash) => Ok(verify_peppered_secret(ring, secret, hash).await? != VerifyOutcome::Fail),
        None => {
            let _ = verify_peppered_secret(ring, secret, &dummy_peppered_hash(ring)).await?;
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ring() -> PepperRing {
        PepperRing::new(0, "portal-token-unit-test-pepper-0123456789", &[])
    }

    #[tokio::test]
    async fn issued_token_round_trips_through_parse_and_verify() {
        let ring = test_ring();
        let issued = issue(&ring).await.expect("issue");
        let (public_id, secret) = parse_bearer(&issued.bearer).expect("parse_bearer");
        assert_eq!(public_id, issued.public_id);
        assert!(
            verify(secret, Some(&issued.secret_hash), &ring)
                .await
                .expect("verify")
        );
    }

    #[tokio::test]
    async fn a_new_token_is_stored_as_peppered_hmac() {
        let issued = issue(&test_ring()).await.expect("issue");
        assert!(
            issued.secret_hash.starts_with("hmac256"),
            "expected a peppered HMAC hash, got {}",
            issued.secret_hash
        );
    }

    #[tokio::test]
    async fn an_argon2_hash_does_not_verify() {
        let hash = attome_auth::password::hash_password_async(
            attome_auth::NewPassword::platform_generated("argon2-portal-secret"),
        )
        .await
        .expect("hash");
        assert!(
            !verify("argon2-portal-secret", Some(&hash), &test_ring())
                .await
                .expect("verify")
        );
    }

    #[tokio::test]
    async fn a_wrong_secret_does_not_verify() {
        let ring = test_ring();
        let issued = issue(&ring).await.expect("issue");
        assert!(
            !verify("not-the-real-secret", Some(&issued.secret_hash), &ring)
                .await
                .expect("verify")
        );
    }

    #[tokio::test]
    async fn a_missing_stored_hash_fails_closed_via_the_dummy_branch() {
        assert!(
            !verify("anything", None, &test_ring())
                .await
                .expect("verify")
        );
    }

    #[test]
    fn a_malformed_bearer_parses_to_none() {
        assert!(parse_bearer("no-dot-separator").is_none());
        assert!(parse_bearer("not-a-uuid.secret").is_none());
        assert!(parse_bearer("").is_none());
    }
}
