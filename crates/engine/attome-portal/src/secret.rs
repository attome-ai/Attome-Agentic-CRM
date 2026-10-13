//! `{id}.{secret}` bearers for portal refresh, invitation and reset tokens,
//! the shape `attome_auth::reset` and the Work Intake portal already use: `id`
//! is a plain lookup key, and only a peppered HMAC of `secret` is stored
//! (D-500). Verification of a miss runs the same verifier work as a wrong
//! secret, so the two are indistinguishable by timing.

use attome_auth::apikey_hash::{
    PepperRing, VerifyOutcome, dummy_peppered_hash, hash_peppered_secret, verify_peppered_secret,
};
use attome_types::AppError;
use uuid::Uuid;

pub struct Minted {
    pub id: Uuid,
    pub secret_hash: String,
    pub bearer: String,
}

impl std::fmt::Debug for Minted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minted").finish_non_exhaustive()
    }
}

/// 244 bits of randomness from two v4 UUIDs.
pub fn mint(ring: &PepperRing) -> Minted {
    let id = Uuid::now_v7();
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    Minted {
        id,
        secret_hash: hash_peppered_secret(ring, &secret),
        bearer: format!("{id}.{secret}"),
    }
}

/// `None` for anything malformed; callers treat that exactly like "unknown".
pub fn parse(bearer: &str) -> Option<(Uuid, &str)> {
    let (id, secret) = bearer.split_once('.')?;
    Some((id.parse().ok()?, secret))
}

/// `stored = None` is the "id not found" branch: it still does the work.
pub async fn verify(
    ring: &PepperRing,
    secret: &str,
    stored: Option<&str>,
) -> Result<bool, AppError> {
    let dummy;
    let hash = match stored {
        Some(h) => h,
        None => {
            dummy = dummy_peppered_hash(ring);
            &dummy
        }
    };
    let outcome = verify_peppered_secret(ring, secret, hash).await?;
    Ok(stored.is_some() && !matches!(outcome, VerifyOutcome::Fail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> PepperRing {
        PepperRing::new(0, "attome-portal-secret-test-pepper-0123456789ab", &[])
    }

    #[tokio::test]
    async fn a_minted_bearer_verifies_and_nothing_else_does() {
        let r = ring();
        let m = mint(&r);
        let (id, secret) = parse(&m.bearer).unwrap();
        assert_eq!(id, m.id);
        assert!(verify(&r, secret, Some(&m.secret_hash)).await.unwrap());
        assert!(!verify(&r, "wrong", Some(&m.secret_hash)).await.unwrap());
        assert!(!verify(&r, secret, None).await.unwrap());
        assert!(parse("not-a-bearer").is_none());
        assert!(parse("nope.secret").is_none());
    }
}
