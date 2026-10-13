//! Local-register email verification (P-account-lifecycle) — backs `POST
//! /api/v1/auth/verify-email/request` and `POST /api/v1/auth/verify-email/confirm`.
//! Same public_id/secret bearer shape as `reset.rs`, against
//! `email_verification_token` (migration 0022). Enforcement of
//! `email_verified` (rejecting login when `auth.require_verified_email` is on)
//! lives in `accounts::login`, not here — this module only issues/confirms
//! tokens.
//!
//! The secret is platform-generated, so it is hashed with the peppered HMAC
//! scheme (`crate::apikey_hash`), not Argon2 (D-500).

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Duration as ChronoDuration, Utc};
use rand::distributions::{Alphanumeric, DistString};
use uuid::Uuid;

use crate::apikey_hash::{
    PepperRing, VerifyOutcome, dummy_peppered_hash, hash_peppered_secret, verify_peppered_secret,
};

fn generate_secret() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 48)
}

pub struct IssuedVerification {
    pub email: String,
    pub bearer: String,
}

impl std::fmt::Debug for IssuedVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedVerification").finish_non_exhaustive()
    }
}

/// Issues a verification token for `user_id`, unconditionally — unlike
/// `reset::request`, this is always called right after a successful register
/// (the caller already knows the account exists, so there's no enumeration
/// concern to equalize timing against).
pub async fn request(
    db: &DbPool,
    user_id: Uuid,
    ttl_hours: u64,
    ring: &PepperRing,
) -> Result<IssuedVerification, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let issued = request_in_tx(&mut tx, user_id, ttl_hours, ring).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(issued)
}

/// Transactional form of [`request`].  Keeps the verification-token row and
/// the durable email job in one commit when called by the HTTP layer.
pub async fn request_in_tx(
    tx: &mut attome_db::Tx<'_>,
    user_id: Uuid,
    ttl_hours: u64,
    ring: &PepperRing,
) -> Result<IssuedVerification, AppError> {
    let email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;

    let public_id = Uuid::now_v7();
    let secret = generate_secret();
    let secret_hash = hash_peppered_secret(ring, &secret);
    let expires_at = Utc::now() + ChronoDuration::hours(ttl_hours as i64);

    sqlx::query(
        "INSERT INTO email_verification_token (user_ref, public_id, secret_hash, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(public_id)
    .bind(&secret_hash)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(IssuedVerification {
        email,
        bearer: format!("{public_id}.{secret}"),
    })
}

/// Verifies a presented token and flips `user_account.email_verified` to
/// true. Single-use, same guarded-UPDATE shape as `reset::confirm`.
pub async fn confirm(db: &DbPool, presented: &str, ring: &PepperRing) -> Result<Uuid, AppError> {
    confirm_with(db, presented, ring, &attome_db::NoHook).await
}

/// [`confirm`], plus a [`attome_db::BeforeCommit`] hook that runs in the
/// verification's transaction with the account id (D-062).
pub async fn confirm_with(
    db: &DbPool,
    presented: &str,
    ring: &PepperRing,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<Uuid, AppError> {
    let (public_id_str, secret) = presented.split_once('.').ok_or(AppError::Unauthorized)?;
    let public_id: Uuid = public_id_str.parse().map_err(|_| AppError::Unauthorized)?;

    // See reset::confirm's identical comment: deliberately not filtering
    // `used_at IS NULL` here so a reused token reaches the guarded UPDATE
    // below (Conflict) instead of looking like an invalid token (Unauthorized).
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, user_ref, secret_hash FROM email_verification_token
         WHERE public_id = $1 AND expires_at > NOW()",
    )
    .bind(public_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let (token_id, user_id) = match row {
        Some((token_id, user_id, secret_hash)) => {
            // The token is consumed below either way, so a retired-pepper
            // match needs no rewrite.
            if verify_peppered_secret(ring, secret, &secret_hash).await? == VerifyOutcome::Fail {
                return Err(AppError::Unauthorized);
            }
            (token_id, user_id)
        }
        None => {
            // Same verifier class as a wrong secret on a current row (I17).
            let _ = verify_peppered_secret(ring, secret, &dummy_peppered_hash(ring)).await?;
            return Err(AppError::Unauthorized);
        }
    };

    let mut tx = attome_db::tx::begin(db).await?;

    let consumed = sqlx::query(
        "UPDATE email_verification_token SET used_at = NOW()
         WHERE id = $1 AND used_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if consumed == 0 {
        return Err(AppError::Conflict("verification token already used"));
    }

    sqlx::query("UPDATE user_account SET email_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(user_id)
}

/// BAU-13b (F15): deletes up to `max_rows` email-verification tokens whose `expires_at` passed
/// more than `retention_secs` ago, used or not, returning how many went. An
/// unexpired row is never touched.
pub async fn prune_expired(
    db: &DbPool,
    retention_secs: i64,
    max_rows: i64,
) -> Result<u64, AppError> {
    sqlx::query(
        "DELETE FROM email_verification_token WHERE id IN (
             SELECT id FROM email_verification_token
             WHERE expires_at < NOW() - make_interval(secs => $1::float8)
             LIMIT $2)",
    )
    .bind(retention_secs)
    .bind(max_rows)
    .execute(db)
    .await
    .map(|done| done.rows_affected())
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unconnected_pool() -> DbPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@127.0.0.1:1/db")
            .expect("connect_lazy must not touch the network")
    }

    /// Both parsing tests return before the ring is consulted.
    fn test_ring() -> PepperRing {
        PepperRing::new(0, "verification-unit-test-pepper-0123456789", &[])
    }

    #[tokio::test]
    async fn confirm_rejects_a_token_with_no_dot_separator_without_querying_the_db() {
        let db = unconnected_pool();
        assert!(matches!(
            confirm(&db, "not-a-valid-token-shape", &test_ring()).await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn confirm_rejects_a_non_uuid_public_id_without_querying_the_db() {
        let db = unconnected_pool();
        assert!(matches!(
            confirm(&db, "not-a-uuid.somesecret", &test_ring()).await,
            Err(AppError::Unauthorized)
        ));
    }
}
