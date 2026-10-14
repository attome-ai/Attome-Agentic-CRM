//! Password reset flow (P-account-lifecycle) — backs `POST
//! /api/v1/auth/reset-request` and `POST /api/v1/auth/reset-confirm`. Same
//! public_id/secret bearer shape as `refresh.rs`, against
//! `password_reset_token` (migration 0022).
//!
//! The secret is platform-generated (48 random alphanumeric characters), so it
//! is hashed with the peppered HMAC scheme (`crate::apikey_hash`), not Argon2
//! (D-500). Any other stored format is refused.
//!
//! `request` never reveals whether the email exists (anti-enumeration, same
//! discipline as `accounts::login`) — the HTTP handler always responds 200
//! regardless of `Ok(None)` vs `Ok(Some(_))`; only `Some(_)` gets an email
//! enqueued.
//!
//! `confirm` applies a reset atomically (D-509, attome-auth hardening 2.3). In
//! one transaction, behind the locked and active account row, it consumes the
//! token, sets the password, expires the account's other reset links, revokes
//! every refresh token and bumps `auth_epoch`. Only after that commits does it
//! invalidate the epoch cache. API keys and MFA enrollment are untouched, and
//! the caller revokes nothing itself.

use attome_cache::Store;
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

/// A newly issued reset token, ready to be turned into a link and emailed.
pub struct IssuedReset {
    pub user_id: Uuid,
    pub email: String,
    pub bearer: String,
}

impl std::fmt::Debug for IssuedReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedReset")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// Looks up an active password account by email and, if one exists, issues a
/// single-use reset token. Returns `Ok(None)` for both "no such account" and
/// "account exists but has no password" (Google-only) — both are exactly the
/// enumeration-safe "nothing to do" case a caller must treat identically to
/// a hit, timing included: the `None` branch does the same hashing work as the
/// `Some` branch so the response doesn't leak which happened.
pub async fn request(
    db: &DbPool,
    email: &str,
    ttl_mins: u64,
    ring: &PepperRing,
) -> Result<Option<IssuedReset>, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let issued = request_in_tx(&mut tx, email, ttl_mins, ring).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(issued)
}

/// Transactional form of [`request`].  Callers that send an email must enqueue
/// its durable job in this same transaction so no usable reset token is ever
/// committed without its delivery work.
pub async fn request_in_tx(
    tx: &mut attome_db::Tx<'_>,
    email: &str,
    ttl_mins: u64,
    ring: &PepperRing,
) -> Result<Option<IssuedReset>, AppError> {
    // Base-auth hardening 2.4: the same lookup `accounts::login` uses. The
    // email is normalized once and matched exactly, so an account that can
    // sign in can also reset (`is_active` is NOT NULL since migration 0460).
    let email = crate::email_identity::normalize_email(email);
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, email FROM user_account
         WHERE email = $1
           AND is_active = true
           AND password_hash IS NOT NULL",
    )
    .bind(&email)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    match row {
        Some((user_id, real_email)) => {
            let public_id = Uuid::now_v7();
            let secret = generate_secret();
            let secret_hash = hash_peppered_secret(ring, &secret);
            let expires_at = Utc::now() + ChronoDuration::minutes(ttl_mins as i64);

            sqlx::query(
                "INSERT INTO password_reset_token (user_ref, public_id, secret_hash, expires_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(user_id)
            .bind(public_id)
            .bind(&secret_hash)
            .bind(expires_at)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;

            Ok(Some(IssuedReset {
                user_id,
                email: real_email,
                bearer: format!("{public_id}.{secret}"),
            }))
        }
        None => {
            // Timing equalization (same shape as accounts::login's miss path):
            // the same hashing work a real issuance does, on a throwaway secret.
            let _ = hash_peppered_secret(ring, &generate_secret());
            Ok(None)
        }
    }
}

/// Confirms a presented reset token and applies the reset atomically (D-509).
/// Returns the account's user id.
///
/// **Before any transaction or lock**: the bearer is parsed, the new password
/// is checked against the policy (I2), the token is looked up and its secret
/// verified, and the new password is hashed through the bounded KDF executor.
/// A failure at any of these writes nothing, and no KDF work ever runs while a
/// row lock is held.
///
/// **One transaction**, in this order:
/// 1. lock the account row `FOR UPDATE` and require it active;
/// 2. consume the token;
/// 3. set the password;
/// 4. expire the account's other unused reset tokens;
/// 5. revoke every refresh token;
/// 6. bump `auth_epoch`;
/// 7. commit.
///
/// The epoch cache is invalidated only after a successful commit. API keys
/// and MFA enrollment are left alone (sessions-only policy).
///
/// Taking the account row first is the lock order every path shares (D-509
/// rule 6). It also serializes two confirms of one token: the loser proceeds
/// only after the winner commits, finds the token used, and rolls back having
/// written nothing.
///
/// Errors: `Unauthorized` for a malformed, unknown, expired or wrong-secret
/// token and for an inactive account, so account state is not revealed;
/// `Validation` for a policy failure; `Conflict` for an already-used token.
pub async fn confirm(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    new_password: &str,
    ring: &PepperRing,
) -> Result<Uuid, AppError> {
    let mut subject = None;
    confirm_inner(
        db,
        redis,
        presented,
        new_password,
        ring,
        &mut subject,
        &attome_db::NoHook,
    )
    .await
}

/// [`confirm`], also returning the account the token identified whenever its
/// secret verified — on success, and on the rejections that follow a verified
/// token (inactive account, already-used token). `None` means the token
/// identified no one. The route uses it to record a failed reset against the
/// account without trusting an unverified token (audit plan 3.4).
pub async fn confirm_with_subject(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    new_password: &str,
    ring: &PepperRing,
) -> (Result<Uuid, AppError>, Option<Uuid>) {
    confirm_with_subject_hook(db, redis, presented, new_password, ring, &attome_db::NoHook).await
}

/// [`confirm_with_subject`], plus a [`attome_db::BeforeCommit`] hook that runs
/// inside the reset's transaction with the account id, after every step of
/// the reset and before it commits, so the caller's reset event commits with
/// the new password or neither does (D-062). A refused reset does not run it.
pub async fn confirm_with_subject_hook(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    new_password: &str,
    ring: &PepperRing,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> (Result<Uuid, AppError>, Option<Uuid>) {
    let mut subject = None;
    let result = confirm_inner(db, redis, presented, new_password, ring, &mut subject, hook).await;
    (result, subject)
}

async fn confirm_inner(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    new_password: &str,
    ring: &PepperRing,
    subject: &mut Option<Uuid>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<Uuid, AppError> {
    let (public_id_str, secret) = presented.split_once('.').ok_or(AppError::Unauthorized)?;
    let public_id: Uuid = public_id_str.parse().map_err(|_| AppError::Unauthorized)?;

    // Security contract I2: enforced in the engine, before any database or KDF
    // work. It sits after the bearer parse, so a malformed token still reads as
    // Unauthorized whatever password came with it.
    let new_password = crate::password::NewPassword::validate(new_password)?;

    // Deliberately does NOT filter `used_at IS NULL` here — an already-used
    // token must still be found and its secret verified so the guarded
    // UPDATE below (which DOES check `used_at IS NULL`) is what reports
    // Conflict, not a misleading Unauthorized. Only expiry short-circuits to
    // Unauthorized before that point.
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, user_ref, secret_hash FROM password_reset_token
         WHERE public_id = $1 AND expires_at > NOW()",
    )
    .bind(public_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let (token_id, user_id) = match row {
        Some((token_id, user_id, secret_hash)) => {
            // `OkNeedsRehash` (a retired pepper id) is still a match; the token
            // is consumed below either way, so nothing to rewrite.
            if verify_peppered_secret(ring, secret, &secret_hash).await? == VerifyOutcome::Fail {
                return Err(AppError::Unauthorized);
            }
            *subject = Some(user_id);
            (token_id, user_id)
        }
        None => {
            // Same verifier class as a wrong secret on a current row (I17).
            let _ = verify_peppered_secret(ring, secret, &dummy_peppered_hash(ring)).await?;
            return Err(AppError::Unauthorized);
        }
    };

    let new_hash = crate::password::hash_password_async(new_password).await?;

    let mut tx = attome_db::tx::begin(db).await?;

    // 1. The account row first (D-509 rules 3.1 and 6).
    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if is_active != Some(true) {
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(AppError::Unauthorized);
    }

    // 2. Single-use enforcement: guarded UPDATE + rows_affected, same
    // retry-safety shape as any other Layer-2 mutation (guidelines §2).
    let consumed = sqlx::query(
        "UPDATE password_reset_token SET used_at = NOW()
         WHERE id = $1 AND used_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if consumed == 0 {
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(AppError::Conflict("reset token already used"));
    }

    // 3. The new password.
    sqlx::query("UPDATE user_account SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // 4. The account's other unused reset links expire. They are not marked
    // used: `used_at` records the token that performed the reset, and an
    // expired link answers 401 like any other.
    sqlx::query(
        "UPDATE password_reset_token SET expires_at = NOW()
         WHERE user_ref = $1 AND used_at IS NULL AND expires_at > NOW() AND id <> $2",
    )
    .bind(user_id)
    .bind(token_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // 5. Every refresh token, in every family.
    crate::refresh::revoke_all_for_user_in_tx(&mut tx, user_id).await?;

    // 6. The epoch, so live access tokens die too.
    crate::epoch::bump_in_tx(&mut tx, user_id).await?;

    // 7. All of the above, and the caller's hook, or none of it.
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    // Cache coherence only, after the commit (bounded by I15).
    crate::epoch::invalidate_cache(redis, user_id).await;

    Ok(user_id)
}

/// BAU-13b (F15): deletes up to `max_rows` password-reset tokens whose `expires_at` passed
/// more than `retention_secs` ago, used or not, returning how many went. An
/// unexpired row is never touched.
pub async fn prune_expired(
    db: &DbPool,
    retention_secs: i64,
    max_rows: i64,
) -> Result<u64, AppError> {
    sqlx::query(
        "DELETE FROM password_reset_token WHERE id IN (
             SELECT id FROM password_reset_token
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
    use fred::prelude::*;

    fn unconnected_pool() -> DbPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@127.0.0.1:1/db")
            .expect("connect_lazy must not touch the network")
    }

    /// A Redis client built but never connected — valid only for the
    /// early-return parsing paths below, which return before `confirm` ever
    /// reaches its `epoch::invalidate_cache` call.
    fn unconnected_redis() -> attome_cache::Store {
        let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
        attome_cache::Store::Redis(Builder::from_config(config).build_pool(1).unwrap())
    }

    /// Both parsing tests return before the ring is consulted.
    fn test_ring() -> PepperRing {
        PepperRing::new(0, "reset-unit-test-pepper-0123456789abcdef", &[])
    }

    #[tokio::test]
    async fn confirm_rejects_a_token_with_no_dot_separator_without_querying_the_db() {
        let db = unconnected_pool();
        let redis = unconnected_redis();
        let result = confirm(
            &db,
            &redis,
            "not-a-valid-token-shape",
            "newpassword",
            &test_ring(),
        )
        .await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn confirm_rejects_a_non_uuid_public_id_without_querying_the_db() {
        let db = unconnected_pool();
        let redis = unconnected_redis();
        let result = confirm(
            &db,
            &redis,
            "not-a-uuid.somesecret",
            "newpassword",
            &test_ring(),
        )
        .await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
