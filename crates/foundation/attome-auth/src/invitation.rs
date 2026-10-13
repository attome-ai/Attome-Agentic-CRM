//! Invitation tokens (P-registration-gating Phase 2, D-128) — back
//! `auth.registration_mode = "invite"`. An admin (`xrm_security`'s admin
//! surface) mints a bearer for a specific email; `accounts::register`
//! requires and consumes it in `invite` mode. Same `{public_id}.{secret}`
//! bearer shape as `verification.rs`/`reset.rs`, against
//! `invitation_token` (migration 0045) — the one structural difference
//! is there is no `user_ref` yet (the invitee has no account until
//! registration succeeds), so the row is keyed by `email` instead.
//!
//! The secret is platform-generated, so it is hashed with the peppered HMAC
//! scheme (`crate::apikey_hash`), not Argon2 (D-500).

use attome_db::{DbPool, Tx};
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

pub struct IssuedInvitation {
    pub id: Uuid,
    pub email: String,
    pub bearer: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

impl std::fmt::Debug for IssuedInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedInvitation")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Mints a new invitation for `email`, admin-initiated
/// (`xrm_security::invitations`) — does not check whether `email` already has
/// an account; the admin-facing caller is the enforcement point for that, not
/// this module (same "caller already knows what it's doing" reasoning as
/// `verification::request`). Thin begin/commit wrapper around
/// [`issue_in_tx`] for callers that don't need to enqueue anything else in
/// the same transaction (e.g. tests).
pub async fn issue(
    db: &DbPool,
    email: &str,
    invited_by: Uuid,
    ttl_hours: u64,
    ring: &PepperRing,
) -> Result<IssuedInvitation, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let issued = issue_in_tx(&mut tx, email, invited_by, ttl_hours, ring).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(issued)
}

/// Transactional form of [`issue`] (P-email-hardening) — callers that send an
/// email must enqueue its durable job (and record its `email_delivery`
/// tracking row) in this same transaction, same reasoning as
/// `reset::request_in_tx`.
pub async fn issue_in_tx(
    tx: &mut Tx<'_>,
    email: &str,
    invited_by: Uuid,
    ttl_hours: u64,
    ring: &PepperRing,
) -> Result<IssuedInvitation, AppError> {
    // Base-auth hardening 2.4: store the invitation under the same normalized
    // email that registration and login use, not whatever the admin typed.
    let email = crate::email_identity::normalize_email(email);
    let public_id = Uuid::now_v7();
    let secret = generate_secret();
    let secret_hash = hash_peppered_secret(ring, &secret);
    let expires_at = Utc::now() + ChronoDuration::hours(ttl_hours as i64);

    let (id, created_at): (Uuid, chrono::DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO invitation_token (email, invited_by_ref, public_id, secret_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, created_at",
    )
    .bind(&email)
    .bind(invited_by)
    .bind(public_id)
    .bind(&secret_hash)
    .bind(expires_at)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(IssuedInvitation {
        id,
        email,
        bearer: format!("{public_id}.{secret}"),
        created_at,
        expires_at,
    })
}

/// Splits a `{public_id}.{secret}` bearer into its parts — pure and
/// synchronous so the wire-shape check never needs a database connection
/// (unlike the rest of `validate_and_consume`, this is unit-tested directly).
fn parse_bearer(presented: &str) -> Result<(Uuid, &str), AppError> {
    let (public_id_str, secret) = presented.split_once('.').ok_or(AppError::Forbidden)?;
    let public_id: Uuid = public_id_str.parse().map_err(|_| AppError::Forbidden)?;
    Ok((public_id, secret))
}

/// Validates a presented invitation bearer against `email` (case-insensitive)
/// and consumes it (`used_at`) — all inside the caller's transaction, so
/// `accounts::register` can run this in the same `tx` as the
/// `user_account` INSERT: a token is never consumed without the account it
/// gated actually being created, and vice versa.
///
/// Unlike `verification::confirm`/`reset::confirm` (which deliberately let a
/// reused token reach a distinct `Conflict` outcome), every failure mode here
/// — unknown token, expired, already used, or a well-formed-but-wrong-email
/// token — collapses to the same `AppError::Forbidden`. P-registration-gating
/// §8: an invite-mode register attempt must not become a new enumeration
/// oracle that tells a caller which of those cases they hit.
pub async fn validate_and_consume(
    tx: &mut Tx<'_>,
    presented: &str,
    email: &str,
    ring: &PepperRing,
) -> Result<(), AppError> {
    let (public_id, secret) = parse_bearer(presented)?;

    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, email, secret_hash FROM invitation_token
         WHERE public_id = $1 AND expires_at > NOW() AND used_at IS NULL",
    )
    .bind(public_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let (token_id, token_email) = match row {
        Some((token_id, token_email, secret_hash)) => {
            if verify_peppered_secret(ring, secret, &secret_hash).await? == VerifyOutcome::Fail {
                return Err(AppError::Forbidden);
            }
            (token_id, token_email)
        }
        None => {
            // A nonexistent or already-used public_id runs the same verifier
            // work as a wrong secret on a current row, so it doesn't respond
            // measurably faster (security contract I17).
            let _ = verify_peppered_secret(ring, secret, &dummy_peppered_hash(ring)).await?;
            return Err(AppError::Forbidden);
        }
    };

    if !token_email.eq_ignore_ascii_case(email) {
        return Err(AppError::Forbidden);
    }

    let consumed = sqlx::query(
        "UPDATE invitation_token SET used_at = NOW() WHERE id = $1 AND used_at IS NULL",
    )
    .bind(token_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if consumed == 0 {
        // Lost a race with another concurrent registration attempt using the
        // same token — same undifferentiated outcome as every other failure
        // mode above.
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// BAU-13b (F15): deletes up to `max_rows` invitation tokens whose `expires_at` passed
/// more than `retention_secs` ago, used or not, returning how many went. An
/// unexpired row is never touched.
pub async fn prune_expired(
    db: &DbPool,
    retention_secs: i64,
    max_rows: i64,
) -> Result<u64, AppError> {
    sqlx::query(
        "DELETE FROM invitation_token WHERE id IN (
             SELECT id FROM invitation_token
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

    #[test]
    fn parse_bearer_rejects_a_token_with_no_dot_separator() {
        assert!(matches!(
            parse_bearer("not-a-valid-token-shape"),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn parse_bearer_rejects_a_non_uuid_public_id() {
        assert!(matches!(
            parse_bearer("not-a-uuid.somesecret"),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn parse_bearer_accepts_a_well_formed_bearer() {
        let public_id = Uuid::now_v7();
        let bearer = format!("{public_id}.some-secret-value");
        let (parsed_id, secret) = parse_bearer(&bearer).unwrap();
        assert_eq!(parsed_id, public_id);
        assert_eq!(secret, "some-secret-value");
    }
}
