//! Trusted server login (D-779): a portal's own servers sign its users in
//! with a password, and create an account for a free username, on behalf of
//! a client that never talks to the CRM itself (Attome Online's login
//! service is the first user). **Business logic only**, on the caller's open
//! transaction; the S2S route, rate limits and security events are in
//! [`crate::router::trusted`].
//!
//! The state machine, evaluated in this order (game repo
//! `docs/ACCOUNTS_PLAN.md` §3.2):
//!
//! | Situation | Outcome |
//! |---|---|
//! | Unknown email, or a username breaking the portal's rules | `BadCredentials` / `NameRejected` |
//! | Account disabled | `Disabled` |
//! | Inside the account's failure delay | `RetryLater` |
//! | Password wrong | `BadCredentials`; the delay grows |
//! | Password right, MFA on, no code | `MfaRequired` |
//! | Password right, MFA on, wrong code | `MfaFailed`; the delay grows (D-780) |
//! | Password right (and the code, when MFA is on) | `Ok` (`OkWithRecoveryCode`) |
//! | Free username, `create_if_missing` false | `BadCredentials` |
//! | Free username, the address's creation limit used up | `CreationLimited` |
//! | Free username, password breaks the policy | `PasswordRejected` |
//! | Free username, everything valid | `Created` |
//!
//! An existing account with a wrong password never creates or changes
//! anything but its failure streak. Unknown accounts and refusals run a dummy
//! KDF so a response's timing doesn't reveal which case it was, beyond what
//! instant creation itself reveals for usernames (D-779 item 4).

use attome_auth::apikey_hash::PepperRing;
use attome_config::KeyRing;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::policy::{AuthPolicy, UsernameRejected};
use crate::provision::{self, LoginKey};
use crate::{mfa, recovery};

/// Longest delay a failure streak imposes on one account.
pub const MAX_DELAY_SECS: i64 = 60;

/// The delay after the `n`th failure in a row: 1, 2, 4, ... seconds, capped.
pub fn failure_delay_secs(streak: i32) -> i64 {
    let shift = (streak.max(1) - 1).min(6) as u32;
    (1_i64 << shift).min(MAX_DELAY_SECS)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedOutcome {
    Ok {
        user_id: Uuid,
        auth_epoch: i32,
    },
    Created {
        user_id: Uuid,
        auth_epoch: i32,
    },
    /// Wrong password, unknown email, or a free username without
    /// `create_if_missing`. `user_id` is set when an account exists (for the
    /// security event), never returned to the caller.
    BadCredentials {
        user_id: Option<Uuid>,
    },
    NameRejected(UsernameRejected),
    PasswordRejected(String),
    Disabled {
        user_id: Uuid,
    },
    /// The account's failure delay hasn't passed yet.
    RetryLater {
        user_id: Uuid,
        retry_after_secs: i64,
    },
    /// The client address has used up its account creations for now.
    CreationLimited {
        retry_after_secs: i64,
    },
    /// The account has MFA and the request carried no second factor.
    MfaRequired {
        user_id: Uuid,
    },
    /// D-780: the password was right but the second factor was wrong,
    /// replayed or used up; counts toward the account's delay.
    MfaFailed {
        user_id: Uuid,
    },
    /// D-780: signed in with a recovery code (one fewer left); the owner is
    /// told by email when the account has one.
    OkWithRecoveryCode {
        user_id: Uuid,
        auth_epoch: i32,
    },
}

/// D-780: the second factor a trusted server passes on for an account with
/// MFA: a TOTP code or a recovery code, and the keys to check it.
pub struct SecondFactor<'a> {
    pub code: &'a str,
    pub pepper: &'a PepperRing,
    pub mfa_ring: &'a KeyRing,
}

impl std::fmt::Debug for SecondFactor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecondFactor").finish_non_exhaustive()
    }
}

struct Account {
    user_id: Uuid,
    status: String,
    password_hash: Option<String>,
    auth_epoch: i32,
    mfa_enabled: bool,
    failed: i32,
    retry_after: Option<DateTime<Utc>>,
    mfa_secret_enc: Option<String>,
    mfa_last_step: Option<i64>,
}

type AccountRow = (
    Uuid,
    String,
    Option<String>,
    i32,
    bool,
    i32,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<i64>,
);

/// The live account for `login`, row-locked for the rest of the transaction
/// so concurrent attempts on one account serialize.
async fn account(
    conn: &mut PgConnection,
    portal_id: Uuid,
    key: &LoginKey,
) -> Result<Option<Account>, AppError> {
    let (filter, value) = match key {
        LoginKey::Email(email) => ("u.webportal_ref = $1 AND lower(u.email) = $2", email),
        LoginKey::Username(name) => ("c.webportal_id = $1 AND c.login_username_lower = $2", name),
    };
    let row: Option<AccountRow> = sqlx::query_as(&format!(
        "SELECT u.id, u.status, c.password_hash, c.auth_epoch, c.mfa_enabled, \
                c.trusted_failed_count, c.trusted_retry_after, c.mfa_secret_enc, c.mfa_last_step \
         FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE {filter} AND u.is_active IS NOT FALSE FOR UPDATE OF c"
    ))
    .bind(portal_id)
    .bind(value)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|r| Account {
        user_id: r.0,
        status: r.1,
        password_hash: r.2,
        auth_epoch: r.3,
        mfa_enabled: r.4,
        failed: r.5,
        retry_after: r.6,
        mfa_secret_enc: r.7,
        mfa_last_step: r.8,
    }))
}

/// Equal work for the paths that check no real password.
pub(crate) async fn dummy(password: &str) -> Result<(), AppError> {
    attome_auth::password::verify_against_dummy_async(password).await?;
    Ok(())
}

/// One trusted-login attempt.
pub struct TrustedRequest<'a> {
    pub login: &'a str,
    pub password: &'a str,
    pub create_if_missing: bool,
    /// The caller's verdict on the client address's creation limits
    /// (`Err(retry_after_secs)` when used up).
    pub creation_budget: Result<(), i64>,
    /// Passed in so tests can step time.
    pub now: DateTime<Utc>,
    /// D-780: for accounts with MFA (ignored for the others).
    pub second_factor: Option<SecondFactor<'a>>,
}

impl std::fmt::Debug for TrustedRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedRequest").finish_non_exhaustive()
    }
}

/// Runs the state machine.
pub async fn trusted_login(
    conn: &mut PgConnection,
    portal_id: Uuid,
    policy: &AuthPolicy,
    req: TrustedRequest<'_>,
) -> Result<TrustedOutcome, AppError> {
    let TrustedRequest {
        login,
        password,
        create_if_missing,
        creation_budget,
        now,
        second_factor,
    } = req;
    let key = provision::login_key(login);
    if let Some(acc) = account(conn, portal_id, &key).await? {
        return existing(conn, acc, password, now, second_factor.as_ref()).await;
    }
    let LoginKey::Username(_) = key else {
        // An email is never created here: accounts with an email come from
        // signup, invitations or identity providers, which prove the address.
        dummy(password).await?;
        return Ok(TrustedOutcome::BadCredentials { user_id: None });
    };
    let username = match policy.check_username(login) {
        Ok(name) => name,
        Err(why) => {
            dummy(password).await?;
            return Ok(TrustedOutcome::NameRejected(why));
        }
    };
    if !create_if_missing {
        dummy(password).await?;
        return Ok(TrustedOutcome::BadCredentials { user_id: None });
    }
    if let Err(retry_after_secs) = creation_budget {
        return Ok(TrustedOutcome::CreationLimited { retry_after_secs });
    }
    let new_password = match attome_auth::NewPassword::validate(password) {
        Ok(p) => p,
        Err(AppError::Validation(why)) => return Ok(TrustedOutcome::PasswordRejected(why)),
        Err(e) => return Err(e),
    };
    let hash = attome_auth::hash_password_async(new_password).await?;
    let created = provision::create_verified_account(
        conn,
        portal_id,
        &username,
        None,
        Some(&username),
        Some(&hash),
    )
    .await?;
    let Some(user_id) = created else {
        // Taken between the lookup and the claim (a concurrent create won
        // the name): it is now an existing account like any other.
        return match account(conn, portal_id, &key).await? {
            Some(acc) => existing(conn, acc, password, now, second_factor.as_ref()).await,
            None => Ok(TrustedOutcome::BadCredentials { user_id: None }),
        };
    };
    if let Some(role) = policy.signup_role_ref {
        crate::roles::assign_role(conn, portal_id, user_id, role).await?;
    }
    Ok(TrustedOutcome::Created {
        user_id,
        auth_epoch: 0,
    })
}

/// One more failure in the account's streak: the delay grows.
pub(crate) async fn record_failure(
    conn: &mut PgConnection,
    user_id: Uuid,
    streak: i32,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE webportal_credential SET trusted_failed_count = $2, \
           trusted_retry_after = $3, updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(user_id)
    .bind(streak)
    .bind(now + chrono::Duration::seconds(failure_delay_secs(streak)))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// D-780: checks the second factor of an account with MFA. `Some(true)` for
/// a recovery code, `Some(false)` for a TOTP code (its step is recorded so it
/// can't be replayed), `None` when wrong.
async fn second_factor_ok(
    conn: &mut PgConnection,
    acc: &Account,
    sf: &SecondFactor<'_>,
    now: DateTime<Utc>,
) -> Result<Option<bool>, AppError> {
    if recovery::normalise(sf.code).is_some() {
        return Ok(recovery::consume(conn, sf.pepper, acc.user_id, sf.code)
            .await?
            .then_some(true));
    }
    let Some(enc) = acc.mfa_secret_enc.as_deref() else {
        return Ok(None);
    };
    let secret = mfa::decrypt(sf.mfa_ring, enc)?;
    let now_secs = u64::try_from(now.timestamp()).unwrap_or(0);
    let Some(step) = mfa::verify(&secret, sf.code, acc.mfa_last_step, now_secs)? else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE webportal_credential SET mfa_last_step = $2, updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(acc.user_id)
    .bind(step)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(false))
}

async fn existing(
    conn: &mut PgConnection,
    acc: Account,
    password: &str,
    now: DateTime<Utc>,
    second_factor: Option<&SecondFactor<'_>>,
) -> Result<TrustedOutcome, AppError> {
    if acc.status == "disabled" {
        dummy(password).await?;
        return Ok(TrustedOutcome::Disabled {
            user_id: acc.user_id,
        });
    }
    if let Some(until) = acc.retry_after.filter(|until| *until > now) {
        return Ok(TrustedOutcome::RetryLater {
            user_id: acc.user_id,
            retry_after_secs: (until - now).num_seconds().max(1),
        });
    }
    let ok = match acc.password_hash.as_deref() {
        Some(hash) if acc.status == "active" => {
            attome_auth::verify_password_async(password, hash).await?
        }
        // Invited (no password yet): no password can be right.
        _ => {
            dummy(password).await?;
            false
        }
    };
    if !ok {
        record_failure(conn, acc.user_id, acc.failed.saturating_add(1), now).await?;
        return Ok(TrustedOutcome::BadCredentials {
            user_id: Some(acc.user_id),
        });
    }
    // The second factor before the streak is cleared: a wrong code keeps
    // growing the same delay a wrong password does.
    let mut recovery_code_used = false;
    if acc.mfa_enabled {
        let Some(sf) = second_factor else {
            return Ok(TrustedOutcome::MfaRequired {
                user_id: acc.user_id,
            });
        };
        match second_factor_ok(conn, &acc, sf, now).await? {
            Some(recovery) => recovery_code_used = recovery,
            None => {
                record_failure(conn, acc.user_id, acc.failed.saturating_add(1), now).await?;
                return Ok(TrustedOutcome::MfaFailed {
                    user_id: acc.user_id,
                });
            }
        }
    }
    if acc.failed != 0 || acc.retry_after.is_some() {
        sqlx::query(
            "UPDATE webportal_credential SET trusted_failed_count = 0, \
               trusted_retry_after = NULL, updated_at = NOW() \
             WHERE webportal_user_id = $1",
        )
        .bind(acc.user_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "UPDATE webportal_credential SET last_login_at = NOW() WHERE webportal_user_id = $1",
    )
    .bind(acc.user_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(if recovery_code_used {
        TrustedOutcome::OkWithRecoveryCode {
            user_id: acc.user_id,
            auth_epoch: acc.auth_epoch,
        }
    } else {
        TrustedOutcome::Ok {
            user_id: acc.user_id,
            auth_epoch: acc.auth_epoch,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_failure_delay_doubles_and_caps_at_a_minute() {
        let delays: Vec<i64> = (1..=9).map(failure_delay_secs).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(failure_delay_secs(0), 1);
        assert_eq!(failure_delay_secs(i32::MAX), 60);
    }
}
