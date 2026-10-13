//! Account self-service through a portal's trusted server (D-780): what a
//! game's login service does for a player who is signed in with it and has
//! no web session: read the account's email and MFA state, add an email
//! (proven by a link sent to it), and turn MFA on or off. **Business logic
//! only**, on the caller's open transaction; the S2S routes, rate limits,
//! emails and security events are in [`crate::router::trusted`].
//!
//! Everything that changes the account asks for the password again (the
//! trusted server holds a session for the player, not their password), and
//! a wrong one grows the same delay a wrong trusted login does (D-779).

use attome_types::AppError;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::onetime::{self, IssuedToken};
use crate::provision;
use crate::trusted::{dummy, record_failure};

/// The result of checking the account's password again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordCheck {
    Ok,
    Wrong,
    /// Inside the account's failure delay.
    RetryLater(i64),
    /// Disabled, erased, or not an account of this portal.
    Unavailable,
}

type CheckRow = (String, Option<String>, i32, Option<DateTime<Utc>>);

/// Checks `password` for the account (row-locked for the transaction).
pub async fn check_password(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
    password: &str,
    now: DateTime<Utc>,
) -> Result<PasswordCheck, AppError> {
    let row: Option<CheckRow> = sqlx::query_as(
        "SELECT u.status, c.password_hash, c.trusted_failed_count, c.trusted_retry_after \
         FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE u.id = $1 AND u.webportal_ref = $2 AND u.is_active IS NOT FALSE \
         FOR UPDATE OF c",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((status, hash, failed, retry_after)) = row else {
        dummy(password).await?;
        return Ok(PasswordCheck::Unavailable);
    };
    if status != "active" {
        dummy(password).await?;
        return Ok(PasswordCheck::Unavailable);
    }
    if let Some(until) = retry_after.filter(|until| *until > now) {
        return Ok(PasswordCheck::RetryLater(
            (until - now).num_seconds().max(1),
        ));
    }
    let ok = match hash.as_deref() {
        Some(hash) => attome_auth::verify_password_async(password, hash).await?,
        None => {
            dummy(password).await?;
            false
        }
    };
    if !ok {
        record_failure(conn, user_id, failed.saturating_add(1), now).await?;
        return Ok(PasswordCheck::Wrong);
    }
    if failed != 0 || retry_after.is_some() {
        sqlx::query(
            "UPDATE webportal_credential SET trusted_failed_count = 0, \
               trusted_retry_after = NULL, updated_at = NOW() \
             WHERE webportal_user_id = $1",
        )
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(PasswordCheck::Ok)
}

/// What a player may see of their own account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub username: Option<String>,
    pub email: Option<String>,
    /// The address a live email-add link would add.
    pub pending_email: Option<String>,
    pub mfa_enabled: bool,
    pub recovery_codes_left: i64,
}

type InfoRow = (Option<String>, Option<String>, bool);

pub async fn account_info(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<Option<AccountInfo>, AppError> {
    let row: Option<InfoRow> = sqlx::query_as(
        "SELECT u.username, u.email, c.mfa_enabled \
         FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE u.id = $1 AND u.webportal_ref = $2 AND u.is_active IS NOT FALSE",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((username, email, mfa_enabled)) = row else {
        return Ok(None);
    };
    let recovery_codes_left = if mfa_enabled {
        crate::recovery::remaining(conn, user_id).await?
    } else {
        0
    };
    Ok(Some(AccountInfo {
        username,
        email,
        pending_email: onetime::pending_email(conn, user_id).await?,
        mfa_enabled,
        recovery_codes_left,
    }))
}

/// Starting to add an email.
pub enum EmailAdd {
    /// Send `token` to `to`: the account gets the address once it is opened.
    Send {
        to: String,
        token: IssuedToken,
    },
    /// Another account of the portal has this address: its owner is told
    /// instead (the caller answers exactly as for `Send`, so no address is
    /// ever revealed as taken, D-779 item 5).
    InUse {
        to: String,
    },
    /// Already the account's email.
    Unchanged,
    Invalid(String),
}

impl std::fmt::Debug for EmailAdd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailAdd").finish_non_exhaustive()
    }
}

pub async fn request_email_add(
    conn: &mut PgConnection,
    pepper: &attome_auth::apikey_hash::PepperRing,
    portal_id: Uuid,
    user_id: Uuid,
    raw_email: &str,
) -> Result<EmailAdd, AppError> {
    let email = match provision::normalize_email(raw_email) {
        Ok(e) => e,
        Err(AppError::Validation(why)) => return Ok(EmailAdd::Invalid(why)),
        Err(e) => return Err(e),
    };
    let current: Option<Option<String>> = sqlx::query_scalar(
        "SELECT lower(email) FROM webportal_user \
         WHERE id = $1 AND webportal_ref = $2 AND is_active IS NOT FALSE",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(current) = current else {
        return Ok(EmailAdd::Invalid("no such account".into()));
    };
    if current.as_deref() == Some(email.as_str()) {
        return Ok(EmailAdd::Unchanged);
    }
    if email_in_use(conn, portal_id, &email).await? {
        return Ok(EmailAdd::InUse { to: email });
    }
    let token = onetime::issue_email_add(conn, pepper, portal_id, user_id, &email).await?;
    Ok(EmailAdd::Send { to: email, token })
}

async fn email_in_use(
    conn: &mut PgConnection,
    portal_id: Uuid,
    email: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_user u \
           LEFT JOIN webportal_credential c ON c.webportal_user_id = u.id \
           WHERE u.webportal_ref = $1 AND u.is_active IS NOT FALSE \
             AND (lower(u.email) = $2 OR c.login_email_lower = $2))",
    )
    .bind(portal_id)
    .bind(email)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Opening the emailed link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailConfirm {
    /// The account now has `email` (verified); `previous` is the address it
    /// replaced, to be told.
    Added {
        user_id: Uuid,
        email: String,
        previous: Option<String>,
    },
    /// Another account took the address since the link was sent.
    InUse,
    /// Unknown, used, expired or malformed link, or the account is gone.
    Invalid,
}

pub async fn confirm_email_add(
    conn: &mut PgConnection,
    pepper: &attome_auth::apikey_hash::PepperRing,
    portal_id: Uuid,
    bearer: &str,
) -> Result<EmailConfirm, AppError> {
    let Some((user_id, email)) =
        onetime::consume_email_add(conn, pepper, portal_id, bearer).await?
    else {
        return Ok(EmailConfirm::Invalid);
    };
    provision::lock(
        conn,
        format!("attome-portal/user-email:{portal_id}:{email}"),
    )
    .await?;
    let previous: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT email, status FROM webportal_user \
         WHERE id = $1 AND webportal_ref = $2 AND is_active IS NOT FALSE FOR UPDATE",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((previous, status)) = previous else {
        return Ok(EmailConfirm::Invalid);
    };
    if status == "disabled" {
        return Ok(EmailConfirm::Invalid);
    }
    if email_in_use(conn, portal_id, &email).await? {
        return Ok(EmailConfirm::InUse);
    }
    sqlx::query("UPDATE webportal_user SET email = $2, modified_at = NOW() WHERE id = $1")
        .bind(user_id)
        .bind(&email)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE webportal_credential SET login_email_lower = $2, email_verified = TRUE, \
           updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(user_id)
    .bind(&email)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        if attome_db::is_unique_violation(&e) {
            AppError::Conflict("this web portal already has a user with this email")
        } else {
            AppError::internal(e)
        }
    })?;
    Ok(EmailConfirm::Added {
        user_id,
        email,
        previous: previous.filter(|p| !p.is_empty()),
    })
}

/// The account as an MFA principal (the MFA functions of [`crate::auth`]
/// act on one; a trusted server has no web session family).
pub async fn principal(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<Option<crate::auth::PortalPrincipal>, AppError> {
    let mfa: Option<bool> = sqlx::query_scalar(
        "SELECT c.mfa_enabled FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE u.id = $1 AND u.webportal_ref = $2 AND u.is_active IS NOT FALSE",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(mfa.map(|mfa_enabled| crate::auth::PortalPrincipal {
        webportal_id: portal_id,
        user_id,
        family_id: Uuid::nil(),
        mfa_enabled,
        mfa_enrollment_required: false,
        role_id: None,
    }))
}

/// `a***@example.com`: enough for the owner to recognise, not a copy of it.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_masked_to_the_first_letter_and_the_domain() {
        assert_eq!(mask_email("zezima@example.com"), "z***@example.com");
        assert_eq!(mask_email("a@b.co"), "a***@b.co");
        assert_eq!(mask_email("nonsense"), "***");
    }
}
