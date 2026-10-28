//! Q5-T4: remembered devices. After a second factor, a person whose policy
//! allows it may have the browser remembered for the policy's
//! `remember_device_days`; a password sign-in from it then skips the second
//! factor. The browser keeps `<row id>.<secret>` in the `__Host-attome_rd`
//! cookie; the row (`remembered_device`, migration 0077) keeps only the
//! secret's peppered hash (the D-500 bearer-secret scheme refresh tokens use)
//! and the account's auth epoch at the time.
//!
//! A remembered device stops counting when it expires, when it is revoked
//! (every session revocation for the person revokes it too:
//! [`crate::refresh::revoke_all_for_user_in_tx`]) and when the account's auth
//! epoch moves on (a password change, reset or disable bumps it). An
//! administrator's policy never remembers a device (`remember_device_days`
//! is 0 for them, Q5-T2), and a policy that does not remember reads every
//! device as unknown.

use attome_db::DbPool;
use attome_types::AppError;
use http::HeaderMap;
use rand::distributions::{Alphanumeric, DistString};
use uuid::Uuid;

use crate::apikey_hash::{PepperRing, VerifyOutcome, verify_peppered_secret};

/// The cookie's name with HTTPS (`__Host-`: Secure, no Domain, `Path=/`), and
/// without it in plain-http local dev, as the session cookie does.
pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-attome_rd"
    } else {
        "attome_rd"
    }
}

/// The `Set-Cookie` value for `bearer`, kept `days` days.
pub fn cookie(bearer: &str, days: i32, secure: bool) -> String {
    let max_age = u64::try_from(days.max(0)).unwrap_or(0) * 86_400;
    crate::cookie::build(cookie_name(secure), bearer, max_age, secure, "/")
}

/// The remembered-device bearer the request presents, if any.
pub fn presented(headers: &HeaderMap, secure: bool) -> Option<String> {
    crate::cookie::extract(headers, cookie_name(secure))
}

/// Remembers this browser for `user_id` at `epoch` for `days` days and
/// returns the bearer to set as the cookie. Only the secret's hash is
/// stored.
pub async fn remember(
    db: &DbPool,
    ring: &PepperRing,
    user_id: Uuid,
    epoch: i32,
    days: i32,
    label: Option<&str>,
) -> Result<String, AppError> {
    if days <= 0 {
        return Err(AppError::Validation(
            "this policy does not remember devices".into(),
        ));
    }
    let id = Uuid::now_v7();
    let secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 48);
    let inserted = sqlx::query(
        "INSERT INTO remembered_device (id, user_ref, token_hash, auth_epoch, label, expires_at) \
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6))",
    )
    .bind(id)
    .bind(user_id)
    .bind(ring.hash(&secret))
    .bind(epoch)
    .bind(label.map(|l| l.chars().take(200).collect::<String>()))
    .bind(days)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if inserted != 1 {
        return Err(AppError::internal("remembered device was not stored"));
    }
    Ok(format!("{id}.{secret}"))
}

/// Whether `presented` is a live remembered device of `user_id` at
/// `current_epoch`: not revoked, not expired, the same epoch, and the secret
/// verifying in constant time. Anything malformed or unknown is `false`; a
/// verified one has its `last_used_at` stamped.
pub async fn is_remembered(
    db: &DbPool,
    ring: &PepperRing,
    user_id: Uuid,
    presented: &str,
    current_epoch: i32,
) -> Result<bool, AppError> {
    let Some((id, secret)) = presented.split_once('.') else {
        return Ok(false);
    };
    let Ok(id) = id.parse::<Uuid>() else {
        return Ok(false);
    };
    let row: Option<String> = sqlx::query_scalar(
        "SELECT token_hash FROM remembered_device \
          WHERE id = $1 AND user_ref = $2 AND auth_epoch = $3 \
            AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(id)
    .bind(user_id)
    .bind(current_epoch)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(stored) = row else {
        return Ok(false);
    };
    let remembered = !matches!(
        verify_peppered_secret(ring, secret, &stored).await?,
        VerifyOutcome::Fail
    );
    if remembered {
        sqlx::query("UPDATE remembered_device SET last_used_at = now() WHERE id = $1")
            .bind(id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(remembered)
}

/// The SQL that forgets every remembered device of a person (`$1`).
pub(crate) const REVOKE_ALL_SQL: &str = "UPDATE remembered_device SET revoked_at = now() \
     WHERE user_ref = $1 AND revoked_at IS NULL";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cookie_is_host_prefixed_with_https_and_kept_the_policy_days() {
        assert_eq!(cookie_name(true), "__Host-attome_rd");
        let set = cookie("id.secret", 30, true);
        assert!(set.starts_with("__Host-attome_rd=id.secret;"), "{set}");
        assert!(set.contains("Max-Age=2592000"), "{set}");
        assert!(set.contains("Secure") && set.contains("HttpOnly"), "{set}");
        assert!(
            set.contains("SameSite=Strict") && set.contains("Path=/"),
            "{set}"
        );
        assert!(cookie("x", 0, false).contains("Max-Age=0"));
    }
}
