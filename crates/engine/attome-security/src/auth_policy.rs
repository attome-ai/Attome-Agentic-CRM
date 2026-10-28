//! Q1-T7: who may sign in with a password.
//!
//! A user may not when their email's domain is a verified SSO-only domain
//! (`oidc_domain.sso_only`), or when any role they hold, directly or through
//! a team, is SSO-only (`role_auth_policy.sso_only`). A break-glass account
//! (`break_glass_account`) always keeps its password, so a broken identity
//! provider never locks every administrator out; its use is audited.
//!
//! The local login asks [`password_login`] after the password verifies and
//! answers a refusal exactly as it answers a wrong password, so the response
//! never reveals the policy.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// What [`password_login`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordLogin {
    /// No SSO-only rule applies.
    Allowed,
    /// A break-glass account: allowed, and the sign-in is recorded.
    BreakGlass,
    /// An SSO-only domain or role applies: sign in through the provider.
    Refused,
}

/// The domain part of an email address, lower-cased; `None` without an `@`.
pub fn email_domain(email: &str) -> Option<String> {
    email
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_lowercase())
        .filter(|domain| !domain.is_empty())
}

/// Q1-T6: the key of the provider `email`'s domain routes sign-in to, when
/// that domain is verified for a provider that is on. Says nothing about
/// whether anyone with that email exists.
pub async fn provider_for_email(db: &DbPool, email: &str) -> Result<Option<String>, AppError> {
    let Some(domain) = email_domain(email) else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT p.key FROM oidc_domain d JOIN oidc_provider p ON p.id = d.provider_ref \
          WHERE d.domain = $1 AND d.verified_at IS NOT NULL \
            AND p.enabled AND NOT p.is_deleted",
    )
    .bind(&domain)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Q1-T6: whether `email`'s domain is verified for the provider `provider_key`.
/// A provider added on screen signs in, links or creates only such people:
/// an administrator who adds a provider does not thereby vouch for every
/// email address it may assert.
pub async fn domain_verified_for(
    db: &DbPool,
    provider_key: &str,
    email: &str,
) -> Result<bool, AppError> {
    let Some(domain) = email_domain(email) else {
        return Ok(false);
    };
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oidc_domain d JOIN oidc_provider p ON p.id = d.provider_ref \
                         WHERE d.domain = $1 AND p.key = $2 AND d.verified_at IS NOT NULL \
                           AND NOT p.is_deleted)",
    )
    .bind(&domain)
    .bind(provider_key)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Whether `user_id` (signing in as `email`) may use a password.
pub async fn password_login(
    db: &DbPool,
    user_id: Uuid,
    email: &str,
) -> Result<PasswordLogin, AppError> {
    let domain = email_domain(email).unwrap_or_default();
    let (break_glass, sso_only): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM break_glass_account WHERE user_ref = $1), \
                EXISTS (SELECT 1 FROM oidc_domain \
                         WHERE domain = $2 AND sso_only AND verified_at IS NOT NULL) \
             OR EXISTS (SELECT 1 FROM role_auth_policy p \
                         WHERE p.sso_only AND p.role_ref IN ( \
                               SELECT ur.role_ref FROM user_account_mm_role ur \
                                WHERE ur.user_ref = $1 AND NOT ur.is_deleted \
                               UNION \
                               SELECT rt.role_ref FROM user_account_mm_team ut \
                                 JOIN role_mm_team rt ON rt.team_ref = ut.team_ref \
                                      AND NOT rt.is_deleted \
                                WHERE ut.user_ref = $1 AND NOT ut.is_deleted))",
    )
    .bind(user_id)
    .bind(&domain)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(decide(break_glass, sso_only))
}

/// The decision from the two facts. Pure.
pub fn decide(break_glass: bool, sso_only: bool) -> PasswordLogin {
    match (break_glass, sso_only) {
        (true, _) => PasswordLogin::BreakGlass,
        (false, true) => PasswordLogin::Refused,
        (false, false) => PasswordLogin::Allowed,
    }
}

/// Counts a break-glass password sign-in (`auth_break_glass_sign_in_total`).
pub fn record_break_glass_sign_in() {
    metrics::counter!("auth_break_glass_sign_in_total").increment(1);
}

/// Whether any SSO-only rule is in force (a verified SSO-only domain or an
/// SSO-only role), for the last-break-glass guard.
pub async fn any_sso_only(conn: &mut sqlx::PgConnection) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oidc_domain WHERE sso_only AND verified_at IS NOT NULL) \
             OR EXISTS (SELECT 1 FROM role_auth_policy WHERE sso_only)",
    )
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_glass_wins_over_sso_only() {
        assert_eq!(decide(true, true), PasswordLogin::BreakGlass);
        assert_eq!(decide(false, true), PasswordLogin::Refused);
        assert_eq!(decide(false, false), PasswordLogin::Allowed);
    }

    #[test]
    fn the_domain_is_the_part_after_the_last_at() {
        assert_eq!(email_domain("Sara@Acme.SA").as_deref(), Some("acme.sa"));
        assert_eq!(email_domain("no-at-sign"), None);
        assert_eq!(email_domain("x@"), None);
    }
}
