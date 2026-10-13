//! Self-service signup (D-588 item 2).
//!
//! Nothing is created before the address is verified. A signup request stores
//! a pending row (`webportal_signup`, migration 0492) holding the
//! password's KDF hash and the consent given, and emails a single-use link.
//! Following the link creates the user, their credential, their role and
//! their consent record in one transaction, under the same advisory lock
//! provisioning takes. So an address can't be squatted by someone who doesn't
//! control it, and two verifications can't both create an account.
//!
//! The HTTP layer answers every request the same way whatever happened (an
//! existing account gets an email saying so, instead of a link), so the route
//! reveals nothing about which addresses have accounts.

use attome_auth::apikey_hash::PepperRing;
use attome_types::AppError;
use chrono::{Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::policy::AuthPolicy;
use crate::provision::{self, PortalDetail};
use crate::secret;

/// A signup link lives this long.
pub const SIGNUP_TTL_SECS: i64 = 24 * 60 * 60;

pub struct SignupInput<'a> {
    pub name: &'a str,
    pub email_lower: &'a str,
    /// Already hashed by the caller, after the password policy check.
    pub password_hash: &'a str,
    pub terms_version: Option<&'a str>,
    pub privacy_version: Option<&'a str>,
}

impl std::fmt::Debug for SignupInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupInput").finish_non_exhaustive()
    }
}

pub enum SignupRequest {
    /// A pending signup: email `bearer` as a link to `email`.
    Pending { bearer: String },
    /// The address already has a live account in this portal: tell its
    /// owner, send no link.
    AlreadyRegistered,
    /// The portal's policy doesn't admit this address (invite-only, a domain
    /// outside the allowlist, or no signup role). Nothing is sent.
    Refused,
}

impl std::fmt::Debug for SignupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupRequest").finish_non_exhaustive()
    }
}

/// The consent the caller gave must be exactly the portal's current versions.
pub fn consent_matches(policy: &AuthPolicy, terms: Option<&str>, privacy: Option<&str>) -> bool {
    policy.terms_version.as_deref() == terms && policy.privacy_version.as_deref() == privacy
}

pub async fn request(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    portal: &PortalDetail,
    policy: &AuthPolicy,
    input: &SignupInput<'_>,
) -> Result<SignupRequest, AppError> {
    if !policy.admits_new_account(input.email_lower) || policy.signup_role_ref.is_none() {
        return Ok(SignupRequest::Refused);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_user \
         WHERE webportal_ref = $1 AND lower(email) = $2 AND is_active IS NOT FALSE)",
    )
    .bind(portal.id)
    .bind(input.email_lower)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(SignupRequest::AlreadyRegistered);
    }
    // Only the newest link for an address works.
    sqlx::query(
        "UPDATE webportal_signup SET used_at = NOW() \
         WHERE webportal_id = $1 AND email_lower = $2 AND used_at IS NULL",
    )
    .bind(portal.id)
    .bind(input.email_lower)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let minted = secret::mint(pepper);
    sqlx::query(
        "INSERT INTO webportal_signup \
           (id, webportal_id, email_lower, name, password_hash, terms_version, privacy_version, \
            secret_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(minted.id)
    .bind(portal.id)
    .bind(input.email_lower)
    .bind(input.name)
    .bind(input.password_hash)
    .bind(input.terms_version)
    .bind(input.privacy_version)
    .bind(&minted.secret_hash)
    .bind(Utc::now() + Duration::seconds(SIGNUP_TTL_SECS))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(SignupRequest::Pending {
        bearer: minted.bearer,
    })
}

/// `(secret_hash, email_lower, name, password_hash, terms_version,
/// privacy_version)`.
type PendingRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

/// Consumes a signup link and creates the account. `None` for every miss
/// (malformed, unknown, used, expired, another portal), and when the account
/// can no longer be created (the policy changed, or the address was
/// registered some other way in the meantime).
pub async fn verify(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    portal: &PortalDetail,
    policy: &AuthPolicy,
    bearer: &str,
) -> Result<Option<Uuid>, AppError> {
    let Some((id, presented)) = secret::parse(bearer) else {
        secret::verify(pepper, bearer, None).await?;
        return Ok(None);
    };
    let row: Option<PendingRow> = sqlx::query_as(
        "SELECT secret_hash, email_lower, name, password_hash, terms_version, privacy_version \
         FROM webportal_signup \
         WHERE id = $1 AND webportal_id = $2 AND used_at IS NULL AND expires_at > NOW() \
         FOR UPDATE",
    )
    .bind(id)
    .bind(portal.id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let signup_id = id;
    let Some((hash, email_lower, name, password_hash, terms, privacy)) = row else {
        secret::verify(pepper, presented, None).await?;
        return Ok(None);
    };
    if !secret::verify(pepper, presented, Some(&hash)).await? {
        return Ok(None);
    }
    sqlx::query("UPDATE webportal_signup SET used_at = NOW() WHERE id = $1")
        .bind(signup_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;

    // The policy is read again at verification: a portal switched back to
    // invite-only since the request creates nothing.
    let Some(role_id) = policy.signup_role_ref else {
        return Ok(None);
    };
    if !policy.admits_new_account(&email_lower) {
        return Ok(None);
    }
    let Some(user_id) =
        provision::create_verified_user(conn, portal.id, &name, &email_lower, Some(&password_hash))
            .await?
    else {
        return Ok(None);
    };
    crate::roles::assign_role(conn, portal.id, user_id, role_id).await?;
    if terms.is_some() || privacy.is_some() {
        record_consent(
            conn,
            portal.id,
            user_id,
            terms.as_deref(),
            privacy.as_deref(),
        )
        .await?;
    }
    Ok(Some(user_id))
}

/// Records that `user_id` accepted these versions (G-11).
pub async fn record_consent(
    conn: &mut PgConnection,
    webportal_id: Uuid,
    user_id: Uuid,
    terms: Option<&str>,
    privacy: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO webportal_consent \
           (id, webportal_id, webportal_user_id, terms_version, privacy_version) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(webportal_id)
    .bind(user_id)
    .bind(terms)
    .bind(privacy)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Whether `user_id` has accepted the portal's current versions. Always true
/// when the portal requires none.
pub async fn has_current_consent(
    conn: &mut PgConnection,
    policy: &AuthPolicy,
    user_id: Uuid,
) -> Result<bool, AppError> {
    if !policy.requires_consent() {
        return Ok(true);
    }
    let latest: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT terms_version, privacy_version FROM webportal_consent \
         WHERE webportal_user_id = $1 ORDER BY accepted_at DESC, id DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(latest.is_some_and(|(t, p)| consent_matches(policy, t.as_deref(), p.as_deref())))
}
