//! Per-portal OpenID Connect sign-in (D-588 item 3).
//!
//! The protocol work (PKCE, nonce, discovery, JWKS, signature and claims) is
//! `attome_auth::oidc`'s, unchanged. This module adds what is portal-specific:
//!
//! - **Binding.** `attome_auth::oidc`'s single-use state doesn't record which
//!   portal started the flow, so this module keeps its own single-use binding
//!   (`attome-portal:oidc-bind:{state}` → portal and provider) and the callback
//!   refuses a state bound to anything else.
//! - **Linking.** An identity already linked in `webportal_identity` signs
//!   in to its account. An unlinked identity whose verified email matches an
//!   existing account is **not** linked automatically: the user must prove the
//!   account (its password, and its TOTP code when enrolled) through a
//!   single-use pending link. An unlinked identity with no account creates one
//!   only when the portal's signup policy admits the address.
//! - **MFA.** An account with TOTP enabled still needs its code after an OIDC
//!   sign-in, through the same pending mechanism.
//!
//! Pending steps live in Redis for [`PENDING_TTL_SECS`] and are single-use
//! (`GETDEL`). Redis failures fail closed.

use std::time::Duration;

use attome_cache::Store;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::policy::AuthPolicy;
use crate::provision::{self, PortalDetail};

pub const PENDING_TTL_SECS: i64 = 300;
const BIND_TTL_SECS: i64 = 600;
/// Bounds each Redis call on the portal OIDC bind/pending state. A
/// request-path call, but kept at its shipped 500 ms rather than
/// `attome_cache::timeouts::REQUEST_PATH` (300 ms): the value is deliberately
/// unchanged by the timeout sweep (cleanup 3.3), and numerically matching
/// `timeouts::BACKGROUND` would misstate the call's class.
const REDIS_TIMEOUT: Duration = Duration::from_millis(500);

fn bind_key(state_id: &str) -> String {
    format!("attome-portal:oidc-bind:{state_id}")
}

fn pending_key(id: Uuid) -> String {
    format!("attome-portal:oidc-pending:{id}")
}

#[derive(Serialize, Deserialize)]
struct Binding {
    webportal_id: Uuid,
    provider: String,
}

/// The `state` query parameter of an authorization URL.
pub fn state_param(authorize_url: &str) -> Option<String> {
    let query = authorize_url.split_once('?')?.1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("state="))
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

/// Records that `state_id` was started by `portal` for `provider`.
pub async fn bind(
    redis: &Store,
    state_id: &str,
    webportal_id: Uuid,
    provider: &str,
) -> Result<(), AppError> {
    let value = serde_json::to_string(&Binding {
        webportal_id,
        provider: provider.to_owned(),
    })
    .map_err(AppError::internal)?;
    tokio::time::timeout(
        REDIS_TIMEOUT,
        redis.set(
            &bind_key(state_id),
            &value,
            Some(std::time::Duration::from_secs(BIND_TTL_SECS as u64)),
        ),
    )
    .await
    .map_err(|_| AppError::internal("portal oidc bind timed out"))??;
    Ok(())
}

/// Consumes the binding for `state_id`; true only if it names this portal and
/// provider. A missing binding, a Redis error or a mismatch is false.
pub async fn take_binding(
    redis: &Store,
    state_id: &str,
    webportal_id: Uuid,
    provider: &str,
) -> bool {
    let raw = tokio::time::timeout(REDIS_TIMEOUT, redis.getdel(&bind_key(state_id))).await;
    let Ok(Ok(Some(raw))) = raw else {
        return false;
    };
    serde_json::from_str::<Binding>(&raw)
        .is_ok_and(|b| b.webportal_id == webportal_id && b.provider == provider)
}

/// What the callback does next.
pub enum Resolution {
    /// Sign in to this account now.
    SignIn { user_id: Uuid },
    /// The account has TOTP enabled: finish with a code
    /// ([`PendingKind::Mfa`]).
    NeedsMfa { pending: Uuid },
    /// The identity is new but its email has an account: prove the account to
    /// link it ([`PendingKind::Link`]).
    NeedsLink { pending: Uuid },
    /// No account, and the portal's policy doesn't create one; or the account
    /// isn't active.
    Refused,
}

impl std::fmt::Debug for Resolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolution").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingKind {
    Link,
    Mfa,
}

#[derive(Serialize, Deserialize)]
pub struct Pending {
    pub kind: PendingKind,
    pub webportal_id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending").finish_non_exhaustive()
    }
}

pub async fn store_pending(redis: &Store, pending: &Pending) -> Result<Uuid, AppError> {
    let id = Uuid::new_v4();
    let value = serde_json::to_string(pending).map_err(AppError::internal)?;
    tokio::time::timeout(
        REDIS_TIMEOUT,
        redis.set(
            &pending_key(id),
            &value,
            Some(std::time::Duration::from_secs(PENDING_TTL_SECS as u64)),
        ),
    )
    .await
    .map_err(|_| AppError::internal("portal oidc pending write timed out"))??;
    Ok(id)
}

/// Consumes a pending step of `kind` for `webportal_id`. `None` for every
/// miss (unknown, used, expired, another portal or kind).
pub async fn take_pending(
    redis: &Store,
    id: Uuid,
    kind: PendingKind,
    webportal_id: Uuid,
) -> Result<Option<Pending>, AppError> {
    let raw = tokio::time::timeout(REDIS_TIMEOUT, redis.getdel(&pending_key(id)))
        .await
        .map_err(|_| AppError::internal("portal oidc pending read timed out"))??;
    Ok(raw
        .and_then(|r| serde_json::from_str::<Pending>(&r).ok())
        .filter(|p| p.kind == kind && p.webportal_id == webportal_id))
}

/// The linked account for `(issuer, subject)` in this portal, if any.
async fn linked_user(
    conn: &mut PgConnection,
    webportal_id: Uuid,
    issuer: &str,
    subject: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT webportal_user_id FROM webportal_identity \
         WHERE webportal_id = $1 AND issuer = $2 AND subject = $3",
    )
    .bind(webportal_id)
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// `(status, mfa_enabled)` of a live account of this portal.
async fn account_state(
    conn: &mut PgConnection,
    webportal_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(String, bool)>, AppError> {
    sqlx::query_as(
        "SELECT u.status, c.mfa_enabled FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE u.id = $1 AND u.webportal_ref = $2 AND u.is_active IS NOT FALSE",
    )
    .bind(user_id)
    .bind(webportal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Links `(issuer, subject)` to `user_id` in this portal.
pub async fn link_identity(conn: &mut PgConnection, pending: &Pending) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO webportal_identity \
           (id, webportal_id, webportal_user_id, provider_key, issuer, subject) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (webportal_id, issuer, subject) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(pending.webportal_id)
    .bind(pending.user_id)
    .bind(&pending.provider)
    .bind(&pending.issuer)
    .bind(&pending.subject)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Decides what a verified identity leads to.
#[allow(clippy::too_many_arguments)]
pub async fn resolve(
    conn: &mut PgConnection,
    redis: &Store,
    portal: &PortalDetail,
    policy: &AuthPolicy,
    provider: &str,
    issuer: &str,
    subject: &str,
    email: &str,
) -> Result<Resolution, AppError> {
    let email_lower = email.trim().to_lowercase();
    let pending_for = |kind, user_id| Pending {
        kind,
        webportal_id: portal.id,
        user_id,
        provider: provider.to_owned(),
        issuer: issuer.to_owned(),
        subject: subject.to_owned(),
    };

    if let Some(user_id) = linked_user(conn, portal.id, issuer, subject).await? {
        return Ok(match account_state(conn, portal.id, user_id).await? {
            Some((status, _)) if status != "active" => Resolution::Refused,
            None => Resolution::Refused,
            Some((_, true)) => Resolution::NeedsMfa {
                pending: store_pending(redis, &pending_for(PendingKind::Mfa, user_id)).await?,
            },
            Some((_, false)) => Resolution::SignIn { user_id },
        });
    }

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM webportal_user \
         WHERE webportal_ref = $1 AND lower(email) = $2 AND is_active IS NOT FALSE",
    )
    .bind(portal.id)
    .bind(&email_lower)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if let Some(user_id) = existing {
        return Ok(Resolution::NeedsLink {
            pending: store_pending(redis, &pending_for(PendingKind::Link, user_id)).await?,
        });
    }

    let (Some(role_id), true) = (
        policy.signup_role_ref,
        policy.admits_new_account(&email_lower),
    ) else {
        return Ok(Resolution::Refused);
    };
    let name = email_lower
        .split_once('@')
        .map(|(local, _)| local.to_owned())
        .unwrap_or_else(|| email_lower.clone());
    let Some(user_id) =
        provision::create_verified_user(conn, portal.id, &name, &email_lower, None).await?
    else {
        return Ok(Resolution::Refused);
    };
    crate::roles::assign_role(conn, portal.id, user_id, role_id).await?;
    link_identity(conn, &pending_for(PendingKind::Link, user_id)).await?;
    Ok(Resolution::SignIn { user_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_parameter_is_read_from_the_authorization_url() {
        let url =
            "https://idp.example/authorize?response_type=code&client_id=c&state=abc123&nonce=n";
        assert_eq!(state_param(url).as_deref(), Some("abc123"));
        assert_eq!(state_param("https://idp.example/authorize?x=1"), None);
        assert_eq!(state_param("https://idp.example/authorize?state="), None);
    }
}
