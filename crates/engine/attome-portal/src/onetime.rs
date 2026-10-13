//! Single-use invitation, password-reset and email-add (D-780) tokens
//! (`webportal_token`). Issuing a new token of a kind voids the user's
//! older unused ones of that kind, so only the latest link works. Every miss
//! (malformed, unknown, wrong portal, wrong kind, used, expired) is the same
//! `None`.

use attome_auth::apikey_hash::PepperRing;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::secret;

pub const INVITATION_TTL_SECS: i64 = 7 * 24 * 60 * 60;
pub const RESET_TTL_SECS: i64 = 60 * 60;
pub const EMAIL_ADD_TTL_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Invitation,
    Reset,
    /// D-780: carries the address being added ([`issue_email_add`]).
    EmailAdd,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Invitation => "invitation",
            Self::Reset => "reset",
            Self::EmailAdd => "email_add",
        }
    }

    fn ttl(self) -> Duration {
        Duration::seconds(match self {
            Self::Invitation => INVITATION_TTL_SECS,
            Self::Reset => RESET_TTL_SECS,
            Self::EmailAdd => EMAIL_ADD_TTL_SECS,
        })
    }
}

pub struct IssuedToken {
    pub bearer: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedToken").finish_non_exhaustive()
    }
}

pub async fn issue(
    conn: &mut PgConnection,
    ring: &PepperRing,
    kind: Kind,
    webportal_id: Uuid,
    user_id: Uuid,
) -> Result<IssuedToken, AppError> {
    issue_inner(conn, ring, kind, webportal_id, user_id, None).await
}

/// D-780: a link that adds `email_lower` to the account once opened. The
/// address rides on the token, not the account, until then.
pub async fn issue_email_add(
    conn: &mut PgConnection,
    ring: &PepperRing,
    webportal_id: Uuid,
    user_id: Uuid,
    email_lower: &str,
) -> Result<IssuedToken, AppError> {
    issue_inner(
        conn,
        ring,
        Kind::EmailAdd,
        webportal_id,
        user_id,
        Some(email_lower),
    )
    .await
}

async fn issue_inner(
    conn: &mut PgConnection,
    ring: &PepperRing,
    kind: Kind,
    webportal_id: Uuid,
    user_id: Uuid,
    email: Option<&str>,
) -> Result<IssuedToken, AppError> {
    sqlx::query(
        "UPDATE webportal_token SET used_at = NOW() \
         WHERE webportal_user_id = $1 AND kind = $2 AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(kind.as_str())
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let minted = secret::mint(ring);
    let expires_at = Utc::now() + kind.ttl();
    sqlx::query(
        "INSERT INTO webportal_token \
           (id, kind, webportal_user_id, webportal_id, secret_hash, expires_at, email) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(minted.id)
    .bind(kind.as_str())
    .bind(user_id)
    .bind(webportal_id)
    .bind(&minted.secret_hash)
    .bind(expires_at)
    .bind(email)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(IssuedToken {
        bearer: minted.bearer,
        expires_at,
    })
}

/// Consumes a presented token. `Some(user_id)` only for a live token of this
/// kind issued for this portal.
pub async fn consume(
    conn: &mut PgConnection,
    ring: &PepperRing,
    kind: Kind,
    webportal_id: Uuid,
    bearer: &str,
) -> Result<Option<Uuid>, AppError> {
    Ok(consume_inner(conn, ring, kind, webportal_id, bearer)
        .await?
        .map(|(user_id, _)| user_id))
}

/// D-780: consumes an email-add link: the account and the address it adds.
pub async fn consume_email_add(
    conn: &mut PgConnection,
    ring: &PepperRing,
    webportal_id: Uuid,
    bearer: &str,
) -> Result<Option<(Uuid, String)>, AppError> {
    Ok(
        consume_inner(conn, ring, Kind::EmailAdd, webportal_id, bearer)
            .await?
            .and_then(|(user_id, email)| email.map(|e| (user_id, e))),
    )
}

/// D-780: the address a live email-add link of the account would add.
pub async fn pending_email(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<Option<String>, AppError> {
    let email: Option<Option<String>> = sqlx::query_scalar(
        "SELECT email FROM webportal_token \
         WHERE webportal_user_id = $1 AND kind = 'email_add' AND used_at IS NULL \
           AND expires_at > NOW() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(email.flatten())
}

async fn consume_inner(
    conn: &mut PgConnection,
    ring: &PepperRing,
    kind: Kind,
    webportal_id: Uuid,
    bearer: &str,
) -> Result<Option<(Uuid, Option<String>)>, AppError> {
    let Some((id, presented)) = secret::parse(bearer) else {
        secret::verify(ring, bearer, None).await?;
        return Ok(None);
    };
    let row: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT webportal_user_id, secret_hash, email FROM webportal_token \
         WHERE id = $1 AND kind = $2 AND webportal_id = $3 \
           AND used_at IS NULL AND expires_at > NOW() \
         FOR UPDATE",
    )
    .bind(id)
    .bind(kind.as_str())
    .bind(webportal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((user_id, hash, email)) = row else {
        secret::verify(ring, presented, None).await?;
        return Ok(None);
    };
    if !secret::verify(ring, presented, Some(&hash)).await? {
        return Ok(None);
    }
    sqlx::query("UPDATE webportal_token SET used_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(Some((user_id, email)))
}
