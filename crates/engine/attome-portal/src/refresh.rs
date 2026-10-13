//! Rotating portal refresh tokens with family reuse detection (D-129's
//! semantics on the portal's own table, `webportal_refresh_token`).
//!
//! A login starts a **family**. Each refresh consumes the presented token and
//! issues the next one in the same family, with the family's absolute expiry
//! carried over. Presenting a token that was already used is **reuse**: some
//! copy of the chain leaked, so the whole family is revoked and every access
//! token naming it stops working (the portal authn checks the family on every
//! request).

use attome_auth::apikey_hash::PepperRing;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::secret;
use crate::session::{REFRESH_ABSOLUTE_SECS, REFRESH_IDLE_SECS};

pub struct Issued {
    pub family_id: Uuid,
    pub bearer: String,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued").finish_non_exhaustive()
    }
}

pub enum Rotation {
    Rotated {
        issued: Issued,
        user_id: Uuid,
    },
    /// An already-used token came back; its family is now revoked.
    Reused {
        family_id: Uuid,
        user_id: Uuid,
    },
    /// Unknown, malformed, wrong portal, expired or revoked.
    Invalid,
}

impl std::fmt::Debug for Rotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rotation").finish_non_exhaustive()
    }
}

async fn insert(
    conn: &mut PgConnection,
    ring: &PepperRing,
    family_id: Uuid,
    webportal_id: Uuid,
    user_id: Uuid,
    family_expires_at: DateTime<Utc>,
) -> Result<String, AppError> {
    let minted = secret::mint(ring);
    sqlx::query(
        "INSERT INTO webportal_refresh_token \
           (id, family_id, webportal_user_id, webportal_id, secret_hash, expires_at, family_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(minted.id)
    .bind(family_id)
    .bind(user_id)
    .bind(webportal_id)
    .bind(&minted.secret_hash)
    .bind(Utc::now() + Duration::seconds(REFRESH_IDLE_SECS))
    .bind(family_expires_at)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(minted.bearer)
}

/// Starts a new family (a login).
pub async fn issue_family(
    conn: &mut PgConnection,
    ring: &PepperRing,
    webportal_id: Uuid,
    user_id: Uuid,
) -> Result<Issued, AppError> {
    let family_id = Uuid::now_v7();
    let absolute = Utc::now() + Duration::seconds(REFRESH_ABSOLUTE_SECS);
    let bearer = insert(conn, ring, family_id, webportal_id, user_id, absolute).await?;
    Ok(Issued { family_id, bearer })
}

type TokenRow = (
    Uuid,
    Uuid,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// Consumes `bearer` for `webportal_id` and issues its successor.
pub async fn rotate(
    conn: &mut PgConnection,
    ring: &PepperRing,
    webportal_id: Uuid,
    bearer: &str,
) -> Result<Rotation, AppError> {
    let Some((id, presented)) = secret::parse(bearer) else {
        secret::verify(ring, bearer, None).await?;
        return Ok(Rotation::Invalid);
    };
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT family_id, webportal_user_id, secret_hash, expires_at, family_expires_at, \
                used_at, revoked_at \
         FROM webportal_refresh_token WHERE id = $1 AND webportal_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(webportal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((family_id, user_id, hash, expires_at, family_expires_at, used_at, revoked_at)) = row
    else {
        secret::verify(ring, presented, None).await?;
        return Ok(Rotation::Invalid);
    };
    if !secret::verify(ring, presented, Some(&hash)).await? {
        return Ok(Rotation::Invalid);
    }
    if revoked_at.is_some() {
        return Ok(Rotation::Invalid);
    }
    if used_at.is_some() {
        revoke_family(conn, family_id).await?;
        return Ok(Rotation::Reused { family_id, user_id });
    }
    let now = Utc::now();
    if expires_at <= now || family_expires_at <= now {
        return Ok(Rotation::Invalid);
    }

    sqlx::query("UPDATE webportal_refresh_token SET used_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let bearer = insert(
        conn,
        ring,
        family_id,
        webportal_id,
        user_id,
        family_expires_at,
    )
    .await?;
    Ok(Rotation::Rotated {
        issued: Issued { family_id, bearer },
        user_id,
    })
}

/// Ends a family: logout, reuse, or a password reset.
pub async fn revoke_family(conn: &mut PgConnection, family_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE webportal_refresh_token SET revoked_at = NOW() \
         WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Ends every family a user holds.
pub async fn revoke_user(conn: &mut PgConnection, user_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE webportal_refresh_token SET revoked_at = NOW() \
         WHERE webportal_user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// True while `family_id` belongs to `user_id`, has not been revoked, and has
/// not reached its absolute expiry. Checked on every authenticated request.
pub async fn family_is_live(
    conn: &mut PgConnection,
    family_id: Uuid,
    user_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_refresh_token \
         WHERE family_id = $1 AND webportal_user_id = $2 \
           AND revoked_at IS NULL AND family_expires_at > NOW())",
    )
    .bind(family_id)
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}
