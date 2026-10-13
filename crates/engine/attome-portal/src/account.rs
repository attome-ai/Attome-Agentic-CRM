//! A portal user managing their own account (plan G-11): change password,
//! list and end their sessions, request erasure. Business logic only; the
//! HTTP layer (`router::account`) writes the security event in the same
//! transaction and commits.
//!
//! Nothing here reads or writes `user_account`.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::PortalPrincipal;

pub enum PasswordChange {
    /// Changed: the credential epoch is now `epoch`, and every other session
    /// has ended. The caller re-mints the current session's access token.
    Changed { epoch: i32 },
    /// The current password is wrong, or the account has none (OIDC-only).
    WrongPassword,
}

impl std::fmt::Debug for PasswordChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordChange").finish_non_exhaustive()
    }
}

/// Changes the password after checking the current one. Bumps the epoch, so
/// every access token issued before dies, and revokes every refresh family
/// except the caller's own.
pub async fn change_password(
    conn: &mut PgConnection,
    principal: &PortalPrincipal,
    current_password: &str,
    new_hash: &str,
) -> Result<PasswordChange, AppError> {
    let stored: Option<Option<String>> = sqlx::query_scalar(
        "SELECT password_hash FROM webportal_credential \
         WHERE webportal_user_id = $1 FOR UPDATE",
    )
    .bind(principal.user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let ok = match stored.flatten() {
        Some(hash) => attome_auth::verify_password_async(current_password, &hash).await?,
        None => {
            attome_auth::password::verify_against_dummy_async(current_password).await?;
            false
        }
    };
    if !ok {
        return Ok(PasswordChange::WrongPassword);
    }
    let epoch: i32 = sqlx::query_scalar(
        "UPDATE webportal_credential SET password_hash = $2, password_changed_at = NOW(), \
           auth_epoch = auth_epoch + 1, updated_at = NOW() \
         WHERE webportal_user_id = $1 RETURNING auth_epoch",
    )
    .bind(principal.user_id)
    .bind(new_hash)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE webportal_refresh_token SET revoked_at = NOW() \
         WHERE webportal_user_id = $1 AND family_id <> $2 AND revoked_at IS NULL",
    )
    .bind(principal.user_id)
    .bind(principal.family_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(PasswordChange::Changed { epoch })
}

/// One signed-in session (a refresh family).
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalSessionItem {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub last_refreshed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The session this request was made with.
    pub current: bool,
}

/// One refresh-token family: (family id, started, last refreshed, expires).
type SessionRow = (Uuid, DateTime<Utc>, DateTime<Utc>, DateTime<Utc>);

pub async fn list_sessions(
    conn: &mut PgConnection,
    principal: &PortalPrincipal,
) -> Result<Vec<PortalSessionItem>, AppError> {
    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT family_id, MIN(created_at), MAX(created_at), MAX(family_expires_at) \
         FROM webportal_refresh_token \
         WHERE webportal_user_id = $1 \
         GROUP BY family_id \
         HAVING bool_and(revoked_at IS NULL) AND MAX(family_expires_at) > NOW() \
         ORDER BY MAX(created_at) DESC \
         LIMIT 100",
    )
    .bind(principal.user_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, started_at, last_refreshed_at, expires_at)| PortalSessionItem {
                id,
                started_at,
                last_refreshed_at,
                expires_at,
                current: id == principal.family_id,
            },
        )
        .collect())
}

/// Ends one of the caller's own sessions. `false` when `family_id` isn't a
/// live session of theirs (the caller answers 404 either way).
pub async fn end_session(
    conn: &mut PgConnection,
    principal: &PortalPrincipal,
    family_id: Uuid,
) -> Result<bool, AppError> {
    let ended = sqlx::query(
        "UPDATE webportal_refresh_token SET revoked_at = NOW() \
         WHERE family_id = $1 AND webportal_user_id = $2 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(principal.user_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(ended > 0)
}

/// Ends every session but the current one. Returns how many ended.
pub async fn end_other_sessions(
    conn: &mut PgConnection,
    principal: &PortalPrincipal,
) -> Result<u64, AppError> {
    let ended: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE webportal_refresh_token SET revoked_at = NOW() \
         WHERE webportal_user_id = $1 AND family_id <> $2 AND revoked_at IS NULL \
         RETURNING family_id",
    )
    .bind(principal.user_id)
    .bind(principal.family_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let mut families = ended;
    families.sort();
    families.dedup();
    Ok(families.len() as u64)
}

/// Opens an erasure request for staff (G-14 runs the erasure). Idempotent:
/// an already-open request is returned rather than duplicated.
pub async fn request_erasure(
    conn: &mut PgConnection,
    principal: &PortalPrincipal,
) -> Result<Uuid, AppError> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM webportal_erasure_request \
         WHERE webportal_user_id = $1 AND status = 'open'",
    )
    .bind(principal.user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO webportal_erasure_request (id, webportal_id, webportal_user_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(principal.webportal_id)
    .bind(principal.user_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // A concurrent request may have won the unique index; return whichever
    // is open now.
    sqlx::query_scalar(
        "SELECT id FROM webportal_erasure_request \
         WHERE webportal_user_id = $1 AND status = 'open'",
    )
    .bind(principal.user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}
