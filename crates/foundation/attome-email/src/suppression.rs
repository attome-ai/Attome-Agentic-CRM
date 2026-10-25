//! `email_suppression` (migration `0062`, P-email-hardening) — addresses
//! that must never be sent to again. Checked by [`crate::sender::send`]
//! before every SMTP attempt (the one call path every producer of an email —
//! all three `PlatformJob::SendEmail` job producers plus
//! `xrm_notification::dispatch`'s direct, non-apalis send — shares), and
//! populated automatically on a permanent (5xx) SMTP rejection or manually
//! via the admin suppression endpoints (`xrm-server/src/email_admin.rs`).
//!
//! Z8-T3: a row names the stream it blocks. An unsubscribe blocks bulk mail
//! only (`stream = 'bulk'`); a hard bounce, a complaint or an
//! administrator's entry blocks everything (`stream = 'all'`), so a sign-in
//! code still reaches an address that left a campaign.

use attome_types::text::normalize_email;

use crate::message::EmailStream;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    HardBounce,
    Complaint,
    AdminManual,
    /// Z8-T3: the address left bulk mail; transactional mail still goes.
    Unsubscribe,
}

impl SuppressionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardBounce => "hard_bounce",
            Self::Complaint => "complaint",
            Self::AdminManual => "admin_manual",
            Self::Unsubscribe => "unsubscribe",
        }
    }

    /// The stream a suppression for this reason blocks: `bulk` for an
    /// unsubscribe, `all` otherwise.
    pub const fn blocks(self) -> &'static str {
        match self {
            Self::Unsubscribe => "bulk",
            Self::HardBounce | Self::Complaint | Self::AdminManual => "all",
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SuppressionRow {
    pub id: Uuid,
    pub email: String,
    pub reason: String,
    /// `all` or `bulk` (Z8-T3).
    pub stream: String,
    pub detail: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Checked before every SMTP send attempt. Normalizes `email` the same way
/// `suppress`/`unsuppress` do, so a differently-cased lookup can't miss an
/// existing suppression.
///
/// `E: PgExecutor` (BEM-12), not `&DbPool`: this is the workspace's **one**
/// suppression query, and a caller that has already opened a transaction must
/// be able to run it inside that transaction rather than on a second pool
/// connection. `xrm_notification::dispatch::is_email_suppressed` delegates
/// here for exactly that reason (its own copy was F8).
///
/// Answers for transactional mail (Z8-T3): only a row blocking every stream
/// counts. [`is_suppressed_for`] answers for either stream.
pub async fn is_suppressed<'e, E>(executor: E, email: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    is_suppressed_for(executor, email, EmailStream::Transactional).await
}

/// Z8-T3: whether mail of `stream` to `email` is suppressed. Bulk mail stops
/// at any live row; transactional mail only at one blocking `all`.
pub async fn is_suppressed_for<'e, E>(
    executor: E,
    email: &str,
    stream: EmailStream,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let normalized = normalize_email(email);
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM email_suppression \
          WHERE email = $1 AND is_deleted = false AND (stream = 'all' OR $2))",
    )
    .bind(normalized)
    .bind(stream == EmailStream::Bulk)
    .fetch_one(executor)
    .await
}

/// Upserts a suppression row — `ON CONFLICT` against the partial unique
/// index on `(email, stream) WHERE is_deleted = false` (the stream from
/// [`SuppressionReason::blocks`]), so re-suppressing an address
/// (e.g. a second hard bounce) updates the existing active row's
/// reason/detail rather than erroring.
pub async fn suppress(
    db: &attome_db::DbPool,
    email: &str,
    reason: SuppressionReason,
    detail: Option<&str>,
    created_by: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let normalized = normalize_email(email);
    sqlx::query(
        "INSERT INTO email_suppression (email, reason, detail, created_by, stream) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (email, stream) WHERE is_deleted = false \
         DO UPDATE SET reason = EXCLUDED.reason, detail = EXCLUDED.detail, \
                       updated_at = now(), row_version = email_suppression.row_version + 1",
    )
    .bind(normalized)
    .bind(reason.as_str())
    .bind(detail)
    .bind(created_by)
    .bind(reason.blocks())
    .execute(db)
    .await?;
    // BEM-10 — the suppression-spike alert's input. An upsert that refreshes an
    // existing row counts too: a second hard bounce is still a signal.
    metrics::counter!("email_suppression_added_total", "reason" => reason.as_str()).increment(1);
    Ok(())
}

/// Soft-deletes a suppression row by id. `Ok(true)` if a row was actually
/// affected (it existed and wasn't already removed).
pub async fn unsuppress(db: &attome_db::DbPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE email_suppression SET is_deleted = true, updated_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// One window of live suppressions, newest first. `offset` and `page_size`
/// are the caller's to clamp (`attome_types::PageWindow`).
pub async fn list_paginated(
    db: &attome_db::DbPool,
    offset: i64,
    page_size: i64,
) -> Result<Vec<SuppressionRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, email, reason, stream, detail, created_by, created_at \
         FROM email_suppression WHERE is_deleted = false \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(db)
    .await
}

pub async fn count(db: &attome_db::DbPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM email_suppression WHERE is_deleted = false")
        .fetch_one(db)
        .await
}
