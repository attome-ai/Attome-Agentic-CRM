//! `email_delivery` (migration `0062`, P-email-hardening) — one row per
//! attempted send from the three account-lifecycle `PlatformJob::SendEmail`
//! producers (registration verification, password reset, admin invitation)
//! plus (M51 Phase 1) `xrm_notification::dispatch::create_dispatch`'s direct
//! per-recipient email channel. Written in the same transaction as the
//! durable job enqueue (same crash-safety shape `xrm_server::bulk::enqueue`
//! uses for `xrm_automation_bulk_operation`), so a crash between the two
//! can't create an untracked send.
//!
//! Deliberately never stores the rendered `text_body`/`html_body` — see this
//! module's home migration's header comment for why (a live, single-use
//! token URL). The notification engine's own dispatch row already carries its
//! rendered content (`xrm_notification_dispatch.body_html`/`body_text`), so
//! this row's nullable `dispatch_ref` (migration `0141`) is purely a
//! traceability pointer back to it, not a second copy of the payload — the
//! dispatch row itself remains F163's independent attempts/status mechanism;
//! this table only tracks the SMTP send/suppression outcome for the `email`
//! channel specifically.

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailDeliveryKind {
    EmailVerification,
    PasswordReset,
    Invitation,
    Generic,
}

impl EmailDeliveryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
            Self::Invitation => "invitation",
            Self::Generic => "generic",
        }
    }
}

impl std::str::FromStr for EmailDeliveryKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "email_verification" => Ok(Self::EmailVerification),
            "password_reset" => Ok(Self::PasswordReset),
            "invitation" => Ok(Self::Invitation),
            "generic" => Ok(Self::Generic),
            _ => {
                Err("kind must be one of: email_verification, password_reset, invitation, generic")
            }
        }
    }
}

/// BEM-4 (attome-email plan §4.3) — the ledger's status vocabulary, replacing
/// the free `&str` every transition used to take.
///
/// The two terminal members a 5xx-free failure can reach are deliberately
/// distinct: `Failed` is "the relay answered, and the answer was no",
/// `Suppressed` is "the recipient is on the suppression list", and
/// `Unknown` (BEM-17) is "the relay may or may not have accepted it" — the one
/// state an operator must be paged about, and the one a resend must never
/// replay blind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Queued,
    Sent,
    Failed,
    Suppressed,
    Unknown,
}

impl DeliveryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Suppressed => "suppressed",
            Self::Unknown => "unknown",
        }
    }

    /// True for the three states no further attempt may leave (BEM-17):
    /// `queued` is the only non-terminal one.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued)
    }
}

impl AsRef<str> for DeliveryStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::str::FromStr for DeliveryStatus {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "sent" => Ok(Self::Sent),
            "failed" => Ok(Self::Failed),
            "suppressed" => Ok(Self::Suppressed),
            "unknown" => Ok(Self::Unknown),
            _ => Err(
                "status must be one of: queued, sent, failed, suppressed, unknown (BEM-17 added \
                 unknown; migration 0499 widened 0062's CHECK)",
            ),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailDeliveryRow {
    pub id: Uuid,
    pub kind: String,
    pub recipient: String,
    pub subject: String,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub user_ref: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub dispatch_ref: Option<Uuid>,
    pub sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Inserts the tracking row with a caller-chosen id (so the same id can be
/// embedded in the `EmailMessage.delivery_id` enqueued alongside it in the
/// same transaction) and `status='queued'`. `dispatch_ref` is an opaque,
/// unconstrained pointer back to the `xrm_notification_dispatch` row that
/// produced this send (M51 Phase 1) — `None` for the three account-lifecycle
/// producers, which have no dispatch row. Deliberately no DB-level FK (same
/// loose-coupling convention as `user_ref` above, which also points at a
/// table this crate has no schema dependency on) so `attome-email` stays
/// XRM-agnostic (guidelines §1): it stores and returns the id, never
/// interprets it.
#[allow(clippy::too_many_arguments)]
pub async fn record_queued_in_tx(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
    kind: EmailDeliveryKind,
    recipient: &str,
    subject: &str,
    user_ref: Option<Uuid>,
    created_by: Option<Uuid>,
    dispatch_ref: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO email_delivery \
             (id, kind, recipient, subject, user_ref, created_by, dispatch_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(kind.as_str())
    .bind(attome_types::text::normalize_email(recipient))
    .bind(subject)
    .bind(user_ref)
    .bind(created_by)
    .bind(dispatch_ref)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Guarded on `status = 'queued'` (BEM-4): `Ok(false)` means the row was
/// already resolved — a duplicate apalis execution, or a resend — and the
/// caller must treat that as "already done", not as a failure to record.
pub async fn mark_sent(db: &attome_db::DbPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE email_delivery SET status = 'sent', sent_at = now(), updated_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND status = 'queued'",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Records a transient-failure attempt without closing out the row —
/// apalis's own retry loop will call `send` again, and each subsequent
/// attempt calls this again until either `mark_sent` or `mark_terminal`.
/// Guarded on `queued` too, so an already-terminal row can never gain an
/// attempt count.
pub async fn mark_transient_attempt(
    db: &attome_db::DbPool,
    id: Uuid,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE email_delivery SET attempts = attempts + 1, last_error = $2, \
             updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND status = 'queued'",
    )
    .bind(id)
    .bind(error)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Closes out the row as `status` — `failed`, `suppressed`, or (BEM-17)
/// `unknown` — no further attempt will follow (the job handler returns
/// `Ok(())` in the first two cases so apalis marks the underlying job `Done`,
/// not `Killed`; see `jobs.rs`'s `SendEmail` arm).
///
/// `status` is `impl AsRef<str>` rather than the [`DeliveryStatus`] enum
/// because `crates/server/src/jobs.rs` — another lane's file this wave —
/// passes a string literal; the enum is the intended call, and the
/// `AsRef` bound is the one shape that accepts both without a shim. An
/// unrecognized value is rejected here rather than reaching the CHECK
/// constraint, so a typo cannot look like a new state.
///
/// `Ok(false)` means the row was already resolved (BEM-4).
pub async fn mark_terminal(
    db: &attome_db::DbPool,
    id: Uuid,
    status: impl AsRef<str>,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let status = status.as_ref();
    if status.parse::<DeliveryStatus>().is_err() {
        return Err(sqlx::Error::Decode(
            format!("unknown delivery status {status:?}").into(),
        ));
    }
    let result = sqlx::query(
        "UPDATE email_delivery SET status = $2, attempts = attempts + 1, last_error = $3, \
             updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND status = 'queued'",
    )
    .bind(id)
    .bind(status)
    .bind(error)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_by_id(
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<Option<EmailDeliveryRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, kind, recipient, subject, status, attempts, last_error, user_ref, \
                created_by, dispatch_ref, sent_at, created_at \
         FROM email_delivery WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// One window of deliveries, newest first. `offset` and `page_size` are the
/// caller's to clamp (`attome_types::PageWindow`).
pub async fn list_paginated(
    db: &attome_db::DbPool,
    status: Option<&str>,
    kind: Option<&str>,
    recipient: Option<&str>,
    offset: i64,
    page_size: i64,
) -> Result<Vec<EmailDeliveryRow>, sqlx::Error> {
    let recipient_normalized = recipient.map(attome_types::text::normalize_email);
    sqlx::query_as(
        "SELECT id, kind, recipient, subject, status, attempts, last_error, user_ref, \
                created_by, dispatch_ref, sent_at, created_at \
         FROM email_delivery \
         WHERE ($1::text IS NULL OR status = $1) \
           AND ($2::text IS NULL OR kind = $2) \
           AND ($3::text IS NULL OR recipient = $3) \
         ORDER BY created_at DESC LIMIT $4 OFFSET $5",
    )
    .bind(status)
    .bind(kind)
    .bind(recipient_normalized)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db)
    .await
}

pub async fn count(
    db: &attome_db::DbPool,
    status: Option<&str>,
    kind: Option<&str>,
    recipient: Option<&str>,
) -> Result<i64, sqlx::Error> {
    let recipient_normalized = recipient.map(attome_types::text::normalize_email);
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_delivery \
         WHERE ($1::text IS NULL OR status = $1) \
           AND ($2::text IS NULL OR kind = $2) \
           AND ($3::text IS NULL OR recipient = $3)",
    )
    .bind(status)
    .bind(kind)
    .bind(recipient_normalized)
    .fetch_one(db)
    .await
}
