//! One-time codes (roadmap Z4-T7): a six-digit code sent to a person by
//! email, SMS or WhatsApp for one purpose (a second factor, a confirmation).
//! The code is random (OS generator), only its peppered HMAC is stored, it
//! lives [`CODE_TTL_SECS`] seconds, works once, and a code is refused after
//! [`MAX_ATTEMPTS`] wrong tries. Issuing a new code for a purpose discards
//! the person's earlier unused ones. Arabic-Indic digits are accepted.

use std::future::Future;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Duration, Utc};
use rand::Rng;
use uuid::Uuid;

use crate::apikey_hash::{PepperRing, VerifyOutcome, hash_peppered_secret, verify_peppered_secret};

/// How long a code lives.
pub const CODE_TTL_SECS: i64 = 60;
/// Wrong tries before a code is dead.
pub const MAX_ATTEMPTS: i32 = 5;

/// Where a code goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpChannel {
    Email,
    Sms,
    WhatsApp,
}

impl OtpChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
            Self::WhatsApp => "whatsapp",
        }
    }
}

/// Delivers a code; the caller owns the transport (email, SMS gateway).
pub trait OtpSender {
    fn send(
        &self,
        user_id: Uuid,
        channel: OtpChannel,
        code: &str,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}

/// What a verify found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpOutcome {
    /// The code was right; it is now used.
    Verified,
    /// Wrong, expired, used, missing or out of tries — one answer for all,
    /// so a caller cannot learn which.
    Refused,
}

/// The material the HMAC covers: a code is bound to its person and purpose.
fn material(user_id: Uuid, purpose: &str, code: &str) -> String {
    format!("{user_id}:{purpose}:{code}")
}

/// `presented` with Arabic-Indic and Eastern Arabic-Indic digits turned
/// into ASCII and everything but digits dropped.
pub fn normalize_digits(presented: &str) -> String {
    presented
        .chars()
        .filter_map(|c| match c {
            '0'..='9' => Some(c),
            '\u{0660}'..='\u{0669}' => char::from_digit(c as u32 - 0x0660, 10),
            '\u{06F0}'..='\u{06F9}' => char::from_digit(c as u32 - 0x06F0, 10),
            _ => None,
        })
        .collect()
}

/// Issues a code for `purpose` and sends it. Earlier unused codes of the
/// same purpose are discarded first.
pub async fn issue(
    db: &DbPool,
    ring: &PepperRing,
    sender: &impl OtpSender,
    user_id: Uuid,
    purpose: &str,
    channel: OtpChannel,
) -> Result<(), AppError> {
    let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
    let hash = hash_peppered_secret(ring, &material(user_id, purpose, &code));
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(
        "DELETE FROM one_time_code WHERE user_ref = $1 AND purpose = $2 AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(purpose)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO one_time_code (user_ref, purpose, channel, code_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(purpose)
    .bind(channel.as_str())
    .bind(&hash)
    .bind(Utc::now() + Duration::seconds(CODE_TTL_SECS))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    // Sent after the commit: a code that was never stored is never sent.
    sender.send(user_id, channel, &code).await
}

/// Checks `presented` against the person's open code for `purpose`.
pub async fn verify(
    db: &DbPool,
    ring: &PepperRing,
    user_id: Uuid,
    purpose: &str,
    presented: &str,
) -> Result<OtpOutcome, AppError> {
    let code = normalize_digits(presented);
    let row: Option<(Uuid, String, i32)> = sqlx::query_as(
        "SELECT id, code_hash, attempts FROM one_time_code \
          WHERE user_ref = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now() \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(purpose)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((id, hash, attempts)) = row else {
        return Ok(OtpOutcome::Refused);
    };
    if attempts >= MAX_ATTEMPTS {
        return Ok(OtpOutcome::Refused);
    }
    // The try counts before the compare, so racing guesses still spend it.
    let counted = sqlx::query(
        "UPDATE one_time_code SET attempts = attempts + 1 \
          WHERE id = $1 AND used_at IS NULL AND attempts < $2",
    )
    .bind(id)
    .bind(MAX_ATTEMPTS)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if counted == 0 {
        return Ok(OtpOutcome::Refused);
    }
    let matched = matches!(
        verify_peppered_secret(ring, &material(user_id, purpose, &code), &hash).await?,
        VerifyOutcome::Ok | VerifyOutcome::OkNeedsRehash
    );
    if !matched {
        return Ok(OtpOutcome::Refused);
    }
    let used =
        sqlx::query("UPDATE one_time_code SET used_at = now() WHERE id = $1 AND used_at IS NULL")
            .bind(id)
            .execute(db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
    Ok(if used == 1 {
        OtpOutcome::Verified
    } else {
        OtpOutcome::Refused
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arabic_indic_digits_normalize() {
        assert_eq!(normalize_digits("١٢٣٤٥٦"), "123456");
        assert_eq!(normalize_digits("۱۲۳ ۴۵۶"), "123456");
        assert_eq!(normalize_digits("12-34-56"), "123456");
    }
}
