//! Marketing consent ledger (roadmap E27-T1): every grant and withdrawal is
//! an insert-only `consent_event` with its proof (where it came from, the
//! form or message, the text shown), and `consent_current` keeps the latest
//! state per subject, purpose and channel, written in the same transaction
//! as the event. A subject is a contact or lead, or a whole account: an
//! account-wide withdrawal stops every person of that account.
//!
//! [`decide`] is the gate's rule (E27-T2): a send is allowed only with a
//! grant in force for the purpose on that channel (or on `any`), and no
//! withdrawal on the account; anything missing refuses. A transactional
//! message bypasses consent only with a declared reason.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The channels consent is given for.
pub const CHANNELS: &[&str] = &["any", "email", "sms", "whatsapp", "phone", "ads"];

// E27-T2: the rule itself lives in attome-core, so senders that may not
// depend on this crate apply the same one.
pub use attome_core::consent_rules::{ConsentState, Decision, decide};

/// A grant or withdrawal to record.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentChange {
    pub subject_entity: String,
    pub subject_id: Uuid,
    pub purpose_key: String,
    pub channel: String,
    pub grant: bool,
    pub source: String,
    pub proof: serde_json::Value,
    pub occurred_at: DateTime<Utc>,
    pub recorded_by: Option<Uuid>,
}

/// Records one change in the caller's transaction: the event, and the
/// current state when the event is not older than the state already held
/// (a late-arriving older event stays in the log only).
pub async fn record(tx: &mut attome_db::Tx<'_>, change: &ConsentChange) -> Result<Uuid, AppError> {
    if !CHANNELS.contains(&change.channel.as_str()) {
        return Err(AppError::Validation(format!(
            "unknown consent channel {:?}",
            change.channel
        )));
    }
    if change.purpose_key.trim().is_empty() {
        return Err(AppError::Validation("purpose_key is required".into()));
    }
    let event: Uuid = sqlx::query_scalar(
        "INSERT INTO consent_event \
           (subject_entity, subject_id, purpose_key, channel, action, source, proof, \
            occurred_at, recorded_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&change.subject_entity)
    .bind(change.subject_id)
    .bind(change.purpose_key.trim())
    .bind(&change.channel)
    .bind(if change.grant { "grant" } else { "withdraw" })
    .bind(&change.source)
    .bind(&change.proof)
    .bind(change.occurred_at)
    .bind(change.recorded_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO consent_current \
           (subject_entity, subject_id, purpose_key, channel, status, event_id, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (subject_entity, subject_id, purpose_key, channel) DO UPDATE \
           SET status = EXCLUDED.status, event_id = EXCLUDED.event_id, \
               updated_at = EXCLUDED.updated_at \
         WHERE consent_current.updated_at <= EXCLUDED.updated_at",
    )
    .bind(&change.subject_entity)
    .bind(change.subject_id)
    .bind(change.purpose_key.trim())
    .bind(&change.channel)
    .bind(if change.grant { "granted" } else { "withdrawn" })
    .bind(event)
    .bind(change.occurred_at)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(event)
}

/// The current rows of one subject for a purpose.
pub async fn current(
    db: &attome_db::DbPool,
    subject_entity: &str,
    subject_id: Uuid,
    purpose_key: &str,
) -> Result<Vec<ConsentState>, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    attome_core::consent_rules::current(&mut conn, subject_entity, subject_id, purpose_key).await
}

/// The gate for one send: reads the person's and the account's rows and
/// applies [`decide`].
pub async fn gate(
    db: &attome_db::DbPool,
    person: (&str, Uuid),
    account: Option<Uuid>,
    purpose_key: &str,
    channel: &str,
    transactional: Option<&str>,
) -> Result<Decision, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    attome_core::consent_rules::gate(
        &mut conn,
        person,
        account,
        purpose_key,
        channel,
        transactional,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, 9, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn state(channel: &str, granted: bool, day: u32) -> ConsentState {
        ConsentState {
            channel: channel.into(),
            granted,
            at: at(day),
        }
    }

    #[test]
    fn missing_consent_fails_closed() {
        assert_eq!(decide(&[], &[], "email", None), Decision::NoConsent);
        assert!(!Decision::NoConsent.allowed());
    }

    #[test]
    fn a_channel_grant_and_the_any_row() {
        let person = [state("any", true, 1), state("sms", false, 5)];
        assert_eq!(decide(&person, &[], "email", None), Decision::Allowed);
        assert_eq!(decide(&person, &[], "sms", None), Decision::Withdrawn);
        let later_any = [state("sms", false, 5), state("any", true, 9)];
        assert_eq!(
            decide(&later_any, &[], "sms", None),
            Decision::Allowed,
            "a newer grant for every channel replaces the older sms withdrawal"
        );
    }

    #[test]
    fn an_account_opt_out_beats_the_person() {
        let person = [state("email", true, 3)];
        let account = [state("any", false, 2)];
        assert_eq!(
            decide(&person, &account, "email", None),
            Decision::AccountOptOut
        );
    }

    #[test]
    fn transactional_needs_a_reason() {
        assert_eq!(
            decide(&[], &[], "email", Some("invoice")),
            Decision::Bypassed
        );
        assert_eq!(decide(&[], &[], "email", Some("  ")), Decision::NoConsent);
    }
}
