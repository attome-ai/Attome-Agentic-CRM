//! The marketing consent rule (roadmap E27-T1/E27-T2), shared by every
//! engine that sends: `attome-compliance` owns the ledger (`consent_event`,
//! `consent_current`) and its routes, and senders such as
//! `attome-notification` — which may not depend on `attome-compliance` —
//! ask the same rule here before a marketing message goes out.
//!
//! [`decide`]: a send is allowed only with a grant in force for the purpose
//! on that channel (or on `any`), and no withdrawal on the account; anything
//! missing refuses. A transactional message bypasses consent only with a
//! declared reason.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use attome_types::AppError;

/// One state row of `consent_current`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentState {
    pub channel: String,
    pub granted: bool,
    pub at: DateTime<Utc>,
}

/// The gate's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    /// Transactional: sent without consent for the declared reason.
    Bypassed,
    NoConsent,
    Withdrawn,
    AccountOptOut,
}

impl Decision {
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::Bypassed)
    }
}

/// The latest state that applies to `channel`: the channel's own row when
/// it is newer than the `any` row, else the `any` row.
fn applicable(states: &[ConsentState], channel: &str) -> Option<bool> {
    states
        .iter()
        .filter(|s| s.channel == channel || s.channel == "any")
        .max_by_key(|s| (s.at, s.channel != "any"))
        .map(|s| s.granted)
}

/// Whether a message on `channel` may go to the person. `person` and
/// `account` are the current rows for the purpose; `transactional` is the
/// declared reason of a message that needs no consent. Pure.
pub fn decide(
    person: &[ConsentState],
    account: &[ConsentState],
    channel: &str,
    transactional: Option<&str>,
) -> Decision {
    if transactional.is_some_and(|reason| !reason.trim().is_empty()) {
        return Decision::Bypassed;
    }
    if applicable(account, channel) == Some(false) {
        return Decision::AccountOptOut;
    }
    match applicable(person, channel) {
        Some(true) => Decision::Allowed,
        Some(false) => Decision::Withdrawn,
        None => Decision::NoConsent,
    }
}

/// The current rows of one subject for a purpose.
pub async fn current(
    conn: &mut sqlx::PgConnection,
    subject_entity: &str,
    subject_id: Uuid,
    purpose_key: &str,
) -> Result<Vec<ConsentState>, AppError> {
    let rows: Vec<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT channel, status, updated_at FROM consent_current \
         WHERE subject_entity = $1 AND subject_id = $2 AND purpose_key = $3",
    )
    .bind(subject_entity)
    .bind(subject_id)
    .bind(purpose_key)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(channel, status, at)| ConsentState {
            channel,
            granted: status == "granted",
            at,
        })
        .collect())
}

/// The gate for one send: reads the person's and the account's rows and
/// applies [`decide`].
pub async fn gate(
    conn: &mut sqlx::PgConnection,
    person: (&str, Uuid),
    account: Option<Uuid>,
    purpose_key: &str,
    channel: &str,
    transactional: Option<&str>,
) -> Result<Decision, AppError> {
    if transactional.is_some_and(|r| !r.trim().is_empty()) {
        return Ok(Decision::Bypassed);
    }
    let person_rows = current(&mut *conn, person.0, person.1, purpose_key).await?;
    let account_rows = match account {
        Some(account) => current(&mut *conn, "account", account, purpose_key).await?,
        None => Vec::new(),
    };
    Ok(decide(&person_rows, &account_rows, channel, None))
}
