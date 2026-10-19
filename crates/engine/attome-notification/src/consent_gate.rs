//! M24/D-428 — the notification engine's consent-enforcement seam. A
//! template can name a `consent_purpose_key` (`crate::seed`); any direct
//! (`recipient_user_ref`) email dispatch of that template requires the
//! recipient to hold an active `audit_consent` row for that purpose, checked
//! here before the send is enqueued (`dispatch::create_dispatch`).
//!
//! Deliberately a small, single-purpose function rather than a rule engine:
//! M45 Phase 2 (declarative policy rules) is expected to absorb this into a
//! general `consent(purpose)` condition once it ships — until then this is
//! the one hard-coded call site, kept narrow and easy to delete/replace
//! wholesale rather than threaded through several files.
//!
//! Queries `audit_consent`/`audit_consent_purpose` directly by table name rather
//! than depending on `attome-compliance` (which owns those entities' seed):
//! both are ordinary generic-CRUD entity tables once provisioned, and
//! reading a known table name by SQL — the same thing `dsr_admin.rs` does
//! against arbitrary registered entities — needs no crate dependency, only
//! the platform's D-005 entity-table convention. An xrm-to-xrm dependency
//! here for one SELECT would be the wrong-shaped boundary (guidelines §1:
//! don't create one to avoid a few related lines).

use attome_core::consent_rules::Decision;
use attome_types::AppError;
use sqlx::PgExecutor;

/// E27-T2: whether a marketing email may go, from the E27 ledger's decision
/// for the recipient and the older M24 consent row. The ledger decides
/// whenever it holds anything: a grant sends, and a withdrawal or an
/// account-wide opt-out stops it. Only a recipient the ledger knows
/// nothing about falls back to the M24 row, and with neither the email is
/// not sent (fails closed). Pure.
pub fn email_allowed(ledger: Decision, legacy_granted: bool) -> bool {
    match ledger {
        Decision::Allowed | Decision::Bypassed => true,
        Decision::NoConsent => legacy_granted,
        Decision::Withdrawn | Decision::AccountOptOut => false,
    }
}

/// True iff the most recent `audit_consent` row for
/// `(regarding_entity, regarding_id, purpose_key)` has `status = 'granted'`.
/// No row at all, or the most recent row being `withdrawn`/`expired`, is
/// "not consented" — fails closed, same posture this platform takes for any
/// other privacy/consent-shaped control (guidelines §7). Consent is
/// append-only (D-428), so "most recent by `created_at`" is the only correct
/// way to read current status — a later withdrawal row must always
/// supersede an earlier grant.
///
/// `regarding_id` is compared as text — the polymorphic reference's own
/// storage type (see `attome-compliance::consent_seed`'s doc comment); the
/// caller formats whatever identifier it holds (a UUID's `to_string()` for
/// the one caller today, `dispatch::create_dispatch`).
pub async fn has_active_consent<'e, E>(
    executor: E,
    regarding_entity: &str,
    regarding_id: &str,
    purpose_key: &str,
) -> Result<bool, AppError>
where
    E: PgExecutor<'e>,
{
    let status: Option<String> = sqlx::query_scalar(
        "SELECT c.status FROM audit_consent c \
         JOIN audit_consent_purpose p ON c.purpose_ref = p.id \
         WHERE p.key = $1 AND c.regarding_entity = $2 AND c.regarding_id = $3 \
         ORDER BY c.created_at DESC LIMIT 1",
    )
    .bind(purpose_key)
    .bind(regarding_entity)
    .bind(regarding_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?;

    Ok(status.as_deref() == Some("granted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_gate_sends_only_with_consent_and_never_after_a_withdrawal() {
        assert!(email_allowed(Decision::Allowed, false));
        assert!(email_allowed(Decision::Bypassed, false));
        assert!(
            email_allowed(Decision::NoConsent, true),
            "an older M24 grant still counts"
        );
        assert!(
            !email_allowed(Decision::NoConsent, false),
            "nothing at all fails closed"
        );
        assert!(
            !email_allowed(Decision::Withdrawn, true),
            "a ledger withdrawal wins"
        );
        assert!(!email_allowed(Decision::AccountOptOut, true));
    }
}
