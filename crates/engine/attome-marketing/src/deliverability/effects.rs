//! Bounce and complaint effects on the person (roadmap E6-T5). The email
//! sender already stops mailing an address after a hard bounce or a
//! complaint (`email_suppression`); this nightly pass carries that onto the
//! people who own the address:
//!
//! - a hard bounce marks the contact's or lead's `email_verification_status`
//!   `invalid`;
//! - a complaint withdraws marketing consent on email through the consent
//!   ledger (E27, `attome_compliance::consent`), once per complaint.
//!
//! Both are idempotent: running again changes nothing.

use attome_types::AppError;
use chrono::{DateTime, Utc};

use uuid::Uuid;

/// The marketing purpose a complaint withdraws.
pub const MARKETING_PURPOSE: &str = "marketing";

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectsRun {
    pub invalidated: u64,
    pub withdrawn: u64,
}

/// Applies the effects of every active suppression.
pub async fn apply(db: &attome_db::DbPool) -> Result<EffectsRun, AppError> {
    let mut out = EffectsRun::default();
    for entity in ["contact", "lead"] {
        let has_field: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_name = $1 AND column_name = 'email_verification_status' \
               AND table_schema = ANY (current_schemas(false)))",
        )
        .bind(entity)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if !has_field {
            continue;
        }
        let table = attome_core::quote_ident(entity);
        out.invalidated += sqlx::query(&format!(
            "UPDATE {table} t SET email_verification_status = 'invalid', modified_at = now(), \
                 row_version = row_version + 1 \
             FROM email_suppression s \
             WHERE s.is_deleted = false AND s.reason = 'hard_bounce' \
               AND lower(t.email) = lower(s.email) \
               AND COALESCE(t.email_verification_status, '') <> 'invalid' \
               AND (t.is_active IS NULL OR t.is_active = true)"
        ))
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();

        let complainers: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(&format!(
            "SELECT t.id, s.created_at FROM {table} t \
             JOIN email_suppression s ON lower(t.email) = lower(s.email) \
             WHERE s.is_deleted = false AND s.reason = 'complaint' \
               AND (t.is_active IS NULL OR t.is_active = true) \
               AND NOT EXISTS (SELECT 1 FROM consent_event e                    WHERE e.subject_entity = $1 AND e.subject_id = t.id                      AND e.purpose_key = $2 AND e.source = 'complaint'                      AND e.occurred_at = s.created_at)"
        ))
        .bind(entity)
        .bind(MARKETING_PURPOSE)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (person, complained_at) in complainers {
            let mut tx = attome_db::tx::begin(db).await?;
            attome_compliance::consent::record(
                &mut tx,
                &attome_compliance::consent::ConsentChange {
                    subject_entity: entity.to_owned(),
                    subject_id: person,
                    purpose_key: MARKETING_PURPOSE.to_owned(),
                    channel: "email".to_owned(),
                    grant: false,
                    source: "complaint".to_owned(),
                    proof: serde_json::json!({ "complained_at": complained_at }),
                    occurred_at: complained_at,
                    recorded_by: None,
                },
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            out.withdrawn += 1;
        }
    }
    Ok(out)
}
