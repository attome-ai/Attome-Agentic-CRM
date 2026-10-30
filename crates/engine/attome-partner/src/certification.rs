//! F9-T7: partner certifications warn before they expire.
//!
//! Daily ([`expiry_tick`]), each live `partner_certification` that expires
//! within [`LEAD_DAYS`] and has not been warned for that expiry is claimed by
//! writing `warned_on`, then its partner's partner manager is told. A
//! certification is warned once per expiry date: one renewed to a later date
//! is warned again for that date, [`LEAD_DAYS`] before it.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

use crate::support::{installed, notify, partner_manager};

/// The registered daily job.
pub const EXPIRY_JOB: &str = "partner_certification_expiry";
/// Days before expiry that the warning goes.
pub const LEAD_DAYS: i32 = 30;
const BATCH: i64 = 500;

/// The warning's subject. Pure.
pub fn warning_subject(name: Option<&str>, days_left: i64) -> String {
    let name = name.unwrap_or("A partner certification");
    match days_left {
        d if d < 0 => format!("{name} has expired"),
        0 => format!("{name} expires today"),
        1 => format!("{name} expires tomorrow"),
        d => format!("{name} expires in {d} days"),
    }
}

/// The daily job. Answers how many certifications were warned.
pub async fn expiry_tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db, "partner_certification", "warned_on").await? {
        return Ok(0);
    }
    let mut warned = 0;
    loop {
        // The claim first, so a certification is warned once however often
        // the job runs.
        let rows: Vec<(Uuid, Option<String>, Option<Uuid>, i64)> = sqlx::query_as(
            "UPDATE partner_certification c SET warned_on = now() \
              WHERE c.id IN ( \
                    SELECT id FROM partner_certification \
                     WHERE expires_on IS NOT NULL \
                       AND expires_on < now() + make_interval(days => $1) \
                       AND (warned_on IS NULL OR warned_on < expires_on - make_interval(days => $1)) \
                       AND (is_active IS NULL OR is_active = true) \
                     ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED) \
              RETURNING c.id, c.name, c.partner_account_ref, \
                        (c.expires_on::date - now()::date)::bigint",
        )
        .bind(LEAD_DAYS)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if rows.is_empty() {
            break;
        }
        for (id, name, partner, days_left) in &rows {
            if let Some(manager) = partner_manager(state, *partner).await {
                notify(
                    state,
                    manager,
                    warning_subject(name.as_deref(), *days_left),
                    "Renew it, or record the new certification, before it lapses.".to_owned(),
                    format!("/xrm/entity/partner_certification/{id}"),
                )
                .await;
            }
        }
        warned += rows.len() as u64;
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    Ok(warned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_warning_says_when() {
        assert_eq!(
            warning_subject(Some("Cloud Expert"), 30),
            "Cloud Expert expires in 30 days"
        );
        assert_eq!(
            warning_subject(Some("Cloud Expert"), 1),
            "Cloud Expert expires tomorrow"
        );
        assert_eq!(
            warning_subject(None, 0),
            "A partner certification expires today"
        );
        assert_eq!(
            warning_subject(None, -2),
            "A partner certification has expired"
        );
    }
}
