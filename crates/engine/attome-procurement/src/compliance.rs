//! W2-T1: vendor compliance documents remind before they expire.
//!
//! Each active `vendor_compliance_document` (vendor-supplier pack) with an
//! `expiry_date` that has not been reminded for that date keeps one pending
//! M10 timer of kind [`TIMER_KIND`], due [`LEAD_DAYS`] before the expiry at
//! midnight UTC and following the date (`attome_core::timer::Follow`), so a
//! renewed document's new date moves it. The daily `compliance_expiry`
//! job sets the timers that are missing; when one fires, [`fire`] claims the
//! document by writing its expiry into `reminded_for` (pack 0003) and then
//! tells the vendor's owner (else its creator) and the document's owner when
//! different. The claim comes first, so a document is reminded once per
//! expiry date however often the timer fires; a document renewed to a new
//! date is reminded again for that date.

use attome_core::EngineState;
use attome_core::timer::{Follow, NewTimer, Timer};
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::json;
use uuid::Uuid;

/// The registered daily job.
pub const JOB: &str = "compliance_expiry";
/// The timer kind.
pub const TIMER_KIND: &str = "procurement.compliance_expiry";
/// Days before expiry that the reminder goes.
pub const LEAD_DAYS: i64 = 30;
const DOCUMENT: &str = "vendor_compliance_document";
const BATCH: i64 = 500;

/// When a document's timer is due. Pure.
pub fn timer_due(expiry: NaiveDate) -> DateTime<Utc> {
    expiry
        .checked_sub_signed(Duration::days(LEAD_DAYS))
        .unwrap_or(expiry)
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc()
}

/// Whether a document still needs its reminder for this expiry. Pure.
pub fn needs_reminder(expiry: Option<NaiveDate>, reminded_for: Option<NaiveDate>) -> bool {
    expiry.is_some_and(|e| reminded_for != Some(e))
}

/// The reminder's subject and body. Pure.
pub fn reminder_text(
    kind: Option<&str>,
    vendor: Option<&str>,
    expiry: NaiveDate,
    today: NaiveDate,
) -> (String, String) {
    let kind = kind
        .map(|k| k.replace('_', " "))
        .unwrap_or_else(|| "compliance document".to_owned());
    let vendor = vendor.unwrap_or("a vendor");
    let when = if expiry < today {
        format!("expired on {expiry}")
    } else {
        format!("expires on {expiry}")
    };
    (
        format!("The {kind} of {vendor} {when}"),
        format!("The {kind} of {vendor} {when}. Ask the vendor for a renewed document."),
    )
}

async fn installed(db: &attome_db::DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'vendor_compliance_document' \
            AND column_name = 'reminded_for')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

fn follow_payload() -> serde_json::Value {
    json!({
        "follow": Follow {
            attribute: "expiry_date".to_owned(),
            offset_minutes: -LEAD_DAYS * 24 * 60,
            condition: None,
        },
    })
}

/// The daily job: a timer for every document that needs one. Answers the
/// timers set.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db).await? {
        return Ok(0);
    }
    let mut scheduled = 0;
    let mut after = Uuid::nil();
    loop {
        let due: Vec<(Uuid, NaiveDate)> = sqlx::query_as(
            "SELECT d.id, d.expiry_date::date FROM vendor_compliance_document d \
              WHERE (d.is_active IS NULL OR d.is_active = true) AND d.expiry_date IS NOT NULL \
                AND d.reminded_for::date IS DISTINCT FROM d.expiry_date::date \
                AND d.id > $1 \
                AND NOT EXISTS (SELECT 1 FROM timer t WHERE t.kind = $2 \
                      AND t.target_entity = $3 AND t.target_id = d.id AND t.status = 'pending') \
              ORDER BY d.id LIMIT $4",
        )
        .bind(after)
        .bind(TIMER_KIND)
        .bind(DOCUMENT)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = due.last().map(|d| d.0) else {
            break;
        };
        let mut tx = attome_db::tx::begin(db).await?;
        for (id, expiry) in &due {
            attome_core::timer::schedule(
                &mut tx,
                &NewTimer {
                    kind: TIMER_KIND.to_owned(),
                    target_entity: Some(DOCUMENT.to_owned()),
                    target_id: Some(*id),
                    run_id: None,
                    due_at: timer_due(*expiry),
                    payload: follow_payload(),
                },
            )
            .await?;
            scheduled += 1;
        }
        attome_db::tx::commit(tx).await?;
        after = last;
        if (due.len() as i64) < BATCH {
            break;
        }
    }
    Ok(scheduled)
}

/// `(document type, expiry, vendor name, vendor owner, document owner)`.
type Claimed = (
    Option<String>,
    NaiveDate,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
);

/// Runs a fired reminder (`EngineJob::TimerFire` for [`TIMER_KIND`]).
pub async fn fire(state: &EngineState, timer: &Timer, today: NaiveDate) -> Result<(), AppError> {
    let db = &state.base.db;
    let Some(document) = timer.target_id else {
        return Ok(());
    };
    if !installed(db).await? {
        return Ok(());
    }
    // Claimed before anyone is told: a second fire finds nothing.
    let claimed: Option<Claimed> = sqlx::query_as(
        "WITH claim AS ( \
           UPDATE vendor_compliance_document SET reminded_for = expiry_date::date \
            WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
              AND expiry_date IS NOT NULL \
              AND reminded_for::date IS DISTINCT FROM expiry_date::date \
            RETURNING document_type::text AS kind, expiry_date::date AS expiry, vendor_ref, \
                      COALESCE(owner_ref, created_by) AS owner) \
         SELECT c.kind, c.expiry, v.name, COALESCE(v.owner_ref, v.created_by), c.owner \
           FROM claim c LEFT JOIN vendor v ON v.id = c.vendor_ref",
    )
    .bind(document)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((kind, expiry, vendor, vendor_owner, document_owner)) = claimed else {
        return Ok(());
    };
    let (subject, body) = reminder_text(kind.as_deref(), vendor.as_deref(), expiry, today);
    let mut people: Vec<Uuid> = vendor_owner.into_iter().collect();
    if let Some(owner) = document_owner
        && !people.contains(&owner)
    {
        people.push(owner);
    }
    for user in people {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(format!("/xrm/entity/{DOCUMENT}/{document}")),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        // The claim stands: a failed send is logged, not retried.
        if let Err(error) =
            attome_notification::dispatch::create_dispatch(db, &state.base.config.notification, req)
                .await
        {
            tracing::warn!(%document, %user, %error, "compliance expiry reminder failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod compliance_expiry {
    use super::*;

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, m, d).expect("a real date")
    }

    #[test]
    fn the_timer_is_due_thirty_days_before_expiry() {
        assert_eq!(timer_due(day(4, 30)).date_naive(), day(3, 31));
        assert_eq!(timer_due(day(4, 30)).time(), chrono::NaiveTime::MIN);
    }

    #[test]
    fn a_document_is_reminded_once_per_expiry_date() {
        assert!(needs_reminder(Some(day(4, 30)), None));
        assert!(!needs_reminder(Some(day(4, 30)), Some(day(4, 30))));
        assert!(
            needs_reminder(Some(day(10, 30)), Some(day(4, 30))),
            "renewed: reminded again"
        );
        assert!(!needs_reminder(None, None), "no expiry, no reminder");
    }

    #[test]
    fn the_text_says_whether_it_has_expired() {
        let (subject, body) = reminder_text(Some("tax_form"), Some("Acme"), day(4, 30), day(4, 1));
        assert_eq!(subject, "The tax form of Acme expires on 2027-04-30");
        assert!(body.contains("renewed"));
        let (subject, _) = reminder_text(None, None, day(4, 1), day(4, 30));
        assert_eq!(
            subject,
            "The compliance document of a vendor expired on 2027-04-01"
        );
    }

    #[test]
    fn the_timer_follows_the_expiry_date() {
        let follow = attome_core::timer::follow_of(&follow_payload()).expect("a follow");
        assert_eq!(follow.attribute, "expiry_date");
        let record = json!({ "expiry_date": "2027-04-30" });
        assert_eq!(follow.due_for(&record), Some(timer_due(day(4, 30))));
    }
}
