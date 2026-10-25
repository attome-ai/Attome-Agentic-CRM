//! R5-T2: the breach register's intake from security cases, and its
//! notification deadline timers.
//!
//! The privacy pack (R5-T1) keeps breaches in `privacy_breach` with a
//! `notify_deadline` and `regulator_notified_at`. This module:
//!
//! - turns a security case (Q22, `security_case`) into a breach record
//!   ([`create_from_case`]): discovered when the case opened, the regulator
//!   deadline from the deployment's country ([`regulator_deadline_hours`],
//!   `core.country`), severity carried over, and the case linked to it, once
//!   (a case that already has a breach answers that one). Q22's mass-export
//!   rule already opens its breach this way at detection time;
//! - keeps two M10 timers ([`TIMER_KIND`]) on every open breach that has a
//!   deadline and no regulator notice yet: a warning [`WARNING_HOURS`] before
//!   the deadline and one at it ([`schedule_due`], run with the security
//!   detections every five minutes, so breaches entered by hand get them
//!   too);
//! - when a timer fires ([`fire`]) and the regulator has still not been
//!   told, raises the `privacy_breach_deadline` operations alert (critical
//!   once a deadline has passed) and logs it; a breach notified or closed in
//!   the meantime does nothing, and the alert clears once no open breach is
//!   waiting on a notice inside the warning window.
//!
//! A deployment without the privacy pack, or without security cases, does
//! nothing.

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_core::timer::{NewTimer, Timer};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use uuid::Uuid;

/// The M10 timer kind of a breach deadline.
pub const TIMER_KIND: &str = "compliance.breach_deadline";
/// The operations alert raised while a breach notice is due or late.
pub const ALERT: &str = "privacy_breach_deadline";
/// How long before the deadline the warning timer fires.
pub const WARNING_HOURS: i64 = 24;
/// Breaches given timers per run.
const BATCH: i64 = 200;
const ENTITY: &str = "privacy_breach";

/// The regulator notice window when a country sets none we know of.
pub const DEFAULT_DEADLINE_HOURS: i64 = 72;

/// Regulator notice windows by country pack (ISO code, hours). Saudi
/// Arabia's PDPL implementing regulation sets 72 hours; the other packs this
/// release ships take the same 72 hours, the common rule of the region's
/// laws and the GDPR, until a pack states a stricter one here.
pub const DEADLINE_HOURS: &[(&str, i64)] = &[
    ("AE", 72),
    ("BH", 72),
    ("EG", 72),
    ("JO", 72),
    ("KW", 72),
    ("OM", 72),
    ("QA", 72),
    ("SA", 72),
];

/// Hours a controller has to notify the regulator after discovering a
/// personal-data breach, from the deployment's country. Pure.
pub fn regulator_deadline_hours(country: Option<&str>) -> i64 {
    let code = country.map(|c| c.trim().to_ascii_uppercase());
    DEADLINE_HOURS
        .iter()
        .find(|(c, _)| Some(*c) == code.as_deref())
        .map_or(DEFAULT_DEADLINE_HOURS, |(_, hours)| *hours)
}

/// The regulator deadline of a breach discovered at `discovered`. Pure.
pub fn deadline(discovered: DateTime<Utc>, country: Option<&str>) -> DateTime<Utc> {
    discovered + Duration::hours(regulator_deadline_hours(country))
}

/// The two timers of a breach: `(stage, due)`. A warning already in the
/// past is dropped; the deadline timer is always kept. Pure.
pub fn timer_plan(
    deadline: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Vec<(&'static str, DateTime<Utc>)> {
    let warning = deadline - Duration::hours(WARNING_HOURS);
    let mut plan = Vec::with_capacity(2);
    if warning > now {
        plan.push(("warning", warning));
    }
    plan.push(("due", deadline));
    plan
}

/// The breach severity a case's severity maps to. Pure.
pub fn breach_severity(case_severity: &str) -> &'static str {
    match case_severity {
        "high" | "critical" => "high",
        "medium" => "medium",
        _ => "low",
    }
}

/// What a fired timer says, when the notice is still owed. Pure.
pub fn deadline_text(title: &str, deadline: DateTime<Utc>, now: DateTime<Utc>) -> String {
    if now >= deadline {
        format!(
            "The regulator notice for breach \"{title}\" was due {} and has not been recorded",
            deadline.format("%Y-%m-%d %H:%M UTC")
        )
    } else {
        format!(
            "The regulator notice for breach \"{title}\" is due {}",
            deadline.format("%Y-%m-%d %H:%M UTC")
        )
    }
}

async fn installed(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('privacy_breach') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

fn deployment_country(state: &EngineState) -> Option<String> {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get("core.country")
        .map(|d| settings.resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|c| !c.is_empty())
}

async fn schedule_timers(
    tx: &mut attome_db::Tx<'_>,
    breach: Uuid,
    deadline: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    for (stage, due_at) in timer_plan(deadline, now) {
        attome_core::timer::schedule(
            &mut **tx,
            &NewTimer {
                kind: TIMER_KIND.to_owned(),
                target_entity: Some(ENTITY.to_owned()),
                target_id: Some(breach),
                run_id: None,
                due_at,
                payload: json!({ "stage": stage }),
            },
        )
        .await?;
    }
    Ok(())
}

/// The breach record of a security case, created on first call. `actor`
/// becomes its owner.
pub async fn create_from_case(
    state: &EngineState,
    case: Uuid,
    actor: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let db = &state.base.db;
    if !installed(db).await? {
        return Err(AppError::Validation(
            "the privacy pack is not installed: there is no breach register".into(),
        ));
    }
    let now = Utc::now();
    let due = |opened: DateTime<Utc>| deadline(opened, deployment_country(state).as_deref());
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(String, String, String, DateTime<Utc>, Option<Uuid>)> = sqlx::query_as(
        "SELECT rule, severity, summary, opened_at, breach_ref FROM security_case \
          WHERE id = $1 FOR UPDATE",
    )
    .bind(case)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (rule, severity, summary, opened_at, existing) = row.ok_or(AppError::NotFound)?;
    if let Some(breach) = existing {
        attome_db::tx::commit(tx).await?;
        return Ok(breach);
    }
    let notify_by = due(opened_at);
    let breach: Uuid = sqlx::query_scalar(
        "INSERT INTO privacy_breach \
           (title, discovered_at, notify_deadline, description, severity, status, owner_ref) \
         VALUES ($1, $2, $3, $4, $5, 'open', $6) RETURNING id",
    )
    .bind(format!("Security case: {summary}"))
    .bind(opened_at)
    .bind(notify_by)
    .bind(format!("From the {rule} security case {case}."))
    .bind(breach_severity(&severity))
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(&mut tx, ENTITY, breach, ChangeOperation::Create).await?;
    sqlx::query("UPDATE security_case SET breach_ref = $2 WHERE id = $1")
        .bind(case)
        .bind(breach)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    schedule_timers(&mut tx, breach, notify_by, now).await?;
    attome_db::tx::commit(tx).await?;
    Ok(breach)
}

/// Gives every open breach with a deadline, no regulator notice and no
/// pending timer its timers. Answers how many breaches got them.
pub async fn schedule_due(db: &DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    if !installed(db).await? {
        return Ok(0);
    }
    let due: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT b.id, b.notify_deadline FROM privacy_breach b \
          WHERE b.is_active AND b.notify_deadline IS NOT NULL \
            AND b.regulator_notified_at IS NULL \
            AND COALESCE(b.status::text, 'open') <> 'closed' \
            AND NOT EXISTS (SELECT 1 FROM timer t WHERE t.kind = $1 \
                  AND t.target_entity = $2 AND t.target_id = b.id) \
          ORDER BY b.id LIMIT $3",
    )
    .bind(TIMER_KIND)
    .bind(ENTITY)
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if due.is_empty() {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    for (breach, notify_by) in &due {
        schedule_timers(&mut tx, *breach, *notify_by, now).await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(due.len() as u64)
}

/// Runs a fired deadline timer (`EngineJob::TimerFire` for [`TIMER_KIND`]).
pub async fn fire(db: &DbPool, timer: &Timer, now: DateTime<Utc>) -> Result<(), AppError> {
    let Some(breach) = timer.target_id else {
        return Ok(());
    };
    if !installed(db).await? {
        return Ok(());
    }
    let owed: Option<(Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT title, notify_deadline FROM privacy_breach \
          WHERE id = $1 AND is_active AND notify_deadline IS NOT NULL \
            AND regulator_notified_at IS NULL \
            AND COALESCE(status::text, 'open') <> 'closed'",
    )
    .bind(breach)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some((title, notify_by)) = &owed {
        let text = deadline_text(title.as_deref().unwrap_or("untitled"), *notify_by, now);
        tracing::warn!(%breach, stage = ?timer.payload.get("stage"), "{text}");
    }
    refresh_alert(db, now).await
}

/// Sets the deadline alert from every breach still owing a notice.
async fn refresh_alert(db: &DbPool, now: DateTime<Utc>) -> Result<(), AppError> {
    let (due_soon, late): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE notify_deadline <= $1 + make_interval(hours => $2::int)), \
                COUNT(*) FILTER (WHERE notify_deadline <= $1) \
           FROM privacy_breach \
          WHERE is_active AND notify_deadline IS NOT NULL AND regulator_notified_at IS NULL \
            AND COALESCE(status::text, 'open') <> 'closed'",
    )
    .bind(now)
    .bind(WARNING_HOURS as i32)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let severity = if late > 0 { "critical" } else { "warning" };
    let summary =
        format!("{due_soon} breach notice(s) due within {WARNING_HOURS} hours, {late} late");
    if let Err(error) = attome_server::alerts::set_job_alert(
        db,
        ALERT,
        severity,
        &summary,
        Some(due_soon as f64),
        due_soon > 0,
    )
    .await
    {
        tracing::warn!(%error, "breach deadline alert not updated");
    }
    Ok(())
}

#[cfg(test)]
mod breach_register {
    use super::*;

    fn at(h: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap() + Duration::hours(h)
    }

    #[test]
    fn breach_register_deadline_by_country() {
        assert_eq!(regulator_deadline_hours(Some("sa")), 72);
        assert_eq!(regulator_deadline_hours(Some("EG")), 72);
        assert_eq!(
            regulator_deadline_hours(None),
            72,
            "unknown: the common 72 hours"
        );
        assert_eq!(deadline(at(0), Some("SA")), at(72));
    }

    #[test]
    fn breach_register_timer_plan() {
        assert_eq!(
            timer_plan(at(72), at(0)),
            vec![("warning", at(48)), ("due", at(72))]
        );
        // Inside the warning window: only the deadline is left.
        assert_eq!(timer_plan(at(72), at(50)), vec![("due", at(72))]);
        // Already late: the deadline timer fires at once.
        assert_eq!(timer_plan(at(72), at(80)), vec![("due", at(72))]);
    }

    #[test]
    fn breach_register_severity_and_text() {
        assert_eq!(breach_severity("high"), "high");
        assert_eq!(breach_severity("medium"), "medium");
        assert_eq!(breach_severity("low"), "low");
        assert!(deadline_text("Export", at(72), at(50)).contains("is due"));
        assert!(deadline_text("Export", at(72), at(73)).contains("has not been recorded"));
    }
}
