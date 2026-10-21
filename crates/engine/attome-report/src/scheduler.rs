//! M25 Phase 1 (Report, D-440) — scheduled report runs, on the Z7 schedule
//! ledger since M12-T2.
//!
//! Each active `report_schedule` row is one ledger entry,
//! `report-schedule:{id}`, whose schedule is the row's recurrence rule
//! counted from the row's `created_at` ([`attome_jobs::schedule::Schedule::rrule`]).
//! [`sweep`] ticks every entry: the ledger's compare-and-swap claims each
//! occurrence once across any number of workers and restarts and enqueues
//! one `EngineJob::ReportScheduleFire`, whose handler ([`fire`]) creates the
//! `report_run` with `requested_by = run_as` (D-440's core property — see
//! `crate::run`'s module doc) and enqueues the same `EngineJob::ReportRun` a
//! manual run uses. The sweep's own `next_run_at`/`row_version` claim is
//! gone; `next_run_at` is still written, for display.
//!
//! A rule that no longer parses, or has no further occurrence (an `UNTIL`
//! already past), deactivates its schedule.
//!
//! P3-T1: a schedule with `recipients` runs once per recipient, as that
//! recipient, and each completed run is delivered to its recipient
//! (`crate::delivery`).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_jobs::schedule::Schedule;
use attome_types::AppError;

#[derive(Debug, Default)]
pub struct SweepStats {
    pub dispatched: u32,
    pub deactivated: u32,
}

#[derive(sqlx::FromRow)]
struct ScheduleRow {
    id: Uuid,
    report_ref: Uuid,
    run_as: Uuid,
    rrule: String,
    created_at: Option<DateTime<Utc>>,
    row_version: i64,
    recipients: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ReportFormat {
    format: String,
}

/// The ledger entry of one report schedule.
pub fn ledger_name(schedule_id: Uuid) -> String {
    format!("report-schedule:{schedule_id}")
}

/// The Z7 schedule a report schedule runs on: its rule from its creation.
pub fn schedule_of(rrule: &str, created_at: DateTime<Utc>) -> Result<Schedule, String> {
    Schedule::rrule(rrule, created_at).map_err(|e| e.0)
}

const SELECT_SCHEDULE: &str = "SELECT id, report_ref, run_as, rrule, created_at, row_version, recipients FROM report_schedule";

/// Ticks every active schedule's ledger entry; each occurrence that came due
/// is claimed once and enqueued as a `ReportScheduleFire`.
pub async fn sweep(state: &EngineState) -> Result<SweepStats, AppError> {
    let rows: Vec<ScheduleRow> =
        sqlx::query_as(&format!("{SELECT_SCHEDULE} WHERE is_active = true"))
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let mut stats = SweepStats::default();
    for row in rows {
        let created = row.created_at.unwrap_or_else(Utc::now);
        let schedule = match schedule_of(&row.rrule, created) {
            Ok(schedule) => schedule,
            Err(error) => {
                tracing::warn!(
                    schedule_id = %row.id, %error,
                    "report schedule: unparseable rrule, deactivating"
                );
                if deactivate(state, row.id, row.row_version).await? {
                    stats.deactivated += 1;
                }
                continue;
            }
        };
        if schedule.next_after(Utc::now()).is_none() {
            if deactivate(state, row.id, row.row_version).await? {
                stats.deactivated += 1;
            }
            continue;
        }
        let claimed = attome_jobs::schedule::tick_at(
            &state.base.db,
            &ledger_name(row.id),
            &schedule,
            EngineJob::ReportScheduleFire {
                schedule_id: row.id,
            },
        )
        .await
        .map_err(AppError::internal)?;
        if claimed {
            stats.dispatched += 1;
        }
    }
    Ok(stats)
}

/// `EngineJob::ReportScheduleFire`'s handler: one claimed occurrence of a
/// schedule becomes a `report_run` under the schedule's `run_as`. A schedule
/// deactivated or removed since the claim runs nothing.
pub async fn fire(state: &EngineState, schedule_id: Uuid) -> Result<(), AppError> {
    let row: Option<ScheduleRow> = sqlx::query_as(&format!(
        "{SELECT_SCHEDULE} WHERE id = $1 AND is_active = true"
    ))
    .bind(schedule_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(());
    };
    let now = Utc::now();
    let next = schedule_of(&row.rrule, row.created_at.unwrap_or(now))
        .ok()
        .and_then(|schedule| schedule.next_after(now));
    sqlx::query(
        "UPDATE report_schedule SET next_run_at = $2, last_run_at = NOW(), modified_at = NOW(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(row.id)
    .bind(next)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let report: Option<ReportFormat> =
        sqlx::query_as("SELECT format FROM attome_report WHERE id = $1 AND is_active = true")
            .bind(row.report_ref)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(report) = report else {
        tracing::warn!(
            schedule_id = %row.id, report_id = %row.report_ref,
            "report schedule: report definition missing or inactive, skipping this occurrence"
        );
        return Ok(());
    };
    // Empty override filters — `crate::run::process` falls back to the
    // report's own `parameters` default (resolved fresh at process time)
    // when a run's `params` is empty, same as a manual run with no `params`
    // in its request body.
    // P3-T1: one run per recipient, each under that recipient's own
    // access; with none, one run as `run_as`.
    let mut people =
        crate::delivery::resolve_recipients(&state.base.db, row.recipients.as_deref()).await?;
    if people.is_empty() {
        people.push(row.run_as);
    }
    for person in people {
        crate::run::create_run(
            state,
            row.report_ref,
            &report.format,
            &[],
            person,
            "scheduled",
            Some(row.id),
        )
        .await?;
    }
    Ok(())
}

async fn deactivate(
    state: &EngineState,
    id: Uuid,
    expected_row_version: i64,
) -> Result<bool, AppError> {
    let rows = sqlx::query(
        "UPDATE report_schedule SET is_active = false, modified_at = NOW(), \
            row_version = row_version + 1 WHERE id = $1 AND row_version = $2",
    )
    .bind(id)
    .bind(expected_row_version)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test fixtures")]

    use super::*;
    use attome_calendar::rrule::Rrule;

    fn utc(text: &str) -> DateTime<Utc> {
        text.parse().expect("an RFC 3339 instant")
    }

    /// M12-T2: a converted schedule fires exactly when its rule says.
    #[test]
    fn schedule_moved_fires_at_the_rule_s_times() {
        let created = utc("2026-09-01T06:00:00Z");
        for text in [
            "FREQ=DAILY",
            "FREQ=WEEKLY;BYDAY=SU,TH",
            "FREQ=WEEKLY;INTERVAL=2",
            "FREQ=MONTHLY;BYMONTHDAY=1,15",
            "FREQ=MONTHLY;BYDAY=-1FR",
            "FREQ=DAILY;UNTIL=2026-10-01T00:00:00Z",
        ] {
            let schedule = schedule_of(text, created).expect("converts");
            let rule = Rrule::parse(text).expect("parses");
            let mut at = utc("2026-09-10T12:00:00Z");
            for _ in 0..12 {
                let expected = rule.next_after(created, at);
                assert_eq!(schedule.next_after(at), expected, "{text} after {at}");
                let Some(next) = expected else { break };
                at = next;
            }
        }
    }

    #[test]
    fn schedule_moved_refuses_what_the_ledger_cannot_run() {
        let created = utc("2026-09-01T06:00:00Z");
        assert!(schedule_of("FREQ=DAILY;COUNT=5", created).is_err());
        assert!(schedule_of("every tuesday", created).is_err());
        assert_eq!(
            ledger_name(Uuid::nil()),
            "report-schedule:00000000-0000-0000-0000-000000000000"
        );
    }
}
