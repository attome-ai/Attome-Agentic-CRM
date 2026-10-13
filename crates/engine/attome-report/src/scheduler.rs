//! M25 Phase 1 (Report, D-440) — the schedule sweep: finds
//! `report_schedule` rows whose `next_run_at` has passed, claims each
//! with a guarded `next_run_at`/`row_version` UPDATE so two worker replicas
//! can never both fire the same occurrence, creates its `report_run`
//! row with `requested_by = run_as` (D-440's core property — see
//! `crate::run`'s module doc), and enqueues the same `EngineJob::ReportRun`
//! a manual run uses.
//!
//! **Recipient delivery (`delivery`/`recipients`/`skip_if_empty`) is
//! persisted as schedule metadata but not yet dispatched.** This pass covers
//! the scheduling and permission-scoping mechanism, which is D-440's actual
//! subject; wiring `in_app`/`email_link` notification of a completed run to
//! `recipients` is deferred, same as attachment delivery and PDF/HTML
//! format — see the accompanying module-plan checklist update.

use uuid::Uuid;

use attome_core::EngineState;
use attome_types::AppError;

use crate::rrule::Rrule;

#[derive(Debug, Default)]
pub struct SweepStats {
    pub dispatched: u32,
    pub deactivated: u32,
}

#[derive(sqlx::FromRow)]
struct DueSchedule {
    id: Uuid,
    report_ref: Uuid,
    run_as: Uuid,
    rrule: String,
    row_version: i64,
}

#[derive(sqlx::FromRow)]
struct ReportFormat {
    format: String,
}

/// Sweeps due schedules and dispatches a run for each. Re-derives current
/// state on every call (which schedules are due right now), never a
/// snapshot — same shape as `WorkflowSlaSweep`/`ContentScheduledPublishSweep`.
pub async fn sweep(state: &EngineState) -> Result<SweepStats, AppError> {
    let due: Vec<DueSchedule> = sqlx::query_as(
        "SELECT id, report_ref, run_as, rrule, row_version \
         FROM report_schedule \
         WHERE is_active = true AND next_run_at IS NOT NULL AND next_run_at <= NOW()",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut stats = SweepStats::default();
    for schedule in due {
        dispatch_one(state, &schedule, &mut stats).await?;
    }
    Ok(stats)
}

/// Claims and fires one due schedule. A lost claim (another replica's sweep
/// won the same tick's row_version race) is normal, logged, and not an
/// error.
async fn dispatch_one(
    state: &EngineState,
    schedule: &DueSchedule,
    stats: &mut SweepStats,
) -> Result<(), AppError> {
    let rule = match Rrule::parse(&schedule.rrule) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                schedule_id = %schedule.id, error = %e,
                "report schedule sweep: unparseable rrule, deactivating"
            );
            if deactivate(state, schedule.id, schedule.row_version).await? {
                stats.deactivated += 1;
            }
            return Ok(());
        }
    };
    let now = chrono::Utc::now();
    let next = rule.next_after(now, now);

    let claimed = match next {
        Some(next_run_at) => {
            // `report_schedule` is a provisioned entity (`seed.rs`), so
            // its system columns are `modified_at`/`is_active`, not
            // `updated_at`/`is_deleted` — see that file's doc comment.
            let rows = sqlx::query(
                "UPDATE report_schedule \
                    SET next_run_at = $3, last_run_at = NOW(), modified_at = NOW(), \
                        row_version = row_version + 1 \
                  WHERE id = $1 AND row_version = $2",
            )
            .bind(schedule.id)
            .bind(schedule.row_version)
            .bind(next_run_at)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            rows > 0
        }
        None => {
            // No further occurrences (an UNTIL already in the past) — claim
            // by deactivating instead of rescheduling.
            if deactivate(state, schedule.id, schedule.row_version).await? {
                stats.deactivated += 1;
            }
            return Ok(());
        }
    };
    if !claimed {
        tracing::info!(
            schedule_id = %schedule.id,
            "report schedule sweep: lost the claim to another replica this tick"
        );
        return Ok(());
    }

    let report: Option<ReportFormat> =
        sqlx::query_as("SELECT format FROM attome_report WHERE id = $1 AND is_active = true")
            .bind(schedule.report_ref)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(report) = report else {
        tracing::warn!(
            schedule_id = %schedule.id, report_id = %schedule.report_ref,
            "report schedule sweep: report definition missing or inactive, skipping this occurrence"
        );
        return Ok(());
    };

    // Empty override filters — `crate::run::process` falls back to the
    // report's own `parameters` default (resolved fresh at process time)
    // when a run's `params` is empty, same as a manual run with no `params`
    // in its request body.
    crate::run::create_run(
        state,
        schedule.report_ref,
        &report.format,
        &[],
        schedule.run_as,
        "scheduled",
        Some(schedule.id),
    )
    .await?;
    stats.dispatched += 1;
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
