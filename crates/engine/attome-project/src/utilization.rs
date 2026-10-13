//! M72 §3 "Utilization" — a per-team utilization KPI plus a sustained-
//! over-85% alert, both built on `capacity.rs`'s own arithmetic.
//!
//! **No code-seeded `dashboard_metric_definition` row — same posture
//! M73's SLA KPIs established (their report queries now ship as `is_report`
//! rows in `platform-bundles/attome-service.json`, D-478; no metric row ships
//! with them).** Every engine in this workspace code-seeds an
//! entity's *schema*, never a *business record* of that entity;
//! `dashboard_metric_definition` rows are ordinary business records, created
//! through the admin API (`POST /api/v1/dashboard_metric_definition`) by whoever
//! wants one, not planted by a boot-time seed. What this module *does*
//! code-seed is the underlying `sql_query` (`is_report = true`,
//! the `ensure_report_query` shape below) so an admin
//! can wire it into a metric definition with two clicks — set `query_ref` to
//! this query's id, `threshold_warn = 85`. That query is necessarily
//! platform-wide, not per-team: M27 Phase 1 (`attome-metric`'s `metric.rs`
//! module doc) has no dimension/group-by concept yet, and a metric's stored
//! query takes no parameters. A genuinely *per-team* metric is one admin
//! action away once dimensions land (M27 Phase 3) or, today, one
//! team-filtered `sql_query` per team an admin wants tracked —
//! exactly the deferral the M73 SLA KPIs accept for their own per-queue
//! breakdown.
//!
//! **The sustained->85%->alert path does not wait for that admin step.**
//! M27 Phase 2's `metric.threshold_crossed` alert (the mechanism that would
//! otherwise fire this) is explicitly out of scope in this codebase today
//! (`attome-metric`'s `metric.rs` module doc) — so [`sweep_utilization_alerts`]
//! computes real per-team utilization directly from `resource_allocation`/
//! `resource_availability` (the same calendar-aware arithmetic
//! `capacity.rs` uses, just grouped by team instead of by resource) and
//! dispatches through the platform's established M51 mechanism
//! (`attome_notification::dispatch::{DispatchRequest, create_dispatch}`) —
//! same call shape `attome-service::clock::notify_recipients` already uses for
//! SLA-breach escalation.
//!
//! **"Sustained".** The lookback window (`lookback_days`, the caller's
//! choice — the utilization report query above uses 28) is itself what makes
//! a crossing "sustained" rather than a one-day spike: utilization is
//! `allocated_hours / capacity_hours` averaged over the whole window, so a
//! single overloaded day cannot trip it on its own.
//!
//! **Wired to a periodic scheduler.** `crates/server/src/jobs.rs`'s
//! `EngineJob::ResourceUtilizationSweep` variant calls
//! [`sweep_utilization_alerts`] at the platform-default 85%/28-day
//! threshold/lookback — see that file's `EngineJob::ResourceUtilizationSweep`
//! match arm for the scheduler wiring itself.
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Duration, NaiveDate, Utc};
use uuid::Uuid;

use crate::capacity::{base_capacity_hours, load_default_calendar};

/// Idempotent insert matched on `(entity_logical_name, record_no)` — the
/// shape and idempotency key of the deleted `attome-service` analytics seeds'
/// `ensure_report_query` (their queries now ship in a platform bundle,
/// D-478); `trd-engine`'s `health_monitor` keeps its own copy. Solution 7
/// (D-785): a platform definition, so a new row is stamped `platform`; an
/// existing row keeps its layer.
async fn ensure_report_query(
    db: &DbPool,
    entity_id: Uuid,
    name: &str,
    sql_query: &str,
    required_privilege: &str,
) -> Result<Uuid, AppError> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sql_query \
         WHERE entity_logical_name = $1 AND record_no = $2",
    )
    .bind(entity_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = existing {
        return Ok(id);
    }

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query \
             (id, sql_query, record_no, entity_logical_name, required_privilege, \
              is_report, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, true, true, NOW(), 'platform')",
    )
    .bind(id)
    .bind(sql_query)
    .bind(name)
    .bind(entity_id)
    .bind(required_privilege)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Called from `seed::seed` once `resource_allocation` is registered.
/// Platform-wide, trailing-28-day nominal utilization — a fixed Mon-Fri
/// 8-hour/day nominal capacity approximation (not the calendar-aware figure
/// `capacity.rs`'s own endpoint computes), because a code-seeded report
/// query's SQL cannot call into `attome_calendar`. Documented as intentionally
/// simpler than the planning endpoint — a KPI catalog entry, not a
/// replacement for it.
pub async fn seed(db: &DbPool, resource_allocation_entity_id: Uuid) -> Result<(), AppError> {
    ensure_report_query(
        db,
        resource_allocation_entity_id,
        "Resource Utilization % (Actual / Nominal Capacity, Last 28 Days)",
        "SELECT (SUM(te.hours) FILTER (WHERE te.entry_date >= CURRENT_DATE - INTERVAL '28 days')) \
             / NULLIF((SELECT COUNT(*) FROM user_account WHERE is_active = true) \
                       * 28.0 * (5.0 / 7.0) * 8.0, 0) * 100 AS value \
         FROM project_time_entry te \
         WHERE (te.is_active IS NULL OR te.is_active = true)",
        "resource_allocation.read",
    )
    .await?;
    tracing::info!("attome-project: resource utilization KPI query seeded");
    Ok(())
}

struct TeamUtilization {
    team_id: Uuid,
    capacity_hours: f64,
    allocated_hours: f64,
}

/// Per-team `capacity_hours`/`allocated_hours`, same overlap-prorating
/// arithmetic as `capacity.rs::fetch_capacity_page`, grouped by team instead
/// of by resource. `base_hours`/`period_days` are the Rust-computed
/// calendar constants shared by every resource in the window (see
/// `capacity.rs::base_capacity_hours`).
async fn team_utilization(
    db: &DbPool,
    from: NaiveDate,
    to: NaiveDate,
    base_hours: f64,
    period_days: f64,
) -> Result<Vec<TeamUtilization>, AppError> {
    sqlx::query_as::<_, (Uuid, f64, f64)>(
        "WITH members AS ( \
             SELECT t.team_ref AS team_id, u.id AS user_id \
             FROM user_account_mm_team t \
             JOIN user_account u ON u.id = t.user_ref AND u.is_active = true \
             WHERE t.is_deleted = false \
         ), \
         leave_overlap AS ( \
             SELECT a.user_id, \
                    SUM(GREATEST(0, LEAST(a.leave_end::date, $2::date) - GREATEST(a.leave_start::date, $1::date) + 1))::float8 AS leave_days \
             FROM resource_availability a \
             WHERE (a.is_active IS NULL OR a.is_active = true) \
               AND a.leave_start::date <= $2::date AND a.leave_end::date >= $1::date \
             GROUP BY a.user_id \
         ), \
         allocation_overlap AS ( \
             SELECT al.user_id, \
                    SUM(al.allocation_percent::float8 / 100.0 * $3::float8 \
                        * (GREATEST(0, LEAST(COALESCE(al.end_date::date, $2::date), $2::date) \
                                     - GREATEST(al.start_date::date, $1::date) + 1)::float8 \
                           / $4::float8)) AS allocated_hours \
             FROM resource_allocation al \
             WHERE (al.is_active IS NULL OR al.is_active = true) \
               AND al.start_date::date <= $2::date \
               AND (al.end_date IS NULL OR al.end_date::date >= $1::date) \
             GROUP BY al.user_id \
         ) \
         SELECT m.team_id, \
                SUM(GREATEST(0, $3::float8 * (1 - COALESCE(lo.leave_days, 0) / $4::float8))) AS capacity_hours, \
                SUM(COALESCE(ao.allocated_hours, 0)) AS allocated_hours \
         FROM members m \
         LEFT JOIN leave_overlap lo ON lo.user_id = m.user_id \
         LEFT JOIN allocation_overlap ao ON ao.user_id = m.user_id \
         GROUP BY m.team_id",
    )
    .bind(from)
    .bind(to)
    .bind(base_hours)
    .bind(period_days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
    .map(|rows| {
        rows.into_iter()
            .map(|(team_id, capacity_hours, allocated_hours)| TeamUtilization {
                team_id,
                capacity_hours,
                allocated_hours,
            })
            .collect()
    })
}

/// Active member ids of one team — the alert's recipients (see this
/// module's doc comment on why "the team itself" is today's recipient set:
/// `team` carries no owner/manager field yet).
async fn active_team_member_ids(db: &DbPool, team_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT u.id FROM user_account_mm_team t \
         JOIN user_account u ON u.id = t.user_ref AND u.is_active = true \
         WHERE t.team_ref = $1 AND t.is_deleted = false",
    )
    .bind(team_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Dedup guard so a repeated sweep (e.g. a manual re-trigger, or a future
/// periodic caller with no dedup of its own) doesn't re-alert the same team
/// every run: skips dispatch if a dispatch with this team's route already
/// exists in the last `dedup_window`. Mirrors `attome-service::clock::
/// escalate_on_breach`'s idempotency intent (never spam a recipient for a
/// condition that hasn't changed) without needing a stored-state column of
/// its own — `notification_dispatch.route` + `created_at` already carry
/// enough to answer "did we already tell this team".
async fn already_alerted_recently(
    db: &DbPool,
    route: &str,
    dedup_window: Duration,
) -> Result<bool, AppError> {
    let cutoff = Utc::now() - dedup_window;
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM notification_dispatch \
         WHERE route = $1 AND created_at >= $2 LIMIT 1",
    )
    .bind(route)
    .bind(cutoff)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(found.is_some())
}

fn utilization_route(team_id: Uuid) -> String {
    format!("resource/utilization-alert/{team_id}")
}

/// Computes trailing `lookback_days`-window utilization for every active
/// team and dispatches a `high`-priority in-app notification to each team's
/// active members for every team whose utilization is at or above
/// `threshold_pct` — deduplicated so the same team isn't re-alerted within
/// `lookback_days` of its last alert. Returns the number of teams alerted.
/// Best-effort per team: one team's dispatch failure is logged and does not
/// stop the sweep from evaluating the rest (same posture
/// `attome-service::clock::notify_recipients` already takes per-recipient).
pub async fn sweep_utilization_alerts(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
    threshold_pct: f64,
    lookback_days: i64,
) -> Result<u32, AppError> {
    let to = Utc::now().date_naive();
    let from = to - Duration::days(lookback_days - 1);
    let calendar = load_default_calendar(db).await?;
    let base_hours = base_capacity_hours(&calendar, from, to)?;
    let period_days = (lookback_days.max(1)) as f64;

    let teams = team_utilization(db, from, to, base_hours, period_days).await?;
    let mut alerted = 0u32;
    for team in teams {
        if team.capacity_hours <= 0.0 {
            continue;
        }
        let utilization_pct = team.allocated_hours / team.capacity_hours * 100.0;
        if utilization_pct < threshold_pct {
            continue;
        }

        let route = utilization_route(team.team_id);
        match already_alerted_recently(db, &route, Duration::days(lookback_days)).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, team_id = %team.team_id, "resource utilization sweep: dedup check failed, skipping team");
                continue;
            }
        }

        let recipients = match active_team_member_ids(db, team.team_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, team_id = %team.team_id, "resource utilization sweep: could not resolve team members");
                continue;
            }
        };
        if recipients.is_empty() {
            continue;
        }

        let subject =
            format!("Team utilization at {utilization_pct:.0}% (last {lookback_days} days)");
        let body = format!(
            "This team's resource utilization has been at or above {threshold_pct:.0}% over the \
             last {lookback_days} days ({utilization_pct:.0}% observed) — review allocations \
             against capacity."
        );
        for user_id in recipients {
            let req = attome_notification::dispatch::DispatchRequest {
                template_key: None,
                locale: "en".to_string(),
                recipient_user_ref: Some(user_id),
                is_global: false,
                organization_ref: None,
                channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
                subject: Some(subject.clone()),
                body_html: None,
                body_text: Some(body.clone()),
                route: Some(route.clone()),
                variables: std::collections::HashMap::new(),
                priority: "high".to_string(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            if let Err(e) =
                attome_notification::dispatch::create_dispatch(db, notification_cfg, req).await
            {
                tracing::error!(error = %e, user_id = %user_id, team_id = %team.team_id, "resource utilization sweep: dispatch failed");
            }
        }
        alerted += 1;
    }
    Ok(alerted)
}
