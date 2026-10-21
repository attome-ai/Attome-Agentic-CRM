//! I5-T2: work orders generated ahead of maintenance due dates.
//!
//! A `maintenance_plan` (field-service pack 0003) on an asset is due by date
//! (`every_n_days` or `calendar_date`: its `next_due_on`) or by meter
//! (`meter_threshold`: the asset's latest `asset_meter_reading` of the plan's
//! `meter` has risen `meter_threshold` above the reading at the last
//! generation, `meter_baseline`).
//!
//! **Date plans run on M10 timers.** The daily `maintenance_generation` job
//! keeps one pending timer of kind [`TIMER_KIND`] per active date plan, due
//! `lead_days` (pack 0007) before `next_due_on`; the timer also follows the
//! date (`attome_core::timer::Follow`), so a person who moves `next_due_on`
//! moves it at once, and the daily job re-times it when `lead_days`
//! changes. When it fires, [`fire`] generates the work order. **Meter plans**
//! are checked by the same daily job against the latest reading.
//!
//! **Once per due date.** Generation creates the work order through the
//! record engine as the plan's owner (record rules, validation, audit), with
//! `maintenance_plan_ref` and `maintenance_due_on`, plus one task per
//! `maintenance_task_template`, then advances the plan. A work order that
//! already exists for the plan and due date (a crash after the create) is
//! not made again: the plan is only advanced. While another work order of
//! the plan is still open, none is made for this due date either; the plan
//! advances, so an open order is never doubled.
//!
//! A plan for an asset type without an asset is a template for planners and
//! generates nothing. Lead time applies to date plans only.

use attome_core::EngineState;
use attome_core::timer::{Follow, NewTimer, Timer};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::json;
use uuid::Uuid;

/// The registered daily job.
pub const JOB: &str = "maintenance_generation";
/// The timer kind of a date plan.
pub const TIMER_KIND: &str = "service.maintenance";
/// Plans per page.
const BATCH: i64 = 500;
/// The longest lead time honoured, in days.
const MAX_LEAD_DAYS: i64 = 365;
/// Work order statuses that are no longer open.
const CLOSED: &str = "('completed', 'cancelled', 'invoiced')";

const PLAN: &str = "maintenance_plan";

/// How a plan comes due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    EveryNDays,
    CalendarDate,
    Meter,
}

impl Trigger {
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value? {
            "every_n_days" => Some(Self::EveryNDays),
            "calendar_date" => Some(Self::CalendarDate),
            "meter_threshold" => Some(Self::Meter),
            _ => None,
        }
    }
}

fn lead(lead_days: Option<f64>) -> i64 {
    lead_days
        .filter(|d| d.is_finite())
        .map(|d| d.round() as i64)
        .unwrap_or(0)
        .clamp(0, MAX_LEAD_DAYS)
}

/// When a date plan's timer is due: midnight UTC `lead_days` before the due
/// date. Pure.
pub fn timer_due(next_due_on: NaiveDate, lead_days: Option<f64>) -> DateTime<Utc> {
    let start = next_due_on
        .checked_sub_signed(Duration::days(lead(lead_days)))
        .unwrap_or(next_due_on);
    start.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc()
}

/// Whether a date plan is due its work order `today`. Pure.
pub fn date_plan_due(next_due_on: NaiveDate, lead_days: Option<f64>, today: NaiveDate) -> bool {
    timer_due(next_due_on, lead_days).date_naive() <= today
}

/// Whether a meter plan is due: the latest reading is `threshold` above the
/// baseline (zero before the first generation). Pure.
pub fn meter_due(latest: Option<f64>, baseline: Option<f64>, threshold: Option<f64>) -> bool {
    match (latest, threshold) {
        (Some(latest), Some(threshold)) if threshold > 0.0 && latest.is_finite() => {
            latest - baseline.unwrap_or(0.0) >= threshold
        }
        _ => false,
    }
}

/// The plan's next due date after it was generated for `due`, or `None`
/// when it does not repeat. Missed periods are skipped, so a plan that was
/// switched off for a year makes one work order, not a burst. Pure.
pub fn next_due_after(
    trigger: Trigger,
    due: NaiveDate,
    interval_days: Option<f64>,
    today: NaiveDate,
) -> Option<NaiveDate> {
    if trigger == Trigger::Meter {
        return None;
    }
    let every = interval_days
        .filter(|d| d.is_finite() && *d >= 1.0)
        .map(|d| d.round() as i64)?;
    let mut next = due.checked_add_signed(Duration::days(every))?;
    while next < today {
        next = next.checked_add_signed(Duration::days(every))?;
    }
    Some(next)
}

/// What one due plan does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Make the work order, then advance the plan.
    Generate,
    /// A work order for this due date exists (a crash after the create):
    /// advance only.
    AdvanceOnly,
    /// Another work order of the plan is still open: make none, advance.
    SkipOpen,
}

/// Decides from what already exists. Pure.
pub fn decide(exists_for_due: bool, open_other: bool) -> Action {
    if exists_for_due {
        Action::AdvanceOnly
    } else if open_other {
        Action::SkipOpen
    } else {
        Action::Generate
    }
}

/// A plan as generation reads it.
#[derive(Debug, Clone, sqlx::FromRow)]
struct PlanRow {
    id: Uuid,
    name: Option<String>,
    asset_ref: Option<Uuid>,
    work_order_type_ref: Option<Uuid>,
    trigger_kind: Option<String>,
    interval_days: Option<f64>,
    lead_days: Option<f64>,
    meter: Option<String>,
    meter_threshold: Option<f64>,
    meter_baseline: Option<f64>,
    next_due_on: Option<NaiveDate>,
    owner: Option<Uuid>,
}

const PLAN_COLUMNS: &str = "id, name, asset_ref, work_order_type_ref, trigger_kind::text AS trigger_kind, \
     interval_days::float8 AS interval_days, lead_days::float8 AS lead_days, meter, \
     meter_threshold::float8 AS meter_threshold, meter_baseline::float8 AS meter_baseline, \
     next_due_on::date AS next_due_on, COALESCE(owner_ref, created_by) AS owner";

/// Whether the pack's generation columns exist (pack 0007 applied).
async fn installed(db: &attome_db::DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('work_order') IS NOT NULL \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = 'maintenance_plan' \
                   AND column_name = 'lead_days') \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = 'work_order' \
                   AND column_name = 'maintenance_plan_ref')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// What one daily run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceRun {
    pub timers_scheduled: u64,
    pub timers_moved: u64,
    pub generated: u64,
}

/// The daily job: keeps each date plan's timer in step and generates for
/// meter plans that are due.
pub async fn tick(state: &EngineState, today: NaiveDate) -> Result<MaintenanceRun, AppError> {
    let db = &state.base.db;
    let mut run = MaintenanceRun::default();
    if !installed(db).await? {
        return Ok(run);
    }
    let sql = format!(
        "SELECT {PLAN_COLUMNS} FROM maintenance_plan \
          WHERE (is_active IS NULL OR is_active = true) AND asset_ref IS NOT NULL \
            AND id > $1 ORDER BY id LIMIT $2"
    );
    let mut after = Uuid::nil();
    loop {
        let plans: Vec<PlanRow> = sqlx::query_as(&sql)
            .bind(after)
            .bind(BATCH)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
        let Some(last) = plans.last().map(|p| p.id) else {
            break;
        };
        for plan in &plans {
            let outcome = match Trigger::parse(plan.trigger_kind.as_deref()) {
                Some(Trigger::Meter) => meter_plan(state, plan, today, &mut run).await,
                Some(_) => keep_timer(db, plan, &mut run).await,
                None => Ok(()),
            };
            if let Err(error) = outcome {
                tracing::warn!(plan = %plan.id, %error, "maintenance generation: plan skipped");
            }
        }
        after = last;
        if (plans.len() as i64) < BATCH {
            break;
        }
    }
    Ok(run)
}

fn follow_payload(plan: &PlanRow) -> serde_json::Value {
    json!({
        "follow": Follow {
            attribute: "next_due_on".to_owned(),
            offset_minutes: -lead(plan.lead_days) * 24 * 60,
            condition: None,
        },
    })
}

/// One pending timer per date plan, due at [`timer_due`].
async fn keep_timer(
    db: &attome_db::DbPool,
    plan: &PlanRow,
    run: &mut MaintenanceRun,
) -> Result<(), AppError> {
    let Some(next) = plan.next_due_on else {
        return Ok(());
    };
    let due_at = timer_due(next, plan.lead_days);
    let mut tx = attome_db::tx::begin(db).await?;
    let pending: Vec<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT due_at FROM timer \
          WHERE kind = $1 AND target_entity = $2 AND target_id = $3 AND status = 'pending' \
          FOR UPDATE",
    )
    .bind(TIMER_KIND)
    .bind(PLAN)
    .bind(plan.id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if pending.is_empty() {
        schedule_timer(&mut tx, plan, due_at).await?;
        run.timers_scheduled += 1;
    } else if pending.iter().any(|d| *d != due_at) {
        attome_core::timer::reschedule_for_target(&mut tx, TIMER_KIND, PLAN, plan.id, due_at)
            .await?;
        run.timers_moved += 1;
    }
    attome_db::tx::commit(tx).await
}

async fn schedule_timer(
    conn: &mut sqlx::PgConnection,
    plan: &PlanRow,
    due_at: DateTime<Utc>,
) -> Result<(), AppError> {
    attome_core::timer::schedule(
        conn,
        &NewTimer {
            kind: TIMER_KIND.to_owned(),
            target_entity: Some(PLAN.to_owned()),
            target_id: Some(plan.id),
            run_id: None,
            due_at,
            payload: follow_payload(plan),
        },
    )
    .await
    .map(|_| ())
}

async fn meter_plan(
    state: &EngineState,
    plan: &PlanRow,
    today: NaiveDate,
    run: &mut MaintenanceRun,
) -> Result<(), AppError> {
    let (Some(asset), Some(meter)) = (plan.asset_ref, plan.meter.as_deref()) else {
        return Ok(());
    };
    let latest: Option<f64> = sqlx::query_scalar(
        "SELECT reading::float8 FROM asset_meter_reading \
          WHERE asset_ref = $1 AND meter = $2 AND (is_active IS NULL OR is_active = true) \
          ORDER BY read_at DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .bind(asset)
    .bind(meter)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    if !meter_due(latest, plan.meter_baseline, plan.meter_threshold) {
        return Ok(());
    }
    if generate(state, plan, today, today, latest).await? {
        run.generated += 1;
    }
    Ok(())
}

/// Runs a fired maintenance timer (`EngineJob::TimerFire` for
/// [`TIMER_KIND`]): when the plan is still active and due, generates.
pub async fn fire(state: &EngineState, timer: &Timer, today: NaiveDate) -> Result<(), AppError> {
    let db = &state.base.db;
    let Some(plan_id) = timer.target_id else {
        return Ok(());
    };
    if !installed(db).await? {
        return Ok(());
    }
    let plan: Option<PlanRow> = sqlx::query_as(&format!(
        "SELECT {PLAN_COLUMNS} FROM maintenance_plan \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) AND asset_ref IS NOT NULL"
    ))
    .bind(plan_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(plan) = plan else {
        return Ok(());
    };
    if matches!(
        Trigger::parse(plan.trigger_kind.as_deref()),
        None | Some(Trigger::Meter)
    ) {
        return Ok(());
    }
    let Some(due) = plan.next_due_on else {
        return Ok(());
    };
    if !date_plan_due(due, plan.lead_days, today) {
        // The date moved later after the timer was set: time it again.
        let mut tx = attome_db::tx::begin(db).await?;
        schedule_timer(&mut tx, &plan, timer_due(due, plan.lead_days)).await?;
        return attome_db::tx::commit(tx).await;
    }
    generate(state, &plan, due, today, None).await.map(|_| ())
}

/// Generates the plan's work order for `due` (unless [`decide`] says not)
/// and advances the plan. Answers whether a work order was made.
async fn generate(
    state: &EngineState,
    plan: &PlanRow,
    due: NaiveDate,
    today: NaiveDate,
    reading: Option<f64>,
) -> Result<bool, AppError> {
    let db = &state.base.db;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM work_order \
          WHERE maintenance_plan_ref = $1 AND maintenance_due_on::date = $2 \
            AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(plan.id)
    .bind(due)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let open_other: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM work_order \
          WHERE maintenance_plan_ref = $1 AND COALESCE(status::text, 'new') NOT IN {CLOSED} \
            AND (is_active IS NULL OR is_active = true))"
    ))
    .bind(plan.id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let action = decide(existing.is_some(), open_other);
    let made = match (action, existing) {
        (Action::Generate, _) => {
            let order = create_order(state, plan, due).await?;
            add_tasks(state, plan, order).await?;
            true
        }
        (Action::AdvanceOnly, Some(order)) => {
            let has_tasks: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM work_order_task WHERE work_order_ref = $1)",
            )
            .bind(order)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            if !has_tasks {
                add_tasks(state, plan, order).await?;
            }
            false
        }
        _ => {
            tracing::info!(plan = %plan.id, %due, "maintenance: a work order is still open, none made");
            false
        }
    };
    advance(db, plan, due, today, reading).await?;
    Ok(made)
}

async fn owner_ctx(
    state: &EngineState,
    plan: &PlanRow,
) -> Result<attome_server::security::SecurityContext, AppError> {
    let owner = plan
        .owner
        .ok_or_else(|| AppError::Validation("the maintenance plan has no owner".into()))?;
    let ctx = state.base.security.resolve_strict(owner).await?;
    ctx.require("work_order", "create")?;
    Ok(ctx)
}

async fn create_order(
    state: &EngineState,
    plan: &PlanRow,
    due: NaiveDate,
) -> Result<Uuid, AppError> {
    let ctx = owner_ctx(state, plan).await?;
    let account: Option<Uuid> = match plan.asset_ref {
        Some(asset) => {
            sqlx::query_scalar("SELECT to_jsonb(a)->>'account_ref' FROM asset a WHERE id = $1")
                .bind(asset)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .flatten()
                .and_then(|s: String| Uuid::parse_str(&s).ok())
        }
        None => None,
    };
    let name = plan
        .name
        .clone()
        .unwrap_or_else(|| "Maintenance".to_owned());
    let mut body = json!({
        "title": format!("{name}: due {due}"),
        "asset_ref": plan.asset_ref,
        "maintenance_plan_ref": plan.id,
        "maintenance_due_on": due.to_string(),
        "scheduled_start": due.to_string(),
        "priority": "normal",
        "status": "new",
    });
    if let Some(kind) = plan.work_order_type_ref {
        body["type_ref"] = json!(kind);
    }
    if let Some(account) = account {
        body["account_ref"] = json!(account);
    }
    let (id, _) = attome_records::entity_crud::create_record_for(
        state,
        &ctx,
        ctx.user_id,
        "work_order",
        body,
    )
    .await?;
    Ok(id)
}

/// One task per template step, in order.
async fn add_tasks(state: &EngineState, plan: &PlanRow, order: Uuid) -> Result<(), AppError> {
    let steps: Vec<(Option<String>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT title, step_order::float8, estimated_minutes::float8 \
           FROM maintenance_task_template \
          WHERE plan_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY step_order NULLS LAST, id",
    )
    .bind(plan.id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if steps.is_empty() {
        return Ok(());
    }
    let ctx = owner_ctx(state, plan).await?;
    ctx.require("work_order_task", "create")?;
    for (index, (title, step, minutes)) in steps.into_iter().enumerate() {
        let body = json!({
            "work_order_ref": order,
            "title": title.unwrap_or_else(|| format!("Step {}", index + 1)),
            "step_order": step.unwrap_or((index + 1) as f64),
            "estimated_minutes": minutes,
            "status": "open",
        });
        attome_records::entity_crud::create_record_for(
            state,
            &ctx,
            ctx.user_id,
            "work_order_task",
            body,
        )
        .await?;
    }
    Ok(())
}

/// Moves the plan past `due` and, for a date plan that repeats, sets its
/// next timer, in one transaction. Guarded on the due date, so a second
/// runner advances nothing.
async fn advance(
    db: &attome_db::DbPool,
    plan: &PlanRow,
    due: NaiveDate,
    today: NaiveDate,
    reading: Option<f64>,
) -> Result<(), AppError> {
    let Some(trigger) = Trigger::parse(plan.trigger_kind.as_deref()) else {
        return Ok(());
    };
    let mut tx = attome_db::tx::begin(db).await?;
    if trigger == Trigger::Meter {
        sqlx::query(
            "UPDATE maintenance_plan SET meter_baseline = $2, last_generated_for = $3, \
                 modified_at = now(), row_version = row_version + 1 WHERE id = $1",
        )
        .bind(plan.id)
        .bind(reading)
        .bind(due)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        return attome_db::tx::commit(tx).await;
    }
    let next = next_due_after(trigger, due, plan.interval_days, today);
    let moved = sqlx::query(
        "UPDATE maintenance_plan SET next_due_on = $3, last_generated_for = $2, \
             modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND next_due_on::date = $2",
    )
    .bind(plan.id)
    .bind(due)
    .bind(next)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if moved == 1
        && let Some(next) = next
    {
        attome_core::timer::cancel_for_target(&mut tx, PLAN, plan.id, Some(TIMER_KIND)).await?;
        schedule_timer(&mut tx, plan, timer_due(next, plan.lead_days)).await?;
    }
    attome_db::tx::commit(tx).await
}

#[cfg(test)]
mod maintenance_generation {
    use super::*;

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, m, d).expect("a real date")
    }

    #[test]
    fn a_date_plan_comes_due_its_lead_time_early() {
        let due = day(5, 15);
        assert!(!date_plan_due(due, Some(7.0), day(5, 7)));
        assert!(date_plan_due(due, Some(7.0), day(5, 8)));
        assert!(date_plan_due(due, None, day(5, 15)));
        assert!(!date_plan_due(due, None, day(5, 14)));
        assert_eq!(timer_due(due, Some(7.0)).date_naive(), day(5, 8));
    }

    #[test]
    fn lead_time_is_bounded() {
        assert_eq!(timer_due(day(5, 15), Some(-3.0)).date_naive(), day(5, 15));
        assert_eq!(
            timer_due(day(5, 15), Some(10_000.0)).date_naive(),
            day(5, 15) - Duration::days(MAX_LEAD_DAYS)
        );
        assert_eq!(
            timer_due(day(5, 15), Some(f64::NAN)).date_naive(),
            day(5, 15)
        );
    }

    #[test]
    fn a_repeating_plan_advances_by_its_interval_skipping_missed_periods() {
        assert_eq!(
            next_due_after(Trigger::EveryNDays, day(5, 15), Some(30.0), day(5, 10)),
            Some(day(6, 14))
        );
        // Off for months: one step past today, not a burst.
        assert_eq!(
            next_due_after(Trigger::EveryNDays, day(1, 1), Some(30.0), day(5, 1)),
            Some(day(5, 1))
        );
        assert_eq!(
            next_due_after(Trigger::CalendarDate, day(5, 15), None, day(5, 10)),
            None,
            "a one-off calendar date does not repeat"
        );
        assert_eq!(
            next_due_after(Trigger::EveryNDays, day(5, 15), Some(0.0), day(5, 10)),
            None
        );
    }

    #[test]
    fn a_meter_plan_is_due_when_the_reading_rises_by_the_threshold() {
        assert!(meter_due(Some(5_000.0), None, Some(5_000.0)));
        assert!(!meter_due(Some(4_999.0), None, Some(5_000.0)));
        assert!(meter_due(Some(10_500.0), Some(5_200.0), Some(5_000.0)));
        assert!(!meter_due(Some(10_000.0), Some(5_200.0), Some(5_000.0)));
        assert!(!meter_due(None, None, Some(5_000.0)));
        assert!(!meter_due(Some(9.0), None, Some(0.0)));
    }

    #[test]
    fn a_work_order_is_made_once_and_never_beside_an_open_one() {
        assert_eq!(decide(false, false), Action::Generate);
        assert_eq!(decide(true, false), Action::AdvanceOnly);
        assert_eq!(decide(true, true), Action::AdvanceOnly);
        assert_eq!(decide(false, true), Action::SkipOpen);
    }

    #[test]
    fn a_fake_clock_walks_a_plan_through_two_periods() {
        // Lead 5 days, every 30 days, first due 1 March.
        let mut due = day(3, 1);
        let mut made = Vec::new();
        let mut today = day(2, 20);
        while today <= day(4, 30) {
            if date_plan_due(due, Some(5.0), today) {
                // The technician closes each order within its period.
                if decide(made.contains(&due), false) == Action::Generate {
                    made.push(due);
                }
                due = next_due_after(Trigger::EveryNDays, due, Some(30.0), today).expect("repeats");
            }
            today += Duration::days(1);
        }
        assert_eq!(made, vec![day(3, 1), day(3, 31), day(4, 30)]);
    }
}
