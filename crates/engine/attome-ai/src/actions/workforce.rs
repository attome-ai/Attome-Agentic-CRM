//! Workforce actions (roadmap G17-T15).
//!
//! - `workforce.coverage(schedule_id)`: a schedule's requirement, coverage
//!   and under- and over-staffing per day (the what-if path with no changes).
//! - `workforce.explain_gap(schedule_id, interval_start)`: why one interval
//!   is short: requirement against coverage, who works then, and which group
//!   members are free that day.
//! - `workforce.my_next_day_off()`: the caller's next day with no published
//!   shift in the coming 60 days.
//! - `workforce.propose_fix(schedule_id)`: for every short interval of a
//!   **draft** schedule, the free members who could cover it, as a proposal
//!   a planner applies through the schedule routes. It writes nothing.
//!
//! Every action refuses a published schedule ([`refuse_published`]); none
//! changes one. They read through `attome_workforce`, as the schedule routes
//! do.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_WORKFORCE;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const COVERAGE: &str = "workforce.coverage";
pub const EXPLAIN_GAP: &str = "workforce.explain_gap";
pub const MY_NEXT_DAY_OFF: &str = "workforce.my_next_day_off";
pub const PROPOSE_FIX: &str = "workforce.propose_fix";

const SCHEDULE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "schedule_id": { "type": "string", "format": "uuid" } },
  "required": ["schedule_id"],
  "additionalProperties": false
}"#;

const GAP_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "schedule_id": { "type": "string", "format": "uuid" },
    "interval_start": { "type": "string", "format": "date-time", "description": "The interval's start (UTC)." }
  },
  "required": ["schedule_id", "interval_start"],
  "additionalProperties": false
}"#;

const NONE_SCHEMA: &str =
    r#"{ "type": "object", "properties": {}, "additionalProperties": false }"#;

/// How far ahead the next day off is looked for.
const DAY_OFF_HORIZON: i64 = 60;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_WORKFORCE,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            COVERAGE,
            "Show a draft schedule's staffing requirement, coverage and under- and over-staffing \
             per day. Refused for a published schedule.",
            SCHEDULE_SCHEMA,
        ),
        read(
            EXPLAIN_GAP,
            "Explain why one interval of a draft schedule is short: requirement against coverage, \
             who works then and which group members are free that day.",
            GAP_SCHEMA,
        ),
        read(
            MY_NEXT_DAY_OFF,
            "Answer when the caller's next day off is: the first day in the coming 60 days with \
             no published shift.",
            NONE_SCHEMA,
        ),
        read(
            PROPOSE_FIX,
            "Propose how to fill a draft schedule's short intervals: for each, the free group \
             members who could cover it. A proposal only; a planner applies it.",
            SCHEDULE_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Coverage),
        Box::new(ExplainGap),
        Box::new(MyNextDayOff),
        Box::new(ProposeFix),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

/// Refuses a published (or superseded) schedule: these actions work on
/// drafts and never change a published one. Pure.
pub fn refuse_published(status: Option<&str>) -> Result<(), AppError> {
    match status {
        Some("draft") => Ok(()),
        Some("published") => Err(AppError::Conflict(
            "this schedule is published; workforce actions work on drafts and never change it",
        )),
        _ => Err(AppError::Conflict("only a draft schedule is worked on")),
    }
}

/// The first day from `from` on which no shift starts. Pure.
pub fn next_free_day(from: NaiveDate, worked: &[NaiveDate], horizon: i64) -> Option<NaiveDate> {
    (0..horizon)
        .map(|d| from + Duration::days(d))
        .find(|d| !worked.contains(d))
}

async fn schedule_status(
    state: &EngineState,
    id: Uuid,
) -> Result<(Option<String>, Option<Uuid>), AppError> {
    sqlx::query_as(
        "SELECT status::text, planning_group_ref FROM wfm_schedule \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn draft_what_if(
    state: &EngineState,
    ctx: &ActionContext,
    schedule: Uuid,
) -> Result<(attome_workforce::what_if::WhatIf, Option<Uuid>), AppError> {
    ctx.security.require("wfm_schedule", "read")?;
    let (status, group) = schedule_status(state, schedule).await?;
    refuse_published(status.as_deref())?;
    let w = attome_workforce::what_if::what_if(
        state,
        schedule,
        &attome_workforce::what_if::WhatIfBody::default(),
    )
    .await?;
    Ok((w, group))
}

/// Members of `group` with no shift of `schedule` on `day`.
async fn free_members(
    state: &EngineState,
    schedule: Uuid,
    group: Option<Uuid>,
    day: NaiveDate,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT m.user_ref FROM wfm_group_member m \
          WHERE m.planning_group_ref = $1 AND m.user_ref IS NOT NULL \
            AND (m.is_active IS NULL OR m.is_active = true) \
            AND NOT EXISTS (SELECT 1 FROM wfm_shift_assignment a \
                 WHERE a.schedule_ref = $2 AND a.user_ref = m.user_ref \
                   AND a.start_at::date = $3 AND (a.is_active IS NULL OR a.is_active = true)) \
            AND NOT EXISTS (SELECT 1 FROM resource_availability l \
                 WHERE l.user_id = m.user_ref AND l.is_active IS NOT FALSE \
                   AND l.leave_start::date <= $3 AND l.leave_end::date >= $3) \
          ORDER BY m.user_ref LIMIT 100",
    )
    .bind(group)
    .bind(schedule)
    .bind(day)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>>;

struct Coverage;

impl Action for Coverage {
    fn id(&self) -> ActionId {
        ActionId(COVERAGE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let schedule = uuid_arg(args, "schedule_id")?;
            let (w, _) = draft_what_if(state, ctx, schedule).await?;
            let days: Vec<Value> = w
                .days
                .iter()
                .map(|d| json!({ "day": d.day, "under": d.under, "over": d.over }))
                .collect();
            Ok(ActionResult::plain(json!({
                "schedule_id": schedule, "under": w.under, "over": w.over, "days": days,
            })))
        })
    }
}

struct ExplainGap;

impl Action for ExplainGap {
    fn id(&self) -> ActionId {
        ActionId(EXPLAIN_GAP)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let schedule = uuid_arg(args, "schedule_id")?;
            let at: DateTime<Utc> = args["interval_start"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
                .ok_or_else(|| {
                    AppError::Validation("interval_start must be an RFC 3339 time".into())
                })?;
            let (w, group) = draft_what_if(state, ctx, schedule).await?;
            let day = at.date_naive();
            let Some(d) = w.days.iter().find(|d| d.day == day) else {
                return Err(AppError::Validation(
                    "interval_start is outside the schedule".into(),
                ));
            };
            let slots = d.requirement.len().max(1);
            let minutes = (24 * 60) / slots as i64;
            let midnight = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
            let index =
                usize::try_from((at - midnight).num_minutes() / minutes.max(1)).unwrap_or(0);
            let working: Vec<Uuid> = sqlx::query_scalar(
                "SELECT user_ref FROM wfm_shift_assignment WHERE schedule_ref = $1 \
                   AND activity = 'work' AND start_at::timestamptz <= $2 AND end_at::timestamptz > $2 \
                   AND (is_active IS NULL OR is_active = true)",
            )
            .bind(schedule)
            .bind(at)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let free = free_members(state, schedule, group, day).await?;
            Ok(ActionResult::plain(json!({
                "interval_start": at,
                "requirement": d.requirement.get(index),
                "coverage": d.coverage.get(index),
                "working": working,
                "free_members": free,
            })))
        })
    }
}

struct MyNextDayOff;

impl Action for MyNextDayOff {
    fn id(&self) -> ActionId {
        ActionId(MY_NEXT_DAY_OFF)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let today = Utc::now().date_naive();
            let worked: Vec<NaiveDate> = sqlx::query_scalar(
                "SELECT DISTINCT a.start_at::date FROM wfm_shift_assignment a \
                   JOIN wfm_schedule s ON s.id = a.schedule_ref \
                  WHERE a.user_ref = $1 AND s.status = 'published' AND a.activity = 'work' \
                    AND a.start_at::date >= $2 AND a.start_at::date < $3 \
                    AND (a.is_active IS NULL OR a.is_active = true)",
            )
            .bind(ctx.security.user_id)
            .bind(today)
            .bind(today + Duration::days(DAY_OFF_HORIZON))
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(ActionResult::plain(json!({
                "next_day_off": next_free_day(today, &worked, DAY_OFF_HORIZON),
            })))
        })
    }
}

struct ProposeFix;

impl Action for ProposeFix {
    fn id(&self) -> ActionId {
        ActionId(PROPOSE_FIX)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let schedule = uuid_arg(args, "schedule_id")?;
            let (w, group) = draft_what_if(state, ctx, schedule).await?;
            let mut proposals = Vec::new();
            for d in w.days.iter().filter(|d| d.under > 0) {
                let free = free_members(state, schedule, group, d.day).await?;
                let short: Vec<usize> = d
                    .requirement
                    .iter()
                    .zip(&d.coverage)
                    .enumerate()
                    .filter(|(_, (need, have))| have < need)
                    .map(|(i, _)| i)
                    .collect();
                proposals.push(json!({
                    "day": d.day,
                    "short_intervals": short,
                    "agents_short": d.under,
                    "could_cover": free,
                }));
            }
            Ok(ActionResult::plain(json!({
                "schedule_id": schedule,
                "proposals": proposals,
                "note": "A proposal only: a planner applies it by editing the draft's assignments.",
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_published_schedule() {
        assert!(refuse_published(Some("draft")).is_ok());
        assert!(matches!(
            refuse_published(Some("published")),
            Err(AppError::Conflict(_))
        ));
        assert!(refuse_published(Some("superseded")).is_err());
        assert!(refuse_published(None).is_err());
    }

    #[test]
    fn descriptors_have_valid_schema() {
        for d in descriptors() {
            let schema: Value = serde_json::from_str(match d.id.0 {
                EXPLAIN_GAP => GAP_SCHEMA,
                MY_NEXT_DAY_OFF => NONE_SCHEMA,
                _ => SCHEDULE_SCHEMA,
            })
            .expect("valid JSON");
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
        }
        assert_eq!(descriptors().len(), 4);
        assert_eq!(executors().len(), 4);
    }

    #[test]
    fn the_next_day_off_skips_worked_days() {
        let d = |n| NaiveDate::from_ymd_opt(2027, 3, n).expect("a date");
        assert_eq!(next_free_day(d(1), &[d(1), d(2)], 60), Some(d(3)));
        assert_eq!(next_free_day(d(1), &[], 60), Some(d(1)));
        assert_eq!(next_free_day(d(1), &[d(1)], 1), None);
    }
}
