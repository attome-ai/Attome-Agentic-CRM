//! Z12-T12: an agent proposes holiday changes; a person approves them.
//!
//! - `calendar.list_holidays` (Read) — a calendar's holidays in one year,
//!   as the calendar engine expands them (rules, seasons and sightings
//!   included), with the names stored for the dated ones.
//! - `calendar.propose_holiday` (Consequential) — adds or renames a dated
//!   holiday. An agent never writes it directly: the Consequential path
//!   turns the call into an approval request, and the holiday is written
//!   only when an administrator approves it.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use chrono::{Datelike, NaiveDate};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const CALENDAR_LIST_HOLIDAYS: &str = "calendar.list_holidays";
pub const CALENDAR_PROPOSE_HOLIDAY: &str = "calendar.propose_holiday";

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            CALENDAR_LIST_HOLIDAYS,
            "List a business calendar's holidays in one year (dated holidays, recurring rules and \
             confirmed sightings, inherited ones included), each with its name when one is stored.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{"type": "object", "required": ["calendar_id", "year"], "properties": {"calendar_id": {"type": "string", "format": "uuid"}, "year": {"type": "integer", "minimum": 2000, "maximum": 2100}}, "additionalProperties": false}"#,
        ),
        ActionDescriptor::new(
            CALENDAR_PROPOSE_HOLIDAY,
            "Propose adding a holiday on a date to a business calendar, or renaming the one on that \
             date, with the reason. An administrator approves it before it takes effect.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{"type": "object", "required": ["calendar_id", "name", "date", "reason"], "properties": {"calendar_id": {"type": "string", "format": "uuid"}, "name": {"type": "string", "minLength": 1, "maxLength": 200}, "name_ar": {"type": "string", "maxLength": 200}, "date": {"type": "string", "format": "date"}, "reason": {"type": "string", "minLength": 1, "maxLength": 2000}}, "additionalProperties": false}"#,
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(CalendarListHolidays),
        Box::new(CalendarProposeHoliday),
    ]
}

fn calendar_id(args: &Value) -> Result<Uuid, AppError> {
    args["calendar_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("calendar_id is a calendar id".into()))
}

/// A holiday proposal's checked fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub calendar: Uuid,
    pub name: String,
    pub name_ar: Option<String>,
    pub date: NaiveDate,
    pub reason: String,
}

/// A proposal's checked fields. Pure.
pub fn proposal(args: &Value) -> Result<Proposal, AppError> {
    let calendar = calendar_id(args)?;
    let text = |key: &str, max: usize| {
        args[key]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.chars().count() <= max)
            .map(str::to_owned)
    };
    let name = text("name", 200)
        .ok_or_else(|| AppError::Validation("name is 1 to 200 characters".into()))?;
    let reason = text("reason", 2000)
        .ok_or_else(|| AppError::Validation("reason is 1 to 2000 characters".into()))?;
    let date = args["date"]
        .as_str()
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .ok_or_else(|| AppError::Validation("date is YYYY-MM-DD".into()))?;
    Ok(Proposal {
        calendar,
        name,
        name_ar: text("name_ar", 200),
        date,
        reason,
    })
}

pub(crate) struct CalendarListHolidays;

impl Action for CalendarListHolidays {
    fn id(&self) -> ActionId {
        ActionId(CALENDAR_LIST_HOLIDAYS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = calendar_id(args)?;
            let year = args["year"]
                .as_i64()
                .and_then(|y| i32::try_from(y).ok())
                .filter(|y| (2000..=2100).contains(y))
                .ok_or_else(|| AppError::Validation("year is 2000 to 2100".into()))?;
            let loaded = attome_core::calendar::load_calendar(&state.base.db, id)
                .await?
                .map_err(|unresolved| AppError::Validation(unresolved.to_string()))?;
            let names: Vec<(NaiveDate, String)> = sqlx::query_as(
                "SELECT holiday_date, name FROM calendar_holiday \
                  WHERE calendar_id = $1 AND is_active = true \
                    AND holiday_date >= make_date($2, 1, 1) AND holiday_date < make_date($2 + 1, 1, 1)",
            )
            .bind(id)
            .bind(year)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let holidays: Vec<Value> = loaded
                .calendar
                .holidays()
                .iter()
                .filter(|d| d.year() == year)
                .map(|d| {
                    let name = names.iter().find(|(nd, _)| nd == d).map(|(_, n)| n);
                    json!({ "date": d, "name": name })
                })
                .collect();
            Ok(ActionResult::plain(json!({
                "calendar_id": id,
                "year": year,
                "holidays": holidays,
            })))
        })
    }
}

pub(crate) struct CalendarProposeHoliday;

impl Action for CalendarProposeHoliday {
    fn id(&self) -> ActionId {
        ActionId(CALENDAR_PROPOSE_HOLIDAY)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // Reached only once approved, for an agent (the Consequential
            // path holds the call until an administrator decides it).
            let Proposal {
                calendar,
                name,
                name_ar,
                date,
                reason,
            } = proposal(args)?;
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM calendar WHERE id = $1)")
                    .bind(calendar)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            if !exists {
                return Err(AppError::NotFound);
            }
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO calendar_holiday \
                     (id, calendar_id, name, name_ar, holiday_date, is_active, created_at, created_by, \
                      owner_layer, source) \
                 VALUES (uuidv7(), $1, $2, $3, $4, true, now(), $5, 'customer', 'manual') \
                 ON CONFLICT (calendar_id, holiday_date) WHERE is_active = true DO UPDATE \
                    SET name = EXCLUDED.name, name_ar = COALESCE(EXCLUDED.name_ar, calendar_holiday.name_ar), \
                        row_version = calendar_holiday.row_version + 1 \
                 RETURNING id",
            )
            .bind(calendar)
            .bind(&name)
            .bind(&name_ar)
            .bind(date)
            .bind(ctx.security.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_audit::write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(state),
                attome_audit::BusinessEvent::new(
                    "calendar",
                    calendar,
                    attome_audit::AuditOperation::Update,
                    "calendar.holiday_proposed",
                    ctx.security.user_id,
                )
                .comment(format!("{date} {name}: {reason}")),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(ActionResult::plain(json!({
                "holiday_id": id,
                "calendar_id": calendar,
                "date": date,
                "name": name,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_holiday_proposal_is_consequential_and_checked() {
        let d = descriptors();
        assert_eq!(d[1].risk, RiskTier::Consequential);
        assert_eq!(d[0].risk, RiskTier::Read);
        assert_eq!(executors().len(), d.len());
        let id = Uuid::now_v7();
        let ok = json!({"calendar_id": id, "name": " National Day ", "date": "2027-09-23", "reason": "official"});
        let p = proposal(&ok).unwrap();
        assert_eq!(p.calendar, id);
        assert_eq!(p.name, "National Day");
        assert!(p.name_ar.is_none());
        assert_eq!(p.date, NaiveDate::from_ymd_opt(2027, 9, 23).unwrap());
        assert!(
            proposal(&json!({"calendar_id": id, "name": "x", "date": "23/09/2027", "reason": "r"}))
                .is_err()
        );
        assert!(proposal(&json!({"calendar_id": id, "name": "x", "date": "2027-09-23"})).is_err());
    }
}
