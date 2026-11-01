//! Segment actions (roadmap E7-T11), read-only:
//!
//! - `segment.explain_change` explains why a marketing list's size changed
//!   between two dates: how many people entered and left, grouped by the
//!   reason the membership event recorded (`scheduled`, `live`, `manual`,
//!   an import, a form, a flow).
//!
//! It needs the caller's `marketing_list.read` and a list they may read,
//! and is hidden without the marketing module. Only counts reach the model,
//! never a person.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_MARKETING;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EXPLAIN_CHANGE: &str = "segment.explain_change";

/// The longest window one explanation reads.
const MAX_DAYS: i64 = 366;

const EXPLAIN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "list_id": { "type": "string", "format": "uuid" },
    "from": { "type": "string", "format": "date" },
    "to": { "type": "string", "format": "date", "description": "inclusive" }
  },
  "required": ["list_id", "from", "to"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            EXPLAIN_CHANGE,
            "Explain a change in a marketing list's size between two dates: how many people \
             entered and left, grouped by why (a scheduled or live refresh, a manual change, \
             an import, a form or a flow).",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_MARKETING,
            &[],
        )
        .input_schema(EXPLAIN_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(Segment(EXPLAIN_CHANGE))]
}

/// One reason's movement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonCount {
    pub reason: String,
    pub entered: i64,
    pub left: i64,
}

/// `(change, reason, count)` rows grouped by reason, the biggest movement
/// first. Pure.
pub fn group_by_reason(rows: &[(String, String, i64)]) -> Vec<ReasonCount> {
    let mut out: Vec<ReasonCount> = Vec::new();
    for (change, reason, n) in rows {
        let at = match out.iter().position(|r| &r.reason == reason) {
            Some(at) => at,
            None => {
                out.push(ReasonCount {
                    reason: reason.clone(),
                    entered: 0,
                    left: 0,
                });
                out.len() - 1
            }
        };
        match change.as_str() {
            "entered" => out[at].entered += n,
            "left" => out[at].left += n,
            _ => {}
        }
    }
    out.sort_by(|a, b| {
        (b.entered + b.left)
            .cmp(&(a.entered + a.left))
            .then_with(|| a.reason.cmp(&b.reason))
    });
    out
}

fn date_arg(args: &Value, key: &str) -> Result<NaiveDate, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a date, YYYY-MM-DD")))
}

fn day_start(d: NaiveDate) -> DateTime<Utc> {
    d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc()
}

struct Segment(&'static str);

impl Action for Segment {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("marketing_list", "read")?;
            match self.0 {
                EXPLAIN_CHANGE => {
                    let list: Uuid = args
                        .get("list_id")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| AppError::Validation("list_id must be an id".into()))?;
                    let (from, to) = (date_arg(args, "from")?, date_arg(args, "to")?);
                    let days = (to - from).num_days() + 1;
                    if !(1..=MAX_DAYS).contains(&days) {
                        return Err(AppError::Validation(format!(
                            "to is on or after from, at most {MAX_DAYS} days later"
                        )));
                    }
                    if !attome_records::entity_crud::referenced_record_visible(
                        state,
                        &ctx.security,
                        "marketing_list",
                        list,
                    )
                    .await?
                    {
                        return Err(AppError::NotFound);
                    }
                    let rows: Vec<(String, String, i64)> = sqlx::query_as(
                        "SELECT change, reason, COUNT(*) FROM marketing_list_membership_event \
                          WHERE list_id = $1 AND at >= $2 AND at < $3 \
                          GROUP BY change, reason",
                    )
                    .bind(list)
                    .bind(day_start(from))
                    .bind(day_start(to + Duration::days(1)))
                    .fetch_all(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    let reasons = group_by_reason(&rows);
                    let entered: i64 = reasons.iter().map(|r| r.entered).sum();
                    let left: i64 = reasons.iter().map(|r| r.left).sum();
                    Ok(ActionResult::plain(json!({
                        "list_id": list,
                        "window": { "from": from, "to": to },
                        "entered": entered,
                        "left": left,
                        "net": entered - left,
                        "by_reason": reasons,
                    })))
                }
                _ => Err(AppError::NotFound),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_change_groups_by_reason() {
        let rows = vec![
            ("entered".to_owned(), "scheduled".to_owned(), 40),
            ("left".to_owned(), "scheduled".to_owned(), 5),
            ("entered".to_owned(), "manual".to_owned(), 3),
            ("left".to_owned(), "live".to_owned(), 12),
        ];
        let grouped = group_by_reason(&rows);
        assert_eq!(grouped[0].reason, "scheduled");
        assert_eq!((grouped[0].entered, grouped[0].left), (40, 5));
        assert_eq!(grouped[1].reason, "live");
        assert_eq!(grouped.len(), 3);
    }

    #[test]
    fn hidden_without_module() {
        for d in descriptors() {
            assert_eq!(d.module, MODULE_MARKETING, "{}", d.id.0);
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        }
        assert_eq!(executors().len(), descriptors().len());
    }
}
