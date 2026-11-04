//! Call analysis actions (roadmap D22-T10).
//!
//! - `callintel.search_calls(tracker, from?, to?)`: calls whose analysis hit
//!   a tracker, each with the moments (`activity_id`, `start_ms`).
//! - `callintel.deal_highlights(opportunity_id)`: a deal's calls and their
//!   findings (questions, objections, next steps, competitor and price
//!   mentions), each linked to its moment.
//! - `callintel.coaching_brief(user_id, from?, to?)`: one person's calls in a
//!   period with their talk patterns and scorecard answers, only for that
//!   person or a manager of theirs (a position above theirs); anyone else is
//!   refused as not found.
//!
//! All read, as the caller: `call_analysis.read` and, for each call, read
//! access to its activity through the record engine. This crate reads the
//! call tables directly because attome-callintel depends on it.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CALLINTEL;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// One call finding as read: the activity, its kind, its start and its text.
type FindingRow = (String, Option<String>, Option<f64>, Option<String>);

pub const SEARCH_CALLS: &str = "callintel.search_calls";
pub const DEAL_HIGHLIGHTS: &str = "callintel.deal_highlights";
pub const COACHING_BRIEF: &str = "callintel.coaching_brief";
/// Calls listed at most.
const MAX_CALLS: i64 = 50;

const SEARCH_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "tracker": { "type": "string", "minLength": 1, "maxLength": 200, "description": "A tracker's name." },
    "from": { "type": "string", "format": "date" },
    "to": { "type": "string", "format": "date" }
  },
  "required": ["tracker"],
  "additionalProperties": false
}"#;

const DEAL_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "opportunity_id": { "type": "string", "format": "uuid" } },
  "required": ["opportunity_id"],
  "additionalProperties": false
}"#;

const BRIEF_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "user_id": { "type": "string", "format": "uuid" },
    "from": { "type": "string", "format": "date" },
    "to": { "type": "string", "format": "date" }
  },
  "required": ["user_id"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CALLINTEL,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            SEARCH_CALLS,
            "Find calls where a tracker was heard, between two dates, with each moment (call and \
             second) so you can link to it.",
            SEARCH_SCHEMA,
        ),
        read(
            DEAL_HIGHLIGHTS,
            "List a deal's call highlights: questions, objections, next steps, competitor and \
             price mentions, each linked to its moment in the call.",
            DEAL_SCHEMA,
        ),
        read(
            COACHING_BRIEF,
            "Prepare a coaching brief for a person: their calls in a period with talk patterns \
             and scorecard answers. Only for the person themselves or their manager.",
            BRIEF_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(SearchCalls),
        Box::new(DealHighlights),
        Box::new(CoachingBrief),
    ]
}

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>>;

/// A link to a moment of a call. Pure.
pub fn moment(activity_id: &str, start_ms: Option<f64>) -> Value {
    let second = start_ms.map(|ms| (ms / 1000.0).floor() as i64);
    json!({
        "activity_id": activity_id,
        "start_ms": start_ms,
        "link": match second {
            Some(s) => format!("/xrm/entity/activity/{activity_id}?t={s}"),
            None => format!("/xrm/entity/activity/{activity_id}"),
        },
    })
}

fn date_arg(args: &Value, key: &str) -> Result<Option<chrono::NaiveDate>, AppError> {
    match args[key].as_str() {
        None => Ok(None),
        Some(s) => chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
            .map(Some)
            .map_err(|_| AppError::Validation(format!("{key} is a date (YYYY-MM-DD)"))),
    }
}

/// Whether the caller may read the call's activity.
async fn readable(state: &EngineState, ctx: &ActionContext, activity: &str) -> bool {
    let Ok(id) = Uuid::parse_str(activity) else {
        return false;
    };
    attome_records::entity_crud::read_record(state, &ctx.security, "activity", id)
        .await
        .is_ok()
}

struct SearchCalls;

impl Action for SearchCalls {
    fn id(&self) -> ActionId {
        ActionId(SEARCH_CALLS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            ctx.security.require("call_analysis", "read")?;
            let tracker = args["tracker"]
                .as_str()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .ok_or_else(|| AppError::Validation("tracker is required".into()))?;
            let (from, to) = (date_arg(args, "from")?, date_arg(args, "to")?);
            let rows: Vec<(String, Option<f64>, Option<String>)> = sqlx::query_as(
                "SELECT a.activity_id, f.start_ms::float8, f.text \
                   FROM call_finding f \
                   JOIN call_analysis a ON a.id = f.analysis_ref \
                   JOIN call_tracker t ON t.id = f.tracker_ref \
                  WHERE (t.name ILIKE $1 OR t.name_ar = $1) \
                    AND ($2::date IS NULL OR a.analysed_at::date >= $2) \
                    AND ($3::date IS NULL OR a.analysed_at::date <= $3) \
                    AND (f.is_active IS NULL OR f.is_active = true) \
                  ORDER BY a.analysed_at DESC, f.start_ms LIMIT $4",
            )
            .bind(tracker)
            .bind(from)
            .bind(to)
            .bind(MAX_CALLS * 5)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let mut hits = Vec::new();
            for (activity, at, text) in rows {
                if !readable(state, ctx, &activity).await {
                    continue;
                }
                let mut m = moment(&activity, at);
                m["text"] = json!(text);
                hits.push(m);
            }
            Ok(ActionResult::plain(
                json!({ "tracker": tracker, "hits": hits }),
            ))
        })
    }
}

struct DealHighlights;

impl Action for DealHighlights {
    fn id(&self) -> ActionId {
        ActionId(DEAL_HIGHLIGHTS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            ctx.security.require("call_analysis", "read")?;
            let deal = args["opportunity_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("opportunity_id must be a UUID".into()))?;
            attome_records::entity_crud::read_record(state, &ctx.security, "opportunity", deal)
                .await?;
            let rows: Vec<FindingRow> = sqlx::query_as(
                "SELECT a.activity_id, f.kind::text, f.start_ms::float8, f.text \
                       FROM call_finding f JOIN call_analysis a ON a.id = f.analysis_ref \
                      WHERE a.opportunity_id = $1 \
                        AND f.kind::text IN ('question', 'objection', 'next_step', \
                                             'competitor_mention', 'price_mention') \
                        AND (f.is_active IS NULL OR f.is_active = true) \
                      ORDER BY a.analysed_at DESC, f.start_ms LIMIT $2",
            )
            .bind(deal.to_string())
            .bind(MAX_CALLS * 5)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let mut highlights = Vec::new();
            for (activity, kind, at, text) in rows {
                if !readable(state, ctx, &activity).await {
                    continue;
                }
                let mut m = moment(&activity, at);
                m["kind"] = json!(kind);
                m["text"] = json!(text);
                highlights.push(m);
            }
            Ok(ActionResult::plain(
                json!({ "opportunity_id": deal, "highlights": highlights }),
            ))
        })
    }
}

/// Whether `manager` holds a position above any of `user`'s.
async fn is_manager_of(state: &EngineState, manager: Uuid, user: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "WITH RECURSIVE above(id, depth) AS ( \
             SELECT p.parent_position_ref, 1 FROM user_account_mm_position m \
               JOIN position p ON p.id = m.position_ref AND p.is_deleted = false \
              WHERE m.user_ref = $2 AND m.is_deleted = false \
             UNION \
             SELECT p.parent_position_ref, a.depth + 1 FROM above a \
               JOIN position p ON p.id = a.id AND p.is_deleted = false \
              WHERE a.depth < 20) \
         SELECT EXISTS (SELECT 1 FROM above a \
                          JOIN user_account_mm_position m \
                            ON m.position_ref = a.id AND m.is_deleted = false \
                         WHERE m.user_ref = $1)",
    )
    .bind(manager)
    .bind(user)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

struct CoachingBrief;

type BriefRow = (
    Uuid,
    String,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

impl Action for CoachingBrief {
    fn id(&self) -> ActionId {
        ActionId(COACHING_BRIEF)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            ctx.security.require("call_analysis", "read")?;
            let person = args["user_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("user_id must be a UUID".into()))?;
            let me = ctx.security.user_id;
            if me != person && !is_manager_of(state, me, person).await? {
                // A peer's coaching data is not there for them.
                return Err(AppError::NotFound);
            }
            let (from, to) = (date_arg(args, "from")?, date_arg(args, "to")?);
            let calls: Vec<BriefRow> = sqlx::query_as(
                "SELECT id, activity_id, staff_talk_share::float8, longest_monologue_s::float8, \
                        staff_questions::float8, interruptions::float8 \
                   FROM call_analysis \
                  WHERE owner_user = $1 AND status::text = 'done' \
                    AND ($2::date IS NULL OR analysed_at::date >= $2) \
                    AND ($3::date IS NULL OR analysed_at::date <= $3) \
                    AND (is_active IS NULL OR is_active = true) \
                  ORDER BY analysed_at DESC LIMIT $4",
            )
            .bind(person)
            .bind(from)
            .bind(to)
            .bind(MAX_CALLS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let mut out = Vec::with_capacity(calls.len());
            for (analysis, activity, share, monologue, questions, interruptions) in calls {
                let answers: Vec<(Option<String>, Option<String>, Option<String>)> =
                    sqlx::query_as(
                        "SELECT question_key, proposed_value::text, confirmed_value::text \
                           FROM call_scorecard_answer \
                          WHERE analysis_ref = $1 AND (is_active IS NULL OR is_active = true) \
                          ORDER BY question_key",
                    )
                    .bind(analysis)
                    .fetch_all(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                let mut call = moment(&activity, None);
                call["talk"] = json!({
                    "staff_talk_share": share, "longest_monologue_s": monologue,
                    "staff_questions": questions, "interruptions": interruptions,
                });
                call["scorecard"] =
                    json!(answers
                    .into_iter()
                    .map(|(k, p, c)| json!({ "question_key": k, "proposed": p, "confirmed": c }))
                    .collect::<Vec<_>>());
                out.push(call);
            }
            Ok(ActionResult::plain(
                json!({ "user_id": person, "calls": out }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deal_highlights_link_to_moments() {
        let m = moment("0198a0a0-0000-7000-8000-000000000001", Some(65_400.0));
        assert_eq!(m["start_ms"], 65_400.0);
        assert_eq!(
            m["link"],
            "/xrm/entity/activity/0198a0a0-0000-7000-8000-000000000001?t=65"
        );
        let all = descriptors();
        assert!(
            all.iter()
                .all(|d| d.risk == RiskTier::Read && d.effect == Effect::Read)
        );
    }
}
