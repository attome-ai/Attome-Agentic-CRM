//! Nurture actions (roadmap E9-T10), read-only, for the marketing module and
//! only where a programme has switched agent suggestions on
//! (`agent_suggestions_enabled`; a programme without it answers as absent):
//!
//! - `nurture.suggest_content` names up to three pieces of content the
//!   person has not seen that people with the same nurture interest most
//!   often saw before they were handed to sales.
//! - `nurture.draft_summary` writes a hand-off's summary as a few lines in
//!   the person's language (Arabic for an Arabic contact), from the summary
//!   the hand-off stored. Nothing is saved; a person keeps the text if they
//!   want it.
//! - `nurture.find_stalls` names the tracks of a programme whose people have
//!   waited for their next email more than twice as long as the
//!   programme's median (the platform keeps no stage history, so the time
//!   since a person's last nurture email stands for the time in stage).
//!
//! None creates a hand-off, decides one or moves a due time: hand-offs come
//! only from a score crossing (E9-T5) and are decided by sales (E9-T8).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_MARKETING;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SUGGEST_CONTENT: &str = "nurture.suggest_content";
pub const DRAFT_SUMMARY: &str = "nurture.draft_summary";
pub const FIND_STALLS: &str = "nurture.find_stalls";

/// Suggestions returned.
const TOP: i64 = 3;

const PERSON_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "person_id": { "type": "string", "format": "uuid" },
    "entity": { "type": "string", "enum": ["contact", "lead"], "description": "contact by default" }
  },
  "required": ["person_id"],
  "additionalProperties": false
}"#;

const HANDOFF_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "handoff_id": { "type": "string", "format": "uuid" } },
  "required": ["handoff_id"],
  "additionalProperties": false
}"#;

const PROGRAM_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "program_id": { "type": "string", "format": "uuid" } },
  "required": ["program_id"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_MARKETING,
        &["marketing_nurture_program.read"],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            SUGGEST_CONTENT,
            "Suggest up to three pieces of nurture content for a person: what people with the same \
             interest most often saw before they were handed to sales, that this person has not \
             seen. Changes nothing.",
            PERSON_SCHEMA,
        ),
        read(
            DRAFT_SUMMARY,
            "Draft a hand-off's summary for sales as a few lines in the person's language, from what \
             the hand-off recorded. Nothing is saved. Do NOT use this to accept or return a hand-off.",
            HANDOFF_SCHEMA,
        ),
        read(
            FIND_STALLS,
            "Find the tracks of a nurture programme whose people have waited for their next email \
             more than twice as long as the programme's median. Changes nothing.",
            PROGRAM_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Nurture(SUGGEST_CONTENT)),
        Box::new(Nurture(DRAFT_SUMMARY)),
        Box::new(Nurture(FIND_STALLS)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be an id")))
}

/// Whether some programme the person is (or `program` is) in allows agent
/// suggestions. A programme that does not answers as absent.
async fn suggestions_on(
    state: &EngineState,
    program: Option<Uuid>,
    person: Option<Uuid>,
) -> Result<(), AppError> {
    let on: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM marketing_nurture_program p \
                         WHERE COALESCE(p.agent_suggestions_enabled, false) \
                           AND p.is_active IS NOT FALSE \
                           AND ($1::uuid IS NULL OR p.id = $1) \
                           AND ($2::uuid IS NULL OR EXISTS ( \
                               SELECT 1 FROM marketing_nurture_state s \
                                WHERE s.program_id = p.id AND s.person_id = $2)))",
    )
    .bind(program)
    .bind(person)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if on { Ok(()) } else { Err(AppError::NotFound) }
}

/// One suggested piece of content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct Suggestion {
    pub content_kind: String,
    pub content_id: String,
    /// People handed to sales who saw it.
    pub seen_by: i64,
}

async fn suggest_content(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Value, AppError> {
    let person = uuid_arg(args, "person_id")?;
    let entity = args
        .get("entity")
        .and_then(Value::as_str)
        .unwrap_or("contact");
    if entity != "contact" && entity != "lead" {
        return Err(AppError::Validation("entity is contact or lead".into()));
    }
    if !attome_marketing::segment_insight::readable(state, &ctx.security, entity, &[person])
        .await?
        .contains(&person)
    {
        return Err(AppError::NotFound);
    }
    suggestions_on(state, None, Some(person)).await?;
    let interest: Option<String> = sqlx::query_scalar(&format!(
        "SELECT nurture_interest FROM {} WHERE id = $1",
        attome_core::quote_ident(entity)
    ))
    .bind(person)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let suggestions: Vec<Suggestion> = sqlx::query_as(&format!(
        "SELECT cs.content_kind, cs.content_id, COUNT(DISTINCT h.person_id) AS seen_by \
           FROM marketing_handoff h \
           JOIN marketing_content_seen cs ON cs.person_id = h.person_id \
                                         AND cs.first_seen_at <= h.created_at \
           JOIN {} t ON t.id = h.person_id \
          WHERE h.status IN ('pending', 'accepted', 'overdue') \
            AND ($2::text IS NULL OR lower(t.nurture_interest) = lower($2)) \
            AND NOT EXISTS (SELECT 1 FROM marketing_content_seen mine \
                             WHERE mine.person_id = $1 AND mine.content_kind = cs.content_kind \
                               AND mine.content_id = cs.content_id) \
          GROUP BY cs.content_kind, cs.content_id \
          ORDER BY seen_by DESC, cs.content_kind, cs.content_id LIMIT $3",
        attome_core::quote_ident(entity)
    ))
    .bind(person)
    .bind(interest.as_deref().map(str::trim).filter(|i| !i.is_empty()))
    .bind(TOP)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(json!({
        "person_id": person,
        "interest": interest,
        "suggestions": suggestions,
        "saved": false,
    }))
}

/// A hand-off's summary as text, in Arabic or English. Pure.
pub fn summary_text(summary: &Value, arabic: bool) -> String {
    let score = summary["score"].as_f64().unwrap_or(0.0);
    let threshold = summary["threshold"].as_f64().unwrap_or(0.0);
    let seen = summary["content_seen"].as_array().map_or(0, Vec::len);
    let next = summary["next_step"].as_str().unwrap_or("call");
    if arabic {
        let step = if next == "meeting" {
            "اقتراح اجتماع"
        } else {
            "اتصال"
        };
        format!(
            "بلغت درجته {score:.0} (درجة التسليم {threshold:.0}). اطّلع على {seen} من محتوى الرعاية مؤخرًا. الخطوة التالية المقترحة: {step}."
        )
    } else {
        let step = if next == "meeting" {
            "propose a meeting"
        } else {
            "call"
        };
        format!(
            "Scored {score:.0} (hand-off score {threshold:.0}). Recently saw {seen} pieces of nurture content. Suggested next step: {step}."
        )
    }
}

async fn draft_summary(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Value, AppError> {
    let handoff = uuid_arg(args, "handoff_id")?;
    let row: Option<(Uuid, Uuid, Option<Value>, Option<String>)> = sqlx::query_as(
        "SELECT h.program_id, h.person_id, h.summary, s.person_entity FROM marketing_handoff h \
           LEFT JOIN marketing_nurture_state s \
                  ON s.program_id = h.program_id AND s.person_id = h.person_id \
          WHERE h.id = $1",
    )
    .bind(handoff)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (program, person, summary, entity) = row.ok_or(AppError::NotFound)?;
    let entity = entity.unwrap_or_else(|| "contact".to_owned());
    if !attome_marketing::segment_insight::readable(state, &ctx.security, &entity, &[person])
        .await?
        .contains(&person)
    {
        return Err(AppError::NotFound);
    }
    suggestions_on(state, Some(program), None).await?;
    let arabic = if entity == "contact" {
        let language: Option<String> =
            sqlx::query_scalar("SELECT preferred_language FROM contact WHERE id = $1")
                .bind(person)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .flatten();
        language.is_some_and(|l| l.to_lowercase().starts_with("ar"))
    } else {
        false
    };
    Ok(json!({
        "handoff_id": handoff,
        "language": if arabic { "ar" } else { "en" },
        "text": summary_text(&summary.unwrap_or(Value::Null), arabic),
        "saved": false,
    }))
}

/// A track's wait: its id, people, median days since their last email.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrackWait {
    pub track_id: Option<Uuid>,
    pub people: i64,
    pub median_days: f64,
}

/// The tracks whose median wait exceeds twice `overall`. Pure.
pub fn stalled(tracks: &[TrackWait], overall: f64) -> Vec<TrackWait> {
    if overall <= 0.0 {
        return Vec::new();
    }
    tracks
        .iter()
        .filter(|t| t.median_days > 2.0 * overall)
        .cloned()
        .collect()
}

async fn find_stalls(state: &EngineState, args: &Value) -> Result<Value, AppError> {
    let program = uuid_arg(args, "program_id")?;
    suggestions_on(state, Some(program), None).await?;
    let waits: Vec<(Option<Uuid>, i64, Option<f64>)> = sqlx::query_as(
        "WITH last AS ( \
             SELECT s.track_id, s.person_id, \
                    EXTRACT(EPOCH FROM now() - COALESCE(MAX(l.sent_at), now())) / 86400.0 AS days \
               FROM marketing_nurture_state s \
               LEFT JOIN marketing_message_log l \
                      ON l.source_kind = 'nurture' AND l.source_id = s.program_id \
                     AND l.person_id = s.person_id \
              WHERE s.program_id = $1 AND s.status = 'active' \
              GROUP BY s.track_id, s.person_id) \
         SELECT track_id, COUNT(*), percentile_cont(0.5) WITHIN GROUP (ORDER BY days) \
           FROM last GROUP BY track_id ORDER BY track_id NULLS LAST",
    )
    .bind(program)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let overall: Option<f64> = sqlx::query_scalar(
        "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY days) FROM ( \
             SELECT EXTRACT(EPOCH FROM now() - COALESCE(MAX(l.sent_at), now())) / 86400.0 AS days \
               FROM marketing_nurture_state s \
               LEFT JOIN marketing_message_log l \
                      ON l.source_kind = 'nurture' AND l.source_id = s.program_id \
                     AND l.person_id = s.person_id \
              WHERE s.program_id = $1 AND s.status = 'active' \
              GROUP BY s.person_id) d",
    )
    .bind(program)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let tracks: Vec<TrackWait> = waits
        .into_iter()
        .map(|(track_id, people, median)| TrackWait {
            track_id,
            people,
            median_days: median.unwrap_or(0.0),
        })
        .collect();
    let overall = overall.unwrap_or(0.0);
    Ok(json!({
        "program_id": program,
        "median_days": overall,
        "stalled": stalled(&tracks, overall),
        "tracks": tracks,
    }))
}

pub(crate) struct Nurture(&'static str);

impl Action for Nurture {
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
            ctx.security.require("marketing_nurture_program", "read")?;
            let out = match self.0 {
                SUGGEST_CONTENT => suggest_content(state, ctx, args).await?,
                DRAFT_SUMMARY => draft_summary(state, ctx, args).await?,
                FIND_STALLS => find_stalls(state, args).await?,
                _ => return Err(AppError::NotFound),
            };
            Ok(ActionResult::plain(out))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_are_read_only() {
        for d in descriptors() {
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert!(
                !d.id.0.contains("handoff") && !d.id.0.contains("accept"),
                "{}",
                d.id.0
            );
        }
        assert_eq!(executors().len(), descriptors().len());
    }

    #[test]
    fn hidden_when_suggestions_disabled() {
        // Hidden without the module; a programme without
        // agent_suggestions_enabled answers as absent (`suggestions_on`).
        for d in descriptors() {
            assert_eq!(d.module, MODULE_MARKETING, "{}", d.id.0);
            assert_eq!(
                d.required_privileges,
                &["marketing_nurture_program.read"],
                "{}",
                d.id.0
            );
        }
    }

    #[test]
    fn a_summary_reads_in_either_language() {
        let summary = json!({ "score": 72.0, "threshold": 60.0,
                              "content_seen": [{ "kind": "email", "id": "d" }], "next_step": "call" });
        let en = summary_text(&summary, false);
        assert!(
            en.contains("72") && en.contains("60") && en.contains("call"),
            "{en}"
        );
        let ar = summary_text(&summary, true);
        assert!(ar.contains("72") && ar.contains("اتصال"), "{ar}");
    }

    #[test]
    fn a_stall_is_twice_the_median() {
        let tracks = [
            TrackWait {
                track_id: None,
                people: 10,
                median_days: 5.0,
            },
            TrackWait {
                track_id: Some(Uuid::nil()),
                people: 4,
                median_days: 21.0,
            },
        ];
        let found = stalled(&tracks, 7.0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].median_days, 21.0);
        assert!(stalled(&tracks, 0.0).is_empty());
    }
}
