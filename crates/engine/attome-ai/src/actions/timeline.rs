//! A record's timeline, summarised and asked (roadmap B1-T3).
//!
//! - `timeline.summarize` writes a short account of what happened on the
//!   record, citing the events it draws on: the summary the timeline shows at
//!   its top when it opens.
//! - `timeline.ask` answers a question about the record's history from its
//!   events, citing them, or declines.
//!
//! **Only readable events.** Both read the timeline through
//! `attome_records::entity_crud::timeline::record_timeline` as the caller, so
//! every event already passed the record read, each source's own read and
//! row security, and the field filter; a record the caller cannot read is
//! `NotFound`. Only an event's time, kind, actor kind and summary line reach
//! the model, never its `detail`. An MCP agent reads the record's own events
//! only (no related records roll in), so an answer never reaches an entity
//! its admission did not name. With no event, no model is called.
//!
//! **Citations** are checked by the code, as `knowledge.answer` checks them
//! ([`judge`]): an answer that cites nothing, or an id it was not shown, is
//! declined; each citation maps back to the event (kind, source, time).
//!
//! **Cache** (guidelines §5), summaries only. Source of truth: the
//! generation. Key: `summary_context::cache_key` over this prompt's version,
//! the model, the language, the entity and the exact event text, so a new
//! event (every change to the record is one) is a new key: a summary is
//! cached per record version. TTL `summary_context::CACHE_TTL`; a cache
//! failure degrades to generating.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_modules::MODULE_AI;
use attome_records::entity_crud::timeline::{TimelineEntry, TimelineOptions, record_timeline};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

use super::knowledge_answer::{DeclineReason, Verdict, evidence_id, judge};

pub const TIMELINE_SUMMARIZE: &str = "timeline.summarize";
pub const TIMELINE_ASK: &str = "timeline.ask";
/// Bumped whenever a prompt changes in a way that could move output.
pub const SUMMARIZE_PROMPT_VERSION: &str = "timeline.summarize/v1";
pub const ASK_PROMPT_VERSION: &str = "timeline.ask/v1";

/// The most events one call reads, newest first.
pub const MAX_EVENTS: i64 = 60;
/// The longest question accepted.
const MAX_QUESTION_CHARS: usize = 500;

const SUMMARIZE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string" },
    "record_id": { "type": "string", "format": "uuid" },
    "language": { "type": "string", "description": "The language to write in; the record's own when absent." }
  },
  "required": ["entity", "record_id"],
  "additionalProperties": false
}"#;

const ASK_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string" },
    "record_id": { "type": "string", "format": "uuid" },
    "question": { "type": "string", "description": "A question about what happened on the record." }
  },
  "required": ["entity", "record_id", "question"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            TIMELINE_SUMMARIZE,
            "Summarise what happened on a record from its timeline, citing the events used. \
             Only events the person may see.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SUMMARIZE_SCHEMA),
        ActionDescriptor::new(
            TIMELINE_ASK,
            "Answer a question about a record's history from its timeline, citing the events \
             used, or decline.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(ASK_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(TimelineSummarize), Box::new(TimelineAsk)]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SummarizeArgs {
    entity: String,
    record_id: Uuid,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskArgs {
    entity: String,
    record_id: Uuid,
    question: String,
}

/// The summary prompt.
pub fn summarize_system_prompt(language: &str) -> String {
    format!(
        "You summarise a CRM record's history for a business user, using only the timeline \
         events provided, newest first. Each event is labelled with an evidence id such as E1 \
         and gives its time, kind, who made it (a person, an agent, a flow or the system) and \
         what happened.\n\n\
         Reply with exactly one JSON object and nothing else:\n\
         {{\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
         \"citations\": [evidence ids]}}\n\n\
         Say where the record stands and what happened recently, in a few sentences, in \
         {language}. List every event you used. Use \"insufficient\" only when the events say \
         nothing worth summarising, with an empty answer and no citations."
    )
}

/// The ask prompt.
pub fn ask_system_prompt() -> String {
    "You answer a question about a CRM record's history using only the timeline events \
     provided, newest first. Each event is labelled with an evidence id such as E1 and gives \
     its time, kind, who made it and what happened.\n\n\
     Reply with exactly one JSON object and nothing else:\n\
     {\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
     \"citations\": [evidence ids]}\n\n\
     Use \"answered\" only when the events answer the question, and list every event you \
     used. Use \"insufficient\" otherwise, with an empty answer and no citations. Write the \
     answer in the language of the question."
        .to_owned()
}

/// One event as the model sees it: time, kind, actor kind and summary line,
/// never the detail. Pure.
pub fn event_text(entry: &TimelineEntry) -> String {
    let kind = serde_json::to_value(entry.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let actor = serde_json::to_value(entry.actor_kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let summary: String = entry.summary.chars().take(400).collect();
    format!(
        "{} {kind} by {actor}: {summary}",
        entry.occurred_at.to_rfc3339()
    )
}

/// The whole event list as one text, for the cache key. Pure.
fn events_text(events: &[TimelineEntry]) -> String {
    events
        .iter()
        .enumerate()
        .map(|(i, e)| format!("{} {}", evidence_id(i), event_text(e)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A cited event as the answer names it. Pure.
pub fn citation(index: usize, entry: &TimelineEntry) -> Value {
    json!({
        "evidence": evidence_id(index),
        "kind": entry.kind,
        "source_entity": entry.source_entity,
        "source_id": entry.source_id,
        "occurred_at": entry.occurred_at,
        "source_record": entry.source_record,
    })
}

/// The model's reply judged against the events it was shown: the answer with
/// its citations, or why there is none. Pure.
pub fn judged(reply: &str, truncated: bool, events: &[TimelineEntry]) -> Value {
    match judge(reply, truncated, events.len()) {
        Verdict::Answered { answer, cited } => json!({
            "answer": answer,
            "citations": cited
                .iter()
                .filter_map(|i| events.get(*i).map(|e| citation(*i, e)))
                .collect::<Vec<_>>(),
        }),
        Verdict::Declined(DeclineReason::InsufficientEvidence | DeclineReason::NoEvidence) => {
            json!({ "answer": null, "reason": "not_found" })
        }
        Verdict::Declined(reason) => json!({ "answer": null, "reason": reason.as_str() }),
    }
}

/// The record's newest events the caller may read. An MCP agent gets the
/// record's own events only.
async fn read_events(
    state: &EngineState,
    ctx: &ActionContext,
    entity: &str,
    record_id: Uuid,
) -> Result<Vec<TimelineEntry>, AppError> {
    let opts = TimelineOptions {
        page_size: MAX_EVENTS,
        related: !ctx.is_mcp_agent(),
        ..Default::default()
    };
    Ok(
        record_timeline(state, &ctx.security, entity, record_id, &opts)
            .await?
            .items,
    )
}

/// One model call over the events, under `action`'s model, approval and
/// budget. Returns the reply text, whether it was cut, and the model id.
async fn generate(
    state: &EngineState,
    ctx: &ActionContext,
    action: &'static str,
    client: &attome_inference::GenerationClient,
    system: String,
    question: Option<&str>,
    events: &[TimelineEntry],
) -> Result<(String, bool, String), AppError> {
    let mut segments = vec![Segment::trusted(system)];
    if let Some(question) = question {
        segments.push(Segment::untrusted("question", question.to_owned()));
    }
    for (index, event) in events.iter().enumerate() {
        segments.push(Segment::untrusted(evidence_id(index), event_text(event)));
    }
    let mut request = GenerationRequest::new(crate::prompt::assemble(&segments));
    request.temperature = 0.0;
    crate::model_registry::require_approved_model(&state.base.db, client.model_id(), action)
        .await?;
    let grant = crate::budget_guard::admit(
        state,
        ctx,
        attome_inference::budget::Priority::Chat,
        action,
        &mut request,
    )
    .await?;
    let generated = client.generate(request).await.map_err(|e| {
        tracing::warn!(error = %e, action, "timeline generation failed");
        AppError::internal("timeline answer generation failed")
    })?;
    grant.settle(state, &generated.usage).await;
    Ok((
        generated.text,
        generated.truncated,
        generated.usage.model_id,
    ))
}

/// A summary as the cache keeps it.
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedTimelineSummary {
    value: Value,
    model_id: String,
}

pub(crate) struct TimelineSummarize;

impl Action for TimelineSummarize {
    fn id(&self) -> ActionId {
        ActionId(TIMELINE_SUMMARIZE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SummarizeArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid timeline.summarize arguments: {e}"))
            })?;
            let events = read_events(state, ctx, &args.entity, args.record_id).await?;
            if events.is_empty() {
                return Ok(ActionResult::plain(
                    json!({ "answer": null, "reason": "no_events" }),
                ));
            }
            let language = args
                .language
                .as_deref()
                .unwrap_or("the language of the events");
            let client = crate::inference_client::client_for(state, TIMELINE_SUMMARIZE).await?;
            let cache_key = super::summary_context::cache_key(
                SUMMARIZE_PROMPT_VERSION,
                client.model_id(),
                language,
                &args.entity,
                &format!("{}\n{}", args.record_id, events_text(&events)),
            );
            // A withdrawn model serves nothing, cached or not.
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                TIMELINE_SUMMARIZE,
            )
            .await?;
            match state.base.redis.get(&cache_key).await {
                Ok(Some(hit)) => {
                    if let Ok(cached) = serde_json::from_str::<CachedTimelineSummary>(&hit) {
                        let mut value = cached.value;
                        if let Value::Object(map) = &mut value {
                            map.insert("cached".into(), Value::Bool(true));
                        }
                        return Ok(ActionResult {
                            value,
                            provenance: Some(Provenance {
                                model_id: cached.model_id,
                                prompt_version: SUMMARIZE_PROMPT_VERSION.to_owned(),
                                suggestion_id: None,
                            }),
                        });
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "timeline.summarize: summary cache unavailable");
                }
            }
            let (reply, truncated, model_id) = generate(
                state,
                ctx,
                TIMELINE_SUMMARIZE,
                &client,
                summarize_system_prompt(language),
                None,
                &events,
            )
            .await?;
            let value = judged(&reply, truncated, &events);
            if value["answer"].is_string()
                && let Ok(entry) = serde_json::to_string(&CachedTimelineSummary {
                    value: value.clone(),
                    model_id: model_id.clone(),
                })
                && let Err(error) = state
                    .base
                    .redis
                    .set(&cache_key, entry, Some(super::summary_context::CACHE_TTL))
                    .await
            {
                tracing::warn!(%error, "timeline.summarize: summary not cached");
            }
            Ok(ActionResult {
                value,
                provenance: Some(Provenance {
                    model_id,
                    prompt_version: SUMMARIZE_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

pub(crate) struct TimelineAsk;

impl Action for TimelineAsk {
    fn id(&self) -> ActionId {
        ActionId(TIMELINE_ASK)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: AskArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid timeline.ask arguments: {e}"))
            })?;
            let question: String = args
                .question
                .trim()
                .chars()
                .take(MAX_QUESTION_CHARS)
                .collect();
            if question.is_empty() {
                return Err(AppError::Validation("question must not be empty".into()));
            }
            let events = read_events(state, ctx, &args.entity, args.record_id).await?;
            if events.is_empty() {
                return Ok(ActionResult::plain(
                    json!({ "answer": null, "reason": "not_found" }),
                ));
            }
            let client = crate::inference_client::client_for(state, TIMELINE_ASK).await?;
            let (reply, truncated, model_id) = generate(
                state,
                ctx,
                TIMELINE_ASK,
                &client,
                ask_system_prompt(),
                Some(&question),
                &events,
            )
            .await?;
            Ok(ActionResult {
                value: judged(&reply, truncated, &events),
                provenance: Some(Provenance {
                    model_id,
                    prompt_version: ASK_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_records::entity_crud::timeline::{ActorKind, SourceRecord, TimelineEntryKind};

    fn event(minute: u32, kind: TimelineEntryKind, summary: &str) -> TimelineEntry {
        TimelineEntry {
            kind,
            occurred_at: chrono::DateTime::parse_from_rfc3339(&format!(
                "2026-10-26T10:{minute:02}:00Z"
            ))
            .unwrap()
            .with_timezone(&chrono::Utc),
            source_entity: "audit_header".into(),
            source_id: Uuid::now_v7(),
            summary: summary.into(),
            detail: json!({ "secret": "never shown" }),
            actor: None,
            actor_kind: ActorKind::Agent,
            run_id: None,
            source_record: SourceRecord {
                entity: "account".into(),
                id: Uuid::nil(),
            },
        }
    }

    /// The fake model's reply, judged: the summary keeps only real
    /// citations, each mapped back to its event.
    #[test]
    fn timeline_summary_cites_events() {
        let events = vec![
            event(
                30,
                TimelineEntryKind::Approval,
                "Approval: discount (approved)",
            ),
            event(
                20,
                TimelineEntryKind::Communication,
                "Communication: Renewal quote",
            ),
        ];
        let reply = r#"{"status": "answered", "answer": "The discount was approved after the renewal quote.", "citations": ["E1", "E2"]}"#;
        let value = judged(reply, false, &events);
        assert_eq!(
            value["answer"],
            "The discount was approved after the renewal quote."
        );
        let citations = value["citations"].as_array().unwrap();
        assert_eq!(citations.len(), 2);
        assert_eq!(citations[0]["evidence"], "E1");
        assert_eq!(citations[0]["kind"], "approval");
        assert_eq!(citations[0]["source_id"], json!(events[0].source_id));
        assert_eq!(citations[1]["kind"], "communication");
    }

    /// A reply citing an event it was not shown, or nothing, is declined; a
    /// reply that is not the object is malformed.
    #[test]
    fn timeline_summary_declines_ungrounded_replies() {
        let events = vec![event(1, TimelineEntryKind::Note, "Note: call back")];
        let invented = judged(
            r#"{"status": "answered", "answer": "Closed won.", "citations": ["E7"]}"#,
            false,
            &events,
        );
        assert!(invented["answer"].is_null());
        assert_eq!(invented["reason"], "ungrounded");
        let uncited = judged(
            r#"{"status": "answered", "answer": "Closed won.", "citations": []}"#,
            false,
            &events,
        );
        assert!(uncited["answer"].is_null());
        let none = judged(
            r#"{"status": "insufficient", "answer": "", "citations": []}"#,
            false,
            &events,
        );
        assert_eq!(none["reason"], "not_found");
        assert_eq!(judged("Closed won.", false, &events)["reason"], "malformed");
        let cut = judged(
            r#"{"status": "answered", "answer": "x", "citations": ["E1"]}"#,
            true,
            &events,
        );
        assert_eq!(cut["reason"], "malformed");
    }

    /// The model sees time, kind, actor kind and the summary line, never the
    /// detail; the summary prompt asks for citations.
    #[test]
    fn timeline_summary_shows_the_model_no_detail() {
        let e = event(
            5,
            TimelineEntryKind::AgentRun,
            "Agent run: records.update (1 change(s))",
        );
        let text = event_text(&e);
        assert_eq!(
            text,
            "2026-10-26T10:05:00+00:00 agent_run by agent: Agent run: records.update (1 change(s))"
        );
        assert!(!text.contains("never shown"));
        assert!(summarize_system_prompt("English").contains("evidence id"));
        assert!(summarize_system_prompt("Arabic").contains("in Arabic"));
        assert!(ask_system_prompt().contains("evidence id"));
        let joined = events_text(&[e.clone(), e]);
        assert!(joined.starts_with("E1 ") && joined.contains("\nE2 "));
    }

    /// Both are plain reads with no privilege of their own: the timeline
    /// read applies the person's.
    #[test]
    fn timeline_summary_actions_are_reads() {
        for d in descriptors() {
            assert_eq!(
                (d.risk, d.effect),
                (RiskTier::Read, Effect::Read),
                "{}",
                d.id.0
            );
            assert!(d.required_privileges.is_empty(), "{}", d.id.0);
        }
        assert!(
            serde_json::from_value::<AskArgs>(
                json!({"entity": "account", "record_id": Uuid::nil(), "question": "why?", "as_admin": true})
            )
            .is_err()
        );
    }
}
