//! Asking search in words (roadmap A25-T7): two read actions and the seam
//! search reaches them through.
//!
//! - `search.parse_filter` turns a query such as "open complaints from
//!   Al-Faisal last month" into a QuerySpec `{entity, where}` (the
//!   `query/run` condition tree; the A13 filter format is that one). The
//!   model sees only the entities and attributes the caller may read, and
//!   answers with JSON, never SQL. The code then checks the filter: the
//!   entity must be readable, and the spec must compile against the
//!   caller's metadata (`attome_records::query_spec::execute_spec` with
//!   `explain`, which plans and runs nothing). An unknown attribute or
//!   operator declines as `invalid_filter`.
//! - `search.answer_records` answers a question from at most
//!   [`MAX_ANSWER_RECORDS`] records, each read as the caller through the
//!   bulk read (record and field security, D-589 bulk exposure). A record
//!   the caller cannot read is left out before the model is called, so it
//!   can never be cited; with none left there is no model call and the
//!   answer is `null` (`not_found`). Citations are checked as
//!   `knowledge.answer` checks them ([`super::knowledge_answer::judge`]).
//!
//! Both go through the budget guard and the approved-model check, like
//! every model action.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use attome_core::EngineState;
use attome_core::search_ask::{AskFuture, SearchAsker};
use attome_inference::GenerationRequest;
use attome_modules::MODULE_AI;
use attome_records::query_spec::{QuerySpec, execute_spec};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionOutcome, ActionResult, Provenance};
use crate::prompt::Segment;

use super::knowledge_answer::{DeclineReason, Verdict, evidence_id, judge};

pub const SEARCH_PARSE_FILTER: &str = "search.parse_filter";
pub const SEARCH_ANSWER_RECORDS: &str = "search.answer_records";
/// Bumped whenever a prompt changes in a way that could move results.
pub const PARSE_PROMPT_VERSION: &str = "search.parse_filter/v1";
pub const RECORDS_ANSWER_PROMPT_VERSION: &str = "search.answer_records/v1";

/// The longest query parsed.
pub const MAX_QUERY_CHARS: usize = 500;
/// Entities and attributes per entity the model is shown.
pub const MAX_PROMPT_ENTITIES: usize = 40;
pub const MAX_PROMPT_ATTRS: usize = 25;
/// Records one answer reads.
pub const MAX_ANSWER_RECORDS: usize = 10;
/// Characters of one field value, and of one record, the model is shown.
const MAX_VALUE_CHARS: usize = 300;
const MAX_RECORD_CHARS: usize = 2_000;

/// The comparison operators the model may use, besides the relative dates.
const COMPARE_OPS: &[&str] = &[
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains",
];

const PARSE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "query": { "type": "string", "description": "The search in words." }
  },
  "required": ["query"],
  "additionalProperties": false
}"#;

const ANSWER_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string" },
    "records": {
      "type": "array",
      "maxItems": 10,
      "items": {
        "type": "object",
        "properties": {
          "entity": { "type": "string" },
          "id": { "type": "string", "format": "uuid" }
        },
        "required": ["entity", "id"]
      }
    }
  },
  "required": ["question", "records"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            SEARCH_PARSE_FILTER,
            "Turn a search in words into a structured filter (entity and \
             conditions) over the records the caller may read. Returns the \
             filter; it does not run it.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(PARSE_SCHEMA),
        ActionDescriptor::new(
            SEARCH_ANSWER_RECORDS,
            "Answer a question from up to ten records the caller may read, \
             citing the records used, or decline when they do not answer it.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(ANSWER_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ParseFilter), Box::new(AnswerRecords)]
}

/// The parse prompt.
pub fn parse_system_prompt() -> String {
    format!(
        "You turn a search typed in words, in English or Arabic, into a filter \
         over a CRM's records. The entities and attributes you may use are listed \
         in the metadata message; use only those names.\n\n\
         Reply with exactly one JSON object and nothing else:\n\
         {{\"entity\": entity name, \"where\": condition}}\n\
         A condition is one of:\n\
         {{\"kind\": \"compare\", \"field\": name, \"op\": op, \"value\": value}}\n\
         {{\"kind\": \"and\", \"all\": [conditions]}}\n\
         {{\"kind\": \"or\", \"any\": [conditions]}}\n\
         {{\"kind\": \"not\", \"condition\": condition}}\n\
         op is one of {ops}, or a relative date: today, last_n_days (value: \
         the number of days), next_n_days, this_month, last_month, \
         this_quarter, this_year (no value). A field of a related record is \
         written lookup.field, for example account.name.\n\n\
         When the search does not name records of one entity, reply \
         {{\"entity\": null}}. Never write SQL.",
        ops = COMPARE_OPS.join(", ")
    )
}

/// The records-answer prompt.
pub fn records_answer_system_prompt() -> String {
    "You answer a staff question using only the CRM records provided. Each \
     record is labelled with an evidence id such as E1.\n\n\
     Reply with exactly one JSON object and nothing else:\n\
     {\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
     \"citations\": [evidence ids]}\n\n\
     Use \"answered\" only when the records contain the answer, state only what \
     they say, and list the id of every record you used. Use \"insufficient\" \
     when they do not answer the question; then \"answer\" is an empty string \
     and \"citations\" is empty.\n\n\
     Write the answer in the language of the question."
        .to_owned()
}

/// The entities and attributes `ctx` may read (and `shown` keeps), one
/// entity per line, for the parse prompt: `entity: attr (type), ...`.
/// Sensitive attributes are shown to administrators only.
pub fn readable_schema(
    state: &EngineState,
    ctx: &SecurityContext,
    shown: impl Fn(&str) -> bool,
) -> String {
    let registry = state.entities.load();
    let mut entities: Vec<_> = registry
        .iter()
        .filter(|e| ctx.require(&e.logicalname, "read").is_ok() && shown(&e.logicalname))
        .collect();
    entities.sort_by(|a, b| a.logicalname.cmp(&b.logicalname));
    entities
        .into_iter()
        .take(MAX_PROMPT_ENTITIES)
        .map(|e| {
            let attrs: Vec<String> = e
                .attrs
                .iter()
                .filter(|a| !a.is_read_gated() || ctx.is_admin)
                .take(MAX_PROMPT_ATTRS)
                .map(|a| format!("{} ({})", a.logicalname, a.field_type().as_str()))
                .collect();
            format!("{}: {}", e.logicalname, attrs.join(", "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A model's reply without one surrounding markdown fence.
fn strip_fence(text: &str) -> &str {
    let t = text.trim();
    let Some(rest) = t.strip_prefix("```") else {
        return t;
    };
    let rest = rest.strip_prefix("json").unwrap_or(rest);
    rest.strip_suffix("```").unwrap_or(rest).trim()
}

/// The QuerySpec a parse reply names, or why it names none. Structure only:
/// the metadata check runs after. Pure.
pub fn spec_from_reply(reply: &str) -> Result<QuerySpec, &'static str> {
    let value: Value = serde_json::from_str(strip_fence(reply)).map_err(|_| "malformed")?;
    let entity = match value.get("entity") {
        Some(Value::String(e)) if !e.trim().is_empty() => e.trim().to_owned(),
        Some(Value::Null) | None => return Err("not_a_filter"),
        _ => return Err("malformed"),
    };
    let mut spec = json!({ "entity": entity });
    if let Some(condition) = value.get("where").filter(|w| !w.is_null()) {
        spec["where"] = condition.clone();
    }
    serde_json::from_value(spec).map_err(|_| "invalid_filter")
}

fn declined(reason: &str) -> Value {
    json!({ "status": "declined", "reason": reason })
}

#[derive(Deserialize)]
struct ParseArgs {
    query: String,
}

pub(crate) struct ParseFilter;

impl Action for ParseFilter {
    fn id(&self) -> ActionId {
        ActionId(SEARCH_PARSE_FILTER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: ParseArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid search.parse_filter arguments: {e}"))
            })?;
            let query: String = args.query.trim().chars().take(MAX_QUERY_CHARS).collect();
            if query.is_empty() {
                return Err(AppError::Validation("query must not be empty".into()));
            }
            // An MCP agent sees and filters only the entities admitted to it.
            let admission = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?;
            let admitted = |entity: &str| admission.as_ref().is_none_or(|a| a.admits(entity));
            let schema = readable_schema(state, &ctx.security, admitted);
            if schema.is_empty() {
                return Ok(ActionResult::plain(declined("no_readable_entity")));
            }
            let client = crate::inference_client::client_for(state, SEARCH_PARSE_FILTER).await?;
            let mut request = GenerationRequest::new(crate::prompt::assemble(&[
                Segment::trusted(parse_system_prompt()),
                Segment::untrusted("metadata", schema),
                Segment::untrusted("query", query),
            ]));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                SEARCH_PARSE_FILTER,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                SEARCH_PARSE_FILTER,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "search.parse_filter generation failed");
                AppError::internal("filter parsing failed")
            })?;
            grant.settle(state, &generated.usage).await;
            let provenance = Some(Provenance {
                model_id: generated.usage.model_id.clone(),
                prompt_version: PARSE_PROMPT_VERSION.to_owned(),
                suggestion_id: None,
            });
            let value = if generated.truncated {
                declined("malformed")
            } else {
                match spec_from_reply(&generated.text) {
                    Err(reason) => declined(reason),
                    Ok(spec) if !admitted(&spec.entity) => declined("invalid_filter"),
                    Ok(spec) => check_filter(state, &ctx.security, spec).await?,
                }
            };
            Ok(ActionResult { value, provenance })
        })
    }
}

/// Whether `spec` is a filter `ctx` may run: a readable entity, and every
/// field and operator known to the caller's metadata.
async fn check_filter(
    state: &EngineState,
    ctx: &SecurityContext,
    spec: QuerySpec,
) -> Result<Value, AppError> {
    if ctx.require(&spec.entity, "read").is_err() {
        return Ok(declined("invalid_filter"));
    }
    let filter = json!({ "entity": spec.entity, "where": spec.r#where });
    let mut planned = spec;
    planned.explain = true;
    match execute_spec(state, ctx, planned).await {
        Ok(_) => Ok(json!({ "status": "parsed", "filter": filter })),
        Err(AppError::Validation(message)) => Ok(json!({
            "status": "declined",
            "reason": "invalid_filter",
            "detail": message,
        })),
        Err(AppError::NotFound | AppError::Forbidden) => Ok(declined("invalid_filter")),
        Err(error) => Err(error),
    }
}

#[derive(Deserialize)]
struct RecordRef {
    entity: String,
    id: Uuid,
}

#[derive(Deserialize)]
struct AnswerArgs {
    question: String,
    #[serde(default)]
    records: Vec<RecordRef>,
}

/// One record as the model is shown it, with what a citation of it names.
struct Evidence {
    entity: String,
    id: Uuid,
    title: Option<String>,
    text: String,
}

/// The text of a record for the answer prompt: its entity, title and each
/// non-empty field, cut to size. Pure.
fn record_text(entity: &str, title: Option<&str>, data: &Value) -> String {
    let mut out = format!("Record: {entity}");
    if let Some(title) = title {
        out.push_str(&format!(" \"{title}\""));
    }
    out.push('\n');
    if let Some(fields) = data.as_object() {
        for (name, value) in fields {
            let shown = match value {
                Value::Null => continue,
                Value::String(s) if s.trim().is_empty() => continue,
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let shown: String = shown.chars().take(MAX_VALUE_CHARS).collect();
            out.push_str(&format!("{name}: {shown}\n"));
            if out.chars().count() >= MAX_RECORD_CHARS {
                break;
            }
        }
    }
    out.chars().take(MAX_RECORD_CHARS).collect()
}

fn not_found(reason: &str) -> Value {
    json!({ "answer": null, "reason": reason })
}

pub(crate) struct AnswerRecords;

impl Action for AnswerRecords {
    fn id(&self) -> ActionId {
        ActionId(SEARCH_ANSWER_RECORDS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: AnswerArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid search.answer_records arguments: {e}"))
            })?;
            let question: String = args.question.trim().chars().take(MAX_QUERY_CHARS).collect();
            if question.is_empty() {
                return Err(AppError::Validation("question must not be empty".into()));
            }
            // Only what the caller may read (and, for an MCP agent, what is
            // admitted to it) becomes evidence.
            let admission = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?;
            let mut evidence = Vec::new();
            for record in args.records.iter().take(MAX_ANSWER_RECORDS) {
                if admission
                    .as_ref()
                    .is_some_and(|a| !a.admits(&record.entity))
                {
                    continue;
                }
                let Ok(read) = attome_records::entity_crud::read_record_bulk(
                    state,
                    &ctx.security,
                    &record.entity,
                    record.id,
                )
                .await
                else {
                    continue;
                };
                let title = state
                    .entities
                    .load()
                    .get(&record.entity)
                    .and_then(|e| e.primary_name_attribute.clone())
                    .and_then(|name| {
                        read.data()
                            .get(&name)
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    });
                evidence.push(Evidence {
                    text: record_text(&record.entity, title.as_deref(), read.data()),
                    entity: record.entity.clone(),
                    id: record.id,
                    title,
                });
            }
            if evidence.is_empty() {
                return Ok(ActionResult::plain(not_found("not_found")));
            }

            let client = crate::inference_client::client_for(state, SEARCH_ANSWER_RECORDS).await?;
            let mut segments = vec![
                Segment::trusted(records_answer_system_prompt()),
                Segment::untrusted("question", question),
            ];
            for (index, e) in evidence.iter().enumerate() {
                segments.push(Segment::untrusted(evidence_id(index), e.text.clone()));
            }
            let mut request = GenerationRequest::new(crate::prompt::assemble(&segments));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                SEARCH_ANSWER_RECORDS,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                SEARCH_ANSWER_RECORDS,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "search.answer_records generation failed");
                AppError::internal("answer generation failed")
            })?;
            grant.settle(state, &generated.usage).await;

            let value = match judge(&generated.text, generated.truncated, evidence.len()) {
                Verdict::Answered { answer, cited } => {
                    let citations: Vec<Value> = cited
                        .iter()
                        .map(|i| {
                            let e = &evidence[*i];
                            json!({ "entity": e.entity, "record_id": e.id, "title": e.title })
                        })
                        .collect();
                    json!({ "answer": answer, "citations": citations })
                }
                Verdict::Declined(
                    DeclineReason::InsufficientEvidence | DeclineReason::NoEvidence,
                ) => not_found("not_found"),
                Verdict::Declined(reason) => not_found(reason.as_str()),
            };
            Ok(ActionResult {
                value,
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: RECORDS_ANSWER_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

/// The seam `attome-search` asks through: each call is the action, run
/// through the gate as the calling person.
#[derive(Debug, Clone, Copy, Default)]
pub struct AiSearchAsker;

async fn run_as(
    state: &EngineState,
    ctx: Arc<SecurityContext>,
    action: &str,
    args: Value,
) -> Result<Value, AppError> {
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, MODULE_AI);
    let action_ctx = ActionContext::user(ctx);
    match crate::execute::dispatch(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        action,
        &action_ctx,
        &inputs,
        &args,
    )
    .await?
    {
        ActionOutcome::Completed { result, .. } => Ok(result),
        // A Read action for a person is never held; anything else is not an answer.
        _ => Err(AppError::internal(
            "search ask: the action did not complete",
        )),
    }
}

impl SearchAsker for AiSearchAsker {
    fn parse_filter<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: Arc<SecurityContext>,
        query: &'a str,
    ) -> AskFuture<'a> {
        Box::pin(run_as(
            state,
            ctx,
            SEARCH_PARSE_FILTER,
            json!({ "query": query }),
        ))
    }

    fn answer<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: Arc<SecurityContext>,
        question: &'a str,
        records: &'a [(String, Uuid)],
    ) -> AskFuture<'a> {
        let records: Vec<Value> = records
            .iter()
            .take(MAX_ANSWER_RECORDS)
            .map(|(entity, id)| json!({ "entity": entity, "id": id }))
            .collect();
        Box::pin(run_as(
            state,
            ctx,
            SEARCH_ANSWER_RECORDS,
            json!({ "question": question, "records": records }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_names_a_spec_or_why_not() {
        let spec = spec_from_reply(
            r#"{"entity":"case","where":{"kind":"compare","field":"status","op":"eq","value":"open"}}"#,
        )
        .unwrap();
        assert_eq!(spec.entity, "case");
        assert!(spec.r#where.is_some());
        let fenced = "```json\n{\"entity\":\"account\"}\n```";
        assert_eq!(spec_from_reply(fenced).unwrap().entity, "account");
        assert_eq!(
            spec_from_reply(r#"{"entity":null}"#).unwrap_err(),
            "not_a_filter"
        );
        assert_eq!(
            spec_from_reply("SELECT * FROM case").unwrap_err(),
            "malformed"
        );
        assert_eq!(
            spec_from_reply(r#"{"entity":"case","where":{"kind":"sql","text":"1=1"}}"#)
                .unwrap_err(),
            "invalid_filter"
        );
    }

    #[test]
    fn record_text_skips_empty_fields_and_is_bounded() {
        let text = record_text(
            "case",
            Some("Late delivery"),
            &json!({"status": "open", "notes": "", "owner": null, "count": 3, "long": "x".repeat(5_000)}),
        );
        assert!(text.starts_with("Record: case \"Late delivery\""));
        assert!(text.contains("status: open") && text.contains("count: 3"));
        assert!(!text.contains("notes:") && !text.contains("owner:"));
        assert!(text.chars().count() <= MAX_RECORD_CHARS);
    }

    #[test]
    fn the_parse_prompt_never_asks_for_sql() {
        let prompt = parse_system_prompt();
        assert!(prompt.contains("Never write SQL"));
        assert!(prompt.contains("last_n_days"));
        for op in COMPARE_OPS {
            assert!(prompt.contains(op));
        }
    }
}
