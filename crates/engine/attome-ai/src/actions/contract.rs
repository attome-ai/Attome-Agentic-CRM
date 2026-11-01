//! Contract actions (roadmap W1-T12). Both read only and filtered by the
//! caller's own access: an agent sees no contract, field or clause its
//! person could not read.
//!
//! - `contract.review_against_playbook`: the contract's deviations from the
//!   playbook rules, each with the library's fallback clauses for it
//!   (`attome_contract::playbook::review`).
//! - `contract.summarise`: the contract's main terms as the caller reads
//!   them, its clause titles and its open obligations by due date. Local;
//!   no model call.
//! - `contract.answer`: a grounded, cited answer from contract clause text,
//!   `knowledge.answer`'s rule over a different corpus. Retrieval comes
//!   first ([`clause_evidence`]): candidate clauses by full-text match, then
//!   each clause and its contract read as the caller, so a clause of a
//!   contract the caller may not read (a confidential one, for most roles)
//!   is never shown to the model and never cited. The model sees only those
//!   passages under server-assigned ids, and `knowledge_answer::judge`
//!   decides: an answer citing nothing, or an id it was not shown, is
//!   declined.
//!
//! Importing an old contract is accepted by a person through
//! `POST /api/v1/contract/imports/{id}/accept`; no action reaches it.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CONTRACT;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::actions::knowledge_answer::{DeclineReason, Verdict, evidence_id, judge};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const REVIEW_AGAINST_PLAYBOOK: &str = "contract.review_against_playbook";
pub const SUMMARISE: &str = "contract.summarise";
pub const ANSWER: &str = "contract.answer";

/// Bumped whenever the answer prompt changes in a way that could move
/// answers.
const ANSWER_PROMPT_VERSION: &str = "contract.answer/v1";
/// Clauses matched before the caller's reads filter them.
const CANDIDATES: i64 = 20;
/// Passages shown to the model, as `knowledge.answer`.
const EVIDENCE_LIMIT: usize = 5;
/// The longest passage, in characters.
const PASSAGE_CHARS: usize = 2000;
/// Search terms taken from a question.
const MAX_TERMS: usize = 12;

const ANSWER_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string", "minLength": 1, "maxLength": 1000, "description": "The question about contract terms." },
    "contract_id": { "type": "string", "format": "uuid", "description": "Only this contract; all the caller may read when left out." }
  },
  "required": ["question"],
  "additionalProperties": false
}"#;

/// Clause titles a summary lists.
const MAX_CLAUSES: i64 = 50;
/// Open obligations a summary lists.
const MAX_OBLIGATIONS: i64 = 20;
/// The contract fields a summary carries, when the caller reads them.
const SUMMARY_FIELDS: [&str; 13] = [
    "title",
    "status",
    "counterparty",
    "contract_value",
    "currency",
    "start_date",
    "end_date",
    "renewal_date",
    "auto_renew",
    "renewal_term_months",
    "notice_period_days",
    "notice_deadline",
    "playbook_deviations",
];

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "contract_id": { "type": "string", "format": "uuid", "description": "The contract." }
  },
  "required": ["contract_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            REVIEW_AGAINST_PLAYBOOK,
            "A contract's deviations from the contract playbook rules (needs legal, block, \
             info), each with the fallback clauses the clause library offers for it. Reads \
             what the caller may read; writes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CONTRACT,
            &[],
        )
        .input_schema(INPUT),
        ActionDescriptor::new(
            SUMMARISE,
            "A contract's main terms (counterparty, value, dates, renewal and notice), its \
             clause titles and its open obligations by due date, as the caller may read them. \
             Writes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CONTRACT,
            &[],
        )
        .input_schema(INPUT),
        ActionDescriptor::new(
            ANSWER,
            "Answer a question about contract terms from the clauses of the contracts the \
             caller may read, with citations to the clauses used; declines when the clauses \
             do not answer it. Writes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CONTRACT,
            &[],
        )
        .input_schema(ANSWER_INPUT)
        .outcome_kind("ai_suggestion"),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(ReviewAgainstPlaybook),
        Box::new(Summarise),
        Box::new(Answer),
    ]
}

fn contract_id(args: &Value) -> Result<Uuid, AppError> {
    args["contract_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .ok_or_else(|| AppError::Validation("contract_id must be a UUID".into()))
}

/// Whether the agent's read admission lets it read `entity`.
fn admitted(state: &EngineState, ctx: &ActionContext, entity: &str) -> Result<bool, AppError> {
    Ok(
        crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?
            .is_none_or(|admission| admission.admits(entity)),
    )
}

/// The summary fields of a contract's data. Pure.
pub fn summary_fields(data: &Value) -> Map<String, Value> {
    SUMMARY_FIELDS
        .iter()
        .filter_map(|f| {
            data.get(*f)
                .filter(|v| !v.is_null())
                .map(|v| ((*f).to_owned(), v.clone()))
        })
        .collect()
}

struct ReviewAgainstPlaybook;

impl Action for ReviewAgainstPlaybook {
    fn id(&self) -> ActionId {
        ActionId(REVIEW_AGAINST_PLAYBOOK)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = contract_id(args)?;
            if !admitted(state, ctx, "contract")? {
                return Err(AppError::NotFound);
            }
            let review = attome_contract::playbook::review(state, &ctx.security, id).await?;
            Ok(ActionResult::plain(review))
        })
    }
}

struct Summarise;

impl Action for Summarise {
    fn id(&self) -> ActionId {
        ActionId(SUMMARISE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = contract_id(args)?;
            if !admitted(state, ctx, "contract")? {
                return Err(AppError::NotFound);
            }
            let record =
                attome_records::entity_crud::read_record(state, &ctx.security, "contract", id)
                    .await?;
            let terms = summary_fields(record.data());
            let clauses: Vec<String> = if ctx.security.require("contract_clause", "read").is_ok()
                && admitted(state, ctx, "contract_clause")?
            {
                sqlx::query_scalar(
                    "SELECT title FROM contract_clause \
                      WHERE contract_ref = $1 AND title IS NOT NULL \
                        AND is_active IS DISTINCT FROM false \
                      ORDER BY position NULLS LAST, id LIMIT $2",
                )
                .bind(id)
                .bind(MAX_CLAUSES)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?
            } else {
                Vec::new()
            };
            let obligations: Vec<Value> = if ctx.security.require("obligation", "read").is_ok()
                && admitted(state, ctx, "obligation")?
            {
                sqlx::query_as::<_, (String, Option<chrono::DateTime<chrono::Utc>>, Option<String>)>(
                    "SELECT COALESCE(title, ''), due_date, owed_by::text FROM obligation \
                      WHERE contract_ref = $1 AND is_active IS DISTINCT FROM false \
                        AND is_complete IS NOT TRUE \
                      ORDER BY due_date NULLS LAST, id LIMIT $2",
                )
                .bind(id)
                .bind(MAX_OBLIGATIONS)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .into_iter()
                .map(|(title, due, owed_by)| {
                    json!({ "title": title, "due_date": due, "owed_by": owed_by })
                })
                .collect()
            } else {
                Vec::new()
            };
            Ok(ActionResult::plain(json!({
                "contract_id": id,
                "terms": terms,
                "clauses": clauses,
                "open_obligations": obligations,
            })))
        })
    }
}

/// A clause the caller may read, as evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClauseEvidence {
    pub contract_id: Uuid,
    pub contract_title: String,
    pub clause_id: Uuid,
    pub clause_title: String,
    pub passage: String,
}

/// The search terms of a question: words of three or more letters or
/// digits, lowercased, each once. Only letters and digits, so they are safe
/// as `to_tsquery` operands. Pure.
pub fn query_terms(question: &str) -> Vec<String> {
    let mut terms: Vec<String> = Vec::new();
    for word in question.split(|c: char| !c.is_alphanumeric()) {
        let word = word.to_lowercase();
        if word.chars().count() >= 3 && !terms.contains(&word) {
            terms.push(word);
            if terms.len() == MAX_TERMS {
                break;
            }
        }
    }
    terms
}

/// Rich text as plain text: tags dropped, the common entities read,
/// whitespace collapsed. Pure.
pub fn plain_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn data_str(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The clauses that may answer `question`, each read as the caller: a clause
/// or contract the caller may not read is left out, so it is never shown to
/// a model or cited. At most five.
pub async fn clause_evidence(
    state: &EngineState,
    ctx: &ActionContext,
    question: &str,
    contract: Option<Uuid>,
) -> Result<Vec<ClauseEvidence>, AppError> {
    if ctx.security.require("contract", "read").is_err()
        || ctx.security.require("contract_clause", "read").is_err()
        || !admitted(state, ctx, "contract")?
        || !admitted(state, ctx, "contract_clause")?
    {
        return Ok(Vec::new());
    }
    let terms = query_terms(question);
    if terms.is_empty() {
        return Ok(Vec::new());
    }
    let candidates: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "WITH q AS (SELECT to_tsquery('simple', $1) AS q), \
              c AS (SELECT cc.id, cc.contract_ref, \
                           to_tsvector('simple', coalesce(cc.title, '') || ' ' \
                               || coalesce(cc.body_html, '') || ' ' \
                               || coalesce(cc.body_ar_html, '')) AS doc \
                      FROM contract_clause cc \
                     WHERE cc.is_active IS DISTINCT FROM false AND cc.contract_ref IS NOT NULL \
                       AND ($2::uuid IS NULL OR cc.contract_ref = $2)) \
         SELECT c.id, c.contract_ref FROM c, q WHERE c.doc @@ q.q \
          ORDER BY ts_rank(c.doc, q.q) DESC, c.id LIMIT $3",
    )
    .bind(terms.join(" | "))
    .bind(contract)
    .bind(CANDIDATES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut evidence = Vec::new();
    let mut titles: std::collections::HashMap<Uuid, Option<String>> =
        std::collections::HashMap::new();
    for (clause_id, contract_id) in candidates {
        if evidence.len() == EVIDENCE_LIMIT {
            break;
        }
        let contract_title = match titles.get(&contract_id) {
            Some(title) => title.clone(),
            None => {
                let title = match attome_records::entity_crud::read_record(
                    state,
                    &ctx.security,
                    "contract",
                    contract_id,
                )
                .await
                {
                    Ok(record) => {
                        Some(data_str(record.data(), "title").unwrap_or_else(|| "Contract".into()))
                    }
                    Err(AppError::NotFound | AppError::Forbidden) => None,
                    Err(e) => return Err(e),
                };
                titles.insert(contract_id, title.clone());
                title
            }
        };
        let Some(contract_title) = contract_title else {
            continue;
        };
        let clause = match attome_records::entity_crud::read_record(
            state,
            &ctx.security,
            "contract_clause",
            clause_id,
        )
        .await
        {
            Ok(record) => record,
            Err(AppError::NotFound | AppError::Forbidden) => continue,
            Err(e) => return Err(e),
        };
        let data = clause.data();
        let body = [data_str(data, "body_html"), data_str(data, "body_ar_html")]
            .into_iter()
            .flatten()
            .map(|h| plain_text(&h))
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        if body.is_empty() {
            continue;
        }
        evidence.push(ClauseEvidence {
            contract_id,
            contract_title,
            clause_id,
            clause_title: data_str(data, "title").unwrap_or_default(),
            passage: body.chars().take(PASSAGE_CHARS).collect(),
        });
    }
    Ok(evidence)
}

fn answer_system_prompt() -> String {
    "You answer staff questions about the terms of the company's contracts using only \
     the clause passages provided. Each passage is labelled with an evidence id such as \
     E1 and names its contract and clause.\n\n\
     Reply with exactly one JSON object and nothing else:\n\
     {\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
     \"citations\": [evidence ids]}\n\n\
     Use \"answered\" only when the passages contain the answer. State only what they \
     say, name the contract each point comes from, and list the id of every passage you \
     used in \"citations\". Do not add legal advice of your own.\n\n\
     Use \"insufficient\" when the passages do not answer the question. Then \"answer\" \
     is an empty string and \"citations\" is empty.\n\n\
     Write the answer in the language of the question."
        .to_owned()
}

fn answer_segments(question: &str, evidence: &[ClauseEvidence]) -> Vec<Segment> {
    let mut segments = vec![
        Segment::trusted(answer_system_prompt()),
        Segment::untrusted("question", question),
    ];
    for (index, e) in evidence.iter().enumerate() {
        segments.push(Segment::untrusted(
            evidence_id(index),
            format!(
                "Contract: {}\nClause: {}\n\n{}",
                e.contract_title, e.clause_title, e.passage
            ),
        ));
    }
    segments
}

fn declined(reason: DeclineReason) -> Value {
    json!({ "status": "declined", "reason": reason.as_str() })
}

struct Answer;

impl Action for Answer {
    fn id(&self) -> ActionId {
        ActionId(ANSWER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let question = args["question"].as_str().map(str::trim).unwrap_or_default();
            if question.is_empty() || question.chars().count() > 1000 {
                return Err(AppError::Validation(
                    "question: 1 to 1,000 characters".into(),
                ));
            }
            let contract = match args.get("contract_id") {
                None | Some(Value::Null) => None,
                Some(_) => Some(contract_id(args)?),
            };
            // Retrieval first, as the caller: no evidence, no model call.
            let evidence = clause_evidence(state, ctx, question, contract).await?;
            if evidence.is_empty() {
                return Ok(ActionResult::plain(declined(DeclineReason::NoEvidence)));
            }
            let client = crate::inference_client::client_for(state, ANSWER).await?;
            let mut request = attome_inference::GenerationRequest::new(crate::prompt::assemble(
                &answer_segments(question, &evidence),
            ));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                ANSWER,
            )
            .await?;
            let started = std::time::Instant::now();
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                ANSWER,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "contract.answer generation failed");
                AppError::internal("answer generation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            let latency_ms = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
            let verdict = judge(&generated.text, generated.truncated, evidence.len());
            let suggestion_id = crate::telemetry::record_suggestion(
                &state.base.db,
                &crate::telemetry::SuggestionRecord {
                    action_id: ANSWER,
                    model_id: &generated.usage.model_id,
                    prompt_version: ANSWER_PROMPT_VERSION,
                    entity_logicalname: "contract_clause",
                    field_ref: None,
                    record_id: None,
                    user_ref: Some(ctx.security.user_id),
                    organization_ref: None,
                    agent_session_ref: ctx.agent_session_id,
                    latency_ms: Some(latency_ms),
                    prompt_tokens: i32::try_from(generated.usage.prompt_tokens).ok(),
                    completion_tokens: i32::try_from(generated.usage.completion_tokens).ok(),
                },
            )
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "failed to log a contract answer");
            })
            .ok();
            let value = match verdict {
                Verdict::Answered { answer, cited } => {
                    let citations: Vec<&ClauseEvidence> =
                        cited.iter().map(|i| &evidence[*i]).collect();
                    let passages: Vec<&str> =
                        citations.iter().map(|c| c.passage.as_str()).collect();
                    let claims = super::claim_check::check(&answer, &passages);
                    json!({
                        "status": "answered",
                        "answer": answer,
                        "citations": citations,
                        "claims": claims,
                    })
                }
                Verdict::Declined(reason) => declined(reason),
            };
            Ok(ActionResult {
                value,
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: ANSWER_PROMPT_VERSION.to_owned(),
                    suggestion_id,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_question_becomes_safe_search_terms() {
        assert_eq!(
            query_terms("What is the liability cap? Liability & 'cap' | !x"),
            vec!["what", "the", "liability", "cap"]
        );
        assert_eq!(query_terms("ما هو حد المسؤولية"), vec!["المسؤولية"]);
        assert!(query_terms("a b !").is_empty());
    }

    #[test]
    fn rich_text_reads_as_plain_text() {
        assert_eq!(
            plain_text(
                "<p>Liability is capped at <b>12</b>&nbsp;months&#39; fees &amp; costs.</p>"
            ),
            "Liability is capped at 12 months' fees & costs."
        );
    }

    #[test]
    fn a_summary_keeps_the_terms_it_may_show() {
        let data = json!({
            "title": "Supply", "contract_value": 100, "currency": "SAR",
            "owner_ref": "someone", "current_terms": "secret", "end_date": null
        });
        let terms = summary_fields(&data);
        assert_eq!(terms.len(), 3);
        assert!(!terms.contains_key("owner_ref"));
        assert!(
            !terms.contains_key("end_date"),
            "an empty field is left out"
        );
    }

    #[test]
    fn both_actions_read_only() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        }
    }
}
