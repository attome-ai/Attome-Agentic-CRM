//! Enrichment tools (roadmap D24-T9).
//!
//! - `sales.enrich.record` queues one record's enrichment by a provider
//!   (L9's queue, `attome_sales::enrichment::queue`). Nothing is written to
//!   the record: the run makes proposals a person accepts.
//! - `sales.enrich.list` queues up to 500 records of one entity. An agent
//!   always stops for confirmation, and the answer carries the cost
//!   estimate against the provider's daily budget (calls, budget left,
//!   records the budget misses today).
//! - `sales.account.brief` drafts a short account brief in which every line
//!   names where it came from: the account record itself (its id), or an
//!   enrichment source (the registry's CR, the website's URL) with the time
//!   it was fetched. Read only, and no model call: the lines are the facts.
//!
//! - `sales.suggest_arabic_names` (D24-T8) asks the model for the Arabic
//!   form of accounts' Latin legal names, 20 a call, and files each as a
//!   `review` proposal from the source `model`: a suggestion a person
//!   accepts, never a fill. An account whose Arabic name is filled, or has a
//!   pending registry (or other provider) value, gets none: the registry
//!   outranks the model (`attome_sales::enrichment::arabic_names`).
//!
//! All of them need the caller to read the entity (the account for the
//! brief, through the record engine, so record-level access applies).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const ENRICH_RECORD: &str = "sales.enrich.record";
pub const ENRICH_LIST: &str = "sales.enrich.list";
pub const ACCOUNT_BRIEF: &str = "sales.account.brief";
pub const SUGGEST_ARABIC_NAMES: &str = "sales.suggest_arabic_names";

const ARABIC_PROMPT_VERSION: &str = "sales.suggest_arabic_names/v1";

/// Accounts one call may ask about.
const MAX_ARABIC_ACCOUNTS: usize = 100;

const RECORD_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "The entity, such as account or lead." },
    "id": { "type": "string", "format": "uuid", "description": "The record." },
    "provider": { "type": "string", "enum": ["registry", "national_address", "website"] }
  },
  "required": ["entity", "id", "provider"],
  "additionalProperties": false
}"#;

const LIST_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "The entity, such as account or lead." },
    "ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 500 },
    "provider": { "type": "string", "enum": ["registry", "national_address", "website"] }
  },
  "required": ["entity", "ids", "provider"],
  "additionalProperties": false
}"#;

const ARABIC_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "account_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 100 }
  },
  "required": ["account_ids"],
  "additionalProperties": false
}"#;

const BRIEF_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "account_id": { "type": "string", "format": "uuid", "description": "The account." }
  },
  "required": ["account_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            ENRICH_RECORD,
            "Queue one record's enrichment by a provider (the commercial register, the National \
             Address or the company website). The run proposes field values with their source; \
             it never changes the record.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(RECORD_INPUT),
        ActionDescriptor::new(
            ENRICH_LIST,
            "Queue up to 500 records of one entity for enrichment by a provider, within its daily \
             budget; answers the cost estimate (calls, budget left, records the budget misses). \
             Proposals only. An agent always asks a person first.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(LIST_INPUT)
        .agent_must_confirm(),
        ActionDescriptor::new(
            ACCOUNT_BRIEF,
            "Draft a short brief of an account in which every line cites its source: the account \
             record or an enrichment source (registry, website) with when it was fetched. Changes \
             nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(BRIEF_INPUT),
        ActionDescriptor::new(
            SUGGEST_ARABIC_NAMES,
            "Suggest the Arabic form of accounts' Latin legal names, as proposals a person \
             accepts. An account whose Arabic name is filled or has a registry value gets none.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(ARABIC_INPUT),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(EnrichRecord),
        Box::new(EnrichList),
        Box::new(AccountBrief),
        Box::new(SuggestArabicNames),
    ]
}

fn text_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation(format!("{key} is required")))
}

fn uuid_of(value: &Value, key: &str) -> Result<Uuid, AppError> {
    value
        .as_str()
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

struct EnrichRecord;

impl Action for EnrichRecord {
    fn id(&self) -> ActionId {
        ActionId(ENRICH_RECORD)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = text_arg(args, "entity")?;
            let provider = text_arg(args, "provider")?;
            let id = uuid_of(args.get("id").unwrap_or(&Value::Null), "id")?;
            // The record itself must be readable, not just the entity.
            attome_records::entity_crud::read_record(state, &ctx.security, entity, id).await?;
            let estimate = attome_sales::enrichment::queue::enqueue(
                state,
                &ctx.security,
                entity,
                vec![id],
                provider,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "queued": 1,
                "entity": entity,
                "provider": provider,
                "estimate": estimate,
            })))
        })
    }
}

struct EnrichList;

impl Action for EnrichList {
    fn id(&self) -> ActionId {
        ActionId(ENRICH_LIST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = text_arg(args, "entity")?;
            let provider = text_arg(args, "provider")?;
            let ids = args
                .get("ids")
                .and_then(Value::as_array)
                .ok_or_else(|| AppError::Validation("ids is required".into()))?
                .iter()
                .map(|v| uuid_of(v, "ids"))
                .collect::<Result<Vec<Uuid>, AppError>>()?;
            let estimate = attome_sales::enrichment::queue::enqueue(
                state,
                &ctx.security,
                entity,
                ids.clone(),
                provider,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "queued": ids.len(),
                "entity": entity,
                "provider": provider,
                "estimate": estimate,
            })))
        })
    }
}

/// One brief line and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefLine {
    pub statement: String,
    /// A URL, or `record:<entity>/<id>`.
    pub source: String,
}

/// The account fields a brief states, with their label.
const BRIEF_FIELDS: [(&str, &str); 8] = [
    ("name", "Name"),
    ("legal_name_en", "Legal name"),
    ("legal_name_ar", "Legal name (Arabic)"),
    ("industry", "Industry"),
    ("cr_number", "Commercial registration"),
    ("founded_year", "Founded"),
    ("hq_address", "Head office"),
    ("website", "Website"),
];

fn shown(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Where a proposal from `source` came from, for a citation. Pure.
fn proposal_source(source: &str, account: &Value) -> String {
    match source {
        "website" => account
            .get("website")
            .and_then(Value::as_str)
            .and_then(attome_sales::enrichment::free_sources::site_root)
            .map_or_else(|| "website".to_owned(), |u| u.to_string()),
        "registry" => account
            .get("cr_number")
            .and_then(Value::as_str)
            .map_or_else(|| "registry".to_owned(), |cr| format!("registry:CR {cr}")),
        other => other.to_owned(),
    }
}

/// A brief of `account` (its fields) and its pending enrichment proposals
/// (`(field, proposed value, source, fetched_at)`), each line citing its
/// source. Pure.
pub fn brief_lines(
    account_id: Uuid,
    account: &Value,
    proposals: &[(String, Value, String, String)],
) -> Vec<BriefLine> {
    let record = format!("record:account/{account_id}");
    let mut lines: Vec<BriefLine> = BRIEF_FIELDS
        .iter()
        .filter_map(|(field, label)| {
            account.get(*field).and_then(shown).map(|v| BriefLine {
                statement: format!("{label}: {v}"),
                source: record.clone(),
            })
        })
        .collect();
    for (field, value, source, fetched_at) in proposals {
        let Some(v) = shown(value) else { continue };
        let label = BRIEF_FIELDS
            .iter()
            .find(|(f, _)| f == field)
            .map_or(field.as_str(), |(_, l)| l);
        lines.push(BriefLine {
            statement: format!("{label} (proposed, fetched {fetched_at}): {v}"),
            source: proposal_source(source, account),
        });
    }
    lines
}

struct AccountBrief;

impl Action for AccountBrief {
    fn id(&self) -> ActionId {
        ActionId(ACCOUNT_BRIEF)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = uuid_of(args.get("account_id").unwrap_or(&Value::Null), "account_id")?;
            let record =
                attome_records::entity_crud::read_record(state, &ctx.security, "account", id)
                    .await?;
            let account = record.data().clone();
            let proposals: Vec<(String, Value, String, String)> = sqlx::query_as(
                "SELECT field, proposed_value, source, \
                        to_char(fetched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
                   FROM enrichment_proposal \
                  WHERE entity_logicalname = 'account' AND record_id = $1 AND status = 'pending' \
                  ORDER BY field, source LIMIT 50",
            )
            .bind(id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let lines = brief_lines(id, &account, &proposals);
            let text: String = lines
                .iter()
                .map(|l| format!("- {} [{}]", l.statement, l.source))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(ActionResult::plain(json!({
                "account_id": id,
                "brief": text,
                "lines": lines
                    .iter()
                    .map(|l| json!({ "statement": l.statement, "source": l.source }))
                    .collect::<Vec<_>>(),
            })))
        })
    }
}

fn arabic_system_prompt() -> String {
    "You give the Arabic form a Saudi company would use for its registered name. Each \
     passage is one company's Latin name. Reply with only a JSON array of strings, one per \
     passage, in the same order: the Arabic form of that name, transliterated where it is a \
     proper name and translated where it is a common word (Company, Foods, Trading). Do not \
     add or drop entries."
        .to_owned()
}

/// D24-T8 step 1: after an enrichment run over accounts, asks for the
/// Arabic form of their Latin legal names as an agent of `requester` (the
/// person who queued the run), through the gate like any agent call: the
/// requester's access, the approved model, their AI budget and the audit
/// all apply, and the accounts that need no suggestion are skipped by the
/// action itself. The suggestions it made; a refusal (no AI, no licence,
/// no budget, no access) is the requester's normal state and answers 0.
pub async fn suggest_after_enrichment(
    state: &EngineState,
    requester: Uuid,
    account_ids: &[Uuid],
) -> Result<u64, AppError> {
    if account_ids.is_empty() {
        return Ok(0);
    }
    let security = state.base.security.resolve(requester).await?;
    let ctx = ActionContext::agent(security, RiskTier::Reversible);
    let module = crate::engine::REGISTRY
        .resolve(SUGGEST_ARABIC_NAMES)
        .map(|d| d.module)
        .ok_or(AppError::NotFound)?;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, module);
    let mut suggested = 0;
    for chunk in account_ids.chunks(MAX_ARABIC_ACCOUNTS) {
        let args = json!({ "account_ids": chunk });
        let outcome = crate::execute::dispatch(
            state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            SUGGEST_ARABIC_NAMES,
            &ctx,
            &inputs,
            &args,
        )
        .await;
        match outcome {
            Ok(crate::execute::ActionOutcome::Completed { result, .. }) => {
                suggested += result.get("suggested").and_then(Value::as_u64).unwrap_or(0);
            }
            Ok(_) => return Ok(suggested),
            Err(error @ (AppError::NotFound | AppError::Forbidden | AppError::Validation(_))) => {
                tracing::debug!(%requester, %error, "Arabic name suggestions: not made");
                return Ok(suggested);
            }
            Err(AppError::TooManyRequests { .. }) => {
                tracing::info!(%requester, "Arabic name suggestions: the AI budget is spent");
                return Ok(suggested);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(suggested)
}

/// An account as the Arabic names step reads it: id, Latin and Arabic
/// legal names, the sources of its pending Arabic values.
type NameRow = (Uuid, Option<String>, Option<String>, Vec<String>);

struct SuggestArabicNames;

impl Action for SuggestArabicNames {
    fn id(&self) -> ActionId {
        ActionId(SUGGEST_ARABIC_NAMES)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            use attome_sales::enrichment::arabic_names::{
                BATCH, MODEL_SOURCE, needs_suggestion, parse_reply,
            };
            let ids = args
                .get("account_ids")
                .and_then(Value::as_array)
                .ok_or_else(|| AppError::Validation("account_ids is required".into()))?
                .iter()
                .map(|v| uuid_of(v, "account_ids"))
                .collect::<Result<Vec<Uuid>, AppError>>()?;
            if ids.is_empty() || ids.len() > MAX_ARABIC_ACCOUNTS {
                return Err(AppError::Validation(format!(
                    "between 1 and {MAX_ARABIC_ACCOUNTS} accounts"
                )));
            }
            ctx.security.require("account", "update")?;
            let entity_id = state
                .entities
                .load()
                .get("account")
                .map(|m| m.entity_id)
                .ok_or(AppError::NotFound)?;
            let readable = attome_records::changes::readable_ids(
                state,
                &ctx.security,
                entity_id,
                "account",
                &ids,
            )
            .await?;
            let readable: Vec<Uuid> = ids.into_iter().filter(|id| readable.contains(id)).collect();
            let rows: Vec<NameRow> = sqlx::query_as(
                "SELECT a.id, a.legal_name_en::text, a.legal_name_ar::text, \
                        COALESCE((SELECT array_agg(p.source) FROM enrichment_proposal p \
                                   WHERE p.entity_logicalname = 'account' AND p.record_id = a.id \
                                     AND p.field = 'legal_name_ar' AND p.status = 'pending'), \
                                 ARRAY[]::text[]) \
                   FROM account a WHERE a.id = ANY($1)",
            )
            .bind(&readable)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let candidates: Vec<(Uuid, String, Option<String>)> = rows
                .into_iter()
                .filter(|(_, latin, arabic, pending)| {
                    let pending: Vec<&str> = pending.iter().map(String::as_str).collect();
                    let arabic = arabic.clone().map(Value::String);
                    needs_suggestion(latin.as_deref(), arabic.as_ref(), &pending)
                })
                .filter_map(|(id, latin, arabic, _)| latin.map(|l| (id, l, arabic)))
                .collect();
            if candidates.is_empty() {
                return Ok(ActionResult::plain(json!({ "suggested": 0, "asked": 0 })));
            }
            let client = crate::inference_client::client_for(state, SUGGEST_ARABIC_NAMES).await?;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                SUGGEST_ARABIC_NAMES,
            )
            .await?;
            let mut suggested = 0usize;
            let mut model_id = String::new();
            for batch in candidates.chunks(BATCH) {
                let mut segments = vec![crate::prompt::Segment::trusted(arabic_system_prompt())];
                for (index, (_, latin, _)) in batch.iter().enumerate() {
                    segments.push(crate::prompt::Segment::untrusted(
                        format!("N{}", index + 1),
                        latin.clone(),
                    ));
                }
                let mut request =
                    attome_inference::GenerationRequest::new(crate::prompt::assemble(&segments));
                request.temperature = 0.0;
                let grant = crate::budget_guard::admit(
                    state,
                    ctx,
                    attome_inference::budget::Priority::Chat,
                    SUGGEST_ARABIC_NAMES,
                    &mut request,
                )
                .await?;
                let generated = client.generate(request).await.map_err(|e| {
                    tracing::warn!(error = %e, "sales.suggest_arabic_names generation failed");
                    AppError::internal("suggestion generation failed")
                })?;
                grant.settle(state, &generated.usage).await;
                model_id.clone_from(&generated.usage.model_id);
                for ((id, _, current), form) in
                    batch.iter().zip(parse_reply(&generated.text, batch.len()))
                {
                    let Some(form) = form else { continue };
                    sqlx::query(
                        "INSERT INTO enrichment_proposal \
                             (entity_logicalname, record_id, field, current_value, proposed_value, \
                              kind, source, fetched_at) \
                         VALUES ('account', $1, 'legal_name_ar', $2, $3, 'review', $4, now()) \
                         ON CONFLICT (entity_logicalname, record_id, field, source) \
                             WHERE status = 'pending' \
                         DO UPDATE SET proposed_value = EXCLUDED.proposed_value, \
                                       fetched_at = EXCLUDED.fetched_at",
                    )
                    .bind(id)
                    .bind(current.as_ref().map_or(Value::Null, |c| json!(c)))
                    .bind(json!(form))
                    .bind(MODEL_SOURCE)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    suggested += 1;
                }
            }
            Ok(ActionResult {
                value: json!({ "suggested": suggested, "asked": candidates.len() }),
                provenance: Some(crate::execute::Provenance {
                    model_id,
                    prompt_version: ARABIC_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_enrich_requires_confirmation() {
        let all = descriptors();
        let list = all.iter().find(|d| d.id.0 == ENRICH_LIST).expect("listed");
        assert!(list.agent_must_confirm);
        let brief = all
            .iter()
            .find(|d| d.id.0 == ACCOUNT_BRIEF)
            .expect("listed");
        assert_eq!(brief.risk, RiskTier::Read);
    }

    #[test]
    fn brief_cites_sources() {
        let id = Uuid::now_v7();
        let account = json!({
            "name": "Al Nakheel Foods",
            "cr_number": "1010123456",
            "website": "alnakheel.sa",
            "industry": ""
        });
        let proposals = vec![
            (
                "phone".to_owned(),
                json!("+966 11 234 5678"),
                "website".to_owned(),
                "2026-11-01T10:00:00Z".to_owned(),
            ),
            (
                "legal_name_ar".to_owned(),
                json!("شركة النخيل للأغذية"),
                "registry".to_owned(),
                "2026-11-01T10:00:00Z".to_owned(),
            ),
        ];
        let lines = brief_lines(id, &account, &proposals);
        assert!(lines.iter().all(|l| !l.source.is_empty()));
        assert_eq!(lines[0].statement, "Name: Al Nakheel Foods");
        assert_eq!(lines[0].source, format!("record:account/{id}"));
        assert!(
            lines
                .iter()
                .any(|l| l.source == "https://alnakheel.sa/" && l.statement.contains("+966")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.source == "registry:CR 1010123456"),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.statement.starts_with("Industry")));
    }
}
