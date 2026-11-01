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
//! All three need the caller to read the entity (the account for the
//! brief, through the record engine, so record-level access applies).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const ENRICH_RECORD: &str = "sales.enrich.record";
pub const ENRICH_LIST: &str = "sales.enrich.list";
pub const ACCOUNT_BRIEF: &str = "sales.account.brief";

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
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(EnrichRecord),
        Box::new(EnrichList),
        Box::new(AccountBrief),
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
