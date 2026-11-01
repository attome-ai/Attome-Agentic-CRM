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

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const REVIEW_AGAINST_PLAYBOOK: &str = "contract.review_against_playbook";
pub const SUMMARISE: &str = "contract.summarise";

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
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ReviewAgainstPlaybook), Box::new(Summarise)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
