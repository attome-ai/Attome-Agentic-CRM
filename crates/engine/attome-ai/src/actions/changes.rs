//! `changes.since` (roadmap L7-T8): an agent catches up on one entity from a
//! delta token (L7-T4), within its permissions.
//!
//! It runs `attome_records::query_exec::execute_delta` over the entity's
//! default list as the person the agent acts for, so the list's record scope
//! and field security decide what comes back: records created and updated
//! since the token as the list shows them, and the ids that left it. Without
//! a token it starts now (`latest`) and answers only a token. One call reads
//! delta windows until the next could pass [`MAX_RESULTS`] records, then
//! answers `next_token` and whether more wait. An MCP agent is admitted per
//! entity by the dispatcher (the `entity` argument), and lookup names into
//! entities it is not admitted to are stripped from each row.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_records::changes::{DELTA_LATEST, DELTA_PAGE};
use attome_records::query_exec::{ExecuteQueryRequest, execute_delta};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const CHANGES_SINCE: &str = "changes.since";

/// The most records (created, updated and deleted together) one call answers.
pub const MAX_RESULTS: usize = 500;

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "The entity's logical name." },
    "token": { "type": "string", "description": "The next_token of the previous call; leave out to start now." }
  },
  "required": ["entity"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        CHANGES_SINCE,
        "Catch up on one entity: the records created, updated and deleted since a token, as \
         the person may see them, and the next token. Call it once without a token to start.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[],
    )
    .input_schema(SCHEMA)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangesArgs {
    entity: String,
    #[serde(default)]
    token: Option<String>,
}

/// Whether another delta window fits in this call: more wait, and even a full
/// window keeps the answer within [`MAX_RESULTS`]. Pure.
pub fn may_read_another(answered: usize, has_more: bool) -> bool {
    has_more && answered + usize::try_from(DELTA_PAGE).unwrap_or(usize::MAX) <= MAX_RESULTS
}

pub(crate) struct ChangesSince;

impl Action for ChangesSince {
    fn id(&self) -> ActionId {
        ActionId(CHANGES_SINCE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: ChangesArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))?;
            let mut token = args
                .token
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| DELTA_LATEST.to_owned());
            let (mut created, mut updated, mut deleted) = (Vec::new(), Vec::new(), Vec::new());
            let has_more = loop {
                let request = ExecuteQueryRequest::for_entity_list(
                    args.entity.clone(),
                    Vec::new(),
                    String::new(),
                    "asc".to_owned(),
                    DELTA_PAGE,
                    None,
                    None,
                );
                let delta = execute_delta(state, &ctx.security, request, &token).await?;
                created.extend(delta.created);
                updated.extend(delta.updated);
                deleted.extend(delta.deleted);
                token = delta.next_token;
                if !may_read_another(
                    created.len() + updated.len() + deleted.len(),
                    delta.has_more,
                ) {
                    break delta.has_more;
                }
            };
            // D-769: lookup names into entities an MCP agent is not admitted
            // to read are stripped from each row.
            if let Some(admission) = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)? {
                let entity_id = state
                    .entities
                    .load()
                    .get(&args.entity)
                    .map(|meta| meta.entity_id);
                for rows in [&mut created, &mut updated] {
                    let mut wrapped = json!({ "data": { "records": std::mem::take(rows) } });
                    admission.redact_query_lookups(state, entity_id, &mut wrapped);
                    *rows = wrapped["data"]["records"]
                        .as_array_mut()
                        .map(std::mem::take)
                        .unwrap_or_default();
                }
            }
            Ok(ActionResult::plain(json!({
                "created": created,
                "updated": updated,
                "deleted": deleted,
                "next_token": token,
                "has_more": has_more,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call never answers more than 500 records: it stops reading windows
    /// while a full one could pass the cap, and when nothing more waits.
    #[test]
    fn changes_since_respects_cap() {
        let page = usize::try_from(DELTA_PAGE).unwrap();
        assert!(page <= MAX_RESULTS, "one window fits the cap");
        assert!(may_read_another(0, true));
        assert!(may_read_another(MAX_RESULTS - page, true));
        assert!(!may_read_another(MAX_RESULTS - page + 1, true));
        assert!(!may_read_another(0, false), "nothing more waits");
        // The most a call can hold: windows while one more still fits.
        let mut answered = 0;
        loop {
            answered += page;
            if !may_read_another(answered, true) {
                break;
            }
        }
        assert!(answered <= MAX_RESULTS);
    }

    #[test]
    fn changes_since_is_a_plain_read() {
        let d = descriptor();
        assert_eq!((d.risk, d.effect), (RiskTier::Read, Effect::Read));
        assert!(d.required_privileges.is_empty());
        assert!(
            serde_json::from_value::<ChangesArgs>(json!({"entity": "account", "sql": "x"}))
                .is_err()
        );
    }
}
