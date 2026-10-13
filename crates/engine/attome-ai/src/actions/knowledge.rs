//! `search.knowledge` — retrieve passages from the published knowledge corpus
//! (M37 / D-489; the action `actions/mod.rs` reserved for "when Track B
//! delivers them").
//!
//! ## It wraps the one enforcement path, it does not build a second
//!
//! The executor calls `attome_search::knowledge::search_knowledge_recorded` — the
//! same function the `GET /api/v1/search/knowledge` route calls — with the
//! caller's own `SecurityContext`. Record-level visibility, the collection
//! permission anchor, and the never-retrieve-a-draft filter are therefore one
//! implementation rather than two that must keep agreeing (I-1). An executor
//! that ran its own query would be exactly the drift I-2 exists to prevent.
//!
//! ## The result is untrusted content
//!
//! A knowledge article is authored to be authoritative and is quoted
//! verbatim, which makes it the highest-value injection target on the
//! platform. The result returned here is plain JSON; the agent loop wraps
//! every tool result as an untrusted block (`turn::assemble_messages`, I-10),
//! so an article can reach a prompt as evidence and never as an instruction.
//!
//! ## Two telemetry writes, both best-effort, made by the shared function
//!
//! `search_knowledge_recorded` records the chunk ids (`record_chunk_retrievals`)
//! for a non-empty result, which is what makes the crawl-value loop
//! measurable, or a gap topic (`record_gap_topic`) for an **empty** one — the
//! `NoResults` branch of D-452's policy. This executor does not duplicate
//! either call: the route and the action sharing one wrapper is what keeps a
//! future third caller from forgetting the write the route once did.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_search::knowledge::{DEFAULT_KNOWLEDGE_LIMIT, MAX_KNOWLEDGE_LIMIT};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// The action id.
pub const SEARCH_KNOWLEDGE: &str = "search.knowledge";

/// A-62: the result a knowledge action returns for a counting or totalling
/// question instead of retrieving. `route` names the search router's own
/// classification; `use` names the action that answers such a question.
/// Nothing is retrieved and no telemetry is recorded — there was no search.
pub(crate) fn aggregation_hand_off() -> Value {
    serde_json::json!({
        "route": "aggregation",
        "use": "query.execute",
        "note": "This is a counting or totalling question. Knowledge articles cannot answer it; use query.execute with a stored query.",
    })
}

const SEARCH_KNOWLEDGE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "The policy or procedure question, in the user's own words. Do NOT put a record id or customer name here - this searches published articles, not records."
    },
    "limit": { "type": "integer", "minimum": 1, "maximum": 20, "default": 5 }
  },
  "required": ["query"],
  "additionalProperties": false
}"#;

/// The descriptor.
///
/// Not cacheable, deliberately: a cache hit would skip
/// `record_chunk_retrievals`, and that per-chunk count is the *only* signal
/// that says which part of the corpus earns its place — the measurement half
/// of the demand and crawl-value loops. Serving from cache to save a query
/// would trade the asset for the cheap part.
pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        SEARCH_KNOWLEDGE,
        "Find passages in published knowledge articles that explain policy \
         or procedure. Use this for 'how do I', 'what is our policy on', \
         'is X allowed'. Returns passages with citations. It does NOT know \
         anything about specific customer records.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(SEARCH_KNOWLEDGE_SCHEMA)
}

/// `deny_unknown_fields` because the published schema says
/// `additionalProperties: false`. Without it the executor would accept fields
/// the contract rejects, and a model inventing `entity` or `record_id` would
/// get a silently different search instead of a 422 — the same "the schema is a
/// contract, not decoration" rule `read.rs`'s `RecordArgs` follows.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<i64>,
}

/// The executor.
#[derive(Debug)]
pub struct SearchKnowledge;

impl Action for SearchKnowledge {
    fn id(&self) -> ActionId {
        ActionId(SEARCH_KNOWLEDGE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SearchArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid search.knowledge arguments: {e}"))
            })?;
            let query = args.query.trim();
            if query.is_empty() {
                return Err(AppError::Validation("query must not be empty".into()));
            }
            // A-62: a counting question is not a knowledge question — the
            // search router's own classification, the rule `search.records`
            // already applies. No retrieval, no gap recorded.
            if !crate::turn::is_knowledge_question(query) {
                let mut result = aggregation_hand_off();
                result["passages"] = serde_json::json!([]);
                result["abstained"] = serde_json::json!(true);
                return Ok(ActionResult::plain(result));
            }
            let limit = args
                .limit
                .unwrap_or(DEFAULT_KNOWLEDGE_LIMIT)
                .clamp(1, MAX_KNOWLEDGE_LIMIT);

            // THE point of this executor: the same function the HTTP route
            // calls, with the caller's own security context. There is no
            // knowledge-specific permission rule here. `_recorded` also makes
            // the gap/retrieval telemetry write here the same call the route
            // makes, rather than two copies that can drift (one already had).
            // D-512 §7: the session's knowledge scope is enforced inside
            // retrieval, never as an advisory filter on what comes back.
            let hits = attome_search::search_knowledge_recorded(
                &state.base.db,
                &ctx.security,
                query,
                limit,
                ctx.session_knowledge_source_refs.as_deref(),
            )
            .await?;

            let passages = hits
                .iter()
                .map(|hit| serde_json::to_value(&hit.citation))
                .collect::<Result<Vec<Value>, _>>()
                .map_err(|e| AppError::internal(format!("citation serialization failed: {e}")))?;

            Ok(ActionResult::plain(serde_json::json!({
                "passages": passages,
                "abstained": hits.is_empty(),
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A knowledge search reads platform data and reaches nothing outside the
    /// deployment. `Effect::Read` is also what lets a read-only bot session
    /// offer it, which is where it earns its place.
    #[test]
    fn it_is_a_read_with_no_outside_effect() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.retry, RetryClass::Idempotent);
    }

    /// **Not cacheable, and this is the reason.** `record_chunk_retrievals`
    /// is the demand signal; a cached hit would silently stop recording it,
    /// and the corpus would look equally useful whether or not anyone read
    /// it.
    #[test]
    fn retrieval_telemetry_is_never_skipped_by_a_cache_hit() {
        assert!(!descriptor().cacheable);
    }

    /// An empty query is a validation error, not a match-everything query. A
    /// model that emits `""` must be told to fix its arguments.
    #[test]
    fn an_empty_query_cannot_reach_postgres() {
        let parsed: Result<SearchArgs, _> =
            serde_json::from_value(serde_json::json!({ "query": "" }));
        assert!(parsed.is_ok());
        assert!(parsed.expect("parses").query.trim().is_empty());
    }

    /// **D-512 §7.** The executor's one retrieval passes the session's
    /// knowledge scope, so a session narrowed to some collections never
    /// returns a passage from another.
    #[test]
    fn retrieval_is_bound_by_the_session_knowledge_scope() {
        let source = include_str!("knowledge.rs");
        let code = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("test marker");
        let call = code
            .find("search_knowledge_recorded(")
            .expect("the executor retrieves");
        let args = &code[call..call + 300];
        assert!(
            args.contains("ctx.session_knowledge_source_refs.as_deref()"),
            "retrieval must pass the session knowledge scope: {args}"
        );
        assert_eq!(code.matches("search_knowledge_recorded(").count(), 1);
    }

    /// Arguments are parsed strictly: an unknown field is rejected rather
    /// than ignored, so a model inventing `entity` or `record_id` gets a 422
    /// instead of a silently different search. The schema's
    /// `additionalProperties: false` is only true because of the
    /// `deny_unknown_fields` attribute above it.
    #[test]
    fn an_unknown_argument_is_rejected() {
        let parsed: Result<SearchArgs, _> = serde_json::from_value(serde_json::json!({
            "query": "refund policy",
            "entity": "account"
        }));
        assert!(parsed.is_err(), "unknown arguments must not be ignored");
    }
}
