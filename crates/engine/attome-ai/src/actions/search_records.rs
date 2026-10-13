//! `search.records` — find records by name, keyword or partial text (C5;
//! closes G9, the tool description the old chat loop carried with no
//! action behind it).
//!
//! ## It wraps the one enforcement path, it does not build a second
//!
//! The executor calls `attome_search::routes::execute_search` — the function the
//! `GET /api/v1/search` handler, a saved search's run and the saved-search
//! alert sweep all call — with the caller's own `SecurityContext`, after the
//! same `validate_query`/`validate_paging` the handler runs. Record-level
//! visibility, the access-map cache and the aggregation short-circuit are one
//! implementation, not two that must keep agreeing (I-1).
//!
//! ## Licensed as search, not as AI
//!
//! The descriptor's module is `MODULE_SEARCH`, the module that gates the HTTP
//! search route. `gate::admissible` refuses an action whose module is not
//! licensed, so a deployment without search cannot reach record search
//! through the chatbot or an MCP host either — the licence boundary holds on
//! every surface rather than only on the route. (`search.knowledge` is
//! `MODULE_AI`: the knowledge base is part of the AI module; record search is
//! not.)
//!
//! ## The result is untrusted content
//!
//! Snippets are record text, attacker-influenceable. The agent loop wraps
//! every tool result in `Segment::Untrusted`, and the call taints the turn —
//! which is why a write proposed after a search is confirmed or approved,
//! never executed on the model's word alone.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_SEARCH;
use attome_search::router::Audience;
use attome_search::routes::{
    SearchResponse, Total, execute_search, route_name, validate_paging, validate_query,
};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// The action id.
pub const SEARCH_RECORDS: &str = "search.records";

/// A page a model can read. The route allows 100; a tool result that size is
/// context spent on rows the model will not use, so the published schema caps
/// lower and the default is a first page, not a dump.
const DEFAULT_PAGE_SIZE: i64 = 10;

const SEARCH_RECORDS_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "A name, keyword, identifier or partial text to look for, e.g. a customer name or an invoice number. Not a question to count or total - use query.execute for that."
    },
    "page": { "type": "integer", "minimum": 1, "default": 1 },
    "page_size": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 }
  },
  "required": ["query"],
  "additionalProperties": false
}"#;

/// The descriptor. The model-facing text is `turn::describe_for_model`'s (it
/// wins there); this is the same sentence, for every consumer
/// that reads the descriptor directly.
pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        SEARCH_RECORDS,
        "Find records by name, keyword, or partial text when you do not \
         know the id. Returns matches ranked by relevance. Do NOT use this \
         to count or total anything — it returns a page of results, not the \
         whole set, so any arithmetic over it is wrong.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_SEARCH,
        &[],
    )
    .input_schema(SEARCH_RECORDS_SCHEMA)
}

/// `deny_unknown_fields`: the schema says `additionalProperties: false`, and a
/// model inventing `entity` must get a 422, not a silently different search.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    page_size: Option<i64>,
}

/// The executor. `pub(crate)` like every C5 executor: `dispatch` is the only
/// way in.
pub(crate) struct SearchRecords;

impl Action for SearchRecords {
    fn id(&self) -> ActionId {
        ActionId(SEARCH_RECORDS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SearchArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid search.records arguments: {e}"))
            })?;
            let page = args.page.unwrap_or(1);
            let page_size = args.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
            if page_size > 25 {
                return Err(AppError::Validation(
                    "page_size must be between 1 and 25".into(),
                ));
            }
            // The handler's own validation, in the handler's order.
            let q = validate_query(&args.query)?;
            validate_paging(page, page_size)?;

            // The router tunes differently for a model assembling context
            // than for a person scanning a list; who is asking decides it,
            // never an argument the model chose.
            let audience = if ctx.is_agent() {
                Audience::Agent
            } else {
                Audience::Human
            };
            let response = match crate::mcp::admission::ReadAdmission::for_caller(state, ctx)? {
                None => execute_search(state, &ctx.security, &q, page, page_size, audience).await?,
                Some(admission) => {
                    admitted_search(state, ctx, &admission, &q, page, page_size, audience).await?
                }
            };
            let value = serde_json::to_value(&response)
                .map_err(|e| AppError::internal(format!("search serialization failed: {e}")))?;
            Ok(ActionResult::plain(value))
        })
    }
}

/// Candidates fetched per underlying search page when MCP admission filters
/// the result (the route's own maximum page size).
const ADMITTED_CANDIDATE_PAGE: i64 = 100;

/// Underlying pages scanned at most for one MCP call. Bounds the extra cost
/// of filtering to five route-sized searches; an admitted hit deeper than
/// that is not reached, and the total says `at_least`.
const ADMITTED_CANDIDATE_PAGES: i64 = 5;

/// D-769 / M3.4: `search.records` for an MCP agent. The same
/// `execute_search`, but a hit of an entity not admitted for read is dropped
/// **before** paging, so `page`, `page_size`, `has_more` and `total` describe
/// admitted hits only and never count, name or number a hidden one:
///
/// - a `type:`/`entity:` filter naming an unadmitted (or excluded) entity is
///   an empty page, as if that entity had no match;
/// - otherwise route-sized candidate pages are scanned, in rank order, until
///   the requested admitted page plus one look-ahead hit is filled, the
///   candidates run out, or [`ADMITTED_CANDIDATE_PAGES`] is spent;
/// - `total` is exact only when every candidate was scanned and the route's
///   own total was exact, otherwise `at_least` the admitted hits seen;
/// - `impression_id` is withheld: the logged impression lists hits the agent
///   was never shown.
async fn admitted_search(
    state: &EngineState,
    ctx: &ActionContext,
    admission: &crate::mcp::admission::ReadAdmission,
    q: &str,
    page: i64,
    page_size: i64,
    audience: Audience,
) -> Result<SearchResponse, AppError> {
    let route = attome_search::router::route(q, audience);
    let is_aggregation = matches!(route, attome_search::router::Route::Aggregation { .. });
    if !is_aggregation
        && let Some(entity) = attome_search::dsl::parse(q).entity_filter
        && !admission.admits(&entity)
    {
        tracing::info!(
            action = SEARCH_RECORDS,
            entity = entity.as_str(),
            agent_session_id = ?ctx.agent_session_id,
            "MCP search filter names an entity not admitted for read; answered empty"
        );
        return Ok(SearchResponse {
            items: Vec::new(),
            total: Total::Exact { value: 0 },
            page,
            page_size,
            has_more: false,
            route: route_name(&route).to_owned(),
            degraded: Vec::new(),
            route_hint: None,
            impression_id: None,
        });
    }

    let page_len = usize::try_from(page_size).unwrap_or(0);
    let skip = usize::try_from((page - 1).saturating_mul(page_size)).unwrap_or(usize::MAX);
    let mut items = Vec::with_capacity(page_len + 1);
    let mut admitted_seen: u64 = 0;
    let mut scanned_all = false;
    let mut route_exact = true;
    let mut first: Option<SearchResponse> = None;
    let mut degraded: Vec<String> = Vec::new();

    for candidate_page in 1..=ADMITTED_CANDIDATE_PAGES {
        let mut response = execute_search(
            state,
            &ctx.security,
            q,
            candidate_page,
            ADMITTED_CANDIDATE_PAGE,
            audience,
        )
        .await?;
        route_exact &= matches!(response.total, Total::Exact { .. });
        for name in response.degraded.drain(..) {
            if !degraded.contains(&name) {
                degraded.push(name);
            }
        }
        let more = response.has_more;
        for hit in response.items.drain(..) {
            if !admission.admits(&hit.entity_logicalname) {
                continue;
            }
            admitted_seen += 1;
            if usize::try_from(admitted_seen).unwrap_or(usize::MAX) > skip
                && items.len() <= page_len
            {
                items.push(hit);
            }
        }
        if first.is_none() {
            first = Some(response);
        }
        if !more {
            scanned_all = true;
            break;
        }
        if items.len() > page_len {
            break;
        }
    }

    let has_more = items.len() > page_len;
    items.truncate(page_len);
    let total = if scanned_all && route_exact {
        Total::Exact {
            value: admitted_seen,
        }
    } else {
        Total::AtLeast {
            value: admitted_seen,
        }
    };
    let first = first.ok_or_else(|| AppError::internal("search returned no page"))?;
    Ok(SearchResponse {
        items,
        total,
        page,
        page_size,
        has_more,
        route: first.route,
        degraded,
        route_hint: first.route_hint,
        impression_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read with no outside effect, which keeps it in the chatbot's
    /// read-only tool set and out of every confirmation path.
    #[test]
    fn it_is_an_idempotent_read() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.retry, RetryClass::Idempotent);
        assert!(!d.agent_must_confirm);
    }

    /// The licence boundary of the HTTP route, not the AI module's.
    #[test]
    fn it_is_licensed_as_search() {
        assert_eq!(descriptor().module, MODULE_SEARCH);
    }

    /// The descriptor and the model-facing description say the same thing,
    /// including the arithmetic disclaimer.
    #[test]
    fn the_descriptor_matches_the_selection_text() {
        assert_eq!(
            crate::turn::describe_for_model(&descriptor()),
            descriptor().description
        );
    }

    #[test]
    fn unknown_arguments_are_refused() {
        let parsed: Result<SearchArgs, _> =
            serde_json::from_value(serde_json::json!({ "query": "acme", "entity": "account" }));
        assert!(parsed.is_err());
    }
}
