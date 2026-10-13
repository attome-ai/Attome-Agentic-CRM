//! `graph.traverse` (M38 Phase 1) — a read-only wrapper around
//! `attome_search::graph::traverse`, the same bounded, permission-per-hop walk
//! `POST /api/v1/graph/traverse` runs. An action that built its own SQL here
//! would be a second way into the data — invariant I-2 exists precisely to
//! keep the security-critical part (permission applied at every hop, never
//! at the end) in one implementation, not two that could drift apart.
//!
//! Gated on `MODULE_AI`, distinct from the HTTP route's `MODULE_SEARCH` gate
//! (`attome-search/src/engine.rs`'s `SearchModel`): a deployment can license
//! retrieval without licensing the AI tool surface, and vice versa is
//! meaningless (the action has nothing to call without the engine) — the
//! same split `record.summarize` (`MODULE_AI`) vs `record.get`/
//! `query.execute` (`MODULE_CORE`) already draws in `read.rs`.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::Value;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const GRAPH_TRAVERSE: &str = "graph.traverse";

/// M101 slice 3 — the argument contract, mirroring
/// `attome_search::graph::TraverseRequest` (which this executor deserialises
/// directly). See `descriptor::UNDECLARED_SCHEMA` for why every action carries
/// one.
const GRAPH_TRAVERSE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "start": {
      "type": "object",
      "description": "The record to walk out from. Its id must already be known.",
      "properties": {
        "entity": { "type": "string" },
        "id": { "type": "string", "format": "uuid" }
      },
      "required": ["entity", "id"],
      "additionalProperties": false
    },
    "edge_types": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Restricts which edges are followed: \"lookup:{field}\", \"hierarchy:{field}\", \"relationship:{type}\", or bare \"relationship\" for every relationship type. Omit to follow everything the caller can see."
    },
    "direction": {
      "type": "string",
      "enum": ["outbound", "inbound", "both"],
      "default": "both"
    },
    "max_depth": {
      "type": "integer",
      "minimum": 1,
      "description": "Hops from the start record. Bounded by the engine's own ceiling."
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "description": "Maximum nodes returned. The result is a bounded set, never a complete one."
    }
  },
  "required": ["start"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            GRAPH_TRAVERSE,
            "Follow relationships between records the caller can already see \
         (lookup fields, record-to-record links, parent/child hierarchy), \
         up to a few hops from one starting record, to answer 'what is \
         connected to X' or 'how does X relate to Y'. Do NOT use this to \
         find a record by name or keyword — it starts from an id you already \
         know (use search.records to find one). Do NOT use this to count, \
         sum, or total anything — it returns a bounded set of nodes and \
         edges, not a complete result set (use query.execute). A record the \
         caller cannot read never appears in the result, even as a \
         pass-through hop to something else.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(GRAPH_TRAVERSE_SCHEMA),
    ]
}

struct GraphTraverse;

impl Action for GraphTraverse {
    fn id(&self) -> ActionId {
        ActionId(GRAPH_TRAVERSE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // Deserialised into the SAME request type the HTTP route uses
            // (`attome_search::graph::TraverseRequest`), so a model's job here
            // is limited to naming a start record, a direction, and depth/
            // limit bounds — there is no field on this type a model could
            // use to reach outside the one enforced walk.
            let req: attome_search::graph::TraverseRequest = serde_json::from_value(args.clone())
                .map_err(|e| {
                AppError::Validation(format!("invalid graph.traverse arguments: {e}"))
            })?;
            let limit = req.limit;

            // D-769 / M3.4: over MCP, the walk starts only from an admitted
            // entity (dark `NotFound` otherwise, the same answer as a record
            // that does not exist), and its result keeps only admitted
            // entities reached through admitted entities. In-product callers
            // get `None` and are unchanged.
            let admission = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?;
            if let Some(admission) = &admission
                && !admission.admits(&req.start.entity)
            {
                tracing::info!(
                    action = GRAPH_TRAVERSE,
                    entity = req.start.entity.as_str(),
                    agent_session_id = ?ctx.agent_session_id,
                    "MCP read tool refused: start entity not admitted for read"
                );
                return Err(AppError::NotFound);
            }

            // The caller's own visibility, resolved and enforced inside
            // `traverse` exactly as the HTTP route enforces it — no second
            // implementation.
            let mut outcome = attome_search::graph::traverse(state, &ctx.security, &req).await?;
            if let Some(admission) = &admission {
                outcome = crate::mcp::admission::filter_traversal(
                    outcome,
                    (&req.start.entity, req.start.id),
                    req.max_depth,
                    |entity| admission.admits(entity),
                );
            }

            Ok(ActionResult::plain(
                serde_json::to_value(outcome.into_response(limit)).map_err(|e| {
                    AppError::internal(format!("graph traversal serialization failed: {e}"))
                })?,
            ))
        })
    }
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(GraphTraverse)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{Effect, RiskTier};

    /// The tool is read-only and cannot be argued into anything else — the
    /// same property `read.rs`'s `the_first_slice_is_read_only` pins for its
    /// own actions.
    #[test]
    fn graph_traverse_is_read_tier() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == GRAPH_TRAVERSE)
            .expect("graph.traverse must be registered");
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
    }

    /// Gated on `MODULE_AI`, not `MODULE_CORE` or `MODULE_SEARCH` — the tool
    /// surface's own license, independent of the HTTP route's
    /// `MODULE_SEARCH` gate.
    #[test]
    fn graph_traverse_is_gated_on_the_ai_module() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == GRAPH_TRAVERSE)
            .expect("graph.traverse must be registered");
        assert_eq!(
            (d.module.word, d.module.mask),
            (MODULE_AI.word, MODULE_AI.mask)
        );
    }

    /// The description draws a boundary against both sibling read tools —
    /// the negative half is what actually steers model selection
    /// (`turn::describe_for_model`).
    #[test]
    fn the_description_is_disjoint_from_search_and_query() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == GRAPH_TRAVERSE)
            .expect("graph.traverse must be registered");
        assert!(
            d.description.contains("Do NOT use this to find a record"),
            "must disclaim search.records's job: {}",
            d.description
        );
        assert!(
            d.description.contains("Do NOT use this to count"),
            "must disclaim query.execute's job: {}",
            d.description
        );
    }
}
