//! Agent tools over an entity's table (roadmap Y2-T14, Y12-T12), all
//! reads, for administrators, as the admin routes they mirror:
//!
//! - `table.health`: size, live and dead rows, unused indexes, unindexed
//!   lookups and growth (`GET /api/v1/admin/entities/{entity_id}/health`);
//! - `table.index_proposals`: the single-column indexes slow statements
//!   suggest (`.../index-proposals`);
//! - `table.change_plan`: how proposed structure changes would run, with
//!   estimates (`.../change-plan`, a dry run).
//!
//! None applies anything. An agent proposes an index or a structure change
//! to a builder; applying it is a person's metadata edit (the agents' own
//! `model.<kind>.edit` tools only save drafts, behind confirmation).

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_metadata::index_advisor::{self, Advice};
use attome_metadata::provision::RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT;
use attome_metadata::provision::change_plan::{self, StructureChange};
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const TABLE_HEALTH: &str = "table.health";
pub const TABLE_INDEX_PROPOSALS: &str = "table.index_proposals";
pub const TABLE_CHANGE_PLAN: &str = "table.change_plan";

const ENTITY_INPUT: &str = r#"{"type": "object", "required": ["entity"], "properties": {"entity": {"type": "string", "description": "The entity's logical name"}}, "additionalProperties": false}"#;

pub fn health_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        TABLE_HEALTH,
        "Read an entity table's health: its size in bytes, live and dead rows and their ratio, \
         when it was last vacuumed, indexes never used, lookup fields no index leads on, and \
         rows added over seven days. Reads statistics only, never records.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(ENTITY_INPUT)
}

pub fn index_proposals_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        TABLE_INDEX_PROPOSALS,
        "List the single-column indexes slow statements suggest for an entity (from \
         pg_stat_statements, when the server has it), with how often and how slowly those \
         statements ran. To build one, ask a builder to make the field filterable; this tool \
         builds nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(ENTITY_INPUT)
}

pub fn change_plan_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        TABLE_CHANGE_PLAN,
        "Preview how proposed structure changes to an entity would run: each as instant, online \
         (built beside live traffic) or background (a durable run), with a time estimate. \
         Changes: add_field, add_choice_value, rename_field (to), set_required, add_index, \
         set_max_length (max_length), change_type (to), backfill, delete_field. A preview \
         only: it applies nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(
        r#"{"type": "object", "required": ["entity", "changes"], "properties": {"entity": {"type": "string"}, "changes": {"type": "array", "minItems": 1, "maxItems": 100, "items": {"type": "object", "required": ["kind", "field"], "properties": {"kind": {"type": "string"}, "field": {"type": "string"}, "to": {"type": "string"}, "max_length": {"type": "integer"}}}}}, "additionalProperties": false}"#,
    )
}

/// The entity the arguments name, if it exists.
fn entity_arg(state: &EngineState, args: &Value) -> Result<(String, BTreeSet<String>), AppError> {
    let name = args
        .get("entity")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("entity is required".into()))?;
    let registry = state.entities.load();
    let meta = registry.get(name).ok_or(AppError::NotFound)?;
    Ok((
        meta.logicalname.clone(),
        meta.attrs.iter().map(|a| a.logicalname.clone()).collect(),
    ))
}

pub(crate) struct TableHealthTool;

impl Action for TableHealthTool {
    fn id(&self) -> ActionId {
        ActionId(TABLE_HEALTH)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let (entity, _) = entity_arg(state, args)?;
            let health = attome_metadata::table_health::health_of(state, &entity).await?;
            Ok(ActionResult::plain(
                serde_json::to_value(health).map_err(AppError::internal)?,
            ))
        })
    }
}

pub(crate) struct TableIndexProposalsTool;

impl Action for TableIndexProposalsTool {
    fn id(&self) -> ActionId {
        ActionId(TABLE_INDEX_PROPOSALS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let (entity, attributes) = entity_arg(state, args)?;
            let answer =
                match index_advisor::proposals(&state.base.db, &entity, &attributes).await? {
                    Advice::Unavailable(reason) => {
                        json!({ "available": false, "reason": reason, "proposals": [] })
                    }
                    Advice::Proposals(proposals) => json!({
                        "available": true,
                        "proposals": proposals.iter().map(|p| json!({
                            "attribute": p.attribute,
                            "statements": p.statements,
                            "calls": p.calls,
                            "worst_mean_ms": p.worst_mean_ms,
                        })).collect::<Vec<_>>(),
                    }),
                };
            Ok(ActionResult::plain(answer))
        })
    }
}

pub(crate) struct TableChangePlanTool;

impl Action for TableChangePlanTool {
    fn id(&self) -> ActionId {
        ActionId(TABLE_CHANGE_PLAN)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let (entity, _) = entity_arg(state, args)?;
            let changes: Vec<StructureChange> =
                serde_json::from_value(args.get("changes").cloned().unwrap_or(Value::Null))
                    .map_err(|e| AppError::Validation(format!("changes: {e}")))?;
            if changes.is_empty() || changes.len() > 100 {
                return Err(AppError::Validation(
                    "a change plan takes 1 to 100 changes".into(),
                ));
            }
            let items = change_plan::plan_changes(
                &state.base.db,
                &entity,
                RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT,
                &changes,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "changes": serde_json::to_value(&items).map_err(AppError::internal)?,
                "total_estimate_secs": items.iter().map(|i| i.estimate_secs).sum::<u64>(),
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_tools_are_read_only() {
        for d in [
            health_descriptor(),
            index_proposals_descriptor(),
            change_plan_descriptor(),
        ] {
            assert_eq!(d.effect, Effect::Read, "{:?}", d.id);
            assert_eq!(d.risk, RiskTier::Read, "{:?}", d.id);
            assert_eq!(d.required_privileges, &["system.admin"]);
        }
    }
}
