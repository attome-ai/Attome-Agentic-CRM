//! L5-T8: the lineage tools.
//!
//! - `lineage.downstream`: what depends on an entity, attribute or
//!   definition (flows, queries, metrics, dashboards, model objects), from
//!   `attome_core::lineage::graph::walk`;
//! - `lineage.upstream`: what a definition uses, or what writes some data;
//! - `lineage.impact`: what a change to an entity or attribute would affect
//!   and what it would break, from `attome_core::lineage::impact`, the same
//!   engine the field changes refuse a breaking delete or retype with.
//!
//! All three read and change nothing. They run as the person the agent acts
//! for: an administrator sees every node; anyone else sees the data of
//! entities they may read, and every other node is counted in `hidden`.
//! An agent proposing a schema change calls `lineage.impact` first and
//! reports its breaking list with the proposal (there is no AI builder path
//! yet that could refuse a proposal without it).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_core::lineage::graph::{self, Direction, NodeRef};
use attome_core::lineage::impact::{self, ChangeKind, MetadataChange};
use attome_modules::MODULE_CORE;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const LINEAGE_DOWNSTREAM: &str = "lineage.downstream";
pub const LINEAGE_UPSTREAM: &str = "lineage.upstream";
pub const LINEAGE_IMPACT: &str = "lineage.impact";

const NODE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "kind": {"type": "string", "description": "entity, or a definition kind: workflow, query, metric, dashboard, ..."},
    "ref": {"type": "string", "description": "for entity: <entity> or <entity>.<attribute>; otherwise the definition's id"},
    "depth": {"type": "integer", "minimum": 1, "maximum": 10},
    "kinds": {"type": "array", "items": {"type": "string"}, "description": "definition kinds to keep"}
  },
  "required": ["kind", "ref"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            LINEAGE_DOWNSTREAM,
            "List what depends on an entity, an attribute or a definition: the flows, stored \
             queries, metrics, dashboards and model objects that use it, then what uses those. \
             Definitions that use personal attributes are flagged. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(NODE_SCHEMA),
        ActionDescriptor::new(
            LINEAGE_UPSTREAM,
            "List what a definition uses (the entities, attributes and other definitions it \
             reads), or what writes or derives an entity's data. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(NODE_SCHEMA),
        ActionDescriptor::new(
            LINEAGE_IMPACT,
            "Before proposing a schema change, list what it would affect and what it would \
             break: deleting or retyping an attribute breaks every dashboard, metric or model \
             definition that uses it directly. Call it before any change proposal and report \
             the breaking list with the proposal. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {
    "entity": {"type": "string"},
    "attribute": {"type": "string"},
    "change": {"type": "string", "enum": ["delete", "retype", "rename", "other"]},
    "depth": {"type": "integer", "minimum": 1, "maximum": 10}
  },
  "required": ["entity", "change"],
  "additionalProperties": false
}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(LineageWalk(Direction::Down)),
        Box::new(LineageWalk(Direction::Up)),
        Box::new(LineageImpact),
    ]
}

/// The change a `change` argument names.
pub fn change_kind(raw: &str) -> Option<ChangeKind> {
    Some(match raw {
        "delete" => ChangeKind::DeleteAttribute,
        "retype" => ChangeKind::ChangeAttributeType,
        "rename" => ChangeKind::RenameAttribute,
        "other" => ChangeKind::Other,
        _ => return None,
    })
}

fn depth_of(args: &Value, default: u8) -> u8 {
    args["depth"]
        .as_u64()
        .and_then(|d| u8::try_from(d).ok())
        .unwrap_or(default)
        .clamp(1, graph::MAX_DEPTH)
}

struct LineageWalk(Direction);

impl Action for LineageWalk {
    fn id(&self) -> ActionId {
        ActionId(match self.0 {
            Direction::Down => LINEAGE_DOWNSTREAM,
            Direction::Up => LINEAGE_UPSTREAM,
        })
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let start = NodeRef::parse(
                args["kind"].as_str().unwrap_or_default(),
                args["ref"].as_str().unwrap_or_default(),
            )
            .ok_or_else(|| {
                AppError::Validation(
                    "name an entity (kind entity, ref <entity>[.<attribute>]) or a definition \
                     by its kind and id"
                        .into(),
                )
            })?;
            let kinds: Option<Vec<String>> = args["kinds"].as_array().map(|k| {
                k.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            });
            let security = &ctx.security;
            let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
            let found = graph::walk(
                &mut conn,
                &start,
                self.0,
                depth_of(args, 3),
                kinds.as_deref(),
                None,
                |node| {
                    security.is_admin
                        || matches!(node, NodeRef::Data { entity, .. }
                            if security.require(entity, "read").is_ok())
                },
            )
            .await?;
            Ok(ActionResult::plain(
                serde_json::to_value(&found).map_err(AppError::internal)?,
            ))
        })
    }
}

struct LineageImpact;

impl Action for LineageImpact {
    fn id(&self) -> ActionId {
        ActionId(LINEAGE_IMPACT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = args["entity"].as_str().unwrap_or_default();
            if state.entities.load().get(entity).is_none() {
                return Err(AppError::Validation(format!("{entity:?} is not an entity")));
            }
            let kind =
                change_kind(args["change"].as_str().unwrap_or_default()).ok_or_else(|| {
                    AppError::Validation("change is delete, retype, rename or other".into())
                })?;
            let change = MetadataChange {
                entity: entity.to_owned(),
                attribute: args["attribute"]
                    .as_str()
                    .filter(|a| !a.is_empty())
                    .map(str::to_owned),
                kind,
            };
            let admin = ctx.security.is_admin;
            let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
            let report = impact::impact(
                &mut conn,
                std::slice::from_ref(&change),
                depth_of(args, impact::DEFAULT_DEPTH),
                |_, _| admin,
            )
            .await?;
            Ok(ActionResult::plain(summarise(&change, &report)))
        })
    }
}

/// The impact report as the tool answers it: a verdict first.
pub fn summarise(change: &MetadataChange, report: &impact::ImpactReport) -> Value {
    json!({
        "change": change,
        "breaks": !report.breaking.is_empty(),
        "breaking": report.breaking,
        "affected": report.affected,
        "hidden": report.hidden,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impact_tool_lists_breaking() {
        let change = MetadataChange {
            entity: "invoice".into(),
            attribute: Some("amount".into()),
            kind: change_kind("delete").unwrap(),
        };
        let report = impact::ImpactReport {
            affected: Vec::new(),
            breaking: vec![impact::Breaking {
                change: change.clone(),
                from_kind: "metric".into(),
                from_ref: uuid::Uuid::nil(),
                from_label: "Revenue".into(),
                edge_kind: "reads".into(),
            }],
            hidden: 2,
        };
        let out = summarise(&change, &report);
        assert_eq!(out["breaks"], true);
        assert_eq!(out["breaking"][0]["from_label"], "Revenue");
        assert_eq!(out["hidden"], 2);
        assert!(change_kind("drop").is_none());
    }

    #[test]
    fn lineage_tools_only_read() {
        let all = descriptors();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|d| d.risk == RiskTier::Read));
        assert_eq!(depth_of(&json!({"depth": 99}), 3), graph::MAX_DEPTH);
        assert_eq!(depth_of(&json!({}), 3), 3);
    }
}
