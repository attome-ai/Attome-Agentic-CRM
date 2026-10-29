//! L1-T10: the data steward's agent tools over master data.
//!
//! - `master.xref` (read): the golden record a source system's id belongs
//!   to, or every system id of a golden record. The record read decides
//!   access: a golden record the person cannot read is not found.
//! - `master.preview_ranking` (read): what a proposed trust ranking
//!   (`source_system_rank` config) would change: per attribute, how many
//!   golden values would take another source's value ("changes 1,240
//!   addresses"). Counts only; nothing is written and no rebuild is queued.
//!   A steward's tool, on attributes the person can read.
//! - `master.propose_release` (consequential): release a held contribution.
//!   An agent's call never runs: the gate turns it into an approval request
//!   (`crate::approval`), and the approved call runs as the person, through
//!   the same release the steward route uses, steward check included.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_records::entity_crud::master::{self, preview, steward, xref};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const MASTER_XREF: &str = "master.xref";
pub const MASTER_PREVIEW_RANKING: &str = "master.preview_ranking";
pub const MASTER_PROPOSE_RELEASE: &str = "master.propose_release";

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            MASTER_XREF,
            "Cross-reference master data: give a source system and the id it uses to find the \
             golden record, or a golden record's id to list every source system id it carries \
             and whether each is attached, held or detached. Changes nothing.",
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
    "system": {"type": "string"},
    "external_id": {"type": "string"},
    "golden_id": {"type": "string", "format": "uuid"}
  },
  "required": ["entity"],
  "additionalProperties": false
}"#,
        ),
        ActionDescriptor::new(
            MASTER_PREVIEW_RANKING,
            "Preview a trust ranking for a master entity before anyone sets it: for each \
             attribute, the source systems most trusted first, and how many golden records' \
             values would change under it. Pinned values are left out. Counts only; changes \
             nothing.",
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
    "ranks": {
      "type": "object",
      "additionalProperties": {"type": "array", "items": {"type": "string"}, "minItems": 1}
    },
    "tie_break": {"type": "string", "enum": ["recency", "completeness"]}
  },
  "required": ["entity", "ranks"],
  "additionalProperties": false
}"#,
        ),
        ActionDescriptor::new(
            MASTER_PROPOSE_RELEASE,
            "Propose releasing a held master-data contribution into its golden record, \
             optionally with a corrected payload, and say why. The proposal waits for a person \
             to approve it; nothing changes until then.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {
    "entity": {"type": "string"},
    "contribution_id": {"type": "string", "format": "uuid"},
    "payload": {"type": "object"},
    "reason": {"type": "string"}
  },
  "required": ["entity", "contribution_id"],
  "additionalProperties": false
}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Master(MASTER_XREF)),
        Box::new(Master(MASTER_PREVIEW_RANKING)),
        Box::new(Master(MASTER_PROPOSE_RELEASE)),
    ]
}

struct Master(&'static str);

impl Action for Master {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let security = &ctx.security;
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            master_entity(state, security, entity).await?;
            let value = match self.0 {
                MASTER_XREF => cross_reference(state, security, entity, args).await?,
                MASTER_PREVIEW_RANKING => preview_ranking(state, security, entity, args).await?,
                MASTER_PROPOSE_RELEASE => release(state, security, entity, args).await?,
                other => {
                    return Err(AppError::internal(format!("unknown master action {other}")));
                }
            };
            Ok(ActionResult::plain(value))
        })
    }
}

/// `entity` exists, is master data, and the person may read it.
async fn master_entity(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
) -> Result<(), AppError> {
    if state.entities.load().get(entity).is_none() {
        return Err(AppError::NotFound);
    }
    security.require(entity, "read")?;
    if !master::is_master(state, entity).await? {
        return Err(AppError::Validation(format!("{entity} is not master data")));
    }
    Ok(())
}

fn uuid_arg(args: &Value, name: &str) -> Result<Option<Uuid>, AppError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .map(Some)
            .ok_or_else(|| AppError::Validation(format!("{name} is a UUID"))),
    }
}

async fn cross_reference(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    args: &Value,
) -> Result<Value, AppError> {
    if let Some(golden) = uuid_arg(args, "golden_id")? {
        attome_records::entity_crud::read_record(state, security, entity, golden).await?;
        let ids = xref::system_ids(&state.base.db, entity, golden).await?;
        let items: Vec<Value> = ids
            .into_iter()
            .map(|s| {
                json!({
                    "contribution_id": s.id,
                    "source_system": s.source_system,
                    "external_id": s.external_id,
                    "status": s.status,
                    "received_at": s.received_at,
                })
            })
            .collect();
        return Ok(json!({ "golden_id": golden, "system_ids": items }));
    }
    let system = args["system"].as_str().map(str::trim).unwrap_or_default();
    let external_id = args["external_id"]
        .as_str()
        .map(str::trim)
        .unwrap_or_default();
    if system.is_empty() || external_id.is_empty() {
        return Err(AppError::Validation(
            "give golden_id, or both system and external_id".into(),
        ));
    }
    let (golden, status) = xref::golden_for(&state.base.db, entity, system, external_id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::read_record(state, security, entity, golden).await?;
    Ok(json!({ "golden_id": golden, "status": status }))
}

/// The attributes a ranking config names, each a stored attribute the
/// person can read; `*` stands for every such attribute.
pub fn ranked_attributes(
    attrs: &[attome_core::AttrInfo],
    readable: impl Fn(&attome_core::AttrInfo) -> bool,
    ranks: &Map<String, Value>,
) -> Result<Vec<String>, AppError> {
    let stored = |a: &&attome_core::AttrInfo| !a.is_computed() && readable(a);
    if ranks.contains_key("*") {
        return Ok(attrs
            .iter()
            .filter(stored)
            .map(|a| a.logicalname.clone())
            .collect());
    }
    let mut out = Vec::with_capacity(ranks.len());
    for name in ranks.keys() {
        if !attrs.iter().filter(stored).any(|a| &a.logicalname == name) {
            return Err(AppError::Validation(format!(
                "{name} is not an attribute you can read"
            )));
        }
        out.push(name.clone());
    }
    Ok(out)
}

async fn preview_ranking(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    args: &Value,
) -> Result<Value, AppError> {
    if !steward::may_steward(state, security, entity).await? {
        return Err(AppError::Forbidden);
    }
    let ranks = args["ranks"]
        .as_object()
        .filter(|r| !r.is_empty())
        .ok_or_else(|| AppError::Validation("ranks names at least one attribute".into()))?;
    let (attrs, primary_name) = state
        .entities
        .load()
        .get(entity)
        .map(|m| (m.attrs.clone(), m.primary_name_attribute.clone()))
        .ok_or(AppError::NotFound)?;
    // D-589: the preview reads these attributes across many records, so the
    // bulk field gate decides (confirmed sensitivity labels, fields hidden
    // from AI), not the sensitive flag alone.
    let attributes = ranked_attributes(
        &attrs,
        |a| {
            attome_security::field_gate::readable(
                security,
                entity,
                a,
                primary_name.as_deref(),
                attome_security::field_gate::Surface::Bulk,
            )
        },
        ranks,
    )?;
    let mut config = json!({ "ranks": ranks });
    if let Some(tie) = args.get("tie_break").filter(|t| !t.is_null()) {
        config["tie_break"] = tie.clone();
    }
    let preview = preview::preview_ranking(state, entity, &config, &attributes).await?;
    let summary: Vec<String> = preview
        .changes
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(a, n)| format!("changes {n} {a} values"))
        .collect();
    Ok(json!({
        "contributions": preview.contributions,
        "golden_records": preview.golden_records,
        "changes": preview.changes,
        "summary": if summary.is_empty() { "changes nothing".to_owned() } else { summary.join("; ") },
    }))
}

async fn release(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    args: &Value,
) -> Result<Value, AppError> {
    if !steward::may_steward(state, security, entity).await? {
        return Err(AppError::Forbidden);
    }
    let contribution = uuid_arg(args, "contribution_id")?
        .ok_or_else(|| AppError::Validation("contribution_id is required".into()))?;
    let payload = match args.get("payload") {
        None | Some(Value::Null) => None,
        Some(Value::Object(p)) => Some(p.clone()),
        Some(_) => return Err(AppError::Validation("payload is an object".into())),
    };
    let (golden, rebuild_queued) =
        steward::release_held(state, security, entity, contribution, payload).await?;
    Ok(json!({ "golden_id": golden, "rebuild_queued": rebuild_queued }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::tests::security_context_with;
    use crate::gate::{self, GateDecision};
    use attome_config::AiEnablement;

    fn decision(id: &str) -> Result<GateDecision, crate::gate::GateRefusal> {
        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        let security = security_context_with(true, &[]);
        let ctx = ActionContext::agent(security, RiskTier::Consequential);
        let inputs = gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };
        let d = descriptors().into_iter().find(|d| d.id.0 == id).unwrap();
        gate::evaluate(&d, &ctx, &inputs)
    }

    /// The preview is a read: it runs without approval and is declared as
    /// changing nothing, so no write path is reachable from it.
    #[test]
    fn preview_ranking_writes_nothing() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.0 == MASTER_PREVIEW_RANKING)
            .unwrap();
        assert_eq!((d.risk, d.effect), (RiskTier::Read, Effect::Read));
        assert_eq!(d.retry, RetryClass::Idempotent);
        assert!(matches!(
            decision(MASTER_PREVIEW_RANKING),
            Ok(GateDecision::Execute)
        ));
        assert!(matches!(decision(MASTER_XREF), Ok(GateDecision::Execute)));
    }

    /// An agent's release is never run directly: the gate asks for approval.
    #[test]
    fn propose_release_creates_approval() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.0 == MASTER_PROPOSE_RELEASE)
            .unwrap();
        assert_eq!((d.risk, d.effect), (RiskTier::Consequential, Effect::Write));
        assert_eq!(
            decision(MASTER_PROPOSE_RELEASE),
            Ok(GateDecision::RequiresApproval),
            "a release must wait for a person's approval"
        );
    }

    #[test]
    fn descriptors_valid() {
        for d in descriptors() {
            let schema: Value = serde_json::from_str(d.input_schema).unwrap();
            assert_eq!(schema["type"], "object", "{}", d.id);
        }
    }
}
