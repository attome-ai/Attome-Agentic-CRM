//! L3-T8: the proposal-only governance tools.
//!
//! - `governance.list_overdue` (read): exceptions waiting more than seven
//!   days for approval, approved exceptions past their end, certifications
//!   whose entity changed since (stale), and entities in no domain, for the
//!   domains the person holds a governance role in (every domain for an
//!   administrator).
//! - `governance.propose_domains` (consequential): assigns unowned entities
//!   to domains;
//! - `governance.draft_policy` (consequential): writes a policy, with its
//!   enforcement links, into a domain.
//!
//! The two proposals are Consequential writes, so an agent's call never
//! runs: the gate turns it into an approval request carrying the arguments
//! as given (`crate::approval`), and only a person other than the one the
//! agent acts for approves it. The approved call then runs as that person,
//! through the same functions the governance routes use, so their domain
//! role is checked again.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const GOVERNANCE_LIST_OVERDUE: &str = "governance.list_overdue";
pub const GOVERNANCE_PROPOSE_DOMAINS: &str = "governance.propose_domains";
pub const GOVERNANCE_DRAFT_POLICY: &str = "governance.draft_policy";

/// Days an exception may wait for its approval before it is overdue.
const EXCEPTION_DUE_DAYS: i32 = 7;
/// Rows per overdue list.
const OVERDUE_LIMIT: i64 = 100;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            GOVERNANCE_LIST_OVERDUE,
            "List governance work that is overdue in the domains you hold a governance role \
             in: policy exceptions waiting more than seven days for approval, approved \
             exceptions past their end, certified entities changed since certification, and \
             entities in no domain. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#),
        ActionDescriptor::new(
            GOVERNANCE_PROPOSE_DOMAINS,
            "Propose data domains for entities that have none. The proposal waits for a \
             person to approve it; nothing changes until then. Say why each entity belongs \
             to its domain.",
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
    "assignments": {
      "type": "array", "minItems": 1, "maxItems": 50,
      "items": {
        "type": "object",
        "properties": {
          "entity": {"type": "string"},
          "domain_id": {"type": "string", "format": "uuid"},
          "reason": {"type": "string"}
        },
        "required": ["entity", "domain_id"],
        "additionalProperties": false
      }
    }
  },
  "required": ["assignments"],
  "additionalProperties": false
}"#,
        ),
        ActionDescriptor::new(
            GOVERNANCE_DRAFT_POLICY,
            "Draft a governance policy for a domain from its checks and labels: a name and \
             text in English (and Arabic), and what enforces it (a check, a label, attribute \
             security, retention or residency, each with its target). The draft waits for a \
             person to approve it; nothing is written until then.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {
    "domain_id": {"type": "string", "format": "uuid"},
    "name_en": {"type": "string"},
    "name_ar": {"type": "string"},
    "body_en": {"type": "string"},
    "body_ar": {"type": "string"},
    "enforcements": {
      "type": "array", "maxItems": 100,
      "items": {
        "type": "object",
        "properties": {
          "kind": {"type": "string", "enum": ["check", "label", "attribute_security", "retention", "residency"]},
          "target_ref": {"type": "string"}
        },
        "required": ["kind", "target_ref"],
        "additionalProperties": false
      }
    }
  },
  "required": ["domain_id", "name_en"],
  "additionalProperties": false
}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Governance(GOVERNANCE_LIST_OVERDUE)),
        Box::new(Governance(GOVERNANCE_PROPOSE_DOMAINS)),
        Box::new(Governance(GOVERNANCE_DRAFT_POLICY)),
    ]
}

/// The domain assignments of a `propose_domains` call, grouped by domain.
pub fn assignments_by_domain(args: &Value) -> Result<Vec<(Uuid, Vec<String>)>, AppError> {
    let items = args["assignments"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 50)
        .ok_or_else(|| AppError::Validation("assignments holds 1 to 50 entries".into()))?;
    let mut grouped: std::collections::BTreeMap<Uuid, Vec<String>> = Default::default();
    for item in items {
        let entity = item["entity"]
            .as_str()
            .filter(|e| !e.is_empty())
            .ok_or_else(|| AppError::Validation("each assignment names its entity".into()))?;
        let domain = item["domain_id"]
            .as_str()
            .and_then(|d| Uuid::parse_str(d).ok())
            .ok_or_else(|| AppError::Validation("each assignment names its domain_id".into()))?;
        let list = grouped.entry(domain).or_default();
        if !list.iter().any(|e| e == entity) {
            list.push(entity.to_owned());
        }
    }
    Ok(grouped.into_iter().collect())
}

struct Governance(&'static str);

impl Action for Governance {
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
            match self.0 {
                GOVERNANCE_LIST_OVERDUE => Ok(ActionResult::plain(
                    list_overdue(state, security.user_id, security.is_admin).await?,
                )),
                GOVERNANCE_PROPOSE_DOMAINS => {
                    let groups = assignments_by_domain(args)?;
                    let recording = attome_compliance::governance_policy::agent_recording(
                        state,
                        security.user_id,
                        GOVERNANCE_PROPOSE_DOMAINS,
                    );
                    let mut assigned = Vec::new();
                    for (domain, entities) in groups {
                        attome_compliance::governance_policy::assign_unowned(
                            state, security, &recording, domain, &entities,
                        )
                        .await?;
                        assigned.push(json!({ "domain_id": domain, "entities": entities }));
                    }
                    Ok(ActionResult::plain(json!({ "assigned": assigned })))
                }
                GOVERNANCE_DRAFT_POLICY => {
                    let body: attome_compliance::governance_policy::CreatePolicyBody =
                        serde_json::from_value(json!({
                            "domain_ref": args["domain_id"],
                            "name_en": args["name_en"],
                            "name_ar": args["name_ar"],
                            "body_en": args["body_en"].as_str().unwrap_or_default(),
                            "body_ar": args["body_ar"],
                            "enforcements": args["enforcements"].as_array().cloned().unwrap_or_default(),
                        }))
                        .map_err(|e| AppError::Validation(format!("policy draft: {e}")))?;
                    let policy =
                        attome_compliance::governance_policy::create(state, security, body).await?;
                    Ok(ActionResult::plain(
                        serde_json::to_value(&policy).map_err(AppError::internal)?,
                    ))
                }
                other => Err(AppError::internal(format!(
                    "unknown governance action {other}"
                ))),
            }
        })
    }
}

/// The policies an overdue list covers: every one for an administrator (`$1`),
/// else those of the domains where the caller (`$2`) holds a governance role.
const IN_SCOPE: &str = "($1 OR EXISTS (SELECT 1 FROM governance_role g \
                        WHERE g.domain_ref = p.domain_ref AND g.user_id = $2))";

async fn list_overdue(state: &EngineState, user: Uuid, admin: bool) -> Result<Value, AppError> {
    let db = &state.base.db;
    let waiting: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(&format!(
        "SELECT x.id, p.id, p.name_en, x.target_ref FROM governance_policy_exception x \
           JOIN governance_policy p ON p.id = x.policy_id \
          WHERE x.status = 'requested' AND x.created_at < now() - make_interval(days => $3) \
            AND {IN_SCOPE} ORDER BY x.created_at LIMIT $4"
    ))
    .bind(admin)
    .bind(user)
    .bind(EXCEPTION_DUE_DAYS)
    .bind(OVERDUE_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let lapsed: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(&format!(
        "SELECT x.id, p.id, p.name_en, x.target_ref FROM governance_policy_exception x \
           JOIN governance_policy p ON p.id = x.policy_id \
          WHERE x.status = 'approved' AND x.expires_at < now() AND {IN_SCOPE} \
          ORDER BY x.expires_at LIMIT $3"
    ))
    .bind(admin)
    .bind(user)
    .bind(OVERDUE_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let certified: Vec<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT c.asset_ref, c.definition_hash, e.domain_ref FROM governance_certification c \
           JOIN entity_info e ON e.logicalname = c.asset_ref \
          WHERE c.asset_kind = 'entity' AND c.status = 'certified' \
            AND ($1 OR EXISTS (SELECT 1 FROM governance_role g \
                                WHERE g.domain_ref = e.domain_ref AND g.user_id = $2)) \
          ORDER BY c.certified_at LIMIT $3",
    )
    .bind(admin)
    .bind(user)
    .bind(OVERDUE_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut stale = Vec::new();
    for (entity, hash, _) in certified {
        let now =
            attome_compliance::governance_policy::entity_definition_hash(state, &entity).await?;
        if now.is_none_or(|(h, _)| h != hash) {
            stale.push(entity);
        }
    }
    let unowned: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
          WHERE domain_ref IS NULL AND (is_active IS NULL OR is_active) \
          ORDER BY logicalname LIMIT $1",
    )
    .bind(OVERDUE_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let row = |(id, policy, name, target): (Uuid, Uuid, String, String)| json!({ "exception_id": id, "policy_id": policy, "policy": name, "target_ref": target });
    Ok(json!({
        "exceptions_waiting": waiting.into_iter().map(row).collect::<Vec<_>>(),
        "exceptions_lapsed": lapsed.into_iter().map(row).collect::<Vec<_>>(),
        "stale_certifications": stale,
        "unowned_entities": if admin { unowned } else { Vec::new() },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_valid() {
        let all = descriptors();
        assert_eq!(all.len(), 3);
        for d in &all {
            let schema: Value = serde_json::from_str(d.input_schema).unwrap();
            assert_eq!(schema["type"], "object", "{}", d.id);
        }
        let groups = assignments_by_domain(&json!({ "assignments": [
            { "entity": "invoice", "domain_id": "0192f7a0-0000-7000-8000-000000000001" },
            { "entity": "payment", "domain_id": "0192f7a0-0000-7000-8000-000000000001" },
            { "entity": "invoice", "domain_id": "0192f7a0-0000-7000-8000-000000000001" }
        ]}))
        .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].1,
            vec!["invoice".to_owned(), "payment".to_owned()]
        );
        assert!(assignments_by_domain(&json!({ "assignments": [] })).is_err());
    }

    /// An agent's proposal is never run directly: the gate asks for approval.
    #[test]
    fn proposals_only_create_approvals() {
        use crate::context::ActionContext;
        use crate::context::tests::security_context_with;
        use crate::gate::{self, GateDecision};
        use attome_config::AiEnablement;

        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        let security = security_context_with(true, &[]);
        // Every surface attaches a per-call key; draft_policy requires one.
        let ctx = ActionContext::agent(security, RiskTier::Consequential)
            .with_idempotency_key("governance-test-call");
        let inputs = gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };
        for d in descriptors() {
            let decision = gate::evaluate(&d, &ctx, &inputs);
            if d.id.0 == GOVERNANCE_LIST_OVERDUE {
                assert_eq!(d.risk, RiskTier::Read);
                assert!(
                    matches!(decision, Ok(GateDecision::Execute)),
                    "{decision:?}"
                );
            } else {
                assert_eq!((d.risk, d.effect), (RiskTier::Consequential, Effect::Write));
                assert_eq!(
                    decision,
                    Ok(GateDecision::RequiresApproval),
                    "{} must wait for a person's approval",
                    d.id.0
                );
            }
        }
    }
}
