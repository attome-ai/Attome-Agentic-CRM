//! `record.transitions` and `record.transition` (roadmap N6-T2): move a
//! record through its entity's state model the way a person does.
//!
//! `record.transitions` lists where a record can go from its current state,
//! only the moves the caller holds the privilege for. `record.transition`
//! sets the state field through the engine's ordinary update path
//! (`entity_crud::update_record_for`), which enforces the state model: a move
//! the model does not configure is refused, a transition's guard and
//! privilege are checked, and a transition that needs approval moves the
//! record to its pending state and submits the approval request instead
//! (its id comes back as `approval_request_id`). The action never decides a
//! transition itself. For an agent it is confirmed by a person first.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const RECORD_TRANSITIONS: &str = "record.transitions";
pub const RECORD_TRANSITION: &str = "record.transition";

const TRANSITIONS_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid" }
  },
  "required": ["entity", "record_id"],
  "additionalProperties": false
}"#;

const TRANSITION_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid" },
    "to": { "type": "string", "description": "The state to move to, one record.transitions lists." },
    "row_version": { "type": "integer", "description": "The row_version you read." }
  },
  "required": ["entity", "record_id", "to", "row_version"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            RECORD_TRANSITIONS,
            "Where a record can move next in its state model (its stage or status): \
             the current state and each allowed move, and whether a move needs approval.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(TRANSITIONS_INPUT),
        ActionDescriptor::new(
            RECORD_TRANSITION,
            "Move a record to another state (stage or status) its state model allows, \
             given the row_version you read. A move that needs approval goes to its \
             pending state and asks for approval. A person confirms it first.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(TRANSITION_INPUT)
        .agent_must_confirm(),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionArgs {
    entity: String,
    record_id: Uuid,
    to: String,
    row_version: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordArgs {
    entity: String,
    record_id: Uuid,
}

/// The state field of `entity`'s active state model.
fn state_field(state: &EngineState, entity: &str) -> Result<String, AppError> {
    let models = state.state_models.load();
    models
        .get(entity)
        .and_then(|entry| entry.model.as_ref())
        .filter(|model| model.is_active)
        .map(|model| model.state_field.clone())
        .ok_or_else(|| AppError::Validation(format!("{entity} has no active state model")))
}

pub(crate) struct RecordTransitions;

impl Action for RecordTransitions {
    fn id(&self) -> ActionId {
        ActionId(RECORD_TRANSITIONS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: RecordArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid arguments: {e}")))?;
            let field = state_field(state, &args.entity)?;
            let record = attome_records::entity_crud::read_record_bulk(
                state,
                &ctx.security,
                &args.entity,
                args.record_id,
            )
            .await?;
            let current = record
                .data()
                .get(&field)
                .and_then(Value::as_str)
                .map(str::to_owned);
            let models = state.state_models.load();
            let moves: Vec<Value> = models
                .get(&args.entity)
                .map(|entry| {
                    attome_core::available_transitions(entry, &ctx.security, current.as_deref())
                        .into_iter()
                        .map(|t| {
                            json!({
                                "name": t.name,
                                "to": t.to_state,
                                "needs_approval": t.requires_approval(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(ActionResult::plain(json!({
                "entity": args.entity,
                "record_id": args.record_id,
                "state_field": field,
                "current": current,
                "row_version": record.row_version(),
                "transitions": moves,
            })))
        })
    }
}

pub(crate) struct RecordTransition;

impl Action for RecordTransition {
    fn id(&self) -> ActionId {
        ActionId(RECORD_TRANSITION)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: TransitionArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid arguments: {e}")))?;
            let to = args.to.trim();
            if to.is_empty() {
                return Err(AppError::Validation("to is required".into()));
            }
            ctx.security.require(&args.entity, "update")?;
            let field = state_field(state, &args.entity)?;
            let mut values = Map::new();
            values.insert(field.clone(), json!(to));
            // The engine enforces the state model on this write.
            let record = attome_records::entity_crud::update_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                &args.entity,
                args.record_id,
                args.row_version,
                Value::Object(values),
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": args.entity,
                "record_id": args.record_id,
                "state": record.data().get(&field).cloned().unwrap_or(Value::Null),
                "row_version": record.row_version(),
                "approval_request_id": record.approval_request_id(),
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let args: TransitionArgs = serde_json::from_value(args.clone()).ok()?;
        Some(json!({
            "action": RECORD_TRANSITION,
            "entity": args.entity,
            "record_id": args.record_id,
            "to": args.to,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::LimitClass;

    #[test]
    fn a_transition_is_a_confirmed_record_change() {
        let all = descriptors();
        let transition = all
            .iter()
            .find(|d| d.id.as_str() == RECORD_TRANSITION)
            .unwrap();
        assert_eq!(transition.limit_class(), LimitClass::RecordChange);
        assert_eq!(transition.retry, RetryClass::RequiresKey);
        let list = all
            .iter()
            .find(|d| d.id.as_str() == RECORD_TRANSITIONS)
            .unwrap();
        assert_eq!(list.limit_class(), LimitClass::None);
    }

    #[test]
    fn transition_arguments_are_strict() {
        let ok: Result<TransitionArgs, _> = serde_json::from_value(json!({
            "entity": "lead", "record_id": Uuid::now_v7(), "to": "qualified", "row_version": 3
        }));
        assert!(ok.is_ok());
        let extra: Result<TransitionArgs, _> = serde_json::from_value(json!({
            "entity": "lead", "record_id": Uuid::now_v7(), "to": "won", "row_version": 3,
            "skip_approval": true
        }));
        assert!(extra.is_err(), "no argument can bypass the state model");
    }
}
