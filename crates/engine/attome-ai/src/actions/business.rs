//! Business actions (roadmap N6-T2) that go through the engine owning each
//! change rather than a raw field write.
//!
//! `record.assign` hands a record to a user (by email) or a team (by name)
//! through `attome_security::admin::reassign_owner_for`, the function the
//! admin route uses: the owner columns, the new owner's share and the
//! owner-change audit event, in one transaction. Like that route it is for
//! administrators. It is `Reversible` and an agent only proposes it: the
//! gate stops every agent invocation for a person's confirmation.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const RECORD_ASSIGN: &str = "record.assign";

const RECORD_ASSIGN_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record to hand over." },
    "user_email": { "type": "string", "description": "The new owner, a user, by email. Give this or team_name." },
    "team_name": { "type": "string", "description": "The new owner, a team, by name. Give this or user_email." }
  },
  "required": ["entity", "record_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            RECORD_ASSIGN,
            "Hand a record to a new owner, a user by email or a team by name. \
             The new owner gets access to it. Administrators only.",
            RiskTier::Reversible,
            Effect::Write,
            // Assigning the same owner twice leaves the same state.
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(RECORD_ASSIGN_INPUT)
        .agent_must_confirm(),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(RecordAssign)]
}

pub(crate) struct RecordAssign;

impl Action for RecordAssign {
    fn id(&self) -> ActionId {
        ActionId(RECORD_ASSIGN)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let entity = args["entity"]
                .as_str()
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            let record_id = args["record_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("record_id must be a UUID".into()))?;
            let user_email = args["user_email"].as_str();
            let team_name = args["team_name"].as_str();
            if user_email.is_some() == team_name.is_some() {
                return Err(AppError::Validation(
                    "give exactly one of user_email or team_name".into(),
                ));
            }
            let done = attome_security::admin::reassign_owner_for(
                state,
                ctx.security.user_id,
                entity,
                record_id,
                user_email,
                team_name,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": done.entity,
                "record_id": done.record_id,
                "owner_type": done.owner_type,
                "owner_id": done.owner_id,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(json!({
            "action": RECORD_ASSIGN,
            "entity": args["entity"],
            "record_id": args["record_id"],
            "user_email": args["user_email"],
            "team_name": args["team_name"],
        }))
    }
}
