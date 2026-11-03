//! `model.review` (roadmap A1-T13): checks a drafted model against the
//! deployment's existing one and returns findings, never edits. The rules
//! are [`crate::builder::review`]'s: entity names that exist already, "extend
//! Party instead" for a person-like entity, duplicate attributes, naming
//! rules, unknown relationship targets and a relationship declared on the
//! wrong side. `model.draft` runs the same review on its own drafts; this
//! tool reviews a draft a person or another agent changed.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::builder::review::{DraftEntity, review};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const MODEL_REVIEW: &str = "model.review";
/// Entities one review takes.
const MAX_ENTITIES: usize = 50;

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["draft"],
  "properties": {
    "draft": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name": { "type": "string" },
          "attributes": { "type": "array", "items": { "type": "object", "required": ["name", "field_type"],
            "properties": { "name": { "type": "string" }, "field_type": { "type": "string" } } } },
          "relationships": { "type": "array", "items": { "type": "object", "required": ["target", "kind"],
            "properties": { "target": { "type": "string" }, "kind": { "type": "string" }, "attribute": { "type": "string" } } } }
        }
      }
    }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            MODEL_REVIEW,
            "Review a drafted data model against the existing one: names that exist already, a \
             person-like entity that should extend Party, duplicate attributes, naming rules and \
             relationship direction. Returns findings; changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ReviewModel)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    draft: Vec<DraftEntity>,
}

#[derive(Debug)]
pub struct ReviewModel;

impl Action for ReviewModel {
    fn id(&self) -> ActionId {
        ActionId(MODEL_REVIEW)
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
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {MODEL_REVIEW} arguments: {e}"))
            })?;
            if args.draft.len() > MAX_ENTITIES {
                return Err(AppError::Validation(format!(
                    "draft: at most {MAX_ENTITIES} entities"
                )));
            }
            let existing: HashSet<String> = state
                .entities
                .load()
                .iter()
                .map(|m| m.logicalname.clone())
                .collect();
            let findings = review(&args.draft, &existing);
            Ok(ActionResult::plain(json!({
                "findings": findings,
                "clean": findings.is_empty(),
            })))
        })
    }
}
