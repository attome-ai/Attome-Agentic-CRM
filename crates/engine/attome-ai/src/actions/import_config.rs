//! `model.import_config` (roadmap AD11-T1): a source CRM's configuration as
//! a draft for Attome. Takes the source's model as the A24 connectors
//! describe it (`SourceModel`) and, optionally, its automations and code;
//! answers the draft ([`crate::builder::import_config`]), the plan against
//! the deployment's library ([`crate::builder::entities::plan`]: a source
//! `Account` lands on `account`), the N12 build-tool calls that would make
//! it, what cannot be moved and why, and each automation with the Attome
//! equivalent to rebuild it as. Nothing is saved or migrated: the calls are
//! made by a person's confirmation, in their Develop workspace (V2-D27).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_integration::connector::adapters::migration_source::SourceModel;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::builder::import_config::{SourceAutomation, automation_equivalents, draft_from_source};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const IMPORT_CONFIG: &str = "model.import_config";
/// Source entities one call takes.
const MAX_ENTITIES: usize = 200;
/// Automations one call lists.
const MAX_AUTOMATIONS: usize = 1_000;

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["source"],
  "properties": {
    "source": { "type": "object", "description": "The source's model as the migration connector describes it: {entities: [{name, label, custom, fields: [{name, label, source_type, attome_type, required, lookup_target, choices, multi}]}], users}." },
    "automations": { "type": "array", "items": { "type": "object", "required": ["name", "kind"],
      "properties": { "name": { "type": "string" }, "kind": { "type": "string" }, "entity": { "type": "string" } } } }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            IMPORT_CONFIG,
            "Map a source CRM's model (as the migration connector describes it) into a draft for \
             Attome, planned against the existing entities, with what cannot be moved and the \
             Attome equivalent of each automation. Saves and migrates nothing; returns the \
             build-tool calls that would make the draft.",
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
    vec![Box::new(ImportConfig)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    source: SourceModel,
    #[serde(default)]
    automations: Vec<SourceAutomation>,
}

#[derive(Debug)]
pub struct ImportConfig;

impl Action for ImportConfig {
    fn id(&self) -> ActionId {
        ActionId(IMPORT_CONFIG)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // The build tools it feeds are administrators' only.
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {IMPORT_CONFIG} arguments: {e}"))
            })?;
            if args.source.entities.len() > MAX_ENTITIES {
                return Err(AppError::Validation(format!(
                    "source: at most {MAX_ENTITIES} entities"
                )));
            }
            if args.automations.len() > MAX_AUTOMATIONS {
                return Err(AppError::Validation(format!(
                    "automations: at most {MAX_AUTOMATIONS}"
                )));
            }
            let (draft, cannot_move) = draft_from_source(&args.source);
            let library = crate::actions::draft_model::library(state).await?;
            let plan = crate::builder::entities::plan(&draft, &library);
            let calls = crate::builder::entities::build_plan_calls(&draft, &plan);
            Ok(ActionResult::plain(json!({
                "draft": draft,
                "plan": plan,
                "calls": calls,
                "cannot_move": cannot_move,
                "automations": automation_equivalents(&args.automations),
                "saved": false,
            })))
        })
    }
}
