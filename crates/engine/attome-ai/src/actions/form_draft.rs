//! `model.form.draft` (roadmap AD2-T1): a building agent drafts an entity's
//! form from a description: tabs and sections over the entity's own fields,
//! related lists for the entities that point at it, and visibility rules to
//! propose (A11). One model call names the fields and the related entities;
//! [`crate::builder::forms`] turns its answer into a form document by ids,
//! checked by the form kind's shape rules, leaving out (and reporting) any
//! name the entity does not have.
//!
//! Nothing is saved: the answer carries the `model.form.edit` call (N12) that
//! saves the form as a draft, made by a person's confirmation, in their
//! Develop workspace when the tab works in one (V2-D27). The visibility
//! proposals are for the rule editor.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_model::kind::Kind;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::builder::forms::{DraftedForm, form_document, known_visibility};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const FORM_DRAFT: &str = "model.form.draft";
/// Bumped whenever the prompt changes in a way that could move results.
pub const FORM_PROMPT_VERSION: &str = "model.form.draft/v1";

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["entity", "description"],
  "properties": {
    "entity": { "type": "string", "description": "The entity's logical name." },
    "description": { "type": "string", "description": "How the form should read, in the person's words." }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            FORM_DRAFT,
            "Draft an entity's form from a description: tabs and sections over its fields, \
             related lists, and visibility rules to propose. Saves nothing; returns the \
             model.form.edit call that saves it as a draft.",
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
    vec![Box::new(FormDraft)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    entity: String,
    description: String,
}

#[derive(Debug)]
pub struct FormDraft;

impl Action for FormDraft {
    fn id(&self) -> ActionId {
        ActionId(FORM_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // The form edit tool it feeds is administrators' only.
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {FORM_DRAFT} arguments: {e}"))
            })?;
            if args.description.trim().is_empty() {
                return Err(AppError::Validation(
                    "description: say how the form should read".into(),
                ));
            }
            let entity: Uuid = sqlx::query_scalar(
                "SELECT id FROM entity_info WHERE logicalname = $1 AND is_active IS NOT FALSE",
            )
            .bind(args.entity.trim())
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
            let fields: Vec<(String, Uuid, i32, bool)> = sqlx::query_as(
                "SELECT logicalname::text, id, \"type\", COALESCE(required, false) \
                   FROM attribute_info WHERE entity_ref = $1 AND is_active IS NOT FALSE \
                  ORDER BY id LIMIT 400",
            )
            .bind(entity)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let fields: Vec<(String, Uuid, i32, bool)> = fields
                .into_iter()
                .filter(|(name, ..)| !attome_core::ALL_SYSTEM_COLS.contains(&name.as_str()))
                .collect();
            // Related lists: the entities with a lookup to this one.
            let related: Vec<(String, Uuid)> = sqlx::query_as(
                "SELECT DISTINCT e.logicalname::text, e.id FROM attribute_info a \
                   JOIN entity_info e ON e.id = a.entity_ref \
                  WHERE a.lookup_entity_ref = $1 AND a.is_active IS NOT FALSE \
                    AND e.is_active IS NOT FALSE AND e.id <> $1 \
                  ORDER BY 1 LIMIT 40",
            )
            .bind(entity)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;

            let system = "You lay out a data-entry form. Answer with one JSON object and \
                nothing else: {\"tabs\": [{\"label\", \"sections\": [{\"label\", \"fields\": \
                [field names], \"columns\" (1 to 4), \"related\": [entity names]}]}], \
                \"visibility\": [{\"field\", \"when\": {\"field\", \"op\" (eq, neq, is_null, \
                is_not_null, in), \"value\"}}]}. Use only the given field and entity names; put \
                the required fields first; place each field once."
                .to_owned();
            let facts = json!({
                "entity": args.entity.trim(),
                "description": args.description,
                "fields": fields.iter().map(|(name, _, kind, required)| json!({
                    "name": name,
                    "type": attome_core::FieldType::from_int(*kind).map_or("text", |t| t.as_str()),
                    "required": required,
                })).collect::<Vec<_>>(),
                "related_entities": related.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            })
            .to_string();
            let (text, provenance) = crate::actions::metric_draft::generate(
                state,
                ctx,
                FORM_DRAFT,
                FORM_PROMPT_VERSION,
                system,
                facts,
            )
            .await?;
            let drafted: DraftedForm =
                serde_json::from_str(crate::actions::metric_draft::strip_fence(&text)).map_err(
                    |e| AppError::Validation(format!("the drafted form is not a form layout: {e}")),
                )?;
            let by_name: Vec<(String, Uuid)> = fields
                .iter()
                .map(|(name, id, ..)| (name.clone(), *id))
                .collect();
            let (doc, left_out) = form_document(entity, &drafted, &by_name, &related);
            let issues: Vec<Value> = match attome_model::kinds::FormKind.validate_shape(&doc) {
                Ok(()) => Vec::new(),
                Err(found) => found
                    .iter()
                    .map(|i| json!({ "path": i.path, "code": i.code, "message": i.message }))
                    .collect(),
            };
            let name = format!(
                "{}_form_{}",
                args.entity.trim(),
                &Uuid::now_v7().simple().to_string()[24..]
            );
            let call = json!({
                "action": "model.form.edit",
                "args": {
                    "id": Uuid::now_v7(),
                    "base_hash": "",
                    "name": name,
                    "commands": [
                        { "op": "set", "path": "/entity", "value": doc["entity"] },
                        { "op": "set", "path": "/form_kind", "value": doc["form_kind"] },
                        { "op": "set", "path": "/tabs", "value": doc["tabs"] },
                    ],
                },
            });
            Ok(ActionResult {
                value: json!({
                    "form": doc,
                    "issues": issues,
                    "left_out": left_out,
                    "visibility": known_visibility(&drafted, &by_name),
                    "call": call,
                    "saved": false,
                }),
                provenance,
            })
        })
    }
}
