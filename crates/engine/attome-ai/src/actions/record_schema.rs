//! `record.schema` (roadmap N6-T1): the typed input an entity's records
//! take, generated from its metadata, so an agent fills `record.create` /
//! `record.update` `values` with the right names and shapes instead of
//! guessing.
//!
//! Returns a JSON Schema object: one property per writable field (system
//! columns and formula fields are computed, never written), typed by the
//! field type, with choices as enums, text limits as `maxLength`, lookups as
//! ids naming their target entity, and the required fields listed. A
//! sensitive field the caller may not write is left out. Reading it needs
//! the entity's read privilege; it reads metadata only, never a record.

use std::future::Future;
use std::pin::Pin;

use attome_core::{AttrInfo, EngineState, FieldType};
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const RECORD_SCHEMA: &str = "record.schema";
pub const RECORD_VALIDATE: &str = "record.validate";

const RECORD_VALIDATE_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "values": { "type": "object", "description": "The values record.create would be given." }
  },
  "required": ["entity", "values"],
  "additionalProperties": false
}"#;

/// `record.validate` (N6-T1's dry run): runs the engine's whole create
/// pipeline (field rules, lookups, business rules, state model) inside a
/// transaction that is always rolled back, and says whether `record.create`
/// would accept the values. Writes nothing.
pub fn validate_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        RECORD_VALIDATE,
        "Check values against everything record.create enforces, without creating \
         anything: returns valid, or the error the create would give.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(RECORD_VALIDATE_INPUT)
}

pub(crate) struct RecordValidate;

impl Action for RecordValidate {
    fn id(&self) -> ActionId {
        ActionId(RECORD_VALIDATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            let values = args["values"]
                .as_object()
                .ok_or_else(|| AppError::Validation("values must be an object".into()))?;
            ctx.security.require(entity, "create")?;
            let (_, entity_name, attrs, _) =
                attome_records::entity_crud::resolve_entity(state, entity).await?;
            let actor =
                attome_records::mutation_ring::MutationActor::fetch(state, ctx.security.user_id)
                    .await;
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let outcome = attome_records::entity_mutation::create_one(
                &mut tx,
                state,
                &ctx.security,
                &entity_name,
                &attrs,
                values,
                ctx.security.user_id,
                actor.org_ref,
                attome_records::entity_mutation::MutationMode::Strict,
            )
            .await;
            // Always rolled back: a dry run never writes.
            tx.rollback().await.map_err(AppError::internal)?;
            Ok(ActionResult::plain(match outcome {
                Ok(result) => json!({
                    "valid": true,
                    "warnings": result
                        .warnings
                        .iter()
                        .map(|w| json!({ "rule": w.rule_name, "field": w.field }))
                        .collect::<Vec<_>>(),
                }),
                Err(
                    error @ (AppError::Validation(_)
                    | AppError::Conflict(_)
                    | AppError::Forbidden
                    | AppError::NotFound),
                ) => json!({
                    "valid": false,
                    "error": error.to_string(),
                }),
                Err(other) => return Err(other),
            }))
        })
    }
}

const RECORD_SCHEMA_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." }
  },
  "required": ["entity"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        RECORD_SCHEMA,
        "Describe the fields a record of an entity takes: each writable field's \
         name, type, choices, length limit and whether it is required, as a JSON \
         Schema for record.create and record.update values.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(RECORD_SCHEMA_INPUT)
}

/// The JSON Schema of one field's value.
pub(crate) fn field_schema(attr: &AttrInfo, target: Option<&str>) -> Option<Value> {
    let mut schema = match attr.field_type() {
        FieldType::Formula => return None,
        FieldType::Text | FieldType::RichText | FieldType::Icon | FieldType::Color => {
            let mut s = json!({ "type": "string" });
            if let Some(max) = attr.max_length.filter(|m| *m > 0) {
                s["maxLength"] = json!(max);
            }
            s
        }
        FieldType::Number | FieldType::Currency => json!({ "type": "number" }),
        FieldType::Date => json!({ "type": "string", "format": "date" }),
        FieldType::Bool => json!({ "type": "boolean" }),
        FieldType::Choice => {
            let choices = attr
                .options
                .as_ref()
                .and_then(|o| o.get("choices"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            let multi = attr
                .options
                .as_ref()
                .and_then(|o| o.get("multi"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if multi {
                json!({ "type": "array", "items": { "enum": choices } })
            } else {
                json!({ "enum": choices })
            }
        }
        FieldType::Lookup => {
            let mut s = json!({ "type": "string", "format": "uuid" });
            if let Some(target) = target {
                s["description"] = json!(format!("the id of a {target} record"));
            }
            s
        }
        FieldType::File | FieldType::Image => json!({
            "type": "string",
            "format": "uuid",
            "description": "the id of a finished upload session"
        }),
    };
    if !attr.is_required {
        // An optional field may be cleared.
        schema = json!({ "anyOf": [schema, { "type": "null" }] });
    }
    Some(schema)
}

pub(crate) struct RecordSchema;

impl Action for RecordSchema {
    fn id(&self) -> ActionId {
        ActionId(RECORD_SCHEMA)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            ctx.security.require(entity, "read")?;
            let registry = state.entities.load();
            let meta = registry.get(entity).ok_or(AppError::NotFound)?;
            let mut properties = Map::new();
            let mut required = Vec::new();
            for attr in &meta.attrs {
                if attome_core::ALL_SYSTEM_COLS.contains(&attr.logicalname.as_str()) {
                    continue;
                }
                if attr.requires_field_write_grant()
                    && !ctx
                        .security
                        .has_field_write_grant(entity, &attr.logicalname)
                {
                    continue;
                }
                let target = attr
                    .lookup_entity_ref
                    .and_then(|id| registry.get_by_id(id))
                    .map(|target| target.logicalname.clone());
                let Some(schema) = field_schema(attr, target.as_deref()) else {
                    continue;
                };
                if attr.is_required {
                    required.push(json!(attr.logicalname));
                }
                properties.insert(attr.logicalname.clone(), schema);
            }
            Ok(ActionResult::plain(json!({
                "entity": entity,
                "schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": false
                }
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(field_type_int: i32, required: bool, options: Value) -> AttrInfo {
        serde_json::from_value(json!({
            "logicalname": "f", "field_type_int": field_type_int, "is_required": required,
            "is_sensitive": false, "is_sortable": false, "is_filterable": false,
            "options": options, "max_length": 40
        }))
        .unwrap()
    }

    #[test]
    fn fields_are_typed_from_their_metadata() {
        let text = field_schema(&attr(3, true, Value::Null), None).unwrap();
        assert_eq!(text, json!({ "type": "string", "maxLength": 40 }));
        let choice = field_schema(
            &attr(7, true, json!({ "choices": ["a", "b"], "multi": false })),
            None,
        )
        .unwrap();
        assert_eq!(choice, json!({ "enum": ["a", "b"] }));
        let optional = field_schema(&attr(6, false, Value::Null), None).unwrap();
        assert_eq!(optional["anyOf"][1], json!({ "type": "null" }));
        let lookup = field_schema(&attr(11, true, Value::Null), Some("account")).unwrap();
        assert_eq!(lookup["description"], "the id of a account record");
    }
}
