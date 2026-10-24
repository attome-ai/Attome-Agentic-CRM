//! C5 — the generic business-record writes: `record.create`, `record.update`,
//! `record.delete`, `record.restore` (`document/chatbot/02-capability-model.md`
//! § "The five write actions C5 adds").
//!
//! Every write goes through the entity engine's own non-HTTP entry points —
//! `entity_crud::{create,update,delete,restore}_record_for` — never
//! route-local SQL (guidelines §9): field validation, lookup integrity,
//! soft delete, row versions, cache invalidation and the audit trail all come
//! from the engine.
//!
//! ## Authorization, per action
//!
//! The engine's `…_for` functions perform record-level access themselves but
//! **not** the table-level privilege check an HTTP extractor performs, so each
//! executor calls `SecurityContextExt::require(entity, verb)` first — the
//! pattern `record_update_field.rs` established. The caller is always the
//! human the session runs for (`ctx.security`), never a service principal.
//!
//! An agent may not write a special-category field through any of these,
//! decided by the one shared check `record_update_field::
//! sensitive_write_is_blocked` — never a second implementation (`02` §
//! "`record.update` does not replace `record.update_field`").
//!
//! ## Human confirmation (C5 decision 2)
//!
//! All four carry `agent_must_confirm`. For an agent, `gate::evaluate` returns
//! `ConfirmFirst` for the `Reversible` three **before** looking at taint, so a
//! business write proposed by an agent never executes autonomously merely
//! because the context happens to be untainted. `record.delete` is
//! `Consequential`, so the gate's approval arm governs it; the flag is set
//! there too, for explicitness — it does not replace four-eyes approval.
//!
//! The executor structs are `pub(crate)`: no other crate can construct one and
//! call `Action::execute` around `dispatch`, so the gate is the only way in.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::actions::record_update_field::sensitive_write_is_blocked;
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const RECORD_CREATE: &str = "record.create";
pub const RECORD_UPDATE: &str = "record.update";
pub const RECORD_DELETE: &str = "record.delete";
pub const RECORD_RESTORE: &str = "record.restore";

const CREATE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name, e.g. an entity from the catalogue the user works in." },
    "values": {
      "type": "object",
      "description": "Field logical names to values for the new record. Shapes follow each field's own type and are validated by the entity engine."
    }
  },
  "required": ["entity", "values"],
  "additionalProperties": false
}"#;

const UPDATE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record to change." },
    "values": {
      "type": "object",
      "description": "Only the fields to change, logical name to new value."
    },
    "row_version": {
      "type": "integer",
      "description": "The row_version the record had when it was read. A stale value is refused as a conflict rather than overwriting a concurrent edit."
    }
  },
  "required": ["entity", "record_id", "values", "row_version"],
  "additionalProperties": false
}"#;

const DELETE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record to delete." },
    "row_version": {
      "type": "integer",
      "description": "Optional. The row_version the record had when it was read; a stale value is refused as a conflict."
    }
  },
  "required": ["entity", "record_id"],
  "additionalProperties": false
}"#;

const RESTORE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid", "description": "The deleted record to bring back." },
    "row_version": {
      "type": "integer",
      "description": "Optional. The row_version the deleted record had when it was read; a stale value is refused as a conflict."
    }
  },
  "required": ["entity", "record_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            RECORD_CREATE,
            "Create one new record of an entity, with the field values given. \
             Use this only when the user asks for a new record. Do NOT use it to \
             change an existing record (use record.update) or to bring back a \
             deleted one (use record.restore). A person confirms it before it \
             is written.",
            RiskTier::Reversible,
            Effect::Write,
            // A retry without a key would create a second record.
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(CREATE_SCHEMA)
        .agent_must_confirm(),
        ActionDescriptor::new(
            RECORD_UPDATE,
            "Change one or more fields on an existing record you can already \
             edit, given the row_version you read. Do NOT use it to create a \
             record, and do NOT guess a row_version — read the record first. \
             A person confirms it before it is written.",
            RiskTier::Reversible,
            Effect::Write,
            // A multi-field update is not a pure set-to-value (02 §).
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(UPDATE_SCHEMA)
        .agent_must_confirm(),
        ActionDescriptor::new(
            RECORD_DELETE,
            "Delete one record, removing it from every view and report until it \
             is restored. Use it only when the user explicitly asks for a \
             deletion. Never use it to tidy up or to undo your own mistake — \
             tell the user instead. It always goes to a second person for \
             approval before anything happens.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::NeverRetry,
            MODULE_AI,
            &[],
        )
        .input_schema(DELETE_SCHEMA)
        .agent_must_confirm(),
        ActionDescriptor::new(
            RECORD_RESTORE,
            "Bring back a record that was deleted. Do NOT use it on a record \
             that is not deleted, and do NOT use it to create a new record. A \
             person confirms it before it is written.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(RESTORE_SCHEMA)
        .agent_must_confirm(),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(RecordCreate),
        Box::new(RecordUpdate),
        Box::new(RecordDelete),
        Box::new(RecordRestore),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateArgs {
    entity: String,
    values: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateArgs {
    entity: String,
    record_id: Uuid,
    values: Map<String, Value>,
    row_version: i64,
}

/// Delete and restore take the same shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRefArgs {
    entity: String,
    record_id: Uuid,
    #[serde(default)]
    row_version: Option<i64>,
}

fn parse<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, AppError> {
    serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))
}

/// Refuses an agent write that touches a special-category field, through the
/// one shared check. A field the entity does not have is a validation error
/// here rather than later, so a model is told which name was wrong. Metadata
/// is read and copied out before any `.await`.
fn refuse_sensitive_fields<'k>(
    state: &EngineState,
    ctx: &ActionContext,
    entity: &str,
    fields: impl Iterator<Item = &'k String>,
) -> Result<(), AppError> {
    let registry = state.entities.load();
    let meta = registry.get(entity).ok_or(AppError::NotFound)?;
    for field in fields {
        let attr = meta
            .attrs
            .iter()
            .find(|a| &a.logicalname == field)
            .ok_or_else(|| AppError::Validation(format!("{entity} has no field named {field}")))?;
        if sensitive_write_is_blocked(ctx.is_agent(), attr.data_classification) {
            return Err(AppError::Forbidden);
        }
    }
    Ok(())
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, AppError> {
    serde_json::to_value(value).map_err(AppError::internal)
}

/// A written record as returned to the caller. Over MCP, its lookup display
/// names into entities not admitted for read are dropped (D-769).
fn redacted<T: serde::Serialize>(
    state: &EngineState,
    ctx: &ActionContext,
    record: T,
) -> Result<Value, AppError> {
    let mut value = to_value(record)?;
    crate::mcp::admission::redact_record_for_caller(state, ctx, &mut value)?;
    Ok(value)
}

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>>;

pub(crate) struct RecordCreate;

impl Action for RecordCreate {
    fn id(&self) -> ActionId {
        ActionId(RECORD_CREATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let args: CreateArgs = parse(args)?;
            ctx.security.require(&args.entity, "create")?;
            refuse_sensitive_fields(state, ctx, &args.entity, args.values.keys())?;
            let (record_id, record) = attome_records::entity_crud::create_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                &args.entity,
                Value::Object(args.values),
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": args.entity,
                "record_id": record_id,
                "record": redacted(state, ctx, record)?,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let args: CreateArgs = parse(args).ok()?;
        Some(json!({ "action": RECORD_CREATE, "entity": args.entity, "values": args.values }))
    }
}

/// A16-T5: an agent's update merges by default. A stale `row_version`
/// whose missed versions changed none of the attributes sent is applied over
/// the record's current version (A16-T2's rule); otherwise the agent gets the
/// conflict, with what changed (A16-T1), to read the record again. AH4's
/// limits name no conflict rule, so no agent write waits for a person.
pub(crate) async fn update_merging(
    state: &EngineState,
    security: &attome_server::security::SecurityContext,
    entity: &str,
    record_id: Uuid,
    row_version: i64,
    body: Value,
) -> Result<attome_records::entity_crud::EntityRecordResponse, AppError> {
    let sent: Vec<String> = body
        .as_object()
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_default();
    let first = attome_records::entity_crud::update_record_for(
        state,
        security,
        security.user_id,
        entity,
        record_id,
        row_version,
        body.clone(),
    )
    .await;
    if !matches!(first, Err(AppError::VersionConflict)) {
        return first;
    }
    let basis = attome_records::entity_crud::history::merge_basis(
        state,
        security,
        entity,
        record_id,
        row_version,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, %record_id, "agent merge basis unavailable");
        None
    })
    .filter(|basis| !basis.changed.iter().any(|name| sent.contains(name)));
    if let Some(basis) = basis {
        match attome_records::entity_crud::update_record_for(
            state,
            security,
            security.user_id,
            entity,
            record_id,
            basis.current_version,
            body,
        )
        .await
        {
            Err(AppError::VersionConflict) => {}
            other => return other,
        }
    }
    Err(attome_records::entity_crud::history::version_conflict(
        state,
        security,
        entity,
        record_id,
        row_version,
        "agent",
    )
    .await)
}

pub(crate) struct RecordUpdate;

impl Action for RecordUpdate {
    fn id(&self) -> ActionId {
        ActionId(RECORD_UPDATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let args: UpdateArgs = parse(args)?;
            ctx.security.require(&args.entity, "update")?;
            if args.values.is_empty() {
                return Err(AppError::Validation(
                    "values must name at least one field to change".into(),
                ));
            }
            refuse_sensitive_fields(state, ctx, &args.entity, args.values.keys())?;
            let record = update_merging(
                state,
                &ctx.security,
                &args.entity,
                args.record_id,
                args.row_version,
                Value::Object(args.values),
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": args.entity,
                "record_id": args.record_id,
                "record": redacted(state, ctx, record)?,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let args: UpdateArgs = parse(args).ok()?;
        Some(json!({
            "action": RECORD_UPDATE,
            "entity": args.entity,
            "record_id": args.record_id,
            "values": args.values,
        }))
    }
}

pub(crate) struct RecordDelete;

impl Action for RecordDelete {
    fn id(&self) -> ActionId {
        ActionId(RECORD_DELETE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let args: RecordRefArgs = parse(args)?;
            ctx.security.require(&args.entity, "delete")?;
            attome_records::entity_crud::delete_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                &args.entity,
                args.record_id,
                args.row_version,
                &attome_records::entity_mutation::DeleteOrigin::new(
                    attome_records::entity_mutation::DeleteKind::Agent,
                ),
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": args.entity,
                "record_id": args.record_id,
                "deleted": true,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let args: RecordRefArgs = parse(args).ok()?;
        Some(json!({ "action": RECORD_DELETE, "entity": args.entity, "record_id": args.record_id }))
    }
}

pub(crate) struct RecordRestore;

impl Action for RecordRestore {
    fn id(&self) -> ActionId {
        ActionId(RECORD_RESTORE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let args: RecordRefArgs = parse(args)?;
            // Restore reuses the "update" grant, as the HTTP restore route does.
            ctx.security.require(&args.entity, "update")?;
            let record = attome_records::entity_crud::restore_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                &args.entity,
                args.record_id,
                args.row_version,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": args.entity,
                "record_id": args.record_id,
                "record": redacted(state, ctx, record)?,
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let args: RecordRefArgs = parse(args).ok()?;
        Some(
            json!({ "action": RECORD_RESTORE, "entity": args.entity, "record_id": args.record_id }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The approved C5 classification (the descriptor table), pinned so a
    /// later edit cannot quietly weaken it.
    #[test]
    fn the_four_writes_are_classified_as_approved() {
        let by_id = |id: &str| {
            descriptors()
                .into_iter()
                .find(|d| d.id.as_str() == id)
                .unwrap_or_else(|| panic!("{id} is registered"))
        };
        for (id, risk, retry) in [
            (RECORD_CREATE, RiskTier::Reversible, RetryClass::RequiresKey),
            (RECORD_UPDATE, RiskTier::Reversible, RetryClass::RequiresKey),
            (
                RECORD_DELETE,
                RiskTier::Consequential,
                RetryClass::NeverRetry,
            ),
            (
                RECORD_RESTORE,
                RiskTier::Reversible,
                RetryClass::RequiresKey,
            ),
        ] {
            let d = by_id(id);
            assert_eq!(d.effect, Effect::Write, "{id}");
            assert_eq!(d.risk, risk, "{id}");
            assert_eq!(d.retry, retry, "{id}");
            assert!(
                d.agent_must_confirm,
                "{id} must always be human-confirmed for an agent"
            );
            assert_eq!(d.module, MODULE_AI, "{id}");
        }
    }

    /// An argument the schema does not name is refused, not ignored — a model
    /// that invents a field is told, and nothing is written from a guess.
    #[test]
    fn unknown_arguments_are_refused() {
        let bad = json!({ "entity": "x", "values": {}, "surprise": 1 });
        assert!(matches!(
            parse::<CreateArgs>(&bad),
            Err(AppError::Validation(_))
        ));
    }
}
