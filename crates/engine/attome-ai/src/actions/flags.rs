//! `flags.list` and `flags.set` (roadmap T6-T4): customer flags as an agent
//! tool, with the permission of `/api/v1/admin/customer-flags`
//! (`admin.deployment`, or an administrator).
//!
//! `flags.list` reads every flag: its name, description, value, emergency
//! off and whether `flag(name)` reads true now. `flags.set` defines a flag or
//! sets its value and is `Consequential`: it never runs for an agent on its
//! own, a person approves it first, and it writes through the flags API
//! itself (`attome_core::customer_flags::FlagsWriter`, registered by
//! `attome-api`), so the name check, the row version and the audit event are
//! the route's own.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const FLAGS_LIST: &str = "flags.list";
pub const FLAGS_SET: &str = "flags.set";

/// The flags API's privilege.
const DEPLOYMENT: &str = "admin.deployment";

/// The most flags listed (the deployment's limit).
const MAX_FLAGS: i64 = 500;

const SET_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "name": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,62}$",
              "description": "The flag's name, as flags.list names it, or a new one." },
    "value": { "type": "boolean", "description": "On or off." },
    "description": { "type": "string", "description": "What the flag is for (a new flag)." },
    "row_version": { "type": "integer", "description": "The flag's row_version from flags.list; required when it exists." }
  },
  "required": ["name", "value"],
  "additionalProperties": false
}"#;

pub fn list_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        FLAGS_LIST,
        "List this deployment's customer flags, the switches rules and flows read as \
         flag(\"name\"): each one's name, description, value, whether it is switched off in an \
         emergency, whether it reads on now, and its row_version.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[DEPLOYMENT],
    )
    .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#)
}

pub fn set_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        FLAGS_SET,
        "Define a customer flag or switch one on or off. A person approves the change before it \
         is made. Use flags.list first for the flag's row_version, which a change to an existing \
         flag needs.",
        RiskTier::Consequential,
        Effect::Write,
        // Setting the same value twice leaves the same state.
        RetryClass::Idempotent,
        MODULE_CORE,
        &[DEPLOYMENT],
    )
    .input_schema(SET_SCHEMA)
}

fn allowed(ctx: &ActionContext) -> bool {
    ctx.security.is_admin || ctx.security.privileges.contains(DEPLOYMENT)
}

pub(crate) struct FlagsList;
pub(crate) struct FlagsSet;

impl Action for FlagsList {
    fn id(&self) -> ActionId {
        ActionId(FLAGS_LIST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !allowed(ctx) {
                return Err(AppError::Forbidden);
            }
            type Row = (String, Option<String>, bool, bool, i64);
            let rows: Vec<Row> = sqlx::query_as(
                "SELECT name, description, value, emergency_off, row_version \
                   FROM customer_flag ORDER BY name LIMIT $1",
            )
            .bind(MAX_FLAGS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let flags: Vec<Value> = rows
                .into_iter()
                .map(|(name, description, value, emergency_off, row_version)| {
                    json!({
                        "name": name,
                        "description": description,
                        "value": value,
                        "emergency_off": emergency_off,
                        "on": value && !emergency_off,
                        "row_version": row_version,
                    })
                })
                .collect();
            Ok(ActionResult::plain(json!({ "flags": flags })))
        })
    }
}

impl Action for FlagsSet {
    fn id(&self) -> ActionId {
        ActionId(FLAGS_SET)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !allowed(ctx) {
                return Err(AppError::Forbidden);
            }
            let name = args
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("name is required".into()))?;
            let value = args
                .get("value")
                .and_then(Value::as_bool)
                .ok_or_else(|| AppError::Validation("value is true or false".into()))?;
            let description = args
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let row_version = args.get("row_version").and_then(Value::as_i64);
            let Some(writer) = state.flags_writer.as_ref() else {
                return Err(AppError::CapabilityUnavailable("flags write"));
            };
            let written = writer
                .set(
                    state,
                    ctx.security.user_id,
                    name,
                    value,
                    description,
                    row_version,
                )
                .await?;
            Ok(ActionResult::plain(json!({ "flag": written })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_tools_carry_the_flags_api_permission_and_a_change_waits_for_a_person() {
        let list = list_descriptor();
        assert_eq!(list.required_privileges, &[DEPLOYMENT]);
        assert_eq!(list.effect, Effect::Read);
        let set = set_descriptor();
        assert_eq!(set.required_privileges, &[DEPLOYMENT]);
        assert_eq!(set.risk, RiskTier::Consequential);
        assert_eq!(set.effect, Effect::Write);
        let schema: Value = serde_json::from_str(SET_SCHEMA).unwrap_or(Value::Null);
        assert_eq!(schema["required"], json!(["name", "value"]));
    }
}
