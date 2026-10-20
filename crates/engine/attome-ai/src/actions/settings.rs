//! `settings.list` and `settings.set` (roadmap U10-T2): the registered
//! settings as an agent tool. Administrators only, like
//! `/api/v1/admin/settings`.
//!
//! `settings.list` reads every runtime setting with its key, area, scopes and
//! deployment value. `settings.set` changes one deployment value and is
//! `Consequential`: it never runs for an agent on its own, a person approves
//! it first, and it writes through the settings API itself
//! (`attome_core::SettingsWriter`, registered by `attome-api`), so the
//! validation, the boot-time-only refusal, the lock, the change log and the
//! audit event are the route's own. Its `key` is an enum of the runtime keys,
//! so a boot-time-only key cannot even be named.

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;

use attome_core::EngineState;
use attome_core::setting_descriptor::area;
use attome_core::setting_registry;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SETTINGS_LIST: &str = "settings.list";
pub const SETTINGS_SET: &str = "settings.set";

/// Every runtime setting's key: the keys `settings.set` accepts.
pub fn settable_keys() -> Vec<&'static str> {
    setting_registry()
        .runtime_eligible()
        .map(|d| d.key)
        .collect()
}

static SET_SCHEMA: LazyLock<String> = LazyLock::new(|| {
    json!({
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "enum": settable_keys(),
                "description": "The setting's key, as settings.list names it."
            },
            "value": {
                "description": "The new deployment value; it must fit the setting's schema."
            }
        },
        "required": ["key", "value"],
        "additionalProperties": false
    })
    .to_string()
});

pub fn list_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        SETTINGS_LIST,
        "List this system's settings: each one's key, area, description, the scopes it can be \
         set at, its JSON schema and its current deployment value.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#)
}

pub fn set_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        SETTINGS_SET,
        "Change one setting's deployment value. A person approves the change before it is \
         made. Use settings.list first for the key and the schema the value must fit. Do NOT \
         use this for a user's own preference.",
        RiskTier::Consequential,
        Effect::Write,
        // Setting the same value twice leaves the same state.
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(SET_SCHEMA.as_str())
}

pub(crate) struct SettingsList;
pub(crate) struct SettingsSet;

impl Action for SettingsList {
    fn id(&self) -> ActionId {
        ActionId(SETTINGS_LIST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let snapshot = state.settings.load();
            let settings: Vec<Value> = setting_registry()
                .runtime_eligible()
                .map(|d| {
                    let (value, _) = snapshot.resolve(d, None, None);
                    json!({
                        "key": d.key,
                        "area": area(d.key),
                        "description": d.description,
                        "scopes": d.allowed_scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                        "schema": (d.schema)(),
                        "value": value,
                    })
                })
                .collect();
            Ok(ActionResult::plain(json!({ "settings": settings })))
        })
    }
}

impl Action for SettingsSet {
    fn id(&self) -> ActionId {
        ActionId(SETTINGS_SET)
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
            let key = args
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("key is required".into()))?;
            let value = args
                .get("value")
                .cloned()
                .ok_or_else(|| AppError::Validation("value is required".into()))?;
            let Some(writer) = state.settings_writer.as_ref() else {
                return Err(AppError::CapabilityUnavailable("settings write"));
            };
            let written = writer
                .write_deployment(state, ctx.security.user_id, key, value)
                .await?;
            Ok(ActionResult::plain(json!({ "setting": written })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_tools_are_for_administrators_and_a_write_waits_for_a_person() {
        let list = list_descriptor();
        assert_eq!(list.required_privileges, &["system.admin"]);
        assert_eq!(list.effect, Effect::Read);
        let set = set_descriptor();
        assert_eq!(set.required_privileges, &["system.admin"]);
        assert_eq!(set.risk, RiskTier::Consequential);
        assert_eq!(set.effect, Effect::Write);
    }

    #[test]
    fn settings_set_names_every_runtime_key_and_no_boot_time_key() {
        let schema: Value = serde_json::from_str(&SET_SCHEMA).expect("valid JSON");
        let named: Vec<&str> = schema["properties"]["key"]["enum"]
            .as_array()
            .map(|keys| keys.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for d in setting_registry().iter() {
            assert_eq!(
                named.contains(&d.key),
                !d.boot_time_only,
                "{}: boot-time-only keys are not settable",
                d.key
            );
        }
    }
}
