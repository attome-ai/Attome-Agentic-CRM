//! `secrets.list` (roadmap Z1-T13): every secret of this node's
//! configuration by name, with the features that use it, whether it is set
//! and how old its active key is, from the secret inventory
//! (`attome_compliance::secret_inventory`, the same query as
//! `GET /api/v1/admin/secrets`). Administrators only, like that route.
//!
//! Names and ages only: no value, hash, fragment or key id ever reaches the
//! model. There is no write or rotate action for secrets; rotation stays
//! with operators.

use std::future::Future;
use std::pin::Pin;

use attome_compliance::secret_inventory::{self, SecretInventoryRow};
use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::{AppError, PageWindow};
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SECRETS_LIST: &str = "secrets.list";

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        SECRETS_LIST,
        "List the secrets this system is configured with, by name: the features that use each, \
         whether it is set, how many days its active key has been in use and whether that is \
         past the rotation limit. Never returns a secret's value.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &["system.admin"],
    )
    .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#)
}

pub(crate) struct SecretsList;

impl Action for SecretsList {
    fn id(&self) -> ActionId {
        ActionId(SECRETS_LIST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let config = &state.base.config;
            let states = config.secret_inventory();
            let all = i64::try_from(states.len()).unwrap_or(i64::MAX).max(1);
            let page = secret_inventory::list(
                &state.base.db,
                states,
                config.security.secret_max_age_days,
                PageWindow {
                    page: 1,
                    page_size: all,
                    offset: 0,
                },
            )
            .await?;
            let secrets: Vec<Value> = page.items.iter().map(secret_row).collect();
            Ok(ActionResult::plain(json!({ "secrets": secrets })))
        })
    }
}

/// One secret as the tool reports it: the fields are listed one by one, so
/// a field later added to the inventory row never reaches the model unseen.
fn secret_row(row: &SecretInventoryRow) -> Value {
    json!({
        "name": row.name,
        "used_by": row.used_by,
        "set": row.set,
        "age_days": row.age_days,
        "over_age": row.over_age,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    out.push(key.clone());
                    keys(inner, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|inner| keys(inner, out)),
            _ => {}
        }
    }

    #[test]
    fn secrets_list_returns_no_values() {
        let row = SecretInventoryRow {
            name: "auth.mfa_encryption_key".to_owned(),
            used_by: vec!["mfa".to_owned()],
            rotation: "key_ring".to_owned(),
            set: true,
            key_ids: vec!["k20260101".to_owned(), "k20261001".to_owned()],
            active_key_id: Some("k20261001".to_owned()),
            active_since: Some(chrono::Utc::now()),
            age_days: Some(18),
            over_age: false,
        };
        let body = json!({ "secrets": [secret_row(&row)] });
        let mut found = Vec::new();
        keys(&body, &mut found);
        for banned in ["value", "secret", "last4", "key_ids", "active_key_id"] {
            assert!(!found.iter().any(|k| k == banned), "{banned} in {body}");
        }
        assert!(!body.to_string().contains("k2026"), "no key id: {body}");
        assert_eq!(body["secrets"][0]["age_days"], 18);
        assert_eq!(body["secrets"][0]["name"], "auth.mfa_encryption_key");
    }

    #[test]
    fn secrets_list_is_for_administrators_and_reads_only() {
        let d = descriptor();
        assert_eq!(d.required_privileges, &["system.admin"]);
        assert_eq!(d.effect, Effect::Read);
    }
}
