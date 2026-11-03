//! N12-T1: `model.entity.create` and `model.attribute.create`, the build
//! tools for the two kinds edited through their own APIs (entities and their
//! fields), beside the generated `model.<kind>.edit|describe|list` tools.
//!
//! An entity or a field is a table or a column as well as metadata, so the
//! write runs the admin API's own create path (`attome-api`), which this
//! crate sits below: `attome-api` installs it as a [`SchemaBuilder`] when the
//! engine system is built. The write records into a changeset as the admin
//! route's does. Called in a Develop workspace (a request naming it with
//! `X-Attome-Workspace`, T5-T3), it lands in that workspace's draft and its
//! changeset, never in live until the workspace is published. Administrators
//! only, as the admin routes; an agent stops at confirmation.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// The create paths, installed by `attome-api`.
pub trait SchemaBuilder: Send + Sync {
    /// Creates an entity from `args` (the admin API's create body) as
    /// `user`; the created entity's metadata.
    fn create_entity<'a>(
        &'a self,
        state: &'a EngineState,
        user: Uuid,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>>;

    /// Adds a field to the entity `args.entity` names (by logical name or
    /// id), the rest of `args` being the admin API's field body.
    fn create_attribute<'a>(
        &'a self,
        state: &'a EngineState,
        user: Uuid,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>>;
}

static BUILDER: OnceLock<Arc<dyn SchemaBuilder>> = OnceLock::new();

/// Installs the create paths; once per process. `false` when already done.
pub fn install(builder: Arc<dyn SchemaBuilder>) -> bool {
    BUILDER.set(builder).is_ok()
}

pub const ENTITY_CREATE: &str = "model.entity.create";
pub const ATTRIBUTE_CREATE: &str = "model.attribute.create";

const ENTITY_SCHEMA: &str = r#"{"type":"object","required":["logicalname","name"],"properties":{"logicalname":{"type":"string","description":"lowercase letters, digits and underscores"},"name":{"type":"string"}}}"#;
const ATTRIBUTE_SCHEMA: &str = r#"{"type":"object","required":["entity","logicalname","name","field_type"],"properties":{"entity":{"type":"string","description":"the entity's logical name or id"},"logicalname":{"type":"string"},"name":{"type":"string"},"field_type":{"type":"string","description":"text, number, date, lookup, choice and the other field types"},"is_required":{"type":"boolean"},"sensitivity":{"type":"string"}}}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    let tool = |id: &'static str, description: &'static str, schema: &'static str| {
        // A table or a column is made at once (in a workspace, only there);
        // removing it again is its own change.
        ActionDescriptor::new(
            id,
            description,
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::NeverRetry,
            attome_modules::MODULE_AI,
            &[],
        )
        .input_schema(schema)
        .agent_must_confirm()
    };
    vec![
        tool(
            ENTITY_CREATE,
            "Create an entity (its table and metadata) through the admin API's create path. \
             In a Develop workspace it stays in the workspace until it is published. \
             Administrators only.",
            ENTITY_SCHEMA,
        ),
        tool(
            ATTRIBUTE_CREATE,
            "Add a field to an entity (its column and metadata) through the admin API's create \
             path. In a Develop workspace it stays in the workspace until it is published. \
             Administrators only.",
            ATTRIBUTE_SCHEMA,
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(SchemaCreate { id: ENTITY_CREATE }),
        Box::new(SchemaCreate {
            id: ATTRIBUTE_CREATE,
        }),
    ]
}

/// The executor of both tools.
#[derive(Debug)]
pub struct SchemaCreate {
    id: &'static str,
}

impl Action for SchemaCreate {
    fn id(&self) -> ActionId {
        ActionId(self.id)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // The admin routes' rule, as for the generated edit tools.
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let builder = BUILDER
                .get()
                .ok_or(AppError::CapabilityUnavailable("schema build tools"))?;
            let user = ctx.security.user_id;
            let made = if self.id == ENTITY_CREATE {
                builder.create_entity(state, user, args).await?
            } else {
                builder.create_attribute(state, user, args).await?
            };
            Ok(ActionResult::plain(made))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_tools_write_and_wait_for_confirmation() {
        let descriptors = descriptors();
        let ids: Vec<&str> = descriptors.iter().map(|d| d.id.0).collect();
        assert_eq!(ids, vec![ENTITY_CREATE, ATTRIBUTE_CREATE]);
        for d in &descriptors {
            assert!(
                serde_json::from_str::<Value>(d.input_schema).is_ok(),
                "{}",
                d.id.0
            );
        }
        let executors = executors();
        assert_eq!(executors.len(), 2);
    }
}
