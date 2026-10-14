//! `model.<kind>.edit` (roadmap Y1-T14): one agent tool per metadata kind
//! stored in the model, generated from the kind registry
//! (`attome_model::agent::tool_specs`), so a new kind gets its tool without
//! code here.
//!
//! Each tool saves a draft through `attome_metadata::model_edit::edit`, the
//! path the admin API's `POST /api/v1/admin/model/{kind}/{id}/commands`
//! uses, under the same rule: the caller must be an administrator. Nothing
//! is published. An agent never saves on its own: every agent invocation
//! stops at confirmation and the human applies it (`agent_must_confirm`), so
//! a run-mode agent cannot change metadata.

use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// One generated tool. The strings are built once per process from the
/// registry and kept for its life, as the static action registry needs.
#[derive(Debug)]
struct ModelTool {
    id: &'static str,
    kind: &'static str,
    description: &'static str,
    input_schema: &'static str,
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn tools() -> &'static [ModelTool] {
    static TOOLS: OnceLock<Vec<ModelTool>> = OnceLock::new();
    TOOLS.get_or_init(|| {
        let registry = attome_metadata::model_edit::registry();
        attome_model::agent::tool_specs(registry)
            .into_iter()
            .filter_map(|spec| {
                let kind_name = spec
                    .name
                    .strip_prefix("model.")
                    .and_then(|rest| rest.strip_suffix(".edit"))?;
                let kind = registry.get(kind_name)?.name().as_str();
                Some(ModelTool {
                    id: leak(spec.name),
                    kind,
                    description: leak(format!(
                        "Edit a draft {kind}: {} Saves a draft only; publishing is separate. \
                         Administrators only.",
                        spec.description
                    )),
                    input_schema: leak(spec.input_schema.to_string()),
                })
            })
            .collect()
    })
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    tools()
        .iter()
        .map(|tool| {
            ActionDescriptor::new(
                tool.id,
                tool.description,
                // A draft changes nothing live until someone publishes it.
                RiskTier::Reversible,
                Effect::Write,
                // `base_hash` makes a replay a version conflict, never a
                // second edit.
                RetryClass::Idempotent,
                attome_modules::MODULE_AI,
                &[],
            )
            .input_schema(tool.input_schema)
            .agent_must_confirm()
        })
        .collect()
}

pub fn executors() -> Vec<Box<dyn Action>> {
    tools()
        .iter()
        .map(|tool| Box::new(ModelEdit { tool }) as Box<dyn Action>)
        .collect()
}

/// The executor for one kind's edit tool.
#[derive(Debug)]
pub struct ModelEdit {
    tool: &'static ModelTool,
}

impl Action for ModelEdit {
    fn id(&self) -> ActionId {
        ActionId(self.tool.id)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // The admin API's rule (`Authorized<Admin>`), checked here
            // because no static privilege key names "administrator".
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let kind = attome_metadata::model_edit::registry()
                .get(self.tool.kind)
                .ok_or(AppError::NotFound)?;
            let id = args["id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("id must be a UUID".into()))?;
            let base_hash = args["base_hash"]
                .as_str()
                .ok_or_else(|| AppError::Validation("base_hash is required".into()))?
                .to_owned();
            let commands = args["commands"]
                .as_array()
                .cloned()
                .ok_or_else(|| AppError::Validation("commands must be a list".into()))?;
            let name = args["name"].as_str().map(str::to_owned);
            let user_id = ctx.security.user_id;

            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let edited = attome_metadata::model_edit::edit(
                &state.base.db,
                &mut tx,
                kind.as_ref(),
                attome_metadata::model_edit::EditRequest {
                    id,
                    base_hash,
                    name,
                    commands,
                },
                Some(user_id),
            )
            .await?;
            write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::Update,
                    user_id,
                    "metadata_object",
                    Some(id),
                )
                .named("model.commands")
                .comment(format!(
                    "{} `{}` draft v{}: {} command(s), by {}",
                    self.tool.kind,
                    edited.name,
                    edited.saved.version_no,
                    edited.commands,
                    self.tool.id
                )),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            let issues: Vec<Value> = edited
                .saved
                .issues
                .iter()
                .map(|issue| json!({ "path": issue.path, "code": issue.code, "message": issue.message }))
                .collect();
            Ok(ActionResult::plain(json!({
                "id": id,
                "version_no": edited.saved.version_no,
                "content_hash": edited.saved.content_hash,
                "issues": issues,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One tool per kind stored in the model, each with its kind's
    /// description; adapter kinds get none.
    #[test]
    fn metadata_kind_tools_are_registered() {
        let registry = attome_metadata::model_edit::registry();
        let stored: Vec<&str> = registry
            .iter()
            .filter(|kind| kind.adapter_table().is_none())
            .map(|kind| kind.name().as_str())
            .collect();
        let descriptors = descriptors();
        let ids: Vec<&str> = descriptors.iter().map(|d| d.id.0).collect();
        let expected: Vec<String> = stored.iter().map(|k| format!("model.{k}.edit")).collect();
        assert_eq!(ids, expected);
        assert!(ids.contains(&"model.form.edit"));
        for descriptor in &descriptors {
            assert!(
                descriptor.agent_must_confirm,
                "an agent only proposes edits"
            );
            assert!(
                serde_json::from_str::<Value>(descriptor.input_schema).is_ok(),
                "{}: the input schema is JSON",
                descriptor.id.0
            );
        }
        assert_eq!(executors().len(), descriptors.len());
    }
}
