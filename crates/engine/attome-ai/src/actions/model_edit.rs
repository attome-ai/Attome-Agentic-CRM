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
//!
//! Beside them (N12-T1), two read tools per kind: `model.<kind>.describe`
//! (the kind's description and document schema, for every kind) and
//! `model.<kind>.list` (the objects of a kind stored in the model, paged).
//! They read what the admin API reads, under the same administrator rule.

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

/// What a read tool does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadOp {
    Describe,
    List,
}

/// One generated read tool.
#[derive(Debug)]
struct ReadTool {
    id: &'static str,
    kind: &'static str,
    op: ReadOp,
    description: &'static str,
}

const DESCRIBE_SCHEMA: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const LIST_SCHEMA: &str = r#"{"type":"object","properties":{"page":{"type":"integer","minimum":1}},"additionalProperties":false}"#;

fn read_tools() -> &'static [ReadTool] {
    static TOOLS: OnceLock<Vec<ReadTool>> = OnceLock::new();
    TOOLS.get_or_init(|| {
        let mut out = Vec::new();
        for kind in attome_metadata::model_edit::registry().iter() {
            let name = kind.name().as_str();
            out.push(ReadTool {
                id: leak(format!("model.{name}.describe")),
                kind: name,
                op: ReadOp::Describe,
                description: leak(format!(
                    "Describe the {name} kind: what it is and its document's JSON Schema."
                )),
            });
            if kind.adapter_table().is_none() {
                out.push(ReadTool {
                    id: leak(format!("model.{name}.list")),
                    kind: name,
                    op: ReadOp::List,
                    description: leak(format!(
                        "List the {name} objects by name, a page at a time, with their ids, \
                         newest version and content hash."
                    )),
                });
            }
        }
        out
    })
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    let reads = read_tools().iter().map(|tool| {
        ActionDescriptor::new(
            tool.id,
            tool.description,
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            attome_modules::MODULE_AI,
            &[],
        )
        .input_schema(match tool.op {
            ReadOp::Describe => DESCRIBE_SCHEMA,
            ReadOp::List => LIST_SCHEMA,
        })
    });
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
        .chain(reads)
        .collect()
}

pub fn executors() -> Vec<Box<dyn Action>> {
    tools()
        .iter()
        .map(|tool| Box::new(ModelEdit { tool }) as Box<dyn Action>)
        .chain(
            read_tools()
                .iter()
                .map(|tool| Box::new(ModelRead { tool }) as Box<dyn Action>),
        )
        .collect()
}

/// The executor for one kind's read tool.
#[derive(Debug)]
pub struct ModelRead {
    tool: &'static ReadTool,
}

impl Action for ModelRead {
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
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let kind = attome_metadata::model_edit::registry()
                .get(self.tool.kind)
                .ok_or(AppError::NotFound)?;
            let value = match self.tool.op {
                ReadOp::Describe => json!({
                    "name": kind.name().as_str(),
                    "schema_version": kind.schema_version(),
                    "description": kind.agent_tool_description(),
                    "stored_in_model": kind.adapter_table().is_none(),
                    "json_schema": kind.json_schema(),
                }),
                ReadOp::List => {
                    let page = args["page"].as_u64().unwrap_or(1).max(1);
                    let query: attome_types::OnePageQuery =
                        serde_json::from_value(json!({ "page": page }))
                            .map_err(|error| AppError::Validation(error.to_string()))?;
                    let found =
                        attome_model::store::list_objects(&state.base.db, self.tool.kind, &query)
                            .await?;
                    json!({
                        "items": found.items,
                        "total": found.total,
                        "page": found.page,
                        "page_size": found.page_size,
                    })
                }
            };
            Ok(ActionResult::plain(value))
        })
    }
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
        let edits: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| id.ends_with(".edit"))
            .collect();
        let expected: Vec<String> = stored.iter().map(|k| format!("model.{k}.edit")).collect();
        assert_eq!(edits, expected);
        assert!(ids.contains(&"model.form.edit"));
        // N12-T1: every kind can be described; stored kinds can be listed.
        assert!(ids.contains(&"model.entity.describe"));
        assert!(ids.contains(&"model.form.list"));
        assert!(!ids.contains(&"model.entity.list"));
        for descriptor in &descriptors {
            assert!(
                descriptor.agent_must_confirm
                    || descriptor.id.0.ends_with(".describe")
                    || descriptor.id.0.ends_with(".list"),
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
