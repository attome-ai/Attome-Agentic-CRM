//! `model.app.plan` (roadmap AD4-T1): a building agent's whole-app build,
//! planned in writing first.
//!
//! From a description it drafts the data model with `model.draft` (the
//! entity skill, AD1-T1: library first, near-duplicates asked about) and, in
//! one more model call, the processes worth automating and the roles the app
//! needs. Called without `confirmed`, it answers the written plan only, for
//! the person to read. Called again with `confirmed: true` it answers the
//! ordered steps that build the app, each one of the building skills:
//!
//! 1. the entity and field build-tool calls (`model.entity.create`,
//!    `model.attribute.create`, N12);
//! 2. per new entity, its starting set (`POST .../entities/{id}/scaffold`,
//!    A1-T7) and a form draft (`model.form.draft`, AD2-T1);
//! 3. per process, a flow draft with its simulated test cases
//!    (`model.flow.draft`, AD3-T1);
//! 4. the roles, as proposals for the access screens.
//!
//! Nothing here writes. Every step is made by a person's confirmation, in
//! their Develop workspace, and nothing publishes without the owner's review
//! (V2-D27).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const APP_PLAN: &str = "model.app.plan";
/// Bumped whenever the prompt changes in a way that could move results.
pub const APP_PROMPT_VERSION: &str = "model.app.plan/v1";
/// Processes and roles one plan carries.
const MAX_PROCESSES: usize = 8;
const MAX_ROLES: usize = 8;

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["description"],
  "properties": {
    "description": { "type": "string", "description": "The app, in the person's words." },
    "confirmed": { "type": "boolean", "description": "true once the person has read and accepted the written plan." }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            APP_PLAN,
            "Plan a whole app from a description: its entities (library first), the processes to \
             automate and its roles, written out for the person to confirm; once confirmed, the \
             ordered building steps (entities, starting sets, forms, flows). Saves nothing.",
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
    vec![Box::new(AppPlan)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    description: String,
    #[serde(default)]
    confirmed: bool,
}

/// A process the app automates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub entity: Option<String>,
}

/// A role the app needs: what it may read and change, by entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleProposal {
    pub name: String,
    #[serde(default)]
    pub reads: Vec<String>,
    #[serde(default)]
    pub writes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Outline {
    #[serde(default)]
    processes: Vec<Process>,
    #[serde(default)]
    roles: Vec<RoleProposal>,
}

/// The plan in writing, one line a step. Pure.
pub fn written_plan(plan: &[Value], processes: &[Process], roles: &[RoleProposal]) -> Vec<String> {
    let mut lines = Vec::new();
    for step in plan {
        let entity = step["entity"].as_str().unwrap_or("?");
        let line = match step["decision"].as_str() {
            Some("create") => format!("Create the entity {entity}."),
            Some("extend") => format!(
                "Create {entity}, extending {}.",
                step["base"].as_str().unwrap_or("?")
            ),
            Some("reuse") => format!(
                "Add fields to the existing {}.",
                step["existing"].as_str().unwrap_or(entity)
            ),
            _ => format!(
                "Decide first: {}",
                step["question"]
                    .as_str()
                    .unwrap_or("this entity is close to an existing one")
            ),
        };
        lines.push(line);
    }
    for p in processes {
        lines.push(format!("Automate {}: {}", p.name, p.description));
    }
    for r in roles {
        lines.push(format!(
            "Role {}: reads {}; changes {}.",
            r.name,
            if r.reads.is_empty() {
                "nothing".to_owned()
            } else {
                r.reads.join(", ")
            },
            if r.writes.is_empty() {
                "nothing".to_owned()
            } else {
                r.writes.join(", ")
            },
        ));
    }
    lines
}

/// The building steps of a confirmed plan, in order. Pure.
pub fn build_steps(draft: &Value, processes: &[Process]) -> Vec<Value> {
    let mut steps: Vec<Value> = draft["calls"].as_array().cloned().unwrap_or_default();
    let created: Vec<&str> = draft["plan"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| matches!(s["decision"].as_str(), Some("create" | "extend")))
        .filter_map(|s| s["entity"].as_str())
        .collect();
    for entity in &created {
        steps.push(json!({
            "request": "POST /api/v1/admin/entities/{entity_id}/scaffold",
            "entity": entity,
        }));
        steps.push(json!({
            "action": crate::actions::form_draft::FORM_DRAFT,
            "args": { "entity": entity, "description": format!("The main form of {entity}.") },
        }));
    }
    for p in processes {
        let mut args = json!({ "description": p.description });
        if let Some(entity) = &p.entity {
            args["entity"] = json!(entity);
        }
        steps.push(json!({ "action": crate::actions::flow_draft::FLOW_DRAFT, "args": args }));
    }
    steps
}

#[derive(Debug)]
pub struct AppPlan;

impl Action for AppPlan {
    fn id(&self) -> ActionId {
        ActionId(APP_PLAN)
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
            let args: Args = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid {APP_PLAN} arguments: {e}")))?;
            if args.description.trim().is_empty() {
                return Err(AppError::Validation(
                    "description: say what the app is for".into(),
                ));
            }
            // The entity skill.
            let drafted = crate::actions::draft_model::DraftModel
                .execute(state, ctx, &json!({ "description": args.description }))
                .await?;
            let draft = drafted.value;
            // Processes and roles over the drafted entities.
            let entities: Vec<&str> = draft["draft"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t["name"].as_str())
                .collect();
            let system = format!(
                "You plan a business app. Answer with one JSON object and nothing else: \
                 {{\"processes\": [at most {MAX_PROCESSES} {{\"name\", \"description\" (what the \
                 flow does, step by step), \"entity\" (the entity whose records start it)}}], \
                 \"roles\": [at most {MAX_ROLES} {{\"name\", \"reads\": [entities], \"writes\": \
                 [entities]}}]}}. Use only the given entities."
            );
            let facts =
                json!({ "description": args.description, "entities": entities }).to_string();
            let (text, provenance) = crate::actions::metric_draft::generate(
                state,
                ctx,
                APP_PLAN,
                APP_PROMPT_VERSION,
                system,
                facts,
            )
            .await?;
            let mut outline: Outline =
                serde_json::from_str(crate::actions::metric_draft::strip_fence(&text))
                    .unwrap_or_default();
            outline.processes.truncate(MAX_PROCESSES);
            outline.roles.truncate(MAX_ROLES);
            let plan = draft["plan"].as_array().cloned().unwrap_or_default();
            let written = written_plan(&plan, &outline.processes, &outline.roles);
            let value = if args.confirmed {
                json!({
                    "written_plan": written,
                    "draft": draft,
                    "steps": build_steps(&draft, &outline.processes),
                    "roles": outline.roles,
                    "saved": false,
                })
            } else {
                json!({
                    "written_plan": written,
                    "findings": draft["findings"],
                    "confirm_with": { "description": args.description, "confirmed": true },
                    "saved": false,
                })
            };
            Ok(ActionResult { value, provenance })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Value {
        json!({
            "plan": [
                { "entity": "visit", "decision": "create" },
                { "entity": "tenant", "decision": "extend", "base": "party" },
                { "entity": "invoice", "decision": "reuse", "existing": "invoice" },
                { "entity": "properties", "decision": "ask", "question": "close to property" },
            ],
            "calls": [{ "action": "model.entity.create", "args": { "logicalname": "visit" } }],
        })
    }

    #[test]
    fn the_plan_is_written_before_anything_is_built() {
        let processes = vec![Process {
            name: "Visit reminder".into(),
            description: "Remind the tenant a day before a visit".into(),
            entity: Some("visit".into()),
        }];
        let roles = vec![RoleProposal {
            name: "Technician".into(),
            reads: vec!["visit".into()],
            writes: vec![],
        }];
        let plan = draft()["plan"].as_array().cloned().unwrap();
        let lines = written_plan(&plan, &processes, &roles);
        assert_eq!(lines[0], "Create the entity visit.");
        assert_eq!(lines[1], "Create tenant, extending party.");
        assert_eq!(lines[2], "Add fields to the existing invoice.");
        assert_eq!(lines[3], "Decide first: close to property");
        assert!(lines[4].starts_with("Automate Visit reminder"));
        assert_eq!(lines[5], "Role Technician: reads visit; changes nothing.");
    }

    #[test]
    fn confirmed_steps_build_entities_then_their_screens_then_flows() {
        let processes = vec![Process {
            name: "Reminder".into(),
            description: "Remind".into(),
            entity: Some("visit".into()),
        }];
        let steps = build_steps(&draft(), &processes);
        // The entity call, then scaffold and form for each new entity, then the flow.
        assert_eq!(steps.len(), 1 + 2 * 2 + 1);
        assert_eq!(steps[0]["action"], "model.entity.create");
        assert_eq!(steps[1]["entity"], "visit");
        assert_eq!(steps[2]["action"], crate::actions::form_draft::FORM_DRAFT);
        assert_eq!(steps[3]["entity"], "tenant");
        assert_eq!(steps[5]["action"], crate::actions::flow_draft::FLOW_DRAFT);
        assert_eq!(steps[5]["args"]["entity"], "visit");
    }
}
