//! Macros (roadmap G6-T2): published `macro` metadata — a named list of
//! actions run on records of one entity — previewed, run in bulk, and
//! undoable within their undo window.
//!
//! - **Steps are actions.** Each step names an action of the registry (a
//!   built-in one such as `record.update`, or a published custom action) and
//!   its arguments, where `{{entity}}` and `{{record_id}}` are filled in per
//!   record ([`fill`]). Every step goes through `dispatch` as the caller, so
//!   the gate, privileges, approvals and audit apply to each one exactly as
//!   when called alone.
//! - **Preview** (`POST /api/v1/macros/{name}/preview`) runs nothing: for
//!   each record it lists every step's action, its risk and its filled-in
//!   arguments, and the problems found (an unknown action, arguments that do
//!   not fit its schema).
//! - **Run** (`POST /api/v1/macros/{name}/run`, at most [`MAX_RECORDS`]
//!   records) dispatches the steps record by record, in order. With an undo
//!   window (`undo_minutes`, 10 by default), each step is held for that
//!   long before it runs (AH8 deferred actions), so cancelling it
//!   (`POST /api/v1/ai/deferred-actions/{id}/cancel`) undoes it; with
//!   `undo_minutes: 0` the steps run at once. A record whose step is refused
//!   or fails stops there (its later steps are not run) and the others go
//!   on; the answer lists each record's outcomes.
//!
//! **State (guidelines §5).** The published macros are held per process in
//! an `ArcSwap`, replaced whole by [`install`] after each metadata version
//! load (the same hook as custom actions).

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;
use attome_core::EngineState;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::execute::{ActionOutcome, dispatch};

/// Most records one run takes.
pub const MAX_RECORDS: usize = 200;
/// The undo window when a macro sets none, in minutes.
pub const DEFAULT_UNDO_MINUTES: u64 = 10;

static CURRENT: LazyLock<ArcSwap<BTreeMap<String, Value>>> =
    LazyLock::new(|| ArcSwap::from_pointee(BTreeMap::new()));

/// Replaces the loaded macros with the published `definitions` (cooked
/// `macro` documents); the number loaded.
pub fn install(definitions: &[Value]) -> usize {
    let map: BTreeMap<String, Value> = definitions
        .iter()
        .filter_map(|d| Some((d.get("name")?.as_str()?.to_owned(), d.clone())))
        .collect();
    let loaded = map.len();
    CURRENT.store(Arc::new(map));
    loaded
}

/// The published macro named `name`.
pub fn get(name: &str) -> Option<Value> {
    CURRENT.load().get(name).cloned()
}

/// `value` with every `{{entity}}` and `{{record_id}}` in its strings
/// replaced. Pure.
pub fn fill(value: &Value, entity: &str, record_id: Uuid) -> Value {
    match value {
        Value::String(s) => Value::String(
            s.replace("{{entity}}", entity)
                .replace("{{record_id}}", &record_id.to_string()),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| fill(v, entity, record_id)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), fill(v, entity, record_id)))
                .collect::<Map<String, Value>>(),
        ),
        other => other.clone(),
    }
}

/// A macro's steps as `(action, args)`. Pure.
pub fn steps(definition: &Value) -> Vec<(String, Value)> {
    definition
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(|s| {
                    Some((
                        s.get("action")?.as_str()?.trim().to_owned(),
                        s.get("args").cloned().unwrap_or_else(|| json!({})),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Records to run a macro on.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MacroRecords {
    pub record_ids: Vec<Uuid>,
}

/// One step for one record.
#[derive(Debug, Serialize, ToSchema)]
pub struct StepPlan {
    pub action: String,
    /// `Read`, `Reversible` or `Consequential`; absent for an unknown action.
    pub risk: Option<String>,
    #[schema(value_type = Object)]
    pub args: Value,
    pub problems: Vec<String>,
}

/// One record's plan.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordPlan {
    pub record_id: Uuid,
    pub steps: Vec<StepPlan>,
}

/// What running a macro would do.
#[derive(Debug, Serialize, ToSchema)]
pub struct MacroPreview {
    pub name: String,
    pub entity: String,
    pub undo_minutes: u64,
    pub records: Vec<RecordPlan>,
}

/// One record's outcomes, step by step.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordRun {
    pub record_id: Uuid,
    #[schema(value_type = Vec<Object>)]
    pub outcomes: Vec<Value>,
    /// Why the record stopped early, when it did.
    pub error: Option<String>,
}

/// What a run did.
#[derive(Debug, Serialize, ToSchema)]
pub struct MacroRun {
    pub name: String,
    pub undo_minutes: u64,
    pub records: Vec<RecordRun>,
}

fn load(name: &str, records: &[Uuid]) -> Result<(Value, String, u64), AppError> {
    let definition = get(name).ok_or(AppError::NotFound)?;
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err(AppError::Validation(format!(
            "record_ids names 1 to {MAX_RECORDS} records"
        )));
    }
    let entity = definition["entity"].as_str().unwrap_or_default().to_owned();
    let undo = definition
        .get("undo_minutes")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_UNDO_MINUTES);
    Ok((definition, entity, undo))
}

/// What running `name` on `records` would do; runs nothing.
pub fn preview(name: &str, records: &[Uuid]) -> Result<MacroPreview, AppError> {
    let (definition, entity, undo_minutes) = load(name, records)?;
    let registry = &*crate::engine::REGISTRY;
    let plans = records
        .iter()
        .map(|record| RecordPlan {
            record_id: *record,
            steps: steps(&definition)
                .into_iter()
                .map(|(action, args)| {
                    let args = fill(&args, &entity, *record);
                    match registry.resolve(&action) {
                        Some(d) => StepPlan {
                            problems: crate::custom_action::validate_args(d.input_schema, &args)
                                .into_iter()
                                .map(|e| e.message)
                                .collect(),
                            risk: Some(format!("{:?}", d.risk)),
                            action,
                            args,
                        },
                        None => StepPlan {
                            problems: vec![format!("{action} is not a registered action")],
                            risk: None,
                            action,
                            args,
                        },
                    }
                })
                .collect(),
        })
        .collect();
    Ok(MacroPreview {
        name: name.to_owned(),
        entity,
        undo_minutes,
        records: plans,
    })
}

/// Runs `name` on `records` as the caller.
pub async fn run(
    state: &EngineState,
    ctx: &ActionContext,
    name: &str,
    records: &[Uuid],
) -> Result<MacroRun, AppError> {
    let (definition, entity, undo_minutes) = load(name, records)?;
    let registry = &*crate::engine::REGISTRY;
    let executors = &*crate::engine::EXECUTORS;
    let planned = steps(&definition);
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let mut outcomes = Vec::new();
        let mut error = None;
        for (action, args) in &planned {
            let args = fill(args, &entity, *record);
            let Some(descriptor) = registry.resolve(action) else {
                error = Some(format!("{action} is not a registered action"));
                break;
            };
            let mut step_ctx = ctx.clone();
            if undo_minutes > 0 {
                let seconds = u32::try_from(undo_minutes.saturating_mul(60)).unwrap_or(u32::MAX);
                step_ctx = step_ctx.with_undo_window(seconds);
            }
            let inputs = crate::engine::gate_inputs(state, descriptor.module);
            match dispatch(
                state, registry, executors, action, &step_ctx, &inputs, &args,
            )
            .await
            {
                Ok(outcome) => {
                    let waiting = matches!(
                        outcome,
                        ActionOutcome::ConfirmationRequired { .. }
                            | ActionOutcome::ApprovalRequired { .. }
                    );
                    outcomes.push(serde_json::to_value(&outcome).unwrap_or(Value::Null));
                    if waiting {
                        // A later step must not run before this one is decided.
                        error = Some(format!("{action} waits for a person's decision"));
                        break;
                    }
                }
                Err(e) => {
                    error = Some(format!("{action}: {e}"));
                    break;
                }
            }
        }
        out.push(RecordRun {
            record_id: *record,
            outcomes,
            error,
        });
    }
    Ok(MacroRun {
        name: name.to_owned(),
        undo_minutes,
        records: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_fills_entity_and_record() {
        let id = Uuid::now_v7();
        let filled = fill(
            &json!({ "entity": "{{entity}}", "record_id": "{{record_id}}",
                     "data": { "note": "closed {{record_id}}" }, "n": 1 }),
            "ticket",
            id,
        );
        assert_eq!(filled["entity"], "ticket");
        assert_eq!(filled["record_id"], id.to_string());
        assert_eq!(filled["data"]["note"], format!("closed {id}"));
        assert_eq!(filled["n"], 1);
    }

    #[test]
    fn macro_steps_keep_their_order() {
        let def = json!({ "steps": [
            { "action": "record.update", "args": { "a": 1 } },
            { "action": "record.transition" }
        ] });
        let s = steps(&def);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].0, "record.update");
        assert_eq!(s[1].1, json!({}));
    }
}
