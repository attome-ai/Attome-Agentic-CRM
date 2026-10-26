//! Custom actions (roadmap AE1-T1): published `custom_action` metadata as a
//! second source of the action registry, beside the built-in actions.
//!
//! **Same descriptor, same gate.** Each published definition becomes an
//! [`ActionDescriptor`] with the risk tier, retry class and required
//! privileges it declares, under `MODULE_AI`. `ActionRegistry::resolve`,
//! `all` and `visible_to` and `Executors::get` consult this set after the
//! built-in one, so a custom action is gated, approved, confirmed and
//! audited exactly like a built-in action of its tier. Its id always starts
//! with `custom.` (the kind makes it), so it can never take or shadow a
//! built-in id; a definition that would is skipped.
//!
//! **What it runs.** A `flow` implementation starts that published workflow
//! through the same seam as `workflow.start` (`EngineState::workflow_starter`)
//! as the caller, with the action's arguments as the flow's context. An
//! `extension` implementation is refused as unavailable until extensions can
//! run.
//!
//! **State (guidelines §5).** Source of truth: the cooked metadata version.
//! The set is held per process in an `ArcSwap` and replaced whole by
//! [`install`], which the metadata layer calls after every version load on
//! this node (a publish here, or following one made on another node), so it
//! never outlives the version it came from. Descriptor fields are
//! `&'static`, so the strings of each distinct definition are interned once
//! and kept for the life of the process: republishing an unchanged
//! definition reuses them, and only an edit adds a new copy (bounded by the
//! number of edits; a warning is logged past [`INTERN_WARN`] entries).

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};

use arc_swap::ArcSwap;
use attome_core::{EngineState, WorkflowStartRequest};
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// The prefix every custom action id carries (the kind's).
pub const ID_PREFIX: &str = "custom.";
/// Interned entries past which a warning is logged.
pub const INTERN_WARN: usize = 10_000;

/// What a custom action runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Implementation {
    Flow(String),
    Extension(String),
}

/// One loaded custom action.
pub struct CustomAction {
    descriptor: &'static ActionDescriptor,
    implementation: Implementation,
}

impl std::fmt::Debug for CustomAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomAction")
            .field("id", &self.descriptor.id)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct CustomSet {
    by_id: BTreeMap<&'static str, &'static CustomAction>,
}

static CURRENT: LazyLock<ArcSwap<CustomSet>> =
    LazyLock::new(|| ArcSwap::from_pointee(CustomSet::default()));

/// Interned actions by their definition text, so an unchanged definition
/// reuses its descriptor.
static INTERNED: LazyLock<Mutex<HashMap<String, &'static CustomAction>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn risk_of(text: &str) -> Option<RiskTier> {
    match text {
        "read" => Some(RiskTier::Read),
        "reversible" => Some(RiskTier::Reversible),
        "consequential" => Some(RiskTier::Consequential),
        _ => None,
    }
}

fn retry_of(text: Option<&str>, risk: RiskTier) -> Option<RetryClass> {
    match text {
        Some("idempotent") => Some(RetryClass::Idempotent),
        Some("requires_key") => Some(RetryClass::RequiresKey),
        Some("never_retry") => Some(RetryClass::NeverRetry),
        // A read is safe to replay; anything that writes needs a key.
        None if risk == RiskTier::Read => Some(RetryClass::Idempotent),
        None => Some(RetryClass::RequiresKey),
        Some(_) => None,
    }
}

/// A cooked definition's parts.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub id: String,
    pub description: String,
    pub risk: RiskTier,
    pub retry: RetryClass,
    pub implementation: Implementation,
    pub privileges: Vec<String>,
    pub input_schema: String,
}

/// The parts of a cooked definition, or why it cannot be loaded. Pure.
pub fn parse(doc: &Value) -> Result<Parsed, String> {
    let id = doc
        .get("action_id")
        .and_then(Value::as_str)
        .filter(|id| id.starts_with(ID_PREFIX) && id.len() > ID_PREFIX.len())
        .ok_or("no custom.<name> action id")?
        .to_owned();
    let mut description = doc
        .get("description_en")
        .and_then(Value::as_str)
        .filter(|d| !d.trim().is_empty())
        .ok_or("no description_en")?
        .to_owned();
    if let Some(ar) = doc.get("description_ar").and_then(Value::as_str) {
        description = format!("{description} / {ar}");
    }
    let risk = doc
        .get("risk_tier")
        .and_then(Value::as_str)
        .and_then(risk_of)
        .ok_or("no valid risk_tier")?;
    let retry = retry_of(doc.get("retry_class").and_then(Value::as_str), risk)
        .ok_or("no valid retry_class")?;
    let implementation = {
        let kind = doc["implementation"]["kind"].as_str().unwrap_or_default();
        let target = doc["implementation"]["ref"]
            .as_str()
            .filter(|r| !r.trim().is_empty())
            .ok_or("no implementation ref")?
            .to_owned();
        match kind {
            "flow" => Implementation::Flow(target),
            "extension" => Implementation::Extension(target),
            _ => return Err("implementation kind is flow or extension".into()),
        }
    };
    let privileges: Vec<String> = doc
        .get("required_privileges")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let schema = doc
        .get("input_schema")
        .filter(|s| s.is_object())
        .ok_or("no input_schema")?
        .to_string();
    Ok(Parsed {
        id,
        description,
        risk,
        retry,
        implementation,
        privileges,
        input_schema: schema,
    })
}

fn intern(doc: &Value) -> Result<&'static CustomAction, String> {
    let key = doc.to_string();
    let mut interned = INTERNED
        .lock()
        .map_err(|_| "intern table poisoned".to_owned())?;
    if let Some(action) = interned.get(&key) {
        return Ok(action);
    }
    let Parsed {
        id,
        description,
        risk,
        retry,
        implementation,
        privileges,
        input_schema: schema,
    } = parse(doc)?;
    let privileges: &'static [&'static str] = Box::leak(
        privileges
            .into_iter()
            .map(leak)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let effect = if risk == RiskTier::Read {
        Effect::Read
    } else {
        Effect::Write
    };
    let descriptor: &'static ActionDescriptor = Box::leak(Box::new(
        ActionDescriptor::new(
            leak(id),
            leak(description),
            risk,
            effect,
            retry,
            MODULE_AI,
            privileges,
        )
        .input_schema(leak(schema)),
    ));
    let action: &'static CustomAction = Box::leak(Box::new(CustomAction {
        descriptor,
        implementation,
    }));
    interned.insert(key, action);
    if interned.len() > INTERN_WARN {
        tracing::warn!(
            entries = interned.len(),
            "custom action definitions interned past the warning mark; restart to reclaim"
        );
    }
    Ok(action)
}

/// Replaces the loaded custom actions with the published `definitions`
/// (cooked `custom_action` documents). Returns the number loaded.
pub fn install(definitions: &[Value]) -> usize {
    let by_id = build(definitions);
    let loaded = by_id.len();
    CURRENT.store(Arc::new(CustomSet { by_id }));
    loaded
}

/// The set `definitions` load to. A definition that cannot load, or whose
/// id a built-in action holds, is skipped with a warning.
fn build(definitions: &[Value]) -> BTreeMap<&'static str, &'static CustomAction> {
    let builtin = &*crate::engine::REGISTRY;
    let mut by_id: BTreeMap<&'static str, &'static CustomAction> = BTreeMap::new();
    for doc in definitions {
        match intern(doc) {
            Ok(action) => {
                let id = action.descriptor.id.as_str();
                if builtin.builtin(id).is_some() {
                    tracing::warn!(
                        action = id,
                        "custom action skipped: a built-in action has its id"
                    );
                    continue;
                }
                by_id.insert(id, action);
            }
            Err(why) => {
                tracing::warn!(name = ?doc.get("name"), why, "custom action not loaded");
            }
        }
    }
    by_id
}

/// The loaded custom action named `id`.
pub fn get(id: &str) -> Option<&'static CustomAction> {
    CURRENT.load().by_id.get(id).copied()
}

/// The loaded custom action descriptor named `id`.
pub fn descriptor(id: &str) -> Option<&'static ActionDescriptor> {
    get(id).map(|a| a.descriptor)
}

/// Every loaded custom action's descriptor, in id order.
pub fn descriptors() -> Vec<&'static ActionDescriptor> {
    CURRENT
        .load()
        .by_id
        .values()
        .map(|a| a.descriptor)
        .collect()
}

impl Action for CustomAction {
    fn id(&self) -> ActionId {
        self.descriptor.id
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let context = match args {
                Value::Object(map) => map.clone(),
                Value::Null => serde_json::Map::new(),
                _ => {
                    return Err(AppError::Validation(
                        "a custom action's arguments are a JSON object".into(),
                    ));
                }
            };
            match &self.implementation {
                Implementation::Flow(flow) => {
                    let Some(starter) = state.workflow_starter.as_ref() else {
                        return Err(AppError::NotFound);
                    };
                    let instance_id = starter
                        .start(
                            state,
                            WorkflowStartRequest {
                                definition_logicalname: flow.clone(),
                                started_by: ctx.security.user_id,
                                correlation_entity_id: None,
                                context: Value::Object(context),
                            },
                        )
                        .await?;
                    Ok(ActionResult::plain(json!({
                        "action": self.descriptor.id.as_str(),
                        "flow": flow,
                        "instance_id": instance_id,
                    })))
                }
                Implementation::Extension(_) => Err(AppError::FeatureUnavailable),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn survey() -> Value {
        json!({
            "name": "site_survey",
            "action_id": "custom.site_survey",
            "description_en": "Book a site survey",
            "description_ar": "حجز معاينة",
            "input_schema": { "type": "object", "properties": { "lead_id": { "type": "string" } } },
            "risk_tier": "consequential",
            "implementation": { "kind": "flow", "ref": "site_survey_booking" },
            "required_privileges": ["lead.update"]
        })
    }

    #[test]
    fn custom_action_published_appears_in_the_registry() {
        // The set a version loads to (the global one is left alone, so tests
        // that list every registered action never see this one).
        let set = build(&[survey()]);
        let action = set.get("custom.site_survey").expect("loaded");
        let descriptor = action.descriptor;
        assert_eq!(descriptor.risk, RiskTier::Consequential);
        assert_eq!(descriptor.retry, RetryClass::RequiresKey);
        assert_eq!(descriptor.required_privileges, &["lead.update"]);
        assert_eq!(
            action.implementation,
            Implementation::Flow("site_survey_booking".into())
        );
        // The same definition again reuses the descriptor.
        let again = build(&[survey()]);
        assert!(std::ptr::eq(
            descriptor,
            again.get("custom.site_survey").expect("loaded").descriptor
        ));
        // A version without it loads nothing.
        assert!(build(&[]).is_empty());
    }

    #[test]
    fn custom_action_bad_definitions_are_refused() {
        let mut bad = survey();
        bad["action_id"] = json!("record.get");
        assert!(parse(&bad).is_err());
        let mut bad = survey();
        bad["risk_tier"] = json!("dangerous");
        assert!(parse(&bad).is_err());
    }
}
