//! Y7-T5: raising a builder-defined business event (the `business_event`
//! metadata kind, `attome_model::kinds::business_event`).
//!
//! [`raise_event`] checks the payload against the published definition and
//! writes one change-feed row in the caller's transaction: the definition's
//! entity and the record the event is about, operation `update` (the same
//! as the platform's own named events, such as `billing.invoice_issued`),
//! `event_name` the definition's name and `after` the payload. It commits or
//! rolls back with the write that caused it, and flows and integrations read
//! it from the feed like any other event.
//!
//! [`RaiseEventStep`] is the flow step (`events.raise`) that raises one about
//! the run's record.

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, ChangePayload};
use attome_core::workflow_step::{StepFuture, StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_model::kinds::business_event::{BUSINESS_EVENT, check_payload};
use attome_modules::{MODULE_WORKFLOW, ModuleId};
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// Every published definition, from the cooked registry (Y7-T7's AsyncAPI
/// document lists them).
pub fn definitions() -> Vec<Value> {
    let cooked = crate::model_admin::cooked();
    let snapshot = cooked.snapshot();
    let prefix = format!("{}:", BUSINESS_EVENT.0);
    snapshot
        .manifest
        .artefacts
        .keys()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| cooked.get::<Value>(BUSINESS_EVENT.0, key))
        .map(|doc| (*doc).clone())
        .collect()
}

/// The published definition named `name`, from the cooked registry.
pub fn definition(name: &str) -> Option<Value> {
    let cooked = crate::model_admin::cooked();
    let snapshot = cooked.snapshot();
    let prefix = format!("{}:", BUSINESS_EVENT.0);
    snapshot
        .manifest
        .artefacts
        .keys()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| cooked.get::<Value>(BUSINESS_EVENT.0, key))
        .find(|doc| doc["name"].as_str() == Some(name))
        .map(|doc| (*doc).clone())
}

/// Raises the business event `name` about `record_id` in the caller's
/// transaction. Refused (422) when no definition by that name is published
/// or the payload does not fit it; every problem is named at once.
pub async fn raise_event(
    conn: &mut sqlx::PgConnection,
    name: &str,
    record_id: Uuid,
    payload: &Value,
) -> Result<(), AppError> {
    let definition = definition(name).ok_or_else(|| {
        AppError::Validation(format!("no published business event is named `{name}`"))
    })?;
    check_payload(&definition, payload).map_err(|problems| {
        AppError::Validation(format!("event `{name}`: {}", problems.join("; ")))
    })?;
    let entity = definition["entity"].as_str().unwrap_or_default();
    let changed = payload
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    attome_core::change_feed::emit_with(
        conn,
        entity,
        record_id,
        ChangeOperation::Update,
        Some(name),
        &ChangePayload {
            changed_attributes: changed,
            before: None,
            after: Some(payload.clone()),
            row_version: None,
        },
    )
    .await
}

/// The step's configuration: `{"event": "<name>", "payload": {…}}`. The
/// literal payload is merged with an object wired to the step's `payload`
/// input, the wired values winning.
fn event_name(config: &Value) -> Option<&str> {
    config
        .get("event")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn step_payload(config: &Value, input: &Value) -> Value {
    let mut payload = config
        .get("payload")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(Map::new);
    if let Some(wired) = input.get("payload").and_then(Value::as_object) {
        for (key, value) in wired {
            payload.insert(key.clone(), value.clone());
        }
    }
    Value::Object(payload)
}

/// Y7-T5: the `events.raise` flow step — raises a business event about the
/// run's record, in its own short transaction. A replay is guarded by the
/// workflow engine's fired-marker, like every module step.
#[derive(Debug, Clone, Copy, Default)]
pub struct RaiseEventStep;

impl WorkflowStepHandler for RaiseEventStep {
    fn key(&self) -> &'static str {
        "events.raise"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_WORKFLOW
    }

    fn validate_config(&self, config: &Value) -> Result<(), String> {
        let name = event_name(config).ok_or("event names a business event")?;
        if config.get("payload").is_some_and(|p| !p.is_object()) {
            return Err("payload is an object".into());
        }
        if definition(name).is_none() {
            return Err(format!("no published business event is named `{name}`"));
        }
        Ok(())
    }

    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let name = event_name(&inv.config)
                .ok_or_else(|| AppError::Validation("event names a business event".into()))?
                .to_owned();
            let Some(record_id) = inv.correlation_entity_id else {
                return Ok(StepOutcome::Blocked {
                    reason: "the run has no record to raise the event about".into(),
                    continue_after: true,
                });
            };
            let payload = step_payload(&inv.config, &inv.input);
            if inv.simulate {
                let definition = definition(&name).ok_or_else(|| {
                    AppError::Validation(format!("no published business event is named `{name}`"))
                })?;
                return Ok(StepOutcome::Done(json!({
                    "would": "raise event",
                    "event": name,
                    "record_id": record_id,
                    "problems": check_payload(&definition, &payload).err().unwrap_or_default(),
                })));
            }
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            raise_event(&mut tx, &name, record_id, &payload).await?;
            tx.commit().await.map_err(AppError::internal)?;
            Ok(StepOutcome::Done(json!({
                "event": name,
                "record_id": record_id,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wired_values_win_over_the_literal_payload() {
        let config =
            json!({"event": "order.shipped", "payload": {"carrier": "DHL", "weight_kg": 1}});
        let input = json!({"payload": {"carrier": "Aramex"}});
        assert_eq!(
            step_payload(&config, &input),
            json!({"carrier": "Aramex", "weight_kg": 1})
        );
        assert_eq!(step_payload(&json!({}), &json!({})), json!({}));
    }

    #[test]
    fn a_step_must_name_an_event() {
        let step = RaiseEventStep;
        assert!(step.validate_config(&json!({})).is_err());
        assert!(
            step.validate_config(&json!({"event": "x", "payload": [1]}))
                .is_err()
        );
        // Nothing is published in a unit test.
        assert!(step.validate_config(&json!({"event": "x"})).is_err());
    }
}
