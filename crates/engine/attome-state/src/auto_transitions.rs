//! M8-T3: automatic transitions.
//!
//! A transition with an `auto_condition` (an attome-rules expression over
//! the record's fields, such as `due_date < today()`) happens by itself when
//! a record sits in its `from_state` and the condition holds. Two passes look
//! for them:
//!
//! - [`sweep`], every minute, reads the change feed (consumer [`CONSUMER`])
//!   and checks each record that was created, changed or restored, so a
//!   condition on the record's own fields fires soon after the write;
//! - [`daily`] checks every record in the `from_state` of an automatic
//!   transition, for conditions that become true with time alone (an invoice
//!   whose due date passed). At most [`DAILY_LIMIT`] records per transition
//!   per run, oldest id first; the rest wait for the next run.
//!
//! The first automatic transition out of the record's state (in display
//! order) whose condition holds is applied through the ordinary update path
//! as the policy actor (with an administrator's privileges), so its guard,
//! approval plan, rules, change feed and audit apply exactly as on any
//! write. A write refused by a guard or a
//! rule is logged and left for the next pass. A condition that does not
//! compile is not met (and is refused when the transition is saved).
//!
//! The pass that sees the automatic write itself (the policy actor changed
//! only the state field) does not check that record again, so two automatic
//! transitions whose conditions both hold do not move a record back and
//! forth on every pass; the daily run moves it on at most once a day.

use std::sync::Arc;

use attome_core::change_feed::{self, ChangeOperation};
use attome_core::state_registry::{StateModelRegistry, TransitionDef};
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_records::entity_crud::{admin_security_context, update_record_for_outcome};
use attome_records::entity_mutation::MutationMode;
use attome_types::AppError;
use chrono::Utc;
use serde_json::{Map, Value};
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-state/auto-transitions";
/// The registered job that runs [`sweep`] every minute.
pub const SWEEP_JOB: &str = "state_auto_transitions";
/// The registered job that runs [`daily`].
pub const DAILY_JOB: &str = "state_auto_transitions_daily";
/// Events read per sweep.
const BATCH: i64 = 500;
/// Records read per page of the daily run.
const PAGE: i64 = 500;
/// The most records the daily run checks per transition.
pub const DAILY_LIMIT: i64 = 50_000;

/// `None` when `source` compiles to a yes-or-no over the entity's fields,
/// else why not.
pub fn check_condition(attrs: &[AttrInfo], source: &str) -> Option<String> {
    let schema = attome_records::rule_engine::schema_for_entity(attrs);
    match attome_rules::compile(source, &schema) {
        Ok(compiled) => attome_records::rule_engine::check_boolean_result_type(&compiled)
            .err()
            .map(|e| e.to_string()),
        Err(e) => Some(e.to_string()),
    }
}

/// True when `source` evaluates to true over the record.
fn holds(source: &str, attrs: &[AttrInfo], record: &Map<String, Value>) -> bool {
    let schema = attome_records::rule_engine::schema_for_entity(attrs);
    let ctx = attome_records::rule_engine::context_for_record(Utc::now(), attrs, record);
    match attome_rules::compile(source, &schema) {
        Ok(compiled) => compiled
            .eval(&ctx)
            .is_ok_and(|v| matches!(v, attome_rules::Value::Bool(true))),
        Err(e) => {
            tracing::warn!(error = %e, "automatic transition condition does not compile; not met");
            false
        }
    }
}

/// The automatic transitions out of `current`, in display order. Pure.
pub fn automatic_from<'a>(
    transitions: &'a [TransitionDef],
    current: &str,
) -> Vec<&'a TransitionDef> {
    transitions
        .iter()
        .filter(|t| t.from_state == current)
        .filter(|t| {
            t.auto_condition
                .as_deref()
                .is_some_and(|c| !c.trim().is_empty())
        })
        .collect()
}

/// The first automatic transition out of `current` whose condition holds.
pub fn due<'a>(
    transitions: &'a [TransitionDef],
    current: &str,
    attrs: &[AttrInfo],
    record: &Map<String, Value>,
) -> Option<&'a TransitionDef> {
    automatic_from(transitions, current).into_iter().find(|t| {
        t.auto_condition
            .as_deref()
            .is_some_and(|c| holds(c, attrs, record))
    })
}

/// Whether the entity has an active model with at least one automatic
/// transition; its state field when it has.
fn automatic_model<'a>(
    registry: &'a StateModelRegistry,
    entity: &str,
) -> Option<(&'a str, &'a [TransitionDef])> {
    let entry = registry.get(entity)?;
    let model = entry.model.as_ref().filter(|m| m.is_active)?;
    entry
        .transitions
        .iter()
        .any(|t| t.auto_condition.is_some())
        .then_some((model.state_field.as_str(), entry.transitions.as_slice()))
}

async fn record_of(
    state: &EngineState,
    entity: &str,
    id: Uuid,
) -> Result<Option<Map<String, Value>>, AppError> {
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id = $1 AND is_active = true",
        quote_ident(entity)
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|v| match v {
        Value::Object(map) => Some(map),
        _ => None,
    }))
}

/// Checks one record and applies its due automatic transition; whether one
/// was applied. `skip_own` skips a record whose last write was an automatic
/// transition (see the module doc).
async fn check_record(
    state: &EngineState,
    registry: &StateModelRegistry,
    entity: &str,
    id: Uuid,
    skip_own: bool,
) -> Result<bool, AppError> {
    let Some((state_field, transitions)) = automatic_model(registry, entity) else {
        return Ok(false);
    };
    let Some(record) = record_of(state, entity, id).await? else {
        return Ok(false);
    };
    let actor = attome_approval::POLICY_ACTOR_ID;
    if skip_own
        && record
            .get("modified_by")
            .and_then(Value::as_str)
            .is_some_and(|m| m == actor.to_string())
    {
        return Ok(false);
    }
    let Some(current) = record.get(state_field).and_then(Value::as_str) else {
        return Ok(false);
    };
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .unwrap_or_default();
    let Some(transition) = due(transitions, current, &attrs, &record) else {
        return Ok(false);
    };
    let Some(row_version) = record.get("row_version").and_then(Value::as_i64) else {
        return Ok(false);
    };
    let mut body = Map::new();
    body.insert(
        state_field.to_owned(),
        Value::String(transition.to_state.clone()),
    );
    let outcome = update_record_for_outcome(
        state,
        &admin_security_context(actor),
        actor,
        entity,
        id,
        row_version,
        Value::Object(body),
        Some(format!(
            "automatic transition '{}': its condition is met",
            transition.name
        )),
        MutationMode::Strict,
    )
    .await;
    match outcome {
        Ok(_) => Ok(true),
        // Someone wrote the record in between; the next pass sees it again.
        Err(AppError::VersionConflict) | Err(AppError::NotFound) => Ok(false),
        Err(e @ (AppError::Validation(_) | AppError::TransitionNotAllowed(_))) => {
            tracing::info!(
                entity,
                record = %id,
                transition = %transition.name,
                reason = %e,
                "automatic transition refused; left for the next pass"
            );
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Checks the records the change feed shows written since the last sweep;
/// how many moved.
pub async fn sweep(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let registry: Arc<StateModelRegistry> = Arc::clone(&*state.state_models.load());
    let mut moved = 0;
    for event in &events {
        if !matches!(
            event.operation(),
            Some(ChangeOperation::Create | ChangeOperation::Update | ChangeOperation::Restore)
        ) {
            continue;
        }
        let Some((state_field, _)) = automatic_model(&registry, &event.entity_logicalname) else {
            continue;
        };
        // Only the state field changed: possibly an automatic transition's own write.
        let state_only =
            event.changed_attributes.len() == 1 && event.changed_attributes[0] == state_field;
        if check_record(
            state,
            &registry,
            &event.entity_logicalname,
            event.record_id,
            state_only,
        )
        .await?
        {
            moved += 1;
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(moved)
}

/// Checks every record in the `from_state` of an automatic transition; how
/// many moved.
pub async fn daily(state: &EngineState) -> Result<u64, AppError> {
    let registry: Arc<StateModelRegistry> = Arc::clone(&*state.state_models.load());
    let mut moved = 0;
    for entity in registry.entities() {
        let Some((state_field, transitions)) = automatic_model(&registry, entity) else {
            continue;
        };
        let mut from_states: Vec<&str> = transitions
            .iter()
            .filter(|t| t.auto_condition.is_some())
            .map(|t| t.from_state.as_str())
            .collect();
        from_states.sort_unstable();
        from_states.dedup();
        for from in from_states {
            let mut after = Uuid::nil();
            let mut read = 0;
            while read < DAILY_LIMIT {
                let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
                    "SELECT id FROM {} WHERE {}::text = $1 AND is_active = true AND id > $2 \
                      ORDER BY id LIMIT $3",
                    quote_ident(entity),
                    quote_ident(state_field)
                ))
                .bind(from)
                .bind(after)
                .bind(PAGE)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                let Some(last) = ids.last().copied() else {
                    break;
                };
                read += ids.len() as i64;
                for id in ids {
                    if check_record(state, &registry, entity, id, false).await? {
                        moved += 1;
                    }
                }
                after = last;
            }
        }
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(from: &str, to: &str, order: i32, condition: Option<&str>) -> TransitionDef {
        TransitionDef {
            id: Uuid::now_v7(),
            model_ref: Uuid::nil(),
            from_state: from.into(),
            to_state: to.into(),
            name: format!("{from}->{to}"),
            required_privilege: None,
            guard_expression: None,
            entry_actions: vec![],
            exit_actions: vec![],
            display_order: order,
            row_version: 0,
            approval_plan: None,
            pending_state: None,
            on_reject_state: None,
            auto_condition: condition.map(str::to_owned),
        }
    }

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: attome_core::OnTargetDelete::default(),
            data_classification: attome_core::DataClassification::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    #[test]
    fn auto_transitions_only_automatic_edges_from_the_state() {
        let ts = vec![
            transition("sent", "paid", 0, None),
            transition("sent", "overdue", 1, Some("amount > 0")),
            transition("draft", "sent", 0, Some("amount > 0")),
            transition("sent", "void", 2, Some("  ")),
        ];
        let found: Vec<&str> = automatic_from(&ts, "sent")
            .iter()
            .map(|t| t.to_state.as_str())
            .collect();
        assert_eq!(found, vec!["overdue"]);
        assert!(automatic_from(&ts, "paid").is_empty());
    }

    #[test]
    fn auto_transitions_first_holding_condition_wins() {
        let attrs = vec![attr("amount", 1)];
        let ts = vec![
            transition("sent", "written_off", 0, Some("amount > 1000")),
            transition("sent", "overdue", 1, Some("amount > 0")),
        ];
        let mut record = Map::new();
        record.insert("amount".into(), serde_json::json!(50));
        assert_eq!(
            due(&ts, "sent", &attrs, &record).map(|t| t.to_state.as_str()),
            Some("overdue")
        );
        record.insert("amount".into(), serde_json::json!(5000));
        assert_eq!(
            due(&ts, "sent", &attrs, &record).map(|t| t.to_state.as_str()),
            Some("written_off")
        );
        record.insert("amount".into(), serde_json::json!(0));
        assert!(due(&ts, "sent", &attrs, &record).is_none());
        assert!(due(&ts, "draft", &attrs, &record).is_none());
    }

    #[test]
    fn auto_transitions_condition_must_compile() {
        let attrs = vec![attr("amount", 1)];
        assert_eq!(check_condition(&attrs, "amount > 0"), None);
        assert!(check_condition(&attrs, "amount >").is_some());
        assert!(check_condition(&attrs, "no_such_field > 0").is_some());
    }
}
