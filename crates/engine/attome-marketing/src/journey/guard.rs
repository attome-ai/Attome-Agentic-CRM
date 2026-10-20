//! The journey kind guard (roadmap E8-T4): before every node of a
//! journey's run, the person's record is checked against the journey's
//! `exit_condition` and `goal_condition` (attome-rules expressions over the
//! contact or lead). The exit condition ends the run and the enrolment
//! (`exited`). The goal condition records `goal_reached_at` once, and ends
//! the run (`completed`) only when the journey's `goal_exits` is set.
//!
//! A run with no active enrolment (started some other way) and a journey
//! with neither condition pass untouched. A condition that does not compile
//! is not met, and says so in the log; the run goes on rather than ending
//! everyone's journey on an authoring mistake.

use attome_core::EngineState;
use attome_core::workflow_step::{GuardFuture, WorkflowKindGuard};
use attome_types::AppError;
use chrono::Utc;
use serde_json::{Map, Value};
use uuid::Uuid;

/// Registered for definition kind `journey`.
#[derive(Debug)]
pub struct JourneyGuard;

impl WorkflowKindGuard for JourneyGuard {
    fn kind(&self) -> &'static str {
        "journey"
    }

    fn before_node<'a>(
        &'a self,
        state: &'a EngineState,
        instance_id: Uuid,
        _correlation_entity_id: Option<Uuid>,
        _node_id: &'a str,
    ) -> GuardFuture<'a> {
        Box::pin(check(state, instance_id))
    }
}

type EnrolmentRow = (
    Uuid,
    Uuid,
    String,
    Option<chrono::DateTime<Utc>>,
    Option<String>,
    Option<String>,
    Option<bool>,
);

/// The guard's work; `Some(reason)` ends the run.
pub async fn check(state: &EngineState, instance_id: Uuid) -> Result<Option<String>, AppError> {
    let row: Option<EnrolmentRow> = sqlx::query_as(
        "SELECT e.id, e.person_id, e.person_entity, e.goal_reached_at, \
                j.exit_condition, j.goal_condition, j.goal_exits \
           FROM marketing_journey_enrolment e \
           JOIN workflow_definition d ON d.id = e.definition_id \
           JOIN marketing_journey j ON j.workflow_definition_logicalname = d.logicalname \
                                   AND j.is_active IS NOT FALSE \
          WHERE e.instance_id = $1 AND e.status = 'active'",
    )
    .bind(instance_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((enrolment, person, entity, goal_reached, exit_condition, goal_condition, goal_exits)) =
        row
    else {
        return Ok(None);
    };
    let exit_condition = exit_condition.filter(|c| !c.trim().is_empty());
    let goal_condition = goal_condition.filter(|c| !c.trim().is_empty());
    let goal_pending = goal_reached.is_none() || goal_exits == Some(true);
    if exit_condition.is_none() && (goal_condition.is_none() || !goal_pending) {
        return Ok(None);
    }
    let Some(record) = person_record(state, &entity, person).await? else {
        return Ok(None);
    };
    let attrs = state
        .entities
        .load()
        .get(entity.as_str())
        .map(|m| m.attrs.clone())
        .unwrap_or_default();

    if let Some(source) = &exit_condition
        && holds(source, &attrs, &record, enrolment)
    {
        end(state, enrolment, "exited", "exit_condition").await?;
        return Ok(Some("the journey's exit condition is met".into()));
    }
    if let Some(source) = &goal_condition
        && goal_pending
        && holds(source, &attrs, &record, enrolment)
    {
        if goal_reached.is_none() {
            sqlx::query(
                "UPDATE marketing_journey_enrolment SET goal_reached_at = now() \
                  WHERE id = $1 AND goal_reached_at IS NULL",
            )
            .bind(enrolment)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        }
        if goal_exits == Some(true) {
            end(state, enrolment, "completed", "goal").await?;
            return Ok(Some("the journey's goal is reached".into()));
        }
    }
    Ok(None)
}

/// True when `source` evaluates to true over the record. Pure apart from
/// the log line for a condition that does not compile.
fn holds(
    source: &str,
    attrs: &[attome_core::AttrInfo],
    record: &Map<String, Value>,
    enrolment: Uuid,
) -> bool {
    let schema = attome_records::rule_engine::schema_for_entity(attrs);
    let ctx = attome_records::rule_engine::context_for_record(Utc::now(), attrs, record);
    match attome_rules::compile(source, &schema) {
        Ok(compiled) => compiled
            .eval(&ctx)
            .is_ok_and(|v| matches!(v, attome_rules::Value::Bool(true))),
        Err(e) => {
            tracing::warn!(%enrolment, error = %e, "journey condition does not compile; treated as not met");
            false
        }
    }
}

/// The person's row as a JSON object, read by the engine (no user is
/// asking). Only contacts and leads are enrolled.
async fn person_record(
    state: &EngineState,
    entity: &str,
    person: Uuid,
) -> Result<Option<Map<String, Value>>, AppError> {
    if !matches!(entity, "contact" | "lead") {
        return Ok(None);
    }
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id = $1",
        attome_core::quote_ident(entity)
    ))
    .bind(person)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|v| match v {
        Value::Object(map) => Some(map),
        _ => None,
    }))
}

async fn end(
    state: &EngineState,
    enrolment: Uuid,
    status: &str,
    reason: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE marketing_journey_enrolment SET status = $2, ended_at = now(), end_reason = $3 \
          WHERE id = $1 AND status = 'active'",
    )
    .bind(enrolment)
    .bind(status)
    .bind(reason)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}
