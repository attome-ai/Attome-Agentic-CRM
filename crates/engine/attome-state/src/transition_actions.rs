//! M8-T1: a transition's exit and entry actions, run after it commits.
//!
//! A transition's `exit_actions` and `entry_actions` name actions (AE1:
//! built-in ids or published `custom.<name>` actions). [`sweep`] reads the
//! change feed after the writes committed (its own cursor, [`CONSUMER`]),
//! so it sees every transition, through `/transition` or an ordinary update
//! of the state field. For an update whose changed attributes include the
//! entity's state field, it reads the before and after state from the
//! outbox row, finds the configured transition and, when it has actions,
//! queues one [`JOB`] for the change (dedup key `transition-actions:{event}`,
//! so a re-read never queues twice): exit actions first, then entry actions.
//!
//! The job (in the composition root, which can reach the AI engine) runs
//! each action through the action gate with the arguments
//! `{entity, record_id, from_state, to_state}`, as the person who made the
//! change (the record's `modified_by` while it is still at the change's row
//! version, else its owner), with the idempotency key
//! `transition:{event}:{index}`, so a retried job never runs an action
//! twice. A failure fails the job, which retries and then lands in the dead
//! letters (M5).

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-state/transition-actions";
/// The registered job that runs one change's actions.
pub const JOB: &str = "state_transition_actions";
/// Events read per run.
pub const BATCH: i64 = 500;

/// One change's actions, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionActions {
    /// The change event the actions answer.
    pub event_id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub from_state: String,
    pub to_state: String,
    /// Exit actions, then entry actions.
    pub actions: Vec<String>,
    /// Whom they run as.
    pub actor: Option<Uuid>,
}

/// The actions a change from `from` to `to` runs: the matching transition's
/// exit actions, then its entry actions. Pure.
pub fn actions_for(
    transitions: &[attome_core::state_registry::TransitionDef],
    from: &str,
    to: &str,
) -> Vec<String> {
    transitions
        .iter()
        .find(|t| t.from_state == from && t.to_state == to)
        .map(|t| {
            t.exit_actions
                .iter()
                .chain(t.entry_actions.iter())
                .map(|a| a.trim().to_owned())
                .filter(|a| !a.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Who made the change: the record's last writer while it is still at the
/// change's version, else its owner.
async fn actor_of(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    row_version: Option<i64>,
) -> Result<Option<Uuid>, AppError> {
    let row: Option<(Option<Uuid>, Option<Uuid>, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT modified_by, owner_ref, row_version FROM {table} WHERE id = $1",
        table = attome_core::quote_ident(entity)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|(modified_by, owner, version)| {
        if row_version.is_some() && version == row_version {
            modified_by.or(owner)
        } else {
            owner.or(modified_by)
        }
    }))
}

/// Queues the actions of the transitions committed since the last run; how
/// many changes were queued.
pub async fn sweep(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let registry = state.state_models.load();
    let mut queued = 0;
    for event in &events {
        if event.operation() != Some(ChangeOperation::Update) {
            continue;
        }
        let Some(entry) = registry.get(&event.entity_logicalname) else {
            continue;
        };
        let Some(model) = entry.model.as_ref().filter(|m| m.is_active) else {
            continue;
        };
        if !event.changed_attributes.contains(&model.state_field) {
            continue;
        }
        let row: Option<(Option<String>, Option<String>, Option<i64>)> = sqlx::query_as(
            "SELECT before ->> $2, after ->> $2, row_version FROM entity_change_event \
              WHERE id = $1",
        )
        .bind(event.id)
        .bind(&model.state_field)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some((Some(from), Some(to), row_version)) = row else {
            continue;
        };
        let actions = actions_for(&entry.transitions, &from, &to);
        if actions.is_empty() {
            continue;
        }
        let payload = TransitionActions {
            event_id: event.id,
            entity: event.entity_logicalname.clone(),
            record_id: event.record_id,
            from_state: from,
            to_state: to,
            actions,
            actor: actor_of(
                state,
                &event.entity_logicalname,
                event.record_id,
                row_version,
            )
            .await?,
        };
        let job = attome_core::jobs::JOB_TYPES
            .job(JOB, &payload)
            .map_err(AppError::internal)?;
        if attome_jobs::enqueue_dedup(
            &state.base.db,
            attome_core::jobs::EngineJob::Registered(job),
            &format!("transition-actions:{}", event.id),
        )
        .await
        .map_err(AppError::internal)?
        {
            queued += 1;
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(queued)
}

/// The idempotency key of a change's `index`-th action.
pub fn action_key(event_id: Uuid, index: usize) -> String {
    format!("transition:{event_id}:{index}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::state_registry::TransitionDef;

    fn transition(from: &str, to: &str, exit: &[&str], entry: &[&str]) -> TransitionDef {
        TransitionDef {
            id: Uuid::now_v7(),
            model_ref: Uuid::now_v7(),
            from_state: from.into(),
            to_state: to.into(),
            name: format!("{from}->{to}"),
            required_privilege: None,
            guard_expression: None,
            entry_actions: entry.iter().map(|s| (*s).to_owned()).collect(),
            exit_actions: exit.iter().map(|s| (*s).to_owned()).collect(),
            display_order: 0,
            row_version: 0,
            approval_plan: None,
            pending_state: None,
            on_reject_state: None,
            auto_condition: None,
        }
    }

    #[test]
    fn transition_actions_exit_then_entry() {
        let transitions = vec![
            transition(
                "open",
                "won",
                &["custom.notify_team"],
                &["custom.book_kickoff", " "],
            ),
            transition("open", "lost", &[], &[]),
        ];
        assert_eq!(
            actions_for(&transitions, "open", "won"),
            vec!["custom.notify_team", "custom.book_kickoff"]
        );
        assert!(actions_for(&transitions, "open", "lost").is_empty());
        assert!(actions_for(&transitions, "won", "open").is_empty());
        assert_eq!(
            action_key(Uuid::nil(), 2),
            format!("transition:{}:2", Uuid::nil())
        );
    }
}
