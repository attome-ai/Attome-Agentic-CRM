//! M10-T2: timers that follow a date attribute of their record. A change-feed
//! consumer reads every record change and, for a record with pending timers
//! that carry a `follow` payload (`attome_core::timer::Follow`), moves each
//! one to the record's new date plus its offset, or cancels it when the
//! record went away, cleared the date or no longer meets the follow's
//! condition (rule text, evaluated as a workflow condition node evaluates
//! it, against the record's current row). Re-reading a batch after a crash
//! recomputes the same answers, so it is safe to retry; a timer that fired
//! or was cancelled meanwhile is left alone.

use std::collections::BTreeSet;

use attome_core::EngineState;
use attome_core::timer::{FollowDecision, apply_follow, follow_decision, following_for_target};
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// This consumer's change-feed cursor.
pub const CONSUMER: &str = "attome-workflow/timer-follow";

const BATCH: i64 = 500;

/// Most batches one sweep reads, so a backlog cannot hold the timer job.
const MAX_BATCHES: usize = 20;

/// What one sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FollowRun {
    pub events: u64,
    pub moved: u64,
    pub cancelled: u64,
}

/// Reads the changes since the cursor and moves or cancels the date-following
/// timers of the records they touched. Runs before due timers are claimed.
pub async fn sweep(state: &EngineState) -> Result<FollowRun, AppError> {
    let db = &state.base.db;
    let mut run = FollowRun::default();
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        run.events += events.len() as u64;
        let mut seen = BTreeSet::new();
        for event in &events {
            if event.event_name.is_some()
                || !seen.insert((event.entity_logicalname.clone(), event.record_id))
            {
                continue;
            }
            let (moved, cancelled) =
                follow_record(state, &event.entity_logicalname, event.record_id).await?;
            run.moved += moved;
            run.cancelled += cancelled;
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(run)
}

/// The record's current row as JSON; `None` when it is gone or deactivated,
/// or its entity is no longer registered.
async fn current_record(
    state: &EngineState,
    entity: &str,
    id: Uuid,
) -> Result<Option<Value>, AppError> {
    if state.entities.load().get(entity).is_none() {
        return Ok(None);
    }
    let sql = format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id = $1",
        attome_core::quote_ident(entity)
    );
    let row: Option<Value> = sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(row.filter(|r| r.get("is_active").and_then(Value::as_bool) != Some(false)))
}

/// Moves or cancels one record's date-following timers; how many of each.
async fn follow_record(
    state: &EngineState,
    entity: &str,
    id: Uuid,
) -> Result<(u64, u64), AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let timers = following_for_target(&mut conn, entity, id).await?;
    drop(conn);
    if timers.is_empty() {
        return Ok((0, 0));
    }
    let record = current_record(state, entity, id).await?;
    let mut decisions = Vec::with_capacity(timers.len());
    for timer in &timers {
        let holds = match (&record, &timer.follow.condition) {
            (Some(record), Some(condition)) => {
                crate::condition::expression_holds(condition, record)
            }
            _ => true,
        };
        decisions.push((
            timer.id,
            follow_decision(&timer.follow, record.as_ref(), holds, timer.due_at),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (mut moved, mut cancelled) = (0, 0);
    for (timer_id, decision) in decisions {
        if apply_follow(&mut tx, timer_id, decision).await? {
            match decision {
                FollowDecision::Move(_) => moved += 1,
                FollowDecision::Cancel => cancelled += 1,
                FollowDecision::Keep => {}
            }
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok((moved, cancelled))
}
