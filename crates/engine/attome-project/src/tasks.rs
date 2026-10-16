//! Checklists and recurring tasks (roadmap V2-T2).
//!
//! A task (an `activity` of type `task`) can carry checklist items
//! (`task_checklist_item`, platform bundle `attome-task-checklist`) and a
//! `recurrence_rule` (`attome_calendar::recurrence`). When a recurring task
//! is completed, [`roll_recurring`] creates the next one, due on the next
//! occurrence after the completed one's due date, with the same subject,
//! regarding record, owner and priority and a fresh copy of its checklist.
//! The rule moves to the new task in the same transaction, so the
//! completed task is rolled exactly once whatever runs twice.

use attome_calendar::recurrence::{next_occurrence, parse_recurrence};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDate;
use uuid::Uuid;

/// Tasks per batch.
pub const BATCH: i64 = 500;

/// How far through a checklist a task is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ChecklistProgress {
    pub done: usize,
    pub total: usize,
}

impl ChecklistProgress {
    pub fn from_items(done_flags: &[bool]) -> Self {
        Self {
            done: done_flags.iter().filter(|d| **d).count(),
            total: done_flags.len(),
        }
    }

    /// Whole percent done; an empty checklist is complete.
    pub fn percent(&self) -> u32 {
        if self.total == 0 {
            return 100;
        }
        u32::try_from(self.done * 100 / self.total).unwrap_or(100)
    }
}

/// The due date of the task after one due on `due` (or completed on
/// `completed` when it had no due date); `None` for an unreadable rule.
pub fn next_due(rule: &str, due: Option<NaiveDate>, completed: NaiveDate) -> Option<NaiveDate> {
    next_occurrence(parse_recurrence(rule)?, due.unwrap_or(completed))
}

type DoneTask = (Uuid, String, Option<NaiveDate>, NaiveDate);

/// Creates the next task for every completed recurring task; the number
/// created. Does nothing where the checklist bundle is not applied.
pub async fn roll_recurring(db: &DbPool, today: NaiveDate) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'activity' AND column_name = 'recurrence_rule' \
           AND table_schema = ANY (current_schemas(false)))",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let mut created = 0;
    let mut after = Uuid::nil();
    loop {
        let rows: Vec<DoneTask> = sqlx::query_as(
            "SELECT id, recurrence_rule, due_at::date, COALESCE(completed_at::date, $2) \
             FROM activity \
             WHERE (is_active IS NULL OR is_active = true) AND activity_type = 'task' \
               AND status = 'completed' AND recurrence_rule IS NOT NULL \
               AND btrim(recurrence_rule) <> '' AND id > $1 \
             ORDER BY id LIMIT $3",
        )
        .bind(after)
        .bind(today)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else { break };
        after = last.0;
        let full = rows.len() as i64 == BATCH;
        for (id, rule, due, completed) in rows {
            let Some(next) = next_due(&rule, due, completed) else {
                tracing::warn!(task = %id, rule, "recurring tasks: unreadable recurrence rule");
                continue;
            };
            if roll_one(db, id, &rule, next).await? {
                created += 1;
            }
        }
        if !full {
            break;
        }
    }
    Ok(created)
}

async fn roll_one(db: &DbPool, id: Uuid, rule: &str, next: NaiveDate) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let moved = sqlx::query(
        "UPDATE activity SET recurrence_rule = NULL, modified_at = now(), \
         row_version = row_version + 1 WHERE id = $1 AND recurrence_rule = $2",
    )
    .bind(id)
    .bind(rule)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() != 1 {
        return Ok(false);
    }
    let new_id: Uuid = sqlx::query_scalar(
        "INSERT INTO activity (subject, activity_type, status, priority, description, \
            entity_name, record_id, due_at, owner_ref, owner_type, organization_ref, \
            recurrence_rule) \
         SELECT subject, activity_type, 'open', priority, description, entity_name, record_id, \
            $2, owner_ref, owner_type, organization_ref, $3 \
         FROM activity WHERE id = $1 RETURNING id",
    )
    .bind(id)
    .bind(next)
    .bind(rule)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let has_checklist: bool =
        sqlx::query_scalar("SELECT to_regclass('task_checklist_item') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if has_checklist {
        sqlx::query(
            "INSERT INTO task_checklist_item (title, activity_id, sequence, is_done, \
                owner_ref, owner_type, organization_ref) \
             SELECT title, $2, sequence, false, owner_ref, owner_type, organization_ref \
             FROM task_checklist_item \
             WHERE activity_id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(id.to_string())
        .bind(new_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(true)
}

#[cfg(test)]
mod recurring_tasks {
    use super::*;

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, d).unwrap_or_default()
    }

    #[test]
    fn the_next_task_follows_the_rule_from_its_due_date() {
        assert_eq!(
            next_due("weekly", Some(day(11, 2)), day(11, 4)),
            Some(day(11, 9))
        );
        assert_eq!(
            next_due("monthly", None, day(1, 31)),
            Some(day(2, 28)),
            "no due date: from the completion day"
        );
        assert_eq!(
            next_due("FREQ=DAILY;INTERVAL=3", Some(day(3, 1)), day(3, 1)),
            Some(day(3, 4))
        );
        assert_eq!(next_due("every so often", Some(day(3, 1)), day(3, 1)), None);
    }

    #[test]
    fn checklist_progress_counts_done_items() {
        let p = ChecklistProgress::from_items(&[true, false, true, false]);
        assert_eq!((p.done, p.total, p.percent()), (2, 4, 50));
        assert_eq!(ChecklistProgress::from_items(&[]).percent(), 100);
    }
}
