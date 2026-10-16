//! Timers (roadmap M10-T1): one table (`timer`) for every point in time the
//! platform waits for — a flow resuming at a date, a reminder, an
//! escalation. [`schedule`] adds one in the caller's transaction;
//! [`claim_due`] moves due timers from `pending` to `fired` with
//! `FOR UPDATE SKIP LOCKED`, so each is claimed once however many nodes
//! sweep; the sweep queues one `EngineJob::TimerFire` per claimed timer,
//! whose handler runs the kind's action and settles the timer `done` or
//! `failed`. [`cancel_for_target`] drops a record's pending timers (the
//! record left its condition or went away).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use attome_types::AppError;

/// Most timers one sweep claims.
pub const CLAIM_BATCH: i64 = 500;

/// A timer to add.
#[derive(Debug, Clone, PartialEq)]
pub struct NewTimer {
    pub kind: String,
    pub target_entity: Option<String>,
    pub target_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    pub due_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

/// A claimed timer.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Timer {
    pub id: Uuid,
    pub kind: String,
    pub target_entity: Option<String>,
    pub target_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    pub due_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

/// Adds a timer in the caller's transaction.
pub async fn schedule(conn: &mut sqlx::PgConnection, timer: &NewTimer) -> Result<Uuid, AppError> {
    if timer.kind.trim().is_empty() {
        return Err(AppError::Validation("a timer needs a kind".into()));
    }
    sqlx::query_scalar(
        "INSERT INTO timer (kind, target_entity, target_id, run_id, due_at, payload) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(timer.kind.trim())
    .bind(&timer.target_entity)
    .bind(timer.target_id)
    .bind(timer.run_id)
    .bind(timer.due_at)
    .bind(&timer.payload)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

/// Moves pending timers of a kind on a record to a new time (a date they
/// follow changed); the number moved.
pub async fn reschedule_for_target(
    conn: &mut sqlx::PgConnection,
    kind: &str,
    target_entity: &str,
    target_id: Uuid,
    due_at: DateTime<Utc>,
) -> Result<u64, AppError> {
    Ok(sqlx::query(
        "UPDATE timer SET due_at = $4 \
         WHERE kind = $1 AND target_entity = $2 AND target_id = $3 AND status = 'pending'",
    )
    .bind(kind)
    .bind(target_entity)
    .bind(target_id)
    .bind(due_at)
    .execute(conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// Cancels a record's pending timers, of one kind or all; the number
/// cancelled.
pub async fn cancel_for_target(
    conn: &mut sqlx::PgConnection,
    target_entity: &str,
    target_id: Uuid,
    kind: Option<&str>,
) -> Result<u64, AppError> {
    Ok(sqlx::query(
        "UPDATE timer SET status = 'cancelled' \
         WHERE target_entity = $1 AND target_id = $2 AND status = 'pending' \
           AND ($3::text IS NULL OR kind = $3)",
    )
    .bind(target_entity)
    .bind(target_id)
    .bind(kind)
    .execute(conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// Claims the timers due at `now` (oldest first), marking them `fired`.
pub async fn claim_due(
    conn: &mut sqlx::PgConnection,
    now: DateTime<Utc>,
) -> Result<Vec<Timer>, AppError> {
    sqlx::query_as(
        "UPDATE timer t SET status = 'fired', fired_at = $1 \
         FROM (SELECT id FROM timer WHERE status = 'pending' AND due_at <= $1 \
               ORDER BY due_at LIMIT $2 FOR UPDATE SKIP LOCKED) due \
         WHERE t.id = due.id \
         RETURNING t.id, t.kind, t.target_entity, t.target_id, t.run_id, t.due_at, t.payload",
    )
    .bind(now)
    .bind(CLAIM_BATCH)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)
}

/// Settles a fired timer: `done`, or `failed` with the reason.
pub async fn settle(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE timer SET status = CASE WHEN $2::text IS NULL THEN 'done' ELSE 'failed' END, \
             last_error = $2 \
         WHERE id = $1 AND status = 'fired'",
    )
    .bind(id)
    .bind(error)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Reads a fired timer for its job.
pub async fn load(conn: &mut sqlx::PgConnection, id: Uuid) -> Result<Option<Timer>, AppError> {
    sqlx::query_as(
        "SELECT id, kind, target_entity, target_id, run_id, due_at, payload FROM timer \
         WHERE id = $1 AND status = 'fired'",
    )
    .bind(id)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)
}
