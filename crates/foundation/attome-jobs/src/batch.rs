//! Z7-T4: chunked batch jobs with a checkpoint, progress and cancel.
//!
//! A long job (a re-index, a backfill, an import) is split into chunks by a
//! [`BatchJob`]: [`next_chunk`](BatchJob::next_chunk) answers the next chunk
//! after a checkpoint, and [`process`](BatchJob::process) does its writes in
//! a transaction the runner gives it. [`run`] commits each chunk's writes
//! together with the new checkpoint and progress in the `job_batch` row, so
//! a worker that dies mid-job loses at most the chunk it was in: the retried
//! job starts again from the last committed checkpoint and never repeats a
//! committed chunk.
//!
//! Between chunks the runner reads `cancel_requested` (set by
//! `POST /api/v1/jobs/{id}/cancel`) and stops cleanly; progress is read by
//! `GET /api/v1/jobs/{id}`. A batch row is created with [`start`] in the
//! caller's transaction, alongside the enqueue of the job that runs it.

use std::future::Future;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::registry::BoxError;

/// A batch's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Running,
    Finished,
    Cancelled,
}

impl BatchStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "finished" => Self::Finished,
            "cancelled" => Self::Cancelled,
            _ => Self::Running,
        }
    }
}

/// One batch's progress, as `GET /api/v1/jobs/{id}` shows it.
#[derive(Debug, Clone, Serialize)]
pub struct BatchProgress {
    pub id: Uuid,
    pub name: String,
    pub status: BatchStatus,
    /// Items done so far.
    pub done: i64,
    /// Items in all, when the job knows.
    pub total: Option<i64>,
    pub cancel_requested: bool,
    /// Who started it: they and administrators may read and cancel it.
    pub started_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// A job that runs in chunks.
pub trait BatchJob: Send + Sync {
    type Chunk: Send;

    /// The chunk after `checkpoint` (`None`: from the start) and the
    /// checkpoint once it is done, or `None` when nothing is left.
    fn next_chunk(
        &self,
        checkpoint: Option<&Value>,
    ) -> impl Future<Output = Result<Option<(Self::Chunk, Value)>, BoxError>> + Send;

    /// Does one chunk's writes in `tx`; answers how many items it did.
    fn process(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        chunk: Self::Chunk,
    ) -> impl Future<Output = Result<i64, BoxError>> + Send;
}

/// Creates a batch row in the caller's transaction; answers its id.
pub async fn start(
    tx: &mut sqlx::PgConnection,
    name: &str,
    total: Option<i64>,
    started_by: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query(attome_db::tagged_sql!(
        "jobs.batch",
        "INSERT INTO job_batch (id, name, total, started_by) VALUES ($1, $2, $3, $4)"
    ))
    .bind(id)
    .bind(name)
    .bind(total)
    .bind(started_by)
    .execute(tx)
    .await?;
    Ok(id)
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Finished,
    Cancelled,
    /// The batch was already finished or cancelled (a duplicate run).
    AlreadyDone,
}

/// Runs batch `id` from its last checkpoint until it finishes or is
/// cancelled. Each chunk commits with its checkpoint and progress; an error
/// leaves the row at the last committed chunk for the job's retry.
#[expect(
    clippy::disallowed_methods,
    reason = "attome-jobs' public surface is sqlx::Error/BoxError, as `schedule::tick`"
)]
pub async fn run<B: BatchJob>(
    pool: &attome_db::DbPool,
    id: Uuid,
    job: &B,
) -> Result<RunOutcome, BoxError> {
    loop {
        let row: Option<(String, Option<Value>, bool)> = sqlx::query_as(attome_db::tagged_sql!(
            "jobs.batch",
            "SELECT status, checkpoint, cancel_requested FROM job_batch WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(pool)
        .await?;
        let Some((status, checkpoint, cancel)) = row else {
            return Err(format!("no batch {id}").into());
        };
        if BatchStatus::parse(&status) != BatchStatus::Running {
            return Ok(RunOutcome::AlreadyDone);
        }
        if cancel {
            finish(pool, id, BatchStatus::Cancelled).await?;
            return Ok(RunOutcome::Cancelled);
        }
        // AA10-T6: wait while the node is busy serving people.
        crate::throttle::global().pace().await;
        let Some((chunk, next)) = job.next_chunk(checkpoint.as_ref()).await? else {
            finish(pool, id, BatchStatus::Finished).await?;
            return Ok(RunOutcome::Finished);
        };
        let mut tx = pool.begin().await?;
        let done = job.process(&mut tx, chunk).await?;
        // Guarded by the checkpoint just read: a second runner that raced
        // this chunk commits nothing.
        let advanced = sqlx::query(attome_db::tagged_sql!(
            "jobs.batch",
            "UPDATE job_batch SET checkpoint = $2, done = done + $3, updated_at = now() \
             WHERE id = $1 AND status = 'running' \
               AND checkpoint IS NOT DISTINCT FROM $4"
        ))
        .bind(id)
        .bind(&next)
        .bind(done)
        .bind(&checkpoint)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if advanced == 0 {
            tx.rollback().await?;
            return Ok(RunOutcome::AlreadyDone);
        }
        tx.commit().await?;
    }
}

async fn finish(
    pool: &attome_db::DbPool,
    id: Uuid,
    status: BatchStatus,
) -> Result<(), sqlx::Error> {
    sqlx::query(attome_db::tagged_sql!(
        "jobs.batch",
        "UPDATE job_batch SET status = $2, finished_at = now(), updated_at = now() \
         WHERE id = $1 AND status = 'running'"
    ))
    .bind(id)
    .bind(status.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// One batch's progress, or `None`.
pub async fn progress(
    pool: &attome_db::DbPool,
    id: Uuid,
) -> Result<Option<BatchProgress>, sqlx::Error> {
    let row: Option<BatchRow> = sqlx::query_as(attome_db::tagged_sql!(
        "jobs.batch",
        "SELECT id, name, status, done, total, cancel_requested, started_by, \
                created_at, updated_at, finished_at \
         FROM job_batch WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| BatchProgress {
        id: row.id,
        name: row.name,
        status: BatchStatus::parse(&row.status),
        done: row.done,
        total: row.total,
        cancel_requested: row.cancel_requested,
        started_by: row.started_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        finished_at: row.finished_at,
    }))
}

/// M12-T4: the batches `user` started, newest first, one page at a time,
/// with how many there are in all.
pub async fn list_started_by(
    pool: &attome_db::DbPool,
    user: Uuid,
    limit: i64,
    offset: i64,
) -> Result<(Vec<BatchProgress>, i64), sqlx::Error> {
    let rows: Vec<BatchRow> = sqlx::query_as(attome_db::tagged_sql!(
        "jobs.batch",
        "SELECT id, name, status, done, total, cancel_requested, started_by, \
                created_at, updated_at, finished_at \
         FROM job_batch WHERE started_by = $1 \
         ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(user)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let total: i64 = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.batch",
        "SELECT count(*) FROM job_batch WHERE started_by = $1"
    ))
    .bind(user)
    .fetch_one(pool)
    .await?;
    Ok((rows.into_iter().map(BatchProgress::from).collect(), total))
}

impl From<BatchRow> for BatchProgress {
    fn from(row: BatchRow) -> Self {
        BatchProgress {
            id: row.id,
            name: row.name,
            status: BatchStatus::parse(&row.status),
            done: row.done,
            total: row.total,
            cancel_requested: row.cancel_requested,
            started_by: row.started_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            finished_at: row.finished_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct BatchRow {
    id: Uuid,
    name: String,
    status: String,
    done: i64,
    total: Option<i64>,
    cancel_requested: bool,
    started_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

/// Asks batch `id` to stop after its current chunk; whether a running
/// batch took the request (a finished one cannot be cancelled).
pub async fn request_cancel(pool: &attome_db::DbPool, id: Uuid) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(attome_db::tagged_sql!(
        "jobs.batch",
        "UPDATE job_batch SET cancel_requested = true, updated_at = now() \
         WHERE id = $1 AND status = 'running'"
    ))
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Removes finished and cancelled batches older than `days` days.
pub async fn prune(pool: &attome_db::DbPool, days: i32) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(attome_db::tagged_sql!(
        "jobs.batch",
        "DELETE FROM job_batch WHERE finished_at < now() - make_interval(days => $1)"
    ))
    .bind(days)
    .execute(pool)
    .await?
    .rows_affected())
}
