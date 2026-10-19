//! Z7-T4: a chunked batch job resumes from its last committed checkpoint,
//! reports its progress and stops when cancelled.
//!
//! Runs against attome-testkit's migrated throwaway database: set
//! `DATABASE_URL`; without it each test prints SKIP.
//!
//! Run: `cargo test -p attome-jobs --test batch -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::{AtomicI64, Ordering};

use attome_jobs::batch::{self, BatchJob, BatchStatus, RunOutcome};
use attome_jobs::registry::BoxError;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Ten chunks, one row each in `batch_test_item`; fails once at
/// `fail_at` (0: never), as a worker killed there would.
struct TenChunks {
    batch: Uuid,
    fail_at: AtomicI64,
    /// Cancel this batch once this chunk is done (0: never).
    cancel_after: i64,
    pool: PgPool,
}

impl BatchJob for TenChunks {
    type Chunk = i64;

    async fn next_chunk(
        &self,
        checkpoint: Option<&Value>,
    ) -> Result<Option<(i64, Value)>, BoxError> {
        let last = checkpoint.and_then(Value::as_i64).unwrap_or(0);
        Ok((last < 10).then(|| (last + 1, json!(last + 1))))
    }

    async fn process(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        chunk: i64,
    ) -> Result<i64, BoxError> {
        sqlx::query("INSERT INTO batch_test_item (batch, chunk) VALUES ($1, $2)")
            .bind(self.batch)
            .bind(chunk)
            .execute(&mut **tx)
            .await?;
        if self.fail_at.load(Ordering::SeqCst) == chunk {
            self.fail_at.store(0, Ordering::SeqCst);
            return Err("the worker died here".into());
        }
        if self.cancel_after == chunk {
            batch::request_cancel(&self.pool, self.batch).await?;
        }
        Ok(1)
    }
}

async fn test_pool() -> Option<PgPool> {
    let pool = attome_testkit::migrated_pool(5).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS batch_test_item (batch uuid NOT NULL, chunk bigint NOT NULL)",
    )
    .execute(&pool)
    .await
    .expect("test table");
    Some(pool)
}

async fn new_batch(pool: &PgPool) -> Uuid {
    let mut conn = pool.acquire().await.expect("connection");
    batch::start(&mut conn, "test.ten_chunks", Some(10), None)
        .await
        .expect("start")
}

async fn chunks_written(pool: &PgPool, batch: Uuid) -> Vec<i64> {
    sqlx::query_scalar("SELECT chunk FROM batch_test_item WHERE batch = $1 ORDER BY chunk")
        .bind(batch)
        .fetch_all(pool)
        .await
        .expect("chunks")
}

#[tokio::test]
async fn a_batch_killed_after_chunk_four_resumes_at_chunk_five() {
    let pool = skip_if_no_db!(test_pool().await);
    let id = new_batch(&pool).await;
    let job = TenChunks {
        batch: id,
        fail_at: AtomicI64::new(5),
        cancel_after: 0,
        pool: pool.clone(),
    };
    assert!(batch::run(&pool, id, &job).await.is_err(), "chunk 5 fails");
    let midway = batch::progress(&pool, id)
        .await
        .expect("progress")
        .expect("row");
    assert_eq!((midway.done, midway.total), (4, Some(10)));
    assert_eq!(midway.status, BatchStatus::Running);
    assert_eq!(
        chunks_written(&pool, id).await,
        [1, 2, 3, 4],
        "chunk 5 rolled back"
    );

    assert_eq!(
        batch::run(&pool, id, &job).await.expect("resume"),
        RunOutcome::Finished
    );
    assert_eq!(
        chunks_written(&pool, id).await,
        (1..=10).collect::<Vec<_>>()
    );
    let done = batch::progress(&pool, id)
        .await
        .expect("progress")
        .expect("row");
    assert_eq!((done.done, done.status), (10, BatchStatus::Finished));
    assert!(done.finished_at.is_some());
    assert_eq!(
        batch::run(&pool, id, &job).await.expect("again"),
        RunOutcome::AlreadyDone
    );
    assert!(
        !batch::request_cancel(&pool, id).await.expect("cancel"),
        "finished stays finished"
    );
}

#[tokio::test]
async fn a_cancelled_batch_stops_between_chunks() {
    let pool = skip_if_no_db!(test_pool().await);
    let id = new_batch(&pool).await;
    let job = TenChunks {
        batch: id,
        fail_at: AtomicI64::new(0),
        cancel_after: 3,
        pool: pool.clone(),
    };
    assert_eq!(
        batch::run(&pool, id, &job).await.expect("run"),
        RunOutcome::Cancelled
    );
    assert_eq!(chunks_written(&pool, id).await, [1, 2, 3]);
    let row = batch::progress(&pool, id)
        .await
        .expect("progress")
        .expect("row");
    assert_eq!((row.done, row.status), (3, BatchStatus::Cancelled));
    assert!(row.cancel_requested);
    assert!(
        batch::progress(&pool, Uuid::now_v7())
            .await
            .expect("progress")
            .is_none()
    );
}
