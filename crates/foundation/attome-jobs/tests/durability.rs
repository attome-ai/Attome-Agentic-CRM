//! P1.4 — the durability property apalis exists for: a job enqueued before a
//! "crash" is still there, and still runs exactly once, after the worker is
//! torn down and rebuilt from scratch against the same Postgres. Nothing
//! here carries over between the "before" and "after" halves except the row
//! in `apalis.jobs` — that's the whole point (contrast with the old
//! `tokio::spawn` sites, which this plan replaced precisely because nothing
//! survived a restart).
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-jobs -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use apalis::prelude::{Data, Monitor, Storage, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_jobs::JobEnvelope;
use attome_testkit::skip_if_no_db;
use common::TestJob;
use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
/// Needs migration `0001_job_queue.sql` already applied; see this file's
/// header.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

#[tokio::test]
async fn enqueued_job_survives_worker_restart_and_runs_exactly_once() {
    let pool = skip_if_no_db!(test_pool().await);

    // Unique per test run so this assertion is correct even against a shared,
    // never-truncated test database with other rows already in apalis.jobs.
    let marker = Uuid::now_v7();
    let job = TestJob::FanOut {
        dispatch_id: marker,
    };

    // ── "Before the crash": enqueue only. No worker exists yet. ─────────────
    let mut producer = attome_jobs::Jobs::<TestJob>::new(pool.clone())
        .fast()
        .clone();
    let parts = producer
        .push(JobEnvelope::new(job))
        .await
        .expect("enqueue must durably persist the job");
    let task_id = parts.task_id.to_string();

    let (status,): (String,) = sqlx::query_as("SELECT status FROM apalis.jobs WHERE id = $1")
        .bind(&task_id)
        .fetch_one(&pool)
        .await
        .expect("job row must exist in Postgres immediately after enqueue, before any worker runs");
    assert_eq!(status, "Pending");

    // ── "Restart": a brand-new worker built from scratch against the same
    // Postgres — standing in for the process having crashed and come back. ──
    let processed = Arc::new(AtomicUsize::new(0));
    let expected_dispatch_id = marker;

    async fn handle(
        job: JobEnvelope<TestJob>,
        processed: Data<Arc<AtomicUsize>>,
        expected_dispatch_id: Data<Uuid>,
    ) -> Result<(), sqlx::Error> {
        if let JobEnvelope::Known {
            job: TestJob::FanOut { dispatch_id },
            ..
        } = &job
            && *dispatch_id == *expected_dispatch_id
        {
            processed.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    let storage = attome_jobs::Jobs::<TestJob>::new(pool.clone())
        .fast()
        .clone();
    let monitor = Monitor::new().register(
        WorkerBuilder::new("durability-test-worker")
            .concurrency(1)
            .data(processed.clone())
            .data(expected_dispatch_id)
            .backend(storage)
            .build_fn(handle),
    );

    // Run until the job row reads `Done` (the assertion below), then shut down
    // — standing in for "the worker exits" so the test terminates instead of
    // running forever. The old fixed 2 s window stays as the deadline, so a job
    // that never completes still fails the assertions exactly as before
    // (build-loop-opt-review Phase 3: condition waits instead of fixed sleeps).
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let poll_pool = pool.clone();
    let poll_task_id = task_id.clone();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            let status: Option<String> =
                sqlx::query_scalar("SELECT status FROM apalis.jobs WHERE id = $1")
                    .bind(&poll_task_id)
                    .fetch_optional(&poll_pool)
                    .await
                    .ok()
                    .flatten();
            if status.as_deref() == Some("Done") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let _ = shutdown_tx.send(true);
    });
    monitor
        .run_with_signal(async move {
            let _ = shutdown_rx.wait_for(|shutting_down| *shutting_down).await;
            Ok(())
        })
        .await
        .expect("worker run");

    assert_eq!(
        processed.load(Ordering::SeqCst),
        1,
        "job enqueued before the worker existed must run exactly once after restart"
    );

    let (status,): (String,) = sqlx::query_as("SELECT status FROM apalis.jobs WHERE id = $1")
        .bind(&task_id)
        .fetch_one(&pool)
        .await
        .expect("query apalis.jobs");
    assert_eq!(status, "Done");
}

/// P-job-queue-hardening (D-165) — `enqueue`/`enqueue_in_tx` route a job onto
/// one of two `job_type` namespaces purely based on
/// `TestJob::is_batch()`, centralized in `attome_jobs` itself so no call
/// site has to know which queue a given variant belongs to.
#[tokio::test]
async fn enqueue_routes_batch_and_fast_variants_onto_their_own_job_type() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut jobs = attome_jobs::Jobs::<TestJob>::new(pool.clone());

    attome_jobs::enqueue(
        &mut jobs,
        TestJob::BulkEdit(common::BulkEditPayload {
            bulk_op_id: Uuid::now_v7(),
            entity_logicalname: "contact".to_string(),
            operation: "update".to_string(),
            records: vec![],
            user_id: Uuid::now_v7(),
        }),
    )
    .await
    .expect("enqueue batch variant");

    attome_jobs::enqueue(&mut jobs, TestJob::Sweep)
        .await
        .expect("enqueue fast variant");

    let batch_type: String = sqlx::query_scalar(
        "SELECT job_type FROM apalis.jobs WHERE job::text LIKE '%BulkEdit%' \
         ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("fetch batch job_type");
    assert_eq!(batch_type, "attome_job_batch");

    let fast_type: String = sqlx::query_scalar(
        "SELECT job_type FROM apalis.jobs WHERE job::text LIKE '%Sweep%' \
         ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("fetch fast job_type");
    assert_eq!(fast_type, "attome_job");
}
