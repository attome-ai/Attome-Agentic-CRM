//! BJB-P0.1 (attome-jobs plan, Phase 0) — the failing test that proves BJB-F5:
//! an undecodable `apalis.jobs` row does not merely fail one job attempt, it
//! panics the worker's poller.
//!
//! apalis-sql 0.7.4 decodes every row a claim returns with
//! `.expect("Unable to decode")` (`apalis-sql-0.7.4/src/postgres.rs:459-461`),
//! so a `Deserialize` `Err` for `JobEnvelope<TestJob>` — which is exactly what
//! the legacy pre-envelope arms in `job.rs` return for a row with no
//! `"variant"` key — unwinds inside `get_jobs`' own claim batch, before
//! `handle_platform_job` ever runs and therefore with no way to dead-letter
//! the row deliberately. Because `main.rs` polls the `Monitor` inline in
//! `tokio::join!`, that panic takes the whole process down; on restart
//! `reenqueue_orphaned` returns the same row to `Pending` and the next poll
//! crashes again. One malformed row = a crash loop for every worker node.
//!
//! What this test asserts (and what BJB-8 makes true): the worker task is
//! still alive after several polls, and the row reaches a bounded terminal /
//! retryable state (`Failed`/`Killed`) rather than wedging in `Running` or
//! panicking the poller.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: `cargo test -p attome-jobs --test poison_row -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_jobs::JobEnvelope;
use attome_testkit::skip_if_no_db;
use common::TestJob;
use sqlx::PgPool;
use std::time::Duration;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// The production `Unrecognized` arm's shape, reduced to its outcome:
/// `crates/server/src/jobs.rs`'s `dispatch_platform_job` fails the attempt
/// with a descriptive error, which apalis records as `Failed` and retries
/// until the row's own `max_attempts`, then `Killed`.
async fn handle(job: JobEnvelope<TestJob>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match job {
        JobEnvelope::Known { .. } => Ok(()),
        JobEnvelope::Unrecognized { variant, version } => Err(format!(
            "unrecognized platform job envelope: variant='{variant}' envelope_version={version}"
        )
        .into()),
    }
}

#[tokio::test]
async fn an_undecodable_row_is_a_bounded_failure_not_a_worker_panic() {
    let pool = skip_if_no_db!(test_pool().await);

    // Per-binary clone, but a leftover row from an earlier run would compete
    // for the first claim; make this queue hold exactly the poison row.
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");

    // BJB-P0.1's exact row: an externally-tagged `TestJob` shape with no
    // `"variant"` key at all. Written through apalis's own `push_job` so the
    // row is shaped exactly as a producer binary would have written it.
    let (id,): (String,) = sqlx::query_as(
        "SELECT id FROM apalis.push_job('attome_job', '{\"NotAVariant\":{}}'::json)",
    )
    .fetch_one(&pool)
    .await
    .expect("insert the poison row through apalis.push_job");

    let storage = attome_jobs::Jobs::<TestJob>::new(pool.clone())
        .fast()
        .clone();
    let monitor = Monitor::new().register(
        WorkerBuilder::new("poison-row-test-worker")
            .concurrency(1)
            .backend(storage)
            .build_fn(handle),
    );

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    // The production wiring polls the Monitor inline; `tokio::spawn` here is
    // what turns "the process would have died" into an observable
    // `is_finished()` on the worker task.
    let worker_task = tokio::spawn(async move {
        monitor
            .run_with_signal(async move {
                let _ = shutdown_rx.wait_for(|shutting_down| *shutting_down).await;
                Ok(())
            })
            .await
    });

    // At least three claim polls must have happened (the safety poll, D-619).
    tokio::time::sleep(attome_jobs::SAFETY_POLL_INTERVAL * 3).await;
    assert!(
        !worker_task.is_finished(),
        "the worker task ended within three poll intervals of claiming the undecodable row — \
         apalis-sql's own `.expect(\"Unable to decode\")` panicked the poller (BJB-F5)"
    );

    // Bounded outcome: `Failed` (still retrying, attempts < max_attempts) or
    // `Killed` (budget exhausted). Never `Running` forever.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut status = String::new();
    let mut attempts = 0_i32;
    let mut max_attempts = 0_i32;
    while tokio::time::Instant::now() < deadline {
        let row: (String, i32, i32) =
            sqlx::query_as("SELECT status, attempts, max_attempts FROM apalis.jobs WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("read the poison row");
        status = row.0;
        attempts = row.1;
        max_attempts = row.2;
        if status == "Failed" || status == "Killed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        status == "Failed" || status == "Killed",
        "an undecodable row must reach a bounded Failed/Killed state, not stay {status} \
         (attempts={attempts}, max_attempts={max_attempts})"
    );
    assert!(
        !worker_task.is_finished(),
        "the worker task ended after the poison row was claimed — the poller panicked (BJB-F5)"
    );

    let _ = shutdown_tx.send(true);
    let _ = worker_task.await;
}

/// BJB-16 — the `Unrecognized` path end to end: a raw row naming a kind this
/// binary does not have reaches a real worker, fails with a descriptive
/// `last_error` on every attempt, and dead-letters at the row's own declared
/// budget — never a panic, and never an infinite retry. This is the behaviour
/// BJB-8 exists to make reachable at all: before it, the legacy decode arms
/// returned `Err` and the row panicked the poller before any of this ran.
#[tokio::test]
async fn an_unrecognized_variant_retries_with_a_last_error_and_then_dead_letters() {
    let pool = skip_if_no_db!(test_pool().await);
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");

    let (id,): (String,) = sqlx::query_as(
        "SELECT id FROM apalis.push_job(\
             job_type => 'attome_job', \
             job => '{\"version\":1,\"variant\":\"SomeFutureJobKind\",\"payload\":{}}'::json, \
             max_attempts => 2)",
    )
    .fetch_one(&pool)
    .await
    .expect("insert a future-variant row with a two-attempt budget");

    let storage = attome_jobs::Jobs::<TestJob>::new(pool.clone())
        .fast()
        .clone();
    let monitor = Monitor::new().register(
        WorkerBuilder::new("unrecognized-e2e-worker")
            .concurrency(1)
            .backend(storage)
            .build_fn(handle),
    );

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let worker_task = tokio::spawn(async move {
        monitor
            .run_with_signal(async move {
                let _ = shutdown_rx.wait_for(|shutting_down| *shutting_down).await;
                Ok(())
            })
            .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut status = String::new();
    let mut attempts = 0_i32;
    let mut last_error: Option<String> = None;
    while tokio::time::Instant::now() < deadline {
        let row: (String, i32, Option<String>) =
            sqlx::query_as("SELECT status, attempts, last_error FROM apalis.jobs WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("read the future-variant row");
        status = row.0;
        attempts = row.1;
        last_error = row.2;
        if status == "Killed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        status, "Killed",
        "an unrecognized envelope must dead-letter at its own max_attempts, not retry forever"
    );
    assert_eq!(attempts, 2, "the row's declared budget is what bounds it");
    let last_error = last_error.expect("every failed attempt records a last_error");
    assert!(
        last_error.contains("unrecognized") && last_error.contains("SomeFutureJobKind"),
        "last_error must describe the rejection, got: {last_error}"
    );
    assert!(
        !worker_task.is_finished(),
        "the worker task must survive an unrecognized row"
    );

    let _ = shutdown_tx.send(true);
    let _ = worker_task.await;
}
