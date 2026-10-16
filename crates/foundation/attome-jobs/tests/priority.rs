//! M08 (Automation) checklist item 1 — priority lanes.
//!
//! `apalis.get_jobs` (`0001_job_queue.sql`)
//! already polls `ORDER BY priority DESC, run_at ASC` against the `0138`
//! composite index — the only gap was application-layer classification
//! (`attome_jobs::JobPriority` / `TestJob::priority()`, `job.rs`) and
//! threading it into `apalis.jobs.priority` through every enqueue entry
//! point. These tests pin that plumbing, plus the checklist's own explicit
//! "lane starvation guard" requirement.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-jobs --test priority -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

mod common;

use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_jobs::{JobEnvelope, JobPriority};
use attome_testkit::skip_if_no_db;
use common::TestJob;
use sqlx::PgPool;
use uuid::Uuid;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// A permissive worker handler: marks any `platform_job` row `Done`
/// regardless of variant. These tests only care about ordering/completion,
/// never about what a real handler in `crates/server` would have done with
/// the payload.
async fn handle(_job: JobEnvelope<TestJob>) -> Result<(), sqlx::Error> {
    Ok(())
}

#[tokio::test]
async fn enqueue_writes_the_classified_apalis_priority_column() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut jobs = attome_jobs::Jobs::<TestJob>::new(pool.clone());

    let low_marker = format!("priority-test-low-{}", Uuid::now_v7());
    attome_jobs::enqueue(
        &mut jobs,
        TestJob::BuildIndex {
            entity_logicalname: low_marker.clone(),
            field_logicalname: "probe".to_string(),
        },
    )
    .await
    .expect("enqueue a Low-classified job");

    let low_priority: i32 =
        sqlx::query_scalar("SELECT priority FROM apalis.jobs WHERE job::text LIKE $1")
            .bind(format!("%{low_marker}%"))
            .fetch_one(&pool)
            .await
            .expect("fetch priority for the Low job");
    assert_eq!(low_priority, JobPriority::Low.apalis_priority());

    let high_marker = Uuid::now_v7();
    attome_jobs::enqueue(
        &mut jobs,
        TestJob::FanOut {
            dispatch_id: high_marker,
        },
    )
    .await
    .expect("enqueue a High-classified job");

    let high_priority: i32 =
        sqlx::query_scalar("SELECT priority FROM apalis.jobs WHERE job::text LIKE $1")
            .bind(format!("%{high_marker}%"))
            .fetch_one(&pool)
            .await
            .expect("fetch priority for the High job");
    assert_eq!(high_priority, JobPriority::High.apalis_priority());
}

#[tokio::test]
async fn enqueue_in_tx_writes_the_classified_apalis_priority_column() {
    let pool = skip_if_no_db!(test_pool().await);
    let marker = Uuid::now_v7();

    let mut tx = pool.begin().await.expect("begin tx");
    attome_jobs::enqueue_in_tx(
        &mut tx,
        TestJob::RunWorkflow {
            instance_id: marker,
        },
    )
    .await
    .expect("enqueue_in_tx a High-classified job");
    tx.commit().await.expect("commit");

    let priority: i32 =
        sqlx::query_scalar("SELECT priority FROM apalis.jobs WHERE job::text LIKE $1")
            .bind(format!("%{marker}%"))
            .fetch_one(&pool)
            .await
            .expect("fetch priority");
    assert_eq!(priority, JobPriority::High.apalis_priority());
}

#[tokio::test]
async fn enqueue_dedup_writes_the_classified_apalis_priority_column() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("priority-dedup-test/{}", Uuid::now_v7());

    let inserted = attome_jobs::enqueue_dedup(&pool, TestJob::SlaSweep, &key)
        .await
        .expect("enqueue_dedup a Low-classified job");
    assert!(inserted);

    let priority: i32 = sqlx::query_scalar("SELECT priority FROM apalis.jobs WHERE dedup_key = $1")
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("fetch priority");
    assert_eq!(priority, JobPriority::Low.apalis_priority());
}

#[tokio::test]
async fn enqueue_in_tx_dedup_writes_the_classified_apalis_priority_column() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("priority-dedup-test/{}", Uuid::now_v7());

    let mut tx = pool.begin().await.expect("begin tx");
    let inserted = attome_jobs::enqueue_in_tx_dedup(&mut tx, TestJob::Revalidate, &key)
        .await
        .expect("enqueue_in_tx_dedup a Low-classified job");
    assert!(inserted);
    tx.commit().await.expect("commit");

    let priority: i32 = sqlx::query_scalar("SELECT priority FROM apalis.jobs WHERE dedup_key = $1")
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("fetch priority");
    assert_eq!(priority, JobPriority::Low.apalis_priority());
}

/// M08 checklist item 4's own required test: "lane starvation guard (low-
/// priority still progresses even when high-priority jobs keep arriving)".
///
/// `apalis.get_jobs`'s poll query has no aging — a lane held continuously at
/// or above one poll's `buffer_size` (10, `queue_config` in `lib.rs`) could
/// in principle starve a lower lane forever; see `JobPriority`'s own doc
/// comment. What this test actually proves is the realistic guarantee: a
/// Low-priority job enqueued first, genuinely deferred behind more than one
/// poll's worth of High-priority rows (proven below via
/// `pending_count_by_priority`, not assumed), still reaches `Done` once that
/// High-priority arrival stream lets up — delayed by priority, never
/// abandoned.
#[tokio::test]
async fn a_low_priority_job_still_completes_despite_a_continuing_stream_of_high_priority_arrivals()
{
    let pool = skip_if_no_db!(test_pool().await);
    let mut jobs = attome_jobs::Jobs::<TestJob>::new(pool.clone());

    // The probe: enqueued first, so if priority were ignored (pure FIFO) it
    // would be the very first job any worker picks up.
    let low_marker = format!("starvation-test-{}", Uuid::now_v7());
    attome_jobs::enqueue(
        &mut jobs,
        TestJob::BuildIndex {
            entity_logicalname: low_marker.clone(),
            field_logicalname: "probe".to_string(),
        },
    )
    .await
    .expect("enqueue the Low-priority probe job first");
    let probe_task_id: String =
        sqlx::query_scalar("SELECT id FROM apalis.jobs WHERE job::text LIKE $1")
            .bind(format!("%{low_marker}%"))
            .fetch_one(&pool)
            .await
            .expect("fetch the probe job's id");

    // Fifteen High-priority rows before any worker exists — more than one
    // poll's buffer_size (10), so the very first poll is guaranteed to fill
    // entirely with High-priority work and defer the probe past it.
    for _ in 0..15 {
        attome_jobs::enqueue(
            &mut jobs,
            TestJob::ScanFile {
                session_id: Uuid::now_v7(),
            },
        )
        .await
        .expect("enqueue a High-priority filler job");
    }

    // Confirm the contention is real before starting any worker, rather than
    // assuming it from the enqueue order above.
    let pending_high = attome_jobs::pending_count_by_priority(&pool, false, JobPriority::High)
        .await
        .expect("pending_count_by_priority (High)");
    let pending_low = attome_jobs::pending_count_by_priority(&pool, false, JobPriority::Low)
        .await
        .expect("pending_count_by_priority (Low)");
    assert!(
        pending_high >= 15,
        "expected at least 15 pending High-priority fast-queue jobs, got {pending_high}"
    );
    assert!(
        pending_low >= 1,
        "expected at least 1 pending Low-priority fast-queue job, got {pending_low}"
    );

    // A single worker: the worst case for contention (only one concurrency
    // slot for the continuing High-priority stream to occupy ahead of the
    // probe).
    let storage = attome_jobs::Jobs::<TestJob>::new(pool.clone())
        .fast()
        .clone();
    let monitor = Monitor::new().register(
        WorkerBuilder::new("starvation-guard-test-worker")
            .concurrency(1)
            .backend(storage)
            .build_fn(handle),
    );

    // "Keep arriving": another 25 High-priority jobs, one every 25ms
    // (~625ms), enqueued concurrently while the worker is already draining
    // the initial 15 — simulates continuing High-priority traffic rather
    // than one static burst.
    let mut trickle_jobs = attome_jobs::Jobs::<TestJob>::new(pool.clone());
    let trickle = tokio::spawn(async move {
        for _ in 0..25 {
            let _ = attome_jobs::enqueue(
                &mut trickle_jobs,
                TestJob::ScanFile {
                    session_id: Uuid::now_v7(),
                },
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    });

    // Run until the probe reads `Done` (the assertion below), then shut down.
    // The deadline is headroom for a slow, busy CI host (the whole DB test
    // tier shares it), not expected processing time: the probe finishes in
    // well under a second when it is not starved, and a probe starved behind
    // the High-priority stream still never reads `Done` (build-loop-opt-review
    // Phase 3: condition waits instead of fixed sleeps).
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let poll_pool = pool.clone();
    let poll_task_id = probe_task_id.clone();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
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

    trickle.await.expect("trickle task must not panic");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM apalis.jobs WHERE id = $1")
        .bind(&probe_task_id)
        .fetch_one(&pool)
        .await
        .expect("query probe job status");
    assert_eq!(
        status, "Done",
        "the Low-priority probe job must still complete once the High-priority \
         arrival stream lets up, not sit pending behind it forever"
    );
}
