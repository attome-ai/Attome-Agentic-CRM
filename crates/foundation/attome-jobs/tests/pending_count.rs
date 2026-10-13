//! The queue gauges (`pending_count`, `dead_letter_count`, `retrying_count`,
//! `worker_last_seen_age_seconds`) are scoped per queue and per status.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`): set `DATABASE_URL` to a PostgreSQL
//! server; without it each test prints SKIP.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use sqlx::PgPool;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_pool() -> Option<PgPool> {
    let url = attome_testkit::migrated_db_url()?;
    let pool = PgPool::connect(&url).await.expect("connect DATABASE_URL");

    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");

    Some(pool)
}

/// P-job-queue-hardening (D-165) — `pending_count`/`dead_letter_count` are
/// per-queue (`batch: bool`), matching the two `job_type` namespaces
/// `attome_jobs::Jobs` now routes across. Confirms a row under one
/// namespace never leaks into the other queue's count.
#[tokio::test]
async fn pending_and_dead_letter_counts_are_scoped_per_queue() {
    let pool = skip_if_no_db!(test_pool().await);

    sqlx::raw_sql(
        "INSERT INTO apalis.jobs (job, id, job_type, status) VALUES
             ('{}', 'fast-pending-1', 'attome_job', 'Pending'),
             ('{}', 'fast-pending-2', 'attome_job', 'Pending'),
             ('{}', 'fast-killed-1',  'attome_job', 'Killed'),
             ('{}', 'batch-pending-1','attome_job_batch', 'Pending'),
             ('{}', 'batch-killed-1', 'attome_job_batch', 'Killed'),
             ('{}', 'batch-killed-2', 'attome_job_batch', 'Killed'),
             ('{}', 'fast-failed-1',  'attome_job', 'Failed')",
    )
    .execute(&pool)
    .await
    .expect("seed apalis.jobs rows");

    assert_eq!(
        attome_jobs::pending_count(&pool, false).await.unwrap(),
        2,
        "fast queue pending count"
    );
    assert_eq!(
        attome_jobs::pending_count(&pool, true).await.unwrap(),
        1,
        "batch queue pending count"
    );
    assert_eq!(
        attome_jobs::dead_letter_count(&pool, false).await.unwrap(),
        1,
        "fast queue dead-letter count"
    );
    assert_eq!(
        attome_jobs::dead_letter_count(&pool, true).await.unwrap(),
        2,
        "batch queue dead-letter count"
    );
    // 'Failed' (still-retryable, not yet exhausted) must never count as
    // dead-lettered — only apalis's own terminal 'Killed' state does.
    assert_eq!(
        attome_jobs::dead_letter_count(&pool, false).await.unwrap(),
        1,
        "a still-retrying Failed row must not be counted as dead-lettered"
    );
}

/// BJB-3 (BJB-F8) — `pending_count` counts only `Pending`, so a backlog
/// waiting out its retry backoff read as zero on the backlog gauge.
/// `retrying_count` is the companion: `Failed` with attempts still left.
#[tokio::test]
async fn retrying_rows_are_counted_separately_from_pending_and_dead_letters() {
    let pool = skip_if_no_db!(test_pool().await);

    sqlx::raw_sql(
        "INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts, run_at) VALUES
             ('{}', 'r-pending',     'attome_job',       'Pending', 0,  25, now()),
             ('{}', 'r-retrying',    'attome_job',       'Failed',  3,  25, now() - interval '120 seconds'),
             ('{}', 'r-exhausted',   'attome_job',       'Failed',  25, 25, now()),
             ('{}', 'r-batch-retry', 'attome_job_batch', 'Failed',  1,  25, now()),
             ('{}', 'r-batch-done',  'attome_job_batch', 'Done',    1,  25, now())",
    )
    .execute(&pool)
    .await
    .expect("seed apalis.jobs rows");

    assert_eq!(
        attome_jobs::pending_count(&pool, false).await.unwrap(),
        1,
        "only the Pending row is pending"
    );
    assert_eq!(
        attome_jobs::retrying_count(&pool, false).await.unwrap(),
        1,
        "a Failed row with attempts left is retrying; an exhausted one is a dead letter, not a retry"
    );
    assert_eq!(
        attome_jobs::retrying_count(&pool, true).await.unwrap(),
        1,
        "retrying rows are counted per queue, same as every other gauge"
    );

    // BJB-14b's oldest-pending age: the retrying row is *not* pending, so the
    // only pending row (seeded at now()) keeps this near zero.
    let age = attome_jobs::oldest_pending_age_seconds(&pool, false)
        .await
        .unwrap()
        .expect("a queue with a pending row has an oldest-pending age");
    assert!(
        (0.0..60.0).contains(&age),
        "oldest-pending age must be the age of the pending row, got {age}"
    );
    assert!(
        attome_jobs::oldest_pending_age_seconds(&pool, true)
            .await
            .unwrap()
            .is_none(),
        "the batch queue has no pending row, so no oldest-pending age"
    );
}

/// BJB-16 — `worker_last_seen_age_seconds` is the "is this queue's worker alive
/// at all" signal: `None` before any worker of that namespace has ever
/// registered, a small number after one heartbeats.
#[tokio::test]
async fn worker_last_seen_age_is_none_until_a_worker_registers_then_small() {
    let pool = skip_if_no_db!(test_pool().await);

    sqlx::query(
        "DELETE FROM apalis.workers WHERE worker_type IN ('attome_job', 'attome_job_batch')",
    )
    .execute(&pool)
    .await
    .expect("clear this binary's worker heartbeats");
    assert!(
        attome_jobs::worker_last_seen_age_seconds(&pool, false)
            .await
            .unwrap()
            .is_none(),
        "a queue whose worker has never registered has no last-seen age"
    );

    sqlx::query(
        "INSERT INTO apalis.workers (id, worker_type, storage_name, last_seen) \
         VALUES ('pending-count-test-worker', 'attome_job', 'attome_job', now()) \
         ON CONFLICT (id) DO UPDATE SET last_seen = now()",
    )
    .execute(&pool)
    .await
    .expect("register a worker heartbeat");

    let age = attome_jobs::worker_last_seen_age_seconds(&pool, false)
        .await
        .unwrap()
        .expect("a registered worker has a last-seen age");
    assert!(
        (0.0..60.0).contains(&age),
        "a just-heartbeated worker's age must be near zero, got {age}"
    );
    assert!(
        attome_jobs::worker_last_seen_age_seconds(&pool, true)
            .await
            .unwrap()
            .is_none(),
        "the batch namespace is a different worker type and stays unknown"
    );
}
