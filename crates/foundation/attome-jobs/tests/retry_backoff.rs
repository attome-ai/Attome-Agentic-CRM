//! T2-12 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §3.11) — `apply_retry_backoff`
//! is the actual fix: apalis-sql 0.7.4's own failure path (`PostgresStorage::update`)
//! writes `status`/`attempts` but never touches `run_at`, so `apalis.get_jobs`
//! re-claims a `Failed` row on the very next ~100ms poll and a transient
//! outage burns the whole `max_attempts` budget in seconds. This suite
//! proves the actual DB write: after each call, `run_at` moves into the
//! future by (approximately) `retry_backoff_seconds(attempt)`, and the delay
//! grows across attempts — the pure formula itself is covered by
//! `retry_backoff_seconds`'s unit tests in `src/lib.rs`; this proves the SQL
//! that applies it to a real row.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-jobs --test retry_backoff -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_jobs::{Jobs, apply_retry_backoff};
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use common::TestJob;
use sqlx::PgPool;

async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// Enqueues a real job through `Jobs::enqueue` (rather than a
/// hand-written `INSERT`) so this test exercises `apply_retry_backoff`
/// against a row shaped exactly the way production rows are — same
/// `job_type`/`status`/`attempts` defaults `apalis.push_job` writes.
async fn seed_job_id(pool: &PgPool) -> String {
    let mut jobs = Jobs::<TestJob>::new(pool.clone());
    attome_jobs::enqueue(&mut jobs, TestJob::Sweep)
        .await
        .expect("enqueue a job to back off");
    sqlx::query_scalar(
        "SELECT id FROM apalis.jobs WHERE job_type = 'attome_job' \
         ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .expect("fetch the id of the row just enqueued")
}

async fn run_at(pool: &PgPool, id: &str) -> chrono::DateTime<Utc> {
    sqlx::query_scalar("SELECT run_at FROM apalis.jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("fetch run_at")
}

#[tokio::test]
async fn apply_retry_backoff_pushes_run_at_into_the_future_by_the_computed_delay() {
    let pool = skip_if_no_db!(test_pool().await);
    let id = seed_job_id(&pool).await;

    let before = Utc::now();
    apply_retry_backoff(&pool, &id, 1)
        .await
        .expect("apply_retry_backoff for attempt 1");
    let after_first = run_at(&pool, &id).await;

    let delta = (after_first - before).num_seconds();
    assert!(
        (8..=13).contains(&delta),
        "attempt 1 must push run_at ~10s into the future, got {delta}s"
    );
}

#[tokio::test]
async fn apply_retry_backoff_grows_the_delay_across_successive_attempts() {
    let pool = skip_if_no_db!(test_pool().await);
    let id = seed_job_id(&pool).await;

    let mut previous_delta = 0i64;
    for attempt in 1..=4usize {
        let before = Utc::now();
        apply_retry_backoff(&pool, &id, attempt)
            .await
            .unwrap_or_else(|e| panic!("apply_retry_backoff for attempt {attempt}: {e}"));
        let new_run_at = run_at(&pool, &id).await;
        let delta = (new_run_at - before).num_seconds();

        assert!(
            delta > previous_delta,
            "attempt {attempt}'s backoff ({delta}s) must exceed the previous attempt's ({previous_delta}s) \
             -- this is the property that actually stops apalis's ~100ms poll from re-claiming the row \
             instantly and burning the whole max_attempts budget in seconds"
        );
        previous_delta = delta;
    }
}

#[tokio::test]
async fn apply_retry_backoff_is_a_harmless_no_op_for_an_id_with_no_row() {
    let pool = skip_if_no_db!(test_pool().await);
    // No row exists with this id -- the UPDATE affects zero rows. Must not
    // error (a job racing with its own cleanup/prune must not fail the
    // worker just because the row it was about to back off disappeared).
    apply_retry_backoff(&pool, "no-such-job-id", 1)
        .await
        .expect("apply_retry_backoff must not error when the row doesn't exist");
}
