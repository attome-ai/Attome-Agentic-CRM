//! BJB-4a / BJB-4d (attome-jobs plan, Phase 2, D-618) — the schedule ledger.
//!
//! What these tests prove (the plan's acceptance for `schedule::tick` and
//! `schedule::mark_succeeded`):
//!
//! - eight ticks racing in one slot enqueue exactly one job;
//! - a restart (a fresh call) inside the already-claimed slot enqueues none;
//! - the next slot enqueues once more;
//! - two schedules never interfere; and
//! - `mark_succeeded` stamps `last_succeeded_at` for the age gauge (BJB-14b).
//!
//! Multi-node behaviour (J5) cannot be reproduced in one process; the
//! accepted evidence is this concurrent-tick test plus the restart case, per
//! the plan's §10 honest limits.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: `cargo test -p attome-jobs --test schedule -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_testkit::skip_if_no_db;
use common::TestJob;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// Longer than any test run, so a claimed slot never comes due again on its
/// own: "the next slot" is always forced explicitly.
const ONE_HOUR: Duration = Duration::from_secs(3_600);

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
/// Twelve connections because the concurrency case runs eight ticks at once,
/// each holding its own transaction.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(12).await
}

/// This binary's clone is shared between the tests below, so each starts from
/// an empty queue and an empty ledger.
async fn reset(pool: &PgPool) {
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(pool)
        .await
        .expect("truncate apalis.jobs");
    sqlx::query("TRUNCATE job_schedule")
        .execute(pool)
        .await
        .expect("truncate job_schedule");
}

fn schedule_name() -> String {
    format!("schedule-test/{}", Uuid::now_v7())
}

async fn enqueued_rows(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs WHERE dedup_key = $1 AND job_type = 'attome_job'",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("count enqueued rows")
}

async fn make_row_terminal(pool: &PgPool, name: &str) {
    sqlx::query("UPDATE apalis.jobs SET status = 'Done' WHERE dedup_key = $1")
        .bind(name)
        .execute(pool)
        .await
        .expect("mark the slot's row Done");
}

async fn force_due(pool: &PgPool, name: &str) {
    sqlx::query(
        "UPDATE job_schedule SET next_due_at = now() - make_interval(secs => 1) \
         WHERE name = $1",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("force the schedule due");
}

#[tokio::test]
async fn eight_concurrent_ticks_in_one_slot_enqueue_exactly_once() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;
    let name = schedule_name();

    let mut ticks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let name = name.clone();
        ticks.push(tokio::spawn(async move {
            attome_jobs::schedule::tick(&pool, &name, ONE_HOUR, TestJob::Sweep).await
        }));
    }

    let mut claimed = 0;
    for tick in ticks {
        if tick.await.expect("tick task").expect("tick") {
            claimed += 1;
        }
    }

    assert_eq!(
        claimed, 1,
        "the row CAS must pick exactly one winner out of eight concurrent ticks"
    );
    assert_eq!(
        enqueued_rows(&pool, &name).await,
        1,
        "one slot must enqueue exactly one job, however many replicas raced for it"
    );
}

#[tokio::test]
async fn a_restart_inside_the_same_slot_does_not_run_it_again() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;
    let name = schedule_name();

    assert!(
        attome_jobs::schedule::tick(&pool, &name, ONE_HOUR, TestJob::Sweep)
            .await
            .expect("first tick"),
        "the first tick of a new schedule claims its slot"
    );
    assert!(
        !attome_jobs::schedule::tick(&pool, &name, ONE_HOUR, TestJob::Sweep)
            .await
            .expect("restart tick"),
        "a restart inside an already-claimed slot must not claim it again"
    );
    assert_eq!(
        enqueued_rows(&pool, &name).await,
        1,
        "a restart inside the slot must not add a second row"
    );
}

#[tokio::test]
async fn the_next_slot_enqueues_once_more() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;
    let name = schedule_name();

    assert!(
        attome_jobs::schedule::tick(&pool, &name, ONE_HOUR, TestJob::Sweep)
            .await
            .expect("slot 1")
    );
    // The slot's job has to be terminal before the next slot can insert: the
    // dedup index deliberately blocks a second live row under the same key
    // while the first is Pending/Running/Failed (the overlap guard D-165
    // added, which this ledger sits in front of rather than replaces).
    make_row_terminal(&pool, &name).await;
    force_due(&pool, &name).await;

    assert!(
        attome_jobs::schedule::tick(&pool, &name, ONE_HOUR, TestJob::Sweep)
            .await
            .expect("slot 2"),
        "the next slot is due again and must be claimed"
    );
    assert_eq!(
        enqueued_rows(&pool, &name).await,
        2,
        "the second slot enqueues exactly one more row"
    );
}

#[tokio::test]
async fn two_schedules_do_not_interfere() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;
    let first = schedule_name();
    let second = schedule_name();

    assert!(
        attome_jobs::schedule::tick(&pool, &first, ONE_HOUR, TestJob::Sweep)
            .await
            .expect("first schedule")
    );
    assert!(
        attome_jobs::schedule::tick(&pool, &second, ONE_HOUR, TestJob::PruneHistory)
            .await
            .expect("second schedule")
    );

    assert_eq!(enqueued_rows(&pool, &first).await, 1);
    assert_eq!(enqueued_rows(&pool, &second).await, 1);
    assert_eq!(
        attome_jobs::schedule::all(&pool)
            .await
            .expect("ledger")
            .len(),
        2,
        "each schedule owns exactly one ledger row"
    );
}

#[tokio::test]
async fn mark_succeeded_stamps_the_last_success_age() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;
    let name = schedule_name();

    assert!(
        attome_jobs::schedule::last_success_age_seconds(&pool, &name)
            .await
            .expect("age query on an unregistered schedule")
            .is_none(),
        "an unregistered schedule has no row, so no age"
    );

    attome_jobs::schedule::tick(&pool, &name, ONE_HOUR, TestJob::Sweep)
        .await
        .expect("tick");
    attome_jobs::schedule::mark_succeeded(&pool, &name)
        .await
        .expect("mark_succeeded");

    let age = attome_jobs::schedule::last_success_age_seconds(&pool, &name)
        .await
        .expect("age query")
        .expect("a succeeded schedule has an age");
    assert!(
        (0.0..60.0).contains(&age),
        "a just-succeeded schedule's age must be near zero, got {age}"
    );

    let rows = attome_jobs::schedule::all(&pool).await.expect("ledger");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, name);
    assert!(rows[0].last_succeeded_at.is_some());
    assert!(rows[0].last_enqueued_at.is_some());
    assert_eq!(
        rows[0].row_version, 1,
        "one claimed slot advances row_version once"
    );
}
