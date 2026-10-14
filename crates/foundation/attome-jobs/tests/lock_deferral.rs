//! Y12-T4 — `defer_for_lock`: a run stopped by a table lock goes back in the
//! queue as a fresh copy five minutes out, with the same kind, payload,
//! priority and attempt budget, counting its deferrals in the envelope; the
//! thirteenth deferral is refused so the worker fails the run with
//! `lock_timeout`. The copy still decodes to the same job.
//!
//! Runs against attome-testkit's migrated throwaway database; without
//! `DATABASE_URL` each test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-jobs --test lock_deferral -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_jobs::{JobEnvelope, Jobs, LOCK_DEFERRAL_SECS, MAX_LOCK_DEFERRALS, defer_for_lock};
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use common::TestJob;
use sqlx::PgPool;

async fn seed_job_id(pool: &PgPool) -> String {
    let mut jobs = Jobs::<TestJob>::new(pool.clone());
    attome_jobs::enqueue(
        &mut jobs,
        TestJob::BuildIndex {
            entity_logicalname: "deferral_probe".into(),
            field_logicalname: "name".into(),
        },
    )
    .await
    .expect("enqueue a job to defer");
    sqlx::query_scalar(
        "SELECT id FROM apalis.jobs WHERE job::jsonb->'payload'->>'entity_logicalname' = 'deferral_probe' \
         ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .expect("fetch the id of the row just enqueued")
}

/// The newest copy of the probe job: its id, deferral count, run_at,
/// attempt budget and stored envelope.
async fn newest(pool: &PgPool) -> (String, i32, chrono::DateTime<Utc>, i32, serde_json::Value) {
    sqlx::query_as(
        "SELECT id, COALESCE((job->>'deferrals')::int, 0), run_at, max_attempts, job::jsonb \
         FROM apalis.jobs WHERE job::jsonb->'payload'->>'entity_logicalname' = 'deferral_probe' \
         ORDER BY 2 DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .expect("read the newest probe row")
}

#[tokio::test]
async fn lock_held_defers_job_then_succeeds() {
    let pool = skip_if_no_db!(attome_testkit::migrated_pool(5).await);
    sqlx::query("DELETE FROM apalis.jobs WHERE job::jsonb->'payload'->>'entity_logicalname' = 'deferral_probe'")
        .execute(&pool)
        .await
        .unwrap();
    let first = seed_job_id(&pool).await;
    let (_, _, _, budget, _) = newest(&pool).await;

    let before = Utc::now();
    assert!(
        defer_for_lock(&pool, &first).await.unwrap(),
        "the first deferral is allowed"
    );
    let (copy, deferrals, run_at, copy_budget, envelope) = newest(&pool).await;
    assert_ne!(copy, first, "a deferral is a fresh row");
    assert_eq!(deferrals, 1);
    assert_eq!(copy_budget, budget, "the attempt budget is unspent");
    let delay = (run_at - before).num_seconds();
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a small whole number of seconds"
    )]
    let expected = LOCK_DEFERRAL_SECS as i64;
    assert!(
        (expected - 2..=expected + 5).contains(&delay),
        "runs ~5 minutes out, got {delay}s"
    );
    // The copy still decodes to the same job.
    let decoded: JobEnvelope<TestJob> = serde_json::from_value(envelope).unwrap();
    assert!(
        matches!(&decoded, JobEnvelope::Known { job: TestJob::BuildIndex { entity_logicalname, .. }, .. }
            if entity_logicalname == "deferral_probe"),
        "{decoded:?}"
    );

    // Every later deferral counts up, until the budget is spent.
    let mut current = copy;
    for n in 2..=MAX_LOCK_DEFERRALS {
        assert!(
            defer_for_lock(&pool, &current).await.unwrap(),
            "deferral {n} is allowed"
        );
        let (next, deferrals, ..) = newest(&pool).await;
        assert_eq!(deferrals, n);
        current = next;
    }
    assert!(
        !defer_for_lock(&pool, &current).await.unwrap(),
        "deferral {} is refused, so the run fails with lock_timeout",
        MAX_LOCK_DEFERRALS + 1
    );
    let (last, deferrals, ..) = newest(&pool).await;
    assert_eq!(
        (last, deferrals),
        (current, MAX_LOCK_DEFERRALS),
        "a refused deferral writes nothing"
    );
}

#[tokio::test]
async fn deferring_a_missing_row_writes_nothing() {
    let pool = skip_if_no_db!(attome_testkit::migrated_pool(5).await);
    assert!(!defer_for_lock(&pool, "no-such-job-id").await.unwrap());
}
