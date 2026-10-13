//! P-job-queue-hardening (D-165) — enqueue-time deduplication
//! (`apalis.push_job_dedup`, migration `0001_job_queue.sql`).
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-jobs --test dedup -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_testkit::skip_if_no_db;
use common::TestJob;
use sqlx::PgPool;
use uuid::Uuid;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
/// Needs migrations `0001_job_queue.sql` + `0001_job_queue.sql`
/// already applied; see this file's header.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

fn sample_job(marker: &str) -> TestJob {
    TestJob::BuildIndex {
        entity_logicalname: marker.to_string(),
        field_logicalname: "dedup_test_field".to_string(),
    }
}

#[tokio::test]
async fn a_second_enqueue_with_the_same_key_is_a_no_op_while_the_first_row_is_pending() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("dedup-test/{}", Uuid::now_v7());

    let first = attome_jobs::enqueue_dedup(&pool, sample_job("first"), &key)
        .await
        .expect("first enqueue_dedup");
    assert!(first, "first enqueue with a fresh key must insert a row");

    let second = attome_jobs::enqueue_dedup(&pool, sample_job("second"), &key)
        .await
        .expect("second enqueue_dedup");
    assert!(
        !second,
        "second enqueue with the same key must be a no-op while the first row is still Pending"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs WHERE dedup_key = $1 AND job_type = 'attome_job'",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("count rows for key");
    assert_eq!(count, 1, "only one row should exist for this dedup key");
}

#[tokio::test]
async fn a_second_enqueue_with_the_same_key_is_blocked_while_the_first_row_is_running() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("dedup-test/{}", Uuid::now_v7());

    let first = attome_jobs::enqueue_dedup(&pool, sample_job("first"), &key)
        .await
        .expect("first enqueue_dedup");
    assert!(first);

    sqlx::query("UPDATE apalis.jobs SET status = 'Running' WHERE dedup_key = $1")
        .bind(&key)
        .execute(&pool)
        .await
        .expect("mark row Running");

    let second = attome_jobs::enqueue_dedup(&pool, sample_job("second"), &key)
        .await
        .expect("second enqueue_dedup");
    assert!(
        !second,
        "a job actively Running still means the logical operation isn't done — a second \
         enqueue with the same key must not create a real duplicate-execution race"
    );
}

#[tokio::test]
async fn a_second_enqueue_with_the_same_key_succeeds_once_the_first_row_is_done() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("dedup-test/{}", Uuid::now_v7());

    let first = attome_jobs::enqueue_dedup(&pool, sample_job("first"), &key)
        .await
        .expect("first enqueue_dedup");
    assert!(first);

    sqlx::query("UPDATE apalis.jobs SET status = 'Done' WHERE dedup_key = $1")
        .bind(&key)
        .execute(&pool)
        .await
        .expect("mark row Done");

    let second = attome_jobs::enqueue_dedup(&pool, sample_job("second"), &key)
        .await
        .expect("second enqueue_dedup");
    assert!(
        second,
        "once the prior run reached a terminal Done state, the same key must be reusable"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs WHERE dedup_key = $1 AND job_type = 'attome_job'",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("count rows for key");
    assert_eq!(count, 2, "both the Done row and the new row should exist");
}

#[tokio::test]
async fn a_second_enqueue_with_the_same_key_succeeds_once_the_first_row_is_killed() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("dedup-test/{}", Uuid::now_v7());

    let first = attome_jobs::enqueue_dedup(&pool, sample_job("first"), &key)
        .await
        .expect("first enqueue_dedup");
    assert!(first);

    sqlx::query("UPDATE apalis.jobs SET status = 'Killed' WHERE dedup_key = $1")
        .bind(&key)
        .execute(&pool)
        .await
        .expect("mark row Killed");

    let second = attome_jobs::enqueue_dedup(&pool, sample_job("second"), &key)
        .await
        .expect("second enqueue_dedup");
    assert!(
        second,
        "a dead-lettered (Killed) prior row must not block a fresh enqueue under the same key"
    );
}

#[tokio::test]
async fn enqueue_dedup_routes_a_batch_variant_onto_the_batch_queue() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("dedup-test/{}", Uuid::now_v7());

    let inserted = attome_jobs::enqueue_dedup(
        &pool,
        TestJob::Rewrap {
            domain: "mfa".to_owned(),
        },
        &key,
    )
    .await
    .expect("enqueue_dedup");
    assert!(inserted);

    let job_type: String =
        sqlx::query_scalar("SELECT job_type FROM apalis.jobs WHERE dedup_key = $1")
            .bind(&key)
            .fetch_one(&pool)
            .await
            .expect("fetch job_type");
    assert_eq!(job_type, "attome_job_batch");
}

#[tokio::test]
async fn different_dedup_keys_never_collide() {
    let pool = skip_if_no_db!(test_pool().await);
    let key_a = format!("dedup-test/{}", Uuid::now_v7());
    let key_b = format!("dedup-test/{}", Uuid::now_v7());

    assert!(
        attome_jobs::enqueue_dedup(&pool, sample_job("a"), &key_a)
            .await
            .expect("enqueue a")
    );
    assert!(
        attome_jobs::enqueue_dedup(&pool, sample_job("b"), &key_b)
            .await
            .expect("enqueue b"),
        "a distinct key must never be blocked by an unrelated key's row"
    );
}
