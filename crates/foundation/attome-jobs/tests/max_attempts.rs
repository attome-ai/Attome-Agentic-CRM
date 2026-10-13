//! BJB-P0.2 (attome-jobs plan, Phase 0) — the failing test that proves BJB-F3:
//! a job kind's retry budget depends on which enqueue path was used, not on
//! the kind.
//!
//! Today `enqueue` writes `SqlContext::default()`'s `max_attempts` (5) because
//! `attome_jobs` never calls `ctx.set_max_attempts`; the other three paths let
//! `apalis.push_job`/`push_job_dedup`'s SQL parameter default stand (25). So
//! the same `TestJob` gets a 5-attempt budget through one producer and a
//! 25-attempt budget through another — a difference nobody chose and nothing
//! documents. BJB-2 fixes it by declaring the budget once, on
//! `TestJob::max_attempts()` (BJB-D2), and binding it on all four paths.
//!
//! The expected value below is the literal BJB-D2 number on purpose: this
//! test must compile and FAIL against the current code rather than fail to
//! compile against a `max_attempts()` that does not exist yet.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! Run: `cargo test -p attome-jobs --test max_attempts -- --test-threads=1`

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

use attome_testkit::skip_if_no_db;
use common::TestJob;
use sqlx::PgPool;
use uuid::Uuid;

/// BJB-D2: `RunWorkflow` is 10 (today 5 by accident through `enqueue` and
/// 25 through every other path).
const EXPECTED_MAX_ATTEMPTS: i32 = 10;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

fn sample_job() -> TestJob {
    TestJob::RunWorkflow {
        instance_id: Uuid::now_v7(),
    }
}

/// The one row the path under test just wrote. Each phase truncates first, so
/// the single row is unambiguously that path's.
async fn sole_max_attempts(pool: &PgPool) -> i32 {
    sqlx::query_scalar("SELECT max_attempts FROM apalis.jobs WHERE job_type = 'attome_job'")
        .fetch_one(pool)
        .await
        .expect("exactly one row was enqueued by the path under test")
}

#[tokio::test]
async fn all_four_enqueue_paths_write_the_same_max_attempts() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut jobs = attome_jobs::Jobs::<TestJob>::new(pool.clone());

    // ── path 1: enqueue (apalis Storage::push_request) ──────────────────────
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate");
    attome_jobs::enqueue(&mut jobs, sample_job())
        .await
        .expect("enqueue");
    let via_enqueue = sole_max_attempts(&pool).await;

    // ── path 2: enqueue_in_tx (apalis.push_job) ─────────────────────────────
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate");
    let mut tx = pool.begin().await.expect("begin");
    attome_jobs::enqueue_in_tx(&mut tx, sample_job())
        .await
        .expect("enqueue_in_tx");
    tx.commit().await.expect("commit");
    let via_enqueue_in_tx = sole_max_attempts(&pool).await;

    // ── path 3: enqueue_dedup (apalis.push_job_dedup) ───────────────────────
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate");
    attome_jobs::enqueue_dedup(
        &pool,
        sample_job(),
        &format!("max-attempts/{}", Uuid::now_v7()),
    )
    .await
    .expect("enqueue_dedup");
    let via_enqueue_dedup = sole_max_attempts(&pool).await;

    // ── path 4: enqueue_in_tx_dedup (apalis.push_job_dedup) ─────────────────
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate");
    let mut tx = pool.begin().await.expect("begin");
    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        sample_job(),
        &format!("max-attempts/{}", Uuid::now_v7()),
    )
    .await
    .expect("enqueue_in_tx_dedup");
    tx.commit().await.expect("commit");
    let via_enqueue_in_tx_dedup = sole_max_attempts(&pool).await;

    assert_eq!(
        (
            via_enqueue,
            via_enqueue_in_tx,
            via_enqueue_dedup,
            via_enqueue_in_tx_dedup
        ),
        (
            EXPECTED_MAX_ATTEMPTS,
            EXPECTED_MAX_ATTEMPTS,
            EXPECTED_MAX_ATTEMPTS,
            EXPECTED_MAX_ATTEMPTS
        ),
        "the same job kind must write the same max_attempts on every enqueue path \
         (enqueue={via_enqueue}, enqueue_in_tx={via_enqueue_in_tx}, \
         enqueue_dedup={via_enqueue_dedup}, enqueue_in_tx_dedup={via_enqueue_in_tx_dedup})"
    );
}

/// attome-email BEM-17 — `is_final_attempt` must agree with apalis-sql's own
/// kill rule (`max_attempts <= attempt` after an `Err`, with `attempt` the
/// 1-based `Attempt::current()` the handler sees), or a `SendEmail` row is
/// either closed out one attempt early or left `queued` after its last try.
#[tokio::test]
async fn the_final_attempt_is_the_one_whose_failure_dead_letters() {
    let pool = skip_if_no_db!(test_pool().await);
    let key = format!("final-attempt/{}", Uuid::now_v7());
    attome_jobs::enqueue_dedup(&pool, sample_job(), &key)
        .await
        .expect("enqueue_dedup");
    let id: String = sqlx::query_scalar("SELECT id FROM apalis.jobs WHERE dedup_key = $1")
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("the enqueued row");

    let at = |attempt| attome_jobs::is_final_attempt(&pool, &id, attempt);
    assert!(!at(1).await.expect("query"));
    assert!(!at(EXPECTED_MAX_ATTEMPTS as usize - 1).await.expect("query"));
    assert!(at(EXPECTED_MAX_ATTEMPTS as usize).await.expect("query"));
    assert!(at(EXPECTED_MAX_ATTEMPTS as usize + 1).await.expect("query"));
    assert!(
        !attome_jobs::is_final_attempt(&pool, "no-such-job", 99)
            .await
            .expect("query"),
        "a row that no longer exists has no retry left to protect"
    );

    sqlx::query("DELETE FROM apalis.jobs WHERE id = $1")
        .bind(&id)
        .execute(&pool)
        .await
        .expect("cleanup");
}
