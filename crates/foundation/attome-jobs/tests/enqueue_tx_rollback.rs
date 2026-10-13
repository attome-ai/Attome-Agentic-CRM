//! BJB-16 (attome-jobs plan, Phase 5) — the transactional enqueue contract:
//! `enqueue_in_tx` writes the job row in the caller's transaction, so a
//! rollback takes it with it. That is the whole reason the `_in_tx` paths
//! exist (guidelines §9: a job that is the durable follow-up to a metadata
//! write must become visible at the same commit), and it was the one public
//! function in `lib.rs` with no DB-backed test.
//!
//! Run: `cargo test -p attome-jobs --test enqueue_tx_rollback -- --test-threads=1`

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

async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// A job whose payload carries `marker`, so the row this test writes is
/// findable even against a queue that already holds other rows.
fn marked_job(marker: &str) -> TestJob {
    TestJob::BuildIndex {
        entity_logicalname: marker.to_string(),
        field_logicalname: "rollback_test_field".to_string(),
    }
}

async fn rows_for(pool: &PgPool, marker: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM apalis.jobs WHERE job::text LIKE $1")
        .bind(format!("%{marker}%"))
        .fetch_one(pool)
        .await
        .expect("count rows carrying the marker")
}

#[tokio::test]
async fn a_rolled_back_enqueue_in_tx_leaves_no_row() {
    let pool = skip_if_no_db!(test_pool().await);
    let marker = format!("rollback-{}", Uuid::now_v7());

    let mut tx = pool.begin().await.expect("begin");
    attome_jobs::enqueue_in_tx(&mut tx, marked_job(&marker))
        .await
        .expect("enqueue_in_tx");
    tx.rollback().await.expect("rollback");

    assert_eq!(
        rows_for(&pool, &marker).await,
        0,
        "a rolled-back transaction must leave no job row behind"
    );
}

#[tokio::test]
async fn a_committed_enqueue_in_tx_row_is_visible() {
    let pool = skip_if_no_db!(test_pool().await);
    let marker = format!("commit-{}", Uuid::now_v7());

    let mut tx = pool.begin().await.expect("begin");
    attome_jobs::enqueue_in_tx(&mut tx, marked_job(&marker))
        .await
        .expect("enqueue_in_tx");
    tx.commit().await.expect("commit");

    assert_eq!(
        rows_for(&pool, &marker).await,
        1,
        "a committed enqueue_in_tx row is durable"
    );
}

#[tokio::test]
async fn a_rolled_back_enqueue_in_tx_dedup_leaves_no_row() {
    let pool = skip_if_no_db!(test_pool().await);
    let marker = format!("rollback-dedup-{}", Uuid::now_v7());

    let mut tx = pool.begin().await.expect("begin");
    let inserted = attome_jobs::enqueue_in_tx_dedup(&mut tx, marked_job(&marker), &marker)
        .await
        .expect("enqueue_in_tx_dedup");
    assert!(inserted, "a fresh dedup key inserts a row");
    tx.rollback().await.expect("rollback");

    assert_eq!(
        rows_for(&pool, &marker).await,
        0,
        "the dedup path must be just as transactional as the plain one"
    );
}
