//! Integration tests for attome-db hardening Phase 1.2: `attome_db::tx::begin`
//! and `attome_db::tx::commit` classify errors through `attome_db::classify`
//! against real pool and PostgreSQL failures, not hand-built errors.
//!
//! - A pool that can't hand out a connection (acquire timeout, or closed) is
//!   `AppError::Overloaded("db_pool")`, a 503.
//! - A commit-time serialization failure is the retryable 409, and a
//!   commit-time unique violation is a 409. Neither can happen in production
//!   code today (no `DEFERRABLE` constraints, no non-default isolation), so
//!   these prove the defensive mapping with test-only tables.
//!
//! Each test uses its own uniquely named table, so the tests can run in
//! parallel inside this binary's throwaway database (D-343). Needs a live
//! PostgreSQL via `DATABASE_URL`; skips (loudly) when unset, except under
//! `ATTOME_TEST_REQUIRE_DB=1` (the older `CI` alias still works). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test tx_errors
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

fn unique_table(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7().simple())
}

async fn pool_with(url: &str, max_connections: u32, acquire_timeout: Duration) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(acquire_timeout)
        .connect(url)
        .await
        .expect("connect to the test database")
}

async fn exec(tx: &mut Transaction<'_, Postgres>, sql: &str) {
    sqlx::query(sql)
        .execute(&mut **tx)
        .await
        .unwrap_or_else(|e| panic!("`{sql}` must succeed: {e}"));
}

#[tokio::test]
async fn begin_on_an_exhausted_pool_is_overloaded() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = pool_with(&url, 1, Duration::from_millis(200)).await;
    let _held = pool
        .acquire()
        .await
        .expect("take the pool's only connection");

    match attome_db::tx::begin(&pool).await {
        Err(AppError::Overloaded(breaker)) => assert_eq!(breaker, "db_pool"),
        Err(other) => panic!("an exhausted pool must be Overloaded(\"db_pool\"), got {other:?}"),
        Ok(_) => panic!("begin must not succeed while the only connection is held"),
    }
}

#[tokio::test]
async fn begin_on_a_closed_pool_is_overloaded() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = pool_with(&url, 1, Duration::from_secs(5)).await;
    pool.close().await;

    match attome_db::tx::begin(&pool).await {
        Err(AppError::Overloaded(breaker)) => assert_eq!(breaker, "db_pool"),
        Err(other) => panic!("a closed pool must be Overloaded(\"db_pool\"), got {other:?}"),
        Ok(_) => panic!("begin must not succeed on a closed pool"),
    }
}

/// The classic SERIALIZABLE write skew: both transactions read the same
/// predicate, both insert into it, T1 commits, and PostgreSQL's SSI cancels
/// T2 at its commit. If PostgreSQL ever raises `40001` at T2's INSERT
/// instead, `exec` panics and this test fails loudly rather than passing
/// without exercising `tx::commit`.
#[tokio::test]
async fn commit_time_serialization_failure_is_a_retryable_conflict() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = pool_with(&url, 3, Duration::from_secs(5)).await;
    let table = unique_table("tx_errors_skew");
    sqlx::query(&format!(
        "CREATE TABLE \"{table}\" (k text NOT NULL, v int NOT NULL)"
    ))
    .execute(&pool)
    .await
    .expect("create the scratch table");

    let mut t1 = attome_db::tx::begin(&pool).await.expect("begin T1");
    let mut t2 = attome_db::tx::begin(&pool).await.expect("begin T2");
    exec(&mut t1, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE").await;
    exec(&mut t2, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE").await;
    let count = format!("SELECT count(*) FROM \"{table}\" WHERE k = 'x'");
    exec(&mut t1, &count).await;
    exec(&mut t2, &count).await;
    exec(&mut t1, &format!("INSERT INTO \"{table}\" VALUES ('x', 1)")).await;
    exec(&mut t2, &format!("INSERT INTO \"{table}\" VALUES ('x', 2)")).await;
    attome_db::tx::commit(t1).await.expect("T1 commits first");

    match attome_db::tx::commit(t2).await {
        Err(AppError::Conflict(message)) => assert!(
            message.to_ascii_lowercase().contains("retry"),
            "a serialization failure must carry a retry hint, got: {message}"
        ),
        Err(other) => panic!("a commit-time 40001 must be a retryable Conflict, got {other:?}"),
        Ok(()) => panic!("T2's commit must fail with a serialization failure"),
    }
}

/// A `DEFERRABLE INITIALLY DEFERRED` unique constraint is checked at commit,
/// so the duplicate surfaces from `tx::commit`, not from the INSERT.
#[tokio::test]
async fn commit_time_unique_violation_is_a_conflict() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = pool_with(&url, 1, Duration::from_secs(5)).await;
    let table = unique_table("tx_errors_deferred");
    sqlx::query(&format!(
        "CREATE TABLE \"{table}\" (k text NOT NULL, \
         CONSTRAINT \"{table}_k_key\" UNIQUE (k) DEFERRABLE INITIALLY DEFERRED)"
    ))
    .execute(&pool)
    .await
    .expect("create the scratch table with a deferred unique constraint");

    let mut tx = attome_db::tx::begin(&pool).await.expect("begin");
    exec(&mut tx, &format!("INSERT INTO \"{table}\" VALUES ('dup')")).await;
    exec(&mut tx, &format!("INSERT INTO \"{table}\" VALUES ('dup')")).await;

    match attome_db::tx::commit(tx).await {
        Err(AppError::Conflict(_)) => {}
        Err(other) => panic!("a commit-time 23505 must be a Conflict, got {other:?}"),
        Ok(()) => panic!("the deferred unique constraint must reject the commit"),
    }
}
