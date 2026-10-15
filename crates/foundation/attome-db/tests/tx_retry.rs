//! Z2-T3: `attome_db::tx::with_retry` runs a transaction again after a
//! serialization failure, and returns any other failure at once.
//!
//! Needs a live PostgreSQL via `DATABASE_URL`; skips (loudly) when unset,
//! except under `ATTOME_TEST_REQUIRE_DB=1`. Each test uses its own table.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::{AtomicUsize, Ordering};

use attome_db::tx::{RetryPolicy, with_retry};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

static RETRIES: AtomicUsize = AtomicUsize::new(0);

fn count_retry(_class: &str) {
    RETRIES.fetch_add(1, Ordering::SeqCst);
}

fn ignore(_class: &str) {}

#[tokio::test]
async fn retries_on_serialization_failure() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    attome_db::set_tx_retry_hooks(attome_db::TxRetryHooks {
        retry: count_retry,
        exhausted: ignore,
    });
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    let table = format!("tx_retry_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE TABLE {table} (id int PRIMARY KEY, v int NOT NULL)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!("INSERT INTO {table} VALUES (1, 0)"))
        .execute(&pool)
        .await
        .unwrap();

    // Two serializable read-then-write transactions on the same row, held
    // open long enough to overlap: one of them must fail with 40001 at
    // least once, and the helper must carry both to success.
    let bump = |pool: sqlx::PgPool, table: String| async move {
        let policy = RetryPolicy {
            max_attempts: 5,
            ..RetryPolicy::SHORT
        };
        with_retry(&pool, "test.bump", policy, |tx| {
            let table = table.clone();
            Box::pin(async move {
                sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                    .execute(&mut **tx)
                    .await?;
                let v: i32 = sqlx::query_scalar(&format!("SELECT v FROM {table} WHERE id = 1"))
                    .fetch_one(&mut **tx)
                    .await?;
                sqlx::query("SELECT pg_sleep(0.2)")
                    .execute(&mut **tx)
                    .await?;
                sqlx::query(&format!("UPDATE {table} SET v = $1 WHERE id = 1"))
                    .bind(v + 1)
                    .execute(&mut **tx)
                    .await?;
                Ok(())
            })
        })
        .await
    };
    let before = RETRIES.load(Ordering::SeqCst);
    let (a, b) = tokio::join!(
        bump(pool.clone(), table.clone()),
        bump(pool.clone(), table.clone())
    );
    a.expect("first bump succeeds");
    b.expect("second bump succeeds");
    let v: i32 = sqlx::query_scalar(&format!("SELECT v FROM {table} WHERE id = 1"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(v, 2, "both increments landed, none lost");
    assert!(RETRIES.load(Ordering::SeqCst) > before, "a retry happened");
}

#[tokio::test]
async fn does_not_retry_unique_violation() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    let table = format!("tx_retry_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE TABLE {table} (id int PRIMARY KEY)"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("INSERT INTO {table} VALUES (1)"))
        .execute(&pool)
        .await
        .unwrap();

    let calls = AtomicUsize::new(0);
    let result = with_retry(&pool, "test.unique", RetryPolicy::SHORT, |tx| {
        calls.fetch_add(1, Ordering::SeqCst);
        let sql = format!("INSERT INTO {table} VALUES (1)");
        Box::pin(async move {
            sqlx::query(&sql).execute(&mut **tx).await?;
            Ok(())
        })
    })
    .await;
    assert!(result.is_err(), "the duplicate key is refused");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a unique violation is not retried"
    );
}
