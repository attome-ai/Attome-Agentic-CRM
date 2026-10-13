//! Integration test for F025's `attome_db::tx::{begin, commit}` helpers:
//! commit persists, and an uncommitted (dropped) transaction rolls back —
//! the guarantee `tx.rs`'s doc comment relies on sqlx to provide.
//!
//! Each test creates its own uniquely named scratch table. Both tests used
//! to run `CREATE TABLE IF NOT EXISTS` on one shared table, which is not
//! concurrency-safe: on a fresh clone the two parallel tests could race into
//! `23505` on `pg_type` (attome-db hardening Phase 1.2).
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when it is
//! unset, except under `ATTOME_TEST_REQUIRE_DB=1` (the older `CI` alias still works); see `attome_testkit` (F-008/TODO-008). Run
//! manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test tx
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use uuid::Uuid;

/// A pool plus a scratch table only this test uses. `None` when there is no
/// throwaway database configured — unwrap with `skip_if_no_db!`, which
/// prints the reason and returns from the test.
async fn test_pool() -> Option<(PgPool, String)> {
    let url = attome_testkit::test_db_url()?;
    let pool = PgPool::connect(&url).await.expect("connect DATABASE_URL");
    let table = format!("tx_helper_test_scratch_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE TABLE \"{table}\" (id uuid primary key, label text not null)"
    ))
    .execute(&pool)
    .await
    .expect("create scratch table");
    Some((pool, table))
}

#[tokio::test]
async fn commit_persists_the_write() {
    let (pool, table) = skip_if_no_db!(test_pool().await);
    let id = Uuid::new_v4();

    let mut tx = attome_db::tx::begin(&pool).await.expect("begin");
    sqlx::query(&format!(
        "INSERT INTO \"{table}\" (id, label) VALUES ($1, 'committed')"
    ))
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("insert inside tx");
    attome_db::tx::commit(tx).await.expect("commit");

    let found: Option<String> =
        sqlx::query_scalar(&format!("SELECT label FROM \"{table}\" WHERE id = $1"))
            .bind(id)
            .fetch_optional(&pool)
            .await
            .expect("query after commit");
    assert_eq!(found.as_deref(), Some("committed"));
}

#[tokio::test]
async fn dropping_an_uncommitted_tx_rolls_back() {
    let (pool, table) = skip_if_no_db!(test_pool().await);
    let id = Uuid::new_v4();

    {
        let mut tx = attome_db::tx::begin(&pool).await.expect("begin");
        sqlx::query(&format!(
            "INSERT INTO \"{table}\" (id, label) VALUES ($1, 'never_committed')"
        ))
        .bind(id)
        .execute(&mut *tx)
        .await
        .expect("insert inside tx");
        // tx dropped here without calling commit — sqlx rolls back on Drop.
    }

    let found: Option<String> =
        sqlx::query_scalar(&format!("SELECT label FROM \"{table}\" WHERE id = $1"))
            .bind(id)
            .fetch_optional(&pool)
            .await
            .expect("query after drop");
    assert_eq!(
        found, None,
        "a transaction dropped without commit must not have persisted its write"
    );
}
