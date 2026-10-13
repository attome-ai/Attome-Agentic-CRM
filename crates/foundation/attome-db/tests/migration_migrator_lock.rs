//! Base-db hardening Phase 3.1: how `attome_db::run_migrations` waits for a
//! **peer migrator**, as opposed to a conflicting table lock
//! (`tests/migration_lock_timeout.rs`).
//!
//! sqlx's migrator takes a database-wide session advisory lock
//! (`Migrate::lock`, keyed on `current_database()`) before it does anything
//! else, so two processes migrating the same database serialize on it. With
//! `lock_timeout` in force, a waiting run sees that as a `55P03` from sqlx's
//! own bookkeeping (`MigrateError::Execute`), which `run_migrations` treats as
//! "a peer is migrating, keep waiting" under `MIGRATOR_LOCK_BUDGET` (600s in
//! production). A conflicting *table* lock surfaces from the migration's own
//! SQL (`MigrateError::ExecuteMigration`) and gets only `DDL_LOCK_ATTEMPTS`
//! (3) tries.
//!
//! Proven here, against a live PostgreSQL, with a test session holding the
//! exact lock a peer migrator would (`Migrate::lock`):
//!
//! 1. With a budget far below one `lock_timeout` window, the run fails after
//!    that first window with the *migrator-lock* error class (`Execute`,
//!    `55P03`), and applies nothing.
//! 2. With the production budget (`run_migrations` itself), the run keeps
//!    waiting past the point where a table-lock wait would have given up
//!    (three 5s windows plus backoff, about 15.5s). It succeeds once the peer
//!    releases, and applies the migration exactly once.
//!
//! The 600s value itself is pinned by `migrate::tests` (no database needed).
//!
//! One sequential test: the lock is database-wide, so parallel scenarios in
//! this binary would block each other. This binary has its own throwaway
//! database (D-343), so other suites aren't affected. The fixture migration
//! runs in a per-run schema, like `tests/migration_lock_timeout.rs`, because
//! the throwaway clone already carries the platform's own `_sqlx_migrations`.
//!
//! Requires a live PostgreSQL (`DATABASE_URL`); skips when unset, except
//! under `ATTOME_TEST_REQUIRE_DB=1` (or the older `CI` alias). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test migration_migrator_lock
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::str::FromStr;
use std::time::{Duration, Instant};

use sqlx::migrate::{Migrate, MigrateError};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("tests/fixtures/lock_timeout_migrations");

/// P0-5 (BDB-F14): `0001` succeeds, `0002` fails at execution time — a
/// non-lock failure, which `run_migrations` returns without reaching its own
/// `pg_advisory_unlock_all()`.
static FAILING_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("tests/fixtures/failing_migrations");

/// When the simulated peer migrator releases its lock in scenario 2. Chosen so
/// the waiting run's fourth attempt is in flight: a table-lock wait would
/// already have failed after its third attempt (about 15.5s).
const PEER_RELEASES_AFTER: Duration = Duration::from_secs(17);

/// Past three `lock_timeout` windows plus backoff. A run that returns
/// successfully after this long has outlasted the table-lock retry budget.
const PAST_THE_TABLE_LOCK_BUDGET: Duration = Duration::from_secs(16);

fn database_url() -> Option<String> {
    let url = attome_testkit::test_db_url();
    if url.is_none() {
        eprintln!(
            "SKIP {}: set DATABASE_URL to a throwaway test database to run this \
             (NEVER attome_dev)",
            module_path!()
        );
    }
    url
}

fn options_for_schema(url: &str, schema: &str) -> PgConnectOptions {
    PgConnectOptions::from_str(url)
        .expect("DATABASE_URL must parse as a PostgreSQL connection string")
        .options([("search_path", schema)])
}

async fn probe_column_exists(pool: &PgPool, schema: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = $1 AND table_name = 'lock_timeout_victim' AND column_name = 'probe')",
    )
    .bind(schema)
    .fetch_one(pool)
    .await
    .expect("inspect the fixture table")
}

fn sqlstate(source: &sqlx::Error) -> Option<String> {
    source
        .as_database_error()
        .and_then(|dbe| dbe.code())
        .map(|code| code.to_string())
}

#[tokio::test]
async fn a_waiting_migrator_is_bounded_by_the_peer_budget_not_the_table_lock_budget() {
    let Some(url) = database_url() else { return };
    let schema = format!("migrator_lock_{}", Uuid::now_v7().simple());

    let mut admin = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&mut admin)
        .await
        .expect("create the isolated test schema");
    let pool: PgPool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options_for_schema(&url, &schema))
        .await
        .expect("open a pool scoped to the isolated test schema");
    sqlx::query("CREATE TABLE lock_timeout_victim (id integer PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("create the table the fixture migration alters");

    // The simulated peer: holds the database-wide migrator lock, exactly as a
    // concurrent `migrate` job or booting node would while applying migrations.
    let mut peer = PgConnection::connect(&url)
        .await
        .expect("connect the simulated peer migrator");
    peer.lock()
        .await
        .expect("the simulated peer must take the migrator lock");

    // Scenario 1: a budget below one lock_timeout window.
    let started = Instant::now();
    let outcome = attome_db::run_migrations_with_migrator_lock_budget(
        &pool,
        &MIGRATOR,
        Duration::from_secs(1),
    )
    .await;
    let elapsed = started.elapsed();
    match &outcome {
        Err(MigrateError::Execute(source)) => assert_eq!(
            sqlstate(source).as_deref(),
            Some("55P03"),
            "a peer-held migrator lock must surface as lock_not_available, got: {source}"
        ),
        other => panic!(
            "with the peer holding the lock and a 1s budget, expected the migrator-lock error \
             class (MigrateError::Execute, 55P03), got: {other:?}"
        ),
    }
    assert!(
        elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_secs(15),
        "the run must give up after one 5s lock_timeout window once the budget is spent, took \
         {elapsed:?}"
    );
    assert!(
        !probe_column_exists(&pool, &schema).await,
        "a run that never got the migrator lock must not have applied anything"
    );

    // Scenario 2: the production budget. The peer releases after
    // PEER_RELEASES_AFTER; the run must still be waiting then, and succeed.
    let release = tokio::spawn(async move {
        tokio::time::sleep(PEER_RELEASES_AFTER).await;
        peer.unlock()
            .await
            .expect("the simulated peer must release the migrator lock");
        let _ = peer.close().await;
    });
    let started = Instant::now();
    let outcome = attome_db::run_migrations(&pool, &MIGRATOR).await;
    let elapsed = started.elapsed();
    release.await.expect("peer release task must not panic");

    outcome.expect(
        "run_migrations must wait out a peer migrator under the production budget and then \
         succeed",
    );
    assert!(
        elapsed >= PAST_THE_TABLE_LOCK_BUDGET,
        "run_migrations returned after {elapsed:?}; it must have kept waiting past the \
         table-lock retry budget until the peer released at {PEER_RELEASES_AFTER:?}"
    );
    assert!(
        probe_column_exists(&pool, &schema).await,
        "once the peer released, the migration must have applied"
    );
    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success = true")
            .fetch_one(&pool)
            .await
            .expect("read the sqlx bookkeeping table");
    assert_eq!(applied, 1, "the migration must be recorded exactly once");

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
        .execute(&mut admin)
        .await
        .expect("drop the isolated test schema");
    admin.close().await.expect("close the admin connection");
}

/// P0-5 (BDB-F14) — a migration run that fails for a reason other than a
/// lock conflict returns before `run_migrations`' own
/// `pg_advisory_unlock_all()`, and sqlx unlocks only on success. The pinned
/// session therefore still holds the migrator advisory lock (and the
/// `statement_timeout`/`lock_timeout` `SET`s) at that point; it must never go
/// back into the caller's pool. `max_connections(1)` makes the check
/// deterministic: the next acquire can only be the same session if it was
/// returned.
#[tokio::test]
async fn a_failed_run_leaves_no_advisory_lock_in_the_pool() {
    let Some(url) = database_url() else { return };
    let schema = format!("migrator_failure_{}", Uuid::now_v7().simple());

    let mut admin = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&mut admin)
        .await
        .expect("create the isolated test schema");
    let pool: PgPool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options_for_schema(&url, &schema))
        .await
        .expect("open a single-connection pool scoped to the isolated test schema");

    let first = attome_db::run_migrations(&pool, &FAILING_MIGRATOR).await;
    assert!(
        first.is_err(),
        "the invalid second migration must fail the run, got: {first:?}"
    );

    // Whatever session the pool hands out next must hold no advisory lock on
    // itself: before BDB-F14's fix this was the pinned session, returned to the
    // pool still holding sqlx's migrator lock.
    let advisory_locks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect the session the pool hands out after the failed run");
    assert_eq!(
        advisory_locks, 0,
        "a failed migration run must not return a session holding its advisory lock to the pool"
    );

    // And the failure is repeatable rather than a one-off: a re-run acquires a
    // clean session, skips the applied 0001 and fails on 0002 again instead of
    // hanging on a lock the pool still owned.
    let second = attome_db::run_migrations(&pool, &FAILING_MIGRATOR).await;
    assert!(
        second.is_err(),
        "a re-run must fail on the invalid migration, not silently succeed: {second:?}"
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
        .execute(&mut admin)
        .await
        .expect("drop the isolated test schema");
    admin.close().await.expect("close the admin connection");
}
