//! DB-backed proof tests for M01 Core C-23 ("Error discrimination at the DB
//! boundary"): `attome_db::classify` must turn the four SQLSTATEs it documents
//! into the right `AppError` variant against a real PostgreSQL error, not
//! just a hand-built one — the whole point of this function is to replace
//! the reflexive `AppError::internal(e)` that used to follow a DB call
//! directly at 1,522 sites (`document/xrm/module/M01-core/master-plan.md` §7
//! C-23).
//!
//! Each test gets its own uniquely-named scratch table (D-343: this binary
//! already has a throwaway database of its own — see `attome_testkit::
//! test_db_url` — so no cross-suite collision risk; the unique name is only
//! to let this file's own tests run concurrently with each other without
//! colliding on the same table).
//!
//! Needs a live PostgreSQL, reached through `DATABASE_URL`; skips (does not
//! fail) when that is unset. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test classify
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use attome_types::AppError;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

/// `None` when `DATABASE_URL` is unset, so `cargo test -p attome-db` on a
/// machine with no PostgreSQL skips this rather than failing — same posture
/// as `tests/migration_lock_timeout.rs`'s identical helper.
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

fn unique_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7().simple())
}

/// A duplicate primary key is the plainest real SQLSTATE 23505
/// (unique_violation) PostgreSQL produces — proves `classify` reads the
/// actual driver error code, not just a hand-built one.
#[tokio::test]
async fn unique_violation_classifies_as_conflict() {
    let Some(url) = database_url() else { return };
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let table = unique_name("classify_unique");

    sqlx::query(&format!("CREATE TABLE \"{table}\" (k text PRIMARY KEY)"))
        .execute(&mut conn)
        .await
        .expect("create a table with a primary key");
    sqlx::query(&format!("INSERT INTO \"{table}\" (k) VALUES ('dup')"))
        .execute(&mut conn)
        .await
        .expect("seed the first row");

    let err = sqlx::query(&format!("INSERT INTO \"{table}\" (k) VALUES ('dup')"))
        .execute(&mut conn)
        .await
        .expect_err("a duplicate primary key must fail");

    match attome_db::classify(err) {
        AppError::Conflict(_) => {}
        other => panic!("expected Conflict for SQLSTATE 23505, got {other:?}"),
    }
}

/// A `REFERENCES` violation is a real SQLSTATE 23503 (foreign_key_violation)
/// — the request named a record that does not exist, which `classify` must
/// report as client-actionable (`Validation`), not a masked 500.
#[tokio::test]
async fn foreign_key_violation_classifies_as_validation() {
    let Some(url) = database_url() else { return };
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let parent = unique_name("classify_parent");
    let child = unique_name("classify_child");

    sqlx::query(&format!(
        "CREATE TABLE \"{parent}\" (id integer PRIMARY KEY)"
    ))
    .execute(&mut conn)
    .await
    .expect("create the parent table");
    sqlx::query(&format!(
        "CREATE TABLE \"{child}\" (id integer PRIMARY KEY, parent_id integer REFERENCES \"{parent}\"(id))"
    ))
    .execute(&mut conn)
    .await
    .expect("create the child table with a foreign key");

    let err = sqlx::query(&format!(
        "INSERT INTO \"{child}\" (id, parent_id) VALUES (1, 999)"
    ))
    .execute(&mut conn)
    .await
    .expect_err("inserting a nonexistent parent_id must fail");

    match attome_db::classify(err) {
        AppError::Validation(_) => {}
        other => panic!("expected Validation for SQLSTATE 23503, got {other:?}"),
    }
}

/// A real SERIALIZABLE read-write conflict (40001) or an actual deadlock
/// (40P01) each need two concurrent sessions to reproduce — this raises the
/// exact SQLSTATE PostgreSQL would attach to either, which is the unit
/// `classify`'s match arm actually branches on, without the flakiness of a
/// timing-dependent concurrent reproduction in CI.
async fn raise_with_sqlstate(conn: &mut PgConnection, sqlstate: &str) -> sqlx::Error {
    sqlx::query(&format!(
        "DO $$ BEGIN RAISE EXCEPTION 'simulated for classify() coverage' USING ERRCODE = '{sqlstate}'; END $$;"
    ))
    .execute(conn)
    .await
    .expect_err("the raised exception must surface as a database error")
}

#[tokio::test]
async fn serialization_failure_classifies_as_conflict_with_a_retry_hint() {
    let Some(url) = database_url() else { return };
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");

    let err = raise_with_sqlstate(&mut conn, "40001").await;
    match attome_db::classify(err) {
        AppError::Conflict(msg) => assert!(
            msg.to_ascii_lowercase().contains("retry"),
            "expected a retry hint in the conflict message, got: {msg}"
        ),
        other => panic!("expected Conflict for SQLSTATE 40001, got {other:?}"),
    }
}

#[tokio::test]
async fn deadlock_detected_classifies_as_conflict_with_a_retry_hint() {
    let Some(url) = database_url() else { return };
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");

    let err = raise_with_sqlstate(&mut conn, "40P01").await;
    match attome_db::classify(err) {
        AppError::Conflict(msg) => assert!(
            msg.to_ascii_lowercase().contains("retry"),
            "expected a retry hint in the conflict message, got: {msg}"
        ),
        other => panic!("expected Conflict for SQLSTATE 40P01, got {other:?}"),
    }
}

/// A SQLSTATE `classify` does not recognize (an ordinary "relation does not
/// exist" from querying a table that was never created) must still mask to
/// `Internal` — proof that this function is additive discrimination, never a
/// blanket downgrade of unrecognized DB errors away from a 500.
#[tokio::test]
async fn an_unrecognized_db_error_still_masks_to_internal() {
    let Some(url) = database_url() else { return };
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    let missing = unique_name("classify_missing");

    let err = sqlx::query(&format!("SELECT * FROM \"{missing}\""))
        .execute(&mut conn)
        .await
        .expect_err("querying a table that was never created must fail");

    match attome_db::classify(err) {
        AppError::Internal(_) => {}
        other => panic!("expected Internal for an unrecognized SQLSTATE, got {other:?}"),
    }
}

/// P0-4 (BDB-F6 / 3.1a) — a backend killed mid-statement (a Patroni switchover,
/// an admin `pg_terminate_backend`, an OOM kill) must surface as the retryable
/// 503 `Overloaded("db_unavailable")`, not as an unremarkable masked 500. The
/// production failure is a real switchover; `pg_terminate_backend` is the
/// accepted local substitute (plan §6, "what this environment cannot prove").
#[tokio::test]
async fn a_terminated_backend_is_unavailable_not_internal() {
    let Some(url) = database_url() else { return };
    let mut victim = PgConnection::connect(&url)
        .await
        .expect("connect the session whose backend will be terminated");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut victim)
        .await
        .expect("read the victim backend pid");
    let mut killer = PgConnection::connect(&url)
        .await
        .expect("connect the session that terminates it");

    // The killer waits long enough for the victim's sleep to be in flight, so
    // the failure is a mid-statement loss rather than a clean disconnect
    // between statements.
    let killer_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(&mut killer)
            .await
            .expect("terminate the victim backend");
    });

    let err = sqlx::query("SELECT pg_sleep(10)")
        .execute(&mut victim)
        .await
        .expect_err("a terminated backend must not return the query result");
    killer_task.await.expect("the killer task must not panic");

    match attome_db::classify(err) {
        AppError::Overloaded(breaker) => assert_eq!(
            breaker, "db_unavailable",
            "a lost connection must be Overloaded(\"db_unavailable\"), never db_pool"
        ),
        other => panic!(
            "a backend terminated mid-statement must classify as Overloaded(\"db_unavailable\"), got {other:?}"
        ),
    }
}

static STATEMENT_TIMEOUT_CALLS: AtomicUsize = AtomicUsize::new(0);

fn count_statement_timeout() {
    STATEMENT_TIMEOUT_CALLS.fetch_add(1, Ordering::SeqCst);
}

/// 3.1b (BDB-F6) — a `statement_timeout` abort stays a masked 500 (the
/// database may have done part of the work, so the client must not be told to
/// retry) but is observable: one `event="db.statement_timeout"` warn and the
/// set-once hook `attome-server` uses for its counter. This is the only test in
/// this binary that classifies `57014`, so the counter is deterministic.
#[tokio::test]
async fn a_statement_timeout_is_internal_and_runs_the_hook_once() {
    let Some(url) = database_url() else { return };
    assert!(
        attome_db::set_statement_timeout_hook(count_statement_timeout),
        "the first install must succeed"
    );
    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    sqlx::query("SET statement_timeout = '1ms'")
        .execute(&mut conn)
        .await
        .expect("set a 1ms statement_timeout");
    let err = sqlx::query("SELECT pg_sleep(0.1)")
        .execute(&mut conn)
        .await
        .expect_err("a 1ms statement_timeout must cancel a 100ms sleep");

    match attome_db::classify(err) {
        AppError::Internal(_) => {}
        other => panic!("expected Internal (masked 500) for SQLSTATE 57014, got {other:?}"),
    }
    assert_eq!(
        STATEMENT_TIMEOUT_CALLS.load(Ordering::SeqCst),
        1,
        "classify runs the statement-timeout hook exactly once"
    );
}
