//! attome-db hardening 4.3: the acquire-timeout hook runs once for every pool
//! acquire timeout that reaches `attome_db::classify` or `attome_db::tx::begin`,
//! and never for any other error.
//!
//! One test function on purpose: the hook is process-wide and set-once, so
//! separate tests in this binary would race on the shared counter. The pure
//! `classify` half runs everywhere; the `tx::begin` half needs a live
//! PostgreSQL via `DATABASE_URL` and skips (loudly) when unset, except under
//! except under `ATTOME_TEST_REQUIRE_DB=1` (the older `CI` alias still works). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test acquire_timeout_hook
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use sqlx::postgres::PgPoolOptions;

static CALLS: AtomicUsize = AtomicUsize::new(0);

fn count_call() {
    CALLS.fetch_add(1, Ordering::SeqCst);
}

fn calls() -> usize {
    CALLS.load(Ordering::SeqCst)
}

#[tokio::test]
async fn the_hook_runs_once_per_acquire_timeout_and_never_otherwise() {
    assert!(
        attome_db::set_acquire_timeout_hook(count_call),
        "the first install must succeed"
    );
    assert!(
        !attome_db::set_acquire_timeout_hook(count_call),
        "the hook is set-once"
    );

    let _ = attome_db::classify(sqlx::Error::PoolClosed);
    let _ = attome_db::classify(sqlx::Error::RowNotFound);
    assert_eq!(calls(), 0, "only an acquire timeout runs the hook");

    match attome_db::classify(sqlx::Error::PoolTimedOut) {
        AppError::Overloaded(breaker) => assert_eq!(breaker, "db_pool"),
        other => panic!("PoolTimedOut must stay Overloaded(\"db_pool\"), got {other:?}"),
    }
    assert_eq!(
        calls(),
        1,
        "classify runs the hook once per acquire timeout"
    );

    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(200))
        .connect(&url)
        .await
        .expect("connect to the test database");
    let _held = pool
        .acquire()
        .await
        .expect("take the pool's only connection");

    match attome_db::tx::begin(&pool).await {
        Err(AppError::Overloaded(breaker)) => assert_eq!(breaker, "db_pool"),
        Err(other) => panic!("an exhausted pool must be Overloaded(\"db_pool\"), got {other:?}"),
        Ok(_) => panic!("begin must not succeed while the only connection is held"),
    }
    assert_eq!(
        calls(),
        2,
        "tx::begin runs the hook exactly once, not a second time through classify"
    );
}
