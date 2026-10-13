//! attome-db hardening 4.3 — `build_layer_and_handle` installs attome-db's
//! acquire-timeout hook, so a pool acquire timeout that reaches
//! `attome_db::classify` shows up as `db_pool_acquire_timeouts_total`.
//!
//! Its own test binary because the recorder and the hook are both
//! process-wide and install once; sharing a binary with `tests/metrics.rs`
//! would install the recorder twice. No live DB/Redis needed: the timeout is
//! a constructed `sqlx::Error::PoolTimedOut`. Run:
//! `cargo test -p attome-server --test db_pool_acquire_timeout_metric`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::build_layer_and_handle;
use attome_types::AppError;

#[tokio::test]
async fn a_pool_acquire_timeout_increments_the_counter() {
    let (_layer, handle) = build_layer_and_handle();

    match attome_db::classify(sqlx::Error::PoolTimedOut) {
        AppError::Overloaded(breaker) => assert_eq!(breaker, "db_pool"),
        other => panic!("PoolTimedOut must stay Overloaded(\"db_pool\"), got {other:?}"),
    }
    // A closed pool is not an acquire timeout, so it must not be counted.
    let _ = attome_db::classify(sqlx::Error::PoolClosed);

    let rendered = handle.render();
    assert!(
        rendered.contains("db_pool_acquire_timeouts_total 1"),
        "expected exactly one counted acquire timeout in the render output, got:\n{rendered}"
    );
}
