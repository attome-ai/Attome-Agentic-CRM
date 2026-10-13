//! Integration test for D-156 (`P-ha-failover-hardening` follow-up):
//! `attome_db::verify_readonly_identity` must accept a pool whose
//! `current_database()` matches the primary's configured `dbname`, and must
//! refuse (not silently accept) one that doesn't — closing the gap D-155's
//! `readonly.host`/`.port` override opened (an operator typo or stale
//! HAProxy/pgbouncer target could otherwise point `db_readonly` at an
//! unrelated database with nothing catching it at boot).
//!
//! Requires a live Postgres (`DATABASE_URL`) — no replica and no dedicated
//! `attome_readonly` role needed, since this checks `current_database()`
//! identity, not replication state or privileges: the tests read the pool's
//! own `current_database()` and compare against that (accept) or against a
//! name that cannot exist (refuse). Skips (loudly) when `DATABASE_URL` is
//! unset, except under `ATTOME_TEST_REQUIRE_DB=1` (or the older `CI` alias); see `attome_testkit` (F-008/TODO-008) — the same
//! convention as `tests/pool_identity.rs` and `tests/tx.rs`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-db --test readonly_identity
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::db_pool_or_skip;

#[tokio::test]
async fn matching_dbname_is_accepted() {
    let pool = db_pool_or_skip!();

    let (actual_dbname,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("current_database() query must succeed");

    let result = attome_db::verify_readonly_identity(&pool, &actual_dbname).await;
    assert!(
        result.is_ok(),
        "a pool whose current_database() matches the expected dbname must be accepted: {result:?}"
    );
}

#[tokio::test]
async fn mismatched_dbname_is_refused() {
    let pool = db_pool_or_skip!();

    let result =
        attome_db::verify_readonly_identity(&pool, "definitely_not_the_real_dbname_d156").await;
    let err = result.expect_err(
        "a pool whose current_database() does NOT match the expected dbname must be refused, \
         never silently accepted — this is the boot-time guard against a misconfigured \
         database.readonly.host/.port pointing at the wrong database",
    );
    let message = err.to_string();
    assert!(
        message.contains("mismatched database"),
        "error must explain the mismatch so an operator can act on it, got: {message}"
    );
}
