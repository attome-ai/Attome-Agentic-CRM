//! Integration test for the P-db-privilege-separation follow-up:
//! `attome_db::verify_pool_identity` must accept a pool whose `current_user`
//! and `current_database()` both match what config expects, and must refuse
//! (not silently accept) either one not matching — closing the gap where the
//! boot-time `database.runtime`/`.migrator`/`.readonly` checks only
//! confirmed the config *block* was present, never that the resulting pool
//! actually connects as the identity it claims to.
//!
//! Requires a live Postgres (`DATABASE_URL`) — any role, any database: the
//! subject is `verify_pool_identity`'s comparison of what the pool *reports*
//! against what the caller *expects*, so the tests read the pool's own
//! `current_user`/`current_database()` and compare against that (accept) or
//! against a name that cannot exist (refuse). No dedicated
//! `attome_readonly`/runtime role is needed. Skips (loudly) when
//! `DATABASE_URL` is unset, except under `ATTOME_TEST_REQUIRE_DB=1` (the older `CI` alias still works); see `attome_testkit`
//! (F-008/TODO-008) — the same convention as `tests/readonly_identity.rs`
//! and `tests/tx.rs`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-db --test pool_identity
//! ```

use attome_testkit::db_pool_or_skip;

#[tokio::test]
async fn matching_user_and_dbname_is_accepted() {
    let pool = db_pool_or_skip!();

    let (actual_user, actual_dbname): (String, String) =
        sqlx::query_as("SELECT current_user, current_database()")
            .fetch_one(&pool)
            .await
            .expect("current_user/current_database() query must succeed");

    let result = attome_db::verify_pool_identity(&pool, &actual_user, &actual_dbname).await;
    assert!(
        result.is_ok(),
        "a pool whose current_user/current_database() match the expected identity must be \
         accepted: {result:?}"
    );
}

#[tokio::test]
async fn mismatched_user_is_refused() {
    let pool = db_pool_or_skip!();

    let (actual_dbname,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("current_database() query must succeed");

    let result =
        attome_db::verify_pool_identity(&pool, "definitely_not_the_real_role_d117", &actual_dbname)
            .await;
    let err = result.expect_err(
        "a pool whose current_user does NOT match the expected role must be refused, never \
         silently accepted — this is the boot-time guard against a stale DATABASE_URL or a \
         database.runtime/.migrator/.readonly credential mismatch",
    );
    let message = err.to_string();
    assert!(
        message.contains("database identity mismatch"),
        "error must explain the mismatch so an operator can act on it, got: {message}"
    );
}

#[tokio::test]
async fn mismatched_dbname_is_refused() {
    let pool = db_pool_or_skip!();

    let (actual_user,): (String,) = sqlx::query_as("SELECT current_user")
        .fetch_one(&pool)
        .await
        .expect("current_user query must succeed");

    let result =
        attome_db::verify_pool_identity(&pool, &actual_user, "definitely_not_the_real_dbname_d117")
            .await;
    let err = result.expect_err(
        "a pool whose current_database() does NOT match the expected database must be refused",
    );
    let message = err.to_string();
    assert!(
        message.contains("database identity mismatch"),
        "error must explain the mismatch so an operator can act on it, got: {message}"
    );
}
