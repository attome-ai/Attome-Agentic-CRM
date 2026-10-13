//! Integration test for `attome_notification::recipient::prune_old_partitions`'s
//! advisory-lock behavior — regression coverage for the fix that replaced a
//! blocking `pg_advisory_xact_lock` with the platform's standard non-blocking
//! `pg_try_advisory_xact_lock` (guidelines §2: never the blocking variant).
//! Before the fix, a second concurrent caller would queue behind the lock
//! holder for up to the 5s `lock_timeout` before erroring; after the fix it
//! returns `Ok(())` immediately as a no-op "another worker already has this"
//! skip.
//!
//! Requires a live Postgres (`DATABASE_URL`) with the platform's migrations
//! already applied — same convention as `tests/dispatch.rs`.
//! **Not run in this session (code-only, no DB access) — TODO: run against a
//! throwaway database before relying on this as verified.**
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-notification --test recipient_retention -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_db::DbPool;
use attome_notification::recipient::prune_old_partitions;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// The same (namespace, key) pair `prune_old_partitions` acquires, held open
/// by this test's own transaction to simulate a concurrent worker already
/// mid-prune. Both halves come from the crate's own constants (L-1 /
/// TODO-027) rather than being re-typed here — a drifted copy would take an
/// unrelated lock and this test would silently stop testing contention. The
/// blocking form is deliberate and confined to this holder: the point is to
/// *hold* the lock, not to probe for it.
const LOCK_SQL: &str = "SELECT pg_advisory_xact_lock($1, hashtext($2))";

#[tokio::test]
async fn skips_without_blocking_when_another_worker_holds_the_lock() {
    let db = skip_if_no_db!(test_db().await);

    let mut holder_tx = db.begin().await.expect("begin lock-holding tx");
    sqlx::query(LOCK_SQL)
        .bind(attome_notification::ADVISORY_LOCK_NAMESPACE)
        .bind(attome_notification::recipient::RETENTION_LOCK_KEY)
        .execute(&mut *holder_tx)
        .await
        .expect("acquire the retention lock in the holding tx");

    // The old blocking `pg_advisory_xact_lock` would wait up to the 5s
    // `lock_timeout` here; the fixed non-blocking `pg_try_advisory_xact_lock`
    // must return almost immediately with a no-op `Ok(())`.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        prune_old_partitions(&db, /* retention_days */ 30),
    )
    .await
    .expect("prune_old_partitions must return promptly, not block on the held lock");

    assert!(
        result.is_ok(),
        "losing the race for the advisory lock must be a clean no-op, got {result:?}"
    );

    holder_tx.rollback().await.expect("release the held lock");
}
