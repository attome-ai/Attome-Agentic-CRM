//! 3.19 — `attome_content::hierarchy::try_lock_trees` keys the page-tree
//! advisory lock on a tree's content space instead of one lock for the
//! whole installation, so reparents in unrelated spaces no longer make each
//! other a `Conflict`. Lives here rather than in `attome-content` because that
//! crate has no async test runtime of its own (no `tokio` dev-dependency);
//! `attome-api` depends on it and already has one.
//!
//! Needs only a Postgres (`DATABASE_URL`, a throwaway database — NEVER
//! attome_dev): advisory locks are session state, no table is touched. Two
//! dedicated connections stand in for two concurrent admin requests, each
//! inside its own transaction the way `admin::move_page` runs. Skips loudly
//! without `DATABASE_URL`, panics under `CI` (see `attome_testkit`).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test content_hierarchy_lock -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_content::hierarchy::{try_lock_hierarchy, try_lock_trees};
use attome_testkit::skip_if_no_db;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

/// A connection outside any pool, so its transaction is exactly one
/// simulated request's — `pg_try_advisory_xact_lock` is scoped to the
/// transaction, and a pooled connection could hand the same session to
/// both "requests".
async fn dedicated_connection() -> Option<PgConnection> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgConnection::connect(&url)
            .await
            .expect("connect a dedicated test connection"),
    )
}

async fn begin(conn: &mut PgConnection) {
    sqlx::query("BEGIN").execute(conn).await.expect("BEGIN");
}

async fn rollback(conn: &mut PgConnection) {
    sqlx::query("ROLLBACK")
        .execute(conn)
        .await
        .expect("ROLLBACK");
}

/// The fix itself: two different trees mutate concurrently, and neither
/// sees a `Conflict` from the other. Under the old single key the second
/// acquisition here was `false`.
#[tokio::test]
async fn two_different_trees_lock_concurrently_without_conflict() {
    let mut request_a = skip_if_no_db!(dedicated_connection().await);
    let mut request_b = skip_if_no_db!(dedicated_connection().await);
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();

    begin(&mut request_a).await;
    begin(&mut request_b).await;

    assert!(
        try_lock_trees(&mut request_a, &[space_a])
            .await
            .expect("lock tree A"),
        "an uncontended tree must lock"
    );
    assert!(
        try_lock_trees(&mut request_b, &[space_b])
            .await
            .expect("lock tree B"),
        "a reparent in space B must proceed while a reparent in space A is in \
         flight — the whole point of keying the lock per tree (3.19)"
    );

    // The same tree, from another transaction, is still serialized.
    assert!(
        !try_lock_trees(&mut request_b, &[space_a])
            .await
            .expect("contend on tree A"),
        "a second mutation of the SAME tree must still be refused while the \
         first holds it"
    );

    rollback(&mut request_a).await;
    rollback(&mut request_b).await;
}

/// A mutation spanning two trees takes both locks, and a holder of either
/// one blocks it — from whichever side, since the keys are requested in
/// sorted order rather than argument order.
#[tokio::test]
async fn a_cross_tree_mutation_conflicts_with_a_holder_of_either_tree() {
    let mut holder = skip_if_no_db!(dedicated_connection().await);
    let mut mover = skip_if_no_db!(dedicated_connection().await);
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();

    for held in [space_a, space_b] {
        begin(&mut holder).await;
        begin(&mut mover).await;
        assert!(
            try_lock_trees(&mut holder, &[held])
                .await
                .expect("hold one tree")
        );
        assert!(
            !try_lock_trees(&mut mover, &[space_a, space_b])
                .await
                .expect("cross-tree attempt"),
            "a move touching trees A and B must be refused while {held} is held"
        );
        assert!(
            !try_lock_trees(&mut mover, &[space_b, space_a])
                .await
                .expect("cross-tree attempt, reversed"),
            "argument order must not change the outcome"
        );
        rollback(&mut holder).await;
        rollback(&mut mover).await;
    }

    // Once nobody holds either, the cross-tree mutation takes both.
    begin(&mut mover).await;
    begin(&mut holder).await;
    assert!(
        try_lock_trees(&mut mover, &[space_b, space_a])
            .await
            .expect("cross-tree lock")
    );
    assert!(
        !try_lock_trees(&mut holder, &[space_a])
            .await
            .expect("contend on A")
    );
    assert!(
        !try_lock_trees(&mut holder, &[space_b])
            .await
            .expect("contend on B")
    );
    rollback(&mut mover).await;
    rollback(&mut holder).await;
}

/// The lock is transaction-scoped: a rolled-back (or committed) mutation
/// releases its tree for the next one — the property `move_page` relies on
/// when it returns `Conflict` after a partial acquisition.
#[tokio::test]
async fn a_tree_is_released_when_its_transaction_ends() {
    let mut first = skip_if_no_db!(dedicated_connection().await);
    let mut second = skip_if_no_db!(dedicated_connection().await);
    let space = Uuid::now_v7();

    begin(&mut first).await;
    assert!(try_lock_trees(&mut first, &[space]).await.expect("lock"));
    rollback(&mut first).await;

    begin(&mut second).await;
    assert!(
        try_lock_trees(&mut second, &[space])
            .await
            .expect("lock after release"),
        "the tree must be free again once the holder's transaction ended"
    );
    rollback(&mut second).await;
}

/// The legacy whole-installation key and the per-tree keys are distinct
/// lock identities. This is the mixed-version reality during a rolling
/// upgrade — an old node's `move_page` and a new node's do not serialize
/// against each other — and it is documented rather than hidden: the
/// window is one deploy long, the cycle guard inside each transaction still
/// runs, and the alternative (taking both keys forever) would keep 3.19's
/// contention. Pinned so the trade-off is visible if it ever needs revisiting.
#[tokio::test]
async fn legacy_global_lock_and_per_tree_locks_are_independent() {
    let mut old_node = skip_if_no_db!(dedicated_connection().await);
    let mut new_node = skip_if_no_db!(dedicated_connection().await);

    begin(&mut old_node).await;
    begin(&mut new_node).await;
    assert!(
        try_lock_hierarchy(&mut old_node)
            .await
            .expect("legacy lock")
    );
    assert!(
        try_lock_trees(&mut new_node, &[Uuid::now_v7()])
            .await
            .expect("per-tree lock")
    );
    rollback(&mut old_node).await;
    rollback(&mut new_node).await;
}
