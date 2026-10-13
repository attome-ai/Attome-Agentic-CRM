//! Proof that `seed_gate`'s boot-time watermark snapshot — the one query that
//! replaces the ~55 sequential stamp reads a boot used to make, one per
//! `apply_platform_bundle`/seed — can neither skip a seed body that should run
//! nor re-run one that shouldn't.
//!
//! Its own test binary on purpose: `prefetch` populates a process-global
//! snapshot, so a test calling it inside a shared binary would change how every
//! other test in that binary resolves its watermarks.
//!
//! Requires a live Postgres (`DATABASE_URL`/`attome_testkit::test_db_url`) — same
//! convention as `tests/crud.rs`. Uses a throwaway module key, never a real one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::seed_gate;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

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

#[tokio::test]
async fn snapshot_gates_correctly_and_absorbs_its_own_writes() {
    let db = skip_if_no_db!(test_db().await);
    if std::env::var_os("FORCE_RESEED").is_some_and(|v| !v.is_empty()) {
        eprintln!("FORCE_RESEED is set — it bypasses every gate by design; skipping");
        return;
    }

    let module = format!("seed-gate-prefetch-test-{}", Uuid::now_v7());
    let runs = AtomicUsize::new(0);
    let bump = || {
        runs.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    };

    // 1. No stamp yet, snapshot not populated: the body runs and stamps.
    seed_gate::run_if_stale(&db, &module, "v1", bump)
        .await
        .expect("first run");
    assert_eq!(runs.load(Ordering::SeqCst), 1, "first run must execute");

    // 2. Same version, still querying directly: the stamp gates it.
    seed_gate::run_if_stale(&db, &module, "v1", bump)
        .await
        .expect("second run");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "an unchanged version must skip the body"
    );

    // 3. Same version through the populated snapshot: still skipped, now
    //    without its own round-trip.
    seed_gate::prefetch(&db).await.expect("prefetch");
    seed_gate::run_if_stale(&db, &module, "v1", bump)
        .await
        .expect("third run");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "a populated snapshot must agree with the table it was loaded from"
    );

    // 4. A changed version must still run — the snapshot is a cache, not an
    //    excuse to skip real work.
    seed_gate::run_if_stale(&db, &module, "v2", bump)
        .await
        .expect("fourth run");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "a changed version must run even when the snapshot is populated"
    );

    // 5. The regression this whole file exists for: that run's `upsert_stamp`
    //    must have updated the snapshot too, not only the table. Without that,
    //    the snapshot still says "v1" and the body runs a second time.
    seed_gate::run_if_stale(&db, &module, "v2", bump)
        .await
        .expect("fifth run");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "upsert_stamp must keep the snapshot coherent with its own write"
    );

    sqlx::query("DELETE FROM seed_watermark WHERE module = $1")
        .bind(&module)
        .execute(&db)
        .await
        .expect("cleanup");
}
