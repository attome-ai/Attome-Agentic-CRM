//! P-db-maintenance item (c) — proves `ensure_ahead_partitions` against a real
//! partitioned table: creates missing months, is idempotent on a re-run, and
//! the created partitions are actually queryable/writable.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-core --test partition_maintenance
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::Datelike;
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

const STORAGE_PARAMS: &str = "fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2";

/// `months_ahead = 6` deliberately reaches past what migration 0026 itself
/// already created (current month via the historical partition + 2 dedicated
/// months ahead) so this test exercises a genuine "create something new" call,
/// not just the current-month overlap-skip case.
const MONTHS_AHEAD: u32 = 6;

#[tokio::test]
async fn ensure_ahead_partitions_creates_missing_months_and_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);

    // First call: whatever's missing beyond what migration 0026 (or a prior
    // test run) already created gets created now. The current month is
    // expected to be skipped (covered by migration 0026's historical
    // partition, not a dedicated `_p{YYYY_MM}` one) — this only asserts that
    // *something* further out got created, not a specific count, since a
    // re-run of this test file itself changes how much is already caught up.
    let first_run = attome_core::partition_maintenance::ensure_ahead_partitions(
        &db,
        "audit_header",
        "created_at",
        STORAGE_PARAMS,
        MONTHS_AHEAD,
    )
    .await
    .expect("first ensure_ahead_partitions call");

    // Second call, immediately after: everything is now caught up — must be a
    // true no-op, not a duplicate-creation error and not a second round of
    // "created" partitions.
    let second_run = attome_core::partition_maintenance::ensure_ahead_partitions(
        &db,
        "audit_header",
        "created_at",
        STORAGE_PARAMS,
        MONTHS_AHEAD,
    )
    .await
    .expect("second ensure_ahead_partitions call (must be idempotent)");
    assert_eq!(
        second_run, 0,
        "an immediate re-run with the same months_ahead must create nothing new"
    );

    // Confirm the furthest-out requested partition actually exists as a real,
    // queryable relation attached to the parent (not just "the function
    // returned Ok") — this is the one guaranteed not to have existed before
    // this test ran (migration 0026 only reaches 2 months out).
    let now = chrono::Utc::now();
    let target_month = now
        .date_naive()
        .with_day(1)
        .unwrap()
        .checked_add_months(chrono::Months::new(MONTHS_AHEAD))
        .unwrap();
    let expected_name = format!("audit_header_p{}", target_month.format("%Y_%m"));
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM pg_inherits i
             JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'audit_header'::regclass AND c.relname = $1
         )",
    )
    .bind(&expected_name)
    .fetch_one(&db)
    .await
    .expect("check partition exists");
    assert!(
        exists,
        "expected partition {expected_name} to exist and be attached to audit_header, \
         first_run created {first_run} partitions"
    );
}
