//! P-retention-archive-completion §3b — proves the archive/drop primitives
//! (`list_archive_candidates`, `propose_partition_archive_actions`,
//! `detach_partition`, `drop_detached_partition`, `count_partition_rows`)
//! against a real partitioned table.
//!
//! Each test provisions its own throwaway RANGE-partitioned parent table
//! rather than reusing `audit_header`/`audit_detail`/
//! `audit_snapshot`. Live-verified finding: those shared tables have no
//! free date range to attach a synthetic "old" partition into on a freshly
//! migrated database — migration 0026's `{table}_pre_partition` covers
//! everything from `MINVALUE` through the month *after* whenever that
//! migration ran (its own `cutover`), and `ensure_ahead_partitions` has
//! already claimed the months immediately following that, so the entire
//! span from the dawn of time through several months into the future is
//! already spoken for on any database migrated within the last few months —
//! including a CI service container migrated seconds before this test runs.
//! `attome_core::partition_maintenance`'s own `ensure_ahead_partitions`
//! (this crate's `src/partition_maintenance.rs`) documents and tolerates
//! exactly this collision (SQLSTATE 42P17) for that reason; this test avoids
//! it entirely by never touching the shared audit tables' partition layout.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-core --test partition_archive -- --test-threads=1
//! ```
//!
//! Requires migration 0067 (`audit_retention_action`) already applied.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::partition_maintenance;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::{Datelike, Duration as ChronoDuration, Utc};
use sqlx::postgres::PgPoolOptions;
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

const STORAGE_PARAMS: &str = "fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2";

/// Creates a throwaway `PARTITION BY RANGE (created_at)` parent table with a
/// unique name (`Uuid::now_v7()`, the D-018-sanctioned test-fixture
/// exception), so this test owns its whole partition layout and can place a
/// partition anywhere without colliding with `core_audit_*`'s own state.
/// Kept short (12 hex chars, not the full 32) — Postgres silently truncates
/// identifiers past 63 bytes, and the longest partition-name suffix this
/// file appends is `_open_ended` (11 bytes) on top of `_pYYYY_MM` territory.
async fn create_throwaway_partitioned_table(db: &DbPool) -> String {
    let suffix = &Uuid::now_v7().simple().to_string()[..12];
    let table = format!("tpa_{suffix}");
    sqlx::query(&format!(
        r#"CREATE TABLE "{table}" (id uuid NOT NULL, created_at timestamptz NOT NULL)
               PARTITION BY RANGE (created_at)"#
    ))
    .execute(db)
    .await
    .expect("create throwaway partitioned parent table");
    table
}

/// Creates a partition far enough in the past that it is unambiguously
/// archive-eligible under a small `retention_days` window. Safe against any
/// `table` this test suite provisions itself (see
/// `create_throwaway_partitioned_table`) — never called against a shared
/// table with pre-existing partitions.
async fn create_old_partition(db: &DbPool, table: &str) -> String {
    let start = (Utc::now() - ChronoDuration::days(400))
        .date_naive()
        .with_day(1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let end = start + ChronoDuration::days(31);
    let partition_name = format!("{table}_p{}", start.format("%Y_%m"));
    sqlx::query(&format!(
        r#"CREATE TABLE IF NOT EXISTS "{partition_name}" PARTITION OF "{table}"
               FOR VALUES FROM ('{}') TO ('{}') WITH ({STORAGE_PARAMS})"#,
        start.to_rfc3339(),
        end.to_rfc3339(),
    ))
    .execute(db)
    .await
    .expect("create an old test partition");
    partition_name
}

#[tokio::test]
async fn list_archive_candidates_finds_an_old_partition_and_skips_open_ended_ones() {
    let db = skip_if_no_db!(test_db().await);
    let table = create_throwaway_partitioned_table(&db).await;
    let partition_name = create_old_partition(&db, &table).await;

    // An open-ended catch-all partition (MAXVALUE upper bound) — the shape
    // `parse_upper_bound` must refuse to treat as archive-eligible under any
    // cutoff, since it has no derivable age.
    let open_ended_partition_name = format!("{table}_open_ended");
    sqlx::query(&format!(
        r#"CREATE TABLE "{open_ended_partition_name}" PARTITION OF "{table}"
               FOR VALUES FROM ('{}') TO (MAXVALUE) WITH ({STORAGE_PARAMS})"#,
        (Utc::now() - ChronoDuration::days(300)).to_rfc3339(),
    ))
    .execute(&db)
    .await
    .expect("create open-ended test partition");

    let cutoff = Utc::now() - ChronoDuration::days(90);
    let candidates = partition_maintenance::list_archive_candidates(&db, &table, cutoff)
        .await
        .expect("list_archive_candidates");

    assert!(
        candidates
            .iter()
            .any(|c| c.partition_name == partition_name),
        "expected {partition_name} among archive candidates, got {candidates:?}"
    );
    assert!(
        !candidates
            .iter()
            .any(|c| c.partition_name == open_ended_partition_name),
        "an open-ended (MAXVALUE) partition must never be archive-eligible"
    );
}

#[tokio::test]
async fn propose_partition_archive_actions_is_idempotent_across_reruns() {
    let db = skip_if_no_db!(test_db().await);
    let table = create_throwaway_partitioned_table(&db).await;
    let partition_name = create_old_partition(&db, &table).await;

    let first = partition_maintenance::propose_partition_archive_actions(&db, &table, 90)
        .await
        .expect("first propose call");
    assert!(
        first >= 1,
        "expected at least the newly-created old partition to be proposed"
    );

    let second = partition_maintenance::propose_partition_archive_actions(&db, &table, 90)
        .await
        .expect("second propose call");
    assert_eq!(
        second, 0,
        "a re-run must not re-propose a partition that already has a non-rejected action row"
    );

    let status: String = sqlx::query_scalar(
        "SELECT status FROM audit_retention_action WHERE action_type = 'partition_archive' AND target = $1",
    )
    .bind(&partition_name)
    .fetch_one(&db)
    .await
    .expect("proposed action row must exist");
    assert_eq!(status, "proposed");
}

#[tokio::test]
async fn detach_then_drop_removes_the_partition_from_the_parents_tree() {
    let db = skip_if_no_db!(test_db().await);
    let table = create_throwaway_partitioned_table(&db).await;
    let partition_name = create_old_partition(&db, &table).await;

    partition_maintenance::detach_partition(&db, &table, &partition_name)
        .await
        .expect("detach_partition");

    // Detached: no longer a child of the parent in pg_inherits, but the
    // table itself still exists (and is still queryable/countable) until
    // explicitly dropped.
    let still_attached: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM pg_inherits i
             JOIN pg_class c ON c.oid = i.inhrelid
             JOIN pg_class p ON p.oid = i.inhparent
             WHERE p.relname = $1 AND c.relname = $2
         )",
    )
    .bind(&table)
    .bind(&partition_name)
    .fetch_one(&db)
    .await
    .expect("pg_inherits check");
    assert!(
        !still_attached,
        "partition must no longer be attached after detach"
    );

    let count = partition_maintenance::count_partition_rows(&db, &partition_name)
        .await
        .expect("count_partition_rows on a detached-but-not-yet-dropped table");
    assert_eq!(count, 0, "freshly created test partition has no rows");

    partition_maintenance::drop_detached_partition(&db, &partition_name)
        .await
        .expect("drop_detached_partition");

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)")
            .bind(&partition_name)
            .fetch_one(&db)
            .await
            .expect("pg_class existence check");
    assert!(
        !exists,
        "table must be gone entirely after drop_detached_partition"
    );
}
