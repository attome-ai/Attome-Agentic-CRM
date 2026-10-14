//! Integration tests for `attome_metadata::provision` (P1.8 money-path #2, the
//! provisioning half): `ensure_entity`/`ensure_attribute` create the
//! `entity_info`/`attribute_info` rows AND the physical table/
//! columns, and re-running the exact same seed is a no-op (`ADD COLUMN IF
//! NOT EXISTS` etc.) — asserted here via `information_schema` rather than
//! trusting the Ok(()) return value, since a silent duplicate-column bug
//! would still return Ok on the DB side while leaving the seed rig broken.
//!
//! The generic-CRUD HTTP round-trip (create → get → update → soft-delete)
//! lives in `attome-server/tests/entity_round_trip.rs`, since it needs the full
//! app + SecurityContext, not just this crate's DB-only provisioning API.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when it is
//! unset, except under `CI` (see `attome_testkit`). Run manually against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-metadata --test provision -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_metadata::provision::{
    ensure_attribute, ensure_default_query, ensure_entity, ensure_entity_list_views,
    resync_seeded_query_sql, set_default_query_display_column, sync_attribute_index_on_connection,
};
use attome_testkit::skip_if_no_db;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
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

async fn column_names(db: &DbPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY column_name",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .expect("query information_schema.columns")
}

async fn index_exists(db: &DbPool, table: &str, index_name: &str) -> bool {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_indexes WHERE tablename = $1 AND indexname = $2",
    )
    .bind(table)
    .bind(index_name)
    .fetch_one(db)
    .await
    .expect("query pg_indexes");
    count > 0
}

#[tokio::test]
async fn ensure_entity_registers_metadata_and_creates_exactly_one_physical_table() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let entity_id = ensure_entity(&db, &logicalname, "Provision Test", Some("name"), false)
        .await
        .expect("ensure_entity");

    let registered: Uuid = sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
        .bind(&logicalname)
        .fetch_one(&db)
        .await
        .expect("entity must be registered in entity_info");
    assert_eq!(registered, entity_id);

    let table_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = $1")
            .bind(&logicalname)
            .fetch_one(&db)
            .await
            .expect("query information_schema.tables");
    assert_eq!(
        table_count, 1,
        "exactly one physical table must exist for the entity"
    );

    let base_cols = column_names(&db, &logicalname).await;
    for expected in [
        "id",
        "created_at",
        "created_by",
        "modified_at",
        "modified_by",
        "organization_ref",
        "is_active",
    ] {
        assert!(
            base_cols.contains(&expected.to_owned()),
            "missing system column: {expected}"
        );
    }
}

#[tokio::test]
async fn ensure_attribute_adds_exactly_one_column_and_one_metadata_row() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(&db, &logicalname, "Provision Test", Some("title"), false)
        .await
        .expect("ensure_entity");

    ensure_attribute(
        &db, entity_id, "title", "Title", "text", true, false, false, false, None, None,
    )
    .await
    .expect("ensure_attribute");

    let cols = column_names(&db, &logicalname).await;
    assert!(
        cols.contains(&"title".to_owned()),
        "the new column must exist on the physical table"
    );

    let attr_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribute_info WHERE entity_ref = $1 AND logicalname = $2",
    )
    .bind(entity_id)
    .bind("title")
    .fetch_one(&db)
    .await
    .expect("count attribute_info rows");
    assert_eq!(attr_count, 1);
}

/// This is the money-path assertion: re-running the exact same
/// `ensure_entity` + `ensure_attribute` seed (as a boot-time reseed would)
/// must be a complete no-op — no duplicate `entity_info`/
/// `attribute_info` rows, no duplicate/renamed columns, still exactly
/// one physical table.
#[tokio::test]
async fn reseeding_the_same_entity_and_attributes_is_fully_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let seed_once = || {
        let db = db.clone();
        let logicalname = logicalname.clone();
        async move {
            let entity_id =
                ensure_entity(&db, &logicalname, "Idempotent Test", Some("title"), false)
                    .await
                    .expect("ensure_entity");
            ensure_attribute(
                &db, entity_id, "title", "Title", "text", true, false, false, false, None, None,
            )
            .await
            .expect("ensure_attribute title");
            ensure_attribute(
                &db, entity_id, "amount", "Amount", "number", false, false, false, false, None,
                None,
            )
            .await
            .expect("ensure_attribute amount");
            entity_id
        }
    };

    let first_id = seed_once().await;
    let second_id = seed_once().await;
    assert_eq!(
        first_id, second_id,
        "re-seeding must resolve to the same entity id, not insert a duplicate"
    );

    let entity_row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM entity_info WHERE logicalname = $1")
            .bind(&logicalname)
            .fetch_one(&db)
            .await
            .expect("count entity_info rows");
    assert_eq!(
        entity_row_count, 1,
        "re-seeding must not duplicate the entity_info row"
    );

    let attr_row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM attribute_info WHERE entity_ref = $1")
            .bind(first_id)
            .fetch_one(&db)
            .await
            .expect("count attribute_info rows");
    assert_eq!(
        attr_row_count, 2,
        "re-seeding must not duplicate attribute rows (title, amount)"
    );

    let table_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = $1")
            .bind(&logicalname)
            .fetch_one(&db)
            .await
            .expect("query information_schema.tables");
    assert_eq!(
        table_count, 1,
        "re-seeding must not create a second physical table"
    );

    let mut cols = column_names(&db, &logicalname).await;
    cols.sort();
    let mut expected = vec![
        "amount",
        "created_by",
        "created_at",
        "id",
        "is_active",
        "modified_by",
        "modified_at",
        "organization_ref",
        "owner_ref",
        "owner_type",
        "row_version",
        "title",
    ];
    expected.sort();
    assert_eq!(
        cols, expected,
        "re-seeding must leave exactly the expected column set, no duplicates"
    );
}

/// P1.11(h) — the index synchronizer creates and removes the one supporting
/// index for a sortable/filterable attribute. Admin writes choose either an
/// inline call or the durable worker; this test exercises the direct-session
/// primitive used by both.
#[tokio::test]
async fn sortable_or_filterable_attribute_index_sync_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(&db, &logicalname, "Index Test", Some("title"), false)
        .await
        .expect("ensure_entity");

    ensure_attribute(
        &db, entity_id, "amount", "Amount", "number", false, false, true, false, None, None,
    )
    .await
    .expect("ensure_attribute amount (sortable)");

    let index_name = format!("idx_{logicalname}_amount_sf");
    let mut conn = skip_if_no_db!(direct_connection().await);
    sync_attribute_index_on_connection(&mut conn, &logicalname, "amount", true)
        .await
        .expect("sync_attribute_index create");
    conn.close().await.expect("close direct session");
    assert!(
        index_exists(&db, &logicalname, &index_name).await,
        "sync_attribute_index(true) must create the supporting index"
    );

    // Re-provisioning with both flags false doesn't touch the index that's
    // already there (ensure_attribute only creates, never demotes) — dropping
    // is exclusively sync_attribute_index's job, driven by the update path.
    let mut conn = skip_if_no_db!(direct_connection().await);
    sync_attribute_index_on_connection(&mut conn, &logicalname, "amount", false)
        .await
        .expect("sync_attribute_index drop");
    conn.close().await.expect("close direct session");
    assert!(
        !index_exists(&db, &logicalname, &index_name).await,
        "sync_attribute_index(false) must drop the index"
    );

    let mut conn = skip_if_no_db!(direct_connection().await);
    sync_attribute_index_on_connection(&mut conn, &logicalname, "amount", true)
        .await
        .expect("sync_attribute_index create");
    conn.close().await.expect("close direct session");
    assert!(
        index_exists(&db, &logicalname, &index_name).await,
        "sync_attribute_index(true) must recreate the index"
    );
}

/// A failed `CREATE INDEX CONCURRENTLY` leaves an invalid catalog entry. The
/// next worker attempt must repair that real PostgreSQL state before retrying
/// the normal create; `IF NOT EXISTS` alone would otherwise accept it forever.
#[tokio::test]
async fn index_sync_repairs_an_invalid_concurrent_index() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(&db, &logicalname, "Index Repair Test", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        &db, entity_id, "amount", "Amount", "number", false, false, true, false, None, None,
    )
    .await
    .expect("ensure_attribute amount");

    sqlx::query(&format!(
        r#"INSERT INTO "{logicalname}" ("amount") VALUES (1), (1)"#
    ))
    .execute(&db)
    .await
    .expect("insert duplicate values");

    let index_name = format!("idx_{logicalname}_amount_sf");
    let mut failed_build = skip_if_no_db!(direct_connection().await);
    let unique_build = sqlx::query(&format!(
        r#"CREATE UNIQUE INDEX CONCURRENTLY "{index_name}" ON "{logicalname}" ("amount") WHERE is_active = TRUE"#
    ))
    .execute(&mut failed_build)
    .await;
    assert!(
        unique_build.is_err(),
        "duplicate values must fail the unique build"
    );
    failed_build
        .close()
        .await
        .expect("close failed-build session");

    let invalid: bool = sqlx::query_scalar(
        "SELECT NOT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = $1",
    )
    .bind(&index_name)
    .fetch_one(&db)
    .await
    .expect("failed concurrent build leaves invalid index");
    assert!(invalid, "the test must exercise invalid-index repair");

    let mut repair = skip_if_no_db!(direct_connection().await);
    sync_attribute_index_on_connection(&mut repair, &logicalname, "amount", true)
        .await
        .expect("repair invalid index then recreate it");
    repair.close().await.expect("close repair session");

    let valid: bool = sqlx::query_scalar(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = $1",
    )
    .bind(&index_name)
    .fetch_one(&db)
    .await
    .expect("query repaired index validity");
    assert!(valid, "the rebuilt index must be valid");
}

#[tokio::test]
async fn index_sync_rejects_a_second_session_while_the_lock_is_held() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(&db, &logicalname, "Index Lock Test", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        &db, entity_id, "amount", "Amount", "number", false, false, true, false, None, None,
    )
    .await
    .expect("ensure_attribute amount");

    let lock_key = format!("attome-metadata/attribute-index:{logicalname}:amount");
    let mut first = skip_if_no_db!(direct_connection().await);
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(attome_metadata::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut first)
        .await
        .expect("acquire first session lock");
    assert!(locked);

    let mut second = skip_if_no_db!(direct_connection().await);
    let err = sync_attribute_index_on_connection(&mut second, &logicalname, "amount", true)
        .await
        .expect_err("second session must not inspect or build without the lock");
    assert_eq!(
        err.to_string(),
        "conflict: attribute index build already in progress"
    );
    second.close().await.expect("close second session");
    first.close().await.expect("release first session lock");
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn direct_connection() -> Option<PgConnection> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgConnection::connect(&url)
            .await
            .expect("connect direct PostgreSQL session"),
    )
}

/// In-memory sink for `tracing_subscriber::fmt`, used by
/// `capture_provisioning_ddl` below to observe exactly which DDL statements
/// `exec_ddl_locked` (attome-metadata/src/provision.rs) actually runs, without
/// depending on `pg_stat_statements` — see that test's doc comment for why.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture buffer lock").clone())
            .expect("captured tracing output must be valid UTF-8")
    }
}

/// Runs `fut` with a process-default `tracing` subscriber installed for the
/// duration (via `tracing::subscriber::set_default`, thread-local — valid
/// here because `#[tokio::test]` defaults to the current-thread runtime, so
/// every task this future spawns is polled on this same OS thread) and
/// returns its output alongside everything logged at DEBUG or above. Used
/// only to observe `exec_ddl_locked`'s per-statement debug event
/// (`"provisioning: executing DDL statement"`, carrying the `sql` field) —
/// not a general test-logging utility.
async fn capture_provisioning_ddl<Fut, T>(fut: Fut) -> (T, String)
where
    Fut: std::future::Future<Output = T>,
{
    let captured = CapturedLogs::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    let result = {
        let _guard = tracing::subscriber::set_default(subscriber);
        fut.await
    };
    (result, captured.contents())
}

/// P-provisioning-hardening item (c) / D-101 — standalone scenario 1 of 3
/// named in the plan's still-open checklist (§6; tracked as open in D-104's
/// closing note). A second `ensure_entity` + `ensure_attribute` pass against
/// an already-provisioned entity must not re-run any of the conditional,
/// catalog-pre-checked `ALTER TABLE ... ADD COLUMN` backfills
/// (row_version/modified_at/modified_by, and any attribute column).
///
/// The plan's first-choice verification mechanism is a `pg_stat_statements`
/// reset+scan, but that extension requires `shared_preload_libraries` set at
/// server start, which the stock `postgres:18` image this repo's compose test
/// profile uses does not set — `CREATE EXTENSION
/// pg_stat_statements` fails outright without it. This uses the
/// tracing-based fallback the plan names as the alternative instead,
/// capturing every DDL statement `exec_ddl_locked` actually executes
/// (provision.rs's `tracing::debug!("provisioning: executing DDL
/// statement", ...)`).
///
/// C-20 tightened this from "zero ADD COLUMN, but still 4 unconditional
/// SET-DEFAULT/reloptions ALTERs" to zero `ALTER TABLE` of any kind: once
/// `existing_columns` also carries each column's stored default expression
/// and the table's `pg_class.reloptions` (not just `column_name`/
/// `data_type`), `backfill_storage_params`/`backfill_system_columns`/
/// `ensure_is_active` can tell "already set to this exact value" from
/// "unset" and skip the ALTER — on a 133-entity deployment that used to be
/// ~530 ACCESS EXCLUSIVE transactions per node boot, now exactly one
/// operation per entity (the unconditional `attome_readonly` GRANT,
/// D-126/P-stored-query-containment phase 1(a), which carries no catalog
/// pre-check by design — see `provision_table`'s own comment on why it
/// can't be skipped).
#[tokio::test]
async fn reseeding_issues_no_alter_table_statements_on_the_second_pass() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let entity_id = ensure_entity(&db, &logicalname, "Reseed DDL Test", Some("title"), false)
        .await
        .expect("first ensure_entity");
    ensure_attribute(
        &db, entity_id, "title", "Title", "text", true, false, false, false, None, None,
    )
    .await
    .expect("first ensure_attribute");

    let (reseed_entity_id, logs) = capture_provisioning_ddl(async {
        let id = ensure_entity(&db, &logicalname, "Reseed DDL Test", Some("title"), false)
            .await
            .expect("reseed ensure_entity");
        ensure_attribute(
            &db, id, "title", "Title", "text", true, false, false, false, None, None,
        )
        .await
        .expect("reseed ensure_attribute");
        id
    })
    .await;
    assert_eq!(
        reseed_entity_id, entity_id,
        "reseed must resolve to the same entity id, not provision a duplicate"
    );

    // Filter to exec_ddl_locked's own marker line before counting: sqlx's
    // built-in query instrumentation ALSO logs at DEBUG (a "summary" preview
    // AND the full "db.statement" text, both independently containing "ALTER
    // TABLE"/"ADD COLUMN" for every statement it runs, including SET LOCAL/
    // COMMIT wrapper statements that reference the same SQL) — counting
    // across the whole capture over-counts every real ALTER roughly 3x.
    // exec_ddl_locked's line is the single source of truth for "a DDL
    // statement was actually submitted."
    let ddl_lines: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("provisioning: executing DDL statement"))
        .collect();
    let ddl_log = ddl_lines.join("\n");

    assert_eq!(
        ddl_lines
            .iter()
            .filter(|l| l.contains("ALTER TABLE"))
            .count(),
        0,
        "a reseed pass must issue zero ALTER TABLE statements of any kind — \
         ADD COLUMN, storage-parameter, or any SET DEFAULT (C-20: all four \
         are now catalog-pre-checked, exactly like ADD COLUMN already was); \
         captured DDL statements:\n{ddl_log}"
    );

    assert_eq!(
        ddl_lines.len(),
        1,
        "a reseed pass is expected to issue exactly the one documented \
         unconditional operation left (the attome_readonly GRANT — \
         D-126/P-stored-query-containment phase 1(a), see provision_table's \
         own comment on why the GRANT can't be skipped) and nothing else — a \
         different count means either a new unguarded ALTER was added \
         (regression: needs a catalog pre-check) or the GRANT itself became \
         conditional (update this test and the provision_table comments \
         together); captured DDL statements:\n{ddl_log}"
    );
    assert!(
        ddl_log.contains("GRANT SELECT ON") && ddl_log.contains("TO attome_readonly"),
        "expected the unconditional attome_readonly re-grant (D-126); captured DDL statements:\n{ddl_log}"
    );
}

/// P-provisioning-hardening item (c) / D-101 — standalone scenario 2 of 3.
/// A conflicting lock held by another session must make `exec_ddl_locked`
/// retry SQLSTATE 55P03 (`lock_not_available`) up to its bounded budget (3
/// attempts, 5s `lock_timeout` each) and then return a clean error — never
/// hang, and never silently succeed by skipping the ALTER.
///
/// Deliberately pays the real ~15s cost of exercising the production
/// `DDL_LOCK_TIMEOUT`/retry constants end-to-end rather than injecting a
/// shortened timeout for the test: the entire point of item (c) is the
/// timing contract itself (a boot can be slow, but must never wedge live
/// traffic indefinitely), so proving it against the real constants is more
/// trustworthy than proving it against a stand-in. Holding an ACCESS SHARE
/// lock (the weakest real lock mode) is enough to conflict with the ACCESS
/// EXCLUSIVE an ALTER TABLE needs — this simulates "someone else has the
/// table open" (a report query, a backup tool) without special-casing what
/// they're doing.
#[tokio::test]
async fn ddl_retries_then_errors_on_a_held_conflicting_lock() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(&db, &logicalname, "Lock Hold Test", None, false)
        .await
        .expect("ensure_entity");

    let mut holder = skip_if_no_db!(direct_connection().await);
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin holder transaction");
    sqlx::query(&format!(
        r#"LOCK TABLE "{logicalname}" IN ACCESS SHARE MODE"#
    ))
    .execute(&mut holder)
    .await
    .expect("acquire holder lock");

    // Migration 0065 sets idle_in_transaction_session_timeout = 10s on
    // this role, but the retry budget below deliberately runs ~15s — a
    // holder connection sitting fully idle that whole time would get
    // killed server-side before this test ever reaches its own ROLLBACK,
    // failing on cleanup even though the retry-then-error behavior under
    // test already passed. A periodic no-op keeps the session out of
    // "idle in transaction" without touching the held ACCESS SHARE lock or
    // the open transaction.
    let holder = Arc::new(AsyncMutex::new(holder));
    let keepalive_conn = Arc::clone(&holder);
    let stop = Arc::new(tokio::sync::Notify::new());
    let stop_signal = Arc::clone(&stop);
    let keepalive = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(3)) => {
                    let mut conn = keepalive_conn.lock().await;
                    let _ = sqlx::query("SELECT 1").execute(&mut *conn).await;
                }
                _ = stop_signal.notified() => break,
            }
        }
    });

    // A genuinely new column forces provision_column's pre-check to fall
    // through to exec_ddl_locked's ALTER TABLE ... ADD COLUMN — the exact
    // path item (c) hardened. C-20 moved this call to before the metadata
    // transaction even begins, so a failure here now means the INSERT into
    // attribute_info is never attempted at all (previously it ran
    // first, inside the same transaction as provision_column, and a
    // failure rolled it back via the transaction's implicit drop) — either
    // way, no row should survive.
    let started = Instant::now();
    let blocked_result = ensure_attribute(
        &db,
        entity_id,
        "held_lock_column",
        "Held Lock Column",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await;
    let elapsed = started.elapsed();

    stop.notify_one();
    keepalive.await.expect("keepalive task must not panic");
    let mut holder = Arc::try_unwrap(holder)
        .unwrap_or_else(|_| panic!("keepalive task must have released its Arc handle by now"))
        .into_inner();
    sqlx::query("ROLLBACK")
        .execute(&mut holder)
        .await
        .expect("release holder lock");
    holder.close().await.expect("close holder session");

    assert!(
        blocked_result.is_err(),
        "ALTER TABLE must surface an error once the retry budget is exhausted, \
         not hang and not silently succeed"
    );
    assert!(
        elapsed >= Duration::from_secs(9),
        "must have actually waited through the retry/backoff budget \
         (3 attempts x 5s lock_timeout ~= 15s) rather than failing \
         immediately for an unrelated reason: elapsed={elapsed:?}"
    );

    let cols_after_failure = column_names(&db, &logicalname).await;
    assert!(
        !cols_after_failure.contains(&"held_lock_column".to_owned()),
        "a failed provisioning attempt must not leave a partial column behind"
    );
    let attr_count_after_failure: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribute_info WHERE entity_ref = $1 AND logicalname = $2",
    )
    .bind(entity_id)
    .bind("held_lock_column")
    .fetch_one(&db)
    .await
    .expect("count attribute_info rows");
    assert_eq!(
        attr_count_after_failure, 0,
        "a failed physical-column ALTER must roll back the metadata row \
         inserted in the same ensure_attribute transaction, not strand it"
    );

    // Prove the failure really was retry-exhaustion under the held lock, not
    // an unrelated bug: once the lock is released, the identical call must
    // succeed cleanly.
    let retried = ensure_attribute(
        &db,
        entity_id,
        "held_lock_column",
        "Held Lock Column",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await;
    assert!(
        retried.is_ok(),
        "after the conflicting lock is released, the identical call must succeed"
    );
    let cols_after_retry = column_names(&db, &logicalname).await;
    assert!(cols_after_retry.contains(&"held_lock_column".to_owned()));
}

/// P-provisioning-hardening item (d) / D-101 — standalone scenario 3 of 3.
/// A table registered before the TIMESTAMPTZ convention landed — simulated
/// here by creating a table with plain TIMESTAMP columns directly (bypassing
/// `provision_table`'s generic CREATE, which already emits TIMESTAMPTZ) —
/// has its TIMESTAMP columns converted to TIMESTAMPTZ in place the first
/// time `ensure_entity` runs against it, and a value stored before the
/// conversion reads back identical afterward: the `SET LOCAL timezone =
/// 'UTC'` binary-compatible cast is value-preserving, not a
/// reinterpretation. A second run is a no-op — the backfill loop's
/// `data_type == "timestamp without time zone"` filter no longer matches an
/// already-converted column, so it never re-fires for it.
#[tokio::test]
async fn timestamptz_backfill_converts_type_and_preserves_the_stored_value() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    sqlx::query(&format!(
        r#"CREATE TABLE "{logicalname}" (
               id        UUID PRIMARY KEY DEFAULT uuidv7(),
               created_at TIMESTAMP DEFAULT NOW(),
               note      TIMESTAMP
           )"#
    ))
    .execute(&db)
    .await
    .expect("create legacy TIMESTAMP-only table");

    let known = NaiveDate::from_ymd_opt(2026, 3, 15)
        .expect("valid date")
        .and_hms_opt(8, 30, 0)
        .expect("valid time");
    let row_id = Uuid::now_v7();
    sqlx::query(&format!(
        r#"INSERT INTO "{logicalname}" (id, created_at, note) VALUES ($1, $2, $3)"#
    ))
    .bind(row_id)
    .bind(known)
    .bind(known)
    .execute(&db)
    .await
    .expect("insert known TIMESTAMP value before conversion");

    let before_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = 'note'",
    )
    .bind(&logicalname)
    .fetch_one(&db)
    .await
    .expect("query pre-conversion data_type");
    assert_eq!(before_type, "timestamp without time zone");

    let entity_id = ensure_entity(&db, &logicalname, "Timestamptz Test", None, false)
        .await
        .expect("ensure_entity must convert the legacy TIMESTAMP columns");
    let registered: Uuid = sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
        .bind(&logicalname)
        .fetch_one(&db)
        .await
        .expect("entity must be registered in entity_info");
    assert_eq!(registered, entity_id);

    let after_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = 'note'",
    )
    .bind(&logicalname)
    .fetch_one(&db)
    .await
    .expect("query post-conversion data_type");
    assert_eq!(after_type, "timestamp with time zone");

    let after_value: DateTime<Utc> = sqlx::query_scalar(&format!(
        r#"SELECT note FROM "{logicalname}" WHERE id = $1"#
    ))
    .bind(row_id)
    .fetch_one(&db)
    .await
    .expect("read back converted value");
    assert_eq!(
        after_value.naive_utc(),
        known,
        "the stored instant must round-trip identical through the TIMESTAMP \
         -> TIMESTAMPTZ conversion"
    );

    // Second run: idempotent no-op for `note`/`created_at` — already
    // TIMESTAMPTZ, so the backfill's own data_type filter excludes them.
    ensure_entity(&db, &logicalname, "Timestamptz Test", None, false)
        .await
        .expect("second ensure_entity must remain a no-op, not error");

    let after_second_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = 'note'",
    )
    .bind(&logicalname)
    .fetch_one(&db)
    .await
    .expect("query data_type after second run");
    assert_eq!(after_second_type, "timestamp with time zone");

    let after_second_value: DateTime<Utc> = sqlx::query_scalar(&format!(
        r#"SELECT note FROM "{logicalname}" WHERE id = $1"#
    ))
    .bind(row_id)
    .fetch_one(&db)
    .await
    .expect("read back value after second run");
    assert_eq!(after_second_value.naive_utc(), known);
}

/// Regression: registering a migration-owned table that predates the D-005
/// entity convention must backfill `created_at`/`created_by`, because
/// `entity_mutation::create_one` splices `created_by` into every generic INSERT
/// column list and `attome_core::select_columns` names both in the
/// RETURNING projection. Without the backfill the INSERT referenced a column
/// that does not exist, Postgres answered 42703, and `POST /api/v1/{entity}`
/// returned a bare 500 for every such entity.
///
/// The fixture is `team`'s real shape from
/// `0051_record_level_security.sql` (its creation column renamed so the table
/// lacks `created_at`, as v1's `created_on` did) — `inserted_at`/`updated_at`/`is_deleted`
/// instead of `created_at`/`modified_at`/`is_active` — which is exactly why that
/// table (and `api_key`, `license`,
/// `user_account_mm_team`) hit this while `organization`, which
/// carries both columns from `0000_core_bootstrap.sql`, did not.
///
/// The final INSERT is the point of the test: it reproduces `create_one`'s
/// exact column set rather than only asserting the two columns appeared, so a
/// future change to `ALL_SYSTEM_COLS` that reintroduces the gap fails here.
#[tokio::test]
async fn legacy_table_registration_backfills_createdon_and_createdby() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    sqlx::query(&format!(
        r#"CREATE TABLE "{logicalname}" (
               id               UUID        PRIMARY KEY DEFAULT uuidv7(),
               name             VARCHAR     NOT NULL,
               description      VARCHAR,
               organization_ref UUID,
               inserted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
               updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
               row_version      BIGINT      NOT NULL DEFAULT 0,
               is_deleted       BOOLEAN     NOT NULL DEFAULT FALSE
           )"#
    ))
    .execute(&db)
    .await
    .expect("create legacy team-shaped table");

    let pre_existing = Uuid::now_v7();
    sqlx::query(&format!(
        r#"INSERT INTO "{logicalname}" (id, name) VALUES ($1, 'pre-registration')"#
    ))
    .bind(pre_existing)
    .execute(&db)
    .await
    .expect("insert a row that predates registration");

    let entity_id = ensure_entity(&db, &logicalname, "Legacy Team", Some("name"), false)
        .await
        .expect("ensure_entity must backfill the missing audit columns");
    ensure_attribute(
        &db, entity_id, "name", "Name", "text", true, false, false, false, None, None,
    )
    .await
    .expect("ensure_attribute for the primary name column");

    let cols = column_names(&db, &logicalname).await;
    for required in ["created_at", "created_by"] {
        assert!(
            cols.contains(&required.to_owned()),
            "registration must backfill {required} onto a legacy table; columns present: {cols:?}"
        );
    }

    // Backfilled without a default, then defaulted — so a row that predates
    // registration keeps an honest NULL rather than being stamped with the
    // backfill's own clock, while new rows still get NOW().
    let legacy_createdon: Option<DateTime<Utc>> = sqlx::query_scalar(&format!(
        r#"SELECT created_at FROM "{logicalname}" WHERE id = $1"#
    ))
    .bind(pre_existing)
    .fetch_one(&db)
    .await
    .expect("read the pre-registration row's created_at");
    assert!(
        legacy_createdon.is_none(),
        "a row created before the backfill must keep created_at NULL (unknown), \
         not inherit the backfill's timestamp"
    );

    // The reproduction: create_one's spliced system columns + one attribute,
    // returning select_columns' full projection.
    let created_id = Uuid::now_v7();
    let caller = Uuid::now_v7();
    let returning = attome_core::ALL_SYSTEM_COLS.join(", ");
    sqlx::query(&format!(
        r#"INSERT INTO "{logicalname}"
               (created_by, modified_by, organization_ref, owner_ref, owner_type, id, name)
           VALUES ($1, $1, $2, $1, 0, $3, 'created-through-generic-crud')
           RETURNING {returning}, name"#
    ))
    .bind(caller)
    .bind(Uuid::now_v7())
    .bind(created_id)
    .execute(&db)
    .await
    .expect("generic-CRUD-shaped INSERT must succeed after the backfill");

    let created_on: Option<DateTime<Utc>> = sqlx::query_scalar(&format!(
        r#"SELECT created_at FROM "{logicalname}" WHERE id = $1"#
    ))
    .bind(created_id)
    .fetch_one(&db)
    .await
    .expect("read the new row's created_at");
    assert!(
        created_on.is_some(),
        "created_at's DEFAULT NOW() must stamp a row inserted without it — \
         create_one never binds the column itself"
    );

    // Second pass is a no-op: both columns are now present, so the pre-checked
    // ADD COLUMN branches must not fire again.
    ensure_entity(&db, &logicalname, "Legacy Team", Some("name"), false)
        .await
        .expect("re-registration must remain idempotent");
}

/// D-079: database uniqueness + ON CONFLICT, not a check-then-insert race,
/// is the provisioning serialization point across nodes.
#[tokio::test]
async fn concurrent_entity_provisioning_returns_one_metadata_identity() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_race_{}", Uuid::now_v7().simple());
    let left = ensure_entity(&db, &logicalname, "Race", None, false);
    let right = ensure_entity(&db, &logicalname, "Race", None, false);
    let (left, right) = tokio::join!(left, right);
    let winner = left
        .ok()
        .or_else(|| right.ok())
        .expect("one provisioner wins");
    let retried = ensure_entity(&db, &logicalname, "Race", None, false)
        .await
        .expect("loser can recover by retrying");
    assert_eq!(winner, retried);

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_info WHERE logicalname = $1 AND (is_active IS NULL OR is_active = TRUE)",
    )
    .bind(&logicalname)
    .fetch_one(&db)
    .await
    .expect("count entity metadata rows");
    assert_eq!(count, 1);
}

async fn change_log_rows(db: &DbPool, entity_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT change_kind FROM metadata_change_log \
         WHERE entity_ref = $1 ORDER BY id",
    )
    .bind(entity_id)
    .fetch_all(db)
    .await
    .expect("query metadata_change_log")
}

/// Regression (2026-08-07): an entity registered by an engine seed reached
/// `entity_info` but appended no `metadata_change_log` row,
/// so `pre_warm_registry`'s snapshot + `changes_since` catch-up could never
/// learn about it. On a node that loaded a Redis snapshot written before the
/// seed, the entity was absent from `EntityMetaRegistry` for the process's
/// whole life: `/api/v1/schema/{entity}` worked (it queries Postgres) while
/// `GET /api/v1/{entity}/{id}` returned `NotFound` from `resolve_entity`'s
/// registry miss — observed on `workflow_definition`, whose edit form
/// rendered its fields but reported "not found" for a record that existed.
///
/// The reseed halves matter as much as the append: seeds re-run on every
/// boot, so logging unconditionally would grow the log without bound and
/// make every node re-apply catch-up work for metadata that never changed.
#[tokio::test]
async fn seeding_appends_one_change_log_row_and_reseeding_appends_none() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_log_{}", Uuid::now_v7().simple());

    let entity_id = ensure_entity(&db, &logicalname, "Change Log Test", Some("title"), false)
        .await
        .expect("ensure_entity");
    assert_eq!(
        change_log_rows(&db, entity_id).await,
        vec!["upsert".to_owned()],
        "a new entity registration must append exactly one upsert row"
    );

    ensure_entity(&db, &logicalname, "Change Log Test", Some("title"), false)
        .await
        .expect("reseed ensure_entity");
    assert_eq!(
        change_log_rows(&db, entity_id).await.len(),
        1,
        "reseeding an already-registered entity must append nothing"
    );

    ensure_attribute(
        &db, entity_id, "title", "Title", "text", false, false, false, false, None, None,
    )
    .await
    .expect("ensure_attribute");
    assert_eq!(
        change_log_rows(&db, entity_id).await,
        vec!["upsert".to_owned(), "upsert".to_owned()],
        "a new attribute must append one upsert row keyed on its owning entity"
    );

    ensure_attribute(
        &db, entity_id, "title", "Title", "text", false, false, false, false, None, None,
    )
    .await
    .expect("reseed ensure_attribute");
    assert_eq!(
        change_log_rows(&db, entity_id).await.len(),
        2,
        "reseeding an already-registered attribute must append nothing"
    );
}

/// Every runtime-created entity gets *two* list views, not one: an Active
/// default and an Inactive companion over the soft-deleted rows. The assertions
/// below pin the three things that make that pair usable rather than merely
/// present — exactly one of them is `is_default` (migration 0078's partial
/// unique index only permits one, so a second default would fail the write,
/// not just look wrong), each carries the `{logicalname}.read` privilege D-036
/// requires for the list page to be readable by non-admins, and their SQL
/// differs only in the `is_active` predicate.
#[tokio::test]
async fn create_seeds_both_an_active_and_an_inactive_list_view() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let entity_id = ensure_entity(&db, &logicalname, "Two View Test", Some("title"), false)
        .await
        .expect("ensure_entity");
    ensure_entity_list_views(&db, entity_id, &logicalname, "Two View Test")
        .await
        .expect("ensure_entity_list_views");

    let views = seeded_views(&db, entity_id).await;
    assert_eq!(
        views.len(),
        2,
        "an entity must be created with exactly two views, got: {views:?}"
    );

    let (active_name, active_is_default, active_sql, active_privilege) = views[0].clone();
    let (inactive_name, inactive_is_default, inactive_sql, inactive_privilege) = views[1].clone();

    assert_eq!(active_name, "Active Two View Test");
    assert_eq!(inactive_name, "Inactive Two View Test");
    assert!(
        active_is_default,
        "the Active view is the list page default"
    );
    assert!(
        !inactive_is_default,
        "only one view per entity may be the default"
    );

    let expected_privilege = format!("{logicalname}.read");
    assert_eq!(
        active_privilege.as_deref(),
        Some(expected_privilege.as_str())
    );
    assert_eq!(
        inactive_privilege.as_deref(),
        Some(expected_privilege.as_str()),
        "the Inactive view must be readable by the same users as the Active one"
    );

    assert_eq!(
        active_sql,
        format!(r#"SELECT id FROM "{logicalname}" WHERE is_active = true"#)
    );
    assert_eq!(
        inactive_sql,
        format!(r#"SELECT id FROM "{logicalname}" WHERE is_active = false"#)
    );
}

/// Both seeded views are id-only at create time (no attribute exists yet), and
/// both must gain the display column once the entity's declared
/// `primary_name_attribute` is created — the Inactive one included. It is not
/// covered by `set_default_query_display_column`'s default-view UPDATE, so it
/// needs its own, and a regression there would leave the Inactive view
/// rendering a column of bare UUIDs forever.
#[tokio::test]
async fn creating_the_primary_attribute_gives_both_views_a_display_column() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let entity_id = ensure_entity(&db, &logicalname, "Display Col Test", Some("title"), false)
        .await
        .expect("ensure_entity");
    ensure_entity_list_views(&db, entity_id, &logicalname, "Display Col Test")
        .await
        .expect("ensure_entity_list_views");
    ensure_attribute(
        &db, entity_id, "title", "Title", "text", true, false, false, false, None, None,
    )
    .await
    .expect("ensure_attribute title");

    set_default_query_display_column(&db, entity_id, &logicalname, "title")
        .await
        .expect("set_default_query_display_column");

    let views = seeded_views(&db, entity_id).await;
    assert_eq!(views.len(), 2);
    assert_eq!(
        views[0].2,
        format!(r#"SELECT id, "title" FROM "{logicalname}" WHERE is_active = true"#)
    );
    assert_eq!(
        views[1].2,
        format!(r#"SELECT id, "title" FROM "{logicalname}" WHERE is_active = false"#),
        "the Inactive view must gain the display column too"
    );
}

/// Boot-time reseeding runs the same provisioning calls again; neither half of
/// the pair may duplicate. The Inactive view is the interesting one — it is
/// keyed on its `(entity, name)` unique constraint rather than on
/// `ensure_default_query`'s "reuse any existing query for this entity" lookup,
/// which is exactly the lookup that cannot distinguish the two.
#[tokio::test]
async fn reseeding_list_views_does_not_duplicate_either_view() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let entity_id = ensure_entity(&db, &logicalname, "Reseed View Test", Some("title"), false)
        .await
        .expect("ensure_entity");
    for _ in 0..3 {
        ensure_entity_list_views(&db, entity_id, &logicalname, "Reseed View Test")
            .await
            .expect("ensure_entity_list_views");
    }

    let views = seeded_views(&db, entity_id).await;
    assert_eq!(
        views.len(),
        2,
        "reseeding must leave exactly the original two views, got: {views:?}"
    );

    let query_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sql_query WHERE entity_logical_name = $1")
            .bind(entity_id)
            .fetch_one(&db)
            .await
            .expect("count sql_query rows");
    assert_eq!(
        query_count, 2,
        "each reseed must reuse its query row, not insert another"
    );
}

/// `resync_seeded_query_sql` is what lets an engine seed change its list-view
/// column list on a deployment that was already seeded — `ensure_default_query`
/// alone is insert-only, so the new literal would otherwise only ever reach a
/// fresh database. The two halves that matter are that it *does* rewrite a row
/// still carrying the previous release's exact text, and that it *does not*
/// touch one an admin has since edited through `/api/v1/admin/queries`.
#[tokio::test]
async fn resync_rewrites_the_seeded_query_but_spares_an_edited_one() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());
    let previous = format!("SELECT id, name, parent_ref FROM {logicalname} WHERE is_active = true");
    let current = format!("SELECT id, name FROM {logicalname} WHERE is_active = true");

    let entity_id = ensure_entity(&db, &logicalname, "Resync Test", Some("name"), false)
        .await
        .expect("ensure_entity");
    ensure_default_query(&db, entity_id, "Resyncs", &previous)
        .await
        .expect("ensure_default_query");

    // Re-running the seed with the new literal alone is a no-op: this is the
    // drift the helper exists to close.
    ensure_default_query(&db, entity_id, "Resyncs", &current)
        .await
        .expect("ensure_default_query reseed");
    assert_eq!(
        seeded_views(&db, entity_id).await[0].2,
        previous,
        "ensure_default_query is insert-only — it must not rewrite an existing row"
    );

    resync_seeded_query_sql(&db, entity_id, &logicalname, &previous, &current)
        .await
        .expect("resync_seeded_query_sql");
    assert_eq!(seeded_views(&db, entity_id).await[0].2, current);

    // Idempotent: the second boot matches nothing and leaves the row alone.
    resync_seeded_query_sql(&db, entity_id, &logicalname, &previous, &current)
        .await
        .expect("resync_seeded_query_sql second run");
    assert_eq!(seeded_views(&db, entity_id).await[0].2, current);

    // An admin edit no longer matches `previous`, so a later release bumping
    // the literal again cannot clobber it.
    let admin_edited =
        format!("SELECT id, name, created_at FROM {logicalname} WHERE is_active = true");
    sqlx::query("UPDATE sql_query SET sql_query = $1 WHERE entity_logical_name = $2")
        .bind(&admin_edited)
        .bind(entity_id)
        .execute(&db)
        .await
        .expect("simulate an admin edit through /api/v1/admin/queries");
    let next_release =
        format!("SELECT id, name, is_active FROM {logicalname} WHERE is_active = true");
    resync_seeded_query_sql(&db, entity_id, &logicalname, &current, &next_release)
        .await
        .expect("resync_seeded_query_sql after admin edit");
    assert_eq!(
        seeded_views(&db, entity_id).await[0].2,
        admin_edited,
        "an admin-authored view must survive a seed literal change"
    );
}

/// `(name, is_default, sql_query, required_privilege)` for an entity's active
/// views, ordered Active-first so the tests above can index them positionally.
/// `is_default DESC` gives that ordering without depending on insertion order
/// or on the names themselves.
async fn seeded_views(db: &DbPool, entity_id: Uuid) -> Vec<(String, bool, String, Option<String>)> {
    sqlx::query_as(
        "SELECT v.name, v.is_default, q.sql_query, q.required_privilege \
         FROM view v \
         JOIN sql_query q ON q.id = v.sql_query_ref \
         WHERE v.entity_logical_name = $1 AND v.is_active = true \
         ORDER BY v.is_default DESC, v.name",
    )
    .bind(entity_id)
    .fetch_all(db)
    .await
    .expect("query seeded views")
}

/// C-20 proof. Before this fix, `reconcile_entity`'s `Create`/`Update`
/// transaction held one pooled connection for its whole lifetime (global
/// metadata-write lock -> per-entity lock -> row write -> commit) while
/// `provision_table` — called *inside* that same transaction, on the pool
/// rather than the open `tx` — ran its own ~12 `exec_ddl_locked`
/// transactions and two `CREATE INDEX CONCURRENTLY` calls, each needing to
/// check out ANOTHER connection from that same pool (`write_attribute_row`'s
/// `provision_column` call had the identical shape). A pool with exactly
/// one connection can never grant that second checkout while the first is
/// held, so provisioning a genuinely new entity/field would hang until
/// sqlx's own acquire timeout elapsed, then fail — never complete.
///
/// This is the harness the task calls "the C-12 `max_connections = 1`
/// harness"; C-12 itself (a general single-connection test rig reusable
/// across suites) is a separate, not-yet-landed item, so this test builds
/// its own single-connection pool rather than reusing infrastructure that
/// doesn't exist yet — a reasonable equivalent scoped to this fix.
#[tokio::test]
async fn provisioning_a_new_entity_and_field_succeeds_on_a_single_connection_pool() {
    let Some(url) = attome_testkit::migrated_db_url() else {
        eprintln!(
            "SKIP {}:{}: set DATABASE_URL to a throwaway test database to run this \
             (NEVER attome_dev)",
            module_path!(),
            line!(),
        );
        return;
    };
    let db = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect DATABASE_URL with a single-connection pool");
    let logicalname = format!("test_prov_{}", Uuid::now_v7().simple());

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let entity_id = ensure_entity(&db, &logicalname, "Single Conn Test", None, false).await?;
        ensure_attribute(
            &db, entity_id, "title", "Title", "text", true, false, false, false, None, None,
        )
        .await?;
        Ok::<Uuid, attome_types::AppError>(entity_id)
    })
    .await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!(
            "provisioning a new entity+field on a single-connection pool must succeed, \
             not fail with a database error: {e}"
        ),
        Err(_) => panic!(
            "provisioning a new entity+field on a single-connection pool timed out after \
             10s — this is the C-20 self-deadlock: physical DDL trying to open a second \
             pool connection while the metadata transaction still holds the only one"
        ),
    }
}
