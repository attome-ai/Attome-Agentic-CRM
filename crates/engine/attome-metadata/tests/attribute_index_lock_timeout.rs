//! attome-db hardening Phase 1.3c: evidence for whether the migrator
//! connection may carry a `lock_timeout`.
//!
//! `sync_attribute_index` runs `CREATE`/`DROP INDEX CONCURRENTLY` on the
//! migrator connection. This test sets `lock_timeout = '1s'` on a
//! migrator-shaped session itself (independent of the production default),
//! blocks the build two different ways, and checks what state each
//! interruption leaves behind and whether one follow-up sync repairs it:
//!
//! 1. Blocked before the index exists (`LOCK TABLE … IN SHARE MODE`). The
//!    timeout must fire, leave no index, and the next sync must build a
//!    valid one.
//! 2. Blocked while `CREATE INDEX CONCURRENTLY` waits for an older snapshot
//!    (an open REPEATABLE READ transaction). If the timeout fires, the index
//!    is left INVALID and the next sync must drop and rebuild it.
//! 3. If PostgreSQL does *not* apply `lock_timeout` to that snapshot wait,
//!    the build simply waits for the blocker, and the test records it.
//!
//! A background task commits the blocking transaction after
//! `RELEASE_AFTER`, so the test can never hang. It runs as one sequential
//! test: a concurrent index build waits on older transactions across the
//! whole database, so parallel tests in this binary would interfere.
//!
//! Needs a live Postgres (`DATABASE_URL`, throwaway clone via
//! `attome_testkit`, never `attome_dev`). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-metadata --test attribute_index_lock_timeout -- --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_metadata::ADVISORY_LOCK_NAMESPACE;
use attome_metadata::provision::{attribute_index_name, sync_attribute_index_on_connection};
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

const FIELD: &str = "code";
/// Far longer than the 1s `lock_timeout`: a sync that returns before this
/// was cut short by the timeout; one that returns after it waited for the
/// blocker to commit.
const RELEASE_AFTER: Duration = Duration::from_secs(8);

async fn connect(url: &str) -> PgConnection {
    PgConnection::connect(url)
        .await
        .expect("connect to the test database")
}

async fn exec(conn: &mut PgConnection, sql: &str) {
    sqlx::query(sql)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("`{sql}` must succeed: {e}"));
}

/// Same session settings as `attome_db::create_migrator_connection`, plus the
/// candidate `lock_timeout`.
async fn migrator_shaped_session(url: &str) -> PgConnection {
    let mut conn = connect(url).await;
    exec(&mut conn, "SET statement_timeout = 0").await;
    exec(&mut conn, "SET lock_timeout = '1s'").await;
    conn
}

/// A small table shaped like a provisioned entity (the partial index needs
/// `is_active`).
async fn create_table(url: &str) -> String {
    let table = format!("lt_{}", Uuid::now_v7().simple());
    let mut conn = connect(url).await;
    exec(
        &mut conn,
        &format!(
            "CREATE TABLE \"{table}\" (id int PRIMARY KEY, {FIELD} text, \
             is_active boolean NOT NULL DEFAULT true)"
        ),
    )
    .await;
    exec(
        &mut conn,
        &format!(
            "INSERT INTO \"{table}\" (id, {FIELD}) SELECT g, 'c' || g FROM generate_series(1, 100) g"
        ),
    )
    .await;
    let _ = conn.close().await;
    table
}

/// `Some(indisvalid)` when the index exists, `None` when it doesn't.
async fn index_validity(url: &str, index: &str) -> Option<bool> {
    let mut conn = connect(url).await;
    let validity = sqlx::query_scalar(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
         WHERE c.relname = $1",
    )
    .bind(index)
    .fetch_optional(&mut conn)
    .await
    .expect("read index validity");
    let _ = conn.close().await;
    validity
}

fn lock_key(table: &str) -> String {
    format!("attome-metadata/attribute-index:{table}:{FIELD}")
}

async fn advisory_key_is_free(url: &str, table: &str) -> bool {
    let mut conn = connect(url).await;
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(table))
        .fetch_one(&mut conn)
        .await
        .expect("try the attribute-index advisory key");
    let _ = conn.close().await;
    free
}

/// What `sync_attribute_index` does after running a sync on its session:
/// release the key, then close the session.
async fn finish_like_the_wrapper(mut conn: PgConnection, table: &str) {
    let _ = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(table))
        .fetch_optional(&mut conn)
        .await;
    let _ = conn.close().await;
}

/// Runs one sync on a migrator-shaped session while another session, set up
/// by `blocker_sql`, blocks it. The blocker commits after `RELEASE_AFTER`.
async fn sync_while_blocked(
    url: &str,
    table: &str,
    blocker_sql: &[String],
) -> (Result<(), AppError>, Duration) {
    let mut blocker = connect(url).await;
    for sql in blocker_sql {
        exec(&mut blocker, sql).await;
    }
    let release = tokio::spawn(async move {
        tokio::time::sleep(RELEASE_AFTER).await;
        exec(&mut blocker, "COMMIT").await;
        let _ = blocker.close().await;
    });

    let mut session = migrator_shaped_session(url).await;
    let started = Instant::now();
    let result = sync_attribute_index_on_connection(&mut session, table, FIELD, true).await;
    let elapsed = started.elapsed();
    finish_like_the_wrapper(session, table).await;
    release.await.expect("blocker task must not panic");
    (result, elapsed)
}

async fn follow_up_sync(url: &str, table: &str) -> Result<(), AppError> {
    let mut session = migrator_shaped_session(url).await;
    let result = sync_attribute_index_on_connection(&mut session, table, FIELD, true).await;
    finish_like_the_wrapper(session, table).await;
    result
}

#[tokio::test]
async fn interrupted_concurrent_index_builds_recover_on_the_next_sync() {
    let url = skip_if_no_db!(attome_testkit::migrated_db_url());

    // Step 1 — blocked before the index exists.
    let table = create_table(&url).await;
    let index = attribute_index_name(&table, FIELD).expect("index name fits");
    let (result, elapsed) = sync_while_blocked(
        &url,
        &table,
        &[
            "BEGIN".to_string(),
            format!("LOCK TABLE \"{table}\" IN SHARE MODE"),
        ],
    )
    .await;
    eprintln!("1.3c step 1 (table lock held): {result:?} after {elapsed:?}");
    assert!(
        result.is_err() && elapsed < RELEASE_AFTER,
        "lock_timeout must bound the wait for the table lock: {result:?} after {elapsed:?}"
    );
    assert_eq!(
        index_validity(&url, &index).await,
        None,
        "a build cut short before taking its lock must leave no index"
    );
    assert!(
        advisory_key_is_free(&url, &table).await,
        "the attribute-index key must be free after the wrapper closes the session"
    );
    let repaired = follow_up_sync(&url, &table).await;
    assert!(repaired.is_ok(), "step 1 follow-up sync: {repaired:?}");
    assert_eq!(
        index_validity(&url, &index).await,
        Some(true),
        "step 1 follow-up sync must leave a valid index"
    );

    // Steps 2 and 3 — blocked while waiting for an older snapshot.
    let table = create_table(&url).await;
    let index = attribute_index_name(&table, FIELD).expect("index name fits");
    let (result, elapsed) = sync_while_blocked(
        &url,
        &table,
        &[
            "BEGIN ISOLATION LEVEL REPEATABLE READ".to_string(),
            format!("SELECT 1 FROM \"{table}\" LIMIT 1"),
        ],
    )
    .await;
    eprintln!("1.3c step 2 (older snapshot held): {result:?} after {elapsed:?}");
    if result.is_err() && elapsed < RELEASE_AFTER {
        assert_eq!(
            index_validity(&url, &index).await,
            Some(false),
            "a build cut short while waiting for an older snapshot must leave an INVALID index"
        );
        eprintln!("1.3c step 2: lock_timeout bounded the snapshot wait; index left INVALID");
    } else {
        assert!(
            result.is_ok(),
            "a build that waited for the blocker must then succeed: {result:?}"
        );
        eprintln!(
            "1.3c step 3: lock_timeout did NOT bound the snapshot wait; the build waited \
             {elapsed:?} for the blocker to commit"
        );
    }
    assert!(
        advisory_key_is_free(&url, &table).await,
        "the attribute-index key must be free after the wrapper closes the session"
    );
    let repaired = follow_up_sync(&url, &table).await;
    assert!(repaired.is_ok(), "step 2 follow-up sync: {repaired:?}");
    assert_eq!(
        index_validity(&url, &index).await,
        Some(true),
        "step 2 follow-up sync must leave a valid index"
    );
}
