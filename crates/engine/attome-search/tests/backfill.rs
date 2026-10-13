//! The backfill must actually index pre-existing records, and must not lose
//! changes that happen while it runs (TODO-014).
//!
//! Both halves matter and only one is obvious. "Did it load the rows" is what
//! anyone would test. **"Did it lose the records that changed mid-scan"** is
//! the one that ships broken: the scan captures a value, the record changes
//! after the scan passes it, and if the cursor were advanced to "now" at the
//! end, the event that would have fixed it is skipped as already-consumed. The
//! record is then permanently stale in the index with nothing to indicate it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test backfill -- --test-threads=1
//! ```
//!
//! **Serial only.** These tests rename `search_index`, which is a
//! cluster-visible ACCESS EXCLUSIVE operation — running them alongside anything
//! else touching that table is a deadlock, not a flake.

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
use attome_search::{Backfill, project};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use std::sync::OnceLock;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// The table swap is not isolatable, so these tests take a process-wide lock
/// rather than pretending they can interleave.
/// `tokio::sync::Mutex`: the guard is held across `.await` for the whole test
/// body, which is exactly what a blocking guard must never do (guidelines §10).
async fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn rows(
    entity: &str,
    n: usize,
) -> Vec<(
    Uuid,
    attome_search::ProjectedRow,
    Option<Uuid>,
    Option<Uuid>,
)> {
    (0..n)
        .map(|i| {
            (
                Uuid::now_v7(),
                project(
                    &format!("{entity} record {i}"),
                    None,
                    &format!("body text for record {i} شركة"),
                    vec![format!("key-{i}")],
                ),
                None,
                None,
            )
        })
        .collect()
}

/// Every pre-existing record is findable afterwards — the G4 assertion, and
/// the whole reason the module exists.
#[tokio::test]
async fn a_backfill_makes_pre_existing_records_findable() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = format!("test_bf_{}", Uuid::now_v7().simple());

    let batch = rows(&entity, 250);

    let mut bf = Backfill::start(&db).await.expect("start");
    bf.load_batch(&db, &entity, &batch).await.expect("load");
    let loaded = bf.finish(&db).await.expect("finish");
    assert_eq!(loaded, 250);

    let found: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM search_index WHERE entity_logicalname = $1")
            .bind(&entity)
            .fetch_one(&db)
            .await
            .expect("count");
    assert_eq!(found, 250, "every scanned record must be in the index");

    // Findable, not merely present: the tsvector was built during the load and
    // the indexes after it, so a lexical query must actually match.
    let matched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM search_index \
         WHERE entity_logicalname = $1 AND tsv @@ plainto_tsquery('attome_search', $2)",
    )
    .bind(&entity)
    .bind(attome_search::index_text("body"))
    .fetch_one(&db)
    .await
    .expect("lexical count");
    assert_eq!(matched, 250, "loaded rows must be lexically searchable");

    // And the Arabic half, through the same load path.
    let arabic: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM search_index \
         WHERE entity_logicalname = $1 AND tsv @@ plainto_tsquery('attome_search', $2)",
    )
    .bind(&entity)
    .bind(attome_search::index_text("شركه"))
    .fetch_one(&db)
    .await
    .expect("arabic count");
    assert_eq!(
        arabic, 250,
        "Arabic text must be searchable after a backfill"
    );

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}

/// **The subtle one.** The cursor is rewound to where it stood BEFORE the
/// scan, not advanced to now.
///
/// A backfill runs for minutes to hours. Records change during it. Advancing
/// the cursor at the end would skip exactly those events — the scan captured
/// the old value, and the event that would have corrected it is marked
/// consumed. The record stays permanently wrong in the index with nothing to
/// signal it.
#[tokio::test]
async fn the_cursor_is_rewound_so_mid_scan_changes_are_replayed() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = format!("test_bf_{}", Uuid::now_v7().simple());

    // Advance the drain's cursor to somewhere non-zero first, so "rewound to
    // the mark" is distinguishable from "reset to zero".
    let mut conn = db.acquire().await.expect("acquire");
    attome_core::change_feed::cursor(&mut conn, "attome-search/index-drain")
        .await
        .expect("register cursor");
    sqlx::query(
        "UPDATE change_consumer_cursor \
            SET last_commit_xid = pg_current_xact_id() \
          WHERE consumer = 'attome-search/index-drain'",
    )
    .execute(&db)
    .await
    .expect("advance the cursor");

    let before: i64 = sqlx::query_scalar(
        "SELECT last_commit_xid::text::bigint FROM change_consumer_cursor \
         WHERE consumer = 'attome-search/index-drain'",
    )
    .fetch_one(&db)
    .await
    .expect("read cursor");
    assert!(
        before > 0,
        "the cursor must be non-zero for this test to mean anything"
    );

    let bf = Backfill::start(&db).await.expect("start");
    assert_eq!(
        bf.cursor_mark(),
        before,
        "the mark must be taken BEFORE the scan — taking it after would leave \
         a window whose events are neither scanned nor replayed"
    );

    // Events committed DURING the scan. These are what must survive.
    let mut tx = db.begin().await.expect("begin");
    attome_core::change_feed::emit(
        &mut tx,
        &entity,
        Uuid::now_v7(),
        attome_core::ChangeOperation::Update,
    )
    .await
    .expect("emit mid-scan event");
    tx.commit().await.expect("commit");

    bf.finish(&db).await.expect("finish");

    let after: i64 = sqlx::query_scalar(
        "SELECT last_commit_xid::text::bigint FROM change_consumer_cursor \
         WHERE consumer = 'attome-search/index-drain'",
    )
    .fetch_one(&db)
    .await
    .expect("read cursor");

    assert_eq!(
        after, before,
        "the cursor must be rewound to the pre-scan mark, NOT advanced — \
         advancing loses every record that changed while the scan ran"
    );
}

/// The swapped-in table carries its indexes and its primary key. A backfill
/// that produced a correct but unindexed table would look entirely healthy and
/// turn every query into a sequential scan.
#[tokio::test]
async fn the_swapped_table_has_its_indexes_and_primary_key() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;

    let bf = Backfill::start(&db).await.expect("start");
    bf.finish(&db).await.expect("finish");

    let index_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_indexes \
         WHERE tablename = 'search_index' AND schemaname = current_schema()",
    )
    .fetch_one(&db)
    .await
    .expect("count indexes");
    assert!(
        index_count >= 6,
        "the swapped table must carry every index the migration defines, not \
         just exist — got {index_count}"
    );

    let has_pk: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint c \
            JOIN pg_class t ON t.oid = c.conrelid \
          WHERE t.relname = 'search_index' AND c.contype = 'p')",
    )
    .fetch_one(&db)
    .await
    .expect("check pk");
    assert!(has_pk, "the upsert's ON CONFLICT needs the primary key");

    // LOGGED, not UNLOGGED. Staging is unlogged for load speed; swapping an
    // unlogged table in as the live index means the first crash empties search
    // silently, and the symptom is "search returns nothing" on a table that
    // looks perfectly healthy.
    let persistence: String = sqlx::query_scalar(
        "SELECT relpersistence::text FROM pg_class \
         WHERE relname = 'search_index'",
    )
    .fetch_one(&db)
    .await
    .expect("check persistence");
    assert_eq!(
        persistence, "p",
        "the live index must be LOGGED — an unlogged one is emptied by any crash"
    );
}

/// The drain and the backfill must produce identical rows for identical
/// input. They are different code paths into the same table, and a divergence
/// would make a record's index row depend on how it got there — which surfaces
/// as "some records aren't findable" long after anyone can connect it to the
/// cause.
#[tokio::test]
async fn the_backfill_and_the_drain_agree_on_content_hash() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = format!("test_bf_{}", Uuid::now_v7().simple());
    let record_id = Uuid::now_v7();

    let row = project("ACME", None, "invoice body", vec!["k-1".into()]);

    let mut bf = Backfill::start(&db).await.expect("start");
    bf.load_batch(&db, &entity, &[(record_id, row.clone(), None, None)])
        .await
        .expect("load");
    bf.finish(&db).await.expect("finish");

    // The drain now sees the same content. The hash gate must recognise it as
    // unchanged and skip the write — which is only true if both paths computed
    // the same hash from the same projection.
    let wrote = attome_search::upsert_row(&db, &entity, record_id, &row, None, None, None)
        .await
        .expect("drain upsert");
    assert!(
        !wrote,
        "the drain must recognise a backfilled row as unchanged — if it \
         rewrites, the two paths disagree about what they projected"
    );

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}
