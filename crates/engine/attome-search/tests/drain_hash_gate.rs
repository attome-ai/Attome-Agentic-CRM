//! The `content_hash` gate must actually prevent the write (TODO-016).
//!
//! Asserting that the SQL *contains* `IS DISTINCT FROM` proves nothing about
//! whether PostgreSQL skips the row — an `ON CONFLICT DO UPDATE ... WHERE` that
//! is subtly wrong still parses, still runs, and still rewrites every row. The
//! only way to know is to write twice and look at whether the tuple moved.
//!
//! `xmin` is the instrument: PostgreSQL stamps every row version with the
//! transaction that created it, so an unchanged `xmin` after a second upsert
//! means no new tuple was written — no dead tuple, no GIN churn, and in Stage 2
//! no repeated embedding call.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test drain_hash_gate
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::{delete_row, project, upsert_row};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// The row version PostgreSQL currently holds. A changed `xmin` means the row
/// was rewritten; an unchanged one means the upsert was genuinely a no-op.
async fn row_version(db: &DbPool, entity: &str, record_id: Uuid) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT xmin::text::bigint FROM search_index \
         WHERE corpus = 'record' AND entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_optional(db)
    .await
    .expect("read xmin")
}

/// **The TODO-016 assertion.** Re-draining an unchanged record produces zero
/// row versions.
///
/// The cursor's visibility horizon means the drain legitimately re-reads a
/// window of events — §11.3 estimates each is re-projected about twelve times.
/// Without this gate that is twelve dead tuples and twelve rounds of GIN churn
/// per record, and in Stage 2 twelve embedding calls of GPU time the customer
/// paid for.
#[tokio::test]
async fn re_upserting_unchanged_content_writes_no_new_row_version() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_gate_{}", Uuid::now_v7().simple());
    let record_id = Uuid::now_v7();

    let row = project(
        "ACME Trading LLC",
        None,
        "Invoice for services rendered",
        vec!["inv-4242".into()],
    );

    assert!(
        upsert_row(&db, &entity, record_id, &row, None, None, None)
            .await
            .expect("first upsert"),
        "the first write must land"
    );
    let first = row_version(&db, &entity, record_id)
        .await
        .expect("row exists");

    // Twelve, to mirror the re-read window the gate exists to absorb.
    for i in 0..12 {
        let wrote = upsert_row(&db, &entity, record_id, &row, None, None, None)
            .await
            .expect("repeat upsert");
        assert!(
            !wrote,
            "repeat {i} rewrote an unchanged row — every indexed column changes \
             on rewrite, so HOT updates are impossible and each no-op write is \
             a dead tuple plus GIN churn on four indexes"
        );
    }

    let after = row_version(&db, &entity, record_id)
        .await
        .expect("row exists");
    assert_eq!(
        first, after,
        "the row version must not move for unchanged content"
    );

    delete_row(&db, &entity, record_id).await.expect("cleanup");
}

/// The gate must not be so eager that it swallows a real change. A gate that
/// never writes is worse than no gate: the index silently stops tracking the
/// data and every result slowly becomes wrong.
#[tokio::test]
async fn changed_content_does_write() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_gate_{}", Uuid::now_v7().simple());
    let record_id = Uuid::now_v7();

    let before = project("ACME Trading LLC", None, "Invoice", vec!["inv-1".into()]);
    upsert_row(&db, &entity, record_id, &before, None, None, None)
        .await
        .expect("first upsert");
    let v1 = row_version(&db, &entity, record_id)
        .await
        .expect("row exists");

    // Each field changed independently, because a hash that only covered the
    // body would pass a title-only edit straight through.
    for changed in [
        project("ACME Trading FZE", None, "Invoice", vec!["inv-1".into()]),
        project(
            "ACME Trading FZE",
            None,
            "Invoice paid",
            vec!["inv-1".into()],
        ),
        project(
            "ACME Trading FZE",
            None,
            "Invoice paid",
            vec!["inv-2".into()],
        ),
        project(
            "ACME Trading FZE",
            Some("subtitle"),
            "Invoice paid",
            vec!["inv-2".into()],
        ),
    ] {
        assert!(
            upsert_row(&db, &entity, record_id, &changed, None, None, None)
                .await
                .expect("upsert changed content"),
            "a genuine change must write"
        );
    }

    let v2 = row_version(&db, &entity, record_id)
        .await
        .expect("row exists");
    assert_ne!(v1, v2, "the row must have been rewritten");

    delete_row(&db, &entity, record_id).await.expect("cleanup");
}

/// The written row is actually searchable — the `tsvector` is built from the
/// normalized, stemmed body rather than left null.
///
/// A gate that skipped writes correctly but produced an unsearchable row would
/// pass every test above and fail the only thing that matters.
#[tokio::test]
async fn the_written_row_is_searchable() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_gate_{}", Uuid::now_v7().simple());
    let record_id = Uuid::now_v7();

    let row = project(
        "شركة أكمي للتجارة",
        None,
        "Invoices for the quarter",
        vec!["inv-7".into()],
    );
    upsert_row(&db, &entity, record_id, &row, None, None, None)
        .await
        .expect("upsert");

    // Lexical: the plural in the body must match the singular in the query,
    // which only works if index-time and query-time stemming agree.
    let lexical: bool = sqlx::query_scalar(
        "SELECT tsv @@ plainto_tsquery('attome_search', $3) \
         FROM search_index \
         WHERE corpus = 'record' AND entity_logicalname = $1 AND record_id = $2",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(attome_search::index_text("invoice"))
    .fetch_one(&db)
    .await
    .expect("lexical probe");
    assert!(lexical, "the stemmed body must match a stemmed query");

    // Arabic: the normalized title must match a query typed without
    // diacritics — the F206 property, end to end through a real write.
    let title_norm: String = sqlx::query_scalar(
        "SELECT title_norm FROM search_index \
         WHERE corpus = 'record' AND entity_logicalname = $1 AND record_id = $2",
    )
    .bind(&entity)
    .bind(record_id)
    .fetch_one(&db)
    .await
    .expect("read title_norm");
    assert_eq!(
        title_norm,
        attome_search::normalize_ar("شركه اكمي للتجاره"),
        "a title written with hamza and taa marbuta must normalize to the same \
         form a user typing without them produces"
    );

    delete_row(&db, &entity, record_id).await.expect("cleanup");
}

/// Delete removes the row. This is the disclosure half of D-358: a
/// soft-deleted or purged record must stop being findable, and "stop being
/// findable" means the index row is gone, not hidden.
#[tokio::test]
async fn delete_removes_the_row_entirely() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_gate_{}", Uuid::now_v7().simple());
    let record_id = Uuid::now_v7();

    let row = project("ACME", None, "body", vec![]);
    upsert_row(&db, &entity, record_id, &row, None, None, None)
        .await
        .expect("upsert");
    assert!(row_version(&db, &entity, record_id).await.is_some());

    assert!(
        delete_row(&db, &entity, record_id).await.expect("delete"),
        "deleting an existing row reports that it deleted something"
    );
    assert!(
        row_version(&db, &entity, record_id).await.is_none(),
        "a purged record must leave NO index row — it is a second copy of \
         business text and inherits the erasure obligation (D-358)"
    );

    // Deleting again is a no-op rather than an error: the drain is idempotent
    // and re-reads its window.
    assert!(
        !delete_row(&db, &entity, record_id)
            .await
            .expect("re-delete"),
        "a repeat delete reports that it deleted nothing"
    );
}
