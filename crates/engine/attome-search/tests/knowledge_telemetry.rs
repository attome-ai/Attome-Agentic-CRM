//! M37 Knowledge Management Phase 2 (D-452) — chunk retrieval telemetry,
//! gap-topic logging, staleness, and semantic neighbors, against a real
//! database. Same shape as `tests/impression_log.rs` and
//! `tests/knowledge_visibility.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test knowledge_telemetry -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::knowledge::{semantic_neighbors, stale_by_source_id};
use attome_search::{record_chunk_retrievals, record_gap_topic, retrieval_counts_by_source};
use attome_testkit::skip_if_no_db;
use chrono::{NaiveDate, Utc};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

async fn insert_article_chunk(db: &DbPool, source_id: Uuid, ordinal: i32) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO knowledge_chunk \
            (id, collection_ref, source_type, source_id, lifecycle, ordinal, \
             text_display, text_indexed, tsv) \
         VALUES ($1, $2, 'article', $3, 'published', $4, 'text', 'text', \
                 to_tsvector('attome_search', 'text'))",
    )
    .bind(id)
    .bind(Uuid::now_v7())
    .bind(source_id)
    .bind(ordinal)
    .execute(db)
    .await
    .expect("seed chunk");
    id
}

async fn insert_space(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_space (id, name, created_by, updated_by, owner_layer) VALUES ($1, $2, $3, $3, 'project')",
    )
    .bind(id)
    .bind(format!("Telemetry Test Space {id}"))
    .bind(actor)
    .execute(db)
    .await
    .expect("insert content_space");
    id
}

async fn insert_page(db: &DbPool, space_id: Uuid, review_by: Option<NaiveDate>) -> Uuid {
    let id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_page \
            (id, content_space_id, title, url_path, status, blocks_draft, blocks_published, \
             review_by, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, 'published', '[]'::jsonb, '[]'::jsonb, $5, $6, $6)",
    )
    .bind(id)
    .bind(space_id)
    .bind(format!("Telemetry Test Page {id}"))
    .bind(format!("/telemetry-test-{id}"))
    .bind(review_by)
    .bind(actor)
    .execute(db)
    .await
    .expect("insert content_page");
    id
}

// ── record_chunk_retrievals / retrieval_counts_by_source ────────────────────

#[tokio::test]
async fn retrieval_counts_are_grouped_by_the_chunks_source_page() {
    let db = skip_if_no_db!(test_db().await);
    let space = insert_space(&db).await;
    let page_a = insert_page(&db, space, None).await;
    let page_b = insert_page(&db, space, None).await;

    let a1 = insert_article_chunk(&db, page_a, 0).await;
    let a2 = insert_article_chunk(&db, page_a, 1).await;
    let b1 = insert_article_chunk(&db, page_b, 0).await;

    // Two retrievals against page A's chunks, one against page B's.
    record_chunk_retrievals(&db, &[a1, a2, b1])
        .await
        .expect("record retrievals");

    let since = Utc::now() - chrono::Duration::hours(1);
    let counts = retrieval_counts_by_source(&db, since)
        .await
        .expect("retrieval_counts_by_source");
    assert_eq!(counts.get(&page_a).copied(), Some(2));
    assert_eq!(counts.get(&page_b).copied(), Some(1));
}

#[tokio::test]
async fn a_retrieval_before_the_cutoff_is_not_counted() {
    let db = skip_if_no_db!(test_db().await);
    let space = insert_space(&db).await;
    let page = insert_page(&db, space, None).await;
    let chunk = insert_article_chunk(&db, page, 0).await;

    record_chunk_retrievals(&db, &[chunk])
        .await
        .expect("record retrieval");

    // A cutoff in the future must exclude the retrieval just recorded.
    let since = Utc::now() + chrono::Duration::hours(1);
    let counts = retrieval_counts_by_source(&db, since)
        .await
        .expect("retrieval_counts_by_source");
    assert_eq!(counts.get(&page), None);
}

#[tokio::test]
async fn recording_an_empty_chunk_list_is_a_safe_no_op() {
    let db = skip_if_no_db!(test_db().await);
    record_chunk_retrievals(&db, &[])
        .await
        .expect("recording zero chunks must not error");
}

// ── record_gap_topic ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_gap_topic_is_logged_once_and_repeat_hits_increment_it() {
    let db = skip_if_no_db!(test_db().await);
    // Enough surviving tokens to pass normalize_gap_phrase's minimum, and
    // unique enough not to collide with another test's row under the
    // UNIQUE(normalized_phrase) constraint.
    let query = format!(
        "what is our policy on remote access token {}",
        Uuid::now_v7()
    );

    record_gap_topic(&db, &query)
        .await
        .expect("first occurrence");
    record_gap_topic(&db, &query)
        .await
        .expect("second occurrence");

    // The digit-bearing uuid token is dropped by normalize_gap_phrase, so
    // the two calls above normalize to the identical stored phrase and must
    // collapse into one row with hit_count = 2, not two rows.
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT hit_count FROM knowledge_gap_topic \
         WHERE normalized_phrase LIKE 'policy remote access%'",
    )
    .fetch_all(&db)
    .await
    .expect("query knowledge_gap_topic");
    assert_eq!(
        rows.len(),
        1,
        "a repeated topic must accumulate, not duplicate"
    );
    assert_eq!(rows[0].0, 2);
}

#[tokio::test]
async fn a_query_that_scrubs_to_nothing_writes_no_row() {
    let db = skip_if_no_db!(test_db().await);
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM knowledge_gap_topic")
        .fetch_one(&db)
        .await
        .expect("count before");

    record_gap_topic(&db, "12345")
        .await
        .expect("must no-op, not error");

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM knowledge_gap_topic")
        .fetch_one(&db)
        .await
        .expect("count after");
    assert_eq!(
        before, after,
        "a fully-scrubbed query must not create a row"
    );
}

// ── stale_by_source_id ───────────────────────────────────────────────────────

#[tokio::test]
async fn staleness_is_computed_from_each_pages_own_review_by_date() {
    let db = skip_if_no_db!(test_db().await);
    let space = insert_space(&db).await;
    let past = (Utc::now() - chrono::Duration::days(1)).date_naive();
    let future = (Utc::now() + chrono::Duration::days(30)).date_naive();

    let stale_page = insert_page(&db, space, Some(past)).await;
    let fresh_page = insert_page(&db, space, Some(future)).await;
    let unset_page = insert_page(&db, space, None).await;

    let result = stale_by_source_id(&db, &[stale_page, fresh_page, unset_page])
        .await
        .expect("stale_by_source_id");
    assert_eq!(result.get(&stale_page), Some(&true));
    assert_eq!(result.get(&fresh_page), Some(&false));
    assert_eq!(
        result.get(&unset_page),
        Some(&false),
        "no review cadence set must not read as stale"
    );
}

#[tokio::test]
async fn an_empty_source_id_list_returns_an_empty_map_without_querying() {
    let db = skip_if_no_db!(test_db().await);
    let result = stale_by_source_id(&db, &[])
        .await
        .expect("stale_by_source_id");
    assert!(result.is_empty());
}

// ── semantic_neighbors ───────────────────────────────────────────────────────

#[tokio::test]
async fn semantic_neighbors_is_empty_when_no_chunk_has_an_embedding_yet() {
    let db = skip_if_no_db!(test_db().await);
    let space = insert_space(&db).await;
    let page = insert_page(&db, space, None).await;
    insert_article_chunk(&db, page, 0).await;

    // D-452's documented current state: nothing in this workspace populates
    // `embedding` yet, so the query must degrade to an empty result rather
    // than error — this is the exact scenario every fresh deployment is in
    // today, not a corner case.
    let neighbors = semantic_neighbors(&db, page, 5)
        .await
        .expect("semantic_neighbors must not error on an unembedded corpus");
    assert!(neighbors.is_empty());
}

#[tokio::test]
async fn semantic_neighbors_of_an_unknown_page_is_empty_not_an_error() {
    let db = skip_if_no_db!(test_db().await);
    let neighbors = semantic_neighbors(&db, Uuid::now_v7(), 5)
        .await
        .expect("semantic_neighbors must not error on an unknown page id");
    assert!(neighbors.is_empty());
}
