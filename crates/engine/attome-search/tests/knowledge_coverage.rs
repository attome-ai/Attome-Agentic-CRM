//! The operator's knowledge coverage read (chatbot plan C8):
//! `attome_search::knowledge_coverage::collection_coverage`.
//!
//! Every number is checked against rows this test wrote, in a collection only
//! this test uses: items by lifecycle (a soft-deleted item does not count),
//! chunks for published items only, the last index write, and the embedding
//! backlog relative to the configured model — `None` when there is none.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-search --test knowledge_coverage -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::knowledge_coverage::{CollectionCoverage, collection_coverage};
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

mod knowledge_harness;
use knowledge_harness::{
    assert_then_cleanup, delete_article, insert_article, insert_source, provision_kb, test_db,
};

const ARTICLE: &str = "# Returns\n\nItems can be returned within thirty days.\n\n\
                       # Exchanges\n\nExchanges are free for the first month.";

/// This collection's row, walking every page: the shared database holds other
/// tests' collections, and the read orders by name.
async fn coverage_of(db: &DbPool, model: Option<&str>, source: Uuid) -> CollectionCoverage {
    let page_size = 100;
    let mut offset = 0;
    loop {
        let (items, total) = collection_coverage(db, model, page_size, offset)
            .await
            .expect("coverage read");
        if let Some(row) = items.into_iter().find(|c| c.collection_id == source) {
            return row;
        }
        offset += page_size;
        assert!(
            offset < total,
            "collection {source} is not in the coverage read"
        );
    }
}

async fn chunk_count(db: &DbPool, source: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM knowledge_chunk \
          WHERE collection_ref = $1 AND lifecycle = 'published'",
    )
    .bind(source)
    .fetch_one(db)
    .await
    .expect("chunk count")
}

async fn article(db: &DbPool, source: Uuid, lifecycle: &str) -> Uuid {
    let item = insert_article(
        db,
        source,
        &format!("{lifecycle} article"),
        ARTICLE,
        lifecycle,
    )
    .await;
    attome_search::reindex_item(db, item)
        .await
        .expect("reindex");
    item
}

async fn cleanup(db: DbPool, items: Vec<Uuid>, source: Uuid) {
    for item in &items {
        delete_article(&db, *item, None).await;
    }
    delete_article(&db, Uuid::nil(), Some(source)).await;
}

/// Items count by lifecycle among live rows only; chunks exist for the
/// published item alone (D-489), and the last index write is theirs. With no
/// configured model there is no backlog to report, so both embedding figures
/// are `None` rather than a count that could never drain.
#[tokio::test]
async fn counts_items_by_lifecycle_and_chunks_only_what_is_published() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Coverage {}", Uuid::now_v7().simple())).await;
    let published = article(&db, source, "published").await;
    let draft = article(&db, source, "draft").await;
    let expired = article(&db, source, "expired").await;
    let deleted = article(&db, source, "published").await;
    sqlx::query("UPDATE knowledge_data_item SET is_active = FALSE WHERE id = $1")
        .bind(deleted)
        .execute(&db)
        .await
        .expect("soft delete");
    attome_search::reindex_item(&db, deleted)
        .await
        .expect("reindex the deletion");

    let body_db = db.clone();
    assert_then_cleanup(
        async move {
            let db = body_db;
            let row = coverage_of(&db, None, source).await;
            assert_eq!(row.items_total, 3, "the soft-deleted item is not counted");
            assert_eq!(row.items_published, 1);
            assert_eq!(row.items_draft, 1);
            assert_eq!(row.items_expired, 1);
            let chunks = chunk_count(&db, source).await;
            assert!(chunks >= 1, "the published item is chunked");
            assert_eq!(row.chunks, chunks);
            let own: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM knowledge_chunk WHERE source_id = $1")
                    .bind(published)
                    .fetch_one(&db)
                    .await
                    .expect("own chunks");
            assert_eq!(own, chunks, "every chunk belongs to the published item");
            assert!(row.last_indexed_at.is_some());
            assert_eq!(row.chunks_embedded, None);
            assert_eq!(row.embedding_backlog, None);
        },
        cleanup(db.clone(), vec![published, draft, expired, deleted], source),
    )
    .await;
}

/// The backlog is relative to the configured model: a chunk carrying another
/// model's vector is still waiting, because retrieval's vector leg reads only
/// the configured model's vectors.
#[tokio::test]
async fn the_embedding_backlog_is_relative_to_the_configured_model() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Coverage {}", Uuid::now_v7().simple())).await;
    let first = article(&db, source, "published").await;
    let second = article(&db, source, "published").await;
    let embedded: Uuid = sqlx::query_scalar(
        "SELECT id FROM knowledge_chunk WHERE source_id = $1 ORDER BY ordinal LIMIT 1",
    )
    .bind(first)
    .fetch_one(&db)
    .await
    .expect("a chunk to embed");
    sqlx::query(
        "UPDATE knowledge_chunk \
            SET embedding = array_fill(0.5::real, ARRAY[1024])::vector::halfvec, \
                embedding_model = 'model-a' \
          WHERE id = $1",
    )
    .bind(embedded)
    .execute(&db)
    .await
    .expect("embed one chunk");

    let body_db = db.clone();
    assert_then_cleanup(
        async move {
            let db = body_db;
            let chunks = chunk_count(&db, source).await;
            assert!(chunks >= 2, "two published articles");

            let a = coverage_of(&db, Some("model-a"), source).await;
            assert_eq!(a.chunks, chunks);
            assert_eq!(a.chunks_embedded, Some(1));
            assert_eq!(a.embedding_backlog, Some(chunks - 1));

            let b = coverage_of(&db, Some("model-b"), source).await;
            assert_eq!(
                b.chunks_embedded,
                Some(0),
                "model-a's vector is not model-b's"
            );
            assert_eq!(b.embedding_backlog, Some(chunks));

            let lexical = coverage_of(&db, None, source).await;
            assert_eq!(lexical.embedding_backlog, None);
        },
        cleanup(db.clone(), vec![first, second], source),
    )
    .await;
}

/// A collection with nothing in it is listed with zeros, not dropped.
#[tokio::test]
async fn an_empty_collection_is_listed_with_zeros() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Coverage {}", Uuid::now_v7().simple())).await;

    let body_db = db.clone();
    assert_then_cleanup(
        async move {
            let row = coverage_of(&body_db, Some("model-a"), source).await;
            assert_eq!(row.items_total, 0);
            assert_eq!(row.chunks, 0);
            assert_eq!(row.last_indexed_at, None);
            assert_eq!(row.chunks_embedded, Some(0));
            assert_eq!(row.embedding_backlog, Some(0));
        },
        cleanup(db.clone(), Vec::new(), source),
    )
    .await;
}
