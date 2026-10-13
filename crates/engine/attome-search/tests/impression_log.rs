//! The impression log, against a real database (TODO-021).
//!
//! This log is the one asset in the search stage that cannot be recovered if
//! it is wrong. A bug in ranking is a bad week; a bug here is a year of
//! training data that describes something other than what happened, discovered
//! when someone tries to use it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test impression_log
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::{
    Impression, ImpressionRow, query_fingerprint, record_impression, record_interaction,
};
use attome_testkit::skip_if_no_db;
use serde_json::json;
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

fn impression(fingerprint: Vec<u8>, entity: &str) -> Impression<'static> {
    Impression {
        query_fingerprint: fingerprint,
        route: "hybrid",
        ranker_id: "linear/v1",
        audience: "human",
        completeness: json!({ "R1.exact": "Complete", "R2.prefix": "HitCeiling" }),
        caller_ref: Some(Uuid::now_v7()),
        organization_ref: None,
        latency_ms: Some(42),
        rows: (1..=3)
            .map(|rank| ImpressionRow {
                rank,
                entity_logicalname: entity.to_string(),
                record_id: Uuid::now_v7(),
                feature_vector: json!({ "lexical": 0.8, "recency": 0.3, "rank": rank }),
            })
            .collect(),
    }
}

/// One search produces exactly one impression row and one row per displayed
/// result, and a click produces exactly one interaction.
#[tokio::test]
async fn a_search_produces_one_impression_and_its_rows() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_imp_{}", Uuid::now_v7().simple());
    let fp = query_fingerprint("acme trading", b"test-key");

    let imp = impression(fp.clone(), &entity);
    let id = record_impression(&db, &imp)
        .await
        .expect("record impression");

    let (result_count, route, ranker): (i32, String, String) = sqlx::query_as(
        "SELECT result_count, route, ranker_id FROM search_impression WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .expect("read impression");
    assert_eq!(result_count, 3);
    assert_eq!(route, "hybrid");
    assert_eq!(
        ranker, "linear/v1",
        "the ranker must be recorded — a log \
                spanning a ranker change is one population pretending to be two"
    );

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM search_impression_row WHERE impression_ref = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("count rows");
    assert_eq!(rows, 3, "one row per displayed result");

    record_interaction(&db, id, 2, &entity, imp.rows[1].record_id, Some(4_500))
        .await
        .expect("record interaction");

    let (rank, dwell): (i32, Option<i32>) =
        sqlx::query_as("SELECT rank, dwell_ms FROM search_interaction WHERE impression_ref = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("read interaction");
    assert_eq!(rank, 2);
    assert_eq!(dwell, Some(4_500));
}

/// The feature vector is stored **per row, as it was at display time**, and
/// comes back intact.
///
/// This is the column a learned ranker actually trains on. Recomputing these
/// later would describe a world that did not exist when the user chose —
/// recency has decayed, the corpus has shifted every IDF — so a model trained
/// on recomputed features learns the wrong thing with no way to notice.
#[tokio::test]
async fn feature_vectors_are_stored_per_row_and_survive_intact() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_imp_{}", Uuid::now_v7().simple());
    let imp = impression(query_fingerprint("q", b"k"), &entity);
    let id = record_impression(&db, &imp).await.expect("record");

    let stored: Vec<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT rank, feature_vector FROM search_impression_row \
         WHERE impression_ref = $1 ORDER BY rank",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .expect("read feature vectors");

    assert_eq!(stored.len(), 3);
    for (rank, vector) in stored {
        assert_eq!(
            vector["rank"].as_i64(),
            Some(rank as i64),
            "each row must keep ITS OWN feature vector — an off-by-one here \
             would train a ranker on the wrong row's signals, and nothing \
             about the data would look wrong"
        );
        assert!(vector["lexical"].is_number());
    }
}

/// Per-leg completeness rides on the impression. A degraded impression is
/// evidence the retrieval was incomplete, not that the ranking was bad — and a
/// training set that conflates the two teaches a ranker to compensate for
/// outages.
#[tokio::test]
async fn completeness_is_recorded_with_the_impression() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_imp_{}", Uuid::now_v7().simple());
    let id = record_impression(&db, &impression(query_fingerprint("q", b"k"), &entity))
        .await
        .expect("record");

    let completeness: serde_json::Value =
        sqlx::query_scalar("SELECT completeness FROM search_impression WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("read completeness");
    assert_eq!(completeness["R2.prefix"], "HitCeiling");
}

/// **No raw query text reaches the database.** `q` carries customer names and
/// national IDs; a log of those is a second copy of exactly the data 0087/0088
/// exist to govern, accumulating in a table nobody classified.
///
/// Asserted by searching the whole impression row's text for the query — the
/// blunt version, because the failure being guarded against is someone adding
/// a `query_text` column "just for debugging".
#[tokio::test]
async fn no_raw_query_text_is_stored_anywhere_on_the_impression() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_imp_{}", Uuid::now_v7().simple());
    let secret_query = "Mohammed Al-Fulan 784-1990-1234567-1";

    let id = record_impression(
        &db,
        &impression(query_fingerprint(secret_query, b"test-key"), &entity),
    )
    .await
    .expect("record");

    let whole_row: String =
        sqlx::query_scalar("SELECT search_impression::text FROM search_impression WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("read row as text");

    for fragment in ["Mohammed", "Al-Fulan", "784-1990", "1234567"] {
        assert!(
            !whole_row.contains(fragment),
            "the impression row leaks {fragment:?} — query text must never be \
             stored, only its keyed fingerprint (TODO-019)"
        );
    }
}

/// The same query fingerprints identically across searches, which is what
/// makes "did this query start getting clicked differently after the ranking
/// change" answerable at all.
#[tokio::test]
async fn the_same_query_groups_across_impressions() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_imp_{}", Uuid::now_v7().simple());
    let fp = query_fingerprint("مُحَمَّد", b"test-key");

    for _ in 0..3 {
        record_impression(&db, &impression(fp.clone(), &entity))
            .await
            .expect("record");
    }

    let grouped: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM search_impression WHERE query_fingerprint = $1")
            .bind(&fp)
            .fetch_one(&db)
            .await
            .expect("count by fingerprint");
    assert!(grouped >= 3);

    // And the un-diacriticised spelling groups with it — one query, not two.
    assert_eq!(
        query_fingerprint("محمد", b"test-key"),
        fp,
        "two spellings of one Arabic name must be one query in the log"
    );
}

/// Cascade delete: removing an impression removes its rows and interactions.
///
/// Not a convenience — the erasure path needs it. These tables reference
/// records, and a retention or DSR action that removed an impression while
/// leaving its rows behind would leave orphaned references to a record that
/// was supposed to be gone.
#[tokio::test]
async fn deleting_an_impression_removes_its_rows_and_interactions() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_imp_{}", Uuid::now_v7().simple());
    let imp = impression(query_fingerprint("q", b"k"), &entity);
    let id = record_impression(&db, &imp).await.expect("record");
    record_interaction(&db, id, 1, &entity, imp.rows[0].record_id, None)
        .await
        .expect("interaction");

    sqlx::query("DELETE FROM search_impression WHERE id = $1")
        .bind(id)
        .execute(&db)
        .await
        .expect("delete impression");

    let orphan_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM search_impression_row WHERE impression_ref = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("count orphans");
    let orphan_interactions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM search_interaction WHERE impression_ref = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("count orphans");

    assert_eq!(orphan_rows, 0);
    assert_eq!(orphan_interactions, 0);
}
