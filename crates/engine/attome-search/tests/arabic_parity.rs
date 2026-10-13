//! The SQL `normalize_ar` and the Rust `normalize_ar` must agree, exactly, on
//! every vector in the fixture (TODO-009, migration `0106`).
//!
//! **Why this test carries so much weight.** Two callers normalize:
//!
//!   * the drain, in Rust, because it already holds the text and a round trip
//!     per row would be absurd;
//!   * an index expression and any in-place repair, in SQL.
//!
//! If they ever disagree, the index holds one form and the query produces
//! another. Nothing errors. The search simply returns fewer results than it
//! should, for a subset of inputs, and no test that checks only one side would
//! notice. This is the test that makes the two-implementation design safe
//! enough to keep.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test arabic_parity
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::normalize_ar;
use attome_testkit::skip_if_no_db;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

#[derive(Deserialize)]
struct Vectors {
    groups: Vec<Group>,
    must_not_match: Vec<MustNotMatch>,
}

#[derive(Deserialize)]
struct Group {
    name: String,
    normalized: String,
    variants: Vec<String>,
}

#[derive(Deserialize)]
struct MustNotMatch {
    pairs: Vec<Vec<String>>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("fixtures/arabic_vectors.json"))
        .expect("arabic_vectors.json must parse")
}

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

async fn sql_normalize(db: &DbPool, input: &str) -> String {
    sqlx::query_scalar("SELECT normalize_ar($1)")
        .bind(input)
        .fetch_one(db)
        .await
        .expect("normalize_ar must be installed by migration 0106")
}

#[tokio::test]
async fn sql_and_rust_normalize_identically_on_every_vector() {
    let db = skip_if_no_db!(test_db().await);

    for group in vectors().groups {
        for variant in &group.variants {
            let sql = sql_normalize(&db, variant).await;
            let rust = normalize_ar(variant);
            assert_eq!(
                sql, rust,
                "group '{}': SQL and Rust disagree on {variant:?} — the index \
                 would hold one form and the query produce the other, and \
                 nothing would error",
                group.name
            );
            assert_eq!(
                sql, group.normalized,
                "group '{}': SQL normalize_ar({variant:?}) must equal the \
                 fixture's stated form",
                group.name
            );
        }
    }
}

#[tokio::test]
async fn sql_normalization_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);

    // Same reasoning as the Rust test: this function runs at index time and at
    // query time, so a non-idempotent version would let a re-indexed row drift
    // away from the query form over successive reindexes.
    for group in vectors().groups {
        for variant in &group.variants {
            let once = sql_normalize(&db, variant).await;
            let twice = sql_normalize(&db, &once).await;
            assert_eq!(
                once, twice,
                "SQL normalize_ar is not idempotent on {variant:?}"
            );
        }
    }
}

#[tokio::test]
async fn sql_keeps_distinct_words_distinct() {
    let db = skip_if_no_db!(test_db().await);

    for entry in vectors().must_not_match {
        for pair in entry.pairs {
            let (a, b) = (&pair[0], &pair[1]);
            assert_ne!(
                sql_normalize(&db, a).await,
                sql_normalize(&db, b).await,
                "{a:?} and {b:?} are different words and must not collapse"
            );
        }
    }
}

/// IMMUTABLE is not decoration: PostgreSQL refuses to build an index on a
/// non-immutable expression, so a STABLE version of this would silently
/// foreclose the trigram index the typeahead path depends on — and it would do
/// so at index-creation time in a later migration, far from the change that
/// caused it.
#[tokio::test]
async fn normalize_ar_is_immutable_and_therefore_indexable() {
    let db = skip_if_no_db!(test_db().await);

    let volatility: String = sqlx::query_scalar(
        "SELECT p.provolatile::text FROM pg_proc p WHERE p.proname = 'normalize_ar'",
    )
    .fetch_one(&db)
    .await
    .expect("normalize_ar must exist");
    assert_eq!(
        volatility, "i",
        "normalize_ar must be IMMUTABLE ('i') or it cannot appear in an index \
         expression"
    );

    // Proven, not just declared: actually build an index on the expression.
    let table = format!("test_norm_idx_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE TABLE {table} (id int, title text)"))
        .execute(&db)
        .await
        .expect("create throwaway table");
    // A plain btree on the expression, not a trigram one: `pg_trgm` is
    // installed by the search-index migration, and this test must not depend
    // on a later migration to prove a property of this one. Btree is just as
    // strict about IMMUTABLE, which is what is being proven.
    let built = sqlx::query(&format!("CREATE INDEX ON {table} (normalize_ar(title))"))
        .execute(&db)
        .await;
    sqlx::query(&format!("DROP TABLE {table}"))
        .execute(&db)
        .await
        .expect("drop throwaway table");
    built.expect(
        "an index on normalize_ar(title) must be buildable — this is the whole \
         reason the function is IMMUTABLE",
    );
}

/// NULL in, NULL out — `RETURNS NULL ON NULL INPUT`. A record with no title
/// reaches this function like any other, and a NULL that turned into `''`
/// would make an untitled record match an empty-string query.
#[tokio::test]
async fn null_input_stays_null() {
    let db = skip_if_no_db!(test_db().await);

    let result: Option<String> = sqlx::query_scalar("SELECT normalize_ar(NULL::text)")
        .fetch_one(&db)
        .await
        .expect("query");
    assert!(result.is_none(), "NULL must not become an empty string");
}
