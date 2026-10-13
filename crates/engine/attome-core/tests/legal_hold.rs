//! P-data-protection-governance §4 — proves `legal_hold::record_is_held`
//! against a real `legal_hold` table (migration
//! `0088_data_protection_governance.sql`): a per-record hold is found for
//! its exact record but not for a different record in the same entity, a
//! whole-entity hold (`record_id IS NULL`) is found for every record in
//! that entity, and a released hold (`released_at` set) is no longer found.
//!
//! **NOT executed as part of this change** — this sandbox has no Postgres
//! and no Rust toolchain. Written to the same convention as
//! `tests/partition_maintenance.rs` so a developer with a real database can
//! run it directly:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-core --test legal_hold
//! ```
//!
//! Requires migration 0088 already applied.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::legal_hold::record_is_held;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
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

async fn insert_hold(
    db: &DbPool,
    entity_logicalname: &str,
    record_id: Option<Uuid>,
    matter_reference: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(matter_reference)
    .bind(Uuid::now_v7())
    .fetch_one(db)
    .await
    .expect("insert legal hold")
}

#[tokio::test]
async fn per_record_hold_matches_only_its_own_record() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_legal_hold_{}", Uuid::now_v7().simple());
    let held_record = Uuid::now_v7();
    let other_record = Uuid::now_v7();

    insert_hold(&db, &entity, Some(held_record), "matter-A").await;

    let held = record_is_held(&db, &entity, held_record)
        .await
        .expect("query");
    assert!(held.is_some(), "the exact held record must be found");
    assert_eq!(held.unwrap().matter_reference, "matter-A");

    let not_held = record_is_held(&db, &entity, other_record)
        .await
        .expect("query");
    assert!(
        not_held.is_none(),
        "a different record in the same entity must not be reported as held"
    );
}

#[tokio::test]
async fn whole_entity_hold_matches_every_record_in_that_entity() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_legal_hold_{}", Uuid::now_v7().simple());
    let record_a = Uuid::now_v7();
    let record_b = Uuid::now_v7();

    insert_hold(&db, &entity, None, "matter-whole-entity").await;

    for record_id in [record_a, record_b] {
        let held = record_is_held(&db, &entity, record_id)
            .await
            .expect("query");
        assert!(
            held.is_some(),
            "a whole-entity hold (record_id IS NULL) must match every record in that entity"
        );
        assert_eq!(held.unwrap().record_id, None);
    }
}

#[tokio::test]
async fn a_released_hold_is_no_longer_reported() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_legal_hold_{}", Uuid::now_v7().simple());
    let record_id = Uuid::now_v7();

    let hold_id = insert_hold(&db, &entity, Some(record_id), "matter-released").await;

    assert!(
        record_is_held(&db, &entity, record_id)
            .await
            .expect("query")
            .is_some(),
        "sanity check: the hold is active before release"
    );

    sqlx::query("UPDATE legal_hold SET released_at = NOW() WHERE id = $1")
        .bind(hold_id)
        .execute(&db)
        .await
        .expect("release hold");

    let held = record_is_held(&db, &entity, record_id)
        .await
        .expect("query");
    assert!(
        held.is_none(),
        "a released hold (released_at set) must no longer block anything"
    );
}
