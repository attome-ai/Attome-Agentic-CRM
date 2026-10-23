//! L1-T2: a master entity's contribution and provenance side tables are
//! created once, with their columns, however often the entity is made
//! master.
//!
//! Requires a live Postgres with migrations applied; skips (loudly) when
//! `DATABASE_URL` is unset, except under `CI` (see `attome_testkit`).
//!
//! ```powershell
//! cargo test -p attome-metadata --test master_tables -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;

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

async fn columns(db: &DbPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_name = $1 AND table_schema = current_schema() ORDER BY column_name",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .unwrap()
}

#[tokio::test]
async fn ensure_master_tables_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("mst_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE TABLE \"{entity}\" (id uuid PRIMARY KEY DEFAULT uuidv7())"
    ))
    .execute(&db)
    .await
    .unwrap();

    for _ in 0..2 {
        attome_metadata::provision::master::ensure_master_tables(&db, &entity)
            .await
            .expect("ensure the master tables");
    }

    let contribution = format!("{entity}__contribution");
    let provenance = format!("{entity}__provenance");
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
          WHERE table_schema = current_schema() AND table_name = ANY($1)",
    )
    .bind(vec![contribution.clone(), provenance.clone()])
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(tables, 2, "each side table exists once");
    assert_eq!(
        columns(&db, &contribution).await,
        vec![
            "external_id",
            "golden_id",
            "held_reason",
            "id",
            "payload",
            "received_at",
            "source_system",
            "status"
        ]
    );
    assert_eq!(
        columns(&db, &provenance).await,
        vec![
            "attribute",
            "chosen_at",
            "contribution_id",
            "golden_id",
            "pinned_by",
            "rule"
        ]
    );
    // One contribution per source system and external id.
    let insert = format!(
        "INSERT INTO \"{contribution}\" (source_system, external_id) VALUES ('erp', 'A-1')"
    );
    sqlx::query(&insert).execute(&db).await.unwrap();
    assert!(sqlx::query(&insert).execute(&db).await.is_err());
}
