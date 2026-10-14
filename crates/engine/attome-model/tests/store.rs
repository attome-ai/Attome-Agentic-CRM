//! The metadata object store's schema (roadmap Y1-T2), on a migrated
//! throwaway database.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn migration_creates_metadata_store_tables() {
    let Some(url) = attome_testkit::migrated_db_url() else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to the migrated test database");
    for table in [
        "metadata_object",
        "metadata_object_version",
        "metadata_artefact",
    ] {
        let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
        assert_eq!(found.as_deref(), Some(table), "{table} exists");
    }
    // One open draft per object: a second draft row is refused.
    let object = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_object (id, kind, name, owner_layer) VALUES ($1, 'form', $2, 'customer')",
    )
    .bind(object)
    .bind(format!("f-{object}"))
    .execute(&pool)
    .await
    .expect("insert object");
    let draft = |version: i64| {
        sqlx::query(
            "INSERT INTO metadata_object_version \
             (object_id, version_no, kind_schema_version, doc, content_hash, state) \
             VALUES ($1, $2, 1, '{}'::jsonb, 'h', 'draft')",
        )
        .bind(object)
        .bind(version)
        .execute(&pool)
    };
    draft(1).await.expect("the first draft");
    assert!(draft(2).await.is_err(), "a second open draft is refused");
}
