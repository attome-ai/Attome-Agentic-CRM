//! Y11-T2: the property-layer tables exist on a migrated database.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::migrated_pool_or_skip;

#[tokio::test]
async fn property_layer_tables_exist() {
    let pool = migrated_pool_or_skip!(2);
    for table in ["metadata_property_layer", "app_layer", "metadata_lock"] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("look up the table");
        assert!(exists, "{table} exists");
    }
}
