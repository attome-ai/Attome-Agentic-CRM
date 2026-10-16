//! L5-T1: the lineage graph's columns and tables exist on a migrated database.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::migrated_pool_or_skip;

#[tokio::test]
async fn lineage_columns_and_tables_exist() {
    let pool = migrated_pool_or_skip!(2);
    for column in [
        "edge_kind",
        "confidence",
        "graph_version",
        "documented_by",
        "note",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'metadata_reference' \
               AND column_name = $1)",
        )
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("look up the column");
        assert!(exists, "metadata_reference.{column} exists");
    }
    for table in ["lineage_version", "lineage_system"] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("look up the table");
        assert!(exists, "{table} exists");
    }
}
