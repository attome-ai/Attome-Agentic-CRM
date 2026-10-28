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

/// Y11-T5: a field's stack lists each layer's value and names the winner.
#[tokio::test]
async fn layer_stack_shows_winner() {
    let pool = migrated_pool_or_skip!(2);
    let key = format!("layer_test_{}.phone", uuid::Uuid::now_v7().simple());
    for (property, layer, value) in [
        ("name", "platform", serde_json::json!("Phone")),
        ("name", "customer", serde_json::json!("Mobile")),
        ("max_length", "platform", serde_json::json!(32)),
    ] {
        sqlx::query(
            "INSERT INTO metadata_property_layer (object_kind, object_key, property, layer, value) \
             VALUES ('attribute', $1, $2, $3, $4)",
        )
        .bind(&key)
        .bind(property)
        .bind(layer)
        .bind(value)
        .execute(&pool)
        .await
        .expect("insert a layer row");
    }
    let stacks = attome_model::layer_stack::stack(&pool, "attribute", &key)
        .await
        .expect("read the stack");
    let name = stacks.iter().find(|s| s.property == "name").expect("name");
    assert_eq!(name.winner, attome_model::Layer::Customer);
    assert_eq!(name.values.len(), 2);
    assert_eq!(name.values[0].layer, attome_model::Layer::Platform);
    let max_length = stacks
        .iter()
        .find(|s| s.property == "max_length")
        .expect("max_length");
    assert_eq!(max_length.winner, attome_model::Layer::Platform);
    sqlx::query("DELETE FROM metadata_property_layer WHERE object_key = $1")
        .bind(&key)
        .execute(&pool)
        .await
        .expect("clean up");
}
