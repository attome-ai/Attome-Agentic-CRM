//! Y12-T9: a retired column keeps its values under its new name, survives
//! while any node is on an older metadata version, and goes once the period
//! has passed and every node has switched.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_metadata::provision::contract::{contract_due, retire_column_in_tx};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// An entity with a text field `label`; its logical name.
async fn entity(app: &TestApp) -> String {
    let logicalname = format!("contract_{}", Uuid::now_v7().simple());
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": logicalname, "name": "Contraction test" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    let (code, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({ "logicalname": "label", "name": "Label", "field_type": "text" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    logicalname
}

async fn columns(app: &TestApp, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = $1",
    )
    .bind(table)
    .fetch_all(app.db())
    .await
    .unwrap()
}

async fn node(app: &TestApp, name: &str, version: i64) {
    sqlx::query("INSERT INTO metadata_node_switch (node_id, version) VALUES ($1, $2)")
        .bind(name)
        .bind(version)
        .execute(app.db())
        .await
        .unwrap();
}

// feature: Y12
#[test]
fn contract_waits_for_lagging_node() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // Only the nodes this test names: the app's own switch at boot
        // would otherwise lag behind the version the test records.
        sqlx::query("DELETE FROM metadata_node_switch")
            .execute(app.db())
            .await
            .unwrap();
        let table = entity(&app).await;
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{table}"),
                Some(json!({ "label": "kept" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{body}");

        let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
        retire_column_in_tx(&mut tx, &table, "label").await.unwrap();
        attome_db::tx::commit(tx).await.unwrap();
        let retired: String = sqlx::query_scalar(
            "SELECT retired_name FROM schema_retired_column WHERE table_name = $1",
        )
        .bind(&table)
        .fetch_one(app.db())
        .await
        .unwrap();
        let now = columns(&app, &table).await;
        assert!(!now.contains(&"label".to_owned()), "{now:?}");
        assert!(
            now.contains(&retired),
            "the values stay under the retired name"
        );
        let value: Option<String> = sqlx::query_scalar(&format!(
            "SELECT \"{retired}\"::text FROM \"{table}\" LIMIT 1"
        ))
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(value.as_deref(), Some("kept"));
        // Past the period, recorded under version 5, and one node on 4.
        sqlx::query(
            "UPDATE schema_retired_column SET metadata_version = 5, \
                    retired_at = now() - interval '8 days' WHERE table_name = $1",
        )
        .bind(&table)
        .execute(app.db())
        .await
        .unwrap();
        node(&app, "node-a", 5).await;
        node(&app, "node-b", 4).await;
        contract_due(app.db(), 168).await.unwrap();
        assert!(
            columns(&app, &table).await.contains(&retired),
            "an old column survives while a node is on an older version"
        );

        // Too soon is too soon, whatever the nodes say.
        node(&app, "node-b", 5).await;
        sqlx::query(
            "UPDATE schema_retired_column SET retired_at = now() - interval '1 hour' \
              WHERE table_name = $1",
        )
        .bind(&table)
        .execute(app.db())
        .await
        .unwrap();
        contract_due(app.db(), 168).await.unwrap();
        assert!(columns(&app, &table).await.contains(&retired));

        sqlx::query(
            "UPDATE schema_retired_column SET retired_at = now() - interval '8 days' \
              WHERE table_name = $1",
        )
        .bind(&table)
        .execute(app.db())
        .await
        .unwrap();
        contract_due(app.db(), 168).await.unwrap();
        assert!(!columns(&app, &table).await.contains(&retired), "dropped");
        let dropped: bool = sqlx::query_scalar(
            "SELECT dropped_at IS NOT NULL FROM schema_retired_column WHERE table_name = $1",
        )
        .bind(&table)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(dropped);
    });
}
