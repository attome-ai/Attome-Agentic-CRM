//! T5-T2: Develop workspaces through the API. A workspace is its own schema
//! with the live metadata (with its rows) and every entity table (empty);
//! identity tables stay shared; discarding drops the schema.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn create_entity(app: &TestApp, name: &str) {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

async fn create_workspace(app: &TestApp, name: &str) -> (Value, String) {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/workspaces",
            Some(json!({ "name": name, "purpose": "a test" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    (body, format!("ws_{}", id.simple()))
}

async fn table_exists(app: &TestApp, schema: &str, table: &str) -> bool {
    let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(format!("\"{schema}\".\"{table}\""))
        .fetch_one(app.db())
        .await
        .unwrap();
    found.is_some()
}

async fn count(app: &TestApp, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(app.db()).await.unwrap()
}

// feature: T5
#[test]
fn a_workspace_copies_the_structure_and_not_the_records() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("ws_probe_{}", &Uuid::now_v7().simple().to_string()[..12]);
        create_entity(&app, &entity).await;
        let (status, record) = app
            .request(Method::POST, &format!("/api/v1/{entity}"), Some(json!({})))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");

        let (workspace, schema) = create_workspace(&app, "Probe").await;
        assert_eq!(workspace["status"], "open", "{workspace}");
        assert!(workspace["metadata_tables"].as_i64().unwrap() > 0);
        assert!(workspace["entity_tables"].as_i64().unwrap() > 0);

        // The entity's table is there, empty; live keeps its record.
        assert!(table_exists(&app, &schema, &entity).await);
        assert_eq!(
            count(
                &app,
                &format!("SELECT COUNT(*) FROM \"{schema}\".\"{entity}\"")
            )
            .await,
            0
        );
        assert_eq!(
            count(&app, &format!("SELECT COUNT(*) FROM \"{entity}\"")).await,
            1
        );
        // The metadata came with its rows.
        assert_eq!(
            count(
                &app,
                &format!(
                    "SELECT COUNT(*) FROM \"{schema}\".entity_info WHERE logicalname = '{entity}'"
                )
            )
            .await,
            1
        );
        // Identity stays shared.
        assert!(!table_exists(&app, &schema, "user_account").await);

        let id = workspace["id"].as_str().unwrap();
        let (status, shown) = app
            .request(Method::GET, &format!("/api/v1/admin/workspaces/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{shown}");
        assert_eq!(shown["name"], "Probe");
        let (status, listed) = app
            .request(Method::GET, "/api/v1/admin/workspaces?page_size=200", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(
            listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["id"] == workspace["id"]),
            "{listed}"
        );

        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/workspaces/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    });
}

// feature: T5
#[test]
fn discard_drops_the_schema() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (workspace, schema) = create_workspace(&app, "Throwaway").await;
        assert!(table_exists(&app, &schema, "entity_info").await);
        let id = workspace["id"].as_str().unwrap();

        let (status, body) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/workspaces/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert!(!table_exists(&app, &schema, "entity_info").await);
        let gone: Option<String> =
            sqlx::query_scalar("SELECT nspname::text FROM pg_namespace WHERE nspname = $1")
                .bind(&schema)
                .fetch_optional(app.db())
                .await
                .unwrap();
        assert_eq!(gone, None, "the schema is dropped");

        let (status, _) = app
            .request(Method::GET, &format!("/api/v1/admin/workspaces/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/workspaces/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// feature: T5
#[test]
fn a_blank_name_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/workspaces",
                Some(json!({ "name": "  " })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}
