//! A1-T6: a high-volume entity's table is partitioned by month on
//! `created_at`, refuses a unique business key, and is read through a date
//! window: its default view shows the last 30 days, and a query naming no
//! window is refused.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// A fresh high-volume entity with a `title`; its name and id.
async fn high_volume_entity(app: &TestApp) -> (String, String) {
    let name = format!("hv_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name, "storage_mode": "high_volume" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    (name, id)
}

// feature: A1
#[test]
fn high_volume_entity_partitioned_by_month() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (name, id) = high_volume_entity(&app).await;
        let kind: String = sqlx::query_scalar(
            "SELECT relkind::text FROM pg_class \
              WHERE relname = $1 AND relnamespace = current_schema()::regnamespace",
        )
        .bind(&name)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(kind, "p", "the table is partitioned");
        let partitions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent \
              WHERE p.relname = $1",
        )
        .bind(&name)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(partitions >= 12, "{partitions} partitions");

        // Records are written and read as on any entity.
        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({ "title": "page viewed" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let record_id = record["id"].as_str().unwrap().to_owned();
        let (status, read) = app
            .request(Method::GET, &format!("/api/v1/{name}/{record_id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(read["data"]["title"], json!("page viewed"));

        // A unique business key is refused.
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{id}"),
                Some(json!({ "business_key": ["title"] })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.to_string().contains("unique_needs_partition_key"),
            "{body}"
        );

        // The storage of an existing entity does not change in place.
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name, "storage_mode": "high_volume" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: A1
#[test]
fn high_volume_query_requires_window() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (name, id) = high_volume_entity(&app).await;
        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({ "title": "signed in" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let record_id = record["id"].as_str().unwrap().to_owned();

        // The entity's view shows the last 30 days without being asked.
        let (status, page) = app
            .request(
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "entity": name })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.to_string().contains(&record_id), "{page}");

        // A stored query run directly, naming no window, is refused.
        let entity_id: Uuid = id.parse().unwrap();
        let query_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM sql_query WHERE entity_logical_name = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(entity_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "query_id": query_id })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.to_string().contains("date_window_required"), "{body}");

        // With a window it runs.
        let (status, page) = app
            .request(
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({
                    "query_id": query_id,
                    "filters": [{ "field": "created_at", "op": "gte", "value": "2000-01-01T00:00:00Z" }],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.to_string().contains(&record_id), "{page}");
    });
}
