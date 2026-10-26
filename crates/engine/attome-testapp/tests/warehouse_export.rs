//! P13-T1: record changes of an exported entity reach a Parquet file and the
//! manifest, a deletion as a tombstone, and a repeated run writes nothing new.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_integration::warehouse_export;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn set_entities(app: &TestApp, entities: Value) {
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/api/v1/admin/settings/{}", warehouse_export::SETTING),
            Some(json!({ "scope": "deployment", "value": entities })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
}

/// The export consumer's cursor, `None` before its first run.
async fn cursor(app: &TestApp) -> Option<(String, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT last_commit_xid::text, last_id FROM change_consumer_cursor WHERE consumer = $1",
    )
    .bind(warehouse_export::CONSUMER)
    .fetch_optional(app.db())
    .await
    .unwrap()
}

/// Runs the export until its cursor stops moving: the change feed is
/// drained (other tests' events come first on a shared database).
async fn drain(app: &TestApp) {
    for _ in 0..500 {
        let before = cursor(app).await;
        warehouse_export::run(&app.state).await.unwrap();
        if cursor(app).await == before {
            return;
        }
    }
    panic!("the change feed did not drain");
}

async fn manifest(app: &TestApp, entity: &str) -> Vec<(i32, i32)> {
    sqlx::query_as(
        "SELECT rows, tombstones FROM warehouse_export_file WHERE entity_logicalname = $1 \
          ORDER BY created_at",
    )
    .bind(entity)
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: P13
#[test]
fn changes_reach_parquet_files_and_the_manifest() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("wx_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
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

        set_entities(&app, json!([name])).await;
        drain(&app).await;
        assert!(
            manifest(&app, &name).await.is_empty(),
            "nothing changed yet"
        );

        let mut ids = Vec::new();
        for title in ["kept", "removed"] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{name}"),
                    Some(json!({ "title": title })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            ids.push(body["id"].as_str().unwrap().to_owned());
        }
        let (status, body) = app
            .request(Method::DELETE, &format!("/api/v1/{name}/{}", ids[1]), None)
            .await;
        assert!(status.is_success(), "{status} {body}");

        drain(&app).await;
        let files = manifest(&app, &name).await;
        assert!(!files.is_empty(), "the changes were exported");
        let rows: i32 = files.iter().map(|(r, _)| r).sum();
        let tombstones: i32 = files.iter().map(|(_, t)| t).sum();
        assert!(rows >= 2, "{files:?}");
        assert!(tombstones >= 1, "the deletion is a tombstone: {files:?}");

        // A repeated run finds nothing new.
        let before = files.len();
        drain(&app).await;
        assert_eq!(manifest(&app, &name).await.len(), before);

        set_entities(&app, json!([])).await;
    });
}
