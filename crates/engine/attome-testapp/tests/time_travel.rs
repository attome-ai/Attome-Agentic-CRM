//! A1-T10: an entity with time travel on keeps the version each update
//! replaces, reads a record as it stood at a moment, and puts an earlier
//! version back through the ordinary update.

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

/// A fresh entity with a `title`, time travel on, and one record titled
/// `first`; the entity's name, the record's id and its first `created_at`.
async fn entity_with_record(app: &TestApp) -> (String, Uuid, String) {
    let name = format!("tt_{}", &Uuid::now_v7().simple().to_string()[..12]);
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

    let (status, settings) = app
        .request_with(
            Method::PUT,
            &format!("/api/v1/admin/time-travel/{name}"),
            &[("if-match", "\"0\"")],
            Some(json!({ "enabled": true, "retention_days": 365 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["enabled"], json!(true));

    let (status, record) = app
        .request(
            Method::POST,
            &format!("/api/v1/{name}"),
            Some(json!({ "title": "first" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    let record_id: Uuid = record["id"].as_str().unwrap().parse().unwrap();
    let created_at = record["created_at"].as_str().unwrap().to_owned();
    (name, record_id, created_at)
}

async fn patch_title(app: &TestApp, name: &str, id: Uuid, title: &str) -> Value {
    let (status, current) = app
        .request(Method::GET, &format!("/api/v1/{name}/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    let version = format!("\"{}\"", current["row_version"]);
    let (status, body) = app
        .request_with(
            Method::PATCH,
            &format!("/api/v1/{name}/{id}"),
            &[("if-match", version.as_str())],
            Some(json!({ "title": title })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// A moment in a query string (`+` would read as a space).
fn query_moment(moment: &str) -> String {
    moment.replace('+', "%2B")
}

// feature: A1
#[test]
fn as_of_returns_old_value() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (name, id, created_at) = entity_with_record(&app).await;
        patch_title(&app, &name, id, "second").await;

        let (status, then) = app
            .request(
                Method::GET,
                &format!("/api/v1/{name}/{id}?as_of={}", query_moment(&created_at)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{then}");
        assert_eq!(then["data"]["title"], json!("first"), "{then}");

        let (status, now) = app
            .request(Method::GET, &format!("/api/v1/{name}/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{now}");
        assert_eq!(now["data"]["title"], json!("second"));

        // Before the record existed, no version is kept.
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/{name}/{id}?as_of=2000-01-01T00:00:00Z"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let kept: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM \"{name}__history\" WHERE id = $1"
        ))
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(kept, 1);
    });
}

// feature: A1
#[test]
fn restore_version_writes_through_mutation() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (name, id, created_at) = entity_with_record(&app).await;
        let after = patch_title(&app, &name, id, "second").await;
        let version = format!("\"{}\"", after["row_version"]);

        let (status, restored) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/{name}/{id}/restore-version"),
                &[("if-match", version.as_str())],
                Some(json!({ "as_of": created_at })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{restored}");
        assert_eq!(restored["data"]["title"], json!("first"));
        // An ordinary update: the version moved on and the change is kept.
        assert!(restored["row_version"].as_i64() > after["row_version"].as_i64());
        let kept: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM \"{name}__history\" WHERE id = $1"
        ))
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(kept, 2);

        // The stale version is refused, and restoring the current one is a 422.
        let (status, _) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/{name}/{id}/restore-version"),
                &[("if-match", version.as_str())],
                Some(json!({ "as_of": created_at })),
            )
            .await;
        assert!(
            status == StatusCode::CONFLICT || status == StatusCode::UNPROCESSABLE_ENTITY,
            "{status}"
        );
        let current = format!("\"{}\"", restored["row_version"]);
        let (status, _) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/{name}/{id}/restore-version"),
                &[("if-match", current.as_str())],
                Some(json!({ "as_of": "2999-01-01T00:00:00Z" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}
