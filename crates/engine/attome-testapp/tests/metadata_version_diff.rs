//! U7-T1: two recorded metadata versions compare by artefact, either way
//! round. Its own binary, so no other test moves the version pointer between
//! a publish and the read of the version it made.

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

/// Publishes a new environment variable; returns its cooked-artefact key.
async fn publish_variable(app: &TestApp) -> String {
    let id = Uuid::now_v7();
    let name = format!("y8_{}", &id.simple().to_string()[..16]);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/model/environment_variable/{id}/commands"),
            Some(json!({
                "base_hash": "",
                "name": name,
                "commands": [{ "op": "set", "path": "/type", "value": "url" }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/model/environment_variable/{id}/publish"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    format!("environment_variable:{id}")
}

async fn current_version(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT version FROM metadata_current")
        .fetch_one(app.db())
        .await
        .expect("a publish records the current metadata version")
}

// feature: U7
#[test]
fn diff_between_two_versions() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let first = publish_variable(&app).await;
        let older = current_version(&app).await;
        let second = publish_variable(&app).await;
        let newer = current_version(&app).await;

        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/metadata/versions/{newer}/diff?against={older}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            (body["from"].clone(), body["to"].clone()),
            (json!(older), json!(newer))
        );
        let has = |list: &str, key: &str| {
            body[list]
                .as_array()
                .is_some_and(|items| items.iter().any(|i| i == key))
        };
        assert!(has("added", &second), "{body}");
        assert!(!has("added", &first), "{body}");

        let (status, back) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/metadata/versions/{older}/diff?against={newer}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{back}");
        assert!(
            back["removed"]
                .as_array()
                .is_some_and(|items| items.iter().any(|i| i == &json!(second))),
            "{back}"
        );

        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/metadata/versions/999999999/diff?against={older}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}
