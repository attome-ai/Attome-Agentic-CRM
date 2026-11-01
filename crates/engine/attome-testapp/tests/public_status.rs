//! AB11-T8: `GET /api/v1/public/status` answers anyone, without signing in,
//! with the public status only. The 404 while the deployment does not
//! publish it is in `status_unpublished.rs`: tests in one binary share one
//! app and its settings, and run at the same time.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;

async fn publish_status(app: &TestApp, on: bool) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/ops.status.enabled",
            Some(json!({ "scope": "deployment", "value": on })),
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");
}

async fn incident(app: &TestApp, title: &str, audience: &str) {
    sqlx::query(
        "INSERT INTO ops_incident (title_en, audience, state, components, impact, created_by) \
         VALUES ($1, $2, 'investigating', ARRAY['records'], 'major', $3)",
    )
    .bind(title)
    .bind(audience)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: AB11
#[test]
fn public_status_hides_internal() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        incident(&app, "Payments are slow", "public").await;
        incident(&app, "Primary database failover drill", "internal").await;
        sqlx::query("UPDATE ops_status_component SET public = false WHERE key = 'ai'")
            .execute(app.db())
            .await
            .unwrap();
        publish_status(&app, true).await;

        let (status, body) = app
            .request_public(Method::GET, "/api/v1/public/status", &[], Vec::new())
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let text = body.to_string();
        assert!(text.contains("Payments are slow"), "{text}");
        assert!(
            !text.contains("failover"),
            "an internal incident leaked: {text}"
        );
        let keys: Vec<&str> = body["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["key"].as_str())
            .collect();
        assert!(keys.contains(&"records"), "{keys:?}");
        assert!(
            !keys.contains(&"ai"),
            "a non-public component leaked: {keys:?}"
        );
    });
}
