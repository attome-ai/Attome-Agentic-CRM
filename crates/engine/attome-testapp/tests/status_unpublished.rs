//! AB11-T6 and AB11-T8: while the deployment does not publish its status
//! (`ops.status.enabled`, off by default), every public status route
//! answers 404 and shows nothing. A binary of its own: no test here turns
//! the setting on.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;

// feature: AB11
// negative: GET /api/v1/public/status
#[test]
fn public_status_404_when_disabled() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        sqlx::query(
            "INSERT INTO ops_incident (title_en, audience, state, components, impact, created_by) \
             VALUES ('Visible only when published', 'public', 'investigating', ARRAY['records'], \
                     'major', $1)",
        )
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        let (status, body) = app
            .request_public(Method::GET, "/api/v1/public/status", &[], Vec::new())
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "off by default: {body}");
        assert!(!body.to_string().contains("Visible only"));
    });
}

// feature: AB11
// negative: POST /api/v1/public/status/subscribe
#[test]
fn public_routes_404_when_disabled() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let body = json!({ "channel": "email", "address": "a@example.com", "consent": true });
        let (status, _) = app
            .request_public(
                Method::POST,
                "/api/v1/public/status/subscribe",
                &[("content-type", "application/json")],
                serde_json::to_vec(&body).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        for path in [
            "/api/v1/public/status/confirm?token=x",
            "/api/v1/public/status/unsubscribe?token=x",
            "/api/v1/public/status/feed.rss",
        ] {
            let (status, _) = app.request_public(Method::GET, path, &[], Vec::new()).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    });
}
