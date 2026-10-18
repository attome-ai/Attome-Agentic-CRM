//! AA9-T6: the limits endpoints.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};

#[test]
fn limits_admin_forbidden_for_non_admin() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let user = seed_user(app.db(), "limits").await;
        let (status, _) = app
            .request_as(&user.cookie, Method::GET, "/api/v1/admin/limits", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
}

#[test]
fn limits_admin_lists_registry() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, page) = app.request(Method::GET, "/api/v1/admin/limits", None).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), attome_config::limits::LIMITS.len());
        let bulk = items
            .iter()
            .find(|i| i["key"] == "bulk.max_records_per_request")
            .expect("the bulk cap is listed");
        assert_eq!(bulk["scope"], "runtime_setting");
        assert_eq!(bulk["floor"], 1);
        assert!(bulk["value"].as_i64().unwrap() >= 1, "{bulk}");
    })
}

#[test]
fn limits_me_lists_bulk_cap() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let user = seed_user(app.db(), "limits-me").await;
        let (status, body) = app
            .request_as(&user.cookie, Method::GET, "/api/v1/limits/me", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let limits = body["limits"].as_array().unwrap();
        let bulk = limits
            .iter()
            .find(|l| l["key"] == "bulk.max_records_per_request")
            .expect("the bulk cap applies to every caller");
        assert!(bulk["value"].as_i64().unwrap() >= 1, "{bulk}");
        let api = limits
            .iter()
            .find(|l| l["key"] == "rate_limit.api")
            .expect("the api rate class is listed");
        assert!(api["remaining"].as_i64().is_some(), "{api}");
    })
}
