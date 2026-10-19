//! Z1-T15: the configuration admin routes (Z1-T7 starts and their
//! comparison, Z1-T8 the secret inventory) through the whole router:
//! starts are listed and compared by key, the inventory carries no secret
//! value, and a user who is not an administrator is refused all three.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;

// feature: Z1
#[test]
fn starts_are_listed_and_diffed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let node = format!("z1-t15-{}", uuid::Uuid::now_v7());
        let before = json!({ "app": { "port": 7865, "log_level": "info" } });
        let after = json!({ "app": { "port": 7866, "log_level": "info" } });
        let a =
            attome_compliance::config_starts::record_start(app.db(), &node, "v1", "fp-a", &before)
                .await
                .unwrap();
        let b =
            attome_compliance::config_starts::record_start(app.db(), &node, "v1", "fp-b", &after)
                .await
                .unwrap();

        let (status, listed) = app
            .request(
                Method::GET,
                "/api/v1/admin/config/starts?page_size=200",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let ids: Vec<&str> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["id"].as_str())
            .collect();
        assert!(ids.contains(&a.to_string().as_str()) && ids.contains(&b.to_string().as_str()));

        let (status, diff) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/config/starts/diff?a={a}&b={b}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{diff}");
        assert_eq!(diff["total"], 1, "{diff}");
        assert_eq!(diff["items"][0]["path"], "app.port");
        assert_eq!(diff["items"][0]["before"], 7865);
        assert_eq!(diff["items"][0]["after"], 7866);
    });
}

// feature: Z1
#[test]
fn secret_inventory_has_no_values() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, body) = app
            .request(Method::GET, "/api/v1/admin/secrets?page_size=200", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["total"].as_i64().unwrap_or(0) > 0,
            "the test configuration holds secrets: {body}"
        );
        let text = body.to_string();
        // The test configuration's own secret values (attome_testapp::test_config).
        for secret in [
            "test-only-throwaway-secret-do-not-use-in-prod",
            &"5e".repeat(32),
            &"6a".repeat(32),
        ] {
            assert!(!text.contains(secret), "a secret value is in the inventory");
        }
    });
}

// feature: Z1
#[test]
fn config_routes_forbid_non_admin() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let user = attome_testapp::seed_user(app.db(), "z1-t15").await;
        let any = uuid::Uuid::now_v7();
        for path in [
            "/api/v1/admin/config/starts".to_owned(),
            format!("/api/v1/admin/config/starts/diff?a={any}&b={any}"),
            "/api/v1/admin/secrets".to_owned(),
        ] {
            let (status, body) = app.request_as(&user.cookie, Method::GET, &path, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        }
    });
}
