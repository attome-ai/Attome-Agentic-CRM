//! Z15-T13: the customer test admin routes — create, run, export, import and
//! delete round trip; an ordinary user is refused; a stale `If-Match` is a
//! 409.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

const BASE: &str = "/api/v1/admin/customer-tests";

// feature: Z15
#[test]
fn create_run_delete_round_trip() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("ct-admin-{}", Uuid::now_v7().simple());
        let (status, created) = app
            .request(
                Method::POST,
                BASE,
                Some(json!({ "name": name, "definition": { "expect": [] }, "blocking": true })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_owned();
        assert_eq!(created["row_version"], 1);

        let (status, run) = app
            .request(Method::POST, &format!("{BASE}/{id}/run"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        assert_eq!(run["passed"], true, "{run}");
        let (_, shown) = app
            .request(Method::GET, &format!("{BASE}/{id}"), None)
            .await;
        assert_eq!(shown["last_passed"], true, "{shown}");
        let (_, runs) = app
            .request(Method::GET, &format!("{BASE}/{id}/runs"), None)
            .await;
        assert_eq!(runs["total"], 1, "{runs}");

        let (status, all) = app
            .request(Method::POST, &format!("{BASE}/run-all"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{all}");
        assert!(
            all["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["test_id"] == id.as_str()),
            "{all}"
        );

        let (status, exported) = app
            .request(Method::GET, &format!("{BASE}/export"), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(exported["format"], "attome-customer-tests/v1");
        let mine: Vec<_> = exported["tests"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["name"] == name.as_str())
            .cloned()
            .collect();
        assert_eq!(mine.len(), 1, "{exported}");

        // Importing it back replaces the test of that name; a new name is created.
        let other = format!("{name}-copy");
        let mut copy = mine[0].clone();
        copy["name"] = json!(other);
        let (status, imported) = app
            .request(
                Method::POST,
                &format!("{BASE}/import"),
                Some(json!({ "format": "attome-customer-tests/v1", "tests": [mine[0], copy] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{imported}");
        assert_eq!(imported, json!({ "created": 1, "updated": 1 }));

        // A bad entry writes nothing.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("{BASE}/import"),
                Some(json!({ "format": "attome-customer-tests/v1", "tests": [
                    { "name": format!("{name}-never"), "definition": {} },
                    { "name": "", "definition": {} }
                ] })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let never: i64 = sqlx::query_scalar("SELECT count(*) FROM customer_test WHERE name = $1")
            .bind(format!("{name}-never"))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(never, 0);

        let (status, _) = app
            .request(Method::DELETE, &format!("{BASE}/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app
            .request(Method::GET, &format!("{BASE}/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let runs_left: i64 =
            sqlx::query_scalar("SELECT count(*) FROM customer_test_run WHERE test_id = $1")
                .bind(Uuid::parse_str(&id).unwrap())
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(runs_left, 0, "a test's runs go with it");
    });
}

// feature: Z15
// negative: create_customer_test
#[test]
fn non_admin_is_forbidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let user = seed_user(app.db(), "ct-plain").await;
        let (status, _) = app
            .request_as(
                &user.cookie,
                Method::POST,
                BASE,
                Some(json!({ "name": "not mine", "definition": {} })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = app
            .request_as(&user.cookie, Method::POST, &format!("{BASE}/run-all"), None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = app
            .request_as(&user.cookie, Method::GET, &format!("{BASE}/export"), None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

// feature: Z15
// negative: update_customer_test
#[test]
fn stale_row_version_is_409() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, created) = app
            .request(
                Method::POST,
                BASE,
                Some(json!({ "name": format!("ct-stale-{}", Uuid::now_v7().simple()), "definition": {} })),
            )
            .await;
        let path = format!("{BASE}/{}", created["id"].as_str().unwrap());

        let (status, _) = app
            .request(
                Method::PATCH,
                &path,
                Some(json!({ "description": "no If-Match" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, changed) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", "\"1\"")],
                Some(json!({ "description": "first" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["row_version"], 2);

        let (status, body) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", "\"1\"")],
                Some(json!({ "description": "stale" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let (status, _) = app
            .request_with(Method::DELETE, &path, &[("if-match", "\"1\"")], None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // A definition that does not read is refused.
        let (status, _) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", "\"2\"")],
                Some(json!({ "definition": { "when": [{ "op": "explode" }] } })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

async fn set_guard(app: &TestApp, on: bool) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/customer_tests.require_pass_before_publish",
            Some(json!({ "scope": "deployment", "value": on })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
}

// feature: Z15
// negative: publish_model_object
#[test]
fn publish_blocked_when_blocking_test_fails() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("ct-guard-{}", Uuid::now_v7().simple());
        // Expects an error no step can meet: always fails.
        let (status, created) = app
            .request(
                Method::POST,
                BASE,
                Some(json!({ "name": name, "blocking": true,
                             "definition": { "expect": [{ "error": "conflict" }] } })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        // No draft under this id: past the guard, the publish answers 404.
        let publish = format!(
            "/api/v1/admin/model/environment_variable/{}/publish",
            Uuid::now_v7()
        );

        let (status, _) = app.request(Method::POST, &publish, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "guard off: nothing changes");

        set_guard(&app, true).await;
        let (status, body) = app.request(Method::POST, &publish, None).await;
        set_guard(&app, false).await;
        // Retire the failing test before asserting, so a failure here leaves
        // no blocking test behind for other tests.
        let path = format!("{BASE}/{}", created["id"].as_str().unwrap());
        let (status_off, _) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", "\"1\"")],
                Some(json!({ "is_active": false })),
            )
            .await;
        assert_eq!(status_off, StatusCode::OK);
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "customer_tests_failed", "{body}");
        assert!(
            body["tests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == name.as_str()),
            "{body}"
        );
    });
}
