//! T7-T4: an acceptance script is a customer test with a checklist; any
//! signed-in user lists it and records a run step by step, and no automatic
//! run picks it up.

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

// feature: T7
#[test]
fn a_person_records_a_run_of_an_acceptance_script() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("acceptance-{}", Uuid::now_v7().simple());
        let (code, script) = app
            .request(
                Method::POST,
                "/api/v1/admin/customer-tests",
                Some(json!({
                    "name": name,
                    "definition": { "checklist": ["Open a lead", "Convert it to an account"] }
                })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{script}");
        let id = script["id"].as_str().unwrap().to_owned();

        // A checklist with anything beside it is refused.
        let (code, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/customer-tests",
                Some(json!({
                    "name": format!("{name}-mixed"),
                    "definition": { "checklist": ["a"], "expect": [{ "error": "validation" }] }
                })),
            )
            .await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);

        // Any signed-in user sees it.
        let person = attome_testapp::seed_user(app.db(), "acceptance-person").await;
        let (code, listed) = app
            .request_as(
                &person.cookie,
                Method::GET,
                "/api/v1/acceptance-scripts?page_size=100",
                None,
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{listed}");
        let mine = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == json!(id))
            .cloned()
            .expect("the script is listed");
        assert_eq!(mine["steps"].as_array().unwrap().len(), 2);

        // Marks must match the steps one for one.
        let runs = format!("/api/v1/acceptance-scripts/{id}/runs");
        let (code, _) = app
            .request_as(
                &person.cookie,
                Method::POST,
                &runs,
                Some(json!({ "steps": [{ "passed": true }] })),
            )
            .await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
        let (code, run) = app
            .request_as(
                &person.cookie,
                Method::POST,
                &runs,
                Some(json!({ "steps": [
                    { "passed": true },
                    { "passed": false, "note": "no Convert button" }
                ] })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{run}");
        assert_eq!(run["passed"], false);
        assert_eq!(
            run["failures"],
            json!(["step 2: Convert it to an account: no Convert button"])
        );
        let run_by: Option<Uuid> =
            sqlx::query_scalar("SELECT run_by FROM customer_test_run WHERE id = $1")
                .bind(run["run_id"].as_str().unwrap().parse::<Uuid>().unwrap())
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(run_by, Some(person.id));

        // Run all leaves it out.
        let (code, all) = app
            .request(Method::POST, "/api/v1/admin/customer-tests/run-all", None)
            .await;
        assert_eq!(code, StatusCode::OK, "{all}");
        assert!(
            !all["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["test_id"] == json!(id)),
            "{all}"
        );
    });
}
