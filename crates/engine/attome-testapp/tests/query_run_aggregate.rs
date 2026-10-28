//! S4-T11: what `POST /api/v1/search/aggregate` answered, asked of
//! `POST /api/v1/query/run` aggregates, which replaced it: a grouped sum, a
//! grouped count, one ungrouped total, and a refused non-numeric measure.

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

/// An entity with `region` and `amount`, and deals across three regions.
async fn fixture(app: &TestApp) -> String {
    let entity = format!("qagg_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    for (name, ty) in [("region", "text"), ("amount", "number")] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(json!({ "logicalname": name, "name": name, "field_type": ty,
                             "is_sortable": true, "is_filterable": true })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for (region, amount) in [("GCC", 100), ("GCC", 50), ("EU", 30), ("APAC", 10)] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "region": region, "amount": amount })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    entity
}

async fn run(app: &TestApp, spec: Value) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        "/api/v1/query/run",
        Some(json!({ "spec": spec })),
    )
    .await
}

/// The value of `alias` in the group whose `region` key is `region`.
fn value_for(body: &Value, region: &str, alias: &str) -> f64 {
    body["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("no groups: {body}"))
        .iter()
        .find(|g| g["keys"]["region"] == region)
        .unwrap_or_else(|| panic!("{region} group missing: {body}"))["values"][alias]
        .as_f64()
        .unwrap_or_else(|| panic!("{alias} is not a number: {body}"))
}

// feature: S4
#[test]
fn aggregate_parity_sum_grouped_by_region() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let (status, body) = run(
            &app,
            json!({
                "entity": entity,
                "group_by": [{"field": "region"}],
                "aggregates": [{"func": "sum", "field": "amount", "alias": "total"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["groups"].as_array().unwrap().len(), 3, "{body}");
        assert_eq!(value_for(&body, "GCC", "total"), 150.0, "{body}");
    });
}

// feature: S4
#[test]
fn aggregate_parity_count_grouped_by_region() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let (status, body) = run(
            &app,
            json!({
                "entity": entity,
                "group_by": [{"field": "region"}],
                "aggregates": [{"func": "count", "alias": "n"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(value_for(&body, "GCC", "n"), 2.0, "{body}");
    });
}

// feature: S4
#[test]
fn aggregate_parity_ungrouped_total() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let (status, body) = run(
            &app,
            json!({
                "entity": entity,
                "aggregates": [{"func": "sum", "field": "amount", "alias": "total"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let groups = body["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "{body}");
        assert_eq!(groups[0]["values"]["total"].as_f64(), Some(190.0), "{body}");
    });
}

// feature: S4
#[test]
fn aggregate_parity_rejects_a_non_numeric_measure() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let (status, body) = run(
            &app,
            json!({
                "entity": entity,
                "group_by": [{"field": "region"}],
                "aggregates": [{"func": "sum", "field": "region", "alias": "total"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}
