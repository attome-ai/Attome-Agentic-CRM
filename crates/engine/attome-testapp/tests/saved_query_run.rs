//! S4-T9: a stored query holding a QuerySpec with typed parameters, run by
//! id through `POST /api/v1/query/run` with values only.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// A fresh entity with a text `title` and a number `level`, two records,
/// and a saved query `level == :level` over it. Returns the entity name and
/// the query id.
async fn saved_query(app: &TestApp, required_privilege: Option<&str>) -> (String, String) {
    let entity = format!("sq_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let entity_id = created["id"].as_str().unwrap().to_owned();
    for (name, field_type) in [("title", "text"), ("level", "number")] {
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": name, "name": name, "field_type": field_type })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for (title, level) in [("first", 1), ("second", 2)] {
        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": title, "level": level })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
    }
    let mut body = json!({
        "name": format!("{entity} by level"),
        "query_spec": {
            "entity": entity,
            "select": ["title", "level"],
            "where": {"kind": "param", "field": "level", "op": "eq", "param": "level"},
        },
        "parameters": [{"name": "level", "type": "number", "required": true}],
    });
    if let Some(key) = required_privilege {
        body["required_privilege"] = json!(key);
    }
    let (status, query) = app
        .request(Method::POST, "/api/v1/admin/queries", Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{query}");
    assert_eq!(query["parameters"][0]["name"], "level", "{query}");
    (entity, query["id"].as_str().unwrap().to_owned())
}

async fn run(app: &TestApp, body: Value) -> (StatusCode, Value) {
    app.request(Method::POST, "/api/v1/query/run", Some(body))
        .await
}

// feature: S4
#[test]
fn saved_query_runs_with_typed_params() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, id) = saved_query(&app, None).await;
        let (status, page) = run(&app, json!({ "query_id": id, "params": { "level": 1 } })).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{page}");
        assert_eq!(items[0]["title"], "first", "{page}");

        // A query by id takes values only.
        let (status, _) = run(
            &app,
            json!({ "query_id": id, "q": "SELECT title FROM x", "params": { "level": 1 } }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // A declaration that names a parameter the spec does not declare is
        // refused on save.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/queries",
                Some(json!({
                    "name": "undeclared",
                    "query_spec": {
                        "entity": "account",
                        "where": {"kind": "param", "field": "name", "op": "eq", "param": "who"},
                    },
                    "parameters": [],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}

// feature: S4
#[test]
fn saved_query_rejects_wrong_param_type() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, id) = saved_query(&app, None).await;
        for params in [
            json!({ "level": "x" }),
            json!({ "level": "1" }),
            json!({}),
            json!({ "level": 1, "other": 2 }),
        ] {
            let (status, body) = run(&app, json!({ "query_id": id, "params": params })).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{params}: {body}");
        }
    });
}

// feature: S4
// negative: query_run
#[test]
fn saved_query_requires_its_privilege() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let user = seed_user(app.db(), "saved-query").await;
        for privilege in [None, Some("reports.level")] {
            let (_, id) = saved_query(&app, privilege).await;
            let (status, body) = app
                .request_as(
                    &user.cookie,
                    Method::POST,
                    "/api/v1/query/run",
                    Some(json!({ "query_id": id, "params": { "level": 1 } })),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{privilege:?}: {body}");
        }
        // An unknown id is a 404.
        let (status, _) = run(
            &app,
            json!({ "query_id": Uuid::now_v7(), "params": { "level": 1 } }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}
