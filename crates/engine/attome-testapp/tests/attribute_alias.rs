//! Y12-T8: after a rename, the old attribute name keeps working in the
//! record API for its alias period: a create or update body and a
//! `query/execute` filter may use it, the response says so with
//! `Deprecation` and `Link`, and responses use the new name only.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

/// One request as the administrator, with its headers in the answer.
async fn send(
    app: &TestApp,
    method: Method,
    path: &str,
    extra: &[(&str, &str)],
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("cookie", app.admin.cookie.as_str())
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let response = app
        .router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// feature: Y12
#[test]
fn old_name_accepted_after_rename() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("alias_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
        let field_id = field["id"].as_str().unwrap().to_owned();
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": "first" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let id = record["id"].as_str().unwrap().to_owned();

        let (status, renamed) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}/rename"),
                Some(json!({ "new_name": "headline" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{renamed}");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        // An update by the old name lands on the new attribute, and says so.
        let (_, current) = app
            .request(Method::GET, &format!("/api/v1/{entity}/{id}"), None)
            .await;
        let version = current["row_version"].to_string();
        let if_match = format!("\"{}\"", version.trim_matches('"'));
        let (status, headers, updated) = send(
            &app,
            Method::PATCH,
            &format!("/api/v1/{entity}/{id}"),
            &[("if-match", if_match.as_str())],
            json!({ "title": "second" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(headers["deprecation"], "true");
        let link = headers["link"].to_str().unwrap();
        assert!(link.contains(&format!("{entity}.headline")), "{link}");
        let (_, shown) = app
            .request(Method::GET, &format!("/api/v1/{entity}/{id}"), None)
            .await;
        assert_eq!(shown["data"]["headline"], "second", "{shown}");
        assert!(
            shown["data"].get("title").is_none(),
            "responses use the new name: {shown}"
        );

        // A create by the old name too; one by the new name has no header.
        let (status, headers, _) = send(
            &app,
            Method::POST,
            &format!("/api/v1/{entity}"),
            &[],
            json!({ "title": "third" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers["deprecation"], "true");
        let (status, headers, _) = send(
            &app,
            Method::POST,
            &format!("/api/v1/{entity}"),
            &[],
            json!({ "headline": "fourth" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(headers.get("deprecation").is_none());

        // A list filter by the old name.
        let (status, listed) = app
            .request(
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "entity": entity,
                             "filters": [{ "field": "title", "op": "eq", "value": "third" }] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(
            listed["data"]["records"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
    });
}
