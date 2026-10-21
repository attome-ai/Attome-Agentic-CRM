//! AA7-T2: `GET /api/v1/schema/{logicalname}` answers from the in-process
//! metadata registry, validates with an `ETag`, and answers a matching
//! `If-None-Match` with a bodiless `304`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

/// The schema as the administrator reads it: status, `ETag`, body.
async fn get_schema(
    app: &TestApp,
    entity: &str,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/schema/{entity}"))
        .header("cookie", app.admin.cookie.as_str())
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(tag) = if_none_match {
        builder = builder.header(header::IF_NONE_MATCH, tag);
    }
    let response = app
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, etag, body)
}

async fn add_field(app: &TestApp, entity_id: &str, name: &str) {
    let (status, field) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(json!({ "logicalname": name, "name": name, "field_type": "text" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{field}");
}

// feature: AA7
#[test]
fn schema_304_and_etag_follow_the_published_metadata() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("aasch_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        add_field(&app, &entity_id, "title").await;

        // schema_304_for_same_version_and_roles
        let (status, etag, body) = get_schema(&app, &entity, None).await;
        assert_eq!(status, StatusCode::OK);
        let etag = etag.expect("the schema carries an ETag");
        assert!(etag.starts_with("W/\""), "{etag}");
        let schema: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            schema["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"] == "title"),
            "{schema}"
        );
        let (status, again, empty) = get_schema(&app, &entity, Some(&etag)).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert_eq!(again.as_deref(), Some(etag.as_str()));
        assert!(empty.is_empty());

        // schema_etag_changes_after_publish
        add_field(&app, &entity_id, "amount_note").await;
        let (status, changed, body) = get_schema(&app, &entity, Some(&etag)).await;
        assert_eq!(status, StatusCode::OK, "a stale tag gets the new schema");
        assert_ne!(changed.as_deref(), Some(etag.as_str()));
        let schema: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            schema["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"] == "amount_note"),
            "{schema}"
        );

        // The registry path serves exactly what the database path serves.
        let Some(uncached) =
            TestApp::start_with(|c| c.cache.metadata_registry_enabled = false).await
        else {
            return;
        };
        let (status, _, db_body) = get_schema(&uncached, &entity, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&db_body).unwrap(),
            schema,
            "registry and database answers differ"
        );
        assert_eq!(
            get_schema(&app, "aasch_missing", None).await.0,
            StatusCode::NOT_FOUND
        );
    });
}
