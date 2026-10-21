//! AA7-T8: a record GET with a matching `If-None-Match` answers `304` from
//! the cached row version, after the caller's access is checked, and never
//! hides a deleted record behind a `304`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

async fn get(
    app: &TestApp,
    cookie: &str,
    path: &str,
    etag: Option<&str>,
) -> (StatusCode, Option<String>) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(tag) = etag {
        builder = builder.header(header::IF_NONE_MATCH, tag);
    }
    let response = app
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let tag = response
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().unwrap().to_owned());
    (response.status(), tag)
}

async fn entity_with_record(app: &TestApp) -> (String, String) {
    let entity = format!("aacg_{}", &Uuid::now_v7().simple().to_string()[..12]);
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
    let (status, record) = app
        .request(
            Method::POST,
            &format!("/api/v1/{entity}"),
            Some(json!({ "title": "first" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    (entity, record["id"].as_str().unwrap().to_owned())
}

// feature: AA7
#[test]
fn if_none_match_cached_returns_304() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, id) = entity_with_record(&app).await;
        let path = format!("/api/v1/{entity}/{id}");
        let admin = app.admin.cookie.clone();
        let (status, etag) = get(&app, &admin, &path, None).await;
        assert_eq!(status, StatusCode::OK);
        let etag = etag.expect("a record carries its ETag");
        let (status, again) = get(&app, &admin, &path, Some(&etag)).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert_eq!(again.as_deref(), Some(etag.as_str()));

        // The version now comes from memory: a change made behind the change
        // feed's back is not seen until the entry goes (the TTL bounds it),
        // which shows the 304 ran no probe.
        sqlx::query(&format!(
            "UPDATE {entity} SET row_version = row_version + 1 WHERE id = $1::uuid"
        ))
        .bind(&id)
        .execute(app.db())
        .await
        .unwrap();
        assert_eq!(
            get(&app, &admin, &path, Some(&etag)).await.0,
            StatusCode::NOT_MODIFIED
        );

        // A write through the API forgets it at once: the old tag no
        // longer matches. (PATCH needs the current version in If-Match.)
        let (_, fresh) = get(&app, &admin, &path, None).await;
        let version = fresh
            .unwrap()
            .trim_start_matches("W/")
            .trim_matches('"')
            .to_owned();
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", &format!("\"{version}\""))],
                Some(json!({ "title": "second" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            get(&app, &admin, &path, Some(&etag)).await.0,
            StatusCode::OK
        );
    });
}

// feature: AA7
#[test]
fn if_none_match_after_delete_is_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, id) = entity_with_record(&app).await;
        let path = format!("/api/v1/{entity}/{id}");
        let admin = app.admin.cookie.clone();
        let (_, etag) = get(&app, &admin, &path, None).await;
        let etag = etag.unwrap();
        assert_eq!(
            get(&app, &admin, &path, Some(&etag)).await.0,
            StatusCode::NOT_MODIFIED
        );
        let (status, body) = app.request(Method::DELETE, &path, None).await;
        assert!(status.is_success(), "{status}: {body}");
        assert_eq!(
            get(&app, &admin, &path, Some(&etag)).await.0,
            StatusCode::NOT_FOUND
        );
    });
}

// feature: AA7
#[test]
fn if_none_match_without_read_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, id) = entity_with_record(&app).await;
        let path = format!("/api/v1/{entity}/{id}");
        let (_, etag) = get(&app, &app.admin.cookie.clone(), &path, None).await;
        let etag = etag.unwrap();
        // Cached now; a caller who may not read the record still gets no 304.
        let stranger = seed_user(app.db(), "stranger").await;
        let (status, _) = get(&app, &stranger.cookie, &path, Some(&etag)).await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "{status}"
        );
    });
}
