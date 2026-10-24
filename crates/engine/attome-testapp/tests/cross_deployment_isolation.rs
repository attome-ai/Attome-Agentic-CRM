//! Y5-T4: two deployments side by side cannot read each other. Deployment A
//! is the shared test app; deployment B gets a database of its own (migrated
//! here), its own object-store bucket and its own Redis database, as a
//! separate customer's data plane does (D-002). A record, a file and a share
//! link are made in A; B's administrator then asks B for them through every
//! interface (the record API, the list, search, the change feed, the query
//! engine, the file download route, the public share link), and each
//! deployment is shown the other's session. Every answer is a refusal (401
//! or 404) or empty, and none carries A's data.
//!
//! Both apps sign sessions with the same test secret, the worst case for this
//! test: a token that verifies is still refused because its user does not
//! exist on the other side.

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

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../apps/attome/migrations");

/// Deployment B: a freshly migrated database, bucket `attome-test-b`, Redis
/// database 1. The database is dropped with the returned guard.
async fn deployment_b() -> Option<(TestApp, attome_testkit::EmptyDatabase)> {
    let database = attome_testkit::empty_database("isolation_b").await?;
    let pool = attome_testkit::connect(database.url(), 2).await;
    MIGRATOR.run(&pool).await.expect("migrate deployment B");
    pool.close().await;
    let url = database.url().to_owned();
    let app = TestApp::start_with(|config| {
        attome_testkit::point_config_at(config, &url);
        config.storage.s3_bucket = "attome-test-b".into();
        config.cache.db = 1;
    })
    .await?;
    Some((app, database))
}

/// An entity with a title and a file field in `app`, and one record whose
/// title is `secret` and whose attachment holds an object key.
async fn record_with_file(app: &TestApp, secret: &str) -> (String, Uuid) {
    let entity = format!("y5_iso_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let entity_id = body["id"].as_str().unwrap().to_owned();
    for field in [
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
        json!({ "logicalname": "attachment", "name": "attachment", "field_type": "file" }),
    ] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(field),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/{entity}"),
            Some(json!({ "title": secret })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    // A promoted upload's key; the upload itself is the file engine's.
    sqlx::query(&format!(
        "UPDATE \"{entity}\" SET attachment = $1 WHERE id = $2"
    ))
    .bind(format!("{entity}/{id}/attachment/{secret}.pdf"))
    .bind(id)
    .execute(app.db())
    .await
    .unwrap();
    (entity, id)
}

/// A refusal or an empty answer, with none of `secret` in it.
fn refused_or_empty(what: &str, status: StatusCode, body: &Value, secret: &str, id: Uuid) {
    // An error names the path it answers (`instance`), which may hold the
    // id that was asked for; that is the question echoed, not A's data.
    let mut answer = body.clone();
    if let Some(error) = answer.as_object_mut() {
        error.remove("instance");
    }
    let text = answer.to_string();
    assert!(
        !text.contains(secret) && !text.contains(&id.to_string()),
        "{what}: answered with deployment A's data: {status} {text}"
    );
    let empty = body
        .get("items")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        || body
            .get("results")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        || body
            .get("hits")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
    assert!(
        matches!(status, StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND)
            || (status == StatusCode::OK && empty),
        "{what}: expected 401, 404 or an empty answer, got {status} {text}"
    );
}

// feature: Y5
#[test]
fn deployment_b_cannot_read_deployment_a() {
    attome_testkit::run_shared(async {
        let Some(a) = TestApp::start().await else {
            return;
        };
        let Some((b, _database)) = deployment_b().await else {
            return;
        };
        let secret = format!("isolation{}", Uuid::now_v7().simple());
        let (entity, id) = record_with_file(&a, &secret).await;

        // A sees its own record, so the probes below are meaningful.
        let (status, body) = a
            .request(Method::GET, &format!("/api/v1/{entity}/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, link) = a
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/{id}/files/attachment/share-links"),
                Some(json!({ "expires_in_hours": 2 })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{link}");
        let share_path = link["path"].as_str().unwrap().to_owned();

        // B's administrator, through every interface B offers.
        let probes: Vec<(&str, Method, String, Option<Value>)> = vec![
            (
                "record",
                Method::GET,
                format!("/api/v1/{entity}/{id}"),
                None,
            ),
            ("list", Method::GET, format!("/api/v1/{entity}"), None),
            (
                "search",
                Method::GET,
                format!("/api/v1/search?q={secret}"),
                None,
            ),
            (
                "change feed",
                Method::POST,
                "/api/v1/query/changes".into(),
                Some(json!({ "entity": entity })),
            ),
            (
                "query engine",
                Method::POST,
                "/api/v1/query/run".into(),
                Some(json!({ "q": format!("SELECT title FROM {entity}") })),
            ),
            (
                "file download",
                Method::GET,
                format!("/api/v1/{entity}/{id}/files/attachment/download-url"),
                None,
            ),
        ];
        for (what, method, path, body) in probes {
            let (status, answer) = b.request(method, &path, body).await;
            refused_or_empty(what, status, &answer, &secret, id);
        }

        // A's public share link, presented to B.
        let (status, answer) = b
            .request_public(Method::GET, &share_path, &[], Vec::new())
            .await;
        refused_or_empty("share link", status, &answer, &secret, id);

        // Each deployment's session, shown to the other.
        let (status, answer) = b
            .request_as(
                &a.admin.cookie,
                Method::GET,
                &format!("/api/v1/{entity}/{id}"),
                None,
            )
            .await;
        refused_or_empty("A's session at B", status, &answer, &secret, id);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
        let (status, answer) = a
            .request_as(
                &b.admin.cookie,
                Method::GET,
                &format!("/api/v1/{entity}/{id}"),
                None,
            )
            .await;
        refused_or_empty("B's session at A", status, &answer, &secret, id);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    });
}
