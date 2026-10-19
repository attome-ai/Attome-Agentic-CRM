//! B3-T3: an attachment is shared with an outside person through a K1
//! expiring link. A record's attachment (a file field) gets a link with a
//! password; the public route asks for the password, refuses a wrong one,
//! answers a short-lived download URL for the right one and audits it; a
//! link past its expiry is a plain 404.

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

const PASSWORD: &str = "Share-Link-Password-2026!";

/// An entity with an `attachment` file field, and one record whose
/// attachment holds an object key this record owns.
async fn attachment(app: &TestApp) -> (String, Uuid) {
    let entity = format!("b3_note_{}", &Uuid::now_v7().simple().to_string()[..12]);
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
            Some(json!({ "title": "contract notes" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    // A promoted upload's key; the upload itself is the file engine's.
    sqlx::query(&format!(
        "UPDATE \"{entity}\" SET attachment = $1 WHERE id = $2"
    ))
    .bind(format!("{entity}/{id}/attachment/contract.pdf"))
    .bind(id)
    .execute(app.db())
    .await
    .unwrap();
    (entity, id)
}

// feature: B3
#[test]
fn share_link_with_password_opens_once_given_and_expires() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, id) = attachment(&app).await;
        let (status, link) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/{id}/files/attachment/share-links"),
                Some(json!({ "expires_in_hours": 2, "password": PASSWORD })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{link}");
        assert_eq!(link["has_password"], true);
        let path = link["path"].as_str().unwrap().to_owned();

        // A password link is not opened by GET, and a wrong password fails.
        let (status, _) = app
            .request_public(Method::GET, &path, &[], Vec::new())
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let open = |password: &str| json!({ "password": password }).to_string().into_bytes();
        let headers = [("content-type", "application/json")];
        let (status, _) = app
            .request_public(Method::POST, &path, &headers, open("not the password"))
            .await;
        assert_ne!(status, StatusCode::OK, "a wrong password opens nothing");

        let (status, opened) = app
            .request_public(Method::POST, &path, &headers, open(PASSWORD))
            .await;
        assert_eq!(status, StatusCode::OK, "{opened}");
        let url = opened["download_url"].as_str().unwrap();
        assert!(url.contains("contract.pdf"), "{url}");

        let counted: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM file_share_link WHERE id = $1 AND download_count = 1",
        )
        .bind(link["id"].as_str().unwrap().parse::<Uuid>().unwrap())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(counted, 1, "the download is counted");

        // Past its expiry the link is a plain 404, password or not.
        sqlx::query(
            "UPDATE file_share_link SET expires_at = now() - interval '1 minute' WHERE id = $1",
        )
        .bind(link["id"].as_str().unwrap().parse::<Uuid>().unwrap())
        .execute(app.db())
        .await
        .unwrap();
        let (status, _) = app
            .request_public(Method::POST, &path, &headers, open(PASSWORD))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}
