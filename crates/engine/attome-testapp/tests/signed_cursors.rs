//! Z14-T5: the generic list hands out a signed cursor, follows it to the
//! next page, and refuses a cursor it did not issue with 400 `invalid_cursor`.

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

// feature: Z14
#[test]
fn signed_cursor_pages_on_and_a_forged_one_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("zcur_{}", &Uuid::now_v7().simple().to_string()[..12]);
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
                Some(json!({ "logicalname": "amount", "name": "amount", "field_type": "number" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
        let mut ids = Vec::new();
        for i in 0..3 {
            let (status, record) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(json!({ "amount": i })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{record}");
            ids.push(record["id"].as_str().unwrap().to_owned());
        }

        let (status, first) = app
            .request(Method::GET, &format!("/api/v1/{entity}?page_size=2"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["items"].as_array().unwrap().len(), 2, "{first}");
        let cursor = first["next_cursor"]
            .as_str()
            .expect("a full page continues");
        // Opaque: not the last row's id any more.
        assert!(!ids.iter().any(|id| id == cursor), "{cursor}");

        let (status, second) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}?page_size=2&cursor={cursor}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(second["items"].as_array().unwrap().len(), 1, "{second}");

        // A bare row id (the old cursor), a tampered tag and garbage.
        let (payload, _) = cursor.split_once('.').unwrap();
        for forged in [
            ids[0].clone(),
            format!("{payload}.AAAA"),
            "not-a-cursor".to_owned(),
        ] {
            let (status, body) = app
                .request(
                    Method::GET,
                    &format!("/api/v1/{entity}?page_size=2&cursor={forged}"),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{forged}: {body}");
            assert_eq!(body["error"], "invalid_cursor", "{body}");
        }
    });
}
