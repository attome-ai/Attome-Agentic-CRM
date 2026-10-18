//! S1-T13: a record read with `Accept-Language: ar` carries each choice
//! field's Arabic label beside its stored value; with no supported language
//! there are no labels.

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

// feature: S1
#[test]
fn accept_language_ar_returns_arabic_choice_label() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("clabel_{}", &Uuid::now_v7().simple().to_string()[..12]);
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
                Some(
                    json!({ "logicalname": "stage", "name": "stage", "field_type": "choice",
                             "options": { "choices": ["open", "won"], "multi": false } }),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
        let (status, label) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/labels"),
                Some(
                    json!({ "object_kind": "choice_option", "attribute_logicalname": "stage",
                             "option_value": "open", "locale": "ar", "display_name": "مفتوح" }),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{label}");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "stage": "open" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let path = format!("/api/v1/{entity}/{}", record["id"].as_str().unwrap());

        let (status, arabic) = app
            .request_with(
                Method::GET,
                &path,
                &[("accept-language", "ar-SA,en;q=0.5")],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{arabic}");
        assert_eq!(arabic["labels"]["stage"], "مفتوح", "{arabic}");
        assert_eq!(arabic["data"]["stage"], "open", "the stored value stays");

        let (_, plain) = app
            .request_with(Method::GET, &path, &[("accept-language", "fr")], None)
            .await;
        assert!(plain.get("labels").is_none(), "{plain}");
    });
}
