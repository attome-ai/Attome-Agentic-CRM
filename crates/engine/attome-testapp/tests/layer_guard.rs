//! Y11-T10: through the admin routes a customer may not take a reserved
//! name, and a locked or add-only item keeps what it has. The lock is set
//! by hand on the throwaway database (a layer's own definitions set it).

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

async fn lock(app: &TestApp, kind: &str, key: &str, mode: &str) {
    sqlx::query(
        "INSERT INTO metadata_lock (object_kind, object_key, mode, set_by_layer) \
         VALUES ($1, $2, $3, 'platform') \
         ON CONFLICT (object_kind, object_key) DO UPDATE SET mode = EXCLUDED.mode",
    )
    .bind(kind)
    .bind(key)
    .bind(mode)
    .execute(app.db())
    .await
    .unwrap();
}

async fn add_field(app: &TestApp, entity_id: &str, name: &str) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/admin/entities/{entity_id}/fields"),
        Some(json!({ "logicalname": name, "name": name, "field_type": "text" })),
    )
    .await
}

// feature: Y11
#[test]
fn reserved_name_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = &Uuid::now_v7().simple().to_string()[..12];
        for name in [format!("attome_widget_{token}"), format!("xrm_old_{token}")] {
            let (status, body) = app
                .request(
                    Method::POST,
                    "/api/v1/admin/entities",
                    Some(json!({ "logicalname": name, "name": name })),
                )
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {body}");
        }
        // A word that merely starts with "at" is the customer's.
        let name = format!("at_risk_{token}");
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let (status, _) = add_field(&app, &entity_id, "attome_flag").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: Y11
#[test]
fn locked_item_refuses_customer_change() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("guard_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let (status, field) = add_field(&app, &entity_id, "note").await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
        let field_id = field["id"].as_str().unwrap().to_owned();
        let field_path = format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}");

        // Add-only: a new field is fine, changing one is not.
        lock(&app, "entity", &name, "add_only").await;
        let (status, body) = add_field(&app, &entity_id, "extra").await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = app
            .request(
                Method::PATCH,
                &field_path,
                Some(json!({ "name": "Renamed" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.to_string().contains("metadata_add_only"), "{body}");

        // Locked: nothing changes, not even an addition.
        lock(&app, "entity", &name, "locked").await;
        let (status, _) = add_field(&app, &entity_id, "more").await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(json!({ "name": "Other" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, _) = app.request(Method::DELETE, &field_path, None).await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}
