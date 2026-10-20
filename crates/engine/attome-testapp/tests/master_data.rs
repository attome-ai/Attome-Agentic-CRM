//! L1-T1: master-data settings on entity metadata. Marking an entity as
//! master data needs a data domain, the settings are written as one
//! `set_entity_master_data` operation, and they are read back from the
//! entity's metadata after the registry reloads. Later L1 tasks add their
//! tests here.

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

// feature: L1
#[test]
fn mark_entity_master_requires_domain_and_survives_reload() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let suffix = &Uuid::now_v7().simple().to_string()[..12];
        let entity = format!("mdm_{suffix}");
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let master = json!({ "master_data": { "is_master": true, "hub_style": "registry" } });

        // No data domain yet: refused, naming the field.
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(master.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.to_string().contains("is_master"), "{body}");

        // An unknown hub style is refused too.
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(json!({ "master_data": { "is_master": false, "hub_style": "federated" } })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let (status, domain) = app
            .request(
                Method::POST,
                "/api/v1/admin/governance/domains",
                Some(json!({ "name": format!("Customers {suffix}") })),
            )
            .await;
        assert!(status.is_success(), "{status} {domain}");
        let domain_id = domain["id"].as_str().unwrap().to_owned();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
                Some(json!({ "entity_logicalnames": [entity] })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");

        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(master),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Read back from the stored metadata, as any node reloading it sees it.
        let (status, detail) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/entities/{entity_id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(
            detail["master_data"],
            json!({ "is_master": true, "hub_style": "registry" })
        );
        let stored: (bool, Option<String>) =
            sqlx::query_as("SELECT is_master, hub_style FROM entity_info WHERE id = $1::uuid")
                .bind(&entity_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(stored, (true, Some("registry".to_owned())));
    });
}
