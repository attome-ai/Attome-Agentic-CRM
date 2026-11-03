//! T8-T2: a managed package, signed by a trusted publisher, previewed and
//! applied, locks what it owns: its entity takes no customer change except
//! the additions its manifest opens, and a field it adds to an entity it
//! does not own is locked.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use serde_json::{Value, json};
use uuid::Uuid;

// feature: T8
#[test]
fn a_managed_package_locks_what_it_installs() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let ns = format!("t{}", &Uuid::now_v7().simple().to_string()[26..]);
        let owned = format!("{ns}_vehicle");
        let added = format!("{ns}_fleet_size");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());

        // The publisher's key, trusted by the deployment.
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/packages.trusted_publishers",
                Some(json!({ "scope": "deployment", "value": [{ "publisher": "Test Co", "key": public }] })),
            )
            .await;
        assert!(status.is_success(), "{status}: {body}");

        let mut package: attome_api::bundle::package::Package = serde_json::from_value(json!({
            "format": "attome-package/v1",
            "manifest": {
                "id": format!("com.example.{ns}"), "publisher": "Test Co", "namespace": ns,
                "version": "1.0.0", "platform": ">=0.1.0", "contents": ["entities"],
                "mode": "managed", "extension_points": [owned]
            },
            "bundle": {
                "format": "attome-bundle/v1",
                "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
                "entities": [
                    { "logicalname": owned, "display_name": "Vehicle",
                      "attributes": [{ "logicalname": "plate", "display_name": "Plate", "field_type": "text" }] },
                    { "logicalname": "account", "display_name": "Account",
                      "attributes": [{ "logicalname": added, "display_name": "Fleet", "field_type": "number" }] }
                ]
            }
        }))
        .unwrap();
        attome_api::bundle::package::sign(&mut package, &key).unwrap();

        let (status, preview) = app
            .request(
                Method::POST,
                "/api/v1/admin/packages/preview",
                Some(json!({ "package": package })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let plan_id: Uuid = preview["plan"]["plan_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let (status, queued) = app
            .request(
                Method::POST,
                "/api/v1/admin/metadata/import?mode=apply",
                Some(json!({ "plan_id": plan_id })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        attome_api::bundle::apply::run_apply_job(&app.state, plan_id)
            .await
            .unwrap();

        let locks: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT object_kind, object_key, mode FROM metadata_lock \
              WHERE object_key = $1 OR object_key = $2 ORDER BY object_kind",
        )
        .bind(&owned)
        .bind(format!("account.{added}"))
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(
            locks,
            vec![
                (
                    "attribute".to_owned(),
                    format!("account.{added}"),
                    "locked".to_owned()
                ),
                ("entity".to_owned(), owned.clone(), "add_only".to_owned()),
            ]
        );

        // The customer may add a field to the extension point, not change it.
        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
                .bind(&owned)
                .fetch_one(app.db())
                .await
                .unwrap();
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(json!({ "name": "Truck" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "colour", "name": "Colour", "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let _: Value = body;
    });
}
