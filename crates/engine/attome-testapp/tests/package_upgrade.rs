//! T8-T3: a managed package's life after install. An upgrade merges with
//! the customer's additions and replaces the old version's locks; drift
//! reads clean after it; an uninstall that removes the data is refused
//! without exports when it asks for them, then retires what the package
//! owns and lifts its locks.

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

fn package(
    key: &ed25519_dalek::SigningKey,
    ns: &str,
    version: &str,
    attributes: Value,
) -> attome_api::bundle::package::Package {
    let owned = format!("{ns}_vehicle");
    let mut package: attome_api::bundle::package::Package = serde_json::from_value(json!({
        "format": "attome-package/v1",
        "manifest": {
            "id": format!("com.example.{ns}"), "publisher": "Test Co", "namespace": ns,
            "version": version, "platform": ">=0.1.0", "contents": ["entities"],
            "mode": "managed", "extension_points": [owned]
        },
        "bundle": {
            "format": "attome-bundle/v1",
            "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
            "entities": [{ "logicalname": owned, "display_name": "Vehicle", "attributes": attributes }]
        }
    }))
    .unwrap();
    attome_api::bundle::package::sign(&mut package, key).unwrap();
    package
}

async fn apply(app: &TestApp, plan: &Value) {
    let plan_id: Uuid = plan["plan_id"].as_str().unwrap().parse().unwrap();
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
}

// feature: T8
#[test]
fn a_managed_package_upgrades_drifts_and_uninstalls() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let ns = format!("u{}", &Uuid::now_v7().simple().to_string()[26..]);
        let id = format!("com.example.{ns}");
        let owned = format!("{ns}_vehicle");
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/packages.trusted_publishers",
                Some(json!({ "scope": "deployment", "value": [{ "publisher": "Test Co", "key": public }] })),
            )
            .await;
        assert!(status.is_success(), "{status}: {body}");

        // Version 1, installed.
        let plate =
            json!({ "logicalname": "plate", "display_name": "Plate", "field_type": "text" });
        let v1 = package(&key, &ns, "1.0.0", json!([plate]));
        let (status, preview) = app
            .request(
                Method::POST,
                "/api/v1/admin/packages/preview",
                Some(json!({ "package": v1 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        apply(&app, &preview["plan"]).await;

        // The customer adds a field on the extension point.
        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
                .bind(&owned)
                .fetch_one(app.db())
                .await
                .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "colour", "name": "Colour", "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        // The same version is not an upgrade.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/packages/upgrade",
                Some(json!({ "package": v1 })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // Version 2 relabels the plate and adds a VIN.
        let v2 = package(
            &key,
            &ns,
            "1.1.0",
            json!([
                { "logicalname": "plate", "display_name": "Plate number", "field_type": "text" },
                { "logicalname": "vin", "display_name": "VIN", "field_type": "text" }
            ]),
        );
        let (status, upgrade) = app
            .request(
                Method::POST,
                "/api/v1/admin/packages/upgrade",
                Some(json!({ "package": v2 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{upgrade}");
        assert_eq!(upgrade["from_version"], "1.0.0");
        assert_eq!(upgrade["conflicts"], json!([]), "{upgrade}");
        assert_eq!(upgrade["plan"]["applicable"], true, "{upgrade}");
        apply(&app, &upgrade["plan"]).await;

        let fields: Vec<String> = sqlx::query_scalar(
            "SELECT a.logicalname FROM attribute_info a \
               JOIN entity_info e ON e.id = a.entity_ref \
              WHERE e.logicalname = $1 AND a.logicalname IN ('plate', 'vin', 'colour') \
              ORDER BY 1",
        )
        .bind(&owned)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(
            fields,
            vec!["colour", "plate", "vin"],
            "the customer's field stays"
        );
        let versions: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT version, data_choice FROM package_install \
              WHERE package_id = $1 AND installed_at IS NOT NULL ORDER BY version",
        )
        .bind(&id)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(
            versions,
            vec![
                ("1.0.0".to_owned(), Some("upgraded".to_owned())),
                ("1.1.0".to_owned(), None)
            ]
        );

        let (status, drift) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/packages/{id}/drift"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{drift}");
        assert_eq!(drift["version"], "1.1.0");
        assert_eq!(drift["clean"], true, "{drift}");

        // Exporting needs the exports.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/packages/{id}/uninstall"),
                Some(json!({ "data": "export" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.to_string().contains(&owned), "{body}");

        let (status, gone) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/packages/{id}/uninstall"),
                Some(json!({ "data": "delete" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{gone}");
        assert_eq!(gone["unlocked"], 1, "{gone}");
        let plan_id: Uuid = gone["apply"]["plan_id"].as_str().unwrap().parse().unwrap();
        attome_api::bundle::apply::run_apply_job(&app.state, plan_id)
            .await
            .unwrap();
        let active: bool =
            sqlx::query_scalar("SELECT is_active FROM entity_info WHERE logicalname = $1")
                .bind(&owned)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert!(!active, "the package's entity is retired");
        let locks: i64 =
            sqlx::query_scalar("SELECT count(*) FROM metadata_lock WHERE object_key = $1")
                .bind(&owned)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(locks, 0);
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/packages/{id}/drift"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}
