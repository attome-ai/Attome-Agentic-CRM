//! S13-T1: the private package catalogue. A signed package is added for
//! review, cannot be installed or reviewed by who added it, and once another
//! administrator approves it installs through the T8 package path.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_admin};
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use serde_json::json;
use uuid::Uuid;

// feature: S13
#[test]
fn a_catalogue_package_installs_once_another_admin_approves_it() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let ns = format!("c{}", &Uuid::now_v7().simple().to_string()[26..]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/packages.trusted_publishers",
                Some(json!({ "scope": "deployment", "value": [{ "publisher": "Catalogue Co", "key": public }] })),
            )
            .await;
        assert!(status.is_success(), "{status}: {body}");

        let mut package: attome_api::bundle::package::Package = serde_json::from_value(json!({
            "format": "attome-package/v1",
            "manifest": {
                "id": format!("com.example.{ns}"), "publisher": "Catalogue Co", "namespace": ns,
                "version": "1.0.0", "platform": ">=0.1.0", "contents": ["entities"],
                "mode": "managed"
            },
            "bundle": {
                "format": "attome-bundle/v1",
                "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
                "entities": [{ "logicalname": format!("{ns}_site"), "display_name": "Site",
                    "attributes": [{ "logicalname": "code", "display_name": "Code", "field_type": "text" }] }]
            }
        }))
        .unwrap();
        attome_api::bundle::package::sign(&mut package, &key).unwrap();

        let author = seed_admin(app.db()).await;
        let reviewer = seed_admin(app.db()).await;
        let (status, entry) = app
            .request_as(
                &author.cookie,
                Method::POST,
                "/api/v1/admin/packages/catalogue",
                Some(json!({ "package": package })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{entry}");
        assert_eq!(entry["review_status"], "pending");
        assert_eq!(entry["source"], "pushed");
        assert_eq!(entry["permissions"]["entities"][0]["fields"], 1);
        let id = entry["id"].as_str().unwrap().to_owned();

        // The same version twice is a conflict.
        let (status, body) = app
            .request_as(
                &author.cookie,
                Method::POST,
                "/api/v1/admin/packages/catalogue",
                Some(json!({ "package": package })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Not installable before review; not reviewable by its author.
        let install = format!("/api/v1/admin/packages/catalogue/{id}/install");
        let review = format!("/api/v1/admin/packages/catalogue/{id}/review");
        let (status, body) = app
            .request_as(&reviewer.cookie, Method::POST, &install, None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, body) = app
            .request_as(
                &author.cookie,
                Method::POST,
                &review,
                Some(json!({ "decision": "approved" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let (status, reviewed) = app
            .request_as(
                &reviewer.cookie,
                Method::POST,
                &review,
                Some(json!({ "decision": "approved", "note": "checked the fields" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{reviewed}");
        assert_eq!(reviewed["review_status"], "approved");
        let (status, body) = app
            .request_as(
                &reviewer.cookie,
                Method::POST,
                &review,
                Some(json!({ "decision": "rejected" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "reviewed once: {body}");

        let (status, preview) = app
            .request_as(&author.cookie, Method::POST, &install, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["plan"]["applicable"], true, "{preview}");

        let (status, list) = app
            .request(
                Method::GET,
                "/api/v1/admin/packages/catalogue?page=1&page_size=200",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(
            list["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["id"] == id.as_str())
        );
    });
}
