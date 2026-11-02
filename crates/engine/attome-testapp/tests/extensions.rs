//! Y10-T5: an extension is uploaded as numbered versions, one is published
//! at a time (publishing an older one rolls back), and switching it off
//! stops every version at once.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine;
use serde_json::json;
use uuid::Uuid;

const MODULE: &str = r#"(module (func (export "run") (param i32) (result i32) (local.get 0)))"#;

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

// feature: Y10
// op: upload_extension
// op: publish_extension
// op: switch_off_extension
// op: list_extension_runs
#[test]
fn extensions_version_publish_roll_back_and_switch_off() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("ext_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let manifest =
            json!({ "entities": { "account": { "read": true } }, "hosts": ["api.erp.example"] });

        // A module that does not compile, and bad grants, are refused.
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions",
                Some(
                    json!({ "name": name, "module_base64": b64("not wasm"), "manifest": manifest }),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions",
                Some(json!({ "name": name, "module_base64": b64(MODULE), "manifest": { "hosts": ["*.example"] } })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        for expected in [1, 2] {
            let (status, body) = app
                .request(
                    Method::POST,
                    "/api/v1/admin/extensions",
                    Some(
                        json!({ "name": name, "module_base64": b64(MODULE), "manifest": manifest }),
                    ),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(body["version"], expected);
            assert_eq!(body["status"], "draft");
        }

        let publish = |v: i32| format!("/api/v1/admin/extensions/{name}/versions/{v}/publish");
        let (status, body) = app.request(Method::POST, &publish(2), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            attome_api::extension_admin::published(app.db(), &name)
                .await
                .unwrap()
                .map(|v| v.version),
            Some(2)
        );
        // Roll back to 1: 2 is superseded.
        let (status, _) = app.request(Method::POST, &publish(1), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            attome_api::extension_admin::published(app.db(), &name)
                .await
                .unwrap()
                .map(|v| v.version),
            Some(1)
        );
        let (status, _) = app.request(Method::POST, &publish(9), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Off: nothing runs.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/off"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            attome_api::extension_admin::published(app.db(), &name)
                .await
                .unwrap()
                .is_none()
        );
        let statuses: Vec<String> =
            sqlx::query_scalar("SELECT status FROM extension WHERE name = $1 ORDER BY version")
                .bind(&name)
                .fetch_all(app.db())
                .await
                .unwrap();
        assert_eq!(statuses, vec!["off".to_owned(), "off".to_owned()]);

        // Y10-T6: a run is logged with its cost and its lines masked.
        attome_api::extension_admin::record_run(
            app.db(),
            &name,
            1,
            attome_extension::CallCost {
                fuel_used: 1234,
                elapsed: std::time::Duration::from_millis(7),
            },
            None,
            &[(
                attome_extension::Level::Info,
                "called ERP with key s3cr3t-value".to_owned(),
            )],
            &["s3cr3t-value"],
            true,
        )
        .await
        .unwrap();
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/extensions/{name}/runs"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let run = &body["items"][0];
        assert_eq!(run["fuel_used"], 1234);
        assert_eq!(run["ok"], true);
        assert_eq!(run["logs"][0]["message"], "called ERP with key ***");
    });
}
