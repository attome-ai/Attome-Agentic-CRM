//! A26-T1: a derived entity lists the anchor's rows matching its condition,
//! reads one member, refuses every write with 405, and refuses a condition
//! that reaches past the anchor's own fields.

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

// feature: A26
#[test]
fn derived_entity_lists_members_and_refuses_writes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }

        let prefix = format!("Derived {}", Uuid::now_v7().simple());
        let mut ids = Vec::new();
        for name in [
            format!("{prefix} A"),
            format!("{prefix} B"),
            "Not a member".to_owned(),
        ] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO account (name, owner_ref, owner_type) VALUES ($1, $2, 0) RETURNING id",
            )
            .bind(&name)
            .bind(app.admin.id)
            .fetch_one(app.db())
            .await
            .unwrap();
            ids.push(id);
        }
        let name = format!("dv_test_{}", &Uuid::now_v7().simple().to_string()[24..]);

        // A condition over a lookup's field is refused.
        let (status, _) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({"anchor": "account", "condition": "owner_ref.name == \"x\""})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({
                    "anchor": "account",
                    "condition": format!("startswith(name, \"{prefix}\")"),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["mode"], "live");

        let (status, body) = app
            .request(Method::GET, &format!("/api/v1/{name}?page_size=50"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut listed: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect();
        listed.sort();
        let mut members = vec![ids[0].to_string(), ids[1].to_string()];
        members.sort();
        assert_eq!(listed, members);

        let (status, body) = app
            .request(Method::GET, &format!("/api/v1/{name}/{}", ids[0]), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = app
            .request(Method::GET, &format!("/api/v1/{name}/{}", ids[2]), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Every write is refused.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({"name": "x"})),
            )
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, _) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/{name}/{}", ids[0]),
                Some(json!({"name": "x"})),
            )
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, _) = app
            .request(Method::DELETE, &format!("/api/v1/{name}/{}", ids[0]), None)
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

        // The view exists with its members.
        let in_view: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"xrm_dv_{name}\""))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(in_view, 2);

        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/derived-entities/{name}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app
            .request(Method::GET, &format!("/api/v1/{name}"), None)
            .await;
        assert_ne!(status, StatusCode::OK);
    });
}
