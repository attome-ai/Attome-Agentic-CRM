//! A23-T8: the import routes: an upload found again by its file's hash, an
//! apply over the policy's row limit waiting for approval, and a preview
//! that masks sensitive attributes.

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

const BOUNDARY: &str = "attome-import-test";

/// A fresh entity with a text `title`, a number `level` and a sensitive
/// text `secret_code`.
async fn entity(app: &TestApp) -> String {
    let name = format!("ir_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    for field in [
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
        json!({ "logicalname": "level", "name": "level", "field_type": "number" }),
        json!({ "logicalname": "secret_code", "name": "secret_code", "field_type": "text",
                "is_sensitive": true }),
    ] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(field),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    name
}

/// A multipart body with the file `name` holding `csv`, and `options`.
fn multipart(name: &str, csv: &str, options: &Value) -> Vec<u8> {
    format!(
        "--{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
         Content-Type: text/csv\r\n\r\n\
         {csv}\r\n\
         --{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"options\"\r\n\r\n\
         {options}\r\n\
         --{BOUNDARY}--\r\n"
    )
    .into_bytes()
}

async fn upload(app: &TestApp, entity: &str, csv: &str, options: Value) -> (StatusCode, Value) {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    app.request_public(
        Method::POST,
        &format!("/api/v1/{entity}/imports"),
        &[
            ("cookie", app.admin.cookie.as_str()),
            ("origin", "http://localhost:4200"),
            ("sec-fetch-site", "same-origin"),
            ("content-type", content_type.as_str()),
        ],
        multipart("rows.csv", csv, &options),
    )
    .await
}

/// Stages and validates job `id` here, instead of waiting for the worker.
async fn stage_and_validate(app: &TestApp, id: Uuid) {
    attome_document::import_stage::stage(&app.state, id)
        .await
        .expect("stage");
    attome_records::import_validate::validate(&app.state, id)
        .await
        .expect("validate");
}

fn job_id(body: &Value) -> Uuid {
    body["job_id"].as_str().unwrap().parse().unwrap()
}

// feature: A23
#[test]
fn same_file_returns_existing_job() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let csv = "title,level\nfirst,1\nsecond,2";
        let (status, first) = upload(&app, &entity, csv, json!({"dry_run": true})).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{first}");
        assert_eq!(first["existing"], false, "{first}");
        let (status, again) = upload(&app, &entity, csv, json!({"dry_run": true})).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["existing"], true, "{again}");
        assert_eq!(job_id(&again), job_id(&first));

        let (status, listed) = app
            .request(Method::GET, &format!("/api/v1/{entity}/imports"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["total"], 1, "{listed}");
        let (status, job) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}/imports/{}", job_id(&first)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{job}");
        assert_eq!(job["file_name"], "rows.csv", "{job}");
        // Not a CSV or XLSX file: refused.
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let (status, _) = app
            .request_public(
                Method::POST,
                &format!("/api/v1/{entity}/imports"),
                &[
                    ("cookie", app.admin.cookie.as_str()),
                    ("origin", "http://localhost:4200"),
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", content_type.as_str()),
                ],
                multipart("rows.json", "{}", &json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: A23
// negative: apply_import
#[test]
fn large_import_needs_approval() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let (status, policy) = app
            .request_with(
                Method::PUT,
                &format!("/api/v1/admin/imports/policy/{entity}"),
                &[("if-match", "\"0\"")],
                Some(json!({"approval_over_rows": 2, "sensitive_needs_approval": false})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{policy}");
        assert_eq!(policy["row_version"], 1, "{policy}");
        // A stale version is refused.
        let (status, _) = app
            .request_with(
                Method::PUT,
                &format!("/api/v1/admin/imports/policy/{entity}"),
                &[("if-match", "\"0\"")],
                Some(json!({"approval_over_rows": 5})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, created) = upload(
            &app,
            &entity,
            "title,level\na,1\nb,2\nc,3",
            json!({"dry_run": true}),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{created}");
        let id = job_id(&created);
        stage_and_validate(&app, id).await;
        let (status, applied) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/imports/{id}/apply"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{applied}");
        assert_eq!(applied["status"], "awaiting_approval", "{applied}");
        assert!(applied["approval_request_id"].is_string(), "{applied}");
        let stored: String = sqlx::query_scalar("SELECT status FROM import_job WHERE id = $1")
            .bind(id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(stored, "awaiting_approval");
        // Applying again while it waits is refused.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/imports/{id}/apply"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: A23
#[test]
fn preview_masks_sensitive_fields() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let (status, created) = upload(
            &app,
            &entity,
            "title,secret_code\nfirst,S-1234\nsecond,",
            json!({"dry_run": true}),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{created}");
        let id = job_id(&created);
        stage_and_validate(&app, id).await;
        let (status, preview) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}/imports/{id}/preview?limit=10"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let rows = preview["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "{preview}");
        assert_eq!(rows[0]["mapped"]["title"], "first", "{preview}");
        assert_eq!(rows[0]["mapped"]["secret_code"], "•••", "{preview}");
        assert!(
            preview["masked"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m == "secret_code"),
            "{preview}"
        );
        assert!(!preview.to_string().contains("S-1234"), "{preview}");
    });
}
