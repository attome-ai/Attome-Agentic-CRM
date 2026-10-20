//! D23-T9: the org chart routes — the manager change needs `If-Match`, the
//! export queues a PDF render (and refuses any other format), and every
//! route is hidden when the sales module is off.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn install(app: &TestApp) {
    for pack in ["crm", "sales"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
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
    }
}

async fn account(app: &TestApp) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (name, is_active, row_version) VALUES ('Routes Co', true, 0) \
         RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn contact(app: &TestApp, name: &str, account: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO contact (full_name, account_ref, is_active, row_version) \
         VALUES ($1, $2, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: D23
#[test]
fn set_manager_needs_if_match() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account = account(&app).await;
        let rep = contact(&app, "Rep", account).await;
        let boss = contact(&app, "Boss", account).await;
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/sales/contacts/{rep}/manager"),
                Some(json!({ "manager_id": boss, "line": "solid" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let manager: Option<Uuid> =
            sqlx::query_scalar("SELECT reports_to FROM contact WHERE id = $1")
                .bind(rep)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(manager, None, "nothing changed without If-Match");
    });
}

// feature: D23
#[test]
fn export_queues_a_pdf_render() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account = account(&app).await;
        contact(&app, "Someone", account).await;
        let path = format!("/api/v1/sales/accounts/{account}/org-chart/export");
        let (status, body) = app
            .request(Method::POST, &path, Some(json!({ "format": "png" })))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, body) = app
            .request(
                Method::POST,
                &path,
                Some(json!({ "format": "pdf", "locale": "ar" })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let render = Uuid::parse_str(body["render_id"].as_str().unwrap()).unwrap();
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/docgen/renders/{render}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}

// feature: D23
#[test]
fn unlicensed_returns_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let before = app.state.modules.load_full();
        app.state
            .modules
            .store(Arc::new(attome_modules::ModuleSet::from_bits([0u64; 4])));
        let id = Uuid::now_v7();
        let calls = [
            (
                Method::GET,
                format!("/api/v1/sales/accounts/{id}/org-chart"),
                None,
            ),
            (
                Method::GET,
                format!("/api/v1/sales/opportunities/{id}/committee-map"),
                None,
            ),
            (
                Method::POST,
                format!("/api/v1/sales/accounts/{id}/org-chart/export"),
                Some(json!({ "format": "pdf" })),
            ),
        ];
        let mut answers = Vec::new();
        for (method, path, body) in calls {
            let (status, answer) = app.request(method, &path, body).await;
            answers.push((path, status, answer));
        }
        app.state.modules.store(before);
        // The platform's answer for a module that is off (D-279) is 403
        // `feature_hidden`, before any handler or privilege check; the
        // plan's "404" is v1's.
        for (path, status, answer) in answers {
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
            assert_eq!(answer["error"], "feature_hidden", "{path}: {answer}");
        }
    });
}
