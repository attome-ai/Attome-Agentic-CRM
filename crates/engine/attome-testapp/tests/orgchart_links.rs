//! D23-T4: a contact's manager is set only through the org chart route,
//! only within the contact's account or its group, and never into a loop.

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

async fn install(app: &TestApp) {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

async fn account(app: &TestApp, name: &str, parent: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (name, parent_account_ref, is_active, row_version) \
         VALUES ($1, $2, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(parent)
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

async fn version(app: &TestApp, contact: Uuid) -> i64 {
    sqlx::query_scalar("SELECT row_version FROM contact WHERE id = $1")
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn set(app: &TestApp, contact: Uuid, manager: Option<Uuid>) -> (StatusCode, Value) {
    let if_match = format!("\"{}\"", version(app, contact).await);
    app.request_with(
        Method::PUT,
        &format!("/api/v1/sales/contacts/{contact}/manager"),
        &[("if-match", if_match.as_str())],
        Some(json!({ "manager_id": manager, "line": "solid" })),
    )
    .await
}

async fn manager_of(app: &TestApp, contact: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT reports_to FROM contact WHERE id = $1")
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: D23
#[test]
fn manager_at_unrelated_account_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let group = account(&app, "Holding", None).await;
        let branch = account(&app, "Holding Riyadh", Some(group)).await;
        let other = account(&app, "Unrelated Co", None).await;
        let rep = contact(&app, "Sara", branch).await;
        let group_boss = contact(&app, "Khalid", group).await;
        let stranger = contact(&app, "Omar", other).await;

        let (status, body) = set(&app, rep, Some(stranger)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(manager_of(&app, rep).await, None);

        let (status, body) = set(&app, rep, Some(group_boss)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["previous_manager_id"], Value::Null, "{body}");
        assert_eq!(manager_of(&app, rep).await, Some(group_boss));

        // Undo: set the previous manager back.
        let (status, body) = set(&app, rep, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["previous_manager_id"], json!(group_boss), "{body}");
        assert_eq!(manager_of(&app, rep).await, None);
    });
}

// feature: D23
#[test]
fn loop_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let acme = account(&app, "Acme", None).await;
        let ceo = contact(&app, "Ceo", acme).await;
        let vp = contact(&app, "Vp", acme).await;
        let rep = contact(&app, "Rep", acme).await;

        assert_eq!(set(&app, vp, Some(ceo)).await.0, StatusCode::OK);
        assert_eq!(set(&app, rep, Some(vp)).await.0, StatusCode::OK);
        let (status, body) = set(&app, ceo, Some(rep)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, body) = set(&app, ceo, Some(ceo)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(manager_of(&app, ceo).await, None);
    });
}

// feature: D23
#[test]
fn generic_patch_of_reports_to_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let acme = account(&app, "Acme", None).await;
        let boss = contact(&app, "Boss", acme).await;
        let rep = contact(&app, "Rep", acme).await;
        let if_match = format!("\"{}\"", version(&app, rep).await);
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/contact/{rep}"),
                &[("if-match", if_match.as_str())],
                Some(json!({ "reports_to": boss })),
            )
            .await;
        assert!(status.is_client_error(), "{status}: {body}");
        assert_eq!(manager_of(&app, rep).await, None);
    });
}
