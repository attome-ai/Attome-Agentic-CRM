//! D21-T7: the dialer's routes refuse a caller without the call privilege,
//! refuse a skip of a member the caller has not claimed, and are hidden when
//! the sales module is off.

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

/// The dialer's mutating routes for a list and one of its members.
fn calls(list: Uuid, member: Uuid) -> [(String, Value); 5] {
    [
        (format!("/api/v1/sales/call-lists/{list}/claim"), json!({})),
        (format!("/api/v1/sales/call-lists/{list}/build"), json!({})),
        (
            format!("/api/v1/sales/call-list-members/{member}/outcome"),
            json!({ "outcome": "no_answer" }),
        ),
        (
            format!("/api/v1/sales/call-list-members/{member}/skip"),
            json!({ "reason": "wrong person" }),
        ),
        (
            format!("/api/v1/sales/call-lists/{list}/voicemail"),
            json!({}),
        ),
    ]
}

// feature: D21
// negative: POST /api/v1/sales/call-list-members/{id}/skip
#[test]
fn claim_requires_list_read_privilege() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let list: Uuid = sqlx::query_scalar(
            "INSERT INTO call_list (name, is_active, row_version) VALUES ('Q4 renewals', true, 0) \
             RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        let member: Uuid = sqlx::query_scalar(
            "INSERT INTO call_list_member (list_ref, entity_name, record_id, member_status, \
                 is_active, row_version) \
             VALUES ($1, 'lead', $2, 'pending', true, 0) RETURNING id",
        )
        .bind(list)
        .bind(Uuid::now_v7().to_string())
        .fetch_one(app.db())
        .await
        .unwrap();

        // No role at all: every dialer call is refused.
        let nobody = attome_testapp::seed_user(app.db(), "no-dialer").await;
        for (path, body) in calls(list, member) {
            let (status, answer) = app
                .request_as(&nobody.cookie, Method::POST, &path, Some(body))
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
        }

        // A member nobody claimed cannot be skipped, even by an administrator.
        let (status, answer) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/call-list-members/{member}/skip"),
                Some(json!({ "reason": "wrong person" })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
        let status_now: String =
            sqlx::query_scalar("SELECT member_status FROM call_list_member WHERE id = $1")
                .bind(member)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status_now, "pending");
    });
}

// feature: D21
#[test]
fn unlicensed_sales_module_is_hidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let before = app.state.modules.load_full();
        app.state
            .modules
            .store(Arc::new(attome_modules::ModuleSet::from_bits([0u64; 4])));
        let mut answers = Vec::new();
        for (path, body) in calls(Uuid::now_v7(), Uuid::now_v7()) {
            let (status, answer) = app.request(Method::POST, &path, Some(body)).await;
            answers.push((path, status, answer));
        }
        app.state.modules.store(before);
        // The platform's answer for a module that is off (D-279): 403
        // `feature_hidden`, before any handler or privilege check.
        for (path, status, answer) in answers {
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
            assert_eq!(answer["error"], "feature_hidden", "{path}: {answer}");
        }
    });
}
