//! G17-T16 (part): the planner's workforce routes refuse a member of staff.
//! A person with no workforce privilege who builds or publishes a schedule,
//! decides a swap or sends an offer is answered 403 before anything is read.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// The workforce pack, as the adherence test installs it.
async fn install(app: &TestApp) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/workforce/changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

// negative: POST /api/v1/workforce/groups/{id}/schedules/build, POST /api/v1/workforce/schedules/{id}/publish, POST /api/v1/workforce/swaps/{id}/decide, POST /api/v1/workforce/offers/{id}/send
#[test]
fn planner_routes_forbid_staff() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let staff = seed_user(app.db(), "wfm-staff").await;
        let id = Uuid::now_v7();
        for (path, body) in [
            (
                format!("/api/v1/workforce/groups/{id}/schedules/build"),
                json!({ "start": "2026-11-08", "days": 7 }),
            ),
            (
                format!("/api/v1/workforce/schedules/{id}/publish"),
                json!({}),
            ),
            (
                format!("/api/v1/workforce/swaps/{id}/decide"),
                json!({ "decision": "approve" }),
            ),
            (format!("/api/v1/workforce/offers/{id}/send"), json!({})),
        ] {
            let (status, answer) = app
                .request_as(&staff.cookie, Method::POST, &path, Some(body))
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
        }
    });
}
