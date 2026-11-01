//! E6-T9: with the sunset policy switched off, nobody is invited back or
//! sunset. A binary of its own: no test here switches the policy on.

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
    for pack in ["crm", "marketing"] {
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
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

async fn create(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}: {created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

// feature: E6
#[test]
fn skipped_when_disabled() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        create(
            &app,
            "marketing_deliverability_policy",
            json!({ "name": "Off", "sunset_enabled": false, "sunset_months": 6,
                    "reengagement_purpose": "newsletter" }),
        )
        .await;
        let person = create(
            &app,
            "contact",
            json!({ "full_name": "Quiet Reader", "email": "quiet@example.com" }),
        )
        .await;
        sqlx::query(
            "UPDATE contact SET created_at = now() - interval '2 years', \
                    reengagement_sent_at = now() - interval '30 days' WHERE id = $1",
        )
        .bind(person)
        .execute(app.db())
        .await
        .unwrap();
        let run = attome_marketing::sunset::run(&app.state).await.unwrap();
        assert!(!run.ran);
        assert_eq!((run.invited, run.sunset), (0, 0));
        let sunset: bool =
            sqlx::query_scalar("SELECT marketing_sunset_at IS NOT NULL FROM contact WHERE id = $1")
                .bind(person)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert!(!sunset, "the policy is off");
    });
}
