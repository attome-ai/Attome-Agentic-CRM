//! K6-T10: a knowledge manager (the role template) manages crawl sources:
//! changes their settings under the row version, reads their runs and the
//! changes waiting for review, and cannot open an intranet host; a user
//! without the role reads nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// Sends `body` as `user` with `if_match`.
async fn patch_as(
    app: &TestApp,
    user: &TestUser,
    path: &str,
    if_match: &str,
    body: Value,
) -> (StatusCode, Value) {
    app.request_public(
        Method::PATCH,
        path,
        &[
            ("cookie", user.cookie.as_str()),
            ("origin", "http://localhost:4200"),
            ("sec-fetch-site", "same-origin"),
            ("content-type", "application/json"),
            ("if-match", if_match),
        ],
        body.to_string().into_bytes(),
    )
    .await
}

async fn knowledge_manager(app: &TestApp) -> TestUser {
    let (code, installed) = app
        .request(
            Method::POST,
            "/api/v1/admin/security/role-templates/knowledge_manager/install",
            Some(json!({ "name": format!("Knowledge manager {}", Uuid::now_v7()) })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{installed}");
    let role: Uuid = installed["role_id"].as_str().unwrap().parse().unwrap();
    let user = attome_testapp::seed_user(app.db(), "knowledge-manager").await;
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .expect("grant role");
    user
}

// feature: K6
#[test]
fn knowledge_manager_can_patch_target() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for name in ["attome-webcrawl", "attome-webcrawl-item-versions"] {
            attome_api::changeset::boot::apply_platform_definition(&app.state, name)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let registry = attome_core::build_registry(&app.state.base.db)
            .await
            .expect("build the metadata registry");
        app.state.entities.swap(registry);
        let target: Uuid = sqlx::query_scalar(
            "INSERT INTO webcrawl_target (url, created_by) VALUES ($1, $2) RETURNING id",
        )
        .bind(format!("https://docs-{}.example.test/", Uuid::now_v7()))
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        let manager = knowledge_manager(&app).await;
        let path = format!("/api/v1/webcrawl/targets/{target}");

        let (code, body) = patch_as(
            &app,
            &manager,
            &path,
            "\"0\"",
            json!({ "schedule": "weekly" }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["schedule"], "weekly");
        assert_eq!(body["row_version"], 1);

        // The version moved on: the same If-Match is stale.
        let (code, body) = patch_as(
            &app,
            &manager,
            &path,
            "\"0\"",
            json!({ "schedule": "daily" }),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT, "{body}");
        // An intranet host is an administrator's call.
        let (code, _) = patch_as(
            &app,
            &manager,
            &path,
            "\"1\"",
            json!({ "allow_host": "intranet.local" }),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        let (code, _) = patch_as(&app, &manager, &path, "1", json!({ "schedule": "hourly" })).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);

        for tail in ["runs", "changes"] {
            let (code, body) = app
                .request_as(
                    &manager.cookie,
                    Method::GET,
                    &format!("{path}/{tail}"),
                    None,
                )
                .await;
            assert_eq!(code, StatusCode::OK, "{tail}: {body}");
            assert_eq!(body["total"], 0, "{tail}: {body}");
        }

        let stranger = attome_testapp::seed_user(app.db(), "no-knowledge").await;
        let (code, _) = app
            .request_as(
                &stranger.cookie,
                Method::GET,
                "/api/v1/webcrawl/targets",
                None,
            )
            .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        let (code, _) = patch_as(
            &app,
            &stranger,
            &path,
            "\"1\"",
            json!({ "schedule": "daily" }),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
    });
}
