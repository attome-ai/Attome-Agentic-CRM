//! AH3-T4: agent principals through `/api/v1/admin/agents`: made with their
//! sponsor, moved through their lifecycle under `If-Match`, given a key
//! whose secret is shown once, and never `system.admin`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;

// feature: AH3
#[test]
fn an_agent_is_made_moved_keyed_and_kept_from_admin() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, agent) = app
            .request(
                Method::POST,
                "/api/v1/admin/agents",
                Some(json!({ "name": "Collections agent", "entity_scope": ["account"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{agent}");
        assert_eq!(agent["lifecycle_state"], "active");
        assert_eq!(agent["entity_scope"], json!(["account"]));
        let id = agent["id"].as_str().unwrap().to_owned();
        let version = agent["row_version"].as_i64().unwrap();
        let kind: i16 =
            sqlx::query_scalar("SELECT principal_kind FROM user_account WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(kind, 2);

        // A key: the secret in this answer only.
        let (status, key) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/agents/{id}/keys"),
                Some(json!({ "name": "collections" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{key}");
        assert!(key["secret"].as_str().unwrap().starts_with("atk_sec_"));
        let (_, shown) = app
            .request(Method::GET, &format!("/api/v1/admin/agents/{id}"), None)
            .await;
        assert!(!shown.to_string().contains("atk_sec_"), "{shown}");

        // Lifecycle under If-Match: a stale version is refused.
        let (status, _) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/admin/agents/{id}/pause"),
                &[("if-match", "\"999\"")],
                Some(json!({ "reason": "review" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let current = format!("\"{version}\"");
        let (status, paused) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/admin/agents/{id}/pause"),
                &[("if-match", current.as_str())],
                Some(json!({ "reason": "review" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{paused}");
        assert_eq!(paused["lifecycle_state"], "paused");
        assert_eq!(paused["state_reason"], "review");
        // A paused agent gets no key.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/agents/{id}/keys"),
                Some(json!({ "name": "another" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Never system.admin, directly.
        let email: String =
            sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(app.db())
                .await
                .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/grants",
                Some(json!({ "user_email": email, "privilege_key": "system.admin" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // Revoked: final, and its keys end.
        let next = format!("\"{}\"", paused["row_version"].as_i64().unwrap());
        let (status, revoked) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/admin/agents/{id}/revoke"),
                &[("if-match", next.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        assert_eq!(revoked["lifecycle_state"], "revoked");
        let live_keys: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM api_key WHERE user_ref = $1::uuid AND is_active",
        )
        .bind(&id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(live_keys, 0);
    });
}
