//! AH7-T3: activating an agent definition runs its permission test in the
//! save. An agent whose policy passes activates; one whose policy cannot be
//! judged (no session could start under it either) is refused with a 422.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

async fn model(app: &TestApp) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_model (id, name, created_at) VALUES ($1, 'activation model', NOW())",
    )
    .bind(id)
    .execute(app.db())
    .await
    .unwrap();
    id
}

/// A narrow policy; without `limits` it names no session limits, so no
/// session could start under it and its test cannot run.
async fn policy(app: &TestApp, limits: bool) -> Uuid {
    let id = Uuid::now_v7();
    let limit = limits.then_some(100_i32);
    sqlx::query(
        "INSERT INTO ai_agent_policy \
            (id, name, risk_ceiling, max_invocations_per_session, max_writes_per_day, \
             max_tokens_per_session, max_session_duration_minutes, created_at) \
         VALUES ($1, 'activation policy', 'read', $2, $2, 20000, 60, NOW())",
    )
    .bind(id)
    .bind(limit)
    .execute(app.db())
    .await
    .unwrap();
    id
}

// feature: AH7
#[test]
fn activation_runs_the_permission_test() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let model = model(&app).await;
        let narrow = policy(&app, true).await;
        let broken = policy(&app, false).await;
        let agent = |status: &str, policy: Uuid| {
            json!({
                "name": "Activation agent",
                "status": status,
                "primary_model_ref": model,
                "system_instructions": "Answer briefly.",
                "policy_ref": policy,
            })
        };

        // A policy the test passes: the agent activates.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/ai_agent",
                Some(agent("active", narrow)),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");

        // A policy that cannot be judged: activation is refused, a draft is not.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/ai_agent",
                Some(agent("active", broken)),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.to_string().contains("max_invocations_per_session"),
            "{body}"
        );
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/ai_agent",
                Some(agent("draft", broken)),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let draft = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
        let row_version = body["row_version"].as_i64().unwrap_or(1).to_string();

        // Activating the draft later runs the test too.
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/ai_agent/{draft}"),
                &[("if-match", &format!("\"{row_version}\""))],
                Some(json!({ "status": "active" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}
