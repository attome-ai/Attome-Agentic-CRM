//! AB5-T11: one test per fallback, each switching its dependency off the
//! way the capability poller would (`CapabilityRegistry::record` with
//! failed probes, past the failure threshold), never by stopping a
//! container. Each test has an app of its own, so a capability forced down
//! here is never seen by another test.
//!
//! - The AI model down: a record still saves.
//! - The object store down: an upload is refused with 503 up front
//!   (AB5-T4's owner ruling: refuse clearly, no holding on local disk).
//! - The search index down: search answers from the tables, marked limited.
//! - The batch worker down: a bulk operation is refused with 503, and the
//!   system status names bulk and imports as degraded.
//! - The cache down: a revoked session is still refused (security fails
//!   closed, whatever the cache capability says).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::CapabilityState;
use attome_server::capability::{Capability, ProbeOutcome};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine;
use serde_json::{Value, json};
use uuid::Uuid;

/// An app of its own with the CRM pack (accounts) installed.
async fn app() -> Option<TestApp> {
    let app = TestApp::start_with(|_| {}).await?;
    app.install_packs(&["crm"]).await;
    Some(app)
}

/// Records failed probes until `capability` is confirmed down, as the
/// poller would after consecutive failures.
fn switch_off(app: &TestApp, capability: Capability) {
    let registry = &app.state.base.capabilities;
    registry.set_enforced(true);
    for _ in 0..5 {
        registry.record(capability, ProbeOutcome::Unreachable);
    }
    assert_eq!(
        registry.state(capability),
        CapabilityState::Unavailable,
        "{capability:?} is forced down"
    );
}

fn unique(label: &str) -> String {
    format!("{label}-{}", Uuid::now_v7().simple())
}

// feature: AB5
// op: POST /api/v1/{entity}
#[test]
fn record_save_works_with_ai_down() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        switch_off(&app, Capability::AiModel);
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/account",
                Some(json!({ "name": unique("ai-down") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    });
}

// feature: AB5
// negative: POST /api/v1/{entity}/{id}/files/{field}/upload-session
#[test]
fn upload_refused_with_store_down() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let (status, account) = app
            .request(
                Method::POST,
                "/api/v1/account",
                Some(json!({ "name": unique("store-down") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{account}");
        let id = account["id"].as_str().expect("the account's id").to_owned();
        let path = format!("/api/v1/account/{id}/files/logo/upload-session");
        let body = json!({
            "filename": "logo.png",
            "content_type": "image/png",
            "declared_size_bytes": 10,
        });

        let (before, answer) = app.request(Method::POST, &path, Some(body.clone())).await;
        assert_ne!(
            before,
            StatusCode::SERVICE_UNAVAILABLE,
            "the store is up: {answer}"
        );

        switch_off(&app, Capability::ObjectStorage);
        let (status, answer) = app.request(Method::POST, &path, Some(body)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    });
}

// feature: AB5
// op: GET /api/v1/search
#[test]
fn search_limited_with_index_down() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let token = unique("idxdown");
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/account",
                Some(json!({ "name": format!("{token} Trading") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        switch_off(&app, Capability::SearchIndex);
        let (status, body) = app
            .request(Method::GET, &format!("/api/v1/search?q={token}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["route"], "fallback", "{body}");
        assert_eq!(body["limited"], true, "{body}");
        assert!(
            body["degraded"]
                .as_array()
                .is_some_and(|d| d.iter().any(|v| v == "search_index")),
            "{body}"
        );
    });
}

// feature: AB5
// negative: POST /api/v1/{entity}/bulk
// op: GET /api/v1/system/status
#[test]
fn jobs_delayed_status_when_worker_down() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let (status, before) = app
            .request(Method::GET, "/api/v1/system/status", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{before}");
        let degraded = |body: &Value| -> Vec<String> {
            body["degraded"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|d| d["feature"].as_str().map(str::to_owned))
                .collect()
        };
        assert!(!degraded(&before).contains(&"bulk".to_owned()), "{before}");

        switch_off(&app, Capability::BatchJobs);
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/account/bulk",
                Some(json!({
                    "operation": "create",
                    "records": [ { "data": { "name": unique("bulk-down") } } ],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");

        let (status, after) = app
            .request(Method::GET, "/api/v1/system/status", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{after}");
        let features = degraded(&after);
        assert!(features.contains(&"bulk".to_owned()), "{after}");
        assert!(features.contains(&"imports".to_owned()), "{after}");
    });
}

/// The `jti` of a session cookie (`name=<jwt>`), read from the token's
/// payload.
fn jti_of(cookie: &str) -> Uuid {
    let token = cookie.split_once('=').expect("name=token").1;
    let payload = token.split('.').nth(1).expect("a JWT has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("the payload is base64url");
    let claims: Value = serde_json::from_slice(&bytes).expect("the payload is JSON");
    claims["jti"].as_str().unwrap().parse().unwrap()
}

// feature: AB5
// negative: GET /api/v1/system/status
#[test]
fn security_fails_closed_with_cache_down() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let user = attome_testapp::seed_user(app.db(), "cache-down").await;
        let (status, body) = app
            .request_as(&user.cookie, Method::GET, "/api/v1/system/status", None)
            .await;
        assert_eq!(status, StatusCode::OK, "the session works: {body}");

        let base = &app.state.base;
        attome_auth::revocation::revoke(
            attome_auth::revocation::RevocationStore::choose(&base.redis_coordination, &base.db),
            jti_of(&user.cookie),
            3600,
        )
        .await
        .expect("revoke the session");

        switch_off(&app, Capability::Cache);
        let (status, body) = app
            .request_as(&user.cookie, Method::GET, "/api/v1/system/status", None)
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a revoked session stays refused with the cache down: {body}"
        );
    });
}
