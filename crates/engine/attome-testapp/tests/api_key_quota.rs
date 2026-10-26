//! S10-T1: per-key quotas. An admin sets a key's own per-minute budget
//! (`PUT /api/v1/admin/api-keys/{id}/quota`, audited); the rate limiter then
//! refuses the key's request past it with `429`, whatever the route, while
//! the deployment's per-category limits stay untouched. The key is written
//! straight to the throwaway database with the deployment's pepper, the
//! hash `POST /api/v1/auth/api-keys` writes (minting over HTTP needs a
//! stepped-up session, beside the point here).

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

/// A fresh key for the administrator: (id, `Authorization` header value).
async fn mint_key(app: &TestApp) -> (Uuid, String) {
    let public_key = format!("atk_pub_quota{}", Uuid::now_v7().simple());
    let secret = format!("atk_sec_quota{}", Uuid::now_v7().simple());
    let secret_hash = app.state.base.pepper_ring().hash(&secret);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(app.admin.id)
    .bind(format!("quota-{}", Uuid::now_v7()))
    .bind(&public_key)
    .bind(&secret_hash)
    .fetch_one(app.db())
    .await
    .expect("insert the key");
    (id, format!("ApiKey {public_key}:{secret}"))
}

async fn call_with_key(app: &TestApp, authorization: &str) -> StatusCode {
    app.request_public(
        Method::GET,
        "/api/v1/admin/api-usage/summary",
        &[("authorization", authorization)],
        Vec::new(),
    )
    .await
    .0
}

#[test]
fn a_key_past_its_quota_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (id, authorization) = mint_key(&app).await;

        // No quota yet: only the deployment's limits apply.
        for _ in 0..3 {
            assert_eq!(call_with_key(&app, &authorization).await, StatusCode::OK);
        }

        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/api-keys/{id}/quota"),
                Some(json!({ "requests_per_minute": 2 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["requests_per_minute"], 2);

        assert_eq!(call_with_key(&app, &authorization).await, StatusCode::OK);
        assert_eq!(call_with_key(&app, &authorization).await, StatusCode::OK);
        assert_eq!(
            call_with_key(&app, &authorization).await,
            StatusCode::TOO_MANY_REQUESTS
        );

        // The change is audited with the change.
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_ingest           WHERE payload->>'category' = 'Configuration' AND payload->>'record_id' = $1",
        )
        .bind(id.to_string())
        .fetch_one(app.db())
        .await
        .expect("count audit rows");
        assert!(audited >= 1, "the quota change has an audit row");

        // Cleared, the key is back under the deployment's limits only.
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/api-keys/{id}/quota"),
                Some(json!({ "requests_per_minute": null })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(call_with_key(&app, &authorization).await, StatusCode::OK);
    });
}

// negative: PUT /api/v1/admin/api-keys/{id}/quota
#[test]
fn admins_list_keys_and_bad_quotas_are_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (id, _) = mint_key(&app).await;

        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/api-keys/{id}/quota"),
                Some(json!({ "requests_per_minute": 0 })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let (status, _) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/api-keys/{}/quota", Uuid::now_v7()),
                Some(json!({ "requests_per_minute": 10 })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, body) = app
            .request(Method::GET, "/api/v1/admin/api-keys?page_size=200", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let row = body["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|k| k["id"] == id.to_string())
            .expect("the new key is listed");
        assert_eq!(row["owner_id"], app.admin.id.to_string());
        assert!(row.get("secret_hash").is_none(), "no hash on the wire");

        // A user without system.admin sees none of it.
        let user = attome_testapp::seed_user(app.db(), "quota-reader").await;
        let (status, _) = app
            .request_as(&user.cookie, Method::GET, "/api/v1/admin/api-keys", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}
