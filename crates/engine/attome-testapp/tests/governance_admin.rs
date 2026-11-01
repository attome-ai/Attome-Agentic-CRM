//! L3-T9: a domain's steward edits only their own domain's policies. The
//! steward of another domain cannot create, edit or delete a policy there
//! (it is not even shown to them), and someone holding a lesser role in the
//! domain reads the policy but cannot change it.

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

async fn domain(app: &TestApp, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO data_domain (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
    )
    .bind(format!("{name} {}", Uuid::now_v7().simple()))
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn hold(app: &TestApp, domain: Uuid, user: Uuid, role: &str) {
    sqlx::query("INSERT INTO governance_role (domain_ref, user_id, role) VALUES ($1, $2, $3)")
        .bind(domain)
        .bind(user)
        .bind(role)
        .execute(app.db())
        .await
        .unwrap();
}

async fn policy_state(app: &TestApp, policy: Uuid) -> (String, i64) {
    sqlx::query_as("SELECT name_en, version::bigint FROM governance_policy WHERE id = $1")
        .bind(policy)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: L3
#[test]
fn steward_of_other_domain_cannot_edit_policy() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (mine, theirs) = (
            domain(&app, "Sales data").await,
            domain(&app, "HR data").await,
        );
        let steward = seed_user(app.db(), "l3-steward").await;
        let consumer = seed_user(app.db(), "l3-consumer").await;
        hold(&app, mine, steward.id, "steward").await;
        hold(&app, theirs, consumer.id, "consumer").await;

        let (code, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/governance/policies",
                Some(json!({ "domain_ref": theirs, "name_en": "Salary retention", "body_en": "Keep 7 years." })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{created}");
        let policy: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let row_version = created["row_version"].clone();
        let path = format!("/api/v1/admin/governance/policies/{policy}");
        let before = policy_state(&app, policy).await;

        // The steward of another domain: the policy is not theirs to see.
        let (code, body) = app
            .request_as(
                &steward.cookie,
                Method::PATCH,
                &path,
                Some(json!({ "row_version": row_version, "name_en": "Taken over" })),
            )
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{body}");
        let (code, body) = app
            .request_as(
                &steward.cookie,
                Method::DELETE,
                &format!("{path}?row_version={row_version}"),
                None,
            )
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{body}");
        let (code, body) = app
            .request_as(
                &steward.cookie,
                Method::POST,
                "/api/v1/admin/governance/policies",
                Some(json!({ "domain_ref": theirs, "name_en": "Planted", "body_en": "x" })),
            )
            .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{body}");

        // A consumer in the domain reads it but may not change it.
        let (code, body) = app
            .request_as(&consumer.cookie, Method::GET, &path, None)
            .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        let (code, body) = app
            .request_as(
                &consumer.cookie,
                Method::PATCH,
                &path,
                Some(json!({ "row_version": row_version, "name_en": "Changed" })),
            )
            .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{body}");

        assert_eq!(policy_state(&app, policy).await, before, "nothing changed");
        let planted: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM governance_policy WHERE domain_ref = $1 AND name_en = 'Planted'",
        )
        .bind(theirs)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(planted, 0);

        // In their own domain the steward writes policies.
        let (code, body) = app
            .request_as(
                &steward.cookie,
                Method::POST,
                "/api/v1/admin/governance/policies",
                Some(json!({ "domain_ref": mine, "name_en": "Deal retention", "body_en": "Keep 5 years." })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{body}");
    });
}
