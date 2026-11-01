//! L3-T6: the accountability coverage lists a domain nobody owns, and the
//! domain's scorecard and the audit evidence answer.

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

// feature: L3
#[test]
fn coverage_lists_unowned_domain() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("Unowned {}", Uuid::now_v7().simple());
        let unowned: Uuid = sqlx::query_scalar(
            "INSERT INTO data_domain (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
        )
        .bind(&name)
        .fetch_one(app.db())
        .await
        .unwrap();
        let owned_name = format!("Owned {}", Uuid::now_v7().simple());
        let owned: Uuid = sqlx::query_scalar(
            "INSERT INTO data_domain (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
        )
        .bind(&owned_name)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO governance_role (domain_ref, user_id, role) VALUES ($1, $2, 'owner')",
        )
        .bind(owned)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();

        let (code, coverage) = app
            .request(Method::GET, "/api/v1/admin/governance/coverage", None)
            .await;
        assert_eq!(code, StatusCode::OK, "{coverage}");
        let unowned_ids: Vec<&str> = coverage["domains_without_owner"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|d| d["id"].as_str())
            .collect();
        assert!(
            unowned_ids.contains(&unowned.to_string().as_str()),
            "{coverage}"
        );
        assert!(
            !unowned_ids.contains(&owned.to_string().as_str()),
            "{coverage}"
        );

        let (code, card) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/governance/domains/{owned}/scorecard"),
                None,
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{card}");
        assert_eq!(card["domain"]["name"], json!(owned_name));
        assert_eq!(card["policies"], 0);
        let (code, _) = app
            .request(
                Method::GET,
                &format!(
                    "/api/v1/admin/governance/domains/{}/scorecard",
                    Uuid::now_v7()
                ),
                None,
            )
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND);

        let (code, evidence) = app
            .request(Method::GET, "/api/v1/admin/governance/evidence", None)
            .await;
        assert_eq!(code, StatusCode::OK, "{evidence}");
        assert!(
            evidence["roles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["domain_id"] == json!(owned) && r["role"] == "owner"),
            "{evidence}"
        );
    });
}
