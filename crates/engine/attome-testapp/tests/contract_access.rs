//! W1-T14: contract roles. A confidential contract is read by Legal only, a
//! requester sees only the contracts they own, value and terms are masked
//! outside the Contract terms profile, and a contract under a legal hold
//! cannot be deleted.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 6] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
];

async fn install(app: &TestApp) {
    for pack in PACKS {
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

async fn user_with_role(app: &TestApp, label: &str, role: &str) -> TestUser {
    let user = attome_testapp::seed_user(app.db(), label).await;
    let role: Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(role)
            .fetch_one(app.db())
            .await
            .unwrap_or_else(|e| panic!("role {role}: {e}"));
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .expect("grant role");
    user
}

/// A contract owned by `owner`, with a value the profile guards.
async fn contract(app: &TestApp, title: &str, confidential: bool, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO contract (id, title, contract_value, current_terms, is_confidential, owner_ref, \
             is_active, row_version) \
         VALUES ($1, $2, 987654, 'net 30 secret terms', $3, $4, true, 0)",
    )
    .bind(id)
    .bind(title)
    .bind(confidential)
    .bind(owner)
    .execute(app.db())
    .await
    .unwrap();
    id
}

async fn get(app: &TestApp, user: &TestUser, id: Uuid) -> (StatusCode, Value) {
    app.request_as(
        &user.cookie,
        Method::GET,
        &format!("/api/v1/contract/{id}"),
        None,
    )
    .await
}

// feature: W1
#[test]
fn viewer_cannot_read_confidential() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let open = contract(&app, "Open supply", false, None).await;
        let secret = contract(&app, "Secret merger", true, None).await;
        let viewer = user_with_role(&app, "viewer", "Contract Viewer").await;
        let manager = user_with_role(&app, "manager", "Contract Manager").await;
        let legal = user_with_role(&app, "legal", "Legal").await;

        let (status, body) = get(&app, &viewer, open).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !body.to_string().contains("987654") && !body.to_string().contains("secret terms"),
            "value and terms are masked for a viewer: {body}"
        );
        for user in [&viewer, &manager] {
            let (status, body) = get(&app, user, secret).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        }
        let (status, body) = app
            .request_as(&viewer.cookie, Method::GET, "/api/v1/contract", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.to_string().contains(&secret.to_string()), "{body}");

        let (status, body) = get(&app, &legal, secret).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.to_string().contains("987654"),
            "legal holds the terms profile: {body}"
        );
    });
}

// feature: W1
// negative: DELETE /api/v1/{entity}/{id}
#[test]
fn held_contract_cannot_be_deleted() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let held = contract(&app, "Disputed lease", false, None).await;
        sqlx::query(
            "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
             VALUES ('contract', $1, 'matter-w1', $2)",
        )
        .bind(held)
        .bind(Uuid::now_v7())
        .execute(app.db())
        .await
        .unwrap();
        let legal = user_with_role(&app, "legal-del", "Legal").await;
        let (status, body) = app
            .request_as(
                &legal.cookie,
                Method::DELETE,
                &format!("/api/v1/contract/{held}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let active: bool = sqlx::query_scalar("SELECT is_active FROM contract WHERE id = $1")
            .bind(held)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert!(active, "the held contract is still there");
    });
}

// feature: W1
#[test]
fn requester_sees_own_only() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let requester = user_with_role(&app, "requester", "Contract Requester").await;
        let mine = contract(&app, "My NDA", false, Some(requester.id)).await;
        let theirs = contract(&app, "Someone else's NDA", false, None).await;

        let (status, body) = get(&app, &requester, mine).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = get(&app, &requester, theirs).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}
