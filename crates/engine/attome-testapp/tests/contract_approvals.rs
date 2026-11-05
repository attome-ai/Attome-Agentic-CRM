//! W1-T9: submitting a contract for approval holds it in review under the
//! pack's approval plan; Legal's step runs only when the playbook check
//! marked a deviation that needs legal, and the move needs its privilege.

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

const PACKS: [&str; 6] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
];

async fn install(app: &TestApp) {
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-contract")
        .await
        .expect("apply the contract platform definition");
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
    let registry = attome_core::build_registry(&app.state.base.db)
        .await
        .expect("build the metadata registry");
    app.state.entities.swap(registry);
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

/// A draft contract; `needs_legal` gives it a value a `needs_legal`
/// playbook rule flags (every save recomputes the deviations, so they come
/// from a real rule, not a stored value).
async fn contract(app: &TestApp, needs_legal: bool) -> Uuid {
    let value = if needs_legal {
        sqlx::query(
            "INSERT INTO contract_playbook_rule                  (clause_key, condition, severity, message, is_active, row_version)              VALUES (NULL, 'contract_value > 60000', 'needs_legal', 'Non-standard value', true, 0)",
        )
        .execute(app.db())
        .await
        .unwrap();
        64000
    } else {
        50000
    };
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/contract",
            Some(json!({ "title": "Maintenance", "counterparty": "Gulf Services Co", "contract_value": value })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn skipped(app: &TestApp, contract: Uuid) -> Vec<i32> {
    sqlx::query_scalar(
        "SELECT skipped_steps FROM approval_request \
          WHERE regarding_entity = 'contract' AND regarding_id = $1 \
          ORDER BY requested_at DESC, id DESC LIMIT 1",
    )
    .bind(contract)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: W1
#[test]
fn deviation_adds_legal_approver() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let flagged = contract(&app, true).await;
        let plain = contract(&app, false).await;
        for id in [flagged, plain] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/contract/{id}/transition"),
                    Some(json!({ "to_state": "approved" })),
                )
                .await;
            assert!(status.is_success(), "{status} {body}");
        }
        // Steps: 0 manager, 1 legal for a deviation, 2 legal above 1,000,000.
        assert_eq!(skipped(&app, flagged).await, vec![2], "legal must approve");
        assert_eq!(skipped(&app, plain).await, vec![1, 2]);
        let held: Option<String> =
            sqlx::query_scalar("SELECT status::text FROM contract WHERE id = $1")
                .bind(flagged)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(held.as_deref(), Some("review"), "held while it waits");
    });
}

// feature: W1
#[test]
fn transition_without_privilege_is_403() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let id = contract(&app, false).await;
        let viewer = user_with_role(&app, "contract-viewer", "Contract Viewer").await;
        let (status, body) = app
            .request_as(
                &viewer.cookie,
                Method::POST,
                &format!("/api/v1/contract/{id}/transition"),
                Some(json!({ "to_state": "approved" })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    });
}
