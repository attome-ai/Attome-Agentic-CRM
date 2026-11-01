//! W1-T12: `contract.answer` grounds its answers only in clauses the caller
//! may read: a confidential contract's clauses never reach a viewer's
//! evidence, so they are never shown to a model or cited.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

use attome_testapp::{TestApp, TestUser};
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

/// A contract with one liability clause.
async fn contract(app: &TestApp, title: &str, confidential: bool, cap: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO contract (id, title, is_confidential, is_active, row_version) \
         VALUES ($1, $2, $3, true, 0)",
    )
    .bind(id)
    .bind(title)
    .bind(confidential)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO contract_clause (id, contract_ref, title, body_html, position, is_active, \
             row_version) \
         VALUES ($1, $2, 'Limitation of liability', $3, 1, true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .bind(format!("<p>The liability cap is {cap}.</p>"))
    .execute(app.db())
    .await
    .unwrap();
    id
}

async fn evidence_for(
    app: &TestApp,
    user: Uuid,
) -> Vec<attome_ai::actions::contract::ClauseEvidence> {
    let security = attome_security::resolve_uncached(&app.state.base.db, user)
        .await
        .unwrap();
    let ctx = attome_ai::context::ActionContext::user(Arc::new(security));
    attome_ai::actions::contract::clause_evidence(
        &app.state,
        &ctx,
        "What is the liability cap?",
        None,
    )
    .await
    .unwrap()
}

// feature: W1
#[test]
fn answer_excludes_confidential_contract_for_viewer() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let open = contract(&app, "Open supply", false, "twelve months of fees").await;
        let secret = contract(&app, "Secret merger", true, "unlimited").await;
        let viewer = user_with_role(&app, "answer-viewer", "Contract Viewer").await;
        let legal = user_with_role(&app, "answer-legal", "Legal").await;

        let seen = evidence_for(&app, viewer.id).await;
        assert!(
            seen.iter().any(|e| e.contract_id == open),
            "the viewer's evidence holds the open contract: {seen:?}"
        );
        assert!(
            seen.iter()
                .all(|e| e.contract_id != secret && !e.passage.contains("unlimited")),
            "a confidential contract is never evidence for a viewer: {seen:?}"
        );

        let seen = evidence_for(&app, legal.id).await;
        assert!(
            seen.iter().any(|e| e.contract_id == secret),
            "legal reads confidential contracts: {seen:?}"
        );
    });
}
