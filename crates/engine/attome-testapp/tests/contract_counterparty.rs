//! W1-T3: counterparty matching proposes an account for a contract's
//! free-text counterparty once, and confirming sets the contract's lookup.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_contract::counterparty::{self, Decision};
use attome_testapp::TestApp;
use uuid::Uuid;

async fn install(app: &TestApp, pack: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs")
        .join(pack)
        .join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

#[test]
fn arabic_variant_matches_account_and_confirm_sets_lookup() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in ["crm", "vendor-supplier", "contract-management"] {
            install(&app, pack).await;
        }
        attome_api::changeset::boot::apply_platform_definition(
            &app.state,
            "attome-contract-counterparty",
        )
        .await
        .expect("apply the counterparty bundle");

        let suffix = Uuid::now_v7().simple().to_string();
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ($1) RETURNING id")
                .bind(format!("شركة الأمل للتجارة {suffix}"))
                .fetch_one(app.db())
                .await
                .expect("insert account");
        // Hamza dropped and taa marbuta written as ha.
        let contract: Uuid = sqlx::query_scalar(
            "INSERT INTO contract (title, status, counterparty) \
             VALUES ('Counterparty test', 'draft', $1) RETURNING id",
        )
        .bind(format!("شركه الامل للتجاره {suffix}"))
        .fetch_one(app.db())
        .await
        .expect("insert contract");

        let first = counterparty::run_match(app.db()).await.expect("first run");
        assert!(first.proposals >= 1);
        let again = counterparty::run_match(app.db()).await.expect("second run");
        assert_eq!(again.proposals, 0, "a contract is proposed for once");

        let (proposal, proposed_account): (Uuid, String) = sqlx::query_as(
            "SELECT id, account_id FROM counterparty_match_proposal \
             WHERE contract_id = $1 AND status = 'proposed'",
        )
        .bind(contract.to_string())
        .fetch_one(app.db())
        .await
        .expect("the proposal");
        assert_eq!(proposed_account, account.to_string());

        let decided = counterparty::decide(&app.state, app.admin.id, proposal, Decision::Confirm)
            .await
            .expect("confirm");
        assert_eq!(decided.status, "confirmed");
        let linked: Option<Uuid> =
            sqlx::query_scalar("SELECT counterparty_account_ref FROM contract WHERE id = $1")
                .bind(contract)
                .fetch_one(app.db())
                .await
                .expect("read contract");
        assert_eq!(linked, Some(account));

        let twice =
            counterparty::decide(&app.state, app.admin.id, proposal, Decision::Dismiss).await;
        assert!(
            matches!(twice, Err(attome_types::AppError::Conflict(_))),
            "a decided proposal cannot be decided again"
        );
    });
}
