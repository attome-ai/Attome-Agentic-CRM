//! W1-T12: an imported contract's text yields a proposal a person accepts;
//! the accepted proposal makes the contract and its obligations.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
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

const TEXT: &str = "Maintenance Agreement\n\
    This agreement is made between Attome Trading Co. and Desert Lifts LLC, (the Contractor).\n\
    It is effective from 2027-03-01 and shall expire on 2028-02-29.\n\
    The total value is SAR 240,000.\n\
    The Contractor shall inspect every lift each month.";

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

// feature: W1
#[test]
fn accept_creates_contract_from_reviewed_json() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        // What the upload pipeline leaves: the import's file and its text.
        let key = format!("contract_import/{}/file/old-lifts.pdf", Uuid::now_v7());
        let import: Uuid = sqlx::query_scalar(
            "INSERT INTO contract_import (file, status, is_active, row_version) \
             VALUES ($1, 'queued', true, 0) RETURNING id",
        )
        .bind(&key)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO document_text (file_key, format, content_text) VALUES ($1, 'pdf', $2)",
        )
        .bind(&key)
        .bind(TEXT)
        .execute(app.db())
        .await
        .unwrap();

        let proposal = attome_contract::import::propose_import(&app.state, &admin, import)
            .await
            .unwrap();
        assert_eq!(
            proposal["fields"]["counterparty"]["value"],
            "Desert Lifts LLC"
        );
        assert_eq!(proposal["fields"]["contract_value"]["value"], 240_000.0);

        // A person corrects the proposal and accepts it.
        let body: attome_contract::import::ImportAcceptBody = serde_json::from_value(json!({
            "contract": {
                "title": "Lift maintenance 2027",
                "counterparty": "Desert Lifts LLC",
                "contract_value": 240000,
                "currency": "SAR",
                "status": "active"
            },
            "obligations": [
                { "title": "Inspect every lift each month", "owed_by": "counterparty", "due_date": "2027-01-31" }
            ]
        }))
        .unwrap();
        let accepted = attome_contract::import::accept_import(&app.state, &admin, import, &body)
            .await
            .unwrap();
        assert_eq!(accepted.obligations, 1);
        let (title, status): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT title, status::text FROM contract WHERE id = $1")
                .bind(accepted.contract_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(title.as_deref(), Some("Lift maintenance 2027"));
        assert_eq!(
            status.as_deref(),
            Some("draft"),
            "status is not taken from the body"
        );
        let obligations: i64 =
            sqlx::query_scalar("SELECT count(*) FROM obligation WHERE contract_ref = $1")
                .bind(accepted.contract_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(obligations, 1);
        let (import_status, contract_id): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT status::text, contract_id FROM contract_import WHERE id = $1")
                .bind(import)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(import_status.as_deref(), Some("accepted"));
        assert_eq!(contract_id, Some(accepted.contract_id.to_string()));

        // A second accept makes no second contract.
        assert!(
            attome_contract::import::accept_import(&app.state, &admin, import, &body)
                .await
                .is_err()
        );
    });
}
