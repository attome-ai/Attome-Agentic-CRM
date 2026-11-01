//! W1-T5: saving a contract or one of its clauses runs the playbook rules in
//! the save: a deviation is recorded on the contract, and a `block` rule
//! refuses the save with a 422.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
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

async fn rule(app: &TestApp, clause_key: Option<&str>, condition: &str, severity: &str) {
    sqlx::query(
        "INSERT INTO contract_playbook_rule \
             (clause_key, condition, severity, message, is_active, row_version) \
         VALUES ($1, $2, $3, $4, true, 0)",
    )
    .bind(clause_key)
    .bind(condition)
    .bind(severity)
    .bind(format!("Rule: {condition}"))
    .execute(app.db())
    .await
    .unwrap();
}

async fn deviations(app: &TestApp, contract: Uuid) -> Vec<Value> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT playbook_deviations FROM contract WHERE id = $1")
            .bind(contract)
            .fetch_one(app.db())
            .await
            .unwrap();
    stored
        .map(|s| serde_json::from_str::<Vec<Value>>(&s).unwrap())
        .unwrap_or_default()
}

fn id_of(body: &Value) -> Uuid {
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

// feature: W1
#[test]
fn a_deviating_contract_records_it_and_a_block_rule_refuses_the_clause() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        rule(&app, None, "contract_value > 1000000", "needs_legal").await;
        rule(
            &app,
            Some("liability"),
            "clause_title == \"Unlimited liability\"",
            "block",
        )
        .await;
        let library: Uuid = sqlx::query_scalar(
            "INSERT INTO clause (title, clause_key, is_active, row_version) \
             VALUES ('Liability', 'liability', true, 0) RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();

        // A contract over the limit: saved, with the deviation recorded.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/contract",
                Some(json!({ "title": "Big supply", "contract_value": 2500000 })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let contract = id_of(&body);
        let found = deviations(&app, contract).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0]["severity"], "needs_legal");

        // A caller cannot write the deviations themselves.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/contract",
                Some(json!({ "title": "Forged", "playbook_deviations": "[]" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // A clause the block rule matches: refused, nothing written.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/contract_clause",
                Some(json!({
                    "contract_ref": contract,
                    "clause_ref": library,
                    "title": "Unlimited liability",
                    "position": 1
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let clauses: i64 =
            sqlx::query_scalar("SELECT count(*) FROM contract_clause WHERE contract_ref = $1")
                .bind(contract)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(clauses, 0);

        // The same clause within the playbook: saved.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/contract_clause",
                Some(json!({
                    "contract_ref": contract,
                    "clause_ref": library,
                    "title": "Liability capped at fees paid",
                    "position": 1
                })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        assert_eq!(deviations(&app, contract).await.len(), 1);

        // Back under the limit: the next clause save judges the contract
        // again and clears the deviation.
        sqlx::query("UPDATE contract SET contract_value = 10 WHERE id = $1")
            .bind(contract)
            .execute(app.db())
            .await
            .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/contract_clause",
                Some(json!({
                    "contract_ref": contract,
                    "title": "Notices",
                    "position": 2
                })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        assert!(deviations(&app, contract).await.is_empty());
    });
}
