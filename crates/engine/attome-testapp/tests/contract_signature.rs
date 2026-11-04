//! W1-T10: an approved contract goes out for signature through a K4
//! envelope; when the envelope completes the signed file becomes a `signed`
//! version and the contract becomes active. Only an approved contract is
//! sent.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
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

/// A contract in `status`, with a drafted version holding a file, stored
/// when `store` (the object store is needed only to send).
async fn contract(app: &TestApp, status: &str, store: bool) -> Uuid {
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/contract",
            Some(json!({ "title": "Maintenance", "counterparty": "Gulf Services Co", "contract_value": 50000 })),
        )
        .await;
    assert!(code.is_success(), "{code} {body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    // Test setup on a throwaway database: the approval itself is W1-T9's.
    sqlx::query("UPDATE contract SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(app.db())
        .await
        .unwrap();
    let version = Uuid::now_v7();
    let key = format!(
        "contract_version/{version}/file/{}-draft.pdf",
        Uuid::now_v7()
    );
    if store {
        app.state
            .base
            .storage
            .store()
            .put(
                &ObjectPath::parse(&key).unwrap(),
                b"%PDF-1.4 the agreed contract".to_vec().into(),
            )
            .await
            .expect("store the drafted file");
    }
    sqlx::query(
        "INSERT INTO contract_version \
           (id, contract_id, source, version_no, file, created_by_ref, created_by, owner_ref) \
         VALUES ($1, $2, 'draft', 1, $3, $4, $4, $4)",
    )
    .bind(version)
    .bind(id.to_string())
    .bind(&key)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .unwrap();
    id
}

// feature: W1
#[test]
fn completion_activates_contract() {
    attome_testkit::run_shared(async {
        if attome_testkit::s3_or_skip().is_none() {
            return;
        }
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let id = contract(&app, "approved", true).await;
        let (code, sent) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/contracts/{id}/send-for-signature"),
                Some(json!({
                    "signers": [{ "name": "Counterparty", "email": "signer@example.com" }]
                })),
            )
            .await;
        assert_eq!(code, StatusCode::ACCEPTED, "{sent}");
        let envelope: Uuid = sent["envelope_id"].as_str().unwrap().parse().unwrap();

        // A second send while it is out is refused.
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/contracts/{id}/send-for-signature"),
                Some(json!({
                    "signers": [{ "name": "Counterparty", "email": "signer@example.com" }]
                })),
            )
            .await;
        assert_eq!(code, StatusCode::CONFLICT, "{body}");

        // Nothing happens until everyone has signed.
        assert_eq!(
            attome_contract::signature::tick(&app.state).await.unwrap(),
            0
        );
        sqlx::query(
            "UPDATE esign_envelope SET status = 'completed', completed_at = now() WHERE id = $1",
        )
        .bind(envelope)
        .execute(app.db())
        .await
        .unwrap();
        assert_eq!(
            attome_contract::signature::tick(&app.state).await.unwrap(),
            1
        );

        let status: Option<String> =
            sqlx::query_scalar("SELECT status::text FROM contract WHERE id = $1")
                .bind(id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("active"));
        let signed: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT file FROM contract_version WHERE contract_id = $1 AND source = 'signed'",
        )
        .bind(id.to_string())
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(signed.len(), 1, "one signed version");
        assert!(signed[0].is_some(), "the signed version holds the file");
        // The signing is finished; a later tick does nothing.
        assert_eq!(
            attome_contract::signature::tick(&app.state).await.unwrap(),
            0
        );
    });
}

// feature: W1
#[test]
fn send_from_draft_is_409() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let id = contract(&app, "draft", false).await;
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/contracts/{id}/send-for-signature"),
                Some(json!({
                    "signers": [{ "name": "Counterparty", "email": "signer@example.com" }]
                })),
            )
            .await;
        assert_eq!(code, StatusCode::CONFLICT, "{body}");
    });
}
