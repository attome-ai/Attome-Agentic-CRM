//! W1-T16: a contract's whole life through the engine: requested, drafted,
//! negotiated with the counterparty (their version compared with ours),
//! approved by a contract manager and Legal for a playbook deviation, signed,
//! active, and the nightly key-date run opens its renewal task.
//!
//! Two steps stand in for machinery a test database does not run: the draft
//! version's file is stored directly (docgen's renderer is W1-T6's own test),
//! and the scanner's verdict and the extracted text are written as the scan
//! and text jobs would.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use base64::Engine as _;
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

/// Stores `bytes` at `key` with its text, as the upload and text jobs would.
async fn store(app: &TestApp, key: &str, bytes: &[u8], text: &str) {
    app.state
        .base
        .storage
        .store()
        .put(&ObjectPath::parse(key).unwrap(), bytes.to_vec().into())
        .await
        .expect("store the file");
    sqlx::query(
        "INSERT INTO document_text (file_key, format, content_text) VALUES ($1, 'pdf', $2) \
         ON CONFLICT (file_key) DO UPDATE SET content_text = EXCLUDED.content_text",
    )
    .bind(key)
    .bind(text)
    .execute(app.db())
    .await
    .unwrap();
}

async fn status(app: &TestApp, contract: Uuid) -> String {
    sqlx::query_scalar("SELECT status::text FROM contract WHERE id = $1")
        .bind(contract)
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// Approves the contract's pending approval as `user`.
async fn approve(app: &TestApp, user: &TestUser, contract: Uuid) {
    let (id, row_version): (Uuid, i64) = sqlx::query_as(
        "SELECT id, row_version FROM approval_request \
          WHERE regarding_entity = 'contract' AND regarding_id = $1 AND status = 'pending' \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(contract)
    .fetch_one(app.db())
    .await
    .unwrap();
    let (code, body) = app
        .request_as(
            &user.cookie,
            Method::POST,
            &format!("/api/v1/approvals/{id}/decide"),
            Some(json!({ "decision": "approve", "row_version": row_version })),
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
}

// feature: W1
#[test]
fn request_draft_negotiate_approve_sign_renew() {
    attome_testkit::run_shared(async {
        if attome_testkit::s3_or_skip().is_none() {
            return;
        }
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let manager = user_with_role(&app, "e2e-manager", "Contract Manager").await;
        let legal = user_with_role(&app, "e2e-legal", "Legal").await;
        let today = chrono::Utc::now().date_naive();

        // Requested: a draft contract ending in 40 days with 30 days' notice,
        // so its notice deadline is 10 days away.
        let (code, body) = app
            .request(
                Method::POST,
                "/api/v1/contract",
                Some(json!({
                    "title": "Managed services",
                    "contract_value": 50000,
                    "end_date": (today + chrono::Duration::days(40)).to_string(),
                    "notice_period_days": 30,
                })),
            )
            .await;
        assert!(code.is_success(), "{code} {body}");
        let contract: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(status(&app, contract).await, "draft");

        // Drafted: version 1 with its file and text.
        let drafted = Uuid::now_v7();
        let draft_key = format!("contract_version/{drafted}/file/{}-v1.pdf", Uuid::now_v7());
        store(
            &app,
            &draft_key,
            b"%PDF-1.4 v1",
            "1. Services\nThe supplier provides managed services.\n2. Liability\nLiability is capped at fees paid.",
        )
        .await;
        sqlx::query(
            "INSERT INTO contract_version \
               (id, contract_id, source, version_no, file, created_by_ref, created_by, owner_ref) \
             VALUES ($1, $2, 'draft', 1, $3, $4, $4, $4)",
        )
        .bind(drafted)
        .bind(contract.to_string())
        .bind(&draft_key)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();

        // Negotiated: the counterparty sends their version through the link.
        let (code, shared) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/contracts/{contract}/share-for-review"),
                Some(json!({ "email": "counsel@counterparty.example" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{shared}");
        let link: Uuid = shared["link_id"].as_str().unwrap().parse().unwrap();
        let token = attome_contract::negotiation::token_for(
            &app.state,
            link,
            chrono::Utc::now() + chrono::Duration::days(14),
        )
        .unwrap();
        let (code, done) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/review/{token}"),
                Some(json!({
                    "file_name": "managed-services-v2.pdf",
                    "content_type": "application/pdf",
                    "content_base64": base64::engine::general_purpose::STANDARD.encode(b"%PDF-1.4 v2"),
                })),
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{done}");
        let theirs: Uuid = done["version_id"].as_str().unwrap().parse().unwrap();
        let (session, name): (Uuid, String) = sqlx::query_as(
            "SELECT session_id, file_name FROM contract_review_entry WHERE link_id = $1 AND kind = 'upload'",
        )
        .bind(link)
        .fetch_one(app.db())
        .await
        .unwrap();
        let their_key =
            attome_document::files::final_key("contract_version", theirs, "file", session, &name);
        store(
            &app,
            &their_key,
            b"%PDF-1.4 v2",
            "1. Services\nThe supplier provides managed services.\n2. Liability\nLiability is unlimited.",
        )
        .await;
        sqlx::query("UPDATE upload_session SET status = 'clean', final_key = $2 WHERE id = $1")
            .bind(session)
            .bind(&their_key)
            .execute(app.db())
            .await
            .unwrap();
        assert_eq!(
            attome_contract::negotiation::tick(&app.state)
                .await
                .unwrap(),
            1
        );

        // Compared: the queued comparison runs and finds the changed clause.
        let comparison: Uuid = sqlx::query_scalar(
            "SELECT comparison_id FROM contract_review_entry WHERE link_id = $1 AND kind = 'upload'",
        )
        .bind(link)
        .fetch_one(app.db())
        .await
        .unwrap();
        let admin = attome_security::resolve_uncached(&app.state.base.db, app.admin.id)
            .await
            .unwrap();
        attome_contract::compare::run_compare(&app.state, &admin, comparison)
            .await
            .unwrap();
        let (compare_status, diff): (String, Option<String>) = sqlx::query_as(
            "SELECT status::text, diff_json::text FROM contract_comparison WHERE id = $1",
        )
        .bind(comparison)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(compare_status, "done");
        assert!(
            diff.is_some_and(|d| d.contains("unlimited")),
            "the change is in the diff"
        );

        // Approved: the playbook marked the liability clause for Legal, so a
        // contract manager and Legal both approve.
        sqlx::query("UPDATE contract SET playbook_deviations = $2 WHERE id = $1")
            .bind(contract)
            .bind(r#"[{"rule_id":"00000000-0000-0000-0000-000000000001","clause_key":"liability","severity":"needs_legal"}]"#)
            .execute(app.db())
            .await
            .unwrap();
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/{contract}/transition"),
                Some(json!({ "to_state": "approved" })),
            )
            .await;
        assert!(code.is_success(), "{code} {body}");
        assert_eq!(status(&app, contract).await, "review");
        approve(&app, &manager, contract).await;
        assert_eq!(
            status(&app, contract).await,
            "review",
            "Legal has not approved yet"
        );
        approve(&app, &legal, contract).await;
        assert_eq!(status(&app, contract).await, "approved");

        // Signed: everyone signs and the contract is active.
        let (code, sent) = app
            .request(
                Method::POST,
                &format!("/api/v1/contract/contracts/{contract}/send-for-signature"),
                Some(json!({
                    "signers": [{ "name": "Counterparty", "email": "signer@counterparty.example" }]
                })),
            )
            .await;
        assert_eq!(code, StatusCode::ACCEPTED, "{sent}");
        sqlx::query(
            "UPDATE esign_envelope SET status = 'completed', completed_at = now() WHERE id = $1",
        )
        .bind(
            sent["envelope_id"]
                .as_str()
                .unwrap()
                .parse::<Uuid>()
                .unwrap(),
        )
        .execute(app.db())
        .await
        .unwrap();
        assert_eq!(
            attome_contract::signature::tick(&app.state).await.unwrap(),
            1
        );
        assert_eq!(status(&app, contract).await, "active");

        // Renewed: the nightly run sees the notice deadline within 30 days
        // and opens one renewal task, once.
        let run = attome_contract::dates::run(
            app.db(),
            &app.state.base.config.notification,
            attome_contract::dates::KeyDateSettings::default(),
            today,
        )
        .await
        .unwrap();
        assert!(run.renewal_tasks >= 1, "{run:?}");
        let tasks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM activity WHERE entity_name = 'contract' AND record_id = $1 \
               AND activity_type = 'task' AND subject = $2",
        )
        .bind(contract.to_string())
        .bind(attome_contract::dates::RENEWAL_TASK_SUBJECT)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(tasks, 1);
    });
}
