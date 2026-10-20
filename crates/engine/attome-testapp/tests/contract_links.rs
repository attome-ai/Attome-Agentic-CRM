//! W1-T13: an accepted quote drafts one sales contract however often the
//! sweep runs, and a request filed under a contract type's intake offering
//! drafts a contract of that type and is resolved into it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "test helpers: a failed setup step should panic with its message; a test opens its own transaction to write a change event"
)]

use attome_core::change_feed::ChangeOperation;
use attome_testapp::TestApp;
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

/// Writes the change event the records engine would have written.
async fn emit(app: &TestApp, entity: &str, id: Uuid, operation: ChangeOperation) {
    let mut tx = app.db().begin().await.unwrap();
    attome_core::change_feed::emit_tx(&mut tx, entity, id, operation)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Runs the sweep until it has read everything there is.
async fn sweep(app: &TestApp) -> u64 {
    let mut drafts = 0;
    for _ in 0..10 {
        let run = attome_contract::links::run(&app.state).await.unwrap();
        drafts += run.drafts;
        if run.events == 0 {
            break;
        }
    }
    drafts
}

// feature: W1
#[test]
fn accepted_quote_creates_one_draft() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let owner = attome_testapp::seed_user(app.db(), "quote-owner").await;
        let quote = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO quote (id, name, quote_number, status, grand_total, currency, owner_ref, \
                 is_active, row_version) \
             VALUES ($1, 'Fleet renewal', 'Q-1042', 'sent', 125000, 'SAR', $2, true, 0)",
        )
        .bind(quote)
        .bind(owner.id)
        .execute(app.db())
        .await
        .unwrap();
        emit(&app, "quote", quote, ChangeOperation::Create).await;
        assert_eq!(sweep(&app).await, 0, "a sent quote drafts nothing");

        sqlx::query("UPDATE quote SET status = 'accepted' WHERE id = $1")
            .bind(quote)
            .execute(app.db())
            .await
            .unwrap();
        emit(&app, "quote", quote, ChangeOperation::Update).await;
        emit(&app, "quote", quote, ChangeOperation::Update).await;
        sweep(&app).await;
        // A replay of the same events drafts nothing more.
        emit(&app, "quote", quote, ChangeOperation::Update).await;
        sweep(&app).await;

        let rows: Vec<(String, Option<String>, Option<f64>, Option<Uuid>)> = sqlx::query_as(
            "SELECT title, currency, contract_value::float8, owner_ref FROM contract \
              WHERE source_kind = 'quote' AND source_id = $1",
        )
        .bind(quote.to_string())
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        let (title, currency, value, contract_owner) = &rows[0];
        assert_eq!(title, "Quote Q-1042");
        assert_eq!(currency.as_deref(), Some("SAR"));
        assert_eq!(*value, Some(125000.0));
        assert_eq!(*contract_owner, Some(owner.id));
    });
}

// feature: W1
#[test]
fn intake_creates_draft_request() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let lease: Uuid = sqlx::query_scalar(
            "INSERT INTO contract_type (name, is_active, row_version) VALUES ('Lease', true, 0) \
             RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        sweep(&app).await;
        let offering: Option<String> =
            sqlx::query_scalar("SELECT intake_form_ref FROM contract_type WHERE id = $1")
                .bind(lease)
                .fetch_one(app.db())
                .await
                .unwrap();
        let offering: Uuid = offering
            .expect("the type has an intake offering")
            .parse()
            .unwrap();

        let requester = attome_testapp::seed_user(app.db(), "lease-requester").await;
        let request = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO service_work_request (id, title, request_type, requester_id, status, \
                 offering_id, is_active, row_version) \
             VALUES ($1, 'Warehouse lease, Dammam', 'custom', $2, 'new', $3, true, 0)",
        )
        .bind(request)
        .bind(requester.id)
        .bind(offering)
        .execute(app.db())
        .await
        .unwrap();
        emit(
            &app,
            "service_work_request",
            request,
            ChangeOperation::Create,
        )
        .await;
        sweep(&app).await;

        let (contract, contract_type, owner): (Uuid, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT id, contract_type_ref, owner_ref FROM contract \
                  WHERE source_kind = 'intake' AND source_id = $1",
        )
        .bind(request.to_string())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(contract_type, Some(lease));
        assert_eq!(owner, Some(requester.id));
        let (status, resolved): (String, Option<String>) = sqlx::query_as(
            "SELECT status, resolved_record_id FROM service_work_request WHERE id = $1",
        )
        .bind(request)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(status, "converted");
        assert_eq!(resolved, Some(contract.to_string()));
    });
}
