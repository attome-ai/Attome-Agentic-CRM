//! F11-T7: a month's close recognises its lines, writes deferred and
//! unbilled balances, posts one entry per product once after approval and
//! locks the lines; a closed ledger period refuses the close.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ledger::revrec::close::{post_close, run, start};
use attome_testapp::TestApp;
use attome_types::AppError;
use uuid::Uuid;

const PACKS: [&str; 8] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "ledger",
];

async fn install(app: &TestApp) {
    // The close and the ERP send are registered jobs; the test runs their
    // bodies itself, so the types only need to exist.
    for name in [
        attome_ledger::revrec::close::JOB,
        attome_ledger::revrec::erp::JOB,
    ] {
        let _ = attome_core::jobs::JOB_TYPES.register(
            attome_jobs::JobType::new(name, 1),
            |_state: attome_core::EngineState, _job: attome_jobs::RegisteredJob| async move {
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        );
    }
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
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn id(app: &TestApp, sql: &str) -> Uuid {
    sqlx::query_scalar(sql)
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// A contract for an order with one product's obligation of 100 a month in
/// January and February 2027; the ledger accounts and the `revrec_close`
/// posting rule; an open ledger period for January. Returns (contract,
/// order id as text).
async fn books(app: &TestApp) -> (Uuid, String) {
    let account = id(
        app,
        "INSERT INTO account (name, owner_ref) VALUES ('Buyer', $1) RETURNING id",
    )
    .await;
    let product = id(
        app,
        "INSERT INTO product (name, sku, owner_ref) VALUES ('Plan', 'PLAN', $1) RETURNING id",
    )
    .await;
    let order = Uuid::now_v7().to_string();
    let contract: Uuid = sqlx::query_scalar(
        "INSERT INTO revenue_contract (id, source_kind, source_id, customer_account_ref, currency, \
             total_price, status, created_by, owner_ref) \
         VALUES ($1, 'order', $2, $3, 'SAR', 200, 'open', $4, $4) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(&order)
    .bind(account)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    let obligation: Uuid = sqlx::query_scalar(
        "INSERT INTO performance_obligation (id, revenue_contract_ref, source_line_id, product_ref, \
             kind, pattern, allocated_amount, status, created_by, owner_ref) \
         VALUES ($1, $2, 'line-1', $3, 'order_line', 'ratable', 200, 'open', $4, $4) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(contract)
    .bind(product)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    for period in ["2027-01", "2027-02"] {
        sqlx::query(
            "INSERT INTO revenue_schedule_line (id, obligation_ref, fiscal_period, \
                 amount_contract_ccy, status, created_by, owner_ref) \
             VALUES ($1, $2, $3, 100, 'planned', $4, $4)",
        )
        .bind(Uuid::now_v7())
        .bind(obligation)
        .bind(period)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
    }
    let deferred = id(app, "INSERT INTO gl_account (code, name, account_type, is_postable, owner_ref) VALUES ('2400', 'Deferred revenue', 'liability', true, $1) RETURNING id").await;
    let revenue = id(app, "INSERT INTO gl_account (code, name, account_type, is_postable, owner_ref) VALUES ('4000', 'Revenue', 'income', true, $1) RETURNING id").await;
    let journal = id(
        app,
        "INSERT INTO gl_journal (code, name, owner_ref) VALUES ('GJ', 'General', $1) RETURNING id",
    )
    .await;
    sqlx::query(
        "INSERT INTO gl_posting_rule (source_kind, journal_ref, debit_account_ref, credit_account_ref, owner_ref) \
         VALUES ('revrec_close', $1, $2, $3, $4)",
    )
    .bind(journal)
    .bind(deferred)
    .bind(revenue)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .unwrap();
    for (name, from, to, status) in [
        ("Jan 2027", "2027-01-01", "2027-01-31", "open"),
        ("Feb 2027", "2027-02-01", "2027-02-28", "open"),
        ("Mar 2027", "2027-03-01", "2027-03-31", "closed"),
    ] {
        sqlx::query(
            "INSERT INTO gl_period (name, starts_on, ends_on, status, owner_ref) \
             VALUES ($1, $2::date, $3::date, $4, $5)",
        )
        .bind(name)
        .bind(from)
        .bind(to)
        .bind(status)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
    }
    (contract, order)
}

async fn approve(app: &TestApp, run_id: Uuid) {
    sqlx::query(
        "UPDATE approval_request SET status = 'approved' \
          WHERE id = (SELECT approval_request_id::uuid FROM revrec_close_run WHERE id = $1)",
    )
    .bind(run_id)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: F11
#[test]
fn close_posts_once_after_approval() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        books(&app).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let close = start(&app.state, app.admin.id, "2027-01").await.unwrap();
        assert_eq!(
            run(&app.state, close.id).await.unwrap(),
            "awaiting_approval"
        );
        let early = post_close(&app.state, &ctx, close.id).await;
        assert!(matches!(early, Err(AppError::Conflict(_))), "{early:?}");

        approve(&app, close.id).await;
        let posted = post_close(&app.state, &ctx, close.id).await.unwrap();
        assert_eq!(posted.status, "posted");
        assert_eq!(posted.entries.len(), 1, "one entry for the one product");
        let again = post_close(&app.state, &ctx, close.id).await;
        assert!(matches!(again, Err(AppError::Conflict(_))), "{again:?}");
        let entries: i64 =
            sqlx::query_scalar("SELECT count(*) FROM gl_entry WHERE source_kind = 'revrec_close'")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(entries, 1);
        let statuses: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT fiscal_period, status::text FROM revenue_schedule_line ORDER BY fiscal_period",
        )
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(statuses[0].1.as_deref(), Some("locked"));
        assert_eq!(
            statuses[1].1.as_deref(),
            Some("planned"),
            "February is untouched"
        );
        // Asking again for January answers the posted close.
        let same = start(&app.state, app.admin.id, "2027-01").await.unwrap();
        assert_eq!(same.id, close.id);
    });
}

// feature: F11
#[test]
fn deferred_and_unbilled_roll_forward() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (contract, order) = books(&app).await;
        // 150 billed in January for the order.
        let account: Uuid =
            sqlx::query_scalar("SELECT customer_account_ref FROM revenue_contract WHERE id = $1")
                .bind(contract)
                .fetch_one(app.db())
                .await
                .unwrap();
        let invoice: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice (invoice_number, amount, account_ref, issued_date, currency, owner_ref) \
             VALUES ('INV-1', 150, $1, '2027-01-15', 'SAR', $2) RETURNING id",
        )
        .bind(account)
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO invoice_line (invoice_ref, description, quantity, unit_price, line_total, \
                 source_kind, source_ref, owner_ref) \
             VALUES ($1, 'Plan', 1, 150, 150, 'order', $2, $3)",
        )
        .bind(invoice)
        .bind(&order)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();

        let snapshot = |period: &'static str| {
            let db = app.db().clone();
            async move {
                sqlx::query_as::<_, (bool, bool)>(
                    "SELECT deferred = $2, unbilled = $3 FROM revenue_balance_snapshot \
                      WHERE revenue_contract_ref = $1 AND fiscal_period = $4",
                )
                .bind(contract)
                .bind(if period == "2027-01" { 50 } else { 0 })
                .bind(if period == "2027-01" { 0 } else { 50 })
                .bind(period)
                .fetch_one(&db)
                .await
                .unwrap()
            }
        };
        let january = start(&app.state, app.admin.id, "2027-01").await.unwrap();
        run(&app.state, january.id).await.unwrap();
        assert_eq!(
            snapshot("2027-01").await,
            (true, true),
            "150 billed, 100 recognised: 50 deferred"
        );
        let february = start(&app.state, app.admin.id, "2027-02").await.unwrap();
        run(&app.state, february.id).await.unwrap();
        assert_eq!(
            snapshot("2027-02").await,
            (true, true),
            "150 billed, 200 recognised: 50 unbilled"
        );
    });
}

// feature: F11
#[test]
fn close_refused_for_locked_ledger_period() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        books(&app).await;
        let refused = start(&app.state, app.admin.id, "2027-03").await;
        assert!(
            matches!(refused, Err(AppError::Validation(_))),
            "{refused:?}"
        );
        let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM revrec_close_run")
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(runs, 0);
    });
}

// feature: F11
#[test]
fn close_for_an_erp_posts_no_ledger_entry() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        books(&app).await;
        let (status, body) = app
            .request(
                axum::http::Method::PUT,
                "/api/v1/admin/settings/revrec.posting_target",
                Some(serde_json::json!({
                    "scope": "deployment",
                    "value": format!("connector:{}", Uuid::now_v7()),
                })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let close = start(&app.state, app.admin.id, "2027-01").await.unwrap();
        run(&app.state, close.id).await.unwrap();
        approve(&app, close.id).await;
        let posted = post_close(&app.state, &ctx, close.id).await.unwrap();
        assert_eq!(posted.status, "posted");
        assert!(
            posted.entries.is_empty(),
            "the ERP gets the entries, not this ledger"
        );
        let entries: i64 =
            sqlx::query_scalar("SELECT count(*) FROM gl_entry WHERE source_kind = 'revrec_close'")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(entries, 0);
        let locked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM revenue_schedule_line WHERE fiscal_period = '2027-01' \
               AND status = 'locked'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(locked, 1);
        let amounts = attome_ledger::revrec::erp::amounts(&app.state, "2027-01")
            .await
            .unwrap();
        assert_eq!(amounts.len(), 1, "one entry to send, for the one product");
    });
}
