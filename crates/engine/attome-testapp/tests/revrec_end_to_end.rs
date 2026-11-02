//! F11-T14: an order to a posted close. A confirmed order becomes a revenue
//! contract with a point-in-time obligation; the delivery dates it; the
//! January close schedules, recognises and (once approved) posts it and
//! locks the line; nothing was billed, so the balance is unbilled; the
//! February close carries the balance forward.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ledger::revrec::close::{post_close, run, start};
use attome_ledger::revrec::contract::build_from_source;
use attome_testapp::TestApp;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 9] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "fulfilment",
    "ledger",
];

async fn install(app: &TestApp) {
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
            let value: Value =
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

// feature: F11
#[test]
fn order_to_posted_close() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let admin = app.admin.id;
        let customer = id(
            &app,
            "INSERT INTO account (name, owner_ref) VALUES ('Buyer', $1) RETURNING id",
        )
        .await;
        let product = id(&app, "INSERT INTO product (name, sku, owner_ref) VALUES ('Licence', 'LIC-E2E', $1) RETURNING id").await;
        let order: Uuid = sqlx::query_scalar(
            "INSERT INTO \"order\" (name, status, account_ref, currency, owner_ref) \
             VALUES ('SO-E2E', 'confirmed', $1, 'SAR', $2) RETURNING id",
        )
        .bind(customer)
        .bind(admin)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO order_line (order_ref, product_ref, quantity, line_total, owner_ref) \
             VALUES ($1, $2, 1, 500, $3)",
        )
        .bind(order)
        .bind(product)
        .bind(admin)
        .execute(app.db())
        .await
        .unwrap();
        // The ledger: accounts, the close's posting rule, the months.
        let deferred = id(&app, "INSERT INTO gl_account (code, name, account_type, is_postable, owner_ref) VALUES ('2400', 'Deferred revenue', 'liability', true, $1) RETURNING id").await;
        let revenue = id(&app, "INSERT INTO gl_account (code, name, account_type, is_postable, owner_ref) VALUES ('4000', 'Revenue', 'income', true, $1) RETURNING id").await;
        let journal = id(&app, "INSERT INTO gl_journal (code, name, owner_ref) VALUES ('GJ', 'General', $1) RETURNING id").await;
        sqlx::query(
            "INSERT INTO gl_posting_rule (source_kind, journal_ref, debit_account_ref, \
                 credit_account_ref, owner_ref) VALUES ('revrec_close', $1, $2, $3, $4)",
        )
        .bind(journal)
        .bind(deferred)
        .bind(revenue)
        .bind(admin)
        .execute(app.db())
        .await
        .unwrap();
        for (name, from, to) in [
            ("2027-01", "2027-01-01", "2027-01-31"),
            ("2027-02", "2027-02-01", "2027-02-28"),
        ] {
            sqlx::query(
                "INSERT INTO gl_period (name, starts_on, ends_on, status, owner_ref) \
                 VALUES ($1, $2::date, $3::date, 'open', $4)",
            )
            .bind(name)
            .bind(from)
            .bind(to)
            .bind(admin)
            .execute(app.db())
            .await
            .unwrap();
        }

        // The contract, then the delivery in January.
        let built = build_from_source(&app.state, "order", order).await.unwrap();
        let fulfilment: Uuid = sqlx::query_scalar(
            "INSERT INTO fulfilment_order (order_ref, status, owner_ref) \
             VALUES ($1, 'delivered', $2) RETURNING id",
        )
        .bind(order)
        .bind(admin)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO shipment (fulfilment_order_ref, carrier, status, delivered_on, owner_ref) \
             VALUES ($1, 'own_fleet', 'delivered', '2027-01-20', $2)",
        )
        .bind(fulfilment)
        .bind(admin)
        .execute(app.db())
        .await
        .unwrap();

        let ctx = attome_security::resolve_uncached(app.db(), admin)
            .await
            .unwrap();
        let january = start(&app.state, admin, "2027-01").await.unwrap();
        assert_eq!(
            run(&app.state, january.id).await.unwrap(),
            "awaiting_approval"
        );
        sqlx::query(
            "UPDATE approval_request SET status = 'approved' \
              WHERE id = (SELECT approval_request_id::uuid FROM revrec_close_run WHERE id = $1)",
        )
        .bind(january.id)
        .execute(app.db())
        .await
        .unwrap();
        let posted = post_close(&app.state, &ctx, january.id).await.unwrap();
        assert_eq!(posted.entries.len(), 1, "one entry for the licence");
        let (status, amount): (Option<String>, Option<f64>) = sqlx::query_as(
            "SELECT s.status::text, s.amount_contract_ccy::float8 FROM revenue_schedule_line s \
               JOIN performance_obligation o ON o.id = s.obligation_ref \
              WHERE o.revenue_contract_ref = $1 AND s.fiscal_period = '2027-01'",
        )
        .bind(built.contract)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!((status.as_deref(), amount), (Some("locked"), Some(500.0)));

        let february = start(&app.state, admin, "2027-02").await.unwrap();
        run(&app.state, february.id).await.unwrap();
        let balances: Vec<(String, Option<f64>, Option<f64>)> = sqlx::query_as(
            "SELECT fiscal_period, recognised_to_date::float8, unbilled::float8 \
               FROM revenue_balance_snapshot WHERE revenue_contract_ref = $1 \
              ORDER BY fiscal_period",
        )
        .bind(built.contract)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(
            balances,
            vec![
                ("2027-01".to_owned(), Some(500.0), Some(500.0)),
                ("2027-02".to_owned(), Some(500.0), Some(500.0)),
            ],
            "recognised and not billed: unbilled, carried forward"
        );
    });
}
