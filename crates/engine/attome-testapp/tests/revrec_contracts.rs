//! F11-T3: a confirmed order gets one revenue contract however often its
//! job runs, a bundle product's split template makes one obligation per kind,
//! and contracts with a locked schedule line no longer combine.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ledger::revrec::contract::build_from_source;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

const PACKS: [&str; 3] = ["crm", "sales", "ledger"];

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
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn account(app: &TestApp) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (id, name, owner_ref, is_active) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(format!("Revrec Co {}", Uuid::now_v7().simple()))
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn product(app: &TestApp, rule: Option<Uuid>) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO product (id, name, owner_ref, is_active) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(format!("Revrec product {}", Uuid::now_v7().simple()))
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    if let Some(rule) = rule {
        sqlx::query("UPDATE product SET revenue_rule_ref = $2 WHERE id = $1")
            .bind(id)
            .bind(rule)
            .execute(app.db())
            .await
            .unwrap();
    }
    id
}

/// A confirmed order of one line.
async fn order(app: &TestApp, customer: Uuid, product: Uuid, total: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO \"order\" (id, name, status, account_ref, currency, owner_ref, is_active) \
         VALUES ($1, $2, 'confirmed', $3, 'SAR', $4, true) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(format!("SO-{}", Uuid::now_v7().simple()))
    .bind(customer)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO order_line (id, order_ref, product_ref, line_total, owner_ref, is_active) \
         VALUES ($1, $2, $3, $4::numeric, $5, true)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .bind(product)
    .bind(total)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .unwrap();
    id
}

// feature: F11
#[test]
fn order_creates_contract_once_on_retry() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let customer = account(&app).await;
        let item = product(&app, None).await;
        let so = order(&app, customer, item, "500.00").await;

        let first = build_from_source(&app.state, "order", so)
            .await
            .expect("build");
        assert_eq!(
            first.obligations_written, 1,
            "no rule: one point-in-time obligation"
        );
        let again = build_from_source(&app.state, "order", so)
            .await
            .expect("retry");
        assert_eq!(again.contract, first.contract);
        assert_eq!(again.obligations_written, 0, "a retry writes nothing");
        let contracts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM revenue_contract WHERE source_kind = 'order' AND source_id = $1",
        )
        .bind(so.to_string())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(contracts, 1);
        let pattern: String = sqlx::query_scalar(
            "SELECT pattern::text FROM performance_obligation WHERE revenue_contract_ref = $1",
        )
        .bind(first.contract)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(pattern, "point_in_time");
    });
}

// feature: F11
#[test]
fn bundle_product_splits_into_three_obligations() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let rule: Uuid = sqlx::query_scalar(
            "INSERT INTO revenue_rule (id, name, pattern, split_template, owner_ref, is_active) \
             VALUES ($1, 'Bundle', 'ratable', 'license:60, support:30, training:10', $2, true) \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        let customer = account(&app).await;
        let item = product(&app, Some(rule)).await;
        let so = order(&app, customer, item, "1000.00").await;

        let built = build_from_source(&app.state, "order", so)
            .await
            .expect("build");
        assert_eq!(built.obligations_written, 3);
        let mut parts: Vec<(String, String)> = sqlx::query_as(
            "SELECT kind, allocated_amount::text FROM performance_obligation \
              WHERE revenue_contract_ref = $1 ORDER BY kind",
        )
        .bind(built.contract)
        .fetch_all(app.db())
        .await
        .unwrap();
        parts.sort();
        let amounts: Vec<(String, f64)> = parts
            .into_iter()
            .map(|(k, a)| (k, a.parse::<f64>().unwrap()))
            .collect();
        assert_eq!(
            amounts,
            vec![
                ("license".to_owned(), 600.0),
                ("support".to_owned(), 300.0),
                ("training".to_owned(), 100.0),
            ]
        );
    });
}

// feature: F11
#[test]
fn combine_refused_after_lock() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let customer = account(&app).await;
        let item = product(&app, None).await;
        let a = build_from_source(
            &app.state,
            "order",
            order(&app, customer, item, "100.00").await,
        )
        .await
        .unwrap();
        let b = build_from_source(
            &app.state,
            "order",
            order(&app, customer, item, "200.00").await,
        )
        .await
        .unwrap();
        let c = build_from_source(
            &app.state,
            "order",
            order(&app, customer, item, "300.00").await,
        )
        .await
        .unwrap();
        // c's schedule is locked.
        let obligation: Uuid = sqlx::query_scalar(
            "SELECT id FROM performance_obligation WHERE revenue_contract_ref = $1 LIMIT 1",
        )
        .bind(c.contract)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO revenue_schedule_line (id, obligation_ref, fiscal_period, status, owner_ref, \
                                                is_active) \
             VALUES ($1, $2, '2026-11', 'locked', $3, true)",
        )
        .bind(Uuid::now_v7())
        .bind(obligation)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();

        let path = "/api/v1/ledger/revrec/contracts/combine";
        let (status, body) = app
            .request(
                Method::POST,
                path,
                Some(json!({"contract_ids": [a.contract, c.contract]})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let (status, body) = app
            .request(
                Method::POST,
                path,
                Some(json!({"contract_ids": [a.contract, b.contract]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["merged"], 1);
        let moved: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM performance_obligation WHERE revenue_contract_ref = $1",
        )
        .bind(a.contract)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(moved, 2, "b's obligation moved to a");
    });
}
