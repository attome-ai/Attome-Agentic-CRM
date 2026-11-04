//! F8-T2: a shop order synced twice makes one order, one sync map row per
//! source record, and a customer already on file is matched by phone.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::str::FromStr;

use attome_integration::connector::adapters::shop_sync::{ShopCustomer, ShopOrder, ShopOrderLine};
use attome_sales::shop_sync::{SourceRecord, upsert_from_source};
use attome_testapp::TestApp;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 8] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "fulfilment",
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

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap()
}

fn order(status: &str) -> ShopOrder {
    ShopOrder {
        source_id: "9001".into(),
        number: "S-1042".into(),
        currency: "SAR".into(),
        placed_at: chrono::Utc::now(),
        status: status.into(),
        customer: Some(ShopCustomer {
            source_id: "c-77".into(),
            name: "Sara Ali".into(),
            email: Some("Sara@Example.com".into()),
            phone: Some("0501234567".into()),
        }),
        lines: vec![ShopOrderLine {
            source_product_id: "p-5".into(),
            sku: Some("TS-RED".into()),
            name: "Red T-shirt".into(),
            quantity: dec("2"),
            unit_price: dec("57.50"),
            vat_rate: Some(dec("0.15")),
        }],
        prices_include_vat: true,
        shipping: Decimal::ZERO,
        discount: Decimal::ZERO,
        total: dec("115"),
        cod_amount: None,
        delivery_address: None,
        delivery_phone: None,
    }
}

async fn count(app: &TestApp, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(app.db()).await.unwrap()
}

// feature: F8
#[test]
fn a_shop_order_synced_twice_is_one_order() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Online shop') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        // The customer is already a contact, under another phone format.
        let known: Uuid = sqlx::query_scalar(
            "INSERT INTO contact (full_name, mobile_phone) VALUES ('Sara', '+966501234567') \
             RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        let connection: Uuid = sqlx::query_scalar(
            "INSERT INTO shop_connection (name, platform, default_account_ref) \
             VALUES ('Main store', 'salla', $1) RETURNING id",
        )
        .bind(account)
        .fetch_one(app.db())
        .await
        .unwrap();
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let first = upsert_from_source(
            &app.state,
            &service,
            connection,
            &SourceRecord::Order(order("pending")),
        )
        .await
        .unwrap();
        assert!(first.created);
        let again = upsert_from_source(
            &app.state,
            &service,
            connection,
            &SourceRecord::Order(order("completed")),
        )
        .await
        .unwrap();
        assert!(!again.created);
        assert_eq!(again.target_id, first.target_id);

        assert_eq!(
            count(
                &app,
                "SELECT count(*) FROM \"order\" WHERE source = 'shop:salla'"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) FROM shop_sync_map WHERE source_kind = 'order'"
            )
            .await,
            1
        );
        assert_eq!(count(&app, "SELECT count(*) FROM shop_sync_map").await, 3);
        let (status, source_number, contact, owner, tax): (
            Option<String>,
            Option<String>,
            Option<Uuid>,
            Option<Uuid>,
            Option<bool>,
        ) = sqlx::query_as(
            "SELECT status::text, source_order_number, updates_contact_ref, account_ref, tax_total = 15 \
               FROM \"order\" WHERE id = $1",
        )
        .bind(first.target_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            status.as_deref(),
            Some("fulfilled"),
            "the second sync updates"
        );
        assert_eq!(source_number.as_deref(), Some("S-1042"));
        assert_eq!(contact, Some(known), "matched by phone, not a new contact");
        assert_eq!(owner, Some(account), "the connection's default account");
        assert_eq!(tax, Some(true), "VAT split out of the inclusive price");
        assert_eq!(
            count(&app, "SELECT count(*) FROM contact").await,
            1,
            "no second contact"
        );
        assert_eq!(
            count(
                &app,
                &format!(
                    "SELECT count(*) FROM order_line WHERE order_ref = '{}'",
                    first.target_id
                )
            )
            .await,
            1
        );

        // Without an account to put it under, an order is refused.
        sqlx::query("UPDATE shop_connection SET default_account_ref = NULL WHERE id = $1")
            .bind(connection)
            .execute(app.db())
            .await
            .unwrap();
        let mut other = order("pending");
        other.source_id = "9002".into();
        let refused = upsert_from_source(
            &app.state,
            &service,
            connection,
            &SourceRecord::Order(other),
        )
        .await;
        assert!(
            matches!(refused, Err(AppError::Validation(_))),
            "{refused:?}"
        );
    });
}
