//! I6-T2: concurrent stock movers keep the balance equal to the sum of the
//! movements and never sell stock that is not there.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_service::inventory::{NewMovement, record_in_tx, reserve_in_tx};
use attome_testapp::TestApp;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 3] = ["crm", "sales", "field-service"];

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

fn movement(product: Uuid, kind: &str, quantity: f64) -> NewMovement {
    NewMovement {
        product_id: product,
        location_code: "WH1".into(),
        kind: kind.into(),
        quantity,
        reference: None,
        serial_id: None,
        lot_id: None,
    }
}

async fn move_once(app: &TestApp, m: NewMovement) -> bool {
    let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
    match record_in_tx(&mut tx, &m, None, false).await {
        Ok(_) => {
            attome_db::tx::commit(tx).await.unwrap();
            true
        }
        Err(_) => false,
    }
}

// feature: I6
#[test]
fn concurrent_issues_never_oversell() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let product: Uuid =
            sqlx::query_scalar("INSERT INTO product (name) VALUES ('Filter') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert!(move_once(&app, movement(product, "receipt", 10.0)).await);
        // Two held for a work order: eight are free to issue.
        let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
        reserve_in_tx(&mut tx, product, "WH1", 2.0, "work_order_line:test", None)
            .await
            .unwrap();
        attome_db::tx::commit(tx).await.unwrap();

        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move { move_once(&app, movement(product, "issue", 1.0)).await })
            })
            .collect();
        let mut granted = 0;
        for task in tasks {
            if task.await.unwrap() {
                granted += 1;
            }
        }
        assert_eq!(granted, 8, "only the free stock is issued");

        let (on_hand, reserved, available, rows): (f64, f64, f64, i64) = sqlx::query_as(
            "SELECT on_hand::float8, reserved::float8, available::float8, \
                    (SELECT COUNT(*) FROM stock_balance WHERE product_ref = $1) \
               FROM stock_balance WHERE product_ref = $1",
        )
        .bind(product)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(rows, 1, "one balance row however many movers raced");
        assert!((on_hand - 2.0).abs() < 1e-9, "{on_hand}");
        assert!((reserved - 2.0).abs() < 1e-9);
        assert!(available.abs() < 1e-9);
        let ledger: f64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(quantity), 0)::float8 FROM stock_movement WHERE product_ref = $1",
        )
        .bind(product)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(
            (ledger - on_hand).abs() < 1e-9,
            "balance = sum of movements"
        );
    });
}
