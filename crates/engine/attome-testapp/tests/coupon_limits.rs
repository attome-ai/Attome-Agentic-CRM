//! F8-T6: a single-use coupon redeemed by two checkouts at once is
//! redeemed once; the other is a conflict.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "test helpers: a failed setup step should panic with its message, and the race opens raw pool transactions, where 503 mapping is moot"
)]

use attome_sales::promotion::redeem_coupon;
use attome_testapp::TestApp;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 7] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
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

async fn order(app: &TestApp, account: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO \"order\" (name, currency, account_ref, status) \
         VALUES ('Shop order', 'SAR', $1, 'draft') RETURNING id",
    )
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn redeem_and_hold(app: &TestApp, order: Uuid) -> Result<Uuid, AppError> {
    let mut tx = app.db().begin().await.unwrap();
    let result = redeem_coupon(&mut tx, "WELCOME", order, None).await;
    // Hold the lock a moment, as a checkout writing its order would.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    }
    result
}

// feature: F8
#[test]
fn concurrent_redemption_of_single_use_coupon_succeeds_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let promotion: Uuid = sqlx::query_scalar(
            "INSERT INTO promotion (name, kind, value, max_uses, is_enabled) \
             VALUES ('Welcome', 'percent', 10, 1, true) RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO coupon (code, promotion_ref, uses_count) VALUES ('WELCOME', $1, 0)",
        )
        .bind(promotion)
        .execute(app.db())
        .await
        .unwrap();
        let (a, b) = (order(&app, account).await, order(&app, account).await);

        let (first, second) = tokio::join!(redeem_and_hold(&app, a), redeem_and_hold(&app, b));
        let results = [first, second];
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| matches!(r, Err(AppError::Conflict(_)))),
            "{results:?}"
        );
        let used: i64 =
            sqlx::query_scalar("SELECT uses_count::bigint FROM coupon WHERE code = 'WELCOME'")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(used, 1);
        let redemptions: i64 = sqlx::query_scalar("SELECT count(*) FROM coupon_redemption")
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(redemptions, 1);

        // Used up: a later checkout is refused too.
        let c = order(&app, account).await;
        let mut tx = app.db().begin().await.unwrap();
        let late = redeem_coupon(&mut tx, "WELCOME", c, None).await;
        assert!(matches!(late, Err(AppError::Conflict(_))), "{late:?}");
    });
}
