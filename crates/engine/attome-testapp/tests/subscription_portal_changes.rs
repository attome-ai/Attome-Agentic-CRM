//! F3-T13: the subscription changes a portal user may make, run as the
//! portal's service user (V2-D1588 (1)): a quantity only within the line's
//! portal bounds, a cancellation only at the end of the term, and never on
//! another account's subscription. The audit event names the portal user.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::subscription::portal::{cancel_at_term_end, change_quantity};
use attome_billing::subscription::schedule::{Alignment, Cadence, Timing};
use attome_billing::subscription::service::{CreateSubscription, NewLine, Source, create};
use attome_testapp::TestApp;
use attome_types::AppError;
use chrono::{Duration, NaiveDate, Utc};
use rust_decimal::Decimal;
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

/// A yearly subscription of 10 seats started ten days ago, its line allowed
/// 5 to 20 seats on the portal; returns (account, subscription, line, end).
async fn subscribe(app: &TestApp) -> (Uuid, Uuid, Uuid, NaiveDate) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Seats Co') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let product: Uuid =
        sqlx::query_scalar("INSERT INTO product (name) VALUES ('Seat') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
        .await
        .unwrap();
    let start = Utc::now().date_naive() - Duration::days(10);
    let end = start + Duration::days(365);
    let id = create(
        &app.state,
        &ctx,
        CreateSubscription {
            name: "Seats".into(),
            account_ref: account,
            currency: "SAR".into(),
            start_date: start,
            end_date: Some(end),
            term_months: Some(12),
            frequency: Cadence::Monthly,
            timing: Timing::Advance,
            alignment: Alignment::Anniversary,
            source: Source::ByHand(vec![NewLine {
                product_ref: product,
                quantity: Decimal::from(10),
                unit_price: Decimal::from(100),
                charge_model: None,
            }]),
        },
    )
    .await
    .unwrap();
    let line: Uuid = sqlx::query_scalar(
        "UPDATE subscription_line SET portal_min_quantity = 5, portal_max_quantity = 20 \
          WHERE subscription_ref = $1 RETURNING id",
    )
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap();
    (account, id, line, end)
}

// feature: F3
#[test]
fn quantity_changes_only_within_bounds() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (account, id, line, _) = subscribe(&app).await;
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let over = change_quantity(
            &app.state,
            &service,
            "portal user p1",
            account,
            id,
            line,
            Decimal::from(50),
        )
        .await;
        assert!(matches!(over, Err(AppError::Validation(_))), "{over:?}");

        change_quantity(
            &app.state,
            &service,
            "portal user p1",
            account,
            id,
            line,
            Decimal::from(15),
        )
        .await
        .unwrap();
        let segments: i64 =
            sqlx::query_scalar("SELECT count(*) FROM subscription_segment WHERE line_ref = $1")
                .bind(line)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(
            segments, 2,
            "the segment in force closed and the next opened"
        );
    });
}

// feature: F3
// negative: POST /{keyword}/api/v1/billing/subscriptions/{id}/quantity
#[test]
fn other_account_is_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (_, id, line, _) = subscribe(&app).await;
        let other: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Someone else') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let changed = change_quantity(
            &app.state,
            &service,
            "portal user p2",
            other,
            id,
            line,
            Decimal::from(12),
        )
        .await;
        assert!(matches!(changed, Err(AppError::NotFound)), "{changed:?}");
        let cancelled =
            cancel_at_term_end(&app.state, &service, "portal user p2", other, id, "budget").await;
        assert!(
            matches!(cancelled, Err(AppError::NotFound)),
            "{cancelled:?}"
        );
    });
}

// feature: F3
// negative: POST /{keyword}/api/v1/billing/subscriptions/{id}/cancel
#[test]
fn cancel_is_term_end_only() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (account, id, _, end) = subscribe(&app).await;
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let bad =
            cancel_at_term_end(&app.state, &service, "portal user p3", account, id, "angry").await;
        assert!(matches!(bad, Err(AppError::Validation(_))), "{bad:?}");

        let ends = cancel_at_term_end(
            &app.state,
            &service,
            "portal user p3",
            account,
            id,
            "budget",
        )
        .await
        .unwrap();
        assert_eq!(ends, end);
        let status: Option<String> =
            sqlx::query_scalar("SELECT status::text FROM subscription WHERE id = $1")
                .bind(id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_ne!(
            status.as_deref(),
            Some("cancelled"),
            "it runs to the end of the term"
        );
        let named: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_ingest \
              WHERE payload->>'event_comment' LIKE '%on behalf of portal user p3%'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(named, 1, "the audit event names the portal user");
    });
}
