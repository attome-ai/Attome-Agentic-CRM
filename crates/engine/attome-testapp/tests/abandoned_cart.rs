//! F8-T9: an idle cart whose buyer consented to marketing makes one
//! `cart.abandoned` event however often the sweep runs; one without consent
//! makes none.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::abandoned_cart::sweep;
use attome_testapp::TestApp;
use axum::http::Method;
use serde_json::{Value, json};
use uuid::Uuid;

const PACKS: [&str; 2] = ["crm", "sales"];

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

async fn set(app: &TestApp, key: &str, value: Value) {
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/api/v1/admin/settings/{key}"),
            Some(json!({ "scope": "deployment", "value": value })),
        )
        .await;
    assert!(status.is_success(), "{key}: {status} {body}");
}

/// A portal buyer's contact with an open cart of one line, last changed two
/// hours ago; the contact.
async fn idle_cart(app: &TestApp) -> Uuid {
    let contact: Uuid = sqlx::query_scalar(
        "INSERT INTO contact (full_name, email) VALUES ('Sara', 'sara@example.com') RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    let portal: Uuid =
        sqlx::query_scalar("INSERT INTO webportal (name, keyword, portal_type) VALUES ('Shop', $1, 'authenticated') RETURNING id")
            .bind(format!("shop{}", Uuid::now_v7().simple()))
            .fetch_one(app.db())
            .await
            .unwrap();
    let user: Uuid = sqlx::query_scalar(
        "INSERT INTO webportal_user (name, webportal_ref, status, contact_ref) \
         VALUES ('Sara', $1, 'active', $2) RETURNING id",
    )
    .bind(portal)
    .bind(contact)
    .fetch_one(app.db())
    .await
    .unwrap();
    let cart = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO commerce_cart (id, portal_user_id, account_id, updated_at) \
         VALUES ($1, $2, $3, now() - interval '2 hours')",
    )
    .bind(cart)
    .bind(user)
    .bind(Uuid::now_v7())
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO commerce_cart_line (cart_id, product_id, quantity) VALUES ($1, $2, 1)",
    )
    .bind(cart)
    .bind(Uuid::now_v7())
    .execute(app.db())
    .await
    .unwrap();
    contact
}

async fn events(app: &TestApp, contact: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM entity_change_event \
          WHERE event_name = 'cart.abandoned' AND record_id = $1",
    )
    .bind(contact)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: F8
#[test]
fn cart_without_consent_emits_nothing() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let contact = idle_cart(&app).await;
        // Off: nothing at all.
        assert_eq!(sweep(&app.state).await.unwrap().emitted, 0);
        set(&app, "commerce.abandoned_cart.enabled", json!(true)).await;
        let swept = sweep(&app.state).await.unwrap();
        assert_eq!((swept.emitted, swept.no_consent), (0, 1));
        assert_eq!(events(&app, contact).await, 0);
    });
}

// feature: F8
#[test]
fn consenting_cart_emits_once_across_two_sweeps() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set(&app, "commerce.abandoned_cart.enabled", json!(true)).await;
        let contact = idle_cart(&app).await;
        let known: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM audit_consent_purpose WHERE key = 'marketing' LIMIT 1",
        )
        .fetch_optional(app.db())
        .await
        .unwrap();
        let purpose: Uuid = match known {
            Some(id) => id,
            None => sqlx::query_scalar(
                "INSERT INTO audit_consent_purpose (key, lawful_basis, is_active) \
                 VALUES ('marketing', 'consent', TRUE) RETURNING id",
            )
            .fetch_one(app.db())
            .await
            .unwrap(),
        };
        sqlx::query(
            "INSERT INTO audit_consent (purpose_ref, regarding_entity, regarding_id, \
                 subject_reference, status, granted_at, source) \
             VALUES ($1, 'contact', $2, $2, 'granted', now(), 'api')",
        )
        .bind(purpose)
        .bind(contact.to_string())
        .execute(app.db())
        .await
        .unwrap();

        assert_eq!(sweep(&app.state).await.unwrap().emitted, 1);
        assert_eq!(
            sweep(&app.state).await.unwrap().emitted,
            0,
            "marked: not again"
        );
        assert_eq!(events(&app, contact).await, 1);
    });
}
