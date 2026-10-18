//! F5-T14: a saved card's token is returned to no role, and a payment's
//! gateway reference and fee only to finance managers.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
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

/// Every key anywhere in a JSON value.
fn keys(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k.clone());
                keys(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| keys(v, out)),
        _ => {}
    }
}

fn has_key(value: &Value, key: &str) -> bool {
    let mut all = Vec::new();
    keys(value, &mut all);
    all.iter().any(|k| k == key)
}

// feature: F5
#[test]
fn payment_token_never_returned() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Card holder') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let method = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO saved_payment_method (id, account_ref, gateway_system_ref, token, brand, \
                 last4, is_default, is_active, row_version) \
             VALUES ($1, $2, 'gw', 'tok_very_secret', 'visa', '4242', true, true, 0)",
        )
        .bind(method)
        .bind(account)
        .execute(app.db())
        .await
        .unwrap();
        let payment = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO customer_payment (id, name, payer_account_ref, amount, fee, currency, \
                 method, status, gateway_system_ref, gateway_reference, unallocated, is_active, \
                 row_version) \
             VALUES ($1, 'Card', $2, 10, 0.23, 'SAR', 'card', 'succeeded', 'gw', 'ref_finance', 0, \
                 true, 0)",
        )
        .bind(payment)
        .bind(account)
        .execute(app.db())
        .await
        .unwrap();

        let finance = user_with_role(&app, "finance", "Finance Manager").await;
        let receivable = user_with_role(&app, "receivable", "Accounts Receivable").await;

        // The token: no role reads it, the finance manager included.
        for user in [&finance, &receivable] {
            let (status, body) = app
                .request_as(
                    &user.cookie,
                    Method::GET,
                    &format!("/api/v1/saved_payment_method/{method}"),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert!(!has_key(&body, "token"), "{body}");
            assert!(!body.to_string().contains("tok_very_secret"), "{body}");
            assert!(
                body.to_string().contains("4242"),
                "the last four are shown: {body}"
            );
        }

        // The gateway's reference and fee: the finance manager only.
        let (status, body) = app
            .request_as(
                &finance.cookie,
                Method::GET,
                &format!("/api/v1/customer_payment/{payment}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().contains("ref_finance"), "{body}");
        let (status, body) = app
            .request_as(
                &receivable.cookie,
                Method::GET,
                &format!("/api/v1/customer_payment/{payment}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.to_string().contains("ref_finance"), "{body}");
        assert!(!has_key(&body, "fee"), "{body}");
    });
}
