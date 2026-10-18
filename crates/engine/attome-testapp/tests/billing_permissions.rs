//! F4-T17: invoicing's permission and negative paths, through the HTTP
//! stack as people who are not administrators. Its own test binary, so its
//! own database: the tax-rate test changes the Saudi rate.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::json;
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
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                    .expect("pack changeset JSON");
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn account(app: &TestApp, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (name, owner_ref, owner_type) VALUES ('Buyer', $1, 0) RETURNING id",
    )
    .bind(owner)
    .fetch_one(app.db())
    .await
    .expect("account")
}

/// A draft to `account` with one standard-rated line of `net`.
async fn draft(app: &TestApp, account: Uuid, net: &str) -> Uuid {
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, 30, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .fetch_one(app.db())
    .await
    .expect("draft");
    sqlx::query(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Line', 1, $3::numeric, 'standard', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(invoice)
    .bind(net)
    .execute(app.db())
    .await
    .expect("line");
    invoice
}

async fn issue_as(app: &TestApp, cookie: &str, invoice: Uuid) -> (StatusCode, serde_json::Value) {
    app.request_as(
        cookie,
        Method::POST,
        &format!("/api/v1/billing/invoices/{invoice}/issue"),
        None,
    )
    .await
}

async fn text(app: &TestApp, sql: &str, id: Uuid) -> String {
    sqlx::query_scalar::<_, Option<String>>(sql)
        .bind(id)
        .fetch_one(app.db())
        .await
        .expect("read")
        .unwrap_or_default()
}

/// A user holding the named role.
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

/// A role with `privileges`, reading accounts at team depth with the owner
/// arm on: the user's own accounts (and what is shared with them) only.
async fn own_accounts_role(app: &TestApp, privileges: &[&str]) -> String {
    let name = format!("Own accounts {}", Uuid::now_v7().simple());
    let role: Uuid = sqlx::query_scalar(
        "INSERT INTO role (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
    )
    .bind(&name)
    .fetch_one(app.db())
    .await
    .expect("role");
    for key in privileges {
        sqlx::query(
            "INSERT INTO role_mm_privilege (role_ref, privilege_ref, owner_layer) \
             SELECT $1, id, 'customer' FROM privilege WHERE key = $2",
        )
        .bind(role)
        .bind(key)
        .execute(app.db())
        .await
        .expect("grant privilege");
    }
    let account_entity: Uuid =
        sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'account'")
            .fetch_one(app.db())
            .await
            .expect("account entity");
    sqlx::query(
        "INSERT INTO role_mm_entity_access (role_ref, entity_ref, read_access_level, \
             write_access_level, delete_access_level, read_owner_visible, owner_layer) \
         VALUES ($1, $2, 1, 1, 1, true, 'customer')",
    )
    .bind(role)
    .bind(account_entity)
    .execute(app.db())
    .await
    .expect("entity access");
    name
}

// feature: F4
#[test]
fn clerk_cannot_issue_without_privilege() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let clerk = user_with_role(&app, "clerk", "Billing Clerk").await;
        let buyer = account(&app, app.admin.id).await;
        let invoice = draft(&app, buyer, "100").await;

        let (status, body) = issue_as(&app, &clerk.cookie, invoice).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let number = text(
            &app,
            "SELECT invoice_number FROM invoice WHERE id = $1",
            invoice,
        )
        .await;
        assert!(number.is_empty(), "a refused issue took a number: {number}");
        let status = text(&app, "SELECT status FROM invoice WHERE id = $1", invoice).await;
        assert_eq!(status, "draft");

        // Accounts Receivable holds billing.issue and issues it.
        let receivable = user_with_role(&app, "receivable", "Accounts Receivable").await;
        let (status, body) = issue_as(&app, &receivable.cookie, invoice).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // A clerk may not write off or credit either.
        for path in ["write-off", "credit-notes", "cancel"] {
            let (status, _) = app
                .request_as(
                    &clerk.cookie,
                    Method::POST,
                    &format!("/api/v1/billing/invoices/{invoice}/{path}"),
                    Some(json!({ "amount": 1, "reason": "No", "lines": [] })),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        }
    });
}

// feature: F4
#[test]
fn sales_user_reads_only_own_accounts_invoices() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let role = own_accounts_role(&app, &["account.read", "invoice.read"]).await;
        let seller = user_with_role(&app, "seller", &role).await;
        let mine = account(&app, seller.id).await;
        let theirs = account(&app, app.admin.id).await;
        for buyer in [mine, theirs] {
            let invoice = draft(&app, buyer, "100").await;
            let (status, body) = issue_as(&app, &app.admin.cookie, invoice).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }

        // The ageing lists only the seller's account.
        let (status, body) = app
            .request_as(
                &seller.cookie,
                Method::GET,
                "/api/v1/billing/ageing?page_size=200",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let accounts: Vec<&serde_json::Value> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| &i["account_id"])
            .collect();
        assert!(accounts.contains(&&json!(mine)), "{body}");
        assert!(!accounts.contains(&&json!(theirs)), "{body}");

        // Their own statement reads; another's is not found.
        for (account, expected) in [(mine, StatusCode::OK), (theirs, StatusCode::NOT_FOUND)] {
            let (status, body) = app
                .request_as(
                    &seller.cookie,
                    Method::GET,
                    &format!("/api/v1/billing/accounts/{account}/statement?from=2000-01-01"),
                    None,
                )
                .await;
            assert_eq!(status, expected, "{body}");
        }

        // Reading is not changing: no update privilege, no recompute.
        let invoice = draft(&app, mine, "50").await;
        let (status, _) = app
            .request_as(
                &seller.cookie,
                Method::POST,
                &format!("/api/v1/billing/invoices/{invoice}/recompute"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

// feature: F4
#[test]
fn tax_rate_change_does_not_alter_issued_invoice() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let buyer = account(&app, app.admin.id).await;
        let issued = draft(&app, buyer, "100").await;
        let (status, body) = issue_as(&app, &app.admin.cookie, issued).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let grand_before = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            issued,
        )
        .await;
        assert_eq!(grand_before.parse::<f64>().unwrap(), 115.0);

        // A new Saudi standard rate from today.
        let rate: Uuid = sqlx::query_scalar(
            "INSERT INTO region_tax_rate (id, country_code, category, rate, effective_from, \
                 is_active, row_version) \
             VALUES ($1, 'SA', 'standard', 20, CURRENT_DATE, true, 0) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .fetch_one(app.db())
        .await
        .expect("new rate");
        attome_billing::invoice::tax_rates().invalidate().await;

        // A draft takes the new rate; the issued invoice keeps its totals
        // and refuses a recompute.
        let other = draft(&app, buyer, "100").await;
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{other}/recompute"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["grand_total"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .unwrap(),
            120.0
        );
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{issued}/recompute"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let grand_after = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            issued,
        )
        .await;
        assert_eq!(grand_after, grand_before);

        // Leave the rates as they were for a second run.
        sqlx::query("DELETE FROM region_tax_rate WHERE id = $1")
            .bind(rate)
            .execute(app.db())
            .await
            .expect("remove the rate");
        attome_billing::invoice::tax_rates().invalidate().await;
    });
}
