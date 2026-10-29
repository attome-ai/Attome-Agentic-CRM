//! D6-T11: opportunity lines against a real database, with the CRM and
//! sales packs installed and the line, schedule and quote-sync switches on:
//! pricing, the deal's amount, the price list check, the deal's row version,
//! the engine owning its lines, the product picker, schedules, quote sync,
//! undo, and record access.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::changeset::Layer;
use attome_testapp::{TestApp, TestUser, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const PACKS: [&str; 2] = ["crm", "sales"];
const FLAGS: [&str; 3] = [
    "sales.opportunity_lines",
    "sales.schedules",
    "sales.quote_sync",
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
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for flag in FLAGS {
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/settings/feature.{flag}"),
                Some(json!({ "scope": "deployment", "value": { "deployment": true } })),
            )
            .await;
        assert!(status.is_success(), "{flag}: {status} {body}");
    }
}

/// A price list in SAR with two products on it, and a third product that
/// is on no list; a deal on the list.
struct Fixture {
    price_list: Uuid,
    product: Uuid,
    other_product: Uuid,
    unlisted: Uuid,
    account: Uuid,
    deal: Uuid,
}

async fn product(app: &TestApp, name: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO product (name, sku) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(format!("SKU-{}", Uuid::now_v7().simple()))
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn price_list(app: &TestApp, name: &str, valid_to: Option<&str>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO price_list (name, currency, valid_from, valid_to) \
         VALUES ($1, 'SAR', CURRENT_DATE - 30, $2::date) RETURNING id",
    )
    .bind(name)
    .bind(valid_to)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn list_item(app: &TestApp, list: Uuid, product: Uuid, price: &str) {
    sqlx::query(
        "INSERT INTO price_list_item (price_list_ref, product_ref, price, list_price) \
         VALUES ($1, $2, $3::numeric, $3::numeric)",
    )
    .bind(list)
    .bind(product)
    .bind(price)
    .execute(app.db())
    .await
    .unwrap();
}

async fn setup(app: &TestApp) -> Fixture {
    install(app).await;
    let tag = Uuid::now_v7().simple().to_string();
    let product_a = product(app, &format!("Licence {tag}")).await;
    let product_b = product(app, &format!("Support {tag}")).await;
    let unlisted = product(app, &format!("Unlisted {tag}")).await;
    let list = price_list(app, &format!("Standard {tag}"), None).await;
    list_item(app, list, product_a, "100").await;
    list_item(app, list, product_b, "250").await;
    let account: Uuid = sqlx::query_scalar("INSERT INTO account (name) VALUES ($1) RETURNING id")
        .bind(format!("Lines Co {tag}"))
        .fetch_one(app.db())
        .await
        .unwrap();
    let deal: Uuid = sqlx::query_scalar(
        "INSERT INTO opportunity (name, account_ref, stage, amount, currency, close_date, \
                                  price_list_ref, owner_ref) \
         VALUES ('Lines deal', $1, 'qualify', 5, 'SAR', CURRENT_DATE + 30, $2, $3) RETURNING id",
    )
    .bind(account)
    .bind(list)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    Fixture {
        price_list: list,
        product: product_a,
        other_product: product_b,
        unlisted,
        account,
        deal,
    }
}

/// The deal's row version, quoted for `If-Match`.
async fn version(app: &TestApp, deal: Uuid) -> String {
    let v: i64 = sqlx::query_scalar("SELECT row_version FROM opportunity WHERE id = $1")
        .bind(deal)
        .fetch_one(app.db())
        .await
        .unwrap();
    format!("\"{v}\"")
}

/// A decimal the API sends as a string or a number.
fn num(value: &Value) -> f64 {
    match value {
        Value::String(s) => s.parse().unwrap(),
        Value::Number(n) => n.as_f64().unwrap(),
        other => panic!("not a number: {other}"),
    }
}

async fn deal_column(app: &TestApp, deal: Uuid, column: &str) -> Option<f64> {
    let text: Option<String> = sqlx::query_scalar(&format!(
        "SELECT {column}::text FROM opportunity WHERE id = $1"
    ))
    .bind(deal)
    .fetch_one(app.db())
    .await
    .unwrap();
    text.map(|t| t.parse().unwrap())
}

async fn add_line(app: &TestApp, deal: Uuid, body: Value) -> (StatusCode, Value) {
    let v = version(app, deal).await;
    app.request_with(
        Method::POST,
        &format!("/api/v1/sales/opportunities/{deal}/lines"),
        &[("if-match", v.as_str())],
        Some(body),
    )
    .await
}

/// Adds `quantity` of `product` and returns the new line's id.
async fn line(app: &TestApp, deal: Uuid, product: Uuid, quantity: &str) -> Uuid {
    let (status, body) = add_line(
        app,
        deal,
        json!({ "product_ref": product, "quantity": quantity }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["line_id"].as_str().unwrap().parse().unwrap()
}

async fn line_total(app: &TestApp, line: Uuid) -> f64 {
    let text: String =
        sqlx::query_scalar("SELECT line_total::text FROM opportunity_line WHERE id = $1")
            .bind(line)
            .fetch_one(app.db())
            .await
            .unwrap();
    text.parse().unwrap()
}

// feature: D6
#[test]
fn add_line_sets_amount() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let (status, body) = add_line(
            &app,
            f.deal,
            json!({ "product_ref": f.product, "quantity": "3", "discount_percent": "10" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        // 3 x 100 less 10%.
        assert_eq!(num(&body["one_time_total"]), 270.0, "{body}");
        let line: Uuid = body["line_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(line_total(&app, line).await, 270.0);
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(270.0));
        let list_price: String =
            sqlx::query_scalar("SELECT list_price::text FROM opportunity_line WHERE id = $1")
                .bind(line)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(
            list_price.parse::<f64>().unwrap(),
            100.0,
            "from the price list"
        );
    });
}

// feature: D6
// negative: PATCH /api/v1/{entity}/{id}
#[test]
fn amount_locked_with_lines() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        line(&app, f.deal, f.product, "2").await;
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(200.0));

        // The totals are the engine's: an ordinary update cannot set them.
        let v = version(&app, f.deal).await;
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/opportunity/{}", f.deal),
                &[("if-match", v.as_str())],
                Some(json!({ "one_time_total": 1 })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // A hand edit of the amount holds only until the next line change.
        let v = version(&app, f.deal).await;
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/opportunity/{}", f.deal),
                &[("if-match", v.as_str())],
                Some(json!({ "amount": 999 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(999.0));
        line(&app, f.deal, f.other_product, "1").await;
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(450.0));
    });
}

// feature: D6
// negative: POST /api/v1/sales/opportunities/{id}/lines
#[test]
fn product_not_on_price_list_422() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let (status, body) = add_line(&app, f.deal, json!({ "product_ref": f.unlisted })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.to_string().contains("product_not_on_price_list"),
            "{body}"
        );
        let lines: i64 =
            sqlx::query_scalar("SELECT count(*) FROM opportunity_line WHERE opportunity_ref = $1")
                .bind(f.deal)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(lines, 0, "nothing was written");
    });
}

// feature: D6
// negative: POST /api/v1/sales/opportunities/{id}/lines
#[test]
fn concurrent_edit_409() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let stale = version(&app, f.deal).await;
        line(&app, f.deal, f.product, "1").await;
        let (status, body) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{}/lines", f.deal),
                &[("if-match", stale.as_str())],
                Some(json!({ "product_ref": f.other_product })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        // Without If-Match at all: the caller's error.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{}/lines", f.deal),
                Some(json!({ "product_ref": f.other_product })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: D6
// negative: POST /api/v1/{entity}
#[test]
fn generic_crud_cannot_write_line() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/opportunity_line",
                Some(json!({ "opportunity_ref": f.deal, "product_ref": f.product, "quantity": 1 })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.to_string().contains("owning engine"), "{body}");
    });
}

// feature: D6
#[test]
fn picker_filters_by_price_list_and_date() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let ids = |page: &Value| -> Vec<String> {
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["product_id"].as_str().unwrap().to_owned())
                .collect()
        };
        let (status, page) = app
            .request(
                Method::GET,
                &format!("/api/v1/sales/price-lists/{}/products", f.price_list),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let listed = ids(&page);
        assert!(listed.contains(&f.product.to_string()), "{page}");
        assert!(listed.contains(&f.other_product.to_string()), "{page}");
        assert!(!listed.contains(&f.unlisted.to_string()), "{page}");

        // A list that ended yesterday offers its products only on a day it
        // was valid.
        let ended = price_list(&app, &format!("Old {}", f.deal), Some("yesterday")).await;
        list_item(&app, ended, f.unlisted, "10").await;
        let on = |day: &str| format!("/api/v1/sales/price-lists/{ended}/products?on={day}");
        let today = chrono::Utc::now().date_naive();
        let (status, page) = app
            .request(Method::GET, &on(&today.to_string()), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(ids(&page).is_empty(), "{page}");
        let earlier = today - chrono::Days::new(5);
        let (status, page) = app
            .request(Method::GET, &on(&earlier.to_string()), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(ids(&page), vec![f.unlisted.to_string()], "{page}");
    });
}

async fn schedule(app: &TestApp, line: Uuid, body: Value) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/sales/opportunity-lines/{line}/schedule"),
        Some(body),
    )
    .await
}

// feature: D6
#[test]
fn schedule_even_spread() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let line = line(&app, f.deal, f.product, "10").await;
        let (status, body) = schedule(
            &app,
            line,
            json!({ "method": "even", "start": "2026-01-01", "months": 3 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let revenue: Vec<f64> = body["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| num(&r["revenue"]))
            .collect();
        // 1,000 over three months: the remainder goes to the last row.
        assert_eq!(revenue, vec![333.33, 333.33, 333.34], "{body}");
        assert_eq!(body["rows"][2]["period_start"], "2026-03-01", "{body}");
    });
}

// feature: D6
// negative: POST /api/v1/sales/opportunity-lines/{line_id}/schedule
#[test]
fn schedule_manual_must_sum() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let line = line(&app, f.deal, f.product, "1").await;
        let rows = |second: &str| {
            json!({ "method": "manual", "rows": [
                { "period_start": "2026-01-01", "revenue": "60" },
                { "period_start": "2026-02-01", "revenue": second },
            ] })
        };
        let (status, body) = schedule(&app, line, rows("30")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, body) = schedule(&app, line, rows("40")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 2, "{body}");
    });
}

// feature: D6
#[test]
fn shift_moves_rows() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let line = line(&app, f.deal, f.product, "3").await;
        let (status, body) = schedule(
            &app,
            line,
            json!({ "method": "even", "start": "2026-01-01", "months": 3 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{}/schedules/shift", f.deal),
                Some(json!({ "months": 2 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows_shifted"], 3, "{body}");
        assert_eq!(body["queued"], false, "{body}");
        let starts: Vec<String> = sqlx::query_scalar(
            "SELECT period_start::date::text FROM opportunity_line_schedule \
             WHERE line_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY period_start",
        )
        .bind(line)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(starts, vec!["2026-03-01", "2026-04-01", "2026-05-01"]);
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{}/schedules/shift", f.deal),
                Some(json!({ "months": 0 })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

/// A primary quote on the deal with one line of `quantity` x 100.
async fn primary_quote(app: &TestApp, f: &Fixture, quantity: i64) -> (Uuid, Uuid) {
    let quote: Uuid = sqlx::query_scalar(
        "INSERT INTO quote (name, account_ref, currency, opportunity_ref, is_primary) \
         VALUES ('Lines quote', $1, 'SAR', $2, true) RETURNING id",
    )
    .bind(f.account)
    .bind(f.deal)
    .fetch_one(app.db())
    .await
    .unwrap();
    let quote_line: Uuid = sqlx::query_scalar(
        "INSERT INTO quote_line (quote_ref, product_ref, quantity, unit_price, line_total) \
         VALUES ($1, $2, $3, 100, $3 * 100) RETURNING id",
    )
    .bind(quote)
    .bind(f.product)
    .bind(quantity)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query("UPDATE opportunity SET primary_quote_ref = $2 WHERE id = $1")
        .bind(f.deal)
        .bind(quote)
        .execute(app.db())
        .await
        .unwrap();
    (quote, quote_line)
}

async fn sync(app: &TestApp, deal: Uuid) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/sales/opportunities/{deal}/sync"),
        Some(json!({ "direction": "from_quote" })),
    )
    .await
}

// feature: D6
#[test]
fn sync_from_primary_quote() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let (_, quote_line) = primary_quote(&app, &f, 4).await;
        let (status, body) = sync(&app, f.deal).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "synced", "{body}");
        assert!(body["snapshot_id"].is_string(), "{body}");
        let synced: Vec<(Option<Uuid>, String)> = sqlx::query_as(
            "SELECT source_quote_line_ref, quantity::text FROM opportunity_line \
             WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(f.deal)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(synced.len(), 1, "{synced:?}");
        assert_eq!(synced[0].0, Some(quote_line));
        assert_eq!(synced[0].1.parse::<f64>().unwrap(), 4.0);
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(400.0));
        // Nothing changed since: in sync.
        let (status, body) = sync(&app, f.deal).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "in_sync", "{body}");
    });
}

// feature: D6
// negative: POST /api/v1/sales/opportunities/{id}/sync
#[test]
fn sync_both_changed_409() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let (_, quote_line) = primary_quote(&app, &f, 2).await;
        let (status, body) = sync(&app, f.deal).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The deal gains a line, and the quote's line changes too.
        line(&app, f.deal, f.other_product, "1").await;
        sqlx::query("UPDATE quote_line SET quantity = 5, line_total = 500 WHERE id = $1")
            .bind(quote_line)
            .execute(app.db())
            .await
            .unwrap();
        let (status, body) = sync(&app, f.deal).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["status"], "sync_both_changed", "{body}");
        assert_eq!(body["deal_lines"].as_array().unwrap().len(), 2, "{body}");
        assert_eq!(body["quote_lines"].as_array().unwrap().len(), 1, "{body}");
        // Forced, the quote's lines win.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{}/sync", f.deal),
                Some(json!({ "direction": "from_quote", "force": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(500.0));
    });
}

async fn deal_discount(app: &TestApp, deal: Uuid, percent: &str) -> Value {
    let v = version(app, deal).await;
    let (status, body) = app
        .request_with(
            Method::POST,
            &format!("/api/v1/sales/opportunities/{deal}/deal-discount"),
            &[("if-match", v.as_str())],
            Some(json!({ "percent": percent })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

// feature: D6
#[test]
fn undo_deal_discount() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let line = line(&app, f.deal, f.product, "2").await;
        let body = deal_discount(&app, f.deal, "10").await;
        assert_eq!(num(&body["one_time_total"]), 180.0, "{body}");
        assert_eq!(line_total(&app, line).await, 180.0);
        let snapshot = body["snapshot_id"].as_str().unwrap().to_owned();

        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/undo/{snapshot}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["lines_restored"], 1, "{body}");
        // The deal discount is gone with it, so the lines are back at full
        // price, not discounted again.
        assert_eq!(
            deal_column(&app, f.deal, "deal_discount_percent").await,
            None
        );
        assert_eq!(
            deal_column(&app, f.deal, "one_time_total").await,
            Some(200.0)
        );
        assert_eq!(deal_column(&app, f.deal, "amount").await, Some(200.0));
        // Once only.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/undo/{snapshot}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: D6
// negative: POST /api/v1/sales/undo/{snapshot_id}
#[test]
fn undo_refused_after_edit() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        let line = line(&app, f.deal, f.product, "2").await;
        let body = deal_discount(&app, f.deal, "10").await;
        let snapshot = body["snapshot_id"].as_str().unwrap().to_owned();

        // A line changes after the discount.
        let v = version(&app, f.deal).await;
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/sales/opportunities/{}/lines/{line}", f.deal),
                &[("if-match", v.as_str())],
                Some(json!({ "quantity": "3" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/undo/{snapshot}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        // Nothing was put back: the edited, discounted line stays.
        assert_eq!(line_total(&app, line).await, 270.0);
    });
}

/// A user whose one role may read and update deals, but only their own
/// (record access level 0).
async fn own_deals_only(app: &TestApp, label: &str) -> TestUser {
    let (status, role) = app
        .request(
            Method::POST,
            "/api/v1/admin/security/roles",
            Some(json!({ "name": format!("d6-{label}-{}", Uuid::now_v7().simple()) })),
        )
        .await;
    assert!(status.is_success(), "{status} {role}");
    let role_id = role["id"].as_str().unwrap().to_owned();
    for key in ["opportunity.read", "opportunity.update"] {
        attome_security::db::ensure_privilege(app.db(), key, key, "test", Layer::Project)
            .await
            .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/role-grants",
                Some(json!({ "role_id": role_id, "privilege_key": key })),
            )
            .await;
        assert!(status.is_success(), "{key}: {status} {body}");
    }
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/security/role-entity-access",
            Some(json!({ "role_id": role_id, "entity": "opportunity", "read_access_level": 0 })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    let user = seed_user(app.db(), label).await;
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2::uuid)")
        .bind(user.id)
        .bind(&role_id)
        .execute(app.db())
        .await
        .unwrap();
    app.state
        .base
        .security
        .invalidate_sync(user.id)
        .await
        .unwrap();
    user
}

// feature: D6
// negative: GET /api/v1/sales/opportunities/{id}/lines
#[test]
fn user_without_opportunity_read_gets_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let f = setup(&app).await;
        line(&app, f.deal, f.product, "1").await;
        let outsider = own_deals_only(&app, "d6-outsider").await;
        let path = format!("/api/v1/sales/opportunities/{}/lines", f.deal);
        let (status, body) = app
            .request_as(&outsider.cookie, Method::GET, &path, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(!body.to_string().contains("Licence"), "{body}");
        // The owner reads them.
        let (status, body) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    });
}
