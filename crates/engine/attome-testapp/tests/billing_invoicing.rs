//! F4-T5: a draft invoice's lines are priced by the tax engine and its totals
//! summed from the rounded lines; an issued invoice is never recomputed.
//! F4-T6: issuing numbers a draft gap-free in its series, locks it and its
//! lines, and writes the ledger posting.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

async fn install(app: &TestApp, pack: &str) {
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

async fn invoice(app: &TestApp, status: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO invoice (id, invoice_number, status, currency, issued_date, is_active, row_version) \
         VALUES ($1, $2, $3, 'SAR', '2026-10-18', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(format!("T-{}", Uuid::now_v7().simple()))
    .bind(status)
    .fetch_one(app.db())
    .await
    .expect("insert invoice")
}

async fn line(
    app: &TestApp,
    invoice: Uuid,
    qty: &str,
    price: &str,
    discount: &str,
    category: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, discount, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Line', $3::numeric, $4::numeric, $5::numeric, $6, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(invoice)
    .bind(qty)
    .bind(price)
    .bind(discount)
    .bind(category)
    .fetch_one(app.db())
    .await
    .expect("insert line")
}

async fn text(app: &TestApp, sql: &str, id: Uuid) -> String {
    sqlx::query_scalar::<_, Option<String>>(sql)
        .bind(id)
        .fetch_one(app.db())
        .await
        .expect("read")
        .unwrap_or_default()
}

// feature: F4
#[test]
fn recompute_sets_line_and_invoice_totals() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in [
            "crm",
            "sales",
            "finance",
            "regions",
            "vendor-supplier",
            "contract-management",
            "billing",
        ] {
            install(&app, pack).await;
        }
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .expect("admin context");

        let draft = invoice(&app, "draft").await;
        let standard = line(&app, draft, "2", "100", "10", "standard").await;
        let exempt = line(&app, draft, "1", "50", "0", "exempt").await;

        let totals = attome_billing::invoice::recompute_draft(&app.state, &ctx, draft)
            .await
            .expect("recompute");
        assert_eq!(totals.lines, 2);
        assert_eq!(totals.net_total, "240");
        assert_eq!(totals.vat_total, "28.50");
        assert_eq!(totals.grand_total, "268.50");

        // Saudi standard VAT is 15%: 190 net, 28.50 VAT on the first line.
        let vat = |id| {
            text(
                &app,
                "SELECT vat_amount::text FROM invoice_line WHERE id = $1",
                id,
            )
        };
        assert_eq!(vat(standard).await.parse::<f64>().unwrap(), 28.5);
        assert_eq!(vat(exempt).await.parse::<f64>().unwrap(), 0.0);
        let grand = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            draft,
        )
        .await;
        assert_eq!(grand.parse::<f64>().unwrap(), 268.5);

        // A second recompute changes nothing.
        let version_before = text(
            &app,
            "SELECT row_version::text FROM invoice WHERE id = $1",
            draft,
        )
        .await;
        attome_billing::invoice::recompute_draft(&app.state, &ctx, draft)
            .await
            .expect("recompute again");
        let version_after = text(
            &app,
            "SELECT row_version::text FROM invoice WHERE id = $1",
            draft,
        )
        .await;
        assert_eq!(version_before, version_after);

        // An issued invoice keeps its totals.
        let issued = invoice(&app, "issued").await;
        line(&app, issued, "1", "10", "0", "standard").await;
        let refused = attome_billing::invoice::recompute_draft(&app.state, &ctx, issued).await;
        assert!(
            matches!(refused, Err(attome_types::AppError::Conflict(_))),
            "{refused:?}"
        );
    });
}

const PACKS: [&str; 7] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
];

/// A draft to `account` with no number yet, of `kind`, numbered in
/// `series` (the tests share one database, so each uses its own series).
async fn unnumbered(app: &TestApp, account: Uuid, kind: &str, series: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             series_key, is_active, row_version) \
         VALUES ($1, 'draft', $2, 'SAR', $3, 30, $4, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(kind)
    .bind(account)
    .bind(series)
    .fetch_one(app.db())
    .await
    .expect("insert draft")
}

async fn issue(app: &TestApp, invoice: Uuid) -> (StatusCode, serde_json::Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/billing/invoices/{invoice}/issue"),
        None,
    )
    .await
}

async fn buyer(app: &TestApp) -> Uuid {
    sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer') RETURNING id")
        .fetch_one(app.db())
        .await
        .expect("account")
}

// feature: F4
#[test]
fn issue_numbers_locks_and_posts() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .expect("admin context");
        let account = buyer(&app).await;
        let year = chrono::Utc::now().format("%Y").to_string();

        // A draft has no number; issuing gives the first of the series.
        let first = unnumbered(&app, account, "invoice", "TI").await;
        let first_line = line(&app, first, "2", "100", "0", "standard").await;
        let (status, body) = issue(&app, first).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "issued");
        assert_eq!(body["invoice_number"], format!("TI-{year}-000001"));
        let second = unnumbered(&app, account, "invoice", "TI").await;
        line(&app, second, "1", "10", "0", "standard").await;
        let (_, body) = issue(&app, second).await;
        assert_eq!(body["invoice_number"], format!("TI-{year}-000002"));
        // Another series numbers on its own.
        let credit = unnumbered(&app, account, "credit_note", "TICR").await;
        line(&app, credit, "1", "10", "0", "standard").await;
        let (_, body) = issue(&app, credit).await;
        assert_eq!(body["invoice_number"], format!("TICR-{year}-000001"));

        // Issued: dated, due after its terms, totals fixed, lines locked,
        // one posting written.
        let due = text(
            &app,
            "SELECT (due_date::date - issued_date::date)::text FROM invoice WHERE id = $1",
            first,
        )
        .await;
        assert_eq!(due, "30");
        let grand = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            first,
        )
        .await;
        assert_eq!(grand.parse::<f64>().unwrap(), 230.0);
        let locked: bool = sqlx::query_scalar("SELECT is_locked FROM invoice_line WHERE id = $1")
            .bind(first_line)
            .fetch_one(app.db())
            .await
            .expect("line");
        assert!(locked);
        let postings: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_posting_outbox \
             WHERE invoice_ref = $1 AND posting_kind = 'issue'",
        )
        .bind(first)
        .fetch_one(app.db())
        .await
        .expect("postings");
        assert_eq!(postings, 1);

        // Issuing twice is refused, and the issued invoice and its lines
        // refuse an edit through the generic write path.
        let (status, _) = issue(&app, first).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let version: i64 = sqlx::query_scalar("SELECT row_version FROM invoice WHERE id = $1")
            .bind(first)
            .fetch_one(app.db())
            .await
            .expect("version");
        let edit = attome_records::entity_crud::update_record_for(
            &app.state,
            &ctx,
            ctx.user_id,
            "invoice",
            first,
            version,
            json!({ "payment_terms_days": 60 }),
        )
        .await;
        assert!(edit.is_err(), "an issued invoice was edited: {edit:?}");
        let line_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM invoice_line WHERE id = $1")
                .bind(first_line)
                .fetch_one(app.db())
                .await
                .expect("line version");
        let edit = attome_records::entity_crud::update_record_for(
            &app.state,
            &ctx,
            ctx.user_id,
            "invoice_line",
            first_line,
            line_version,
            json!({ "quantity": 3 }),
        )
        .await;
        assert!(edit.is_err(), "a locked line was edited: {edit:?}");

        // Pro forma and an invoice without lines are never issued.
        let pro_forma = unnumbered(&app, account, "pro_forma", "TI").await;
        line(&app, pro_forma, "1", "10", "0", "standard").await;
        let (status, _) = issue(&app, pro_forma).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let empty = unnumbered(&app, account, "invoice", "TI").await;
        let (status, _) = issue(&app, empty).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: F4
#[test]
fn concurrent_issues_never_share_a_number() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let mut drafts = Vec::new();
        for _ in 0..4 {
            let draft = unnumbered(&app, account, "invoice", "TC").await;
            line(&app, draft, "1", "10", "0", "standard").await;
            drafts.push(draft);
        }
        // All four at once: each that wins the series lock takes the next
        // number, one that finds it held is refused with 409.
        let (a, b, c, d) = tokio::join!(
            issue(&app, drafts[0]),
            issue(&app, drafts[1]),
            issue(&app, drafts[2]),
            issue(&app, drafts[3]),
        );
        for (status, body) in [a, b, c, d] {
            assert!(
                status == StatusCode::OK || status == StatusCode::CONFLICT,
                "{status}: {body}"
            );
        }
        // The refused ones issue on retry.
        for &draft in &drafts {
            let still_draft = text(&app, "SELECT status FROM invoice WHERE id = $1", draft).await;
            if still_draft == "draft" {
                let (status, body) = issue(&app, draft).await;
                assert_eq!(status, StatusCode::OK, "{body}");
            }
        }
        let mut numbers: Vec<String> = sqlx::query_scalar(
            "SELECT invoice_number FROM invoice WHERE id = ANY($1) ORDER BY invoice_number",
        )
        .bind(&drafts)
        .fetch_all(app.db())
        .await
        .expect("numbers");
        numbers.dedup();
        let year = chrono::Utc::now().format("%Y").to_string();
        let expected: Vec<String> = (1..=4).map(|n| format!("TC-{year}-{n:06}")).collect();
        assert_eq!(numbers, expected);
    });
}
