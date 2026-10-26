//! F4-T5: a draft invoice's lines are priced by the tax engine and its totals
//! summed from the rounded lines; an issued invoice is never recomputed.
//! F4-T6: issuing numbers a draft gap-free in its series, locks it and its
//! lines, and writes the ledger posting.
//! F4-T7: credit and debit notes correct an issued invoice; cancelling is a
//! full credit note, issued at once.
//! F4-T8: a deposit is deducted once; a pro forma is converted, never issued.
//! F4-T9: invoice requests become drafts once; schedules run once a period.
//! F4-T10: payment status follows payments and the due date, never a hand edit.
//! F4-T11: statements and receivables ageing.
//! F4-T12: write-offs, with an approval above the threshold.

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

/// An issued invoice of one line, `qty` at 100 SAR.
async fn issued_invoice(app: &TestApp, account: Uuid, qty: &str, series: &str) -> (Uuid, Uuid) {
    let draft = unnumbered(app, account, "invoice", series).await;
    let line_id = line(app, draft, qty, "100", "0", "standard").await;
    let (status, body) = issue(app, draft).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (draft, line_id)
}

// feature: F4
// negative: POST /api/v1/billing/invoices/{id}/credit-notes
#[test]
fn credit_more_than_issued_is_422() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let (original, original_line) = issued_invoice(&app, account, "5", "TN").await;
        let credit = |qty: f64, reason: &str| json!({ "lines": [{ "line_id": original_line, "quantity": qty }], "reason": reason });
        let path = format!("/api/v1/billing/invoices/{original}/credit-notes");

        // Two of five credited: a draft credit note with the line negated.
        let (status, body) = app
            .request(Method::POST, &path, Some(credit(2.0, "Returned")))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["kind"], "credit_note");
        let note: Uuid = body["note_id"].as_str().unwrap().parse().unwrap();
        let grand = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            note,
        )
        .await;
        assert_eq!(grand.parse::<f64>().unwrap(), -230.0);
        let link = text(
            &app,
            "SELECT original_invoice_ref::text FROM invoice WHERE id = $1",
            note,
        )
        .await;
        assert_eq!(link, original.to_string());

        // Four more would credit six of five: refused, naming the line.
        let (status, body) = app
            .request(Method::POST, &path, Some(credit(4.0, "Again")))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.to_string().contains(&original_line.to_string()),
            "{body}"
        );
        // No reason, refused.
        let (status, _) = app
            .request(Method::POST, &path, Some(credit(1.0, " ")))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // A draft is not corrected by a note.
        let draft = unnumbered(&app, account, "invoice", "TN").await;
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{draft}/credit-notes"),
                Some(credit(1.0, "No")),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // A debit note adds a positive charge.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{original}/debit-notes"),
                Some(json!({
                    "lines": [{ "description": "Freight", "quantity": 1, "unit_price": 20 }],
                    "reason": "Freight was not billed",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let debit: Uuid = body["note_id"].as_str().unwrap().parse().unwrap();
        let grand = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            debit,
        )
        .await;
        assert_eq!(grand.parse::<f64>().unwrap(), 23.0);
    });
}

// feature: F4
// negative: POST /api/v1/billing/invoices/{id}/cancel
#[test]
fn cancel_issues_full_credit_note() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let (original, original_line) = issued_invoice(&app, account, "3", "TX").await;
        // One of three already credited (and issued): the cancel credits two.
        let (_, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{original}/credit-notes"),
                Some(json!({
                    "lines": [{ "line_id": original_line, "quantity": 1 }],
                    "reason": "Damaged",
                })),
            )
            .await;
        let partial: Uuid = body["note_id"].as_str().unwrap().parse().unwrap();
        let (status, body) = issue(&app, partial).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let partial_number = body["invoice_number"].as_str().unwrap().to_owned();

        let cancel = format!("/api/v1/billing/invoices/{original}/cancel");
        let (status, body) = app
            .request(
                Method::POST,
                &cancel,
                Some(json!({ "reason": "Order cancelled" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "issued");
        // Credit notes share the CRN series: the next number after the
        // partial credit's.
        let year = chrono::Utc::now().format("%Y").to_string();
        let number = body["invoice_number"].as_str().unwrap();
        assert!(number.starts_with(&format!("CRN-{year}-")), "{number}");
        assert!(
            number > partial_number.as_str(),
            "{number} after {partial_number}"
        );
        let note: Uuid = body["note_id"].as_str().unwrap().parse().unwrap();
        let quantity = text(
            &app,
            "SELECT quantity::text FROM invoice_line WHERE invoice_ref = $1",
            note,
        )
        .await;
        assert_eq!(quantity.parse::<f64>().unwrap(), -2.0);

        // Nothing is left to cancel.
        let (status, _) = app
            .request(Method::POST, &cancel, Some(json!({ "reason": "Again" })))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: F4
// negative: POST /api/v1/billing/invoices/{id}/apply-deposit
#[test]
fn deposit_is_deducted_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        // A deposit of 100 net (115 with VAT), issued.
        let deposit = unnumbered(&app, account, "deposit", "TD").await;
        line(&app, deposit, "1", "100", "0", "standard").await;
        let (status, body) = issue(&app, deposit).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let deposit_number = body["invoice_number"].as_str().unwrap().to_owned();

        // The final invoice of 400 net: 300 net and 345 due after the deposit.
        let app = &app;
        let apply = |invoice: Uuid| {
            let path = format!("/api/v1/billing/invoices/{invoice}/apply-deposit");
            let body = json!({ "deposit_invoice_id": deposit });
            async move { app.request(Method::POST, &path, Some(body)).await }
        };
        let first = unnumbered(app, account, "invoice", "TD").await;
        line(app, first, "4", "100", "0", "standard").await;
        let (status, body) = apply(first).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["lines"], 1);
        assert_eq!(
            body["grand_total"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .unwrap(),
            345.0
        );
        let label = text(
            app,
            "SELECT description FROM invoice_line WHERE invoice_ref = $1 AND source_kind = 'deposit'",
            first,
        )
        .await;
        assert_eq!(label, format!("Deposit {deposit_number}"));

        // Twice on the same invoice, or on another, is refused.
        let (status, _) = apply(first).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let second = unnumbered(app, account, "invoice", "TD").await;
        line(app, second, "1", "100", "0", "standard").await;
        let (status, _) = apply(second).await;
        assert_eq!(status, StatusCode::CONFLICT);
        // A draft deposit is not deducted.
        let draft_deposit = unnumbered(app, account, "deposit", "TD").await;
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{second}/apply-deposit"),
                Some(json!({ "deposit_invoice_id": draft_deposit })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, body) = issue(app, first).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}

// feature: F4
// negative: POST /api/v1/billing/invoices/{id}/convert-pro-forma
#[test]
fn pro_forma_cannot_be_issued() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let pro_forma = unnumbered(&app, account, "pro_forma", "TP").await;
        line(&app, pro_forma, "2", "50", "0", "standard").await;
        let (status, _) = issue(&app, pro_forma).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let number = text(
            &app,
            "SELECT invoice_number FROM invoice WHERE id = $1",
            pro_forma,
        )
        .await;
        assert!(number.is_empty(), "a pro forma took a number: {number}");

        // Converting makes a priced draft invoice with the same lines.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{pro_forma}/convert-pro-forma"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["lines"], 1);
        let invoice: Uuid = body["invoice_id"].as_str().unwrap().parse().unwrap();
        let kind = text(&app, "SELECT kind FROM invoice WHERE id = $1", invoice).await;
        assert_eq!(kind, "invoice");
        let grand = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            invoice,
        )
        .await;
        assert_eq!(grand.parse::<f64>().unwrap(), 115.0);
        let (status, body) = issue(&app, invoice).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Converting an invoice that is not pro forma is refused.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{invoice}/convert-pro-forma"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

async fn request(
    app: &TestApp,
    key: &str,
    account: Uuid,
    price: u32,
) -> (StatusCode, serde_json::Value) {
    app.request(
        Method::POST,
        "/api/v1/billing/invoice-requests",
        Some(json!({
            "source_kind": "order",
            "source_ref": key,
            "idempotency_key": key,
            "account_ref": account,
            "currency": "SAR",
            "request_date": "2026-10-18",
            "lines": [{ "description": "Goods", "quantity": 1, "unit_price": price }],
        })),
    )
    .await
}

async fn invoices_of(app: &TestApp, request_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT invoice_ref) FROM invoice_line \
         WHERE source_kind = 'request' AND source_ref LIKE $1",
    )
    .bind(format!("{request_id}:%"))
    .fetch_one(app.db())
    .await
    .expect("count")
}

// feature: F4
#[test]
fn repeated_request_creates_one_invoice() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let key = format!("SO-{}", Uuid::now_v7().simple());
        let (status, first) = request(&app, &key, account, 100).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["created"], true);
        let (_, again) = request(&app, &key, account, 100).await;
        assert_eq!(again["created"], false);
        assert_eq!(again["request_id"], first["request_id"]);
        let id = first["request_id"].as_str().unwrap().to_owned();

        attome_billing::requests::process_pending(&app.state)
            .await
            .expect("sweep");
        attome_billing::requests::process_pending(&app.state)
            .await
            .expect("sweep again");
        assert_eq!(invoices_of(&app, &id).await, 1);
        let (_, after) = request(&app, &key, account, 100).await;
        assert_eq!(after["status"], "invoiced", "{after}");
        let invoice: Uuid = after["invoice_id"].as_str().unwrap().parse().unwrap();
        let grand = text(
            &app,
            "SELECT grand_total::text FROM invoice WHERE id = $1",
            invoice,
        )
        .await;
        assert_eq!(grand.parse::<f64>().unwrap(), 115.0);

        // A grouping account gets one draft for the day's requests.
        let grouping = buyer(&app).await;
        sqlx::query("UPDATE account SET billing_group_invoices = true WHERE id = $1")
            .bind(grouping)
            .execute(app.db())
            .await
            .expect("group");
        let a = format!("SO-{}", Uuid::now_v7().simple());
        let b = format!("SO-{}", Uuid::now_v7().simple());
        request(&app, &a, grouping, 10).await;
        request(&app, &b, grouping, 20).await;
        attome_billing::requests::process_pending(&app.state)
            .await
            .expect("sweep grouped");
        let (_, ra) = request(&app, &a, grouping, 10).await;
        let (_, rb) = request(&app, &b, grouping, 20).await;
        assert!(ra["invoice_id"].is_string(), "{ra}");
        assert_eq!(ra["invoice_id"], rb["invoice_id"]);
    });
}

// feature: F4
#[test]
fn schedule_runs_once_per_period() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let template = unnumbered(&app, account, "invoice", "TS").await;
        line(&app, template, "1", "500", "0", "standard").await;
        let today = chrono::Utc::now().date_naive();
        let schedule: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice_schedule (id, template_invoice_ref, frequency, next_run, \
                 is_enabled, created_by, is_active, row_version) \
             VALUES ($1, $2, 'monthly', $3, true, $4, true, 0) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(template)
        .bind(today)
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .expect("schedule");

        let made = attome_billing::requests::run_schedules(&app.state)
            .await
            .expect("run");
        assert!(made >= 1);
        let key = format!("schedule:{schedule}:{today}");
        let drafts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invoice WHERE idempotency_key = $1")
                .bind(&key)
                .fetch_one(app.db())
                .await
                .expect("drafts");
        assert_eq!(drafts, 1);
        let next = text(
            &app,
            "SELECT next_run::date::text FROM invoice_schedule WHERE id = $1",
            schedule,
        )
        .await;
        let expected = attome_billing::requests::next_run(today, Some("monthly")).unwrap();
        assert_eq!(next, expected.to_string());
        // Run again the same day: the schedule is not due, nothing is made.
        attome_billing::requests::run_schedules(&app.state)
            .await
            .expect("run again");
        let drafts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM invoice WHERE idempotency_key LIKE $1")
                .bind(format!("schedule:{schedule}:%"))
                .fetch_one(app.db())
                .await
                .expect("drafts");
        assert_eq!(drafts, 1);
    });
}

// feature: F4
#[test]
fn overdue_sweep_marks_past_due_open_invoices() {
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
        let mut issued = Vec::new();
        for _ in 0..3 {
            let draft = unnumbered(&app, account, "invoice", "TO").await;
            line(&app, draft, "1", "100", "0", "standard").await;
            let (status, body) = issue(&app, draft).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            issued.push(draft);
        }
        let (late, paid, current) = (issued[0], issued[1], issued[2]);
        // Two fall due last month; one of them is paid in full.
        sqlx::query("UPDATE invoice SET due_date = CURRENT_DATE - 30 WHERE id = ANY($1)")
            .bind(vec![late, paid])
            .execute(app.db())
            .await
            .expect("backdate");
        sqlx::query(
            "INSERT INTO payment_allocation (id, invoice_ref, amount, is_active, row_version) \
             VALUES ($1, $2, 115, true, 0)",
        )
        .bind(Uuid::now_v7())
        .bind(paid)
        .execute(app.db())
        .await
        .expect("allocation");
        let state = attome_billing::status::refresh_status(&app.state, paid)
            .await
            .expect("refresh");
        assert_eq!(state.payment_status, "paid");

        attome_billing::status::overdue_sweep(&app.state)
            .await
            .expect("sweep");
        let status_of = |id| text(&app, "SELECT payment_status FROM invoice WHERE id = $1", id);
        assert_eq!(status_of(late).await, "overdue");
        assert_eq!(status_of(paid).await, "paid");
        assert_eq!(status_of(current).await, "open");

        // Nobody marks an issued invoice paid by hand.
        let version: i64 = sqlx::query_scalar("SELECT row_version FROM invoice WHERE id = $1")
            .bind(late)
            .fetch_one(app.db())
            .await
            .expect("version");
        let edit = attome_records::entity_crud::update_record_for(
            &app.state,
            &ctx,
            ctx.user_id,
            "invoice",
            late,
            version,
            json!({ "payment_status": "paid" }),
        )
        .await;
        assert!(edit.is_err(), "payment status was set by hand: {edit:?}");
    });
}

/// An issued invoice of `net` (15% VAT) to `account`, due `due_in` days
/// from today (negative: past due).
async fn issued_due(app: &TestApp, account: Uuid, net: &str, due_in: i32) -> Uuid {
    let draft = unnumbered(app, account, "invoice", "TA").await;
    line(app, draft, "1", net, "0", "standard").await;
    let (status, body) = issue(app, draft).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    sqlx::query("UPDATE invoice SET due_date = CURRENT_DATE + $2 WHERE id = $1")
        .bind(draft)
        .bind(due_in)
        .execute(app.db())
        .await
        .expect("due date");
    draft
}

// feature: F4
#[test]
fn ageing_buckets_by_days_past_due() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        issued_due(&app, account, "100", 5).await; // 115 current
        issued_due(&app, account, "200", -10).await; // 230 in 1-30
        issued_due(&app, account, "300", -45).await; // 345 in 31-60
        issued_due(&app, account, "400", -100).await; // 460 over 90

        let mut row = None;
        for page in 1..=50 {
            let (status, body) = app
                .request(
                    Method::GET,
                    &format!("/api/v1/billing/ageing?page={page}&page_size=200"),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let items = body["items"].as_array().unwrap().clone();
            if let Some(found) = items
                .iter()
                .find(|i| i["account_id"] == json!(account))
                .cloned()
            {
                row = Some(found);
                break;
            }
            if items.is_empty() {
                break;
            }
        }
        let row = row.expect("the account is in the ageing");
        let amount = |key: &str| row[key].as_str().unwrap().parse::<f64>().unwrap();
        assert_eq!(row["currency"], "SAR");
        assert_eq!(amount("current"), 115.0);
        assert_eq!(amount("days_1_30"), 230.0);
        assert_eq!(amount("days_31_60"), 345.0);
        assert_eq!(amount("days_61_90"), 0.0);
        assert_eq!(amount("over_90"), 460.0);
        assert_eq!(amount("total"), 1150.0);

        let (status, totals) = app
            .request(Method::GET, "/api/v1/billing/ageing/totals", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{totals}");
        assert!(
            totals["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["currency"] == "SAR")
        );
    });
}

// feature: F4
#[test]
fn statement_closing_equals_open_totals() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let first = issued_due(&app, account, "100", 30).await;
        issued_due(&app, account, "200", 30).await;
        sqlx::query(
            "INSERT INTO payment_allocation (id, invoice_ref, amount, allocated_on, is_active, \
                 row_version) \
             VALUES ($1, $2, 50, CURRENT_DATE, true, 0)",
        )
        .bind(Uuid::now_v7())
        .bind(first)
        .execute(app.db())
        .await
        .expect("allocation");
        attome_billing::status::refresh_status(&app.state, first)
            .await
            .expect("refresh");

        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/billing/accounts/{account}/statement?from=2000-01-01"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let sar = body["currencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["currency"] == "SAR")
            .expect("a SAR section")
            .clone();
        assert_eq!(sar["opening_balance"], "0");
        assert_eq!(sar["entries"].as_array().unwrap().len(), 3);
        let closing: f64 = sar["closing_balance"].as_str().unwrap().parse().unwrap();
        let open: String = sqlx::query_scalar(
            "SELECT SUM(open_total)::text FROM invoice WHERE account_ref = $1 \
               AND status <> 'draft'",
        )
        .bind(account)
        .fetch_one(app.db())
        .await
        .expect("open totals");
        assert_eq!(closing, open.parse::<f64>().unwrap());
        assert_eq!(closing, 295.0);

        // An unknown account is not found.
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/billing/accounts/{}/statement", Uuid::now_v7()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

async fn set_write_off_threshold(app: &TestApp, value: u32) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/billing.write_off_approval_threshold",
            Some(json!({ "scope": "deployment", "value": value })),
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");
}

// feature: F4
// negative: POST /api/v1/billing/invoices/{id}/write-off
#[test]
fn write_off_above_threshold_needs_approval() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in PACKS {
            install(&app, pack).await;
        }
        let account = buyer(&app).await;
        let invoice = issued_due(&app, account, "100", -40).await; // 115 open
        let path = format!("/api/v1/billing/invoices/{invoice}/write-off");

        // More than is open, or no reason: refused.
        let (status, _) = app
            .request(
                Method::POST,
                &path,
                Some(json!({ "amount": 200, "reason": "Bad debt" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = app
            .request(
                Method::POST,
                &path,
                Some(json!({ "amount": 10, "reason": "" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Under the threshold: applied at once.
        set_write_off_threshold(&app, 50).await;
        let (status, body) = app
            .request(
                Method::POST,
                &path,
                Some(json!({ "amount": 15, "reason": "Rounding" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "written_off");
        assert_eq!(
            body["open_total"].as_str().unwrap().parse::<f64>().unwrap(),
            100.0
        );

        // Above it: an approval, and nothing changes until it is approved.
        let (status, body) = app
            .request(
                Method::POST,
                &path,
                Some(json!({ "amount": 100, "reason": "Bad debt" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending_approval");
        let approval: Uuid = body["approval_id"].as_str().unwrap().parse().unwrap();
        let action: String =
            sqlx::query_scalar("SELECT action_type FROM approval_request WHERE id = $1")
                .bind(approval)
                .fetch_one(app.db())
                .await
                .expect("approval");
        assert_eq!(action, "billing.write_off");
        let open = text(
            &app,
            "SELECT open_total::text FROM invoice WHERE id = $1",
            invoice,
        )
        .await;
        assert_eq!(open.parse::<f64>().unwrap(), 100.0);
        set_write_off_threshold(&app, 0).await;

        // The approved write-off clears the rest and survives a refresh.
        let payload: attome_billing::writeoff::WriteOffPayload = serde_json::from_value(
            sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT payload FROM approval_request WHERE id = $1",
            )
            .bind(approval)
            .fetch_one(app.db())
            .await
            .expect("payload"),
        )
        .expect("payload reads");
        attome_billing::writeoff::do_write_off_approved(&app.state, &payload, app.admin.id)
            .await
            .expect("approved write-off");
        let state = attome_billing::status::refresh_status(&app.state, invoice)
            .await
            .expect("refresh");
        assert_eq!(state.payment_status, "written_off");
        assert_eq!(state.open_total.parse::<f64>().unwrap(), 0.0);
        let postings: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_posting_outbox \
             WHERE invoice_ref = $1 AND posting_kind = 'write_off'",
        )
        .bind(invoice)
        .fetch_one(app.db())
        .await
        .expect("postings");
        assert_eq!(postings, 2);
    });
}
