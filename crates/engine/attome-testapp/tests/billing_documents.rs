//! F4-T13: after issue, the invoice gets its bilingual PDF and is emailed
//! to its contact. The renderer is a fake (no render sidecar in tests); the
//! storage is the test object store (`S3_ACCESS_KEY`/`S3_SECRET_KEY`, and
//! `TEST_S3_ENDPOINT` when it is not on port 9000), skipped without one.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use attome_billing::issue::IssueHook;
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::{Method, StatusCode};
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

/// A renderer that keeps the HTML it was given and answers a tiny PDF.
#[derive(Default)]
struct FakeRenderer {
    seen: Mutex<Vec<String>>,
}

impl attome_docgen::generate::PdfRenderer for FakeRenderer {
    fn render<'a>(
        &'a self,
        _config: &'a attome_config::DocgenSection,
        html: &'a str,
        _page_size: &'a str,
        _margin_mm: Option<f64>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
        self.seen.lock().unwrap().push(html.to_owned());
        Box::pin(async { Ok(b"%PDF-1.4\n%fake\n".to_vec()) })
    }
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
fn issue_hook_attaches_pdf() {
    attome_testkit::run_shared(async {
        if attome_testkit::s3_or_skip().is_none() {
            return;
        }
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer Co') RETURNING id")
                .fetch_one(app.db())
                .await
                .expect("account");
        let contact: Uuid = sqlx::query_scalar(
            "INSERT INTO contact (full_name, email) VALUES ('Ada', 'ada@example.invalid') \
             RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .expect("contact");
        let invoice: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice (id, status, kind, currency, account_ref, contact_ref, \
                 payment_terms_days, series_key, is_active, row_version) \
             VALUES ($1, 'draft', 'invoice', 'SAR', $2, $3, 30, 'TDOC', true, 0) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(account)
        .bind(contact)
        .fetch_one(app.db())
        .await
        .expect("draft");
        sqlx::query(
            "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
                 vat_category, is_active, row_version) \
             VALUES ($1, $2, 'Setup', 1, 100, 'standard', true, 0)",
        )
        .bind(Uuid::now_v7())
        .bind(invoice)
        .execute(app.db())
        .await
        .expect("line");
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/invoices/{invoice}/issue"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let number = body["invoice_number"].as_str().unwrap().to_owned();

        // The document hook renders the bilingual invoice and attaches it.
        let renderer = Arc::new(FakeRenderer::default());
        let document = attome_billing::document::DocumentHook {
            renderer: renderer.clone(),
        };
        document
            .after_issue(&app.state, invoice)
            .await
            .expect("document hook");
        let html = renderer
            .seen
            .lock()
            .unwrap()
            .first()
            .cloned()
            .expect("rendered");
        assert!(
            html.contains(&number) && html.contains("فاتورة ضريبية"),
            "{html}"
        );
        let key = text(&app, "SELECT document FROM invoice WHERE id = $1", invoice).await;
        assert!(
            key.starts_with(&format!("invoice/{invoice}/document/")),
            "{key}"
        );
        // A retry renders nothing more.
        document
            .after_issue(&app.state, invoice)
            .await
            .expect("document hook again");
        assert_eq!(renderer.seen.lock().unwrap().len(), 1);

        // The send hook emails it and marks the invoice sent, once.
        let send = attome_billing::document::SendHook;
        send.after_issue(&app.state, invoice)
            .await
            .expect("send hook");
        send.after_issue(&app.state, invoice)
            .await
            .expect("send hook again");
        let status = text(&app, "SELECT status FROM invoice WHERE id = $1", invoice).await;
        assert_eq!(status, "sent");
        let emails: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM apalis.jobs \
             WHERE job->>'variant' = 'SendEmail' AND job::text LIKE $1",
        )
        .bind(format!("%{number}.pdf%"))
        .fetch_one(app.db())
        .await
        .expect("emails");
        assert_eq!(emails, 1);
    });
}
