//! F4-T5: a draft invoice's lines are priced by the tax engine and its totals
//! summed from the rounded lines; an issued invoice is never recomputed.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
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
