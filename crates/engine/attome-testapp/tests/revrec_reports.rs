//! F11-T10: the revenue reports tie to the schedule lines: the waterfall
//! adds up to what is not yet recognised, and remaining performance
//! obligations leave recognised lines out.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use serde_json::Value;
use uuid::Uuid;

// The roll-forward reads billed amounts from billing's invoices, so billing
// and the packs it depends on come before the ledger.
const PACKS: [&str; 7] = [
    "crm",
    "sales",
    "vendor-supplier",
    "contract-management",
    "finance",
    "billing",
    "ledger",
];

fn changesets(pack: &str) -> Vec<Value> {
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
    files
        .iter()
        .map(|f| serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap())
        .collect()
}

/// The SQL of the ledger pack's report `name`.
fn report(name: &str) -> String {
    changesets("ledger")
        .iter()
        .flat_map(|cs| cs["operations"].as_array().cloned().unwrap_or_default())
        .find(|op| op["op"] == "upsert_query" && op["args"]["definition"]["name"] == name)
        .and_then(|op| op["args"]["definition"]["sql"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("no report {name}"))
}

/// One contract with one obligation of 100 a month for three months, the
/// first recognised. Returns the contract.
async fn books(app: &TestApp) -> Uuid {
    for pack in PACKS {
        for cs in changesets(pack) {
            attome_api::changeset::boot::apply_pack_document(&app.state, &cs)
                .await
                .unwrap_or_else(|e| panic!("{pack}: {e}"));
        }
    }
    let admin = app.admin.id;
    let contract: Uuid = sqlx::query_scalar(
        "INSERT INTO revenue_contract (id, source_kind, source_id, currency, total_price, status, \
             created_by, owner_ref) \
         VALUES ($1, 'order', $2, 'SAR', 300, 'open', $3, $3) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7().to_string())
    .bind(admin)
    .fetch_one(app.db())
    .await
    .unwrap();
    let obligation: Uuid = sqlx::query_scalar(
        "INSERT INTO performance_obligation (id, revenue_contract_ref, source_line_id, kind, \
             pattern, allocated_amount, status, created_by, owner_ref) \
         VALUES ($1, $2, 'line-1', 'order_line', 'ratable', 300, 'open', $3, $3) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(contract)
    .bind(admin)
    .fetch_one(app.db())
    .await
    .unwrap();
    for (period, status) in [
        ("2027-01", "recognised"),
        ("2027-02", "planned"),
        ("2027-03", "planned"),
    ] {
        sqlx::query(
            "INSERT INTO revenue_schedule_line (id, obligation_ref, fiscal_period, \
                 amount_contract_ccy, status, created_by, owner_ref) \
             VALUES ($1, $2, $3, 100, $4, $5, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(obligation)
        .bind(period)
        .bind(status)
        .bind(admin)
        .execute(app.db())
        .await
        .unwrap();
    }
    contract
}

// feature: F11
#[test]
fn waterfall_sums_to_unrecognised() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        books(&app).await;
        let rows: Vec<(Option<String>, Option<f64>)> = sqlx::query_as(&format!(
            "SELECT fiscal_period, planned::float8 FROM ({}) w",
            report("Revenue: Waterfall")
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        let periods: Vec<&str> = rows.iter().filter_map(|r| r.0.as_deref()).collect();
        assert_eq!(periods, ["2027-02", "2027-03"], "planned periods only");
        let total: f64 = rows.iter().filter_map(|r| r.1).sum();
        let unrecognised: f64 = sqlx::query_scalar(
            "SELECT COALESCE(sum(amount_contract_ccy), 0)::float8 FROM revenue_schedule_line \
              WHERE status = 'planned'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!((total - unrecognised).abs() < 1e-9 && (total - 200.0).abs() < 1e-9);
    });
}

// feature: F11
#[test]
fn rpo_excludes_recognised() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let contract = books(&app).await;
        let rows: Vec<(Option<Uuid>, Option<f64>, Option<String>)> = sqlx::query_as(&format!(
            "SELECT revenue_contract_ref, remaining::float8, from_period FROM ({}) r",
            report("Revenue: Remaining Performance Obligations")
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, Some(contract));
        assert_eq!(rows[0].1, Some(200.0), "January is recognised and left out");
        assert_eq!(rows[0].2.as_deref(), Some("2027-02"));

        // The roll-forward writes this month's snapshot for the contract.
        let written = attome_ledger::revrec::close::refresh_snapshots(
            &app.state,
            chrono::NaiveDate::from_ymd_opt(2027, 3, 15).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(written, 1);
        let unbilled: f64 = sqlx::query_scalar(
            "SELECT unbilled::float8 FROM revenue_balance_snapshot \
              WHERE revenue_contract_ref = $1 AND fiscal_period = '2027-03'",
        )
        .bind(contract)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(unbilled, 100.0, "100 recognised, nothing billed");
    });
}
