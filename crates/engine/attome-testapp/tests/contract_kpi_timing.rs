//! W1-T16: the contract KPI reports at 100,000 contracts. Seeds the
//! throwaway test database (never the shared dev database) with 100,000
//! contracts, two versions each and 100,000 obligations, then runs every
//! report the contract-management pack ships (`is_report` stored queries)
//! and asserts each answers within 300 ms once warm.
//!
//! Ignored by default (the seed takes a while): run with `-- --ignored`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "a timing test: setup panics with its message, and the timings are printed"
)]

use std::time::{Duration, Instant};

use attome_testapp::TestApp;
use serde_json::Value;

const CONTRACTS: i64 = 100_000;
const BUDGET: Duration = Duration::from_millis(300);
const PACKS: [&str; 6] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
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

/// The pack's reports: (name, sql).
fn reports() -> Vec<(String, String)> {
    changesets("contract-management")
        .iter()
        .flat_map(|cs| cs["operations"].as_array().cloned().unwrap_or_default())
        .filter(|op| op["op"] == "upsert_query" && op["args"]["definition"]["is_report"] == true)
        .map(|op| {
            let d = &op["args"]["definition"];
            (
                d["name"].as_str().unwrap().to_owned(),
                d["sql"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// feature: W1
#[test]
#[ignore = "seeds 100,000 contracts; run with -- --ignored"]
fn kpis_under_300ms_at_100k() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // The contract engine's own entities (contract_version) come first.
        attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-contract")
            .await
            .expect("apply the contract platform definition");
        for pack in PACKS {
            for cs in changesets(pack) {
                attome_api::changeset::boot::apply_pack_document(&app.state, &cs)
                    .await
                    .unwrap_or_else(|e| panic!("{pack}: {e}"));
            }
        }
        let reports = reports();
        assert!(reports.len() >= 5, "the pack's five reports: {reports:?}");

        // A spread of states, dates and deviations, as a deployment has, seeded
        // on one connection without the pool's statement timeout.
        let mut seed = app.db().acquire().await.unwrap();
        sqlx::query("SET statement_timeout = 0")
            .execute(&mut *seed)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO contract (id, title, counterparty, status, contract_value, end_date, \
                 playbook_deviations, is_active, row_version, created_at) \
             SELECT uuidv7(), 'Contract ' || g, 'Counterparty ' || (g % 500), \
                    (ARRAY['draft', 'review', 'approved', 'active', 'terminated'])[1 + g % 5], \
                    (g % 1000) * 100, now()::date + (g % 720 - 120)::int, \
                    CASE WHEN g % 7 = 0 THEN '[{\"severity\":\"needs_legal\"}]' \
                         WHEN g % 11 = 0 THEN '[]' END, \
                    true, 0, now() - make_interval(days => (g % 400)::int) \
               FROM generate_series(1, $1) AS g",
        )
        .bind(CONTRACTS)
        .execute(&mut *seed)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO contract_version \
                 (contract_id, source, version_no, created_by_ref, created_by, owner_ref, created_at) \
             SELECT c.id::text, s.source, s.no, $1, $1, $1, c.created_at + make_interval(days => s.no * 9) \
               FROM contract c \
              CROSS JOIN (VALUES ('draft', 1), ('counterparty_upload', 2), ('signed', 3)) AS s(source, no) \
              WHERE s.no < 3 OR c.status = 'active'",
        )
        .bind(app.admin.id)
        .execute(&mut *seed)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO obligation (id, title, contract_ref, due_date, is_complete, completed_on, \
                 is_active, row_version) \
             SELECT uuidv7(), 'Obligation for ' || c.title, c.id, c.end_date::date - 30, \
                    c.status = 'terminated', \
                    CASE WHEN c.status = 'terminated' THEN c.end_date::date - 32 + (random() * 4)::int END, \
                    true, 0 \
               FROM contract c",
        )
        .execute(&mut *seed)
        .await
        .unwrap();
        sqlx::query("ANALYZE contract, contract_version, obligation")
            .execute(&mut *seed)
            .await
            .unwrap();
        drop(seed);

        let mut slow = Vec::new();
        for (name, sql) in &reports {
            // Warm once, then time.
            sqlx::query(sql).fetch_all(app.db()).await.unwrap();
            let started = Instant::now();
            let rows = sqlx::query(sql).fetch_all(app.db()).await.unwrap();
            let took = started.elapsed();
            println!("{name}: {} rows in {took:?}", rows.len());
            if took > BUDGET {
                slow.push(format!("{name}: {took:?}"));
            }
        }
        assert!(
            slow.is_empty(),
            "over 300 ms at 100,000 contracts: {slow:?}"
        );
    });
}
