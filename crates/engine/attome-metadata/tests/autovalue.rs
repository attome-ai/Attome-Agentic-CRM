//! C-22 — live-Postgres concurrency coverage for `AutoValue::allocate`
//! (`crates/engine/attome-metadata/src/autovalue.rs`).
//!
//! `allocate`'s row-locked `UPDATE ... RETURNING` is what makes the
//! platform's autonumbers (invoice numbers, case references) gap-free — the
//! module's own "Concurrency" doc section reasons about two concurrent
//! creates serializing on the rule row, but until this suite nothing
//! exercised that against a real Postgres. Two tasks, each on its own
//! connection, allocate 500 numbers apiece from the same rule; the property
//! under test is that the 1,000 results are exactly `1..=1000` — distinct,
//! and with no gap a crashed/rolled-back allocation would have left behind.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI` (see `attome_testkit`). `autovalue` is a
//! metadata-provisioned entity table (`attome_metadata::autovalue::seed`), so this
//! needs the standard migrated test schema, same precondition as
//! `tests/provision.rs`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test"
//! cargo test -p attome-metadata --test autovalue -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_metadata::autovalue::{AutoValue, ResetScope};
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};
use std::collections::HashSet;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Number of allocations each of the two concurrent tasks performs.
const PER_TASK: usize = 500;

/// Two writers racing on one rule row must still hand out 1,000 distinct,
/// gap-free numbers starting at `initial_value` — the whole point of the
/// row-locked `UPDATE ... RETURNING` over a plain Postgres `SEQUENCE`
/// (module doc: "gap-free... the entire point of a customer-visible invoice
/// number").
#[tokio::test]
async fn concurrent_allocation_across_two_connections_is_distinct_and_gap_free() {
    let db = skip_if_no_db!(test_db().await);
    attome_metadata::autovalue::seed_for_tests(&db)
        .await
        .expect("seed the autovalue entity");

    // A throwaway rule row, inserted directly — `allocate` only ever reads
    // `id`/`reset_scope`/`format`/`initial_value` off the row and never
    // touches `entity_logicalname`/`attribute_logicalname` itself (those
    // exist for `generate_for_create`'s lookup, exercised elsewhere), so
    // there is no need to provision a real target entity for this test.
    let rule_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO autovalue \
             (id, name, entity_logicalname, attribute_logicalname, format, \
              initial_value, next_value, reset_scope, is_active, row_version) \
         VALUES ($1, 'concurrency test rule', 'test_autovalue_target', 'code', \
                 '{SEQ}', 1, 1, 'never', true, 0)",
    )
    .bind(rule_id)
    .execute(&db)
    .await
    .expect("seed a throwaway rule row");

    let rule = AutoValue {
        id: rule_id,
        entity_logicalname: "test_autovalue_target".to_owned(),
        attribute_logicalname: "code".to_owned(),
        format: "{SEQ}".to_owned(),
        initial_value: 1,
        reset_scope: ResetScope::Never,
        sequence_key: String::new(),
        assign_when: None,
    };

    let url = attome_testkit::migrated_db_url().expect("checked by skip_if_no_db above");
    let now = Utc::now().fixed_offset();

    let mut tasks = Vec::new();
    for _ in 0..2 {
        let rule = rule.clone();
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let mut conn = PgConnection::connect(&url)
                .await
                .expect("each task opens its own connection");
            let mut values = Vec::with_capacity(PER_TASK);
            for _ in 0..PER_TASK {
                let rendered = rule
                    .allocate(&mut conn, now)
                    .await
                    .expect("allocate must not error")
                    .expect("rule stays active for the whole test");
                values.push(
                    rendered
                        .parse::<i64>()
                        .expect("format is a bare {SEQ} — rendered value is the number itself"),
                );
            }
            values
        }));
    }

    let mut all_values: Vec<i64> = Vec::with_capacity(PER_TASK * 2);
    for task in tasks {
        all_values.extend(task.await.expect("allocation task must not panic"));
    }

    assert_eq!(
        all_values.len(),
        PER_TASK * 2,
        "both tasks must have completed every allocation"
    );

    let unique: HashSet<i64> = all_values.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all_values.len(),
        "no two concurrent allocations may return the same sequence number"
    );

    all_values.sort_unstable();
    let expected: Vec<i64> = (1..=(PER_TASK * 2) as i64).collect();
    assert_eq!(
        all_values, expected,
        "1,000 allocations from initial_value 1 must be exactly 1..=1000 with no gap"
    );
}

/// A4-T3: a rule with a sequence key keeps one counter per key and period:
/// two branches each number from the initial value, and a new Hijri year
/// starts each branch again.
#[tokio::test]
async fn autonumber_type_counts_per_branch_and_hijri_year() {
    let db = skip_if_no_db!(test_db().await);
    attome_metadata::autovalue::seed_for_tests(&db)
        .await
        .expect("seed the autovalue entity");
    let rule = AutoValue {
        id: Uuid::now_v7(),
        entity_logicalname: "test_autovalue_target".to_owned(),
        attribute_logicalname: "code".to_owned(),
        format: "INV-{branch}-{hyyyy}-{SEQ:4}".to_owned(),
        initial_value: 1,
        reset_scope: ResetScope::HijriYearly,
        sequence_key: "{branch}".to_owned(),
        assign_when: None,
    };
    let mut conn = db.acquire().await.expect("connection");
    // 2026-03-01 is in Hijri 1447, 2026-08-01 in 1448.
    let in_1447 = chrono::DateTime::parse_from_rfc3339("2026-03-01T10:00:00+03:00").unwrap();
    let in_1448 = chrono::DateTime::parse_from_rfc3339("2026-08-01T10:00:00+03:00").unwrap();
    let mut values = attome_metadata::autovalue::TokenValues::new();
    let mut next = |branch: &str| {
        values.insert("branch".to_owned(), branch.to_owned());
        values.clone()
    };
    let ruh = next("RUH");
    let jed = next("JED");
    let mut issued = Vec::new();
    for (key, values, now) in [
        ("RUH", &ruh, in_1447),
        ("RUH", &ruh, in_1447),
        ("JED", &jed, in_1447),
        ("RUH", &ruh, in_1448),
    ] {
        issued.push(
            rule.allocate_keyed(&mut conn, now, key, values)
                .await
                .expect("allocate"),
        );
    }
    assert_eq!(
        issued,
        [
            "INV-RUH-1447-0001",
            "INV-RUH-1447-0002",
            "INV-JED-1447-0001",
            "INV-RUH-1448-0001",
        ]
    );
}
