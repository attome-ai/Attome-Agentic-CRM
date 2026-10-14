//! M19 (Audit) gap list — captures `EXPLAIN (ANALYZE, BUFFERS)` plans for
//! `attome_audit::admin::search`/`export`'s actual queries against a
//! representative volume of `audit_header` rows, so `document/evidence/`
//! carries a real measurement rather than a claim.
//!
//! `#[ignore]`d — it seeds ~60k rows across a handful of organizations and
//! several partitions, which is not something every `cargo test -p
//! attome-audit` run should pay for. Run it manually against the test-profile
//! database and copy the printed output into `document/evidence/`:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test"
//! cargo test -p attome-audit --test explain_evidence -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Read-only against a throwaway clone (`attome_testkit::test_db_url`) — never
//! points at `attome_dev`, same guarantee every other DB-backed suite here
//! relies on.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use chrono::{Duration, Utc};
use sqlx::{Executor, postgres::PgPoolOptions};
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            // Every application role in this stack carries a 500ms
            // `statement_timeout` (`document/evidence/query-plans-2026-08-25`'s
            // own note) — fine for the request-time queries it protects, but
            // this test's 60k-row bulk seed would be cancelled by it well
            // before finishing. Lifted per-connection at connect time (not a
            // one-off `SET` issued through the pool, which only reaches
            // whichever single connection happens to serve that query, not
            // necessarily the one serving the next) — every connection this
            // pool ever hands out gets the lift.
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET statement_timeout = 0").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Seeds `n` `audit_header` rows spread across `orgs` organizations and
/// the last `months` monthly partitions, with a realistic mix of
/// `entity_name`/`operation`/`user_id` values so the EXPLAIN plans below
/// reflect selectivity a real deployment would actually see, not a
/// degenerate all-one-value table.
///
/// `org_ids`/`user_ids` are generated in Rust and bound as `uuid[]`
/// parameters rather than built inside the SQL with an uncorrelated
/// `LATERAL` — an uncorrelated lateral subquery isn't guaranteed to be
/// evaluated exactly once by the planner, and re-evaluating a 200-UUID
/// `array_agg` per output row would make this seed pathologically slow (up
/// to `n * 200` UUID generations instead of `orgs + 200`). Binding
/// precomputed arrays and indexing them is both correct and fast: one
/// `INSERT ... SELECT` round trip regardless of `n`.
async fn seed_representative_headers(db: &DbPool, n: i64, orgs: i64, months: i64) {
    let org_ids: Vec<Uuid> = (0..orgs).map(|_| Uuid::now_v7()).collect();
    let user_ids: Vec<Uuid> = (0..200).map(|_| Uuid::now_v7()).collect();
    let entities = [
        "service_ticket",
        "service_work_request",
        "attome_document",
        "account",
    ];
    let operations = [0i32, 1, 1, 1, 2, 11, 12];

    sqlx::query(
        "INSERT INTO audit_header \
            (id, created_at, organization_ref, is_active, category, entity_name, record_id, \
             operation, user_id, user_name, user_email, changed_on, source, event_hash) \
         SELECT \
            uuidv7(), \
            NOW() - (random() * ($3::float * 30) || ' days')::interval, \
            ($4::uuid[])[1 + (i % $2)::int], \
            true, \
            0, \
            ($6::text[])[1 + (i % array_length($6::text[], 1))::int], \
            uuidv7(), \
            ($7::int[])[1 + (i % array_length($7::int[], 1))::int], \
            ($5::uuid[])[1 + (i % 200)::int], \
            'seed-user-' || (i % 200)::text, \
            'seed-user-' || (i % 200)::text || '@example.test', \
            NOW() - (random() * ($3::float * 30) || ' days')::interval, \
            1, \
            'seed-hash-' || i::text \
         FROM generate_series(1, $1) AS i",
    )
    .bind(n)
    .bind(orgs)
    .bind(months)
    .bind(&org_ids)
    .bind(&user_ids)
    .bind(&entities[..])
    .bind(&operations[..])
    .execute(db)
    .await
    .expect("seed representative audit_header rows");
}

#[tokio::test]
#[ignore = "seeds ~60k rows; run manually with --ignored, see module doc"]
async fn capture_search_and_export_explain_plans() {
    let Some(db) = test_db().await else {
        eprintln!("DATABASE_URL not set — skipping (see module doc)");
        return;
    };

    seed_representative_headers(&db, 60_000, 5, 6).await;

    // Without this, the planner works off pre-seed (near-empty-table)
    // statistics and can badly misjudge selectivity — observed live: a
    // first pass with no ANALYZE estimated 94 rows for a predicate that
    // actually matched all 60,000, which picked a Bitmap Heap Scan reading
    // the whole table instead of an early-terminating forward index scan.
    // `query-plans-2026-08-25`'s own seed does the same "seed, then VACUUM
    // ANALYZE" before capturing.
    sqlx::query("ANALYZE audit_header")
        .execute(&db)
        .await
        .expect("ANALYZE after seeding");

    let row_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_header")
        .fetch_one(&db)
        .await
        .expect("count seeded rows");
    println!("=== audit_header row count after seeding: {row_count} ===\n");

    // Representative search: entity + date range, the shape
    // `attome_audit::admin::search` builds when a caller filters to one
    // entity's recent history (the composite index
    // `idx_core_audit_header_entity_record (org, entity_name, record_id,
    // created_at DESC)` should lead this).
    let from = (Utc::now() - Duration::days(30)).to_rfc3339();
    let to = Utc::now().to_rfc3339();
    let search_sql = format!(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) \
         SELECT h.id, h.created_at, h.organization_ref, h.category, h.entity_name, \
                h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
                h.changed_on, h.correlation_id, h.event_name \
         FROM audit_header h WHERE h.is_active = true \
           AND h.entity_name = 'service_ticket' \
           AND h.created_at >= '{from}' AND h.created_at <= '{to}' \
         ORDER BY h.created_at DESC, h.id DESC LIMIT 50 OFFSET 0"
    );
    let plan: Vec<(String,)> = sqlx::query_as(&search_sql)
        .fetch_all(&db)
        .await
        .expect("EXPLAIN the search query");
    println!("=== SEARCH: entity_name + date range, 50-row page ===");
    for (line,) in &plan {
        println!("{line}");
    }
    println!();

    // Representative search: pure date-range scan, no entity/user/record
    // filter and no organization_ref — the worst case `attome_audit::admin::
    // search` allows (organization_ref is optional), included specifically
    // to measure whether that's a real cost, not assumed cheap.
    let wide_sql = format!(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) \
         SELECT h.id, h.created_at, h.organization_ref, h.category, h.entity_name, \
                h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
                h.changed_on, h.correlation_id, h.event_name \
         FROM audit_header h WHERE h.is_active = true \
           AND h.created_at >= '{from}' AND h.created_at <= '{to}' \
         ORDER BY h.created_at DESC, h.id DESC LIMIT 50 OFFSET 0"
    );
    let plan: Vec<(String,)> = sqlx::query_as(&wide_sql)
        .fetch_all(&db)
        .await
        .expect("EXPLAIN the wide date-range query");
    println!("=== SEARCH: date range only, no org/entity/user filter ===");
    for (line,) in &plan {
        println!("{line}");
    }
    println!();

    // Export's streaming cursor batch: id > cursor, created_at below the
    // safety-margin ceiling, ordered by id, LIMIT 1000 (EXPORT_BATCH_SIZE).
    let cursor = Uuid::nil();
    let ceiling = (Utc::now() - Duration::seconds(30)).to_rfc3339();
    let export_sql = format!(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) \
         SELECT h.id, h.created_at, h.organization_ref, h.category, h.entity_name, \
                h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
                h.changed_on, h.source, h.ip_address, h.correlation_id, h.batch_id, \
                h.event_name, h.event_hash, h.prev_hash, h.signing_key_id \
         FROM audit_header h WHERE h.is_active = true \
           AND h.created_at <= '{ceiling}' \
           AND h.id > '{cursor}' \
         ORDER BY h.id ASC LIMIT 1000"
    );
    let plan: Vec<(String,)> = sqlx::query_as(&export_sql)
        .fetch_all(&db)
        .await
        .expect("EXPLAIN the export cursor batch query");
    println!("=== EXPORT: id-cursor batch, LIMIT 1000 ===");
    for (line,) in &plan {
        println!("{line}");
    }
}
