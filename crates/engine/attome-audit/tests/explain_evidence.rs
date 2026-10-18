//! AA14-T2: plan guards for `attome_audit::admin::search`'s and `export`'s
//! queries. The tests share one seed: `audit_header` holds a fixed 10,000
//! rows with a deterministic spread of organizations, entities, users and
//! days, and fresh statistics. Each test asserts the planner reads the index
//! its query shape is meant to use, with no `Seq Scan` on `audit_header` or
//! its monthly partitions, so a schema or query change that stops an index
//! being used fails here.
//!
//! Runs against this process's migrated throwaway database
//! (`attome_testkit::migrated_db_url`), never `attome_dev`; skips without
//! `DATABASE_URL` unless `ATTOME_TEST_REQUIRE_DB` is set. The release gate
//! runs it in its `perf_plans` step:
//!
//! ```powershell
//! cargo test -p attome-audit --test explain_evidence -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::{run_shared, skip_if_no_db};
use chrono::{DateTime, Duration, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Row};
use tokio::sync::OnceCell;
use uuid::Uuid;

/// The seeded row count every guard plans against.
const ROWS: i32 = 10_000;
/// Organizations the rows are spread over.
const ORGS: u128 = 5;
/// Users the rows are spread over.
const USERS: u128 = 200;
/// Days back the rows' `created_at` reaches (about three monthly partitions).
const DAYS: i32 = 90;

fn org(n: u128) -> Uuid {
    Uuid::from_u128(0x0a0d_0000_0000_7000_8000_0000_0000_0000 + n)
}

fn user(n: u128) -> Uuid {
    Uuid::from_u128(0x0a0e_0000_0000_7000_8000_0000_0000_0000 + n)
}

/// The seeded database and the partitions holding its rows, once per test
/// process. The tests run on testkit's shared runtime, so the pool outlives
/// each test.
async fn seeded() -> Option<&'static (PgPool, Vec<String>)> {
    static DB: OnceCell<(PgPool, Vec<String>)> = OnceCell::const_new();
    let url = attome_testkit::migrated_db_url()?;
    Some(
        DB.get_or_init(|| async move {
            // The stack's roles carry a 500 ms `statement_timeout`, which the
            // seed would hit; lifted at connect time so every pooled
            // connection has it.
            let db = PgPoolOptions::new()
                .max_connections(2)
                .after_connect(|conn, _meta| {
                    Box::pin(async move {
                        conn.execute("SET statement_timeout = 0").await?;
                        Ok(())
                    })
                })
                .connect(&url)
                .await
                .expect("connect to the migrated test database");
            seed(&db).await;
            let populated: Vec<String> =
                sqlx::query_scalar("SELECT DISTINCT tableoid::regclass::text FROM audit_header")
                    .fetch_all(&db)
                    .await
                    .expect("the partitions holding rows");
            (db, populated)
        })
        .await,
    )
}

/// Seeds [`ROWS`] `audit_header` rows. Every value but the generated ids is
/// a function of the row number, so each run plans against the same data:
/// row `i` belongs to organization `i % 5` and user `i % 200`, takes one of
/// four entities and seven operations, and is `(i * 13) % (90 days in
/// minutes)` minutes old.
async fn seed(db: &PgPool) {
    let org_ids: Vec<Uuid> = (0..ORGS).map(org).collect();
    let user_ids: Vec<Uuid> = (0..USERS).map(user).collect();
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
         SELECT uuidv7(), c.t, \
            ($2::uuid[])[1 + i % array_length($2::uuid[], 1)], \
            true, 0, \
            ($4::text[])[1 + i % array_length($4::text[], 1)], \
            uuidv7(), \
            ($5::int[])[1 + i % array_length($5::int[], 1)], \
            ($3::uuid[])[1 + i % array_length($3::uuid[], 1)], \
            'seed-user-' || (i % 200)::text, \
            'seed-user-' || (i % 200)::text || '@example.test', \
            c.t, 1, 'seed-hash-' || i::text \
         FROM generate_series(1, $1::int) AS i, \
              LATERAL (SELECT now() - make_interval(mins => (i * 13) % ($6::int * 1440))) AS c(t)",
    )
    .bind(ROWS)
    .bind(&org_ids)
    .bind(&user_ids)
    .bind(&entities[..])
    .bind(&operations[..])
    .bind(DAYS)
    .execute(db)
    .await
    .expect("seed audit_header");
    // Without fresh statistics the planner judges selectivity from the
    // near-empty table, and the plans are not the ones a deployment with
    // this much history gets.
    sqlx::query("ANALYZE audit_header")
        .execute(db)
        .await
        .expect("ANALYZE audit_header");
}

/// A bind for [`explain`].
enum Bind {
    Uuid(Uuid),
    Text(&'static str),
    Time(DateTime<Utc>),
    Int(i64),
}

/// `EXPLAIN (ANALYZE)` of `sql` with `binds`, as one string.
async fn explain(db: &PgPool, sql: &str, binds: Vec<Bind>) -> String {
    let explain = format!("EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) {sql}");
    let mut q = sqlx::query(&explain);
    for bind in binds {
        q = match bind {
            Bind::Uuid(v) => q.bind(v),
            Bind::Text(v) => q.bind(v),
            Bind::Time(v) => q.bind(v),
            Bind::Int(v) => q.bind(v),
        };
    }
    q.fetch_all(db)
        .await
        .expect("explain")
        .iter()
        .map(|row| row.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Asserts the plan uses an index whose name contains `index`, and never
/// scans a partition holding rows sequentially. A partition's index is named
/// after its parent's columns and cut at 63 characters, so the caller passes
/// a prefix every partition's name keeps. An empty partition (a month ahead)
/// may be scanned sequentially: for an empty table that is the right plan.
fn assert_index_plan(plan: &str, index: &str, populated: &[String]) {
    assert!(
        plan.contains(index),
        "expected an index containing `{index}` in the plan:
{plan}"
    );
    for partition in populated {
        assert!(
            !plan.contains(&format!("Seq Scan on {partition} ")),
            "the plan scans {partition}, which holds rows, sequentially:
{plan}"
        );
    }
}

const SEARCH_SELECT: &str = "SELECT h.id, h.created_at, h.organization_ref, h.category, \
        h.entity_name, h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
        h.changed_on, h.correlation_id, h.event_name \
     FROM audit_header h WHERE h.is_active = true";

/// Search within one organization over a date range, the first page: the
/// shape `admin::search` builds for an organization's recent history.
#[test]
fn search_by_organization_and_dates_reads_the_org_created_index() {
    run_shared(async {
        let (db, populated) = skip_if_no_db!(seeded().await);
        let sql = format!(
            "{SEARCH_SELECT} AND h.organization_ref = $1 \
             AND h.created_at >= $2 AND h.created_at <= $3 \
             ORDER BY h.created_at DESC, h.id DESC LIMIT $4 OFFSET $5"
        );
        let plan = explain(
            db,
            &sql,
            vec![
                Bind::Uuid(org(2)),
                Bind::Time(Utc::now() - Duration::days(30)),
                Bind::Time(Utc::now()),
                Bind::Int(50),
                Bind::Int(0),
            ],
        )
        .await;
        assert_index_plan(&plan, "organization_ref_created_at", populated);
    });
}

/// One record's history, as a record's audit tab asks for it.
#[test]
fn search_by_record_reads_the_entity_record_index() {
    run_shared(async {
        let (db, populated) = skip_if_no_db!(seeded().await);
        let record: Uuid = sqlx::query_scalar(
            "SELECT record_id FROM audit_header \
             WHERE organization_ref = $1 AND entity_name = 'service_ticket' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(org(1))
        .fetch_one(db)
        .await
        .expect("a seeded record");
        let sql = format!(
            "{SEARCH_SELECT} AND h.organization_ref = $1 AND h.entity_name = $2 \
             AND h.record_id = $3 \
             ORDER BY h.created_at DESC, h.id DESC LIMIT $4 OFFSET $5"
        );
        let plan = explain(
            db,
            &sql,
            vec![
                Bind::Uuid(org(1)),
                Bind::Text("service_ticket"),
                Bind::Uuid(record),
                Bind::Int(50),
                Bind::Int(0),
            ],
        )
        .await;
        assert_index_plan(&plan, "organization_ref_entity_name_rec", populated);
    });
}

/// One user's actions in an organization.
#[test]
fn search_by_user_reads_the_user_index() {
    run_shared(async {
        let (db, populated) = skip_if_no_db!(seeded().await);
        let sql = format!(
            "{SEARCH_SELECT} AND h.organization_ref = $1 AND h.user_id = $2 \
             ORDER BY h.created_at DESC, h.id DESC LIMIT $3 OFFSET $4"
        );
        let plan = explain(
            db,
            &sql,
            vec![
                Bind::Uuid(org(3)),
                Bind::Uuid(user(3)),
                Bind::Int(50),
                Bind::Int(0),
            ],
        )
        .await;
        assert_index_plan(&plan, "organization_ref_user_id", populated);
    });
}

/// Export's streaming cursor batch: below the safety-margin ceiling, after
/// the last id, ordered by id, `EXPORT_BATCH_SIZE` rows.
#[test]
fn export_cursor_batch_reads_the_primary_key() {
    run_shared(async {
        let (db, populated) = skip_if_no_db!(seeded().await);
        let cursor: Uuid =
            sqlx::query_scalar("SELECT id FROM audit_header ORDER BY id OFFSET 5000 LIMIT 1")
                .fetch_one(db)
                .await
                .expect("a mid-table cursor");
        let sql = "SELECT h.id, h.created_at, h.organization_ref, h.category, h.entity_name, \
                    h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
                    h.changed_on, h.source, h.ip_address, h.correlation_id, h.batch_id, \
                    h.event_name, h.event_hash, h.prev_hash, h.signing_key_id \
             FROM audit_header h WHERE h.is_active = true \
               AND h.created_at <= $1 AND h.id > $2 \
             ORDER BY h.id ASC LIMIT $3";
        let plan = explain(
            db,
            sql,
            vec![
                Bind::Time(Utc::now() - Duration::seconds(30)),
                Bind::Uuid(cursor),
                Bind::Int(1000),
            ],
        )
        .await;
        assert_index_plan(&plan, "pkey", populated);
    });
}
