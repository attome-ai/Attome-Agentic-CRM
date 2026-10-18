//! AA4-T2: plan evidence for the keyset page query query/execute runs
//! (`attome_records::query_exec::build_cursor_sql`). A throwaway table with
//! the partial single-column index an indexed sortable attribute gets, 20,000
//! rows and fresh statistics; each test asserts the planner walks the index
//! rather than sorting the whole table.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::query_exec::build_cursor_sql;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

const PAGE: i64 = 50;

/// The table, its index and rows; returns (table, a cursor id deep in the
/// set).
async fn fixture(db: &PgPool) -> (String, Uuid) {
    let table = format!("plan_ev_{}", &Uuid::now_v7().simple().to_string()[20..]);
    for sql in [
        format!(
            r#"CREATE TABLE "{table}" (
                   id uuid PRIMARY KEY DEFAULT uuidv7(),
                   due_date timestamptz,
                   status text,
                   is_active boolean DEFAULT TRUE)"#
        ),
        format!(r#"CREATE INDEX ON "{table}" (due_date) WHERE is_active = TRUE"#),
        format!(
            r#"INSERT INTO "{table}" (due_date, status)
               SELECT now() + make_interval(mins => g), CASE WHEN g % 10 = 0 THEN 'open' ELSE 'done' END
                 FROM generate_series(1, 20000) g"#
        ),
        format!(r#"ANALYZE "{table}""#),
    ] {
        sqlx::query(&sql)
            .execute(db)
            .await
            .expect("fixture statement");
    }
    let cursor: Uuid = sqlx::query_scalar(&format!(
        r#"SELECT id FROM "{table}" ORDER BY due_date, id OFFSET 15000 LIMIT 1"#
    ))
    .fetch_one(db)
    .await
    .expect("a deep cursor row");
    (table, cursor)
}

fn base_sql(table: &str) -> String {
    format!(r#"SELECT id, due_date, status FROM "{table}" WHERE is_active = true"#)
}

/// `EXPLAIN (ANALYZE)` of `sql` with `binds` (text, then optional uuid,
/// then the page size), as one string.
async fn explain(db: &PgPool, sql: &str, texts: &[&str], cursor: Option<Uuid>) -> String {
    let explain = format!("EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF) {sql}");
    let mut q = sqlx::query(&explain);
    for text in texts {
        q = q.bind(*text);
    }
    if let Some(cursor) = cursor {
        q = q.bind(cursor);
    }
    q = q.bind(PAGE);
    q.fetch_all(db)
        .await
        .expect("explain")
        .iter()
        .map(|row| row.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn db() -> Option<PgPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect"),
    )
}

#[tokio::test]
async fn deep_cursor_page_uses_index_cond() {
    let db = skip_if_no_db!(db().await);
    let (table, cursor) = fixture(&db).await;
    let sql = build_cursor_sql(
        &base_sql(&table),
        "\"due_date\"",
        "t.\"due_date\"",
        "ASC",
        &[],
        1,
        true,
    );
    let plan = explain(&db, &sql, &[], Some(cursor)).await;
    assert!(plan.contains("Index Cond"), "{plan}");
    assert!(plan.contains("due_date"), "{plan}");
    for line in plan
        .lines()
        .filter(|l| l.contains("Rows Removed by Join Filter"))
    {
        let removed: i64 = line
            .rsplit(':')
            .next()
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0);
        assert!(
            removed <= PAGE,
            "the join filter read past the page: {plan}"
        );
    }
}

#[tokio::test]
async fn filtered_sorted_page_uses_index_scan() {
    let db = skip_if_no_db!(db().await);
    let (table, _) = fixture(&db).await;
    let sql = build_cursor_sql(
        &base_sql(&table),
        "\"due_date\"",
        "t.\"due_date\"",
        "ASC",
        &["t.\"status\" = $1".to_owned()],
        2,
        false,
    );
    let plan = explain(&db, &sql, &["open"], None).await;
    assert!(plan.contains("Index Scan"), "{plan}");
}

#[tokio::test]
async fn first_page_uses_limit_over_index() {
    let db = skip_if_no_db!(db().await);
    let (table, _) = fixture(&db).await;
    let sql = build_cursor_sql(
        &base_sql(&table),
        "\"due_date\"",
        "t.\"due_date\"",
        "ASC",
        &[],
        1,
        false,
    );
    let plan = explain(&db, &sql, &[], None).await;
    assert!(plan.trim_start().starts_with("Limit"), "{plan}");
    assert!(plan.contains("Index Scan"), "{plan}");
    // An incremental sort over the index (ties on the sort column broken by
    // id, a page's worth of rows) is fine; a full sort reads the table.
    assert!(
        !plan.lines().any(|line| line
            .trim_start()
            .trim_start_matches("->")
            .trim_start()
            .starts_with("Sort (")),
        "no full sort: {plan}"
    );
}
