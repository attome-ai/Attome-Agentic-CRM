//! M48 Phase 1 (Scenario & Simulation) money path for R-12's `scenario.rs`
//! changes: `do_evaluate`'s per-metric result rows and its advisory-lock
//! guard, and `do_compare`'s `with=` cap — exercised directly against
//! `scenario.rs`'s `pub` `do_*` functions, same "call the `pub` `do_*`
//! function, skip the HTTP layer" convention every suite in this crate
//! already uses (see `tests/dashboard_crud.rs`'s module doc comment).
//! Template: `tests/metric.rs`; `mod common` (R-07) supplies the `EngineState` +
//! `SecurityContext` fixtures `do_evaluate`/`do_compare` need (unlike
//! `metric.rs`'s functions, which take a bare `DbPool`).
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI`. Run with `--test-threads=1` (idempotent provisioning
//! DDL shared with the other suites in this crate):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-dashboard --test scenario -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
mod common;

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

async fn insert_scenario(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_scenario (id, name, status) VALUES ($1, $2, 'draft')")
        .bind(id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test dashboard_scenario row");
    id
}

/// Bypasses the generic entity engine and `metric.rs`'s own seed-time
/// validation — same reasoning `tests/metric.rs::insert_manual_metric` gives:
/// this suite exercises `scenario.rs`'s compute/lock logic directly, not
/// entity CRUD.
async fn insert_manual_metric(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition (id, name, key, source_kind, direction, period) \
         VALUES ($1, $2, $3, 'manual', 'higher_is_better', 'month')",
    )
    .bind(id)
    .bind(format!("Test Metric {id}"))
    .bind(format!("test_metric_{id}"))
    .execute(db)
    .await
    .expect("insert test dashboard_metric_definition row");
    id
}

async fn link_scenario_metric(db: &DbPool, scenario_id: Uuid, metric_id: Uuid, display_order: i32) {
    sqlx::query(
        "INSERT INTO dashboard_scenario_metric (id, scenario_ref, metric_ref, display_order) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(scenario_id)
    .bind(metric_id)
    .bind(f64::from(display_order))
    .execute(db)
    .await
    .expect("insert test dashboard_scenario_metric row");
}

async fn result_row_count(db: &DbPool, scenario_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_scenario_result WHERE scenario_ref = $1")
        .bind(scenario_id)
        .fetch_one(db)
        .await
        .expect("count dashboard_scenario_result rows")
}

/// A connection outside the pool, so its transaction is exactly one
/// simulated concurrent request's — `pg_try_advisory_xact_lock` is scoped to
/// the session/transaction, and a pooled connection could otherwise hand the
/// same session to both "requests". Same fixture
/// `attome-api/tests/content_hierarchy_lock.rs::dedicated_connection` uses.
async fn dedicated_connection() -> Option<PgConnection> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgConnection::connect(&url)
            .await
            .expect("connect a dedicated test connection"),
    )
}

#[tokio::test]
async fn evaluate_writes_one_result_row_per_referenced_metric() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    common::seed_once(&state).await;

    let scenario_id = insert_scenario(db, "Two Metric Scenario").await;
    let metric_a = insert_manual_metric(db).await;
    let metric_b = insert_manual_metric(db).await;
    link_scenario_metric(db, scenario_id, metric_a, 0).await;
    link_scenario_metric(db, scenario_id, metric_b, 1).await;

    let actor = Uuid::now_v7();
    let results = attome_dashboard::scenario::do_evaluate(&state, scenario_id, actor)
        .await
        .expect("evaluate must succeed for two ordinary manual metrics");

    assert_eq!(
        results.len(),
        2,
        "one dashboard_scenario_result per referenced metric"
    );
    // Neither metric has a snapshot yet — evaluate_one_metric's documented
    // "no successful snapshot" branch, which still writes a real row.
    assert!(
        results.iter().all(|r| r.status == "pending"),
        "a metric with no snapshot yet must be recorded as pending, not skipped: {:?}",
        results.iter().map(|r| &r.status).collect::<Vec<_>>()
    );

    assert_eq!(
        result_row_count(db, scenario_id).await,
        2,
        "evaluate must persist exactly one row per referenced metric"
    );
}

#[tokio::test]
async fn a_second_evaluate_while_the_first_holds_the_lock_returns_conflict() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    common::seed_once(&state).await;

    let scenario_id = insert_scenario(db, "Locked Scenario").await;
    let metric_id = insert_manual_metric(db).await;
    link_scenario_metric(db, scenario_id, metric_id, 0).await;

    let mut holder = skip_if_no_db!(dedicated_connection().await);
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("BEGIN on the holder connection");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_dashboard::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-dashboard/scenario-evaluate:{scenario_id}"))
        .fetch_one(&mut holder)
        .await
        .expect("take the scenario-evaluate lock on the holder connection");
    assert!(locked, "the holder must be the first to take this lock");

    let actor = Uuid::now_v7();
    let err = attome_dashboard::scenario::do_evaluate(&state, scenario_id, actor)
        .await
        .expect_err("evaluate must be refused while the lock is held open elsewhere");
    assert!(
        matches!(err, attome_types::AppError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    sqlx::query("ROLLBACK")
        .execute(&mut holder)
        .await
        .expect("ROLLBACK the holder connection");

    // Releasing the lock lets a subsequent evaluate proceed normally.
    let results = attome_dashboard::scenario::do_evaluate(&state, scenario_id, actor)
        .await
        .expect("evaluate must succeed once the lock is released");
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn compare_rejects_more_than_ten_additional_scenarios() {
    let state = skip_if_no_db!(common::test_state().await);
    common::seed_once(&state).await;
    let actor = Uuid::now_v7();
    let ctx = common::admin_ctx(actor);

    let anchor = Uuid::now_v7();
    let with = (0..11)
        .map(|_| Uuid::now_v7().to_string())
        .collect::<Vec<_>>()
        .join(",");

    let err = attome_dashboard::scenario::do_compare(&state, &ctx, anchor, Some(&with))
        .await
        .expect_err("more than 10 additional scenarios in `with` must be rejected");
    assert!(
        matches!(err, attome_types::AppError::Validation(_)),
        "expected Validation, got {err:?}"
    );
}

#[tokio::test]
async fn compare_accepts_exactly_ten_additional_scenarios() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    common::seed_once(&state).await;
    let actor = Uuid::now_v7();
    let ctx = common::admin_ctx(actor);

    let anchor = insert_scenario(db, "Anchor").await;
    let mut with_ids = Vec::with_capacity(10);
    for i in 0..10 {
        with_ids.push(insert_scenario(db, &format!("Peer {i}")).await);
    }
    let with = with_ids
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let response = attome_dashboard::scenario::do_compare(&state, &ctx, anchor, Some(&with))
        .await
        .expect("exactly 10 additional scenarios must be accepted");
    assert_eq!(
        response.scenarios.len(),
        11,
        "the anchor plus 10 peers must all appear in the grid"
    );
}
