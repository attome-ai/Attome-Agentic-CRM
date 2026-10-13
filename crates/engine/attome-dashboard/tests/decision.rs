//! R-16 item 2 (`document/xrm/module/M26-dashboard/remediation.md`)
//! — M28 Phase 1 (Decision Intelligence) money path: `decision.rs::do_approve`
//! exercised directly against a live database, same "call the `pub` `do_*`
//! function, skip the HTTP layer" convention every suite in this crate
//! already uses (see `tests/dashboard_crud.rs`'s module doc comment).
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI`. Run with `--test-threads=1` (idempotent provisioning
//! DDL shared with the other suites in this crate):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-dashboard --test decision -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use uuid::Uuid;

/// Bypasses the generic entity engine (same reasoning
/// `dashboard_crud.rs::insert_dashboard` documents) — this suite tests
/// `decision.rs`'s own transaction/lock/validation logic, not entity CRUD.
async fn insert_decision(db: &DbPool, title: &str, status: &str) -> (Uuid, i64) {
    let id = Uuid::now_v7();
    let (row_version,): (i64,) = sqlx::query_as(
        "INSERT INTO dashboard_decision (id, title, status) VALUES ($1, $2, $3) \
         RETURNING row_version",
    )
    .bind(id)
    .bind(title)
    .bind(status)
    .fetch_one(db)
    .await
    .expect("insert test dashboard_decision row");
    (id, row_version)
}

async fn insert_decision_option(db: &DbPool, decision_id: Uuid, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_decision_option (id, decision_ref, label) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(decision_id)
    .bind(label)
    .execute(db)
    .await
    .expect("insert test dashboard_decision_option row");
    id
}

async fn status_and_chosen_option(db: &DbPool, id: Uuid) -> (Option<String>, Option<Uuid>, i64) {
    sqlx::query_as(
        "SELECT status, chosen_option_ref, row_version FROM dashboard_decision WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("read dashboard_decision row")
}

#[tokio::test]
async fn do_approve_happy_path_sets_status_and_chosen_option() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let (decision_id, row_version) =
        insert_decision(&db, "Ship the new pricing page?", "proposed").await;
    let option_id = insert_decision_option(&db, decision_id, "Yes, ship it").await;

    let new_row_version =
        attome_dashboard::decision::do_approve(&db, decision_id, option_id, row_version)
            .await
            .expect("approve a proposed decision with an option belonging to it");
    assert_eq!(new_row_version, row_version + 1);

    let (status, chosen_option_ref, db_row_version) =
        status_and_chosen_option(&db, decision_id).await;
    assert_eq!(status.as_deref(), Some("approved"));
    assert_eq!(chosen_option_ref, Some(option_id));
    assert_eq!(db_row_version, new_row_version);
}

/// `decision.rs` ≈ 177-187: the chosen option must actually belong to the
/// decision being approved — otherwise a caller could point
/// `chosen_option_id` at an arbitrary option row from a different decision.
#[tokio::test]
async fn do_approve_rejects_an_option_belonging_to_a_different_decision() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let (decision_a, row_version_a) = insert_decision(&db, "Decision A", "proposed").await;
    let (decision_b, _row_version_b) = insert_decision(&db, "Decision B", "proposed").await;
    let option_of_b = insert_decision_option(&db, decision_b, "B's own option").await;

    let err = attome_dashboard::decision::do_approve(&db, decision_a, option_of_b, row_version_a)
        .await
        .expect_err("an option from a different decision must be rejected");
    assert!(
        matches!(err, attome_types::AppError::Validation(_)),
        "expected Validation, got {err:?}"
    );

    // Nothing must have changed — a rejected approve is not a partial write.
    let (status, chosen_option_ref, db_row_version) =
        status_and_chosen_option(&db, decision_a).await;
    assert_eq!(status.as_deref(), Some("proposed"));
    assert_eq!(chosen_option_ref, None);
    assert_eq!(db_row_version, row_version_a);
}

/// Only a `proposed` decision can be approved — `do_approve` checks state
/// before it ever looks at `row_version`/the chosen option.
#[tokio::test]
async fn do_approve_rejects_a_decision_not_in_the_proposed_state() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let (decision_id, row_version) = insert_decision(&db, "Already approved", "approved").await;
    let option_id = insert_decision_option(&db, decision_id, "Option 1").await;

    let err = attome_dashboard::decision::do_approve(&db, decision_id, option_id, row_version)
        .await
        .expect_err("approving a decision that is not proposed must be refused");
    assert!(
        matches!(err, attome_types::AppError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    let (status, chosen_option_ref, db_row_version) =
        status_and_chosen_option(&db, decision_id).await;
    assert_eq!(
        status.as_deref(),
        Some("approved"),
        "state must be unchanged"
    );
    assert_eq!(chosen_option_ref, None);
    assert_eq!(db_row_version, row_version);
}

/// A stale `row_version` is also refused, even against an otherwise-valid
/// `proposed` decision and a legitimately owned option.
#[tokio::test]
async fn do_approve_rejects_a_stale_row_version() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let (decision_id, row_version) = insert_decision(&db, "Stale version test", "proposed").await;
    let option_id = insert_decision_option(&db, decision_id, "Option 1").await;

    let err = attome_dashboard::decision::do_approve(&db, decision_id, option_id, row_version + 1)
        .await
        .expect_err("a row_version that does not match must be refused");
    assert!(
        matches!(err, attome_types::AppError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
}
