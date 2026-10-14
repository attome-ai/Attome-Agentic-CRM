//! Integration test for `attome_project::work_plan::rollup_rows_for_project` —
//! the money-path arithmetic behind the WBS "point-weighted progress" rule:
//! a leaf's own points/status roll up to every ancestor, "done" contributes
//! 100% of its points, "in progress"/"not started" contribute 0%, and
//! "blocked" points are surfaced separately rather than netted out. Seeds a
//! small phase → 3-task tree (one done, one blocked, one in progress) and
//! asserts every row's rollup against hand-computed values.
//!
//! Requires a live Postgres (`DATABASE_URL`) with the platform's migrations
//! already applied — same convention as `attome-notification/tests/dispatch.rs`.
//! Run manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-project --test rollup -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use attome_project::model::WorkItemRollupRow;
use attome_project::work_plan::rollup_rows_for_project;
use sqlx::postgres::PgPoolOptions;
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

/// Idempotent — safe to call at the top of every test in this file, even
/// concurrently against the same shared per-binary test database (D-343):
/// both seeds only ever insert-if-missing.
async fn ensure_seeded(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed");
}

async fn insert_organization(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("Rollup Test Organization {id}"))
        .execute(db)
        .await
        .expect("insert organization");
    id
}

async fn insert_project(db: &DbPool, organization_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attome_project (id, name, project_code, organization_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(format!("Rollup Test Project {id}"))
    .bind(format!("PRJ-TEST-{id}"))
    .bind(organization_id)
    .execute(db)
    .await
    .expect("insert attome_project");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_work_item(
    db: &DbPool,
    project_id: Uuid,
    parent_id: Option<Uuid>,
    name: &str,
    item_type: &str,
    points: f64,
    status: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO project_work_item \
         (id, name, project_id, parent_work_item_id, item_type, points, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(project_id)
    .bind(parent_id)
    .bind(item_type)
    .bind(points)
    .bind(status)
    .execute(db)
    .await
    .expect("insert project_work_item");
    id
}

fn row_for(rows: &[WorkItemRollupRow], id: Uuid) -> &WorkItemRollupRow {
    rows.iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no rollup row for work item {id}"))
}

/// Same shape as `insert_work_item`, plus `start_date`/`due_date` — needed
/// for critical-path tests, which compute duration from that pair.
#[allow(clippy::too_many_arguments)]
async fn insert_work_item_with_dates(
    db: &DbPool,
    project_id: Uuid,
    name: &str,
    item_type: &str,
    status: &str,
    start_date: chrono::DateTime<chrono::Utc>,
    due_date: chrono::DateTime<chrono::Utc>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO project_work_item \
         (id, name, project_id, item_type, points, status, start_date, due_date) \
         VALUES ($1, $2, $3, $4, 0, $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(project_id)
    .bind(item_type)
    .bind(status)
    .bind(start_date)
    .bind(due_date)
    .execute(db)
    .await
    .expect("insert project_work_item with dates");
    id
}

async fn insert_dependency(
    db: &DbPool,
    predecessor_id: Uuid,
    successor_id: Uuid,
    dependency_type: &str,
    lag_days: f64,
) {
    sqlx::query(
        "INSERT INTO project_work_item_dependency \
         (id, predecessor_id, successor_id, dependency_type, lag_days) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(predecessor_id)
    .bind(successor_id)
    .bind(dependency_type)
    .bind(lag_days)
    .execute(db)
    .await
    .expect("insert project_work_item_dependency");
}

#[tokio::test]
async fn phase_rollup_matches_hand_computed_leaf_totals() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let project_id = insert_project(&db, organization_id).await;

    // Phase (parent, own points deliberately nonzero to prove it's ignored —
    // "a phase/parent row never contributes its own points" per the WBS rule).
    let phase_id = insert_work_item(
        &db,
        project_id,
        None,
        "Phase 1",
        "phase",
        99.0,
        "not_started",
    )
    .await;
    // Leaf tasks under the phase: 5 done, 3 blocked, 2 in progress.
    let done_task = insert_work_item(
        &db,
        project_id,
        Some(phase_id),
        "Done Task",
        "task",
        5.0,
        "done",
    )
    .await;
    let blocked_task = insert_work_item(
        &db,
        project_id,
        Some(phase_id),
        "Blocked Task",
        "task",
        3.0,
        "blocked",
    )
    .await;
    let in_progress_task = insert_work_item(
        &db,
        project_id,
        Some(phase_id),
        "In Progress Task",
        "task",
        2.0,
        "in_progress",
    )
    .await;

    let rows = rollup_rows_for_project(&db, project_id)
        .await
        .expect("rollup_rows_for_project");
    assert_eq!(rows.len(), 4, "phase + 3 leaf tasks");

    // Phase: total = 5+3+2 = 10, completed = 5 (done only), blocked = 3.
    let phase = row_for(&rows, phase_id);
    assert_eq!(phase.points_total, 10);
    assert_eq!(phase.points_completed, 5);
    assert_eq!(phase.points_blocked, 3);
    assert!(
        (phase.progress_pct - 50.0).abs() < 1e-9,
        "phase progress_pct: expected 50.0, got {}",
        phase.progress_pct
    );

    // Done leaf: contributes 100% of its own points, nothing blocked.
    let done = row_for(&rows, done_task);
    assert_eq!(done.points_total, 5);
    assert_eq!(done.points_completed, 5);
    assert_eq!(done.points_blocked, 0);
    assert!((done.progress_pct - 100.0).abs() < 1e-9);

    // Blocked leaf: counted in points_total and points_blocked, NOT in
    // points_completed — "blocked points are surfaced separately", never
    // netted into completed or silently dropped.
    let blocked = row_for(&rows, blocked_task);
    assert_eq!(blocked.points_total, 3);
    assert_eq!(blocked.points_completed, 0);
    assert_eq!(blocked.points_blocked, 3);
    assert!((blocked.progress_pct - 0.0).abs() < 1e-9);

    // In-progress leaf: contributes 0% until done, per the stated rule.
    let in_progress = row_for(&rows, in_progress_task);
    assert_eq!(in_progress.points_total, 2);
    assert_eq!(in_progress.points_completed, 0);
    assert_eq!(in_progress.points_blocked, 0);
    assert!((in_progress.progress_pct - 0.0).abs() < 1e-9);
}

#[tokio::test]
async fn empty_project_has_no_rollup_rows() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let project_id = insert_project(&db, organization_id).await;

    let rows = rollup_rows_for_project(&db, project_id)
        .await
        .expect("rollup_rows_for_project");
    assert!(
        rows.is_empty(),
        "a project with no work items yet must roll up to an empty list, not error"
    );
}

/// End-to-end proof that `work_plan.rs` actually wires `critical_path.rs`
/// up to real `project_work_item_dependency` rows — the pure algorithm
/// itself is covered by `critical_path.rs`'s own unit tests
/// (`cargo test -p attome-project --lib`, no database). Two branches off A:
/// A->B is an 8-day task with no further dependency; A->C->D is a 2-day
/// task feeding a 3-day task, 5 days total. The B branch is strictly
/// longer, so A and B sit on the critical path (zero float) while C and D
/// each carry the 3-day difference as float.
#[tokio::test]
async fn critical_path_marks_the_longer_chain_and_gives_the_shorter_one_float() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let project_id = insert_project(&db, organization_id).await;

    let day = |n: i64| chrono::Utc::now() + chrono::Duration::days(n);

    let a =
        insert_work_item_with_dates(&db, project_id, "A", "task", "not_started", day(0), day(0))
            .await;
    let b =
        insert_work_item_with_dates(&db, project_id, "B", "task", "not_started", day(0), day(8))
            .await;
    let c =
        insert_work_item_with_dates(&db, project_id, "C", "task", "not_started", day(0), day(2))
            .await;
    let d =
        insert_work_item_with_dates(&db, project_id, "D", "task", "not_started", day(0), day(3))
            .await;

    insert_dependency(&db, a, b, "finish_to_start", 0.0).await;
    insert_dependency(&db, a, c, "finish_to_start", 0.0).await;
    insert_dependency(&db, c, d, "finish_to_start", 0.0).await;

    let rows = rollup_rows_for_project(&db, project_id)
        .await
        .expect("rollup_rows_for_project");

    assert!(row_for(&rows, a).is_critical_path);
    assert!(
        row_for(&rows, b).is_critical_path,
        "A->B (8 days) is the longer branch"
    );
    assert_eq!(row_for(&rows, b).total_float_days, Some(0));
    assert!(
        !row_for(&rows, c).is_critical_path,
        "A->C->D is 5 days, 3 days shorter than A->B"
    );
    assert_eq!(row_for(&rows, c).total_float_days, Some(3));
    assert!(!row_for(&rows, d).is_critical_path);
    assert_eq!(row_for(&rows, d).total_float_days, Some(3));
}
