//! Integration test for `attome_project::baseline::capture_baseline` — the
//! first mutation this crate owns. Covers: (1) capturing snapshots every
//! active work item's own start/due/points, (2) an inactive work item is
//! excluded, (3) capturing twice with the same `(project_id, label)` is
//! retry-safe — the second call returns the first baseline rather than
//! creating a duplicate.
//!
//! Requires a live Postgres (`DATABASE_URL`) with the platform's migrations
//! already applied — same convention as the sibling test files. Run
//! manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-project --test baseline -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use attome_project::baseline::capture_baseline;
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

/// Idempotent — safe at the top of every test, even concurrently against
/// the shared per-binary test database (D-343).
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
        .bind(format!("Baseline Test Organization {id}"))
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
    .bind(format!("Baseline Test Project {id}"))
    .bind(format!("PRJ-BL-{id}"))
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
    name: &str,
    points: f64,
    start_date: chrono::DateTime<chrono::Utc>,
    due_date: chrono::DateTime<chrono::Utc>,
    is_active: bool,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO project_work_item \
         (id, name, project_id, item_type, points, status, start_date, due_date, is_active) \
         VALUES ($1, $2, $3, 'task', $4, 'not_started', $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(project_id)
    .bind(points)
    .bind(start_date)
    .bind(due_date)
    .bind(is_active)
    .execute(db)
    .await
    .expect("insert project_work_item");
    id
}

async fn baseline_items(
    db: &DbPool,
    baseline_id: Uuid,
) -> Vec<(
    Uuid,
    Option<f64>,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
)> {
    sqlx::query_as::<
        _,
        (
            Uuid,
            Option<f64>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT work_item_id, planned_points::double precision, planned_start, planned_due \
         FROM project_baseline_item WHERE baseline_id = $1",
    )
    .bind(baseline_id)
    .fetch_all(db)
    .await
    .expect("select project_baseline_item")
}

#[tokio::test]
async fn capture_snapshots_every_active_work_item_and_skips_inactive_ones() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let project_id = insert_project(&db, organization_id).await;
    let user_id = Uuid::now_v7();

    let day = |n: i64| chrono::Utc::now() + chrono::Duration::days(n);
    let active = insert_work_item(&db, project_id, "Active Item", 5.0, day(0), day(3), true).await;
    let _inactive =
        insert_work_item(&db, project_id, "Inactive Item", 8.0, day(0), day(5), false).await;

    let (response, created) = capture_baseline(&db, project_id, user_id, "Baseline A", "manual")
        .await
        .expect("capture_baseline");

    assert!(
        created,
        "first capture must be a fresh insert, not a replay"
    );
    assert_eq!(response.project_id, project_id);
    assert_eq!(response.label, "Baseline A");
    assert_eq!(response.trigger, "manual");
    assert_eq!(
        response.item_count, 1,
        "only the active work item is captured"
    );

    let items = baseline_items(&db, response.baseline_id).await;
    assert_eq!(items.len(), 1);
    let (item_id, planned_points, ..) = &items[0];
    assert_eq!(*item_id, active);
    assert_eq!(*planned_points, Some(5.0));
}

#[tokio::test]
async fn capturing_twice_with_the_same_label_is_retry_safe_not_a_duplicate() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let project_id = insert_project(&db, organization_id).await;
    let user_id = Uuid::now_v7();

    let day = |n: i64| chrono::Utc::now() + chrono::Duration::days(n);
    insert_work_item(&db, project_id, "Item", 3.0, day(0), day(2), true).await;

    let (first, first_created) =
        capture_baseline(&db, project_id, user_id, "Sprint 1 Baseline", "manual")
            .await
            .expect("first capture_baseline");
    assert!(first_created);

    let (second, second_created) =
        capture_baseline(&db, project_id, user_id, "Sprint 1 Baseline", "manual")
            .await
            .expect("second capture_baseline");

    assert!(
        !second_created,
        "a retry with the same (project_id, label) must not create a new row"
    );
    assert_eq!(
        second.baseline_id, first.baseline_id,
        "the retry must return the exact same baseline"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM project_baseline WHERE project_id = $1 AND label = $2",
    )
    .bind(project_id)
    .bind("Sprint 1 Baseline")
    .fetch_one(&db)
    .await
    .expect("count project_baseline");
    assert_eq!(
        count, 1,
        "exactly one baseline row must exist for this label"
    );
}

#[tokio::test]
async fn a_different_label_on_the_same_project_captures_a_second_independent_baseline() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let project_id = insert_project(&db, organization_id).await;
    let user_id = Uuid::now_v7();

    let day = |n: i64| chrono::Utc::now() + chrono::Duration::days(n);
    insert_work_item(&db, project_id, "Item", 3.0, day(0), day(2), true).await;

    let (first, _) = capture_baseline(&db, project_id, user_id, "Initial", "initial")
        .await
        .expect("first capture_baseline");
    let (second, second_created) =
        capture_baseline(&db, project_id, user_id, "Post-CR-1", "change_request")
            .await
            .expect("second capture_baseline");

    assert!(second_created);
    assert_ne!(first.baseline_id, second.baseline_id);
    assert_eq!(second.trigger, "change_request");
}
