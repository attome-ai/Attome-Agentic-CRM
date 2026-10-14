//! Integration test for `attome_project::portfolio_program`'s aggregation SQL —
//! `project_aggregates_for_programs`/`leaf_points_for_programs`, exercised
//! directly (no HTTP/security layer) the same way `tests/rollup.rs` exercises
//! `work_plan::rollup_rows_for_project`. Builds Portfolio -> Program ->
//! 2 Projects, each with leaf work items, and asserts the roll-up against
//! hand-computed totals at both the program and portfolio scope.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use attome_project::portfolio_program::{
    PORTFOLIO_SCOPE, PROGRAM_SCOPE, leaf_points_for_programs, project_aggregates_for_programs,
};
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
        .bind(format!("PP Test Organization {id}"))
        .execute(db)
        .await
        .expect("insert organization");
    id
}

async fn insert_portfolio(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO project_portfolio (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("PP Test Portfolio {id}"))
        .execute(db)
        .await
        .expect("insert project_portfolio");
    id
}

async fn insert_program(db: &DbPool, portfolio_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO project_program (id, name, portfolio_id) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("PP Test Program {id}"))
        .bind(portfolio_id)
        .execute(db)
        .await
        .expect("insert project_program");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_project(
    db: &DbPool,
    organization_id: Uuid,
    program_id: Uuid,
    health: &str,
    budget_amount: f64,
    budget_consumed: f64,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attome_project \
         (id, name, project_code, organization_id, program_id, health, budget_amount, budget_consumed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(format!("PP Test Project {id}"))
    .bind(format!("PP-TEST-{id}"))
    .bind(organization_id)
    .bind(program_id)
    .bind(health)
    .bind(budget_amount)
    .bind(budget_consumed)
    .execute(db)
    .await
    .expect("insert attome_project");
    id
}

async fn insert_leaf_work_item(db: &DbPool, project_id: Uuid, points: f64, status: &str) {
    sqlx::query(
        "INSERT INTO project_work_item (id, name, project_id, item_type, points, status) \
         VALUES ($1, $2, $3, 'task', $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind("leaf")
    .bind(project_id)
    .bind(points)
    .bind(status)
    .execute(db)
    .await
    .expect("insert project_work_item");
}

/// Portfolio -> one Program -> two Projects: green project (10 pts done of
/// 15, budget 1000/400) and red project (2 pts done of 8, budget 500/500).
/// Hand-computed totals: project_count=2, health_green=1, health_red=1,
/// points_completed=12, points_total=23, budget_amount_total=1500,
/// budget_consumed_total=900. Since the portfolio has only this one program,
/// scoping by PORTFOLIO_SCOPE must produce the exact same numbers as
/// PROGRAM_SCOPE — that equality is itself part of what this test proves.
#[tokio::test]
async fn program_and_portfolio_scopes_roll_up_the_same_two_projects_identically() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let organization_id = insert_organization(&db).await;
    let portfolio_id = insert_portfolio(&db).await;
    let program_id = insert_program(&db, portfolio_id).await;

    let green_project =
        insert_project(&db, organization_id, program_id, "green", 1000.0, 400.0).await;
    insert_leaf_work_item(&db, green_project, 10.0, "done").await;
    insert_leaf_work_item(&db, green_project, 5.0, "in_progress").await;

    let red_project = insert_project(&db, organization_id, program_id, "red", 500.0, 500.0).await;
    insert_leaf_work_item(&db, red_project, 2.0, "done").await;
    insert_leaf_work_item(&db, red_project, 6.0, "blocked").await;

    for (scope, bind) in [(PROGRAM_SCOPE, program_id), (PORTFOLIO_SCOPE, portfolio_id)] {
        let (
            project_count,
            health_green,
            health_amber,
            health_red,
            budget_amount_total,
            budget_consumed_total,
        ) = project_aggregates_for_programs(&db, scope, bind)
            .await
            .expect("project_aggregates_for_programs");
        assert_eq!(project_count, 2, "scope {scope:?}: project_count");
        assert_eq!(health_green, 1, "scope {scope:?}: health_green");
        assert_eq!(health_amber, 0, "scope {scope:?}: health_amber");
        assert_eq!(health_red, 1, "scope {scope:?}: health_red");
        assert_eq!(
            budget_amount_total,
            Some(1500.0),
            "scope {scope:?}: budget_amount_total"
        );
        assert_eq!(
            budget_consumed_total,
            Some(900.0),
            "scope {scope:?}: budget_consumed_total"
        );

        let (points_completed, points_total) = leaf_points_for_programs(&db, scope, bind)
            .await
            .expect("leaf_points_for_programs");
        assert_eq!(points_completed, 12, "scope {scope:?}: points_completed");
        assert_eq!(points_total, 23, "scope {scope:?}: points_total");
    }
}

#[tokio::test]
async fn a_program_with_no_projects_rolls_up_to_zero_not_an_error() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let portfolio_id = insert_portfolio(&db).await;
    let program_id = insert_program(&db, portfolio_id).await;

    let (
        project_count,
        health_green,
        health_amber,
        health_red,
        budget_amount_total,
        budget_consumed_total,
    ) = project_aggregates_for_programs(&db, PROGRAM_SCOPE, program_id)
        .await
        .expect("project_aggregates_for_programs");
    assert_eq!(project_count, 0);
    assert_eq!((health_green, health_amber, health_red), (0, 0, 0));
    assert_eq!(budget_amount_total, None);
    assert_eq!(budget_consumed_total, None);

    let (points_completed, points_total) = leaf_points_for_programs(&db, PROGRAM_SCOPE, program_id)
        .await
        .expect("leaf_points_for_programs");
    assert_eq!((points_completed, points_total), (0, 0));
}
