//! Integration tests for `attome_grc::lifecycle::{start_assessment,
//! remediate_finding}` — exercised directly against a real database, same
//! shape as `attome-service/tests/offering.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use attome_grc::lifecycle::{remediate_finding, start_assessment};
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
    attome_grc::seed::seed(db)
        .await
        .expect("attome_grc::seed::seed");
}

async fn insert_assessment(db: &DbPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO grc_assessment (id, name, status) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("Lifecycle Test Assessment {id}"))
        .bind(status)
        .execute(db)
        .await
        .expect("insert grc_assessment");
    id
}

async fn insert_finding(db: &DbPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO grc_finding (id, title, status) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("Lifecycle Test Finding {id}"))
        .bind(status)
        .execute(db)
        .await
        .expect("insert grc_finding");
    id
}

#[tokio::test]
async fn starting_a_planned_assessment_moves_it_to_in_progress() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;
    let assessment_id = insert_assessment(&db, "planned").await;

    let response = start_assessment(&db, assessment_id)
        .await
        .expect("start_assessment");
    assert_eq!(response.status, "in_progress");

    let stored: String = sqlx::query_scalar("SELECT status FROM grc_assessment WHERE id = $1")
        .bind(assessment_id)
        .fetch_one(&db)
        .await
        .expect("read status");
    assert_eq!(stored, "in_progress");
}

#[tokio::test]
async fn starting_an_already_started_assessment_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;
    let assessment_id = insert_assessment(&db, "in_progress").await;

    let response = start_assessment(&db, assessment_id)
        .await
        .expect("start_assessment on an already-started assessment must not error");
    assert_eq!(response.status, "in_progress");
}

#[tokio::test]
async fn starting_a_nonexistent_assessment_is_not_found() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let err = start_assessment(&db, Uuid::now_v7())
        .await
        .expect_err("a nonexistent assessment must fail");
    assert!(matches!(err, attome_types::AppError::NotFound));
}

#[tokio::test]
async fn remediating_an_open_finding_moves_it_to_remediated() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;
    let finding_id = insert_finding(&db, "open").await;

    let response = remediate_finding(&db, finding_id)
        .await
        .expect("remediate_finding");
    assert_eq!(response.status, "remediated");

    let stored: String = sqlx::query_scalar("SELECT status FROM grc_finding WHERE id = $1")
        .bind(finding_id)
        .fetch_one(&db)
        .await
        .expect("read status");
    assert_eq!(stored, "remediated");
}

#[tokio::test]
async fn remediating_an_already_closed_finding_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;
    let finding_id = insert_finding(&db, "closed").await;

    let response = remediate_finding(&db, finding_id)
        .await
        .expect("remediate_finding on an already-closed finding must not error");
    assert_eq!(response.status, "closed");
}

#[tokio::test]
async fn remediating_a_nonexistent_finding_is_not_found() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let err = remediate_finding(&db, Uuid::now_v7())
        .await
        .expect_err("a nonexistent finding must fail");
    assert!(matches!(err, attome_types::AppError::NotFound));
}
