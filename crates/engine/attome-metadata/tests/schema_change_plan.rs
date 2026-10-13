//! End-to-end coverage for the async `ApplySchemaChangePlan` path
//! (P-online-schema-change Steps 2-5, D-180).
//!
//! D-180 shipped this engine code-only and listed the gaps itself: no
//! integration test for the async path end-to-end, migration `0069` never run
//! against a live Postgres, and the row-CAS claim's concurrency behavior
//! "reasoned about against D-100's precedent, not exercised". This suite
//! closes the first, exercises the second by construction (it writes to
//! `schema_change_operation`, which only exists if `0069` applied),
//! and covers the resume/duplicate-delivery half of the third.
//!
//! `queue_schema_change_plan` enqueues the apalis job in the same transaction
//! as the ledger insert, so this suite needs the *whole* migrated schema, not
//! just `0069` — the job table's `generate_ulid()` default comes from `0014`.
//! That is why it targets the standard migrated test schema rather than
//! building a throwaway one.
//!
//! Requires a live Postgres with migrations applied — the same setup
//! `scripts/run-integration-tests.ps1` performs. Skips (loudly) when
//! `DATABASE_URL` is unset, except under `CI` (see `attome_testkit`):
//!
//! ```powershell
//! docker exec attome-postgres-test psql -U postgres -d attomedb_test -c "CREATE SCHEMA IF NOT EXISTS attome_dev;"
//! sqlx migrate run --database-url "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic" --source crates/server/migrations
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-metadata --test schema_change_plan -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_metadata::provision::{
    SchemaChangePlanRequest, apply_schema_change_plan, queue_schema_change_plan,
};
use attome_types::AppError;
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

/// Entity-shaped table: `id UUID` is what the backfill loop cursors on.
async fn seed_entity_table(db: &DbPool, table: &str, rows: i32, null_every: i32) {
    sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{table}""#))
        .execute(db)
        .await
        .expect("drop stale fixture");
    sqlx::query(&format!(
        r#"CREATE TABLE "{table}" (id UUID PRIMARY KEY DEFAULT uuidv7(), note TEXT)"#
    ))
    .execute(db)
    .await
    .expect("create entity table");
    sqlx::query(&format!(
        r#"INSERT INTO "{table}" (note)
           SELECT CASE WHEN g % $2 = 0 THEN NULL ELSE 'v' || g END
           FROM generate_series(1, $1) g"#
    ))
    .bind(rows)
    .bind(null_every)
    .execute(db)
    .await
    .expect("seed rows");
}

async fn plan_status(db: &DbPool, plan_id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, error_message FROM schema_change_operation WHERE id = $1")
        .bind(plan_id)
        .fetch_one(db)
        .await
        .expect("read ledger row")
}

async fn null_count(db: &DbPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!(
        r#"SELECT COUNT(*) FROM "{table}" WHERE note IS NULL"#
    ))
    .fetch_one(db)
    .await
    .expect("count nulls")
}

async fn is_not_null(db: &DbPool, table: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT attnotnull FROM pg_attribute \
         WHERE attrelid = $1::regclass AND attname = 'note'",
    )
    .bind(table)
    .fetch_one(db)
    .await
    .expect("read attnotnull")
}

/// The end-to-end path D-180 left unproven, under D-788: queue a required
/// plan, run the job, and watch the ledger go terminal — with **no** backfill
/// (a supplied `backfill_default` is ignored) and **no** physical NOT NULL:
/// required is application-level and existing empty rows stay empty.
#[tokio::test]
async fn queued_required_plan_neither_backfills_nor_installs_not_null() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_plan_e2e";
    seed_entity_table(&db, table, 5_000, 7).await;
    let before = null_count(&db, table).await;
    assert!(before > 0, "fixture must start with NULLs");

    let plan_id = queue_schema_change_plan(
        &db,
        SchemaChangePlanRequest {
            entity_id: Uuid::now_v7(),
            attribute_id: Uuid::now_v7(),
            entity_logicalname: table,
            field_logicalname: "note",
            field_type: "text",
            target_required: true,
            target_max_length: None,
            previous_required: false,
            previous_max_length: None,
            backfill_default: Some(serde_json::json!("backfilled")),
            is_multi: false,
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .expect("queue plan");

    assert_eq!(plan_status(&db, plan_id).await.0, "queued");

    apply_schema_change_plan(&db, plan_id)
        .await
        .expect("job should succeed");

    let (status, error) = plan_status(&db, plan_id).await;
    assert_eq!(status, "succeeded", "ledger error was: {error:?}");
    assert_eq!(
        null_count(&db, table).await,
        before,
        "D-788: empty rows stay empty (no backfill)"
    );
    assert!(
        !is_not_null(&db, table).await,
        "D-788: no physical NOT NULL"
    );
}

/// A plan that cannot succeed must land `failed` with a readable reason rather
/// than half-applying or looping. Under D-788 only a `max_length` contract can
/// fail: existing values longer than the limit refuse the VALIDATE.
#[tokio::test]
async fn plan_that_cannot_validate_lands_failed_with_a_reason() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_plan_fail";
    seed_entity_table(&db, table, 300, 10).await;

    let plan_id = queue_schema_change_plan(
        &db,
        SchemaChangePlanRequest {
            entity_id: Uuid::now_v7(),
            attribute_id: Uuid::now_v7(),
            entity_logicalname: table,
            field_logicalname: "note",
            field_type: "text",
            target_required: false,
            target_max_length: Some(1),
            previous_required: false,
            previous_max_length: None,
            backfill_default: None,
            is_multi: false,
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .expect("queue plan");

    let outcome = apply_schema_change_plan(&db, plan_id).await;

    let (status, error) = plan_status(&db, plan_id).await;
    assert_eq!(
        status, "failed",
        "a plan whose terminal DDL is refused must be recorded failed, got {status} / {error:?}"
    );
    assert!(
        error.is_some_and(|e| !e.is_empty()),
        "failed plans must carry an operator-readable reason"
    );
    let _ = outcome;
}

/// Re-running a terminal plan is a no-op, not a second application — the
/// row-CAS claim refuses it. This is the resume/duplicate-delivery half of
/// D-180's untested concurrency note (apalis can deliver a job more than once).
#[tokio::test]
async fn reapplying_a_terminal_plan_is_a_no_op() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_plan_again";
    seed_entity_table(&db, table, 100, 5).await;

    let plan_id = queue_schema_change_plan(
        &db,
        SchemaChangePlanRequest {
            entity_id: Uuid::now_v7(),
            attribute_id: Uuid::now_v7(),
            entity_logicalname: table,
            field_logicalname: "note",
            field_type: "text",
            target_required: true,
            target_max_length: None,
            previous_required: false,
            previous_max_length: None,
            backfill_default: Some(serde_json::json!("x")),
            is_multi: false,
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .expect("queue plan");

    apply_schema_change_plan(&db, plan_id)
        .await
        .expect("first apply");
    assert_eq!(plan_status(&db, plan_id).await.0, "succeeded");

    // Second delivery of the same job.
    apply_schema_change_plan(&db, plan_id)
        .await
        .expect("second apply must not error");
    assert_eq!(
        plan_status(&db, plan_id).await.0,
        "succeeded",
        "a terminal plan must stay terminal"
    );
    assert!(
        !is_not_null(&db, table).await,
        "D-788: no physical NOT NULL"
    );
}

/// C-22: a multi-valued (`TEXT[]`/`JSONB`, D-078/D-362) column cannot support
/// `max_length` (its CHECK constraint calls `char_length`, undefined against
/// `jsonb`) or a backfill `default_value` (a scalar cast via
/// `$1::text::{pg_type}` is meaningless against an array/object type). Both
/// used to reach Postgres from deep inside the async job and surface as an
/// opaque `AppError::internal`; `queue_schema_change_plan` must now refuse
/// them at enqueue time with a `Validation` (422) instead, before any ledger
/// row is even inserted.
#[tokio::test]
async fn queue_refuses_max_length_and_backfill_default_for_a_multi_valued_field() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_plan_multi";
    seed_entity_table(&db, table, 10, 1_000).await;

    let max_length_err = queue_schema_change_plan(
        &db,
        SchemaChangePlanRequest {
            entity_id: Uuid::now_v7(),
            attribute_id: Uuid::now_v7(),
            entity_logicalname: table,
            field_logicalname: "note",
            field_type: "file",
            target_required: false,
            target_max_length: Some(255),
            previous_required: false,
            previous_max_length: None,
            backfill_default: None,
            is_multi: true,
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .expect_err("max_length on a multi-valued column must be refused");
    assert!(
        matches!(max_length_err, AppError::Validation(_)),
        "expected a 422 Validation error, got {max_length_err:?}"
    );

    let backfill_err = queue_schema_change_plan(
        &db,
        SchemaChangePlanRequest {
            entity_id: Uuid::now_v7(),
            attribute_id: Uuid::now_v7(),
            entity_logicalname: table,
            field_logicalname: "note",
            field_type: "file",
            target_required: true,
            target_max_length: None,
            previous_required: false,
            previous_max_length: None,
            backfill_default: Some(serde_json::json!("x")),
            is_multi: true,
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .expect_err("a backfill default_value on a multi-valued column must be refused");
    assert!(
        matches!(backfill_err, AppError::Validation(_)),
        "expected a 422 Validation error, got {backfill_err:?}"
    );

    let ledger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM schema_change_operation WHERE entity_logicalname = $1",
    )
    .bind(table)
    .fetch_one(&db)
    .await
    .expect("count ledger rows");
    assert_eq!(
        ledger_rows, 0,
        "a refused request must never insert a ledger row (the whole transaction rolls back)"
    );

    // The same combination on a non-multi field is unaffected — proves the
    // refusal is keyed on `is_multi`, not on `field_type == \"file\"` alone.
    let plan_id = queue_schema_change_plan(
        &db,
        SchemaChangePlanRequest {
            entity_id: Uuid::now_v7(),
            attribute_id: Uuid::now_v7(),
            entity_logicalname: table,
            field_logicalname: "note",
            field_type: "file",
            target_required: false,
            target_max_length: Some(255),
            previous_required: false,
            previous_max_length: None,
            backfill_default: None,
            is_multi: false,
            created_by: Uuid::now_v7(),
        },
    )
    .await
    .expect("max_length on a scalar file field must still be accepted");
    assert_eq!(plan_status(&db, plan_id).await.0, "queued");
}
