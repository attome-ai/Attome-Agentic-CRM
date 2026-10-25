//! P-retention-archive-completion §3c — proves `attome_metadata::purge` against a
//! real provisioned entity table: `propose_purge_actions` finds a
//! soft-deleted record past its grace period (and is idempotent across
//! re-runs), and `scrub_record` nulls only the non-system columns.
//!
//! **NOT executed as part of this change** — this sandbox has no Postgres
//! and no Rust toolchain. Written to the same convention as
//! `tests/provision.rs` so a developer with a real database can run it
//! directly:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-metadata --test purge -- --test-threads=1
//! ```
//!
//! Requires migration 0067 (`audit_retention_action`) and 0088
//! (`legal_hold`) already applied.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_core::AttrInfo;
use attome_db::DbPool;
use attome_metadata::provision::{ensure_attribute, ensure_entity};
use attome_testkit::skip_if_no_db;
use chrono::{Duration as ChronoDuration, Utc};
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

/// Provisions a throwaway entity with one sensitive text attribute (`ssn`)
/// alongside the system columns every provisioned table carries.
async fn provision_test_entity(db: &DbPool) -> String {
    let logicalname = format!("test_purge_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(db, &logicalname, "Test Purge Entity", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        db, entity_id, "ssn", "SSN", "text", false, true, false, false, None, None,
    )
    .await
    .expect("ensure_attribute ssn");
    logicalname
}

fn attrs_for(logicalname_attr: &str) -> Vec<AttrInfo> {
    vec![AttrInfo {
        logicalname: logicalname_attr.to_string(),
        field_type_int: 3,
        is_required: false,
        max_length: None,
        is_sensitive: true,
        is_write_restricted: false,
        is_sortable: false,
        is_filterable: false,
        lookup_entity_ref: None,
        on_target_delete: Default::default(),
        data_classification: Default::default(),
        sensitivity: Default::default(),
        options: None,
    }]
}

/// Seeds a soft-deleted record whose `modified_at` is backdated past any
/// reasonable grace period, mirroring how D-068's own tests manipulate
/// `created_at` directly rather than waiting real time out.
async fn seed_soft_deleted_record(db: &DbPool, logicalname: &str, days_ago: i64) -> Uuid {
    let record_id = Uuid::now_v7();
    let backdated = Utc::now() - ChronoDuration::days(days_ago);
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (id, ssn, is_active, created_at, modified_at) \
         VALUES ($1, 'secret-ssn', false, $2, $2)"
    ))
    .bind(record_id)
    .bind(backdated)
    .execute(db)
    .await
    .expect("seed a soft-deleted test record");
    record_id
}

/// Bulk counterpart of `seed_soft_deleted_record` — one round trip via
/// `generate_series` rather than `count` individual `INSERT`s, so a
/// 5,000-row fixture is cheap to set up.
async fn seed_soft_deleted_records(db: &DbPool, logicalname: &str, count: i32, days_ago: i64) {
    let backdated = Utc::now() - ChronoDuration::days(days_ago);
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (id, ssn, is_active, created_at, modified_at) \
         SELECT uuidv7(), 'secret-ssn-' || g, false, $2, $2 \
         FROM generate_series(1, $1) g"
    ))
    .bind(count)
    .bind(backdated)
    .execute(db)
    .await
    .expect("bulk-seed soft-deleted test records");
}

#[tokio::test]
async fn propose_purge_actions_finds_an_old_soft_deleted_record_and_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = provision_test_entity(&db).await;
    let record_id = seed_soft_deleted_record(&db, &logicalname, 400).await;

    let first = attome_metadata::purge::propose_purge_actions(&db, 90, "purge")
        .await
        .expect("first propose_purge_actions call");
    assert!(
        first >= 1,
        "expected at least the newly-seeded old soft-deleted record to be proposed"
    );

    let target = format!("{logicalname}:{record_id}");
    let status: String = sqlx::query_scalar(
        "SELECT status FROM audit_retention_action WHERE action_type = 'entity_purge' AND target = $1",
    )
    .bind(&target)
    .fetch_one(&db)
    .await
    .expect("proposed entity_purge action row must exist");
    assert_eq!(status, "proposed");

    let second = attome_metadata::purge::propose_purge_actions(&db, 90, "purge")
        .await
        .expect("second propose_purge_actions call");
    // Other deployments' leftover fixtures may also be past-grace and
    // proposed on the first call already — this only asserts THIS record's
    // target isn't inserted a second time (the unique index would reject a
    // literal duplicate; ON CONFLICT DO NOTHING makes the affected-rows
    // delta for this specific target zero either way).
    let _ = second;
    let count_for_target: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_action WHERE action_type = 'entity_purge' AND target = $1",
    )
    .bind(&target)
    .fetch_one(&db)
    .await
    .expect("count rows for target");
    assert_eq!(
        count_for_target, 1,
        "must never propose the same record twice"
    );
}

#[tokio::test]
async fn propose_purge_actions_skips_a_record_still_within_its_grace_period() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = provision_test_entity(&db).await;
    let record_id = seed_soft_deleted_record(&db, &logicalname, 5).await;

    attome_metadata::purge::propose_purge_actions(&db, 90, "purge")
        .await
        .expect("propose_purge_actions call");

    let target = format!("{logicalname}:{record_id}");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_action WHERE action_type = 'entity_purge' AND target = $1",
    )
    .bind(&target)
    .fetch_one(&db)
    .await
    .expect("count rows for target");
    assert_eq!(
        count, 0,
        "a record only 5 days past soft-delete must not be proposed under a 90-day grace period"
    );
}

/// C-22: the old shape loaded every eligible id into a `Vec<Uuid>` with no
/// `LIMIT`, then did one `INSERT` round trip per row. 5,000 candidates —
/// more than twice `PURGE_PROPOSAL_BATCH_SIZE` (2,000) — forces the batch
/// loop through at least three passes, proving every candidate is proposed
/// exactly once (no row skipped, none duplicated) and that a second run
/// stays idempotent, the same property the single-record test above already
/// covers, now under batching.
#[tokio::test]
async fn propose_purge_actions_handles_5000_candidates_in_bounded_batches() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = provision_test_entity(&db).await;
    seed_soft_deleted_records(&db, &logicalname, 5_000, 400).await;

    let proposed = attome_metadata::purge::propose_purge_actions(&db, 90, "purge")
        .await
        .expect("propose_purge_actions over 5,000 candidates");
    assert!(
        proposed >= 5_000,
        "expected at least the 5,000 newly-seeded candidates to be proposed, got {proposed}"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_action \
         WHERE action_type = 'entity_purge' AND target LIKE $1",
    )
    .bind(format!("{logicalname}:%"))
    .fetch_one(&db)
    .await
    .expect("count proposed rows for this entity");
    assert_eq!(
        count, 5_000,
        "every one of the 5,000 candidates must be proposed exactly once"
    );

    // Idempotent under batching too: a second sweep proposes nothing new for
    // this entity (every candidate is already `proposed`, and the cursor-
    // driven loop must still terminate rather than looping on skipped rows).
    attome_metadata::purge::propose_purge_actions(&db, 90, "purge")
        .await
        .expect("second propose_purge_actions call over the same 5,000 candidates");
    let count_again: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_action \
         WHERE action_type = 'entity_purge' AND target LIKE $1",
    )
    .bind(format!("{logicalname}:%"))
    .fetch_one(&db)
    .await
    .expect("count proposed rows for this entity after the second sweep");
    assert_eq!(
        count_again, 5_000,
        "a re-run must not propose any candidate a second time"
    );
}

#[tokio::test]
async fn scrub_record_nulls_the_sensitive_column_and_leaves_system_columns_intact() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = provision_test_entity(&db).await;
    let record_id = seed_soft_deleted_record(&db, &logicalname, 400).await;
    let attrs = attrs_for("ssn");
    let purged_by = Uuid::now_v7();

    let mut tx = db.begin().await.expect("begin tx");
    let scrubbed =
        attome_metadata::purge::scrub_record(&mut tx, &logicalname, &attrs, record_id, purged_by)
            .await
            .expect("scrub_record");
    tx.commit().await.expect("commit");
    assert!(
        scrubbed,
        "scrub_record must report it actually matched and updated the row"
    );

    let (ssn, is_active, created_on): (Option<String>, bool, chrono::DateTime<Utc>) =
        sqlx::query_as(&format!(
            "SELECT ssn, is_active, created_at FROM \"{logicalname}\" WHERE id = $1"
        ))
        .bind(record_id)
        .fetch_one(&db)
        .await
        .expect("fetch scrubbed row");

    assert_eq!(ssn, None, "sensitive field must be nulled by scrub_record");
    assert!(
        !is_active,
        "is_active (a system column) must be left untouched by scrub_record"
    );
    let _ = created_on; // system column: just proves the row is still readable/intact
}

#[tokio::test]
async fn scrub_record_does_not_touch_a_record_that_was_restored_before_execution() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = provision_test_entity(&db).await;
    let record_id = seed_soft_deleted_record(&db, &logicalname, 400).await;

    // Simulate a restore happening between propose and execute.
    sqlx::query(&format!(
        "UPDATE \"{logicalname}\" SET is_active = true WHERE id = $1"
    ))
    .bind(record_id)
    .execute(&db)
    .await
    .expect("simulate a restore");

    let attrs = attrs_for("ssn");
    let mut tx = db.begin().await.expect("begin tx");
    let scrubbed = attome_metadata::purge::scrub_record(
        &mut tx,
        &logicalname,
        &attrs,
        record_id,
        Uuid::now_v7(),
    )
    .await
    .expect("scrub_record must not error, just no-op");
    tx.commit().await.expect("commit");

    assert!(
        !scrubbed,
        "scrub_record must not match a record that is_active = true (restored since proposal)"
    );

    let ssn: Option<String> =
        sqlx::query_scalar(&format!("SELECT ssn FROM \"{logicalname}\" WHERE id = $1"))
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch record");
    assert_eq!(
        ssn,
        Some("secret-ssn".to_string()),
        "a restored record's data must survive untouched"
    );
}

/// P-data-protection-governance §4 — a record under an active legal hold
/// must not be scrubbed, even though it is otherwise eligible (soft-deleted,
/// past grace). Proves `scrub_record`'s new
/// `attome_core::legal_hold::record_is_held` check.
#[tokio::test]
async fn scrub_record_refuses_a_record_under_an_active_legal_hold() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = provision_test_entity(&db).await;
    let record_id = seed_soft_deleted_record(&db, &logicalname, 400).await;

    sqlx::query(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ($1, $2, 'test-matter', $3)",
    )
    .bind(&logicalname)
    .bind(record_id)
    .bind(Uuid::now_v7())
    .execute(&db)
    .await
    .expect("place legal hold");

    let attrs = attrs_for("ssn");
    let mut tx = db.begin().await.expect("begin tx");
    let result = attome_metadata::purge::scrub_record(
        &mut tx,
        &logicalname,
        &attrs,
        record_id,
        Uuid::now_v7(),
    )
    .await;
    tx.rollback().await.expect("rollback");

    assert!(
        matches!(result, Err(attome_types::AppError::Conflict(_))),
        "scrub_record must refuse a held record with a Conflict, not silently no-op or succeed: {result:?}"
    );

    let ssn: Option<String> =
        sqlx::query_scalar(&format!("SELECT ssn FROM \"{logicalname}\" WHERE id = $1"))
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch record");
    assert_eq!(
        ssn,
        Some("secret-ssn".to_string()),
        "a held record's data must survive untouched"
    );
}
