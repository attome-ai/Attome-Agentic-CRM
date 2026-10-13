//! Against a real database (coding-guidelines.md §1's "integration coverage
//! for its public behavior" requirement for a new engine crate) — the two
//! load-bearing properties `extraction::run_sweep` and
//! `discovery::compute_snapshot` need to hold for M41 Phase 1 to be trusted:
//!
//! 1. **Extraction is idempotent and cursor-advancing.** Seeding a synthetic
//!    `audit_header`/`_detail` log for an `"entity:<logicalname>"`
//!    case def and running `run_sweep` twice writes every event exactly once
//!    — the second run's `events_written` is `0` because the cursor already
//!    passed every source row (`extraction.rs`'s idempotency contract via
//!    `process_event`'s unique index + the persisted `(cursor_last_ts,
//!    cursor_last_id)`).
//! 2. **Discovery correctly derives nodes/edges/variants/cycle-time from a
//!    known synthetic log.** Two cases sharing a common prefix and diverging
//!    on their last step must produce exactly two variants, and the DFG must
//!    contain every edge actually walked.
//!
//! Bottleneck/conformance/findings are Phase 2/3 stubs (`stubs.rs`) with
//! nothing to compute yet — not covered here.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-process --test extraction_and_discovery
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_process::{discovery, extraction};
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Inserts one `process_case_def` row sourced from `entity:<logicalname>`,
/// mapping raw `status_reason` values `1`/`2`/`3` to activity labels.
async fn seed_case_def(db: &DbPool, entity_logicalname: &str) -> Uuid {
    let activity_mapping = serde_json::json!({
        "field": "status_reason",
        "values": { "1": "Submitted", "2": "Approved", "3": "Closed", "4": "Rejected" },
    });
    sqlx::query_scalar(
        "INSERT INTO process_case_def (name, source, activity_mapping, owner_layer) \
         VALUES ($1, $2, $3, 'project') RETURNING id",
    )
    .bind(attome_testkit::unique("process-case-def"))
    .bind(format!("entity:{entity_logicalname}"))
    .bind(activity_mapping)
    .fetch_one(db)
    .await
    .expect("insert case def")
}

/// Seeds one `audit_header` + one child `audit_detail` row
/// (on `status_reason`) — the minimal shape `extraction::extract_entity`'s
/// query reads. `record_id` is the case id; `raw_value` is the status_reason
/// transition's new value.
async fn seed_transition(
    db: &DbPool,
    entity_logicalname: &str,
    record_id: Uuid,
    raw_value: &str,
    created_at: chrono::DateTime<Utc>,
) {
    let header_id: Uuid = sqlx::query_scalar(
        "INSERT INTO audit_header (entity_name, record_id, created_at, operation) \
         VALUES ($1, $2, $3, 1) RETURNING id",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(created_at)
    .fetch_one(db)
    .await
    .expect("insert audit header");

    sqlx::query(
        "INSERT INTO audit_detail (audit_ref, field_name, new_value, created_at) \
         VALUES ($1, 'status_reason', $2, $3)",
    )
    .bind(header_id)
    .bind(raw_value)
    .bind(created_at)
    .execute(db)
    .await
    .expect("insert audit detail");
}

/// Runs both scenarios below sequentially against one shared connection,
/// rather than as two separate `#[tokio::test]` functions. `run_sweep` is a
/// *global* sweep — every active case def in the whole database on every
/// call, which is the correct, intentional production shape for a periodic
/// scheduler tick (`EngineJob::ProcessExtractionSweep`) — so two test
/// functions that each create a case def and independently call
/// `run_sweep` against the SAME per-binary throwaway database (D-343) race
/// each other under cargo test's default parallelism: one test's sweep
/// call can incidentally pick up and partially extract the other's
/// still-being-seeded case def, corrupting both tests' `events_written`
/// counts. Found live (`events_written` landed at half the expected count
/// under default threading, exactly the signature of that race). Merging
/// into one test removes the race outright instead of pinning
/// `--test-threads=1`, which the CI/pre-push gate does not pass.
#[tokio::test]
async fn extraction_and_discovery() {
    let Some(db) = test_db().await else {
        eprintln!("skipping: no DATABASE_URL configured");
        return;
    };
    extraction_is_idempotent_and_discovery_finds_two_variants(&db).await;
    a_case_def_with_no_configured_field_extracts_nothing(&db).await;
}

/// Extraction is idempotent and cursor-advancing, and discovery correctly
/// derives nodes/edges/variants/cycle-time from a known synthetic log — see
/// this file's module doc comment.
async fn extraction_is_idempotent_and_discovery_finds_two_variants(db: &DbPool) {
    let entity_logicalname = attome_testkit::unique_logicalname("process_test_entity");
    let case_def_id = seed_case_def(db, &entity_logicalname).await;

    // Two cases sharing "Submitted -> Approved" then diverging: case A ends
    // "Closed", case B ends "Rejected" — this must produce exactly two
    // variants and both a Submitted->Approved and an Approved->Closed and an
    // Approved->Rejected edge in the discovered graph.
    // Relative to "now", not a fixed calendar date: extraction's own
    // watermark excludes anything inside EXTRACTION_GRACE_WINDOW (2
    // minutes) of "now", and discovery::compute_snapshot only looks at a
    // trailing ROLLING_WINDOW_DAYS (90 days) — a fixed past date drifts out
    // of that window as real time passes (and already had, checked against
    // this repo's dated conventions) whereas "7 days ago" always safely
    // clears the extraction watermark and always stays inside discovery's
    // window.
    let base_ts = Utc::now() - chrono::Duration::days(7);
    let case_a = Uuid::now_v7();
    let case_b = Uuid::now_v7();

    seed_transition(db, &entity_logicalname, case_a, "1", base_ts).await;
    seed_transition(
        db,
        &entity_logicalname,
        case_a,
        "2",
        base_ts + chrono::Duration::minutes(10),
    )
    .await;
    seed_transition(
        db,
        &entity_logicalname,
        case_a,
        "3",
        base_ts + chrono::Duration::minutes(30),
    )
    .await;

    seed_transition(
        db,
        &entity_logicalname,
        case_b,
        "1",
        base_ts + chrono::Duration::seconds(1),
    )
    .await;
    seed_transition(
        db,
        &entity_logicalname,
        case_b,
        "2",
        base_ts + chrono::Duration::minutes(11),
    )
    .await;
    seed_transition(
        db,
        &entity_logicalname,
        case_b,
        "4",
        base_ts + chrono::Duration::minutes(20),
    )
    .await;

    // First sweep: every one of the 6 audit_detail rows becomes one
    // process_event row. `run_sweep` scans every active case def in the
    // whole database, not just this test's own — and the two tests in this
    // file share one per-binary throwaway database (D-343) with no
    // teardown between them, so a case def another test in this same run
    // already created can legitimately still be active here too. Assert
    // >= 1 (this test's own case def was among the ones processed), not
    // == 1 (the total count in the whole shared database) — the property
    // actually under test is `events_written`, checked next.
    let stats = extraction::run_sweep(db).await.expect("first sweep");
    assert!(stats.case_defs_processed >= 1);
    assert_eq!(
        stats.events_written, 6,
        "expected all 6 transitions written"
    );

    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM process_event WHERE case_def_ref = $1")
            .bind(case_def_id)
            .fetch_one(db)
            .await
            .expect("count events");
    assert_eq!(event_count, 6);

    // Second sweep: cursor already passed every source row, so this must be
    // a true no-op — the idempotency property this crate depends on for a
    // periodic scheduler tick to never double-count.
    let stats2 = extraction::run_sweep(db).await.expect("second sweep");
    assert_eq!(
        stats2.events_written, 0,
        "a re-run past an unmoved source log must write nothing new"
    );
    let event_count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM process_event WHERE case_def_ref = $1")
            .bind(case_def_id)
            .fetch_one(db)
            .await
            .expect("count events after second sweep");
    assert_eq!(
        event_count_after, 6,
        "no duplicate rows from the second sweep"
    );

    // Discovery: run_sweep's first pass already triggered one recompute
    // (events_written > 0), so a snapshot should already exist — assert
    // directly on it rather than calling compute_snapshot again, to also
    // cover the extraction -> discovery wiring inside run_sweep itself.
    let snapshot_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM process_dfg_snapshot WHERE case_def_ref = $1")
            .bind(case_def_id)
            .fetch_one(db)
            .await
            .expect("count snapshots");
    assert_eq!(
        snapshot_count, 1,
        "run_sweep must compute exactly one snapshot after writing new events"
    );

    let stats3 = discovery::compute_snapshot(db, case_def_id)
        .await
        .expect("compute_snapshot must succeed")
        .expect("window has events, must return Some");
    assert_eq!(stats3.case_count, 2, "two distinct case ids");
    assert_eq!(stats3.event_count, 6);

    let (graph_json, variants_json): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT graph_json, variants_json FROM process_dfg_snapshot \
         WHERE case_def_ref = $1 ORDER BY computed_at DESC LIMIT 1",
    )
    .bind(case_def_id)
    .fetch_one(db)
    .await
    .expect("fetch latest snapshot");

    let variants = variants_json.as_array().expect("variants is an array");
    assert_eq!(variants.len(), 2, "two distinct activity sequences");
    for v in variants {
        assert_eq!(v["count"], 1, "each variant occurs exactly once");
    }
    let sequences: Vec<Vec<String>> = variants
        .iter()
        .map(|v| {
            v["sequence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        })
        .collect();
    assert!(sequences.contains(&vec![
        "Submitted".to_string(),
        "Approved".to_string(),
        "Closed".to_string()
    ]));
    assert!(sequences.contains(&vec![
        "Submitted".to_string(),
        "Approved".to_string(),
        "Rejected".to_string()
    ]));

    let edges = graph_json["edges"].as_array().expect("edges is an array");
    let has_edge = |from: &str, to: &str| edges.iter().any(|e| e["from"] == from && e["to"] == to);
    assert!(has_edge("Submitted", "Approved"));
    assert!(has_edge("Approved", "Closed"));
    assert!(has_edge("Approved", "Rejected"));

    let nodes = graph_json["nodes"].as_array().expect("nodes is an array");
    assert_eq!(nodes.len(), 4, "Submitted, Approved, Closed, Rejected");
}

/// A misconfigured case def (no `activity_mapping.field`) is a silent no-op
/// at extraction time, not an error — see this file's module doc comment.
async fn a_case_def_with_no_configured_field_extracts_nothing(db: &DbPool) {
    let entity_logicalname = attome_testkit::unique_logicalname("process_test_entity");
    let case_def_id: Uuid = sqlx::query_scalar(
        "INSERT INTO process_case_def (name, source, activity_mapping, owner_layer) \
         VALUES ($1, $2, '{}'::jsonb, 'project') RETURNING id",
    )
    .bind(attome_testkit::unique("process-case-def-noop"))
    .bind(format!("entity:{entity_logicalname}"))
    .fetch_one(db)
    .await
    .expect("insert case def");

    seed_transition(db, &entity_logicalname, Uuid::now_v7(), "1", Utc::now()).await;

    let stats = extraction::run_sweep(db).await.expect("sweep");
    // >= 1, not == 1 — see the matching comment in
    // extraction_is_idempotent_and_discovery_finds_two_variants about why
    // this file's two tests can't assume they're the only active case def
    // in their shared per-binary database.
    assert!(stats.case_defs_processed >= 1);
    assert_eq!(
        stats.events_written, 0,
        "a case def with no activity_mapping.field must silently extract nothing"
    );

    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM process_event WHERE case_def_ref = $1")
            .bind(case_def_id)
            .fetch_one(db)
            .await
            .expect("count events");
    assert_eq!(event_count, 0);
}
