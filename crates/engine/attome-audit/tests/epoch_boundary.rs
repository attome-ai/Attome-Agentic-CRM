//! P-audit-chain-hardening item (c), D-280 — calendar-month audit-chain
//! epochs. Proves the plan's §5 Phase 3 step 11 scenario: seal an epoch,
//! simulate its `audit_chain_batch` row being gone (the batch-ledger
//! side of a future partition/archive drop), confirm verification of the
//! surviving epoch still succeeds using only the externally anchored seal —
//! never the dropped row.
//!
//! Deliberately scoped to the batch-ledger layer only, not
//! `audit_header`/`detail`/`snapshot` row pruning: this plan (§4(c))
//! implements the epoch-aware sealing *capability*, not `P-db-maintenance`'s
//! archive/drop job itself, and that job's exact scope (whether it ever
//! prunes `audit_chain_batch` rows, not just the header/detail/snapshot
//! partitions) is explicitly undecided. This test simulates the layer this
//! plan's own schema/anchor changes actually target — `verify::verify_batches`
//! bridging `prev_batch_hash` across a missing `audit_chain_batch` row —
//! and leaves row-level (`verify::verify_row_chain`) bridging as a documented
//! future gap (see that function's lack of a `store` parameter): its
//! `prev_hash` check has no anchor to bridge with today, since a batch's
//! Merkle root does not expose the individual leaf hash a next-epoch row
//! would need to chain from.
//!
//! Same `DATABASE_URL`/`S3_*` conventions as `chainer_end_to_end.rs` and
//! `anchor.rs`.
//!
//! **Live-verified 2026-08-07 — 2/2 pass** against real Postgres 18.4 +
//! RustFS, the first actual execution of this file (it was written
//! code-only under D-282 with no backend reachable). The implementation
//! under test needed no changes; both tests passed as soon as they could
//! run. One real *test-isolation* bug was found and fixed by that first
//! run — see `single_batch_for`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test epoch_boundary -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSigner, AuditSource,
    AuditUserContext, anchor, chainer, verify,
};
use attome_config::AppConfig;
use attome_db::DbPool;
use attome_storage::{StorageClient, create_storage_client};
use attome_testkit::skip_if_no_db;
use chrono::{Datelike, NaiveDate, Utc};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// Same throwaway-config shape as `tests/anchor.rs::test_storage_client` —
/// kept independent (not shared via a `common` module) since neither file
/// wants a compile-time dependency on the other's test helpers.
async fn test_storage_client() -> StorageClient {
    let json = format!(
        r#"{{
            "app": {{ "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 8, "max_connection_num_per_ip": 8,
                "use_gzip": false, "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 10, "keepalive_requests": 10,
                "static_files_cache_time": 0, "server_header_field": "test" }},
            "database": {{ "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1, "timeout": 5.0 }},
            "cache": {{ "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60 }},
            "storage": {{ "s3_endpoint": "{endpoint}", "s3_region": "us-east-1",
                "s3_access_key": "{access_key}", "s3_secret_key": "{secret_key}",
                "s3_bucket": "{bucket}", "s3_use_path_style": true, "s3_verify_ssl": false }},
            "auth": {{ "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min" }},
            "rate_limit": {{ "anonymous_rpm": 100, "authenticated_rpm": 1000 }},
            "observability": {{ "metrics_port": 0, "log_sampling_rate": 1.0,
                "trace_sampling_rate": 1.0, "enable_distributed_tracing": false }},
            "email": {{ "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c", "smtp_from_name": "t",
                "smtp_use_tls": false, "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5 }},
            "google_ai": {{ "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5 }}
        }}"#,
        endpoint = env_or("S3_ENDPOINT", "http://127.0.0.1:9000"),
        access_key = env_or("S3_ACCESS_KEY", ""),
        secret_key = env_or("S3_SECRET_KEY", ""),
        bucket = env_or("S3_BUCKET", "attomebase"),
    );
    let config: AppConfig = serde_json::from_str(&json).expect("parse throwaway storage config");
    create_storage_client(&config)
        .await
        .expect("connect to the configured S3-compatible store")
}

fn make_event(organization_ref: Uuid, i: usize) -> AuditEvent {
    AuditEvent {
        organization_ref,
        category: AuditCategory::BusinessEvent,
        entity_name: Some("test_entity".into()),
        record_id: Some(Uuid::now_v7()),
        operation: AuditOperation::Submitted,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: format!("epoch-boundary-test-user-{i}"),
            user_display_name: format!("Epoch Boundary Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("epoch-boundary-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

async fn insert_ingest_row(db: &DbPool, event: &AuditEvent) {
    let payload = serde_json::to_value(event).expect("serialize AuditEvent");
    sqlx::query("INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2)")
        .bind(event.organization_ref)
        .bind(payload)
        .execute(db)
        .await
        .expect("insert ingest row");
}

/// Returns the batch `run_once` produced for `org`, asserting exactly one.
///
/// `chainer::run_once` batches **per distinct `organization_ref` across the
/// whole table** (`SELECT DISTINCT organization_ref FROM audit_ingest`)
/// and returns one batch per org — so its return length reflects however
/// many orgs happen to have pending rows database-wide, not this test's
/// work. A bare `assert_eq!(batches.len(), 1)` therefore fails with a
/// confusing `left: 2, right: 1` whenever any other suite has rows in
/// flight, which is the normal condition in this repo's shared
/// `attomedb_test` (found live on this file's first-ever execution,
/// 2026-08-07: 4,247 leftover rows across 5 orgs, 4,000 of them from one
/// load-oriented suite).
///
/// Filtering `run_once`'s result by org is the correct fix. Deleting other
/// orgs' ingest rows is NOT: `cargo test` runs test binaries in parallel, so
/// that destroys pending work belonging to a concurrently-running suite —
/// verified by trying it, which made `chainer_end_to_end.rs` and
/// `chainer_race_and_leader_election.rs` fail (e.g. 5 expected batches
/// became 3). This helper only reads.
fn single_batch_for(
    batches: &[chainer::ChainBatchSummary],
    org: Uuid,
) -> &chainer::ChainBatchSummary {
    let mine: Vec<_> = batches
        .iter()
        .filter(|b| b.organization_ref == org)
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "expected exactly one batch for this test's own org {org}; \
         run_once returned {} batch(es) total across all orgs",
        batches.len()
    );
    mine[0]
}

fn months_ago(n: i32) -> NaiveDate {
    let now = Utc::now();
    let total_months = now.year() * 12 + (now.month() as i32 - 1) - n;
    let year = total_months.div_euclid(12);
    let month = total_months.rem_euclid(12) + 1;
    NaiveDate::from_ymd_opt(year, month as u32, 1).expect("valid calendar month")
}

/// The load-bearing case (§5 Phase 3 step 11): once an old epoch is sealed
/// and its `audit_chain_batch` row is gone, `verify_chain_with_anchors`
/// must still report the surviving batch's `prev_batch_hash` as proven —
/// via the externally anchored seal, not the dropped row — rather than a
/// tamper-looking mismatch.
#[tokio::test]
async fn verify_bridges_a_sealed_epoch_once_its_batch_row_is_dropped() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer =
        AuditSigner::from_config("epoch-boundary-test-key", &"77".repeat(32)).expect("signer");
    let org = Uuid::now_v7();
    // Batch A: written "now", but immediately backdated to two months ago —
    // deliberately non-adjacent to the current month (not just "last
    // month") to prove the seal is looked up by the SURVIVING batch's own
    // epoch_period directly, never by walking backward one calendar month
    // at a time, which would silently miss a sparse-activity org that skips
    // a month entirely.
    const N1: usize = 5;
    for i in 0..N1 {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }
    let batches_a = chainer::run_once(&db, Some(&signer), 100, Some(&store))
        .await
        .expect("chainer run_once (batch A)");
    let batch_a_id = single_batch_for(&batches_a, org).batch_id;

    let backdated_epoch = months_ago(2);
    sqlx::query("UPDATE audit_chain_batch SET epoch_period = $1 WHERE id = $2")
        .bind(backdated_epoch)
        .bind(batch_a_id)
        .execute(&db)
        .await
        .expect("backdate batch A's epoch_period (test-role only, simulating elapsed time)");

    // Batch B: a later batch, in the current (real) epoch. This is the run
    // that must detect the boundary crossing and anchor the seal.
    const N2: usize = 5;
    for i in N1..(N1 + N2) {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }
    let batches_b = chainer::run_once(&db, Some(&signer), 100, Some(&store))
        .await
        .expect("chainer run_once (batch B, crosses the epoch boundary)");
    let batch_b_id = single_batch_for(&batches_b, org).batch_id;

    let current_epoch: NaiveDate =
        sqlx::query_scalar("SELECT epoch_period FROM audit_chain_batch WHERE id = $1")
            .bind(batch_b_id)
            .fetch_one(&db)
            .await
            .expect("read batch B's own epoch_period");

    // The seal must exist, filed under batch B's own epoch — not under
    // `backdated_epoch` (the sealed epoch itself) and not under "one month
    // before batch B" (there is no batch in that month at all).
    let sealed = anchor::fetch_epoch_seal(&store, org, current_epoch)
        .await
        .expect("fetch_epoch_seal against a real object store")
        .expect("chainer must have sealed the epoch batch A closed");
    assert_eq!(sealed.0, batch_a_id, "the seal must name batch A");

    let batch_a_merkle_root: String =
        sqlx::query_scalar("SELECT merkle_root FROM audit_chain_batch WHERE id = $1")
            .bind(batch_a_id)
            .fetch_one(&db)
            .await
            .expect("read batch A's merkle_root before dropping its row");
    assert_eq!(
        sealed.1, batch_a_merkle_root,
        "the sealed root must match what batch A actually chained"
    );

    // Sanity check: verification succeeds BEFORE anything is dropped (both
    // batches' rows still present, no bridging needed yet).
    let baseline = verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
        .await
        .expect("verify_chain_with_anchors before drop");
    assert!(
        baseline.is_ok(),
        "chain must verify cleanly before any row is dropped: {:?}",
        baseline.errors
    );

    // Now simulate the batch-ledger side of a future partition/archive drop
    // (P-db-maintenance item (c), not yet built) — remove ONLY batch A's
    // `audit_chain_batch` row. Its member `audit_header` rows are
    // deliberately left in place: row-level pruning is a separate, larger
    // capability this plan does not implement (see this file's header).
    sqlx::query("DELETE FROM audit_chain_batch WHERE id = $1")
        .bind(batch_a_id)
        .execute(&db)
        .await
        .expect("drop batch A's ledger row, simulating an archived/dropped epoch");

    // Without a store, this must now report an honest mismatch — no anchor
    // configured, no way to prove continuity.
    let unbridged = verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (no store) after drop");
    assert!(
        !unbridged.is_ok(),
        "without a store, a missing prev batch must be reported, not silently accepted"
    );

    // With the store, the seal bridges it: batch B's prev_batch_hash no
    // longer has a corresponding in-database row, but its anchored seal
    // proves the same continuity — this is the actual point of D-280.
    let bridged = verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
        .await
        .expect("verify_chain_with_anchors (with store) after drop");
    assert!(
        bridged.is_ok(),
        "the sealed epoch's anchor must bridge the dropped batch row: {:?}",
        bridged.errors
    );
    assert_eq!(
        bridged.batches_checked, 1,
        "only batch B remains in audit_chain_batch after the drop"
    );
}

/// A batch's own `prev_batch_hash` mismatch (real tamper, not a dropped
/// row) must still be reported as an error even when a `store` is
/// configured — the sealed anchor for a DIFFERENT epoch than the one
/// actually referenced must never paper over a genuine mismatch.
#[tokio::test]
async fn verify_still_reports_a_genuine_prev_batch_hash_mismatch_with_a_store_configured() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer =
        AuditSigner::from_config("epoch-boundary-tamper-key", &"88".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    const N: usize = 5;
    for i in 0..N {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }
    let batches = chainer::run_once(&db, Some(&signer), 100, Some(&store))
        .await
        .expect("chainer run_once");
    // See `single_batch_for` — `run_once` is table-wide, so filter to this
    // test's own org rather than asserting on the total count.
    let my_batch_id = single_batch_for(&batches, org).batch_id;

    // Tamper directly: this is the only batch, so its prev_batch_hash
    // should be empty (genesis) — corrupt it to something non-empty with
    // no epoch seal ever anchored to explain it.
    sqlx::query("UPDATE audit_chain_batch SET prev_batch_hash = $1 WHERE id = $2")
        .bind("a".repeat(64))
        .bind(my_batch_id)
        .execute(&db)
        .await
        .expect("tamper update");

    let report = verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
        .await
        .expect("verify_chain_with_anchors after tamper");
    assert!(
        !report.is_ok(),
        "a tampered prev_batch_hash with no corresponding sealed anchor must still fail, \
         even with a store configured"
    );
}
