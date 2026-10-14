//! P1.13 §6's literal "kill the chainer mid-batch" test. This lives here
//! (not in attome-xrm's own `attome-audit` test suite) because it needs the
//! compiled `attome` binary (`attome audit-chainer`)
//! of this crate — attome-xrm doesn't, and per the dependency-direction rule
//! never should, depend on attome-website. The library-level half of P1.13's
//! crash-recovery gap (an abandoned-transaction DB-guarantee proof) lives in
//! `attome-xrm/crates/attome-audit/tests/chainer_crash_recovery.rs`; the
//! out-of-order-commit race and leader-election gaps live in that crate's
//! `chainer_race_and_leader_election.rs`. See P1.13-audit-chainer.md's
//! progress notes for the full list this closes.
//!
//! Same `DATABASE_URL` convention as `attome-audit`'s integration tests — a
//! throwaway database, never `attome_dev`. Points the spawned `audit_chainer`
//! process straight at the repo's real `config.debug.json`; `DATABASE_URL` is
//! passed explicitly into the child's environment so it can never fall back
//! to whatever `config.debug.json`'s own `database` block or an inherited
//! `.env` happen to point at (`attome_db::create_pool` prefers the
//! `DATABASE_URL` env var over the config file's `database` section when
//! both are present) — this is what keeps this test from ever being able to
//! reach the real dev database.
//!
//! Config-surface reduction (item 23) turned `audit.chain_poll_interval_ms`/
//! `chain_batch_size` from config fields into fixed constants next to
//! `audit_chainer.rs`'s own poll loop (500ms / 500 events per batch) — this
//! test used to splice a fast/oversized override into a temp config file to
//! make the race easy to hit quickly; it now just waits long enough for the
//! fixed cadence to produce a batch instead.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres@localhost:<port>/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p server --test audit_chainer_process_kill
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSigner, AuditSource,
    AuditUserContext,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
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
            user_name: format!("kill-test-user-{i}"),
            user_display_name: format!("Kill Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("kill-test-{i}")),
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

/// `config.debug.json` (repo root, one level up from this crate) — reusing
/// the real file instead of hand-writing a second copy of every required
/// `AppConfig` section avoids this test silently drifting out of sync with
/// the config shape. The `database` block inside it is irrelevant to where
/// this test's spawned process actually connects: `DATABASE_URL` is passed
/// as an explicit env var to the child, which `attome_db::create_pool`
/// prefers over the config file's `database` section.
fn debug_config_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../config.debug.json")
}

#[tokio::test]
async fn killing_the_audit_chainer_process_mid_batch_leaves_a_cleanly_resumable_chain() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"cc".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    // More than one fixed-size (500-event) batch, so draining still takes
    // several polls — raising the odds the kill below actually lands
    // mid-write for whichever batch is in flight — though the assertions
    // after the kill hold regardless of whether it does.
    const N: usize = 4000;
    for i in 0..N {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }

    let database_url = attome_testkit::migrated_db_url().expect("checked by test_db() above");
    let config_path = debug_config_path();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_attome"))
        .arg("audit-chainer")
        .env("CONFIG_FILE", &config_path)
        .env("DATABASE_URL", &database_url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn audit_chainer");

    // The chainer's poll cadence is a fixed 500ms (CHAIN_POLL_INTERVAL_MS in
    // audit_chainer.rs) — wait past the first tick so it's actually mid (or
    // just past) its first batch write, then kill it hard (TerminateProcess
    // on Windows / SIGKILL-equivalent — not a graceful shutdown signal,
    // which this binary does handle via ctrl_c/SIGTERM and which would prove
    // nothing about crash safety).
    //
    // CI-8 (PLATFORM-REVIEW-2026-08-24) names this file as a fixed-delay
    // offender to convert to poll-with-timeout. **Do not convert this one.**
    // The duration is load-bearing, not lazy synchronization: `CHAIN_BATCH_SIZE`
    // is 500 and `N` above is 4000, so eight batches' worth of work is queued
    // and the chainer would keep writing one per 500ms tick indefinitely. 550ms
    // bounds the kill to just past the *first* tick, which is what makes
    // `batch_rows.len() <= 1` below true. Polling until a batch row appears and
    // then killing would race the second tick and can leave two batch rows,
    // failing that assertion — the "fix" breaks the test.
    //
    // What a fixed delay does cost here is real, though, and worth knowing: on
    // a heavily loaded machine the chainer may not reach its first tick inside
    // 550ms, so the kill lands before any work and the assertions below hold
    // vacuously. The test still passes while proving nothing about crash
    // safety. Tightening that needs a signal for "the first batch write has
    // started" that does not also let the second one commit; `audit_ingest`
    // cannot supply it (append-only, D-005 — see the note further down), so it
    // would take a new observable, not a mechanical sleep-to-poll swap.
    tokio::time::sleep(Duration::from_millis(550)).await;
    child.kill().expect("kill audit_chainer");
    let _ = child.wait();

    // Whatever the kill left behind, Postgres's transaction atomicity
    // guarantees it is either nothing or one complete, internally consistent
    // batch — never a torn write with a batch row whose headers don't match
    // its own event_count.
    let batch_rows: Vec<(Uuid, i32)> =
        sqlx::query_as("SELECT id, event_count FROM audit_chain_batch WHERE organization_ref = $1")
            .bind(org)
            .fetch_all(&db)
            .await
            .expect("query batches");
    assert!(
        batch_rows.len() <= 1,
        "a killed process must never leave more than one batch row for a single-org, \
         single-process run, got {}",
        batch_rows.len()
    );
    if let Some((batch_id, event_count)) = batch_rows.first() {
        let header_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_header WHERE chain_batch_ref = $1")
                .bind(batch_id)
                .fetch_one(&db)
                .await
                .expect("count headers for batch");
        assert_eq!(
            header_count, *event_count as i64,
            "a batch row that exists must have exactly the header rows it claims — a torn \
             write would show a batch row whose event_count doesn't match its own headers"
        );
    }

    // "Restart": a real supervisor would relaunch the process; calling the
    // library entrypoint directly is an equivalent stand-in and avoids a
    // second flaky process-timing dependency in this same test.
    //
    // `audit_ingest` is append-only (D-005) — chaining a row never
    // deletes it, so its row count can't be used as a "still pending" signal
    // (retention pruning, P1.13 step 6, is a separate not-yet-built piece).
    // `run_once` returning empty is also ambiguous on its own
    // (`run_batch_for_org` returns the same `Ok(None)` for "nothing left to
    // drain" and "another session's advisory lock is still held" — see
    // chainer.rs — and immediately after a hard kill, the killed process's
    // own Postgres backend may take a short moment to notice the dropped TCP
    // connection and release that lock). So: keep polling, and only treat it
    // as done once a few consecutive polls all come back empty.
    let mut consecutive_empty = 0;
    for _ in 0..100 {
        let batches = attome_audit::chainer::run_once(&db, Some(&signer), 1000, None)
            .await
            .expect("resume after kill");
        if batches.is_empty() {
            consecutive_empty += 1;
            if consecutive_empty >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        } else {
            consecutive_empty = 0;
        }
    }

    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "chain must verify cleanly after resuming from a kill: {:?}",
        report.errors
    );
    assert_eq!(
        report.headers_checked as usize, N,
        "no lost or duplicated events across the kill + resume"
    );
    assert_eq!(
        report.pending_ingest, 0,
        "every ingest row must end up claimed by exactly one batch"
    );
}
