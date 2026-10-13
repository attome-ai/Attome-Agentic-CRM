//! P1.13 §6 crash-recovery gap, DB-guarantee half: "kill the chainer
//! mid-batch → restart → batch re-runs, no duplicate headers" rests on
//! Postgres's own transaction atomicity (the whole batch, lock included, is
//! one transaction — see `chainer.rs::run_batch_for_org`), which had never
//! actually been exercised. This proves that guarantee deterministically, by
//! abandoning a partially-written batch transaction (explicit `ROLLBACK`,
//! same server-side effect a hard process kill relies on) and confirming a
//! clean retry picks the untouched ingest rows up correctly. The literal
//! "kill a real OS process" version of this test lives in
//! `attome-website/crates/server/tests/audit_chainer_process_kill.rs` — that
//! crate is where `audit_chainer`'s compiled binary is actually visible
//! (attome-xrm doesn't, and per the dependency-direction rule never should,
//! depend on attome-website).
//!
//! Same `DATABASE_URL` convention as `concurrency.rs`/`chainer_end_to_end.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres@localhost:<port>/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test chainer_crash_recovery -- --test-threads=1
//! ```

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
use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};
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

async fn raw_conn() -> Option<PgConnection> {
    let url = attome_testkit::migrated_db_url()?;
    Some(PgConnection::connect(&url).await.expect("raw connection"))
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
            user_name: format!("crash-test-user-{i}"),
            user_display_name: format!("Crash Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("crash-test-{i}")),
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

#[tokio::test]
async fn an_abandoned_batch_transaction_leaves_ingest_rows_intact_for_a_clean_retry() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"aa".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    // Stage 1: durably capture 3 events the normal way (their own committed
    // transactions — exactly what AuditService::write_ingest does).
    const N: usize = 3;
    for i in 0..N {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }

    // Simulate a chainer that started a batch (acquired the chain lock,
    // wrote a batch bookkeeping row) and crashed before COMMIT. The whole
    // batch is one transaction (chainer.rs::run_batch_for_org), so an
    // explicit ROLLBACK here has the identical server-side effect a hard
    // client disconnect has — Postgres discards everything the transaction
    // did, lock included.
    {
        let mut conn = skip_if_no_db!(raw_conn().await);
        sqlx::query("BEGIN")
            .execute(&mut conn)
            .await
            .expect("begin");
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_audit::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-audit/chain:{org}"))
            .fetch_one(&mut conn)
            .await
            .expect("acquire lock");
        assert!(locked, "test setup must actually hold the chain lock");

        sqlx::query(
            "INSERT INTO audit_chain_batch
                 (organization_ref, first_ingest_id, last_ingest_id, event_count, merkle_root)
             VALUES ($1, $2, $2, 1, 'partial-batch-before-crash')",
        )
        .bind(org)
        .bind(Uuid::now_v7())
        .execute(&mut conn)
        .await
        .expect("partial batch insert");

        sqlx::query("ROLLBACK")
            .execute(&mut conn)
            .await
            .expect("simulate crash: rollback");
    }

    let ingest_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count ingest rows");
    assert_eq!(
        ingest_count, N as i64,
        "the crashed batch attempt must not have touched the already-committed ingest rows"
    );

    let batch_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_chain_batch WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count batch rows");
    assert_eq!(
        batch_count, 0,
        "the aborted batch attempt must leave zero batch rows behind"
    );

    // "Restart": the real chainer, unaware anything went wrong, picks the
    // same rows up cleanly on its next poll.
    //
    // Filtered to this test's own org (D-312's rule — see the identical note
    // in chainer_end_to_end.rs). `run_once` drains every organization with
    // pending ingest rows and returns one batch per organization, so a bare
    // `batches.len() == 1` asserts something about the whole database; it
    // fails as soon as any other suite leaves undrained rows behind, which
    // D-316's default flip makes routine. Every assertion below this point is
    // already org-scoped.
    let batches: Vec<_> = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("retry after simulated crash")
        .into_iter()
        .filter(|batch| batch.organization_ref == org)
        .collect();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].event_count, N);

    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "chain must verify cleanly after the retry: {:?}",
        report.errors
    );
    assert_eq!(report.headers_checked, N);
    assert_eq!(
        report.batches_checked, 1,
        "exactly one batch — no duplicate from the aborted attempt"
    );
    assert_eq!(report.pending_ingest, 0);
}
