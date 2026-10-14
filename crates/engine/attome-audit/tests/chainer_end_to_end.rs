//! Integration test for P1.13 stages 1–3 — durable ingest capture, the async
//! chainer, and chain verification, exercised end-to-end against a live
//! Postgres. Complements `concurrency.rs` (P1.5's fork test); same
//! `DATABASE_URL` convention — see that file's header.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test chainer_end_to_end
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSigner,
    AuditSource, AuditUserContext,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
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
            user_name: format!("chainer-test-user-{i}"),
            user_display_name: format!("Chainer Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("chainer-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

/// Inserts a `audit_ingest` row directly, the way `AuditService::write`
/// does internally when `ingest_capture_enabled`, WITHOUT also going through
/// the synchronous header/detail/snapshot write. This is deliberate: today,
/// `AuditService::write` always does both (stage 1 is purely additive — see
/// its doc comment), so calling `write()` here would double-count every
/// event into `audit_header` (once from the sync path, once when the
/// chainer later drains the same ingest row) and this test would be
/// asserting the wrong thing. Bypassing `write()` and inserting straight
/// into `audit_ingest` instead exercises the chainer/verify pair the
/// way stage 4's cutover world is actually meant to look — sync path writes
/// only the ingest row, the chainer alone produces `audit_header` rows.
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
async fn chainer_drains_ingest_into_a_verifiable_signed_batch_and_verify_catches_tampering() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"33".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    const N: usize = 12;
    for i in 0..N {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }

    // Stage 2: the chainer should drain all N ingest rows into one batch
    // (well under the 100-row cap given here).
    //
    // Filtered to THIS test's own org, deliberately (D-312's rule: an
    // integration test must not assert a count whose scope is wider than its
    // own fixtures). `run_once` drains every organization with pending ingest
    // rows and returns a batch per organization, so a bare `batches.len() == 1`
    // is really an assertion about the whole database — it fails the moment any
    // other suite leaves undrained `audit_ingest` rows behind, which
    // D-316's default flip makes routine rather than exceptional: every suite
    // whose config omits `audit.chainer_enabled` now writes ingest rows instead
    // of header rows, and nothing in a test run starts a chainer to drain them.
    // Observed as a real failure (2 batches: this org plus a leftover nil-UUID
    // org) against the shared `attomedb_test` database.
    let batches: Vec<_> = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("chainer run_once")
        .into_iter()
        .filter(|batch| batch.organization_ref == org)
        .collect();
    assert_eq!(
        batches.len(),
        1,
        "all N events for one org should land in a single batch"
    );
    assert_eq!(batches[0].event_count, N);

    // Running again immediately must be a no-op (nothing left to drain) — for
    // this org; see the scoping note above.
    let second_pass: Vec<_> = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("chainer run_once (second pass)")
        .into_iter()
        .filter(|batch| batch.organization_ref == org)
        .collect();
    assert!(
        second_pass.is_empty(),
        "a second immediate run should find nothing pending for this org"
    );

    // Stage 3: verification should pass cleanly on the untampered chain.
    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "verification should pass on an untampered chain, got errors: {:?}",
        report.errors
    );
    assert_eq!(report.headers_checked, N);
    assert_eq!(report.batches_checked, 1);
    assert_eq!(report.pending_ingest, 0);

    // Now tamper with one stored header's event_hash directly (simulating a
    // compromised/modified row) and confirm verification catches it — the
    // actual "does the tamper-evidence moat work" proof, not just "does the
    // happy path run".
    sqlx::query(
        "UPDATE audit_header SET event_hash = $1
         WHERE id = (SELECT id FROM audit_header WHERE organization_ref = $2 ORDER BY id LIMIT 1)",
    )
    .bind("a".repeat(64))
    .bind(org)
    .execute(&db)
    .await
    .expect("tamper update");

    let tampered_report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain after tamper");
    assert!(
        !tampered_report.is_ok(),
        "verification must fail after a stored event_hash is tampered with"
    );
}

/// P1.13 stage 4 — with `chainer_enabled`, `write()` must produce NO
/// `audit_header` row itself, only a `audit_ingest` row; the
/// chainer alone is then responsible for producing the (verifiable) header.
/// This is the highest-stakes path in the whole plan (it's what actually
/// removes the append lock from the request path), so it gets its own test
/// rather than being inferred from the additive-mode test above.
#[tokio::test]
async fn cutover_write_produces_no_header_row_until_the_chainer_drains_it() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"55".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    const N: usize = 5;
    for i in 0..N {
        AuditService::new(&db, Some(&signer))
            .with_chainer_enabled(true)
            .write(make_event(org, i))
            .await
            .expect("audit write (cutover mode)");
    }

    let header_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_header WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count headers");
    assert_eq!(
        header_count, 0,
        "write() with chainer_enabled must not write audit_header itself"
    );

    let ingest_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count ingest rows");
    assert_eq!(
        ingest_count, N as i64,
        "every cutover-mode write must land exactly one ingest row"
    );

    let batches = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("chainer run_once");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].event_count, N);

    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "cutover-mode chain should verify cleanly: {:?}",
        report.errors
    );
    assert_eq!(
        report.headers_checked, N,
        "the chainer should have produced exactly N header rows"
    );
}

/// Plan 4.2 -- the "KNOWN GAP" the plan cites (`service.rs`'s doc comment on
/// `IngestEnvelope`/`append_in_batch` already carries attribution through the
/// ingest payload; this proves the round trip actually holds for both
/// non-`User` initiators, not just that the code compiles). An Agent- and a
/// System-attributed write, each under `chainer_enabled = true`, must read
/// back through `run_once`'s drain with the same `initiator` (and, for the
/// agent case, the same `agent_session_id`) a plain synchronous write with
/// the identical `Attribution` produces -- i.e. going through the ingest
/// JSONB round trip loses nothing the sync path would have stored.
#[tokio::test]
async fn chainer_drained_events_keep_their_attribution() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");
    let signer = AuditSigner::from_config("test-key", &"66".repeat(32)).expect("signer");

    async fn stored_initiator_and_agent_session(db: &DbPool, org: Uuid) -> (i16, Option<Uuid>) {
        sqlx::query_as(
            "SELECT initiator, agent_session_id FROM audit_header \
             WHERE organization_ref = $1 ORDER BY id LIMIT 1",
        )
        .bind(org)
        .fetch_one(db)
        .await
        .expect("fetch header")
    }

    // Agent-attributed, sync path (chainer_enabled = false): the baseline
    // this test compares the chainer path against.
    let sync_org = Uuid::now_v7();
    let agent_session_id = Uuid::now_v7();
    let agent_attribution =
        attome_audit::Attribution::agent(Uuid::now_v7(), agent_session_id, "test.action");
    AuditService::new(&db, Some(&signer))
        .write_attributed(make_event(sync_org, 0), agent_attribution.clone())
        .await
        .expect("sync agent-attributed write");
    let (sync_initiator, sync_agent_session) =
        stored_initiator_and_agent_session(&db, sync_org).await;
    assert_eq!(
        sync_initiator,
        attome_audit::Initiator::Agent.as_i16(),
        "sync path baseline: Agent initiator"
    );
    assert_eq!(sync_agent_session, Some(agent_session_id));

    // Same Attribution, chainer path: write() lands only in audit_ingest,
    // then run_once drains it into audit_header.
    let chainer_org = Uuid::now_v7();
    AuditService::new(&db, Some(&signer))
        .with_chainer_enabled(true)
        .write_attributed(make_event(chainer_org, 0), agent_attribution)
        .await
        .expect("chainer-mode agent-attributed write");
    attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("chainer run_once (agent case)");
    let (chained_initiator, chained_agent_session) =
        stored_initiator_and_agent_session(&db, chainer_org).await;
    assert_eq!(
        chained_initiator, sync_initiator,
        "chainer-drained Agent initiator must match the sync path"
    );
    assert_eq!(
        chained_agent_session,
        Some(agent_session_id),
        "chainer-drained agent_session_id must survive the ingest round trip"
    );

    // System-attributed, chainer path only (no agent_session_id to compare,
    // just the initiator itself).
    let system_org = Uuid::now_v7();
    let system_attribution = attome_audit::Attribution {
        acting_user_id: Uuid::nil(),
        initiator: attome_audit::Initiator::System,
        agent_session_id: None,
        agent_action_id: None,
    };
    AuditService::new(&db, Some(&signer))
        .with_chainer_enabled(true)
        .write_attributed(make_event(system_org, 0), system_attribution)
        .await
        .expect("chainer-mode system-attributed write");
    attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("chainer run_once (system case)");
    let (system_initiator, _) = stored_initiator_and_agent_session(&db, system_org).await;
    assert_eq!(
        system_initiator,
        attome_audit::Initiator::System.as_i16(),
        "chainer-drained System initiator must round-trip, not silently fall back to User"
    );
}

/// D-130's §6 rotate-then-rewrap scenario for the audit-signing key: sign N
/// events under key A (registering its public key the way boot does, once,
/// for the signer configured at the time), rotate to a brand-new key B
/// (registered under its own never-before-used `signing_key_id`), sign N
/// more events under B, then confirm `verify_chain` still verifies every
/// batch across the whole chain -- resolving each batch's own stored
/// `signing_key_id` via the registry, not via whichever signer happens to be
/// live "today."
#[tokio::test]
async fn rotating_the_signing_key_keeps_every_prior_batch_verifiable_via_the_registry() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer_a =
        AuditSigner::from_config("rotate-test-key-a", &"aa".repeat(32)).expect("signer a");
    attome_core::audit_signing::upsert_signing_key(
        &db,
        "rotate-test-key-a",
        &signer_a.verifying_key_b64(),
    )
    .await
    .expect("register key a");

    let org = Uuid::now_v7();
    const N: usize = 5;
    for i in 0..N {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }
    let batches_a = attome_audit::chainer::run_once(&db, Some(&signer_a), 100, None)
        .await
        .expect("chainer run_once (key a)");
    assert_eq!(batches_a.len(), 1);
    assert_eq!(batches_a[0].event_count, N);

    // Rotate: a brand new signing key under a never-before-used id.
    let signer_b =
        AuditSigner::from_config("rotate-test-key-b", &"bb".repeat(32)).expect("signer b");
    attome_core::audit_signing::upsert_signing_key(
        &db,
        "rotate-test-key-b",
        &signer_b.verifying_key_b64(),
    )
    .await
    .expect("register key b");

    for i in N..(2 * N) {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }
    let batches_b = attome_audit::chainer::run_once(&db, Some(&signer_b), 100, None)
        .await
        .expect("chainer run_once (key b)");
    assert_eq!(batches_b.len(), 1);
    assert_eq!(batches_b[0].event_count, N);

    // Verification covers the whole chain -- one batch signed under key A,
    // one under key B -- passing today's live signer (b) only as the
    // fallback for pre-registry history, which neither batch here needs
    // since both are registered.
    let report = attome_audit::verify::verify_chain(&db, Some(&signer_b), org)
        .await
        .expect("verify_chain across a rotated signing key");
    assert!(
        report.is_ok(),
        "every batch must verify via the registry regardless of which key signed it: {:?}",
        report.errors
    );
    assert_eq!(report.headers_checked, 2 * N);
    assert_eq!(report.batches_checked, 2);

    // The registry never overwrites -- re-registering key A's id under its
    // own (unchanged) public key is a no-op, not an error.
    attome_core::audit_signing::upsert_signing_key(
        &db,
        "rotate-test-key-a",
        &signer_a.verifying_key_b64(),
    )
    .await
    .expect("re-registering the same key under the same id is a no-op");
}
