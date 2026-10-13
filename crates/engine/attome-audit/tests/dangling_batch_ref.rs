//! Audit 10/10 plan Phase 1.2 (D-516 ruling 4): a header's `chain_batch_ref`
//! must name a batch of its organization.
//!
//! Chainer-path headers are exempt from the per-row signature rule because
//! their batch signs them (`verify_row_signature`), and `verify_batches` only
//! walks batches that exist. So a DB-level writer could append an unsigned
//! header carrying a *random* `chain_batch_ref`, with a correct `prev_hash`
//! and a recomputed `event_hash` (the formula is public), and `verify_chain`
//! reported clean. These tests forge exactly that row.
//!
//! D-280's legitimate case — a sealed epoch whose batch row was dropped — is
//! covered by `epoch_boundary.rs`, which must keep passing.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test dangling_batch_ref -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSigner,
    AuditSource, AuditUserContext, chainer, verify,
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
            user_name: format!("dangling-ref-test-user-{i}"),
            user_display_name: format!("Dangling Ref Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("dangling-ref-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

/// Writes three events through the chainer path, drains them into a signed
/// batch, and checks the untouched chain verifies. Returns the signer.
async fn chained_org(db: &DbPool, org: Uuid, key_id: &str, seed_byte: &str) -> AuditSigner {
    attome_audit::seed(db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config(key_id, &seed_byte.repeat(32)).expect("signer");
    attome_core::audit_signing::upsert_signing_key(db, key_id, &signer.verifying_key_b64())
        .await
        .expect("register the signing key, as boot does");

    for i in 0..3 {
        AuditService::new(db, Some(&signer))
            .with_chainer_enabled(true)
            .write(make_event(org, i))
            .await
            .expect("audit write (chainer path)");
    }

    let batches = chainer::run_once(db, Some(&signer), 100, None)
        .await
        .expect("chainer run");
    assert!(
        batches.iter().any(|b| b.organization_ref == org),
        "the chainer must produce a batch for this organization"
    );

    let baseline = verify::verify_chain(db, Some(&signer), org)
        .await
        .expect("verify_chain (baseline)");
    assert!(
        baseline.is_ok(),
        "the untouched chained history must verify cleanly, got: {:?}",
        baseline.errors
    );

    signer
}

/// Appends a forged header after the organization's last header: a copy of
/// that row with a fresh id and record, the given `chain_batch_ref`, no
/// signature, `prev_hash` = the last row's `event_hash`, and an `event_hash`
/// recomputed with the public formula its `hash_version` names (D-539 hash v2
/// for rows written today; `verify::recompute_stored_event_hash` is exactly
/// that public computation). Returns the forged header's id.
async fn forge_header_after_last(db: &DbPool, org: Uuid, chain_batch_ref: Uuid) -> Uuid {
    let last_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_header
         WHERE organization_ref = $1
         ORDER BY id DESC
         LIMIT 1",
    )
    .bind(org)
    .fetch_one(db)
    .await
    .expect("read the organization's last header");

    let forged_id = Uuid::now_v7();
    let forged_record = Uuid::now_v7();

    // A copy through jsonb keeps every other column of the real row, so the
    // forgery is exactly as well-formed as a chainer-written header.
    sqlx::query(
        "INSERT INTO audit_header
         SELECT (jsonb_populate_record(
                     NULL::audit_header,
                     to_jsonb(h) || jsonb_build_object(
                         'id', $2::uuid,
                         'record_id', $3::uuid,
                         'chain_batch_ref', $4::uuid,
                         'prev_hash', h.event_hash,
                         'signature', NULL,
                         'signing_key_id', NULL
                     )
                 )).*
         FROM audit_header h
         WHERE h.id = $1",
    )
    .bind(last_id)
    .bind(forged_id)
    .bind(forged_record)
    .bind(chain_batch_ref)
    .execute(db)
    .await
    .expect("forge a header row, as a DB-level writer could");

    let forged_hash = verify::recompute_stored_event_hash(db, forged_id)
        .await
        .expect("recompute the forged row's hash")
        .expect("the forged header exists");
    sqlx::query("UPDATE audit_header SET event_hash = $1 WHERE id = $2")
        .bind(&forged_hash)
        .bind(forged_id)
        .execute(db)
        .await
        .expect("store the recomputed hash");

    forged_id
}

#[tokio::test]
async fn a_forged_header_with_a_random_chain_batch_ref_fails_full_chain_and_single_row_verification()
 {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let signer = chained_org(&db, org, "dangling-batch-ref-key", "55").await;

    let dangling_ref = Uuid::now_v7();
    let forged_id = forge_header_after_last(&db, org, dangling_ref).await;

    let report = verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (forged)");
    assert!(
        !report.is_ok(),
        "a header claiming a batch that does not exist must fail verification"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&dangling_ref.to_string())
                && e.contains("names no audit_chain_batch row")),
        "expected a dangling chain_batch_ref error naming {dangling_ref}, got: {:?}",
        report.errors
    );

    let row = verify::verify_header_row(&db, Some(&signer), forged_id)
        .await
        .expect("verify_header_row (forged)")
        .expect("the forged header exists");
    assert!(
        row.hash_ok,
        "the forged row's event_hash recomputes correctly — only the batch check catches it"
    );
    assert_eq!(
        row.signature_ok,
        Some(false),
        "no verifiable signature covers a chainer-path row whose batch does not exist"
    );
    assert!(!row.is_ok());
}

/// The other half of I2's forgery case: a forged header that names a batch
/// that *does* exist is not exempted either — the batch's Merkle root no
/// longer matches its members.
#[tokio::test]
async fn a_forged_header_claiming_an_existing_batch_fails_the_merkle_check() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let signer = chained_org(&db, org, "existing-batch-ref-key", "66").await;

    let real_batch: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_chain_batch WHERE organization_ref = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("read the organization's batch");

    let forged_id = forge_header_after_last(&db, org, real_batch).await;

    let report = verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (forged into a real batch)");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&real_batch.to_string())
                && (e.contains("merkle_root mismatch") || e.contains("event_count"))),
        "expected batch {real_batch}'s membership check to fail, got: {:?}",
        report.errors
    );

    let row = verify::verify_header_row(&db, Some(&signer), forged_id)
        .await
        .expect("verify_header_row")
        .expect("the forged header exists");
    assert_eq!(
        row.signature_ok, None,
        "single-row verification cannot see batch membership; the existing batch signs the row"
    );
}
