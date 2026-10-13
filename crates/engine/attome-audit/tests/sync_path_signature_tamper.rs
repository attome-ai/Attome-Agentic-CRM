//! Regression test for the sync-path signature-verification gap: before
//! `verify.rs`'s `verify_row_chain` checked a header row's `signature`
//! against its `signing_key_id`, a writer with direct DB access could
//! rewrite a `audit_header` row's business columns, recompute
//! `event_hash` with the same formula `AuditService`/`verify.rs` use (the
//! formula is not secret — it's SHA-256 over public column values), and
//! `verify_chain` would report clean because nothing ever checked the
//! stored `signature` on the sync path (only the batch/chainer path's
//! `verify_batch_signature` verified anything cryptographic).
//!
//! This test tampers the LAST header row only — no forward hash-chain
//! propagation is needed, since no later row's `prev_hash` depends on it —
//! which is the simplest form of the attack: silently edit the most recent
//! audit entry and recompute just that row's own `event_hash` so the
//! row-level hash-chain check alone would pass. The old `signature` is left
//! in place (the attacker cannot forge a new one without the Ed25519
//! private key), so it now signs a `prev_hash||event_hash` pair that no
//! longer matches what's stored — which only the new signature check
//! catches.
//!
//! Same `DATABASE_URL` convention as the other integration tests in this
//! suite (see `chainer_end_to_end.rs`'s header).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test sync_path_signature_tamper
//! ```

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
use chrono::{DateTime, SubsecRound, Utc};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::fmt::Write as _;
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
            user_name: format!("sig-tamper-test-user-{i}"),
            user_display_name: format!("Sig Tamper Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("sig-tamper-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

/// Mirrors `attome_audit::service::compute_hash_raw` (private to that crate) —
/// the formula is documented and derivable from stored columns alone, which
/// is exactly why the signature check (not just this hash) has to be the
/// thing that catches tampering.
fn compute_hash_raw(
    prev_hash: &str,
    operation: i32,
    entity_name: Option<&str>,
    record_id: Option<Uuid>,
    user_id: Uuid,
    changed_on_millis: i64,
) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(operation.to_le_bytes());
    if let Some(name) = entity_name {
        h.update(name.as_bytes());
    }
    if let Some(record) = record_id {
        h.update(record.as_bytes());
    }
    h.update(user_id.as_bytes());
    h.update(changed_on_millis.to_le_bytes());

    let bytes = h.finalize();
    let mut hex = String::with_capacity(64);
    for b in bytes {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}

#[tokio::test]
async fn tampering_a_sync_path_row_and_recomputing_its_own_hash_is_still_caught_by_signature_check()
{
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("sig-tamper-test-key", &"33".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    const N: usize = 5;
    let mut last_id = Uuid::nil();
    for i in 0..N {
        last_id = AuditService::new(&db, Some(&signer))
            .write(make_event(org, i))
            .await
            .expect("audit write (sync path)");
    }

    let baseline = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (baseline)");
    assert!(
        baseline.is_ok(),
        "untampered sync-path chain must verify cleanly, got errors: {:?}",
        baseline.errors
    );

    #[derive(sqlx::FromRow)]
    struct Row {
        operation: i32,
        entity_name: Option<String>,
        record_id: Option<Uuid>,
        #[allow(dead_code)]
        user_id: Uuid,
        changed_on: DateTime<Utc>,
        prev_hash: Option<String>,
    }

    let row: Row = sqlx::query_as(
        "SELECT operation, entity_name, record_id, user_id, changed_on, prev_hash
         FROM audit_header WHERE id = $1",
    )
    .bind(last_id)
    .fetch_one(&db)
    .await
    .expect("fetch last header row");

    // Simulate a DB-level attacker: change the recorded user, then recompute
    // this row's own event_hash so the row-level hash-link check alone would
    // pass (prev_hash is untouched, and there is no later row whose
    // prev_hash depends on this one, so no forward propagation is needed).
    let forged_user_id = Uuid::now_v7();
    let prev_hash = row.prev_hash.unwrap_or_default();
    let forged_event_hash = compute_hash_raw(
        &prev_hash,
        row.operation,
        row.entity_name.as_deref(),
        row.record_id,
        forged_user_id,
        row.changed_on.trunc_subsecs(6).timestamp_millis(),
    );

    sqlx::query("UPDATE audit_header SET user_id = $1, event_hash = $2 WHERE id = $3")
        .bind(forged_user_id)
        .bind(&forged_event_hash)
        .bind(last_id)
        .execute(&db)
        .await
        .expect("forge header row");

    let tampered = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (tampered)");

    assert!(
        !tampered.is_ok(),
        "a forged row whose own event_hash was recomputed to match must still be \
         caught by the signature check"
    );
    assert!(
        tampered
            .errors
            .iter()
            .any(|e| e.contains(&last_id.to_string()) && e.contains("signature does not verify")),
        "expected a signature-verification error for header {last_id}, got: {:?}",
        tampered.errors
    );
}

/// Platform review 2026-08-24 B8 — the trivial bypass of the check above.
/// An attacker who can rewrite a header row can also NULL its `signature`,
/// and `verify_row_signature` used to skip unsigned rows outright, so a
/// stripped row verified clean. Now, once `audit_signing_key` has any
/// row (this deployment has configured signing), a sync-path row with no
/// signature is an error in its own right — no tamper of the business
/// columns is even needed to trip it.
///
/// Registers the signer's key the way boot does (`upsert_signing_key`, see
/// `attome-server::system`), which is what turns the rule on; the baseline
/// verifies clean against the registry-resolved key first, so the failure
/// below is attributable to the strip alone.
#[tokio::test]
async fn stripping_a_sync_path_rows_signature_is_caught_once_a_signing_key_is_registered() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("sig-strip-test-key", &"44".repeat(32)).expect("signer");
    attome_core::audit_signing::upsert_signing_key(
        &db,
        "sig-strip-test-key",
        &signer.verifying_key_b64(),
    )
    .await
    .expect("register the signing key, as boot does");
    let org = Uuid::now_v7();

    const N: usize = 4;
    let mut ids = Vec::with_capacity(N);
    for i in 0..N {
        ids.push(
            AuditService::new(&db, Some(&signer))
                .write(make_event(org, i))
                .await
                .expect("audit write (sync path)"),
        );
    }

    let baseline = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (baseline)");
    assert!(
        baseline.is_ok(),
        "signed sync-path chain must verify cleanly with its key registered, got: {:?}",
        baseline.errors
    );

    // Strip a middle row's signature (and the key id, as a row written with
    // signing disabled would look) — nothing else changes, every hash still
    // links, so only the NULL-signature rule can catch this.
    let stripped_id = ids[1];
    sqlx::query("UPDATE audit_header SET signature = NULL, signing_key_id = NULL WHERE id = $1")
        .bind(stripped_id)
        .execute(&db)
        .await
        .expect("strip signature");

    let stripped = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain (stripped)");
    assert!(
        !stripped.is_ok(),
        "a stripped signature must fail verification once a signing key is registered"
    );
    assert!(
        stripped
            .errors
            .iter()
            .any(|e| e.contains(&stripped_id.to_string()) && e.contains("no signature")),
        "expected a missing-signature error for header {stripped_id}, got: {:?}",
        stripped.errors
    );
    // Exactly the stripped row is reported — the still-signed neighbours
    // must not be dragged in (the rule is per row, not per chain).
    let missing: Vec<&String> = stripped
        .errors
        .iter()
        .filter(|e| e.contains("no signature"))
        .collect();
    assert_eq!(
        missing.len(),
        1,
        "only the stripped row should be reported, got: {missing:?}"
    );
}
