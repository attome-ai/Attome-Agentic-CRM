//! D-107 (P-data-lifecycle item (d)'s erasure ruling) — proves crypto-shredding
//! end to end: `AuditService::with_erasure_key` actually encrypts
//! `audit_detail` values at rest, decrypts correctly given the record's
//! key, and destroying that key makes the stored ciphertext permanently
//! unrecoverable WITHOUT affecting chain verification -- hash v1
//! (`compute_hash_raw`) never hashed field values, and hash v2 (D-539) hashes
//! the stored ciphertext, never the plaintext, so there is nothing for
//! erasure to break. See
//! `document/ERASURE-OPTIONS-2026-07-21.md` for the trace through the code
//! that established this before the ruling was made, and
//! `crates/engine/attome-audit/src/erasure.rs`'s doc comment for the full design.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test erasure
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditRequestContext, AuditService,
    AuditSource, AuditUserContext,
};
use attome_config::KeyRing;
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

/// P-key-rotation-and-jwt (a): the erasure master key is a `KeyRing` now, not
/// a bare `[u8; 32]` -- see `attome_audit::erasure`'s doc.
fn test_master_ring() -> KeyRing {
    KeyRing::single("ab".repeat(32))
}

/// Test-only stand-in for the future admin audit-history read path (D-107
/// follow-up): fetches a record's wrapped DEK and unwraps it under the
/// master ring -- `decrypt_field` needs the record's DEK, never the master
/// key directly (the master key only ever wraps/unwraps DEKs, exactly like
/// any other envelope-encryption scheme).
async fn record_dek(db: &DbPool, master_ring: &KeyRing, record_id: Uuid) -> [u8; 32] {
    let wrapped: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(db)
            .await
            .expect("fetch key row");
    let wrapped = wrapped.expect("wrapped_dek must be present (key not destroyed)");
    attome_auth::envelope::decrypt_bytes("test-key", master_ring, &wrapped)
        .expect("unwrap DEK with master key")
        .try_into()
        .expect("DEK must be 32 bytes")
}

fn make_event(organization_ref: Uuid, record_id: Uuid, new_value: &str) -> AuditEvent {
    AuditEvent {
        organization_ref,
        category: AuditCategory::Entity,
        entity_name: Some("erasure_test_entity".into()),
        record_id: Some(record_id),
        operation: AuditOperation::Update,
        version_before: Some(1),
        version_after: Some(2),
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: "erasure-test-user".into(),
            user_display_name: "Erasure Test User".into(),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: None,
        event_comment: None,
        changed_fields: vec![AuditFieldChange {
            field_name: "notes".into(),
            display_name: Some("Notes".into()),
            data_type: Some(0),
            old_value: Some("old plaintext".into()),
            new_value: Some(new_value.to_string()),
            old_display_value: None,
            new_display_value: None,
            old_lookup_entity: None,
            old_lookup_name: None,
            new_lookup_entity: None,
            new_lookup_name: None,
            is_sensitive: false,
        }],
        snapshot_json: None,
    }
}

#[tokio::test]
async fn erasure_key_encrypts_at_rest_and_decrypts_correctly() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let key = test_master_ring();
    let org = Uuid::now_v7();
    let record_id = Uuid::now_v7();

    let header_id = AuditService::new(&db, None)
        .with_erasure_key(Some(key.clone()))
        .write(make_event(org, record_id, "sensitive new value"))
        .await
        .expect("audit write with erasure key");

    let (stored_new_value,): (Option<String>,) =
        sqlx::query_as("SELECT new_value FROM audit_detail WHERE audit_ref = $1")
            .bind(header_id)
            .fetch_one(&db)
            .await
            .expect("fetch detail row");

    let stored = stored_new_value.expect("new_value must be present");
    assert_ne!(
        stored, "sensitive new value",
        "value must be encrypted at rest, not stored as plaintext"
    );

    let dek = record_dek(&db, &key, record_id).await;
    let decrypted =
        attome_audit::decrypt_field(&dek, &stored).expect("decrypt with the record's DEK");
    assert_eq!(decrypted, "sensitive new value");
}

#[tokio::test]
async fn wrong_master_key_cannot_unwrap_a_records_dek() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let key = test_master_ring();
    let wrong_key = KeyRing::single("cd".repeat(32));
    let org = Uuid::now_v7();
    let record_id = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_erasure_key(Some(key))
        .write(make_event(org, record_id, "protected value"))
        .await
        .expect("audit write");

    let wrapped: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch key row");
    let wrapped = wrapped.expect("wrapped_dek present");

    assert!(
        attome_auth::envelope::decrypt_bytes("test-key-2", &wrong_key, &wrapped).is_err(),
        "a deployment's erasure_key_encryption_key must be the only key that can ever \
         unwrap a record's DEK -- a wrong/rotated-away key must not silently succeed"
    );
}

#[tokio::test]
async fn destroying_the_key_makes_history_permanently_unrecoverable_but_chain_still_verifies() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let key = test_master_ring();
    let org = Uuid::now_v7();
    let record_id = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_erasure_key(Some(key))
        .write(make_event(org, record_id, "to be erased"))
        .await
        .expect("audit write");

    let mut tx = db.begin().await.expect("begin");
    let destroyed =
        attome_audit::destroy_key(&mut tx, "erasure_test_entity", record_id, Uuid::now_v7())
            .await
            .expect("destroy_key");
    tx.commit().await.expect("commit");
    assert!(
        destroyed,
        "a live key existed and should have been destroyed"
    );

    let wrapped: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch key row");
    assert!(
        wrapped.is_none(),
        "wrapped_dek must be NULL after destroy -- no key material survives anywhere"
    );

    // Hash v2 covers the stored ciphertext, not the plaintext (D-539, I3),
    // so destroying a record's key -- which changes no stored audit byte --
    // must never fail chain verification.
    let report = attome_audit::verify::verify_chain(&db, None, org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "chain verification must pass after erasure: {:?}",
        report.errors
    );

    // Idempotent: a retried erasure request is not an error.
    let mut tx2 = db.begin().await.expect("begin");
    let destroyed_again =
        attome_audit::destroy_key(&mut tx2, "erasure_test_entity", record_id, Uuid::now_v7())
            .await
            .expect("destroy_key (second call)");
    tx2.commit().await.expect("commit");
    assert!(
        !destroyed_again,
        "second destroy call changes nothing -- the key was already gone"
    );
}

#[tokio::test]
async fn erasing_a_record_with_no_protected_history_is_a_no_op_not_an_error() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let mut tx = db.begin().await.expect("begin");
    let destroyed = attome_audit::destroy_key(
        &mut tx,
        "erasure_test_entity",
        Uuid::now_v7(),
        Uuid::now_v7(),
    )
    .await
    .expect("destroy_key on a record with no key row");
    tx.commit().await.expect("commit");
    assert!(
        !destroyed,
        "a record that was never crypto-shredded has nothing to destroy"
    );
}

#[tokio::test]
async fn editing_a_record_after_its_key_was_destroyed_reprovisions_a_fresh_key() {
    // Design decision documented in erasure.rs's `fetch_or_create_dek` doc
    // comment: a record whose key was destroyed, then edited again, gets a
    // NEW key protecting its new edits -- it does not silently fall back to
    // plaintext. This proves that choice actually holds.
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let key = test_master_ring();
    let org = Uuid::now_v7();
    let record_id = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_erasure_key(Some(key.clone()))
        .write(make_event(org, record_id, "first edit"))
        .await
        .expect("first write");

    let mut tx = db.begin().await.expect("begin");
    attome_audit::destroy_key(&mut tx, "erasure_test_entity", record_id, Uuid::now_v7())
        .await
        .expect("destroy_key");
    tx.commit().await.expect("commit");

    let header_id_2 = AuditService::new(&db, None)
        .with_erasure_key(Some(key.clone()))
        .write(make_event(org, record_id, "second edit after erasure"))
        .await
        .expect("second write should re-provision a key, not error or go plaintext");

    let (stored_2,): (Option<String>,) =
        sqlx::query_as("SELECT new_value FROM audit_detail WHERE audit_ref = $1")
            .bind(header_id_2)
            .fetch_one(&db)
            .await
            .expect("fetch second detail row");
    let stored_2 = stored_2.expect("value present");
    assert_ne!(
        stored_2, "second edit after erasure",
        "the record's new edit must be protected under a fresh key, not left as plaintext"
    );
    let new_dek = record_dek(&db, &key, record_id).await;
    assert_eq!(
        attome_audit::decrypt_field(&new_dek, &stored_2).expect("decrypt with the fresh DEK"),
        "second edit after erasure"
    );

    let wrapped: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch key row");
    assert!(
        wrapped.is_some(),
        "a fresh key must exist after the re-provisioning edit"
    );
}

/// P-data-protection-governance §4 — a record under an active legal hold
/// must not have its crypto-shredding key destroyed. Proves `destroy_key`'s
/// new `attome_core::legal_hold::record_is_held` check.
#[tokio::test]
async fn destroy_key_refuses_a_record_under_an_active_legal_hold() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let key = test_master_ring();
    let org = Uuid::now_v7();
    let record_id = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_erasure_key(Some(key))
        .write(make_event(org, record_id, "protected under hold"))
        .await
        .expect("audit write");

    sqlx::query(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ('erasure_test_entity', $1, 'test-matter', $2)",
    )
    .bind(record_id)
    .bind(Uuid::now_v7())
    .execute(&db)
    .await
    .expect("place legal hold");

    let mut tx = db.begin().await.expect("begin");
    let result =
        attome_audit::destroy_key(&mut tx, "erasure_test_entity", record_id, Uuid::now_v7()).await;
    tx.rollback().await.expect("rollback");

    assert!(
        matches!(result, Err(attome_types::AppError::Conflict(_))),
        "destroy_key must refuse a held record with a Conflict, not silently no-op or succeed: {result:?}"
    );

    let wrapped: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch key row");
    assert!(
        wrapped.is_some(),
        "a held record's key must survive untouched"
    );
}

/// D-130's §6 rotate-then-rewrap scenario for the erasure master key: add
/// key B + flip active, confirm the DEK still unwraps pre-rewrap (the
/// wrapped blob still names key A), run the rewrap job, confirm the row now
/// names key B with the SAME underlying DEK (only the wrapping key changes,
/// never the DEK itself), then retire key A and confirm unwrap still works.
#[tokio::test]
async fn rotating_the_erasure_master_key_survives_rewrap_and_retirement() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let key_a = "aa".repeat(32);
    let key_b = "bb".repeat(32);
    let mut ring = KeyRing {
        keys: std::iter::once(("key-a".to_string(), key_a)).collect(),
        active_key_id: "key-a".to_string(),
    };

    // rewrap_secrets scans the whole table by design; other tests in this
    // binary populate audit_erasure_key under a different ring
    // (test_master_ring()'s "legacy" key id) this test's two-key ring can't
    // decrypt. Scope the scan to rows created from this point on, the way a
    // real cursor-resumed rewrap pass would.
    let before_id: Uuid = sqlx::query_scalar(
        "SELECT record_id FROM audit_erasure_key ORDER BY record_id DESC LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .expect("fetch high-water mark")
    .unwrap_or_else(Uuid::nil);

    let org = Uuid::now_v7();
    let record_id = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_erasure_key(Some(ring.clone()))
        .write(make_event(org, record_id, "rotation test value"))
        .await
        .expect("audit write");

    let wrapped_before: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch wrapped_dek");
    assert_eq!(
        attome_auth::envelope::stored_key_id_bytes(&wrapped_before).as_deref(),
        Some("key-a")
    );
    let dek_before = record_dek(&db, &ring, record_id).await;

    // Add key B, flip active.
    ring.keys.insert("key-b".to_string(), key_b);
    ring.active_key_id = "key-b".to_string();

    // Pre-rewrap: the ring still holds key-a, so unwrap must still succeed
    // and must yield the exact same DEK (nothing about the protected data
    // changes here, only what wraps its key).
    assert_eq!(record_dek(&db, &ring, record_id).await, dek_before);

    let progress = attome_audit::erasure::rewrap_secrets(&db, &ring, Some(before_id), 100)
        .await
        .expect("rewrap");
    assert_eq!(progress.rewrapped, 1);

    let wrapped_after: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_dek FROM audit_erasure_key WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(&db)
            .await
            .expect("fetch wrapped_dek after rewrap");
    assert_eq!(
        attome_auth::envelope::stored_key_id_bytes(&wrapped_after).as_deref(),
        Some("key-b")
    );

    // Idempotent second pass.
    let progress2 = attome_audit::erasure::rewrap_secrets(&db, &ring, Some(before_id), 100)
        .await
        .expect("rewrap again");
    assert_eq!(progress2.rewrapped, 0);

    // Retire key A -- unwrap must still succeed on key B alone, and the DEK
    // (and therefore every already-encrypted field value under it) is
    // unchanged.
    ring.keys.remove("key-a");
    assert_eq!(record_dek(&db, &ring, record_id).await, dek_before);
}
