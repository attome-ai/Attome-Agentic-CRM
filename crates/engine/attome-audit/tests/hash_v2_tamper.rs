//! Audit 10/10 plan Phase 2 (contract C1, D-539): hash version 2 signs the
//! complete canonical event, so changing any class of stored field fails
//! verification, while destroying an erasure key does not.
//!
//! Every tamper case writes real events through the production path (the
//! chainer: capture into `audit_ingest`, drain into a batch), confirms
//! the untouched chain verifies, then rewrites one stored value directly in
//! the database — the DB-level writer of the threat model — and asserts the
//! verifier names the changed header. The writer here does **not** recompute
//! the hash; `a_consistently_rewritten_row_is_still_caught_by_the_batch_root`
//! covers the writer who does.
//!
//! `attachment_mutation_fails_verification` (a C1 evidence-matrix name) is
//! deliberately absent: attachment references have no storage until Phase 7
//! creates `audit_attachment`, so there is no stored value to tamper.
//! Field 42 is encoded now (always `count = 0` for a written event), the
//! unit test `canonical::tests::an_attachment_changes_the_digest` proves the
//! slot is hashed, the published vector has an attachment case, and the
//! verifier fails closed if the table appears before it learns to read it.
//! The stored-row tamper test lands with Phase 7.
//!
//! `test_vector_matches` needs no database. To regenerate the published
//! vector after a deliberate D-539 change (the decision text wins over the
//! file):
//!
//! ```powershell
//! $env:ATTOME_REGENERATE_HASH_V2_VECTOR = "1"
//! cargo test -p attome-audit --test hash_v2_tamper test_vector_matches
//! ```
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test hash_v2_tamper -- --test-threads=1
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

use attome_audit::canonical::{
    self, CanonicalAttachment, CanonicalDetail, CanonicalEvent, CanonicalHeader, CanonicalSnapshot,
};
use attome_audit::{
    Attribution, AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditRequestContext,
    AuditService, AuditSource, AuditUserContext, chainer, verify,
};
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("failed to connect to DATABASE_URL");
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");
    Some(db)
}

fn field(name: &str, old: &str, new: &str) -> AuditFieldChange {
    AuditFieldChange {
        field_name: name.into(),
        display_name: Some(format!("{name} (display)")),
        data_type: Some(0),
        old_value: Some(old.into()),
        new_value: Some(new.into()),
        old_display_value: None,
        new_display_value: None,
        old_lookup_entity: None,
        old_lookup_name: None,
        new_lookup_entity: None,
        new_lookup_name: None,
        is_sensitive: false,
    }
}

/// An event exercising every field class C1 names: identity, actor, source,
/// request context, detail values, remark and a snapshot.
fn full_event(org: Uuid, i: usize) -> AuditEvent {
    AuditEvent {
        organization_ref: org,
        category: AuditCategory::Entity,
        entity_name: Some("hash_v2_test_entity".into()),
        record_id: Some(Uuid::now_v7()),
        operation: AuditOperation::Update,
        version_before: Some(i as i64),
        version_after: Some(i as i64 + 1),
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: format!("hash-v2-user-{i}"),
            user_display_name: format!("Hash V2 User {i}"),
            user_email: format!("hash-v2-{i}@example.test"),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext {
            ip_address: Some(format!("10.0.0.{i}")),
            browser: Some("hash-v2-test-agent".into()),
            device_type: Some(0),
        },
        correlation_id: Some(Uuid::now_v7()),
        batch_id: None,
        event_name: Some(format!("hash-v2-event-{i}")),
        event_comment: Some(format!("remark {i}")),
        changed_fields: vec![
            field("status", "draft", &format!("approved-{i}")),
            field("amount", "10", &format!("{}", 20 + i)),
        ],
        snapshot_json: Some(
            serde_json::json!({"status": format!("approved-{i}"), "amount": 20 + i}),
        ),
    }
}

/// Writes `n` full events through the chainer path, drains them, asserts the
/// untouched chain verifies as all-v2, and returns the header ids in chain order.
async fn chained_headers(db: &DbPool, org: Uuid, n: usize) -> Vec<Uuid> {
    for i in 0..n {
        AuditService::new(db, None)
            .with_chainer_enabled(true)
            .write(full_event(org, i))
            .await
            .expect("audit write (chainer path)");
    }
    chainer::run_once(db, None, 1000, None)
        .await
        .expect("chainer run");
    assert_clean(db, org).await;
    header_ids(db, org).await
}

async fn header_ids(db: &DbPool, org: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM audit_header WHERE organization_ref = $1 ORDER BY id")
        .bind(org)
        .fetch_all(db)
        .await
        .expect("read header ids")
}

async fn assert_clean(db: &DbPool, org: Uuid) -> verify::VerificationReport {
    let report = verify::verify_chain(db, None, org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "the untouched chain must verify, got: {:?}",
        report.errors
    );
    report
}

async fn exec(db: &DbPool, sql: &str, id: Uuid) {
    let affected = sqlx::query(sql)
        .bind(id)
        .execute(db)
        .await
        .unwrap_or_else(|e| panic!("tamper statement failed: {sql}: {e}"))
        .rows_affected();
    assert!(affected > 0, "tamper statement changed nothing: {sql}");
}

/// Verification fails and reports a content change on `header`.
async fn assert_content_tamper_reported(db: &DbPool, org: Uuid, header: Uuid) {
    let report = verify::verify_chain(db, None, org)
        .await
        .expect("verify_chain (tampered)");
    assert!(!report.is_ok(), "a tampered event must fail verification");
    let id = header.to_string();
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&id) && e.contains("content_digest mismatch")),
        "expected a content_digest mismatch for header {header}, got: {:?}",
        report.errors
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&id) && e.contains("event_hash mismatch")),
        "expected an event_hash mismatch for header {header}, got: {:?}",
        report.errors
    );
}

// ── C1 evidence-matrix tests ────────────────────────────────────────────────

#[tokio::test]
async fn identity_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 3).await;

    exec(
        &db,
        "UPDATE audit_header SET version_after = version_after + 100 WHERE id = $1",
        ids[1],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[1]).await;

    // Identity fields v1 never covered: category and correlation id.
    exec(
        &db,
        "UPDATE audit_header SET category = 4, correlation_id = uuidv7() WHERE id = $1",
        ids[2],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[2]).await;
}

#[tokio::test]
async fn actor_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "UPDATE audit_header SET user_id = uuidv7() WHERE id = $1",
        ids[0],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[0]).await;
}

#[tokio::test]
async fn initiator_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let event = full_event(org, 0);
    let attribution =
        Attribution::agent(event.user_context.user_id, Uuid::now_v7(), "record.update");
    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write_attributed(event, attribution)
        .await
        .expect("agent-attributed audit write (chainer path)");
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run");
    assert_clean(&db, org).await;
    let ids = header_ids(&db, org).await;

    // The chainer writes the attribution the mutation's transaction hashed,
    // rather than dropping it to the plain-user default.
    let (initiator, action): (i16, Option<String>) =
        sqlx::query_as("SELECT initiator, agent_action_id FROM audit_header WHERE id = $1")
            .bind(ids[0])
            .fetch_one(&db)
            .await
            .expect("read attribution");
    assert_eq!(initiator, 1, "the agent initiator survives the chainer");
    assert_eq!(action.as_deref(), Some("record.update"));

    // Relabel the agent's write as the human's own.
    exec(
        &db,
        "UPDATE audit_header SET initiator = 0 WHERE id = $1",
        ids[0],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[0]).await;
}

#[tokio::test]
async fn source_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "UPDATE audit_header SET source = 3 WHERE id = $1",
        ids[1],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[1]).await;
}

#[tokio::test]
async fn context_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 3).await;

    exec(
        &db,
        "UPDATE audit_header SET ip_address = '192.0.2.99' WHERE id = $1",
        ids[0],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[0]).await;

    // `request_id` (field 21) is reserved and NULL today; writing one into a
    // stored event is a change to its request context.
    exec(
        &db,
        "UPDATE audit_header SET request_id = 'forged-request' WHERE id = $1",
        ids[1],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[1]).await;

    exec(
        &db,
        "UPDATE audit_header SET browser = NULL WHERE id = $1",
        ids[2],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[2]).await;
}

#[tokio::test]
async fn values_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "UPDATE audit_detail SET new_value = 'forged' \
         WHERE audit_ref = $1 AND field_name = 'status'",
        ids[0],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[0]).await;

    // Single-row verification (signoff's check) covers content too.
    let row = verify::verify_header_row(&db, None, ids[0])
        .await
        .expect("verify_header_row")
        .expect("header exists");
    assert_eq!(row.hash_version, 2);
    assert!(
        !row.hash_ok,
        "single-row verification must see the value change"
    );
    let untouched = verify::verify_header_row(&db, None, ids[1])
        .await
        .expect("verify_header_row")
        .expect("header exists");
    assert!(untouched.hash_ok);
}

#[tokio::test]
async fn remark_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "UPDATE audit_header SET event_comment = 'a different remark' WHERE id = $1",
        ids[1],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[1]).await;
}

#[tokio::test]
async fn erasure_keeps_verification_passing() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ring = KeyRing::single("cd".repeat(32));
    let event = full_event(org, 0);
    let record_id = event.record_id.expect("record id");

    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .with_erasure_key(Some(ring))
        .write(event)
        .await
        .expect("encrypted audit write (chainer path)");
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run");
    assert_clean(&db, org).await;
    let ids = header_ids(&db, org).await;

    let stored: Option<String> = sqlx::query_scalar(
        "SELECT new_value FROM audit_detail WHERE audit_ref = $1 AND field_name = 'status'",
    )
    .bind(ids[0])
    .fetch_one(&db)
    .await
    .expect("read detail");
    assert_ne!(
        stored.as_deref(),
        Some("approved-0"),
        "the digest covers ciphertext, never the plaintext (I3)"
    );

    let mut tx = db.begin().await.expect("begin");
    assert!(
        attome_audit::destroy_key(&mut tx, "hash_v2_test_entity", record_id, Uuid::now_v7())
            .await
            .expect("destroy_key")
    );
    tx.commit().await.expect("commit");

    let report = assert_clean(&db, org).await;
    assert_eq!(report.v2_headers, 1);
}

// ── Plan Phase 2 tamper matrix ──────────────────────────────────────────────

#[tokio::test]
async fn detail_row_added_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "INSERT INTO audit_detail (organization_ref, audit_ref, field_name, data_type, \
                                       new_value, is_sensitive) \
         SELECT organization_ref, id, 'owner', 0, 'forged-owner', false \
         FROM audit_header WHERE id = $1",
        ids[1],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[1]).await;
}

#[tokio::test]
async fn detail_row_deleted_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "DELETE FROM audit_detail WHERE audit_ref = $1 AND field_name = 'amount'",
        ids[0],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[0]).await;
}

#[tokio::test]
async fn snapshot_mutation_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "UPDATE audit_snapshot \
         SET snapshot_json = jsonb_set(snapshot_json, '{status}', '\"forged\"') \
         WHERE audit_ref = $1",
        ids[1],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[1]).await;
}

#[tokio::test]
async fn swapping_detail_rows_between_headers_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    // Swap each header's `status` detail row onto the other header: both
    // headers still hold one `status` and one `amount` row.
    let a: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_detail WHERE audit_ref = $1 AND field_name = 'status'",
    )
    .bind(ids[0])
    .fetch_one(&db)
    .await
    .expect("detail a");
    let b: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_detail WHERE audit_ref = $1 AND field_name = 'status'",
    )
    .bind(ids[1])
    .fetch_one(&db)
    .await
    .expect("detail b");
    sqlx::query(
        "UPDATE audit_detail SET audit_ref = CASE WHEN id = $1 THEN $4::uuid ELSE $3::uuid END \
         WHERE id IN ($1, $2)",
    )
    .bind(a)
    .bind(b)
    .bind(ids[0])
    .bind(ids[1])
    .execute(&db)
    .await
    .expect("swap detail rows");

    assert_content_tamper_reported(&db, org, ids[0]).await;
    assert_content_tamper_reported(&db, org, ids[1]).await;
}

#[tokio::test]
async fn unknown_hash_version_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;

    exec(
        &db,
        "UPDATE audit_header SET hash_version = 3 WHERE id = $1",
        ids[0],
    )
    .await;
    let report = verify::verify_chain(&db, None, org)
        .await
        .expect("verify_chain");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&ids[0].to_string()) && e.contains("unknown hash_version 3")),
        "an unknown version is a failure, never a skip: {:?}",
        report.errors
    );
    let row = verify::verify_header_row(&db, None, ids[0])
        .await
        .expect("verify_header_row")
        .expect("header exists");
    assert!(!row.hash_ok);
}

/// A pre-v2 ingest payload: the serialized `AuditEvent` with no hash version,
/// digest or attribution, exactly what a writer produced before this change
/// (and what an old-binary node still produces during a rolling upgrade).
async fn insert_legacy_ingest_row(db: &DbPool, event: &AuditEvent) {
    let payload = serde_json::to_value(event).expect("serialize AuditEvent");
    sqlx::query("INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2)")
        .bind(event.organization_ref)
        .bind(payload)
        .execute(db)
        .await
        .expect("insert legacy ingest row");
}

async fn hash_versions(db: &DbPool, org: Uuid) -> Vec<i16> {
    sqlx::query_scalar(
        "SELECT hash_version FROM audit_header WHERE organization_ref = $1 ORDER BY id",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .expect("read hash versions")
}

#[tokio::test]
async fn v1_only_chain_verifies() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    for i in 0..3 {
        insert_legacy_ingest_row(&db, &full_event(org, i)).await;
    }
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run");

    assert_eq!(hash_versions(&db, org).await, vec![1, 1, 1]);
    let report = assert_clean(&db, org).await;
    assert_eq!((report.v1_headers, report.v2_headers), (3, 0));

    // v1 content stays unprotected by the hash (the cutover checkpoint, plan
    // item 2.6, is what freezes it): a detail edit on a v1 row still verifies.
    let ids = header_ids(&db, org).await;
    exec(
        &db,
        "UPDATE audit_detail SET new_value = 'edited' WHERE audit_ref = $1",
        ids[0],
    )
    .await;
    assert_clean(&db, org).await;
}

#[tokio::test]
async fn mixed_v1_to_v2_chain_verifies() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();

    // Two legacy rows drained first, as the upgrade finds them.
    for i in 0..2 {
        insert_legacy_ingest_row(&db, &full_event(org, i)).await;
    }
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run (v1)");

    // Then a batch that itself mixes a straggling legacy payload with v2.
    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(full_event(org, 2))
        .await
        .expect("v2 write");
    insert_legacy_ingest_row(&db, &full_event(org, 3)).await;
    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(full_event(org, 4))
        .await
        .expect("v2 write");
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run (mixed)");

    // And the synchronous writer, which also writes v2.
    AuditService::new(&db, None)
        .write(full_event(org, 5))
        .await
        .expect("sync v2 write");

    assert_eq!(hash_versions(&db, org).await, vec![1, 1, 2, 1, 2, 2]);
    let report = assert_clean(&db, org).await;
    assert_eq!((report.v1_headers, report.v2_headers), (3, 3));

    // The first v2 row links to the last v1 row's hash verbatim.
    let (prev, v1_hash): (Option<String>, String) = sqlx::query_as(
        "SELECT h2.prev_hash, h1.event_hash
         FROM audit_header h2, audit_header h1
         WHERE h2.id = $1 AND h1.id = $2",
    )
    .bind(header_ids(&db, org).await[2])
    .bind(header_ids(&db, org).await[1])
    .fetch_one(&db)
    .await
    .expect("read link");
    assert_eq!(prev.as_deref(), Some(v1_hash.as_str()));

    // A content change on the synchronous v2 row is caught as well.
    let ids = header_ids(&db, org).await;
    exec(
        &db,
        "UPDATE audit_detail SET old_value = 'x' WHERE audit_ref = $1 AND field_name = 'amount'",
        ids[5],
    )
    .await;
    assert_content_tamper_reported(&db, org, ids[5]).await;
}

/// The writer who knows the public formula recomputes the tampered row's
/// digest and hash. That row then recomputes cleanly, and the batch's signed
/// Merkle root (or the per-row signature on the sync path) is what catches it.
#[tokio::test]
async fn a_consistently_rewritten_row_is_still_caught_by_the_batch_root() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let ids = chained_headers(&db, org, 2).await;
    let last = ids[1];

    exec(
        &db,
        "UPDATE audit_detail SET new_value = 'forged' WHERE audit_ref = $1 AND field_name = 'status'",
        last,
    )
    .await;
    let forged_hash = verify::recompute_stored_event_hash(&db, last)
        .await
        .expect("recompute")
        .expect("header exists");
    sqlx::query("UPDATE audit_header SET event_hash = $1, content_digest = NULL WHERE id = $2")
        .bind(&forged_hash)
        .bind(last)
        .execute(&db)
        .await
        .expect("store the recomputed hash");

    let report = verify::verify_chain(&db, None, org)
        .await
        .expect("verify_chain");
    assert!(
        !report
            .errors
            .iter()
            .any(|e| e.contains(&last.to_string()) && e.contains("event_hash mismatch")),
        "the forged row recomputes cleanly on its own: {:?}",
        report.errors
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("merkle_root mismatch")),
        "the batch Merkle root must catch the rewritten leaf: {:?}",
        report.errors
    );
}

/// D-539 ruling 4: a payload whose digest does not match what the chainer
/// writes fails the batch instead of committing an unverifiable row.
#[tokio::test]
async fn a_payload_digest_that_does_not_match_the_stored_rows_fails_the_batch() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(full_event(org, 0))
        .await
        .expect("v2 write");

    // Tamper the pending ingest payload's content, keeping its digest.
    sqlx::query(
        "UPDATE audit_ingest SET payload = jsonb_set(payload, '{event_comment}', '\"edited in ingest\"') \
         WHERE organization_ref = $1",
    )
    .bind(org)
    .execute(&db)
    .await
    .expect("tamper ingest payload");

    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run (per-org failures are logged, not returned)");
    assert!(
        header_ids(&db, org).await.is_empty(),
        "the batch must roll back rather than chain a row that does not reproduce its digest"
    );

    // Clean up so later chainer runs in this binary are not blocked by it.
    sqlx::query("DELETE FROM audit_ingest WHERE organization_ref = $1")
        .bind(org)
        .execute(&db)
        .await
        .expect("remove the poisoned ingest row");
}

// ── Published test vector (D-539 ruling 8) ──────────────────────────────────

const VECTOR_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/hash_v2.json");

#[derive(Serialize, Deserialize)]
struct VectorFile {
    format: String,
    spec: String,
    notes: Vec<String>,
    cases: Vec<VectorCase>,
}

#[derive(Serialize, Deserialize, Clone)]
struct V1Inputs {
    prev_hash: String,
    operation: i32,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    user_id: Uuid,
    changed_on_millis: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct VectorCase {
    name: String,
    description: String,
    /// When present, `prev_hash` is the v1 `event_hash` of these inputs.
    v1_prev: Option<V1Inputs>,
    prev_hash: String,
    event: CanonicalEvent,
    canonical_hex: String,
    content_digest: String,
    event_hash: String,
}

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0000 | n)
}

fn at(micros: i64) -> DateTime<Utc> {
    Utc.timestamp_micros(micros)
        .single()
        .expect("valid timestamp")
}

fn keys_only_header() -> CanonicalHeader {
    CanonicalHeader {
        organization_ref: Some(uuid(1)),
        category: Some(0),
        operation: Some(1),
        source: Some(1),
        user_id: Some(uuid(2)),
        initiator: Some(0),
        changed_on: Some(at(1_789_000_000_123_456)),
        ..CanonicalHeader::default()
    }
}

fn detail(name: &str, new_value: Option<&str>) -> CanonicalDetail {
    CanonicalDetail {
        field_name: Some(name.into()),
        display_name: Some(name.to_uppercase()),
        data_type: Some(0),
        new_value: new_value.map(str::to_owned),
        is_sensitive: Some(false),
        ..CanonicalDetail::default()
    }
}

/// Inputs of every published case. Outputs are computed by this crate's
/// implementation when the file is regenerated.
/// `(name, description, v1_prev, index of the v2 case whose hash is prev_hash, event)`.
type VectorInput = (
    String,
    String,
    Option<V1Inputs>,
    Option<usize>,
    CanonicalEvent,
);

// The inputs keep v1's entity names on purpose: they are arbitrary data, and
// keeping them leaves the published vector (D-539 ruling 8) byte-identical to
// the one v1 published, so an outside verifier checks both with one file.
fn vector_inputs() -> Vec<VectorInput> {
    let v1 = V1Inputs {
        prev_hash: String::new(),
        operation: 1,
        entity_name: Some("xrm_contact".into()),
        record_id: Some(uuid(3)),
        user_id: uuid(2),
        changed_on_millis: 1_788_999_999_000,
    };
    vec![
        (
            "keys_only_all_else_null".into(),
            "Every nullable header field NULL; no details, no snapshot, zero attachments; genesis.".into(),
            None,
            None,
            CanonicalEvent {
                header: keys_only_header(),
                ..CanonicalEvent::default()
            },
        ),
        (
            "empty_string_next_to_null".into(),
            "event_comment is the empty string (present, length 0); event_name is NULL.".into(),
            None,
            None,
            CanonicalEvent {
                header: CanonicalHeader {
                    event_comment: Some(String::new()),
                    event_name: None,
                    ..keys_only_header()
                },
                ..CanonicalEvent::default()
            },
        ),
        (
            "multi_byte_utf8".into(),
            "Arabic, an em dash, an accented letter and an astral-plane emoji, hashed as stored UTF-8 bytes with no normalization.".into(),
            None,
            None,
            CanonicalEvent {
                header: CanonicalHeader {
                    entity_name: Some("xrm_contact".into()),
                    event_name: Some("تمت الموافقة — é 😀".into()),
                    ..keys_only_header()
                },
                details: vec![CanonicalDetail {
                    display_name: Some("Nom complet — é".into()),
                    new_value: Some("Ünïcödé 😀".into()),
                    ..detail("fullname", None)
                }],
                ..CanonicalEvent::default()
            },
        ),
        (
            "two_details_given_in_reverse_order".into(),
            "Details supplied as [zeta, alpha]; encoded ordered by field_name bytes as [alpha, zeta].".into(),
            None,
            None,
            CanonicalEvent {
                header: keys_only_header(),
                details: vec![detail("zeta", Some("26")), detail("alpha", Some("1"))],
                ..CanonicalEvent::default()
            },
        ),
        (
            "encrypted_snapshot_string".into(),
            "The stored jsonb value is a JSON string (ciphertext); field 41.3 is its UTF-8 content.".into(),
            None,
            None,
            CanonicalEvent {
                header: CanonicalHeader {
                    entity_name: Some("xrm_contact".into()),
                    record_id: Some(uuid(3)),
                    version_after: Some(7),
                    ..keys_only_header()
                },
                snapshots: vec![CanonicalSnapshot {
                    version: Some(7),
                    trigger: Some(0),
                    snapshot_json: Some(serde_json::json!("AQIDBAUGBwgJCgsMDQ4PEA==")),
                }],
                ..CanonicalEvent::default()
            },
        ),
        (
            "plaintext_jcs_snapshot".into(),
            "A plaintext object snapshot, canonicalized with RFC 8785 (member order by UTF-16 code units, ECMAScript number form).".into(),
            None,
            None,
            CanonicalEvent {
                header: keys_only_header(),
                snapshots: vec![CanonicalSnapshot {
                    version: Some(2),
                    trigger: Some(0),
                    snapshot_json: Some(serde_json::json!({
                        "zeta": 1.50,
                        "alpha": [true, null, "x\n\"y\""],
                        "\u{20ac}": 1e21,
                        "\u{1F600}": -0.000001,
                        "big": 9007199254740993u64,
                        "nested": {"b": 2, "a": 1.0}
                    })),
                }],
                ..CanonicalEvent::default()
            },
        ),
        (
            "zero_attachments_and_one_reserved_attachment".into(),
            "One attachment reference (field 42). No writer produces one before Phase 7; published so the framing is pinned.".into(),
            None,
            None,
            CanonicalEvent {
                header: keys_only_header(),
                attachments: vec![CanonicalAttachment {
                    document_ref: Some(uuid(9)),
                    content_sha256: Some("ab".repeat(32)),
                    filename: Some("evidence.pdf".into()),
                    attached_by: Some(uuid(2)),
                    attached_on: Some(at(1_789_000_000_000_000)),
                }],
                ..CanonicalEvent::default()
            },
        ),
        (
            "negative_i64".into(),
            "version_before is i64::MIN and version_after is -1 (two's-complement big-endian).".into(),
            None,
            None,
            CanonicalEvent {
                header: CanonicalHeader {
                    version_before: Some(i64::MIN),
                    version_after: Some(-1),
                    ..keys_only_header()
                },
                ..CanonicalEvent::default()
            },
        ),
        (
            "genesis_full_event".into(),
            "Every header field present, a sensitive masked detail, a snapshot; empty prev_hash (genesis).".into(),
            None,
            None,
            CanonicalEvent {
                header: CanonicalHeader {
                    organization_ref: Some(uuid(1)),
                    category: Some(0),
                    operation: Some(1),
                    source: Some(1),
                    entity_name: Some("xrm_contact".into()),
                    record_id: Some(uuid(3)),
                    version_before: Some(4),
                    version_after: Some(5),
                    user_id: Some(uuid(2)),
                    initiator: Some(1),
                    agent_session_id: Some(uuid(4)),
                    agent_action_id: Some("record.update".into()),
                    changed_on: Some(at(1_789_000_000_123_456)),
                    correlation_id: Some(uuid(5)),
                    batch_id: Some(uuid(6)),
                    event_name: Some("updated".into()),
                    event_comment: Some("remark".into()),
                    ip_address: Some("192.0.2.1".into()),
                    browser: Some("Mozilla/5.0".into()),
                    device_type: Some(2),
                    request_id: Some("req-123".into()),
                    session_id: Some(uuid(7)),
                    ai_model_id: Some("model-x".into()),
                    approval_request_ref: Some(uuid(8)),
                    outcome: Some(0),
                    requested_count: Some(10),
                    affected_count: Some(9),
                    failed_count: Some(1),
                    occurrence_count: Some(1),
                },
                details: vec![CanonicalDetail {
                    field_name: Some("salary".into()),
                    display_name: Some("Salary".into()),
                    data_type: Some(1),
                    value_mode: Some(1),
                    old_value: Some("********".into()),
                    new_value: Some("********".into()),
                    old_display_value: None,
                    new_display_value: None,
                    old_lookup_entity: Some("xrm_core_systemuser".into()),
                    old_lookup_name: Some("old".into()),
                    new_lookup_entity: Some("xrm_core_systemuser".into()),
                    new_lookup_name: Some("new".into()),
                    is_sensitive: Some(true),
                }],
                snapshots: vec![CanonicalSnapshot {
                    version: Some(5),
                    trigger: Some(0),
                    snapshot_json: Some(serde_json::json!("c2VjcmV0")),
                }],
                attachments: vec![],
            },
        ),
        (
            "v1_to_v2_link".into(),
            "The first v2 row after a v1 row: prev_hash is the v1 event_hash of v1_prev, verbatim.".into(),
            Some(v1),
            None,
            CanonicalEvent {
                header: keys_only_header(),
                details: vec![detail("status", Some("approved"))],
                ..CanonicalEvent::default()
            },
        ),
        (
            "v2_to_v2_link".into(),
            "prev_hash is the event_hash of case genesis_full_event.".into(),
            None,
            Some(8),
            CanonicalEvent {
                header: keys_only_header(),
                ..CanonicalEvent::default()
            },
        ),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn generate_vector() -> VectorFile {
    let mut cases: Vec<VectorCase> = Vec::new();
    for (name, description, v1_prev, v2_prev_case, event) in vector_inputs() {
        let prev_hash = match (&v1_prev, v2_prev_case) {
            (Some(v1), _) => canonical::event_hash_v1(
                &v1.prev_hash,
                v1.operation,
                v1.entity_name.as_deref(),
                v1.record_id,
                v1.user_id,
                v1.changed_on_millis,
            ),
            (None, Some(index)) => cases[index].event_hash.clone(),
            (None, None) => String::new(),
        };
        let bytes = canonical::encode_v2(&event).expect("encode");
        let digest = canonical::content_digest_v2(&event).expect("digest");
        let event_hash = canonical::event_hash_v2(&prev_hash, &digest).expect("event hash");
        cases.push(VectorCase {
            name,
            description,
            v1_prev,
            prev_hash,
            event,
            canonical_hex: hex(&bytes),
            content_digest: digest,
            event_hash,
        });
    }
    VectorFile {
        format: "attome-audit-hash-v2-test-vector/1".into(),
        spec: "document/decisions/security/D-539.md (ruling 3); if this file and that text disagree, the text wins and this file is regenerated".into(),
        notes: vec![
            "Every field is u16 field_no (big-endian), a presence tag u8 (0x00 NULL/absent, 0x01 present), then when present LP(value) = u32 big-endian byte length followed by the bytes.".into(),
            "The stream starts with LP(\"ATTOME-AUDIT-EVENT\") || u16(2). Header fields 1-29 follow in order, then field 40 (details), 41 (snapshot), 42 (attachments).".into(),
            "Field 40 and field 42 are present (0x01) with value = u32 count followed by LP(row bytes) per row; rows use the same field syntax. Details are ordered by field_name bytes; attachments by document_ref bytes then content_sha256 bytes.".into(),
            "Field 41 is 0x00 with no snapshot row, else 0x01 then LP(row bytes) with fields 1 version (i64), 2 trigger (i32), 3 snapshot canonical text.".into(),
            "Integers are two's-complement big-endian inside their LP; uuid is its 16 RFC 9562 bytes; bool is one byte; timestamptz is i64 microseconds since the Unix epoch (UTC); content_sha256 is its 32 raw bytes.".into(),
            "event.snapshots[].snapshot_json is the stored jsonb value: a JSON string encodes as its UTF-8 content, anything else as its RFC 8785 serialization.".into(),
            "content_digest = lowercase hex SHA-256(canonical bytes). event_hash = lowercase hex SHA-256(\"ATTOME-AUDIT-CHAIN\" || 0x00 || u16(2) || LP(prev_hash ASCII) || content_digest raw 32 bytes).".into(),
            "v1_prev inputs hash with the v1 formula: SHA-256(prev_hash || operation i32 LE || entity_name bytes if present || record_id 16 bytes if present || user_id 16 bytes || changed_on_millis i64 LE).".into(),
        ],
        cases,
    }
}

#[test]
fn test_vector_matches() {
    if std::env::var_os("ATTOME_REGENERATE_HASH_V2_VECTOR").is_some() {
        let generated = generate_vector();
        let mut json = serde_json::to_string_pretty(&generated).expect("serialize vector");
        json.push('\n');
        std::fs::write(VECTOR_PATH, json).expect("write vector file");
    }

    let text = std::fs::read_to_string(VECTOR_PATH).expect("read tests/vectors/hash_v2.json");
    let file: VectorFile = serde_json::from_str(&text).expect("parse vector file");

    let required = [
        "keys_only_all_else_null",
        "empty_string_next_to_null",
        "multi_byte_utf8",
        "two_details_given_in_reverse_order",
        "encrypted_snapshot_string",
        "plaintext_jcs_snapshot",
        "zero_attachments_and_one_reserved_attachment",
        "negative_i64",
        "genesis_full_event",
        "v1_to_v2_link",
    ];
    for name in required {
        assert!(
            file.cases.iter().any(|c| c.name == name),
            "the published vector must carry case {name} (D-539 ruling 8)"
        );
    }

    // Reproduce every case from the file's own inputs.
    for case in &file.cases {
        let bytes = canonical::encode_v2(&case.event).expect("encode");
        assert_eq!(
            hex(&bytes),
            case.canonical_hex,
            "{}: canonical bytes",
            case.name
        );
        let digest = canonical::content_digest_v2(&case.event).expect("digest");
        assert_eq!(digest, case.content_digest, "{}: content_digest", case.name);
        assert_eq!(
            canonical::event_hash_v2(&case.prev_hash, &digest).expect("event hash"),
            case.event_hash,
            "{}: event_hash",
            case.name
        );
        if let Some(v1) = &case.v1_prev {
            assert_eq!(
                canonical::event_hash_v1(
                    &v1.prev_hash,
                    v1.operation,
                    v1.entity_name.as_deref(),
                    v1.record_id,
                    v1.user_id,
                    v1.changed_on_millis,
                ),
                case.prev_hash,
                "{}: v1 link",
                case.name
            );
        }
    }

    // The zero-attachment cases end with field 42 present, count 0.
    let keys_only = file
        .cases
        .iter()
        .find(|c| c.name == "keys_only_all_else_null")
        .expect("case");
    assert!(
        keys_only.canonical_hex.ends_with("002a010000000400000000"),
        "field 42 must be encoded explicitly with count 0"
    );

    // The file's inputs are the implementation's current inputs, so a changed
    // encoder cannot silently keep passing against a stale file.
    let generated = generate_vector();
    assert_eq!(
        serde_json::to_value(&generated.cases).expect("serialize"),
        serde_json::to_value(&file.cases).expect("serialize"),
        "tests/vectors/hash_v2.json is stale; regenerate it (see this file's header) and review the diff"
    );
}
