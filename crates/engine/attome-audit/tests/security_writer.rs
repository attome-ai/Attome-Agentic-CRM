//! Audit 10/10 plan items 3.2/3.3 (D-541 rules 3-4, D-542 rule 4): the
//! mandatory security writer.
//!
//! - an event written through [`SecurityTx`] commits with its mutation, on
//!   both the synchronous and the chainer path, with the outcome and count
//!   columns stored and covered by the v2 digest;
//! - a `SecurityTx` dropped without commit writes neither the mutation nor
//!   the event;
//! - rewriting a stored outcome or occurrence count fails verification.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test security_writer -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool; production code uses attome_db::tx::begin"
)]

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{AuditOperation, AuditOutcome, AuditService, chainer, verify};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
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
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS security_writer_probe (id uuid PRIMARY KEY, note text)",
    )
    .execute(&db)
    .await
    .expect("probe table");
    Some(db)
}

fn event(org: Uuid, record: Uuid) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Credential,
        AuditOperation::PasswordReset,
        Uuid::nil(),
        "user_account",
        Some(record),
    )
    .organization(org)
    .outcome(AuditOutcome::Succeeded)
    .occurrence_count(4)
    .named("password_reset_confirmed")
}

type HeaderRow = (i32, i32, Option<i16>, Option<i32>, Option<String>, i16);

async fn headers(db: &DbPool, org: Uuid) -> Vec<(Uuid, HeaderRow)> {
    sqlx::query_as::<
        _,
        (
            Uuid,
            i32,
            i32,
            Option<i16>,
            Option<i32>,
            Option<String>,
            i16,
        ),
    >(
        "SELECT id, category, operation, outcome, occurrence_count, event_name, hash_version \
         FROM audit_header WHERE organization_ref = $1 ORDER BY id",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .expect("read headers")
    .into_iter()
    .map(|(id, c, o, out, n, name, v)| (id, (c, o, out, n, name, v)))
    .collect()
}

async fn probe_exists(db: &DbPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM security_writer_probe WHERE id = $1)")
        .bind(id)
        .fetch_one(db)
        .await
        .expect("probe lookup")
}

async fn write_probe(audit: AuditService<'_>, db: &DbPool, org: Uuid, commit: bool) -> Uuid {
    let id = Uuid::now_v7();
    let mut stx = SecurityTx::begin_with(audit, db, event(org, id))
        .await
        .expect("begin");
    sqlx::query("INSERT INTO security_writer_probe (id, note) VALUES ($1, 'x')")
        .bind(id)
        .execute(&mut *stx)
        .await
        .expect("probe insert");
    if commit {
        stx.commit().await.expect("commit");
    } else {
        drop(stx);
    }
    id
}

fn assert_row(row: &HeaderRow) {
    assert_eq!(
        row,
        &(
            5,
            35,
            Some(AuditOutcome::Succeeded as i16),
            Some(4),
            Some("password_reset_confirmed".to_owned()),
            2
        )
    );
}

#[tokio::test]
async fn sync_path_commits_mutation_and_event_together_with_extras() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();

    let id = write_probe(AuditService::new(&db, None), &db, org, true).await;

    assert!(probe_exists(&db, id).await);
    let rows = headers(&db, org).await;
    assert_eq!(rows.len(), 1, "exactly one event");
    assert_row(&rows[0].1);
    let report = verify::verify_chain(&db, None, org).await.expect("verify");
    assert!(report.is_ok(), "{:?}", report.errors);
}

#[tokio::test]
async fn chainer_path_carries_extras_into_the_header() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();

    let audit = AuditService::new(&db, None).with_chainer_enabled(true);
    let id = write_probe(audit, &db, org, true).await;
    assert!(probe_exists(&db, id).await);
    assert!(
        headers(&db, org).await.is_empty(),
        "chainer path: no header yet"
    );

    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run");
    let rows = headers(&db, org).await;
    assert_eq!(rows.len(), 1);
    assert_row(&rows[0].1);
    let report = verify::verify_chain(&db, None, org).await.expect("verify");
    assert!(report.is_ok(), "{:?}", report.errors);
}

#[tokio::test]
async fn a_dropped_security_tx_writes_neither_mutation_nor_event() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();

    let id = write_probe(AuditService::new(&db, None), &db, org, false).await;

    assert!(!probe_exists(&db, id).await);
    assert!(headers(&db, org).await.is_empty());
    let ingest: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("ingest count");
    assert_eq!(ingest, 0);
}

#[tokio::test]
async fn a_rewritten_outcome_or_occurrence_count_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    write_probe(AuditService::new(&db, None), &db, org, true).await;
    let header = headers(&db, org).await[0].0;

    sqlx::query("UPDATE audit_header SET occurrence_count = 1, outcome = 1 WHERE id = $1")
        .bind(header)
        .execute(&db)
        .await
        .expect("tamper");

    let report = verify::verify_chain(&db, None, org).await.expect("verify");
    assert!(
        !report.is_ok(),
        "a rewritten outcome must fail verification"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&header.to_string()) && e.contains("content_digest mismatch")),
        "{:?}",
        report.errors
    );
}
