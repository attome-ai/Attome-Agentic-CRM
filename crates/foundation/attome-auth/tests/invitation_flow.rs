//! Integration test for the invitation-issue/email-enqueue atomicity fix
//! (audit finding: "email delivery failures are logged and swallowed").
//!
//! `xrm_security::admin::create_invitation` used to call `invitation::issue`
//! (its own commit) and then a *separate* `attome_jobs::enqueue`, catching and
//! only `tracing::warn!`-ing an enqueue failure — so a caller could be told
//! "201 Created" with a register link that would never be emailed. The fix
//! moves both writes onto one caller-owned transaction via
//! `invitation::issue_in_tx` + `attome_jobs::enqueue_in_tx`, mirroring the
//! existing `accounts::register_in_tx` / `reset::request_in_tx` discipline:
//! either both the invitation row and its email job become visible at the
//! same commit, or neither does.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test invitation_flow -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_auth::invitation::issue_in_tx;
use attome_auth::password::hash_password_async;
use attome_db::DbPool;
use attome_email::EmailMessage;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

/// The pepper ring invitation tokens hash with (attome-auth hardening 1.4).
fn test_ring() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "attome-auth-test-pepper-0123456789abcdef", &[])
}

/// The one job kind this test enqueues; attome-jobs is generic over the
/// application's job type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum TestJob {
    SendEmail(Box<EmailMessage>),
}

impl attome_jobs::Job for TestJob {
    fn kind(&self) -> &'static str {
        "SendEmail"
    }
}

fn dummy_email_job(to: &str) -> TestJob {
    TestJob::SendEmail(Box::new(EmailMessage {
        to: to.to_owned(),
        subject: "test invitation".to_owned(),
        text_body: "invite link".to_owned(),
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
        stream: Default::default(),
    }))
}

/// Queued jobs whose payload carries `email`: this test's own jobs only, so
/// tests running in parallel on the same database cannot change the count.
async fn email_jobs_for(db: &DbPool, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'")
        .bind(email)
        .fetch_one(db)
        .await
        .expect("count this test's jobs")
}

async fn invitation_token_count(db: &DbPool, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM invitation_token WHERE email = $1")
        .bind(email)
        .fetch_one(db)
        .await
        .expect("count invitation_token")
}

/// `invitation_token.invited_by_ref` is `NOT NULL REFERENCES
/// user_account(id)` (migration 0045), so the admin id needs a real row —
/// same throwaway-user insert `reset_flow.rs::create_test_user` uses.
async fn create_test_admin(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    let email = format!("invite-admin-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "irrelevant-password-123",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active)
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(db)
    .await
    .expect("insert test admin");
    id
}

/// Base-auth hardening 2.4 (F10): an invitation is stored under the normalized
/// email, the same form registration and login match against.
#[tokio::test]
async fn issue_in_tx_stores_the_normalized_email() {
    let db = skip_if_no_db!(pool().await);
    let normalized = format!("invite-normalize-{}@example.invalid", Uuid::now_v7());
    let typed = format!("  {}  ", normalized.to_uppercase());
    let admin_id = create_test_admin(&db).await;

    let mut tx = db.begin().await.expect("begin tx");
    let issued = issue_in_tx(&mut tx, &typed, admin_id, 24, &test_ring())
        .await
        .expect("issue_in_tx must succeed");
    tx.commit().await.expect("commit");

    assert_eq!(issued.email, normalized);
    assert_eq!(
        invitation_token_count(&db, &normalized).await,
        1,
        "the invitation row must be stored under the normalized email"
    );
}

/// Happy path: `issue_in_tx` + `enqueue_in_tx` on one transaction, committed
/// together, both become visible — the invitation row and a queued
/// `apalis.jobs` row.
#[tokio::test]
async fn commit_makes_both_the_invitation_and_its_email_job_visible() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("invite-commit-{}@example.invalid", Uuid::now_v7());

    let pending_before = email_jobs_for(&db, &email).await;
    let admin_id = create_test_admin(&db).await;

    let mut tx = db.begin().await.expect("begin tx");
    let issued = issue_in_tx(&mut tx, &email, admin_id, 24, &test_ring())
        .await
        .expect("issue_in_tx must succeed");
    attome_jobs::enqueue_in_tx(&mut tx, dummy_email_job(&issued.email))
        .await
        .expect("enqueue_in_tx must succeed");
    tx.commit().await.expect("commit");

    assert_eq!(
        invitation_token_count(&db, &email).await,
        1,
        "committed invitation row must be visible"
    );
    let pending_after = email_jobs_for(&db, &email).await;
    assert_eq!(
        pending_after,
        pending_before + 1,
        "committed email job must be visible in apalis.jobs"
    );
}

/// The regression this fix closes, proven directly: if the transaction never
/// commits (standing in for "the enqueue step failed"), the invitation row
/// must NOT exist either — a caller can never observe a minted invitation
/// whose email job did not also survive, in either direction. This is what
/// distinguishes the fix from the old code, which committed the invitation
/// unconditionally and only logged an enqueue failure after the fact.
#[tokio::test]
async fn a_rolled_back_transaction_leaves_neither_the_invitation_nor_its_email_job() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("invite-rollback-{}@example.invalid", Uuid::now_v7());

    let pending_before = email_jobs_for(&db, &email).await;
    let admin_id = create_test_admin(&db).await;

    let mut tx = db.begin().await.expect("begin tx");
    let issued = issue_in_tx(&mut tx, &email, admin_id, 24, &test_ring())
        .await
        .expect("issue_in_tx must succeed inside the still-open tx");
    attome_jobs::enqueue_in_tx(&mut tx, dummy_email_job(&issued.email))
        .await
        .expect("enqueue_in_tx must succeed inside the still-open tx");
    tx.rollback().await.expect("rollback");

    assert_eq!(
        invitation_token_count(&db, &email).await,
        0,
        "a rolled-back invitation row must not be visible"
    );
    let pending_after = email_jobs_for(&db, &email).await;
    assert_eq!(
        pending_after, pending_before,
        "a rolled-back email job must not be visible in apalis.jobs"
    );
}
