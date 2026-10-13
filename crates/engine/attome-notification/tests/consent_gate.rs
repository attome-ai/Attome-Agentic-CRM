//! Integration test for the M24/D-428 consent-enforcement seam
//! (`attome_notification::consent_gate`, wired into
//! `dispatch::create_dispatch`'s email-channel decision). Covers the real
//! behavior the pure logic in `consent_gate.rs` can't exercise on its own —
//! a live `audit_consent`/`audit_consent_purpose` fixture (provisioned via the
//! real `attome_compliance::consent_seed::seed`, not a hand-duplicated schema)
//! and the actual `SendEmail` job (not-)enqueued.
//!
//! Requires a live Postgres (`DATABASE_URL`), same convention as
//! `tests/dispatch.rs`:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-notification --test consent_gate -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::collections::HashMap;

use attome_config::NotificationSection;
use attome_db::DbPool;
use attome_notification::dispatch::{DispatchRequest, create_dispatch};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn notification_cfg() -> NotificationSection {
    NotificationSection::default()
}

fn base_request() -> DispatchRequest {
    DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: None,
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: None,
        body_html: None,
        body_text: None,
        route: None,
        variables: HashMap::new(),
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    }
}

async fn insert_active_user_with_email(db: &DbPool, email: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, is_active) VALUES ($1, $2, TRUE)")
        .bind(id)
        .bind(email)
        .execute(db)
        .await
        .expect("insert test user");
    id
}

async fn insert_purpose(db: &DbPool, key: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO audit_consent_purpose (key, lawful_basis, is_active) \
         VALUES ($1, 'consent', TRUE) RETURNING id",
    )
    .bind(key)
    .fetch_one(db)
    .await
    .expect("insert test consent purpose")
}

async fn insert_consent(
    db: &DbPool,
    purpose_id: Uuid,
    regarding_entity: &str,
    regarding_id: &str,
    status: &str,
) {
    let (extra_col, extra_expr) = if status == "withdrawn" {
        ("withdrawn_at", "NOW()")
    } else {
        ("granted_at", "NOW()")
    };
    sqlx::query(&format!(
        "INSERT INTO audit_consent \
             (purpose_ref, regarding_entity, regarding_id, subject_reference, status, \
              {extra_col}, source) \
         VALUES ($1, $2, $3, $4, $5, {extra_expr}, 'api')"
    ))
    .bind(purpose_id)
    .bind(regarding_entity)
    .bind(regarding_id)
    .bind(format!("{regarding_id}@test.invalid"))
    .bind(status)
    .execute(db)
    .await
    .expect("insert test consent row");
}

async fn insert_template(db: &DbPool, template_key: &str, consent_purpose_key: &str) {
    sqlx::query(
        "INSERT INTO notification_template \
             (template_key, locale, subject, body_text, default_channels, \
              consent_purpose_key, is_active) \
         VALUES ($1, 'en', 'Test subject', 'Test body', 'email', $2, TRUE)",
    )
    .bind(template_key)
    .bind(consent_purpose_key)
    .execute(db)
    .await
    .expect("insert test template");
}

async fn send_email_job_count(db: &DbPool, dedup_key: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs \
         WHERE job_type = 'attome_job' AND job->>'variant' = 'SendEmail' \
           AND dedup_key = $1",
    )
    .bind(dedup_key)
    .fetch_one(db)
    .await
    .expect("query apalis.jobs")
}

async fn email_outcome(db: &DbPool, dispatch_id: Uuid) -> String {
    let outcomes: serde_json::Value =
        sqlx::query_scalar("SELECT channel_outcomes FROM notification_dispatch WHERE id = $1")
            .bind(dispatch_id)
            .fetch_one(db)
            .await
            .expect("dispatch row must exist");
    outcomes["email"]
        .as_str()
        .expect("email outcome must be present")
        .to_string()
}

#[tokio::test]
async fn a_recipient_with_an_active_consent_gets_the_email_sent() {
    let db = skip_if_no_db!(test_db().await);
    attome_notification::seed::seed(&db).await.expect("seed");
    attome_compliance::consent_seed::seed(&db)
        .await
        .expect("seed consent entities");

    let template_key = format!("m24-consent-{}", Uuid::now_v7());
    let purpose_key = format!("marketing-{}", Uuid::now_v7());
    let purpose_id = insert_purpose(&db, &purpose_key).await;
    insert_template(&db, &template_key, &purpose_key).await;

    let email = format!("m24-consent-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;
    insert_consent(
        &db,
        purpose_id,
        "user_account",
        &user_id.to_string(),
        "granted",
    )
    .await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.template_key = Some(template_key);
    req.channels = Some(vec!["email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("dispatch to a consented recipient must be created");

    assert_eq!(email_outcome(&db, dispatch_id).await, "sent");
    let dedup_key = format!("{dispatch_id}:{user_id}");
    assert_eq!(
        send_email_job_count(&db, &dedup_key).await,
        1,
        "a consented recipient's email must actually be enqueued"
    );
}

/// The headline negative test: a withdrawn consent (a NEW row appended
/// after the grant — D-428) must block a subsequent marketing-channel send,
/// and must never enqueue a `SendEmail` job for it.
#[tokio::test]
async fn a_withdrawn_consent_blocks_the_marketing_send() {
    let db = skip_if_no_db!(test_db().await);
    attome_notification::seed::seed(&db).await.expect("seed");
    attome_compliance::consent_seed::seed(&db)
        .await
        .expect("seed consent entities");

    let template_key = format!("m24-withdrawn-{}", Uuid::now_v7());
    let purpose_key = format!("marketing-{}", Uuid::now_v7());
    let purpose_id = insert_purpose(&db, &purpose_key).await;
    insert_template(&db, &template_key, &purpose_key).await;

    let email = format!("m24-withdrawn-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;
    insert_consent(
        &db,
        purpose_id,
        "user_account",
        &user_id.to_string(),
        "granted",
    )
    .await;
    // D-428: the withdrawal is a second, later row — never an UPDATE of the
    // grant above.
    insert_consent(
        &db,
        purpose_id,
        "user_account",
        &user_id.to_string(),
        "withdrawn",
    )
    .await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.template_key = Some(template_key);
    req.channels = Some(vec!["email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("the dispatch itself must still be created (the block is per-channel)");

    assert_eq!(
        email_outcome(&db, dispatch_id).await,
        "consent_blocked",
        "operators must be able to see why the email did not go out"
    );
    let dedup_key = format!("{dispatch_id}:{user_id}");
    assert_eq!(
        send_email_job_count(&db, &dedup_key).await,
        0,
        "a withdrawn consent must never enqueue a SendEmail job"
    );

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_consent WHERE purpose_ref = $1")
            .bind(purpose_id)
            .fetch_one(&db)
            .await
            .expect("count consent rows");
    assert_eq!(
        row_count, 2,
        "withdrawal must be a second row, not an update of the grant"
    );
}

#[tokio::test]
async fn a_recipient_with_no_consent_at_all_is_blocked() {
    let db = skip_if_no_db!(test_db().await);
    attome_notification::seed::seed(&db).await.expect("seed");
    attome_compliance::consent_seed::seed(&db)
        .await
        .expect("seed consent entities");

    let template_key = format!("m24-none-{}", Uuid::now_v7());
    let purpose_key = format!("marketing-{}", Uuid::now_v7());
    insert_purpose(&db, &purpose_key).await;
    insert_template(&db, &template_key, &purpose_key).await;

    let email = format!("m24-none-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;
    // No audit_consent row at all for this recipient/purpose.

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.template_key = Some(template_key);
    req.channels = Some(vec!["email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("dispatch must still be created");

    assert_eq!(
        email_outcome(&db, dispatch_id).await,
        "consent_blocked",
        "absence of any consent row must fail closed, same as a withdrawn one"
    );
}

/// A template with no `consent_purpose_key` is unaffected — the gate is
/// opt-in per template, not a blanket new requirement on every send.
#[tokio::test]
async fn a_template_without_a_consent_purpose_key_is_unaffected() {
    let db = skip_if_no_db!(test_db().await);
    attome_notification::seed::seed(&db).await.expect("seed");

    let email = format!("m24-no-gate-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.subject = Some("Test subject".to_string());
    req.body_text = Some("Test body".to_string());
    req.channels = Some(vec!["email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("an ungated dispatch must be created");

    assert_eq!(email_outcome(&db, dispatch_id).await, "sent");
}
