//! Integration tests for `attome_notification::dispatch::create_dispatch` — the
//! request-path entry point of the Notification Engine's durable dispatch
//! queue (F163/F164). Covers the real-Postgres behavior the pure unit tests
//! in `src/dispatch.rs` can't reach: audience validation against
//! `user_account`, the `notification_dispatch`/`notification_recipient`
//! writes, and template lookup once the template entity is provisioned.
//!
//! Requires a live Postgres (`DATABASE_URL`) with the platform's migrations
//! already applied — same convention as `attome-metadata/tests/provision.rs` and
//! `attome-db/tests/tx.rs`. **Live-verified against a real Postgres
//! (2026-08-03):** all 5 tests pass. Run manually against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-notification --test dispatch -- --test-threads=1
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

use attome_testkit::skip_if_no_db;
use std::collections::HashMap;

use attome_config::NotificationSection;
use attome_db::DbPool;
use attome_notification::dispatch::{DispatchRequest, create_dispatch, create_dispatch_in_tx};
use attome_types::AppError;
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

/// `email_from` unset -> the email channel (when exercised) falls back to
/// `config.email`'s own from-address, same as every other test config.
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
        subject: Some("Test subject".to_string()),
        body_html: None,
        body_text: Some("Test body".to_string()),
        route: None,
        variables: HashMap::new(),
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    }
}

async fn insert_active_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, is_active) VALUES ($1, $2, TRUE)")
        .bind(id)
        .bind(format!("{id}@test.invalid"))
        .execute(db)
        .await
        .expect("insert test user");
    id
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

/// Counts the `SendEmail` jobs apalis has queued (fast queue, `job_type =
/// 'attome_job'`) under this exact dedup key -- the same
/// `"{dispatch_id}:{recipient_id}"` shape `create_dispatch` enqueues with.
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

#[tokio::test]
async fn rejects_a_dispatch_with_no_audience() {
    let db = skip_if_no_db!(test_db().await);

    let err = create_dispatch(&db, &notification_cfg(), base_request())
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(_)),
        "expected a validation error, got {err:?}"
    );
}

#[tokio::test]
async fn rejects_a_dispatch_with_more_than_one_audience() {
    let db = skip_if_no_db!(test_db().await);
    let mut req = base_request();
    req.recipient_user_ref = Some(Uuid::now_v7());
    req.is_global = true;

    let err = create_dispatch(&db, &notification_cfg(), req)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(_)),
        "exactly one audience field is required, got {err:?}"
    );
}

#[tokio::test]
async fn rejects_a_recipient_that_is_not_a_known_active_user() {
    let db = skip_if_no_db!(test_db().await);
    let mut req = base_request();
    req.recipient_user_ref = Some(Uuid::now_v7()); // no such user exists

    let err = create_dispatch(&db, &notification_cfg(), req)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(_)),
        "an unknown/inactive recipient must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn persists_a_direct_dispatch_and_materializes_an_in_app_recipient_row() {
    let db = skip_if_no_db!(test_db().await);
    let user_id = insert_active_user(&db).await;
    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.body_text = Some("Hello {{name}}".to_string());
    req.variables.insert("name".to_string(), "Ada".to_string());

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("a valid direct dispatch must be created");

    let (body_text, status): (String, String) =
        sqlx::query_as("SELECT body_text, status FROM notification_dispatch WHERE id = $1")
            .bind(dispatch_id)
            .fetch_one(&db)
            .await
            .expect("dispatch row must exist");
    assert_eq!(
        body_text, "Hello Ada",
        "template variables must be applied before persisting"
    );
    assert_eq!(status, "pending");

    let recipient_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_recipient WHERE dispatch_ref = $1 AND user_ref = $2",
    )
    .bind(dispatch_id)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .expect("query recipient rows");
    assert_eq!(
        recipient_count, 1,
        "a direct in_app dispatch must materialize exactly one recipient row synchronously"
    );
}

#[tokio::test]
async fn rejects_an_unknown_template_key_once_the_template_entity_is_provisioned() {
    let db = skip_if_no_db!(test_db().await);
    attome_notification::seed::seed(&db)
        .await
        .expect("seeding the notification-template entity must be idempotent");

    let mut req = base_request();
    req.recipient_user_ref = Some(Uuid::now_v7());
    req.body_text = None;
    req.template_key = Some(format!("does-not-exist-{}", Uuid::now_v7()));

    let err = create_dispatch(&db, &notification_cfg(), req)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(_)),
        "an unrecognized template_key must be rejected, got {err:?}"
    );
}

// ── M51 Phase 1 (email wiring) ──────────────────────────────────────────────

#[tokio::test]
async fn dispatch_with_email_channel_enqueues_exactly_one_send_email_job() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("m51-email-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.channels = Some(vec!["in_app".to_string(), "email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("a direct dispatch requesting email must be created");

    let dedup_key = format!("{dispatch_id}:{user_id}");
    assert_eq!(
        send_email_job_count(&db, &dedup_key).await,
        1,
        "exactly one SendEmail job must be enqueued for this dispatch/recipient pair"
    );

    let (channels_sent, channel_outcomes): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT channels_sent, channel_outcomes FROM notification_dispatch WHERE id = $1",
    )
    .bind(dispatch_id)
    .fetch_one(&db)
    .await
    .expect("dispatch row must exist");
    let sent: Vec<String> = serde_json::from_value(channels_sent).unwrap();
    assert!(sent.contains(&"in_app".to_string()));
    assert!(sent.contains(&"email".to_string()));
    assert_eq!(channel_outcomes["email"], "sent");

    // A tracking row must exist and be linked back to this dispatch (M51
    // Phase 1's traceability FK).
    let (status, dispatch_ref): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, dispatch_ref FROM email_delivery \
         WHERE recipient = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(attome_types::text::normalize_email(&email))
    .fetch_one(&db)
    .await
    .expect("an email_delivery tracking row must exist");
    assert_eq!(status, "queued");
    assert_eq!(dispatch_ref, Some(dispatch_id));
}

#[tokio::test]
async fn dispatch_email_is_idempotent_under_a_retried_enqueue() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("m51-email-dedup-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.channels = Some(vec!["email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("dispatch must be created");
    let dedup_key = format!("{dispatch_id}:{user_id}");

    // Simulate a caller retrying the exact same enqueue (e.g. a crashed
    // worker re-processing the identical dedup key) -- must be a no-op, not
    // a second SMTP attempt.
    let mut tx = db.begin().await.unwrap();
    let inserted = attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: email.clone(),
            subject: "Test subject".to_string(),
            text_body: "Test body".to_string(),
            html_body: None,
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
            stream: Default::default(),
        })),
        &dedup_key,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert!(
        !inserted,
        "a retried enqueue under the same dedup key must be a no-op"
    );
    assert_eq!(send_email_job_count(&db, &dedup_key).await, 1);
}

#[tokio::test]
async fn a_suppressed_address_gets_in_app_only() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("m51-suppressed-{}@test.invalid", Uuid::now_v7());
    let user_id = insert_active_user_with_email(&db, &email).await;
    attome_email::suppression::suppress(
        &db,
        &email,
        attome_email::suppression::SuppressionReason::AdminManual,
        Some("test fixture"),
        None,
    )
    .await
    .expect("suppress the address");

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.channels = Some(vec!["in_app".to_string(), "email".to_string()]);

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("a dispatch to a suppressed address must still be created");

    let (channels_sent, channel_outcomes): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT channels_sent, channel_outcomes FROM notification_dispatch WHERE id = $1",
    )
    .bind(dispatch_id)
    .fetch_one(&db)
    .await
    .expect("dispatch row must exist");
    let sent: Vec<String> = serde_json::from_value(channels_sent).unwrap();
    assert!(sent.contains(&"in_app".to_string()));
    assert!(
        sent.contains(&"email".to_string()),
        "a suppressed email is a resolved (terminal) outcome, not a pending retry"
    );
    assert_eq!(
        channel_outcomes["email"], "suppressed",
        "operators must be able to see why the email did not go out"
    );

    let recipient_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_recipient WHERE dispatch_ref = $1 AND user_ref = $2",
    )
    .bind(dispatch_id)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(recipient_count, 1, "in-app delivery must still happen");

    let dedup_key = format!("{dispatch_id}:{user_id}");
    assert_eq!(
        send_email_job_count(&db, &dedup_key).await,
        0,
        "a suppressed address must never enqueue a SendEmail job"
    );
}

#[tokio::test]
async fn body_html_without_body_text_derives_a_plain_text_fallback() {
    let db = skip_if_no_db!(test_db().await);
    let user_id = insert_active_user(&db).await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.body_text = None;
    req.body_html = Some("<p>Hello <b>Ada</b>,</p><p>You have a task.</p>".to_string());

    let dispatch_id = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("html-only content must still produce a valid dispatch");

    let body_text: String =
        sqlx::query_scalar("SELECT body_text FROM notification_dispatch WHERE id = $1")
            .bind(dispatch_id)
            .fetch_one(&db)
            .await
            .expect("dispatch row must exist");
    assert_eq!(body_text, "Hello Ada,\nYou have a task.");
}

// ── U5 / D-602: notification preferences (B-R5) ─────────────────────────────

/// A mute row, written directly: the route that normally writes it is tested
/// in `attome-api/tests/reminders_preferences.rs`.
async fn mute(db: &DbPool, user_id: Uuid, category: &str, channel: &str) {
    sqlx::query(
        "INSERT INTO notification_preference (user_ref, category, channel, enabled) \
         VALUES ($1, $2, $3, FALSE)",
    )
    .bind(user_id)
    .bind(category)
    .bind(channel)
    .execute(db)
    .await
    .expect("insert mute");
}

async fn insert_template(db: &DbPool, template_key: &str, is_mandatory: bool) {
    sqlx::query(
        "INSERT INTO notification_template \
             (template_key, locale, subject, body_text, default_channels, is_mandatory, is_active) \
         VALUES ($1, 'en', 'Template subject', 'Template body', 'in_app,email', $2, TRUE)",
    )
    .bind(template_key)
    .bind(is_mandatory)
    .execute(db)
    .await
    .expect("insert test template");
}

async fn dispatch_channels(db: &DbPool, dispatch_id: Uuid) -> (Vec<String>, serde_json::Value) {
    let (channels, outcomes): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT channels, channel_outcomes FROM notification_dispatch WHERE id = $1",
    )
    .bind(dispatch_id)
    .fetch_one(db)
    .await
    .expect("dispatch row");
    (serde_json::from_value(channels).unwrap(), outcomes)
}

async fn create_in_tx(db: &DbPool, req: DispatchRequest, category: Option<&str>) -> Uuid {
    let mut tx = db.begin().await.expect("begin");
    let id = create_dispatch_in_tx(&mut tx, &notification_cfg(), req, category)
        .await
        .expect("create_dispatch_in_tx");
    tx.commit().await.expect("commit");
    id
}

#[tokio::test]
async fn a_muted_channel_is_skipped_and_recorded_as_muted() {
    let db = skip_if_no_db!(test_db().await);
    let user_id = insert_active_user(&db).await;
    mute(&db, user_id, "reminder", "email").await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    let dispatch_id = create_in_tx(&db, req, Some("reminder")).await;

    let (channels, outcomes) = dispatch_channels(&db, dispatch_id).await;
    assert_eq!(channels, vec!["in_app".to_string()], "email was muted");
    assert_eq!(outcomes["email"], "muted");
    assert_eq!(
        send_email_job_count(&db, &format!("{dispatch_id}:{user_id}")).await,
        0,
        "a muted email channel must never be enqueued"
    );
    let recipient_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_recipient WHERE dispatch_ref = $1")
            .bind(dispatch_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(recipient_rows, 1, "the in-app channel was not muted");
}

#[tokio::test]
async fn a_mute_under_another_category_changes_nothing() {
    let db = skip_if_no_db!(test_db().await);
    let user_id = insert_active_user(&db).await;
    mute(&db, user_id, "reminder", "email").await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    // No category and no template key: preferences do not apply at all.
    let uncategorized = create_in_tx(&db, req, None).await;
    let (channels, _) = dispatch_channels(&db, uncategorized).await;
    assert_eq!(channels, vec!["in_app".to_string(), "email".to_string()]);
}

#[tokio::test]
async fn a_mandatory_template_ignores_a_stored_mute() {
    let db = skip_if_no_db!(test_db().await);
    attome_notification::seed::seed(&db).await.expect("seed");
    let user_id = insert_active_user(&db).await;

    let mandatory = format!("tpl-mandatory-{}", Uuid::now_v7().simple());
    let ordinary = format!("tpl-ordinary-{}", Uuid::now_v7().simple());
    insert_template(&db, &mandatory, true).await;
    insert_template(&db, &ordinary, false).await;
    mute(&db, user_id, &mandatory, "email").await;
    mute(&db, user_id, &ordinary, "email").await;

    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.template_key = Some(mandatory.clone());
    let kept = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("mandatory dispatch");
    let (channels, outcomes) = dispatch_channels(&db, kept).await;
    assert!(
        channels.contains(&"email".to_string()),
        "a mandatory template ignores the mute: {channels:?}"
    );
    assert_ne!(outcomes["email"], "muted");
    let category: Option<String> =
        sqlx::query_scalar("SELECT preference_category FROM notification_dispatch WHERE id = $1")
            .bind(kept)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        category, None,
        "a mandatory dispatch carries no preference category"
    );

    // Control: the same mute on an ordinary template is honoured, under the
    // template key as the category.
    let mut req = base_request();
    req.recipient_user_ref = Some(user_id);
    req.template_key = Some(ordinary.clone());
    let muted = create_dispatch(&db, &notification_cfg(), req)
        .await
        .expect("ordinary dispatch");
    let (channels, outcomes) = dispatch_channels(&db, muted).await;
    assert_eq!(channels, vec!["in_app".to_string()]);
    assert_eq!(outcomes["email"], "muted");
}

#[tokio::test]
async fn organization_fan_out_skips_a_user_who_muted_in_app() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let mut users = Vec::new();
    for _ in 0..2 {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_account (id, email, organization_ref, is_active) \
             VALUES ($1, $2, $3, TRUE)",
        )
        .bind(id)
        .bind(format!("{id}@test.invalid"))
        .bind(org)
        .execute(&db)
        .await
        .expect("insert org user");
        users.push(id);
    }
    mute(&db, users[0], "reminder", "in_app").await;

    let mut req = base_request();
    req.organization_ref = Some(org);
    req.channels = Some(vec!["in_app".to_string()]);
    let dispatch_id = create_in_tx(&db, req, Some("reminder")).await;
    attome_notification::recipient::fan_out_notification(&db, dispatch_id)
        .await
        .expect("fan out");

    let recipients: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_ref FROM notification_recipient WHERE dispatch_ref = $1")
            .bind(dispatch_id)
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(
        recipients,
        vec![users[1]],
        "only the user who did not mute in_app"
    );
}
