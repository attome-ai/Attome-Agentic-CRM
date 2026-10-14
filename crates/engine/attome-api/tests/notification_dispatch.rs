//! Notification Engine (P2.11) money-path test — D-010's "integration tests
//! for the engine's money path" requirement. License-gating coverage for
//! `NotificationModel` lives alongside the other module-gating tests in
//! `tests/license_gating.rs`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) with migrations already applied —
//! same convention as every other test in this directory. Run manually
//! against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test notification_dispatch -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::EngineState;
use attome_notification::NotificationInbox;
use attome_notification::dispatch::{self, DispatchRequest};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

fn test_config() -> attome_config::AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "enabled": false,
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// A bare `EngineState` (NoopNotifications, degraded license, empty registry) —
/// enough to exercise `attome_notification::dispatch` directly without paying
/// for `EngineSystem::builder().build()`'s registry pre-warm / Redis pub/sub
/// subscriptions, which this test doesn't need.
async fn test_state() -> Option<EngineState> {
    attome_testkit::migrated_db_url()?;
    let config = test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis");
    let redis_coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build storage client");
    let db_readonly = db.clone();
    let db_migrator = db.clone();
    let base = AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    );
    Some(EngineState::new(base))
}

/// `label` is a readable prefix, not the literal address: every caller's
/// address gets a per-run UUID suffix here, in the one place that cannot be
/// forgotten at a call site.
///
/// `user_account` has a unique index on `email`
/// (`core_systemuser_email_unique`), so the hardcoded
/// `notif-money-path@example.invalid`-style literals these callers used to
/// pass made this suite pass once against a fresh database and fail 8× on
/// every rerun — the throwaway Postgres is a persistent container, not a
/// per-run volume (F-006/TODO-008(c)).
async fn seed_user_with_email(db: &attome_db::DbPool, label: &str) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("notif-test-{user_id}"))
    .bind(attome_testkit::unique_email(label))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    user_id
}

/// `label` is a readable prefix, not the literal address — see
/// [`seed_user_with_email`] for why.
async fn seed_user_in_org(
    db: &attome_db::DbPool,
    label: &str,
    organization_ref: Option<Uuid>,
) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account \
             (id, user_name, email, organization_ref, is_active) \
         VALUES ($1, $2, $3, $4, true)",
    )
    .bind(user_id)
    .bind(format!("notif-test-{user_id}"))
    .bind(attome_testkit::unique_email(label))
    .bind(organization_ref)
    .execute(db)
    .await
    .expect("insert throwaway organization user");
    user_id
}

/// Money path: dispatch an in-app notification, run the poller's batch
/// processor once, and confirm it landed in the per-user recipient inbox with
/// the dispatch row marked `sent` (F163).
#[tokio::test]
async fn dispatch_delivers_in_app_channel_and_marks_sent() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user_with_email(&state.base.db, "notif-money-path").await;

    let dispatch_id = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Money path test".to_string()),
            body_html: None,
            body_text: Some("hello from the money-path test".to_string()),
            route: Some("/some/route".to_string()),
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create_dispatch");

    dispatch::run_pending_batch(&state, 10).await;

    let (status, channels_sent): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, channels_sent FROM notification_dispatch WHERE id = $1")
            .bind(dispatch_id)
            .fetch_one(&state.base.db)
            .await
            .expect("fetch dispatch row");

    assert_eq!(
        status, "sent",
        "dispatch should be fully sent (in_app only)"
    );
    let sent: Vec<String> = serde_json::from_value(channels_sent).unwrap();
    assert_eq!(sent, vec!["in_app".to_string()]);
    let (title, message): (Option<String>, String) = sqlx::query_as(
        "SELECT title, message FROM notification_recipient \
         WHERE dispatch_ref = $1 AND user_ref = $2",
    )
    .bind(dispatch_id)
    .bind(user_id)
    .fetch_one(&state.base.db)
    .await
    .expect("fetch recipient row");

    assert_eq!(title.as_deref(), Some("Money path test"));
    assert_eq!(message, "hello from the money-path test");
}

/// F164 — template-based, bilingual notifications: dispatch by
/// `template_key`/`locale` instead of inline content, and confirm the
/// dispatch row was rendered from the template row rather than left blank.
#[tokio::test]
async fn dispatch_renders_from_template_by_locale() {
    let state = skip_if_no_db!(test_state().await);
    attome_notification::seed::seed(&state.base.db)
        .await
        .expect("seed notification_template entity");

    let user_id = seed_user_with_email(&state.base.db, "notif-template-test").await;
    let template_key = format!("test-template-{}", Uuid::now_v7());

    sqlx::query(
        "INSERT INTO notification_template \
             (id, template_key, locale, subject, body_text, default_channels, is_active) \
         VALUES (uuidv7(), $1, 'en', $2, $3, 'in_app', true)",
    )
    .bind(&template_key)
    .bind("Hello {{name}}")
    .bind("Welcome, {{name}}!")
    .execute(&state.base.db)
    .await
    .expect("insert test template row");

    let mut variables = std::collections::HashMap::new();
    variables.insert("name".to_string(), "Ada".to_string());

    let dispatch_id = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: Some(template_key),
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None, // resolved from the template's default_channels
            subject: None,
            body_html: None,
            body_text: None,
            route: None,
            variables,
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create_dispatch from template");

    let (subject, body_text, channels): (Option<String>, String, serde_json::Value) =
        sqlx::query_as(
            "SELECT subject, body_text, channels FROM notification_dispatch WHERE id = $1",
        )
        .bind(dispatch_id)
        .fetch_one(&state.base.db)
        .await
        .expect("fetch dispatch row");

    assert_eq!(subject.as_deref(), Some("Hello Ada"));
    assert_eq!(body_text, "Welcome, Ada!");
    let channels: Vec<String> = serde_json::from_value(channels).unwrap();
    assert_eq!(channels, vec!["in_app".to_string()]);
}

/// A worker can die after claiming a row but before `finish_dispatch` runs.
/// The next poller pass must reclaim that stale processing row and deliver it.
#[tokio::test]
async fn stale_processing_dispatch_is_reclaimed_and_delivered() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user_with_email(&state.base.db, "notif-stale-processing").await;

    let dispatch_id = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Stale processing test".to_string()),
            body_html: None,
            body_text: Some("reclaim this dispatch".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create_dispatch");

    // Simulate the durable state left by a worker crash after claim and before
    // finish_dispatch. The recovery path must treat this as stale work.
    sqlx::query(
        "UPDATE notification_dispatch \
         SET status = 'processing', attempts = 1, updated_at = NOW() - INTERVAL '6 minutes' \
         WHERE id = $1",
    )
    .bind(dispatch_id)
    .execute(&state.base.db)
    .await
    .expect("mark dispatch as stale processing");

    dispatch::run_pending_batch(&state, 10).await;

    let (status, attempts, recipient_count): (String, i32, i64) = sqlx::query_as(
        "SELECT status, attempts, COUNT(*) \
         FROM notification_dispatch d \
         JOIN notification_recipient r ON r.dispatch_ref = d.id \
         WHERE d.id = $1 GROUP BY status, attempts",
    )
    .bind(dispatch_id)
    .fetch_one(&state.base.db)
    .await
    .expect("fetch reclaimed dispatch row");

    assert_eq!(status, "sent");
    assert_eq!(
        attempts, 2,
        "reclaim must count as the next processing attempt"
    );
    assert_eq!(
        recipient_count, 1,
        "reclaimed in_app dispatch must be delivered"
    );
}

/// Escalation progress survives a failed later channel and a stale claim.
/// The escalation is not marked complete until every requested channel sends.
#[tokio::test]
async fn escalation_retries_unsent_channels_before_marking_complete() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user_with_email(&state.base.db, "notif-escalation-recovery").await;

    let dispatch_id = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Escalation recovery test".to_string()),
            body_html: None,
            body_text: Some("escalate this dispatch".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: Some(1),
            escalate_channels: Some(vec!["in_app".to_string(), "email".to_string()]),
        },
    )
    .await
    .expect("create_dispatch");

    dispatch::run_pending_batch(&state, 10).await;
    sqlx::query(
        "UPDATE notification_dispatch \
         SET dispatched_at = NOW() - INTERVAL '10 minutes' \
         WHERE id = $1",
    )
    .bind(dispatch_id)
    .execute(&state.base.db)
    .await
    .expect("backdate dispatch for escalation");

    dispatch::run_due_escalations(&state, 10).await;

    let (status, escalated_at, escalation_channels_sent): (
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT status, escalated_at, escalation_channels_sent \
             FROM notification_dispatch WHERE id = $1",
    )
    .bind(dispatch_id)
    .fetch_one(&state.base.db)
    .await
    .expect("fetch partial escalation");

    assert_eq!(status, "escalated");
    assert!(
        escalated_at.is_none(),
        "failed escalation must remain incomplete"
    );
    let sent: Vec<String> = serde_json::from_value(escalation_channels_sent).unwrap();
    assert_eq!(sent, vec!["in_app".to_string()]);

    sqlx::query(
        "UPDATE notification_dispatch \
         SET updated_at = NOW() - INTERVAL '6 minutes' \
         WHERE id = $1",
    )
    .bind(dispatch_id)
    .execute(&state.base.db)
    .await
    .expect("backdate escalation claim");

    dispatch::run_due_escalations(&state, 10).await;

    let (escalated_at, escalation_channels_sent): (
        Option<chrono::DateTime<chrono::Utc>>,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT escalated_at, escalation_channels_sent \
             FROM notification_dispatch WHERE id = $1",
    )
    .bind(dispatch_id)
    .fetch_one(&state.base.db)
    .await
    .expect("fetch reclaimed escalation");

    assert!(escalated_at.is_none());
    let sent: Vec<String> = serde_json::from_value(escalation_channels_sent).unwrap();
    assert_eq!(sent, vec!["in_app".to_string()]);
}

#[tokio::test]
async fn recipient_inbox_is_scoped_to_user_not_organization() {
    let state = skip_if_no_db!(test_state().await);
    let org = Uuid::now_v7();
    let other_org = Uuid::now_v7();
    let user_a = seed_user_in_org(&state.base.db, "notif-scope-a", Some(org)).await;
    let user_b = seed_user_in_org(&state.base.db, "notif-scope-b", Some(org)).await;
    let user_c = seed_user_in_org(&state.base.db, "notif-scope-c", Some(other_org)).await;
    let user_d = seed_user_in_org(&state.base.db, "notif-scope-d", None).await;

    let org_dispatch = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: None,
            is_global: false,
            organization_ref: Some(org),
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Organization notice".to_string()),
            body_html: None,
            body_text: Some("Only this organization".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create organization dispatch");
    attome_notification::recipient::fan_out_notification(&state.base.db, org_dispatch)
        .await
        .expect("fan out organization dispatch");
    attome_notification::recipient::fan_out_notification(&state.base.db, org_dispatch)
        .await
        .expect("re-run organization fan out");

    let recipient_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_recipient WHERE dispatch_ref = $1")
            .bind(org_dispatch)
            .fetch_one(&state.base.db)
            .await
            .expect("count recipient rows");
    assert_eq!(recipient_rows, 2, "fan-out retry must be idempotent");

    let inbox = NotificationInbox::new(&state.base.db);
    let (rows_a, unread_a) = inbox.poll(user_a, 50).await.expect("poll user A");
    let (rows_b, unread_b) = inbox.poll(user_b, 50).await.expect("poll user B");
    let (rows_c, unread_c) = inbox.poll(user_c, 50).await.expect("poll user C");
    let (rows_d, unread_d) = inbox.poll(user_d, 50).await.expect("poll user D");
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_c.len(), 0);
    assert_eq!(rows_d.len(), 0);
    assert_eq!(unread_a, 1);
    assert_eq!(unread_b, 1);
    assert_eq!(unread_c, 0);
    assert_eq!(unread_d, 0);

    inbox
        .mark_read(user_a, rows_a[0].id)
        .await
        .expect("mark user A read");
    let (_, unread_a_after) = inbox.poll(user_a, 50).await.expect("re-poll user A");
    let (_, unread_b_after) = inbox.poll(user_b, 50).await.expect("re-poll user B");
    assert_eq!(unread_a_after, 0);
    assert_eq!(
        unread_b_after, 1,
        "user A read state must not affect user B"
    );

    inbox.clear(user_a).await.expect("clear user A inbox");
    let (_, unread_b_after_clear) = inbox.poll(user_b, 50).await.expect("re-poll user B");
    assert_eq!(
        unread_b_after_clear, 1,
        "user A clear must not affect user B"
    );

    let global_dispatch = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: None,
            is_global: true,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Global notice".to_string()),
            body_html: None,
            body_text: Some("Everyone can see this".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create global dispatch");
    attome_notification::recipient::fan_out_notification(&state.base.db, global_dispatch)
        .await
        .expect("fan out global dispatch");

    let (rows_c, _) = inbox.poll(user_c, 50).await.expect("poll global for C");
    let (rows_d, _) = inbox.poll(user_d, 50).await.expect("poll global for D");
    assert_eq!(rows_c.len(), 1);
    assert_eq!(rows_d.len(), 1);
}

#[tokio::test]
async fn direct_notification_does_not_reach_another_orgless_user() {
    let state = skip_if_no_db!(test_state().await);
    let user_a = seed_user_with_email(&state.base.db, "notif-direct-a").await;
    let user_b = seed_user_with_email(&state.base.db, "notif-direct-b").await;

    let dispatch_id = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_a),
            is_global: false,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Private notice".to_string()),
            body_html: None,
            body_text: Some("Only user A".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create direct dispatch");

    let inbox = NotificationInbox::new(&state.base.db);
    let (rows_a, unread_a) = inbox.poll(user_a, 50).await.expect("poll direct recipient");
    let (rows_b, unread_b) = inbox
        .poll(user_b, 50)
        .await
        .expect("poll other orgless user");
    assert_eq!(rows_a.len(), 1);
    assert_eq!(
        rows_a[0].id,
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM notification_recipient WHERE dispatch_ref = $1",
        )
        .bind(dispatch_id)
        .fetch_one(&state.base.db)
        .await
        .expect("fetch direct recipient id")
    );
    assert_eq!(unread_a, 1);
    assert_eq!(rows_b.len(), 0);
    assert_eq!(unread_b, 0);
}

#[tokio::test]
async fn ambiguous_notification_audience_is_rejected() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user_with_email(&state.base.db, "notif-ambiguous").await;

    let result = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: Some(Uuid::now_v7()),
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Invalid notice".to_string()),
            body_html: None,
            body_text: Some("Invalid audience".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await;

    assert!(result.is_err(), "ambiguous audience must fail closed");
}

#[tokio::test]
async fn new_user_backfill_catches_up_global_notification() {
    let state = skip_if_no_db!(test_state().await);
    let existing_user = seed_user_with_email(&state.base.db, "notif-backfill-existing").await;
    let dispatch_id = dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: None,
            is_global: true,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some("Backfill notice".to_string()),
            body_html: None,
            body_text: Some("Catch up new users".to_string()),
            route: None,
            variables: Default::default(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
    )
    .await
    .expect("create backfill dispatch");
    attome_notification::recipient::fan_out_notification(&state.base.db, dispatch_id)
        .await
        .expect("fan out existing user");

    let new_user = seed_user_with_email(&state.base.db, "notif-backfill-new").await;
    attome_notification::recipient::backfill_for_new_user(&state.base.db, new_user, 30)
        .await
        .expect("backfill new user");

    // Scoped to THIS dispatch, not "how many rows are in the inbox".
    // `backfill_for_new_user` deliberately catches up every global dispatch
    // inside its window (30 days here), so on the shared throwaway database a
    // whole-inbox count also counts every global dispatch previous runs left
    // behind — this read 3 against 1 on the first rerun. `poll` returns no
    // dispatch reference, so the per-dispatch check goes to the recipient
    // table directly, which is also where the exactly-once claim lives
    // (`uq_xrm_notification_recipient_dispatch_user`). F-006/TODO-008(c).
    let rows_for_dispatch = |user_id: uuid::Uuid| {
        let db = state.base.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM notification_recipient \
                 WHERE dispatch_ref = $1 AND user_ref = $2 AND is_deleted = FALSE",
            )
            .bind(dispatch_id)
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("count recipient rows for this dispatch")
        }
    };
    assert_eq!(
        rows_for_dispatch(existing_user).await,
        1,
        "fan_out must address the existing user exactly once"
    );
    assert_eq!(
        rows_for_dispatch(new_user).await,
        1,
        "backfill must catch the new user up on this global dispatch exactly once"
    );
}
