//! E14-T11: tracking retention and erasure against a real database. Page
//! views past a site's retention become daily totals and their month is
//! dropped; an erased contact's visits, and every other visit of the same
//! visitor, are gone while someone else's stay.
//!
//! `marketing_tracked_site` is provisioned here (the marketing pack
//! provisions it on a deployment); fixture rows are direct SQL against this
//! binary's throwaway database (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test tracking_retention"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use std::sync::Arc;

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_core::erasure_hook::ErasureHook;
use attome_marketing::tracking::retention::{TrackingErasure, roll_up_and_prune};
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

fn test_config() -> AppConfig {
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
                "connection_number": 8, "timeout": 5.0
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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
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
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_state() -> Option<EngineState> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config).await.expect("connect");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("redis");
    let coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("storage");
    let site = attome_metadata::provision::ensure_entity(
        &db,
        "marketing_tracked_site",
        "marketing_tracked_site",
        None,
        false,
    )
    .await
    .expect("provision marketing_tracked_site");
    for (field, field_type) in [
        ("site_key", "text"),
        ("office_networks", "text"),
        ("enabled", "bool"),
        ("retention_days", "number"),
    ] {
        attome_metadata::provision::ensure_attribute(
            &db, site, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .expect("provision site attribute");
    }
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        coordination,
        storage,
    );
    let state = EngineState::new(base);
    state
        .modules
        .store(Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    Some(state)
}

/// A new enabled site keeping raw events `retention_days`; returns its key.
async fn site(state: &EngineState, retention_days: i32) -> String {
    let key = format!("site-{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO marketing_tracked_site (site_key, enabled, retention_days) \
         VALUES ($1, true, $2)",
    )
    .bind(&key)
    .bind(retention_days)
    .execute(&state.base.db)
    .await
    .expect("insert tracked site");
    key
}

/// A session of `visitor` on `site_key`, known as `contact` when given.
async fn session(
    db: &sqlx::PgPool,
    site_key: &str,
    visitor: Uuid,
    contact: Option<Uuid>,
    at: DateTime<Utc>,
    campaign: Option<&str>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_web_session \
            (id, site_key, visitor_id, started_at, last_seen_at, utm_campaign, contact_ref) \
         VALUES ($1, $2, $3, $4, $4, $5, $6)",
    )
    .bind(id)
    .bind(site_key)
    .bind(visitor)
    .bind(at)
    .bind(campaign)
    .bind(contact)
    .execute(db)
    .await
    .expect("insert session");
    id
}

/// One page view of `url` in `session`.
async fn view(
    db: &sqlx::PgPool,
    site_key: &str,
    visitor: Uuid,
    session: Uuid,
    at: DateTime<Utc>,
    url: &str,
) {
    ensure_month(db, at).await;
    sqlx::query(
        "INSERT INTO marketing_web_event \
            (id, site_key, visitor_id, session_id, occurred_at, kind, url) \
         VALUES ($1, $2, $3, $4, $5, 'page_view', $6)",
    )
    .bind(Uuid::now_v7())
    .bind(site_key)
    .bind(visitor)
    .bind(session)
    .bind(at)
    .bind(url)
    .execute(db)
    .await
    .expect("insert event");
}

/// The monthly partition `at` falls in, named as the migration names them.
/// The migration made only the month it ran in and the next, and a test may
/// look a few days back across the turn of a month. Another test process may
/// create it at the same moment: then it exists, which is all this needs.
async fn ensure_month(db: &sqlx::PgPool, at: DateTime<Utc>) {
    let (name, ddl): (String, String) = sqlx::query_as(
        "SELECT 'marketing_web_event_p' || to_char(date_trunc('month', $1::timestamptz), 'YYYY_MM'), \
                format('CREATE TABLE IF NOT EXISTS %I PARTITION OF marketing_web_event \
                        FOR VALUES FROM (%L) TO (%L)', \
                       'marketing_web_event_p' || to_char(date_trunc('month', $1::timestamptz), 'YYYY_MM'), \
                       date_trunc('month', $1::timestamptz), \
                       date_trunc('month', $1::timestamptz) + interval '1 month')",
    )
    .bind(at)
    .fetch_one(db)
    .await
    .expect("the month's partition DDL");
    if let Err(error) = sqlx::query(&ddl).execute(db).await {
        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(&name)
            .fetch_one(db)
            .await
            .expect("look the partition up");
        assert!(exists.is_some(), "create {name}: {error}");
    }
}

async fn count(db: &sqlx::PgPool, sql: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(db)
        .await
        .expect("count")
}

#[tokio::test]
async fn old_events_become_daily_totals() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    // A month far past every retention, as its own partition.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS marketing_web_event_p2020_01 PARTITION OF marketing_web_event \
         FOR VALUES FROM ('2020-01-01 00:00:00+00') TO ('2020-02-01 00:00:00+00')",
    )
    .execute(db)
    .await
    .expect("old partition");
    let key = site(&state, 30).await;
    let visitor = Uuid::now_v7();
    let day: DateTime<Utc> = "2020-01-15T10:00:00Z".parse().unwrap();
    let old = session(db, &key, visitor, None, day, Some("spring")).await;
    view(db, &key, visitor, old, day, "https://x.test/pricing").await;
    view(
        db,
        &key,
        visitor,
        old,
        day + Duration::minutes(5),
        "https://x.test/pricing",
    )
    .await;
    view(
        db,
        &key,
        visitor,
        old,
        day + Duration::minutes(6),
        "https://x.test/",
    )
    .await;
    // A visit inside retention stays as it is.
    let recent_at = Utc::now() - Duration::days(1);
    let recent = session(db, &key, visitor, None, recent_at, None).await;
    view(db, &key, visitor, recent, recent_at, "https://x.test/").await;

    let done = roll_up_and_prune(&state).await.expect("retention run");
    assert!(done.partitions_dropped >= 1, "{done:?}");

    let totals: Vec<(String, String, i32, i32)> = sqlx::query_as(
        "SELECT url, utm_campaign, views, sessions FROM marketing_web_daily \
          WHERE site_key = $1 AND day = '2020-01-15' ORDER BY url",
    )
    .bind(&key)
    .fetch_all(db)
    .await
    .expect("daily totals");
    assert_eq!(
        totals,
        vec![
            ("https://x.test/".to_owned(), "spring".to_owned(), 1, 1),
            (
                "https://x.test/pricing".to_owned(),
                "spring".to_owned(),
                2,
                1
            ),
        ]
    );
    let partition: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('marketing_web_event_p2020_01')::text")
            .fetch_one(db)
            .await
            .expect("partition gone");
    assert_eq!(partition, None, "the old month was dropped");
    let sql = "SELECT count(*) FROM marketing_web_session WHERE id = $1";
    assert_eq!(count(db, sql, old).await, 0, "the old session was deleted");
    assert_eq!(count(db, sql, recent).await, 1, "the recent session stays");
    let events = "SELECT count(*) FROM marketing_web_event WHERE session_id = $1";
    assert_eq!(count(db, events, recent).await, 1, "recent events stay raw");

    // A rerun adds nothing.
    let again = roll_up_and_prune(&state).await.expect("second run");
    assert_eq!(again.partitions_dropped, 0);
    assert_eq!(again.sessions_deleted, 0);
}

#[tokio::test]
async fn erasure_removes_visits() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let key = site(&state, 395).await;
    let now = Utc::now();
    let contact = Uuid::now_v7();
    let visitor = Uuid::now_v7();
    // The person's identified visit and an earlier anonymous one of theirs.
    let known = session(db, &key, visitor, Some(contact), now, None).await;
    let anonymous = session(db, &key, visitor, None, now - Duration::days(3), None).await;
    view(db, &key, visitor, known, now, "https://x.test/").await;
    view(
        db,
        &key,
        visitor,
        anonymous,
        now - Duration::days(3),
        "https://x.test/a",
    )
    .await;
    // Someone else's visit.
    let other_visitor = Uuid::now_v7();
    let other = session(db, &key, other_visitor, None, now, None).await;
    view(db, &key, other_visitor, other, now, "https://x.test/").await;

    let mut tx = db.begin().await.expect("begin");
    let removed = TrackingErasure
        .erase(&mut tx, "contact", contact)
        .await
        .expect("erase");
    tx.commit().await.expect("commit");
    assert_eq!(removed, 4, "two sessions and their two events");

    let sessions = "SELECT count(*) FROM marketing_web_session WHERE visitor_id = $1";
    let events = "SELECT count(*) FROM marketing_web_event WHERE visitor_id = $1";
    assert_eq!(count(db, sessions, visitor).await, 0);
    assert_eq!(count(db, events, visitor).await, 0);
    assert_eq!(count(db, sessions, other_visitor).await, 1);
    assert_eq!(count(db, events, other_visitor).await, 1);

    // Another kind of record erases nothing here.
    let mut tx = db.begin().await.expect("begin");
    let none = TrackingErasure
        .erase(&mut tx, "account", other_visitor)
        .await
        .expect("erase account");
    tx.rollback().await.expect("rollback");
    assert_eq!(none, 0);
}
