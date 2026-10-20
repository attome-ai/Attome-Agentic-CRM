//! E14-T6: the collect endpoint's queueing half against a real database —
//! an unknown site and a foreign origin queue nothing, a valid batch queues
//! one job and writes no event row, and the job carries only the truncated
//! address.
//!
//! `marketing_tracked_site` is provisioned here (the marketing pack
//! provisions it on a deployment); fixture rows are direct SQL against this
//! binary's throwaway database (guidelines §4's test exemption). The licence
//! and flag gate in front of `collect::queue` is in-memory and covered by
//! `collect`'s own doc; these tests start after it.
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test tracking_collect"
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

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_marketing::tracking::collect::{CollectRequest, Collected, queue};
use attome_marketing::tracking::writer;
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use chrono::{SecondsFormat, Utc};
use serde_json::json;
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
    let id = attome_metadata::provision::ensure_entity(
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
        ("domains", "text"),
        ("enabled", "bool"),
    ] {
        attome_metadata::provision::ensure_attribute(
            &db, id, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .expect("provision attribute");
    }
    // The app registers the writer's job type; this binary stands in for it.
    let _ = attome_core::jobs::JOB_TYPES.register(
        attome_jobs::JobType::new(writer::JOB, 1),
        |_state: EngineState, _job: attome_jobs::RegisteredJob| async move {
            Ok::<(), attome_jobs::registry::BoxError>(())
        },
    );
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        coordination,
        storage,
    );
    Some(EngineState::new(base))
}

/// A new enabled site on `domains`; returns its key.
async fn site(state: &EngineState, domains: &str) -> String {
    let key = format!("site-{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO marketing_tracked_site (site_key, domains, enabled) VALUES ($1, $2, true)",
    )
    .bind(&key)
    .bind(domains)
    .execute(&state.base.db)
    .await
    .expect("insert tracked site");
    key
}

fn request(site_key: &str, session: Uuid, origin: &str) -> CollectRequest {
    CollectRequest {
        origin: Some(origin.into()),
        client_ip: "203.0.113.77".parse().unwrap(),
        country: Some("SA".into()),
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0".into(),
        body: json!({
            "site": site_key,
            "visitor": Uuid::now_v7().to_string(),
            "session": session.to_string(),
            "events": [{
                "kind": "page_view",
                "at": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "url": "https://example.com/"
            }]
        }),
    }
}

/// The queued jobs whose payload names `session`, as text.
async fn jobs_for(state: &EngineState, session: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT job::text FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'")
        .bind(session.to_string())
        .fetch_all(&state.base.db)
        .await
        .expect("read queued jobs")
}

#[tokio::test]
async fn collect_unknown_site_is_dropped() {
    let state = skip_if_no_db!(test_state().await);
    let session = Uuid::now_v7();
    let outcome = queue(
        &state,
        request("no-such-site", session, "https://example.com"),
    )
    .await
    .expect("collect");
    assert_eq!(outcome, Collected::Dropped);
    assert!(jobs_for(&state, session).await.is_empty());
}

#[tokio::test]
async fn collect_wrong_origin_is_dropped() {
    let state = skip_if_no_db!(test_state().await);
    let key = site(&state, "example.com").await;
    let session = Uuid::now_v7();
    let outcome = queue(&state, request(&key, session, "https://evil.test"))
        .await
        .expect("collect");
    assert_eq!(outcome, Collected::Dropped);
    assert!(jobs_for(&state, session).await.is_empty());
}

#[tokio::test]
async fn collect_queues_and_writes_no_event_row() {
    let state = skip_if_no_db!(test_state().await);
    let key = site(&state, "example.com").await;
    let session = Uuid::now_v7();
    let outcome = queue(&state, request(&key, session, "https://www.example.com"))
        .await
        .expect("collect");
    assert_eq!(outcome, Collected::Queued);
    assert_eq!(jobs_for(&state, session).await.len(), 1);
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM marketing_web_event WHERE session_id = $1")
            .bind(session)
            .fetch_one(&state.base.db)
            .await
            .expect("count events");
    assert_eq!(events, 0, "nothing is written on the request path");
}

#[tokio::test]
async fn tracking_ip_truncated() {
    let state = skip_if_no_db!(test_state().await);
    let key = site(&state, "example.com").await;
    let session = Uuid::now_v7();
    queue(&state, request(&key, session, "https://example.com"))
        .await
        .expect("collect");
    let jobs = jobs_for(&state, session).await;
    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].contains("203.0.113.0"), "{}", jobs[0]);
    assert!(
        !jobs[0].contains("203.0.113.77"),
        "the full address is never queued"
    );
    assert!(
        !jobs[0].contains("Chrome/120"),
        "only the user agent's class is queued"
    );
}
