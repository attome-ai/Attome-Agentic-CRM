//! E14-T9: page-view alerts against a real database. A known visitor's view
//! of a watched page emits one `web.page_viewed` change event on their
//! contact (the event the workflow engine's `web.page_viewed` trigger
//! starts a flow from, `attome_workflow::trigger_index::entry_trigger_type`),
//! once per session however often they view it; an anonymous visitor, a
//! page nobody watches and the flag being off emit nothing.
//!
//! The tracking entities are provisioned here (the marketing pack
//! provisions them on a deployment); fixture rows are direct SQL against
//! this binary's throwaway database (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test tracking_alerts"
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
use attome_core::feature_flag_store::FeatureFlagPolicy;
use attome_core::setting_store::{SettingRow, SettingsSnapshot};
use attome_marketing::tracking::alerts::{FLAG, after_batch};
use attome_marketing::tracking::writer::{WebEventBatch, write_batch};
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
    ] {
        attome_metadata::provision::ensure_attribute(
            &db, site, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .expect("provision site attribute");
    }
    let watched = attome_metadata::provision::ensure_entity(
        &db,
        "marketing_watched_page",
        "marketing_watched_page",
        None,
        false,
    )
    .await
    .expect("provision marketing_watched_page");
    for (field, field_type, lookup) in [
        ("site_ref", "lookup", Some(site)),
        ("url_pattern", "text", None),
        ("audience", "text", None),
        ("enabled", "bool", None),
    ] {
        attome_metadata::provision::ensure_attribute(
            &db, watched, field, field, field_type, false, false, false, true, lookup, None,
        )
        .await
        .expect("provision watched page attribute");
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

/// Turns the alerts flag on or off for the deployment.
fn set_alerts(state: &EngineState, on: bool) {
    let policy = FeatureFlagPolicy {
        deployment: on,
        ..FeatureFlagPolicy::default()
    };
    state
        .settings
        .swap(SettingsSnapshot::from_rows(vec![SettingRow {
            id: Uuid::now_v7(),
            key: format!("feature.{FLAG}"),
            scope: "deployment".into(),
            scope_ref: None,
            value: serde_json::to_value(&policy).unwrap(),
            schema: json!({}),
            row_version: 0,
            updated_at: Utc::now(),
        }]));
}

/// A new enabled site watching `pattern`; returns its key.
async fn watching(state: &EngineState, pattern: &str) -> String {
    let key = format!("site-{}", Uuid::now_v7().simple());
    let site: Uuid = sqlx::query_scalar(
        "INSERT INTO marketing_tracked_site (site_key, enabled) VALUES ($1, true) RETURNING id",
    )
    .bind(&key)
    .fetch_one(&state.base.db)
    .await
    .expect("insert tracked site");
    sqlx::query(
        "INSERT INTO marketing_watched_page (site_ref, url_pattern, audience, enabled) \
         VALUES ($1, $2, 'known_contact', true)",
    )
    .bind(site)
    .bind(pattern)
    .execute(&state.base.db)
    .await
    .expect("insert watched page");
    key
}

/// Writes one batch of page views for `session`.
async fn views(state: &EngineState, key: &str, session: Uuid, urls: &[&str]) {
    let at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let events: Vec<_> = urls
        .iter()
        .enumerate()
        .map(|(i, u)| json!({"kind": "page_view", "at": at, "url": u, "title": format!("p{i}")}))
        .collect();
    let batch = WebEventBatch {
        site_key: key.into(),
        ip_prefix: "203.0.113.0".into(),
        country: Some("sa".into()),
        user_agent_class: "desktop".into(),
        batch: json!({
            "site": key,
            "visitor": Uuid::now_v7().to_string(),
            "session": session.to_string(),
            "events": events,
        }),
    };
    write_batch(&state.base.db, &batch)
        .await
        .expect("write batch");
}

async fn identify(state: &EngineState, session: Uuid, contact: Uuid) {
    sqlx::query("UPDATE marketing_web_session SET contact_ref = $2 WHERE id = $1")
        .bind(session)
        .bind(contact)
        .execute(&state.base.db)
        .await
        .expect("identify session");
}

async fn page_viewed_events(state: &EngineState, contact: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event \
          WHERE entity_logicalname = 'contact' AND record_id = $1 AND event_name = 'web.page_viewed'",
    )
    .bind(contact)
    .fetch_one(&state.base.db)
    .await
    .expect("count events")
}

#[tokio::test]
async fn watched_page_view_starts_flow() {
    let state = skip_if_no_db!(test_state().await);
    set_alerts(&state, true);
    let key = watching(&state, "/pricing").await;
    let session = Uuid::now_v7();
    let contact = Uuid::now_v7();

    // Anonymous: the view is written, nothing starts.
    views(&state, &key, session, &["https://acme.test/pricing"]).await;
    assert_eq!(after_batch(&state, &key, session).await.expect("alerts"), 0);

    // Known: one event on the contact, for the view already made.
    identify(&state, session, contact).await;
    views(&state, &key, session, &["https://acme.test/about"]).await;
    assert_eq!(after_batch(&state, &key, session).await.expect("alerts"), 1);
    assert_eq!(page_viewed_events(&state, contact).await, 1);

    // Viewing it again in the same session starts nothing more.
    views(
        &state,
        &key,
        session,
        &["https://acme.test/pricing?plan=pro"],
    )
    .await;
    assert_eq!(after_batch(&state, &key, session).await.expect("alerts"), 0);
    assert_eq!(page_viewed_events(&state, contact).await, 1);

    // A new session of the same person alerts again.
    let next = Uuid::now_v7();
    views(
        &state,
        &key,
        next,
        &["https://acme.test/pricing/enterprise"],
    )
    .await;
    identify(&state, next, contact).await;
    assert_eq!(after_batch(&state, &key, next).await.expect("alerts"), 1);
    assert_eq!(page_viewed_events(&state, contact).await, 2);
}

#[tokio::test]
async fn unwatched_page_or_flag_off_starts_nothing() {
    let state = skip_if_no_db!(test_state().await);
    let key = watching(&state, "/demo").await;
    let session = Uuid::now_v7();
    let contact = Uuid::now_v7();
    views(&state, &key, session, &["https://acme.test/blog"]).await;
    identify(&state, session, contact).await;
    set_alerts(&state, true);
    assert_eq!(after_batch(&state, &key, session).await.expect("alerts"), 0);

    views(&state, &key, session, &["https://acme.test/demo"]).await;
    set_alerts(&state, false);
    assert_eq!(after_batch(&state, &key, session).await.expect("alerts"), 0);
    assert_eq!(page_viewed_events(&state, contact).await, 0);
}
