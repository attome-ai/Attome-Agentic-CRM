//! C-18 — proves `spawn_doorbell_reload`'s periodic catch-up tick (the half
//! `state_registry`/`relationship_registry`/`rule_registry`
//! never had before this change): a write to `state_model` made
//! directly against the database, with NO `PUBLISH` on
//! `STATE_MODEL_VERSION_CHANNEL` at all (the strongest form of "the doorbell
//! message never arrived" — dropped, or the admin write path failing to
//! publish), must still show up in the cache within one tick of the
//! interval `spawn_doorbell_reload` was given, not only on the table's next
//! write.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`, defaulting to `localhost:6380` — the `test` compose
//! profile's `redis-test`). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-core --test snapshot_source_reload
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_config::AppConfig;
use attome_core::{STATE_MODEL_VERSION_CHANNEL, SnapshotSource, StateModelRegistry};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;

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

/// Minimal `AppConfig` — every section is required for deserialization, but
/// this test only exercises `cache.*` (via `attome_cache::create_subscriber_client`).
fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5556, "dbname": "unused_overridden_by_env",
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
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6380".into()),
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn insert_state_model(db: &DbPool, entity_logicalname: &str) {
    sqlx::query(
        "INSERT INTO state_model (entity_logicalname, name, state_field, initial_state, owner_layer) \
         VALUES ($1, $2, 'status', 'new', 'project')",
    )
    .bind(entity_logicalname)
    .bind(format!("{entity_logicalname}-model"))
    .execute(db)
    .await
    .expect("insert throwaway state_model row");
}

/// Polls `cache.load().get(entity_logicalname)` until present or `bound`
/// elapses.
async fn poll_until_present(
    cache: &attome_cache::MetadataCache<StateModelRegistry>,
    entity_logicalname: &str,
    bound: Duration,
) -> bool {
    let started = Instant::now();
    loop {
        if cache.load().get(entity_logicalname).is_some() {
            return true;
        }
        if started.elapsed() >= bound {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_write_with_no_doorbell_published_still_converges_by_the_next_catch_up_tick() {
    let db = skip_if_no_db!(test_db().await);
    let config = test_config();

    let redis = attome_cache::Store::from_config(&config).await;
    let subscriber = match match redis {
        Ok((store, _)) => attome_cache::Subscriber::connect(&store, &config).await,
        Err(e) => Err(e),
    } {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "SKIP {}:{}: could not connect to the test Redis ({e}) — set \
                 TEST_REDIS_HOST/TEST_REDIS_PORT (default localhost:6380)",
                module_path!(),
                line!()
            );
            return;
        }
    };
    subscriber
        .subscribe(STATE_MODEL_VERSION_CHANNEL)
        .await
        .expect("subscribe to STATE_MODEL_VERSION_CHANNEL");

    let cache = attome_cache::MetadataCache::new(StateModelRegistry::default());
    // Deliberately short — production uses tens of seconds
    // (`attome-server/src/system.rs`'s `SNAPSHOT_CATCHUP_POLL_INTERVAL_SECS`);
    // this test only needs to prove the tick itself self-heals, not measure
    // production cadence.
    let tick_interval = Duration::from_millis(300);
    attome_core::spawn_doorbell_reload::<StateModelRegistry>(
        &subscriber,
        db.clone(),
        cache.clone(),
        tick_interval,
    );

    let entity = attome_testkit::unique_logicalname("c18_snapshot_reload");

    // Sanity: the row does not exist yet, so of course the cache doesn't
    // have it.
    assert!(cache.load().get(&entity).is_none());

    // The write that matters: a plain SQL insert, exactly like a dropped
    // doorbell scenario — no PUBLISH on STATE_MODEL_VERSION_CHANNEL happens
    // here at all, so `spawn_doorbell_reload`'s on_message half can never
    // fire for this write. Only its periodic tick can find it.
    insert_state_model(&db, &entity).await;

    assert!(
        poll_until_present(&cache, &entity, tick_interval * 4).await,
        "the cache for {entity} must converge within a few catch-up ticks even though no \
         doorbell message was ever published for this write"
    );

    let entry = cache.load().get(&entity).cloned().unwrap();
    assert_eq!(
        entry.model.expect("model must be populated").name,
        format!("{entity}-model")
    );
}

#[test]
fn snapshot_source_channel_is_reexported_and_matches() {
    assert_eq!(
        <StateModelRegistry as SnapshotSource>::CHANNEL,
        STATE_MODEL_VERSION_CHANNEL
    );
}
