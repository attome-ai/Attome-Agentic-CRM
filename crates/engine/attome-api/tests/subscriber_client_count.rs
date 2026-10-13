//! C-18 — proves `EngineSystemBuilder::build()` opens exactly ONE dedicated
//! Redis subscriber connection, not the seven it used to (one apiece for
//! metadata, security, audit_users, state_models, relationships, forms, and
//! rules — see `attome-api/src/system.rs`'s module doc trail for the old
//! shape). Asserted via `attome_cache::SUBSCRIBER_CLIENTS_CREATED`, a counter
//! `create_subscriber_client` increments on every call, rather than parsing
//! `CLIENT LIST` output.
//!
//! Harness copied near-verbatim from `dashboard_access.rs` (this crate's
//! established convention for a real, non-placeholder `database.*` config):
//! `database.{host,port,dbname,user,password}` here are the REAL resolved
//! per-binary throwaway-clone values, not an `"unused"`/`APP_ENV=debug`
//! placeholder — `AppConfig::migrator_database_url()` (`sync_attribute_index`'s
//! target, reached from ordinary `EngineSystem::build()` seed plumbing) is built
//! from those fields DIRECTLY and does not consult `DATABASE_URL`/`APP_ENV`
//! at all, so the placeholder pattern fails this file's build with
//! `password authentication failed for user "unused"` (confirmed live,
//! matching `dashboard_access.rs`'s own doc comment on the same failure).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`, defaulting to `localhost:6380`). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test subscriber_client_count
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::Ordering;

use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(db: &DbUrlParts) -> AppConfig {
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
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }}
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
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
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
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6380".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_node() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let config = test_config(&db_parts);
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
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    Some(system)
}

/// Mechanism-level proof: build exactly one `EngineSystem` and assert the
/// counter moved by exactly 1 — not 0 (the subscriber wiring silently
/// skipped), and not 7 (the pre-C-18 shape: one apiece for metadata,
/// security, audit_users, state_models, relationships, forms, rules).
#[tokio::test]
async fn build_opens_exactly_one_dedicated_subscriber_connection() {
    let before = attome_cache::SUBSCRIBER_CLIENTS_CREATED.load(Ordering::Relaxed);

    let system = skip_if_no_db!(test_node().await);
    // Keep the system alive so its background subscriber task (and the
    // connection it holds) isn't dropped before we read the counter — not
    // that dropping would change the counter (it only counts creations),
    // but a system reaching Drop mid-test would be a stronger reason to
    // treat this run as inconclusive than the assertion below is.
    let _system = system;

    let after = attome_cache::SUBSCRIBER_CLIENTS_CREATED.load(Ordering::Relaxed);
    assert_eq!(
        after - before,
        1,
        "EngineSystemBuilder::build() must open exactly one dedicated Redis subscriber \
         connection (C-18) — before was {before}, after was {after}"
    );
}
