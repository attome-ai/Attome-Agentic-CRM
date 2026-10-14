//! Solo boots without Redis (A5, `docs/solo-memory-backend.md`).
//!
//! Boots one empty database through the real `attome::boot::init` with
//! `cache.backend = "memory"` and no Redis anywhere in the configuration, then
//! drives the shared-state primitives through `AppState`'s stores: a
//! revocation marker, a rate-limit window and a doorbell the listener hears.
//! Needs only PostgreSQL (`DATABASE_URL`, a role with `CREATEDB`); skips
//! loudly without it, except under `CI`.

#![recursion_limit = "512"]
#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Restores `DATABASE_URL` on drop (see `fresh_bootstrap.rs`: `create_pool`
/// must fall back to the config pointing at the throwaway database).
struct DatabaseUrlGuard {
    original: Option<String>,
}

impl DatabaseUrlGuard {
    /// SAFETY: this file has exactly one test, so nothing else in this
    /// process mutates `DATABASE_URL` concurrently.
    fn unset() -> Self {
        let original = std::env::var("DATABASE_URL").ok();
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }
        Self { original }
    }
}

impl Drop for DatabaseUrlGuard {
    fn drop(&mut self) {
        // SAFETY: see `unset`.
        unsafe {
            match &self.original {
                Some(v) => std::env::set_var("DATABASE_URL", v),
                None => std::env::remove_var("DATABASE_URL"),
            }
        }
    }
}

const DEPLOYMENT_SCHEMA: &str = "attome_dev";

fn test_config(db: &DbUrlParts) -> AppConfig {
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
                "host": "{host}", "port": {port}, "dbname": "{dbname}",
                "user": "{user}", "password": "{password}", "schema": "{schema}",
                "connection_number": 5, "timeout": 5.0, "migrate_on_boot": true,
                "runtime": {{ "user": "attome_runtime", "password": "boot-test-runtime-pw" }},
                "migrator": {{ "user": "attome_migrator", "password": "boot-test-migrator-pw" }},
                "readonly": {{ "user": "attome_readonly", "password": "boot-test-readonly-pw" }}
            }},
            "cache": {{
                "backend": "memory",
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": true
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
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}}
            }},
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
            "cors": {{ "allowed_origins": ["http://allowed.test"] }}
        }}"#,
        host = db.host,
        port = db.port,
        dbname = db.dbname,
        user = db.user,
        password = db.password,
        schema = DEPLOYMENT_SCHEMA,
    );
    serde_json::from_str(&json).expect("test config JSON must deserialize into AppConfig")
}

async fn assert_connected_to(pool: &PgPool, expected: &str) {
    let (current,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("SELECT current_database()");
    assert_eq!(
        current, expected,
        "this test only ever writes to its own throwaway database"
    );
}

async fn boot_fresh(db: &attome_testkit::EmptyDatabase) -> (attome::boot::Boot, AppConfig) {
    let parts = DbUrlParts::parse(db.url()).expect("DATABASE_URL must parse");
    let config = test_config(&parts);
    let migration_db = attome_db::create_direct_pool(&config)
        .await
        .expect("connect to the fresh database");
    assert_connected_to(&migration_db, db.name()).await;
    attome_db::ensure_schema(&migration_db, &config)
        .await
        .expect("ensure_schema");
    attome_db::run_migrations(&migration_db, &MIGRATOR)
        .await
        .expect("run_migrations");
    migration_db.close().await;
    let boot = attome::boot::init(&config)
        .await
        .unwrap_or_else(|e| panic!("a fresh boot failed: {e:?}"));
    (boot, config)
}

#[tokio::test]
async fn solo_boots_on_postgres_alone_and_the_stores_work() {
    let fresh = skip_if_no_db!(attome_testkit::empty_database("solo_memory_boot").await);
    let _database_url_guard = DatabaseUrlGuard::unset();

    let (boot, _config) = boot_fresh(&fresh).await;
    let base = boot.system.state().base.clone();
    assert!(base.redis.is_memory(), "the cache role runs in process");
    assert!(
        base.redis_coordination.is_memory(),
        "the coordination role runs in process"
    );
    assert!(base.redis_coordination.ping().await);

    // The registry pre-warm finished, so /health/ready would answer.
    assert!(
        base.registry_ready
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    // Revocation: denylisted until its TTL, fail-closed semantics intact.
    let jti = uuid::Uuid::now_v7();
    assert!(!attome_auth::revocation::is_revoked(&base.redis_coordination, jti).await);
    attome_auth::revocation::revoke(&base.redis_coordination, jti, 60)
        .await
        .expect("revoke");
    assert!(attome_auth::revocation::is_revoked(&base.redis_coordination, jti).await);

    // Rate limiting: a window admits its limit, then refuses.
    let key = format!("solo:test:{jti}");
    for _ in 0..3 {
        let out = attome_cache::rate_limit::check(&base.redis_coordination, &key, 3)
            .await
            .expect("check");
        assert!(out.allowed);
    }
    let refused = attome_cache::rate_limit::check(&base.redis_coordination, &key, 3)
        .await
        .expect("check");
    assert!(!refused.allowed);
}
