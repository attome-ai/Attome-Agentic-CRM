//! Integration test for attome-db hardening Phase 2.1: moving every pool onto
//! one `build_pool` must not change any pool's per-connection session setup.
//!
//! - `create_direct_pool` connections disable `statement_timeout` and bound
//!   lock waits with `MIGRATION_LOCK_TIMEOUT`. This is the one pool with a
//!   session hook; see its doc comment.
//! - The other pools set no session state on connect, because a hook would
//!   leak across clients behind a transaction-mode pgbouncer (P1.12). The
//!   migrator pool is checked here as the representative, since it shares
//!   `connection_number` sizing with the rest.
//!
//! Uses this binary's throwaway clone (`attome_testkit::test_db_url`), never
//! `attome_dev`. Skips (loudly) when `DATABASE_URL` is unset, except under
//! except under `ATTOME_TEST_REQUIRE_DB=1` (the older `CI` alias still works). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test pool_session_settings
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::str::FromStr;

use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;

/// Same minimal-fixture shape as `tests/migrator_connection.rs`, with the
/// `database` section supplied by the caller.
fn config_with_database(database: serde_json::Value) -> AppConfig {
    let json = serde_json::json!({
        "app": {
            "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
            "log_level": "error", "threads": 1, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
            "keepalive_requests": 100, "static_files_cache_time": 0,
            "server_header_field": "test"
        },
        "database": database,
        "cache": {
            "host": "localhost", "port": 6379, "password": "", "db": 0,
            "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
            "l1_cache_ttl_seconds": 60
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
            "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
            "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
        },
        "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
        "observability": {
            "metrics_port": 0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "a@b.c",
            "smtp_from_name": "t", "smtp_use_tls": false,
            "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5
        },
        "google_ai": {
            "api_key": "test", "base_url": "http://localhost",
            "default_model": "test", "timeout_seconds": 5
        },
    });
    serde_json::from_value(json).expect("test config must deserialize")
}

/// A config whose `database.host:port`, `dbname`, and bootstrap credentials
/// all point at the throwaway database, so every pool reaches it.
fn config_for(url: &str) -> AppConfig {
    let options = PgConnectOptions::from_str(url).expect("test DATABASE_URL must parse");
    let password = url
        .split_once("://")
        .and_then(|(_, rest)| rest.rsplit_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .map(|(_, password)| password.to_string())
        .unwrap_or_default();
    config_with_database(serde_json::json!({
        "host": options.get_host(), "port": options.get_port(),
        "dbname": options.get_database().expect("test DATABASE_URL must name a database"),
        "user": options.get_username(), "password": password, "schema": "public",
        "connection_number": 2, "timeout": 5.0,
    }))
}

async fn show(pool: &PgPool, setting: &str) -> String {
    sqlx::query_scalar(&format!("SHOW {setting}"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("SHOW {setting} must succeed: {e}"))
}

#[tokio::test]
async fn direct_pool_connections_disable_statement_timeout_and_bound_lock_waits() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = attome_db::create_direct_pool(&config_for(&url))
        .await
        .expect("direct pool must connect");

    assert_eq!(show(&pool, "statement_timeout").await, "0");
    assert_eq!(
        show(&pool, "lock_timeout").await,
        attome_db::MIGRATION_LOCK_TIMEOUT
    );
    // Phase 2.2: this test's config reaches PostgreSQL directly (no
    // pgbouncer), so the role's application_name is visible.
    assert_eq!(show(&pool, "application_name").await, "attome-direct");
    pool.close().await;
}

#[tokio::test]
async fn migrator_pool_connections_set_no_session_state() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let pool = attome_db::create_migrator_pool(&config_for(&url))
        .await
        .expect("migrator pool must connect");

    assert_eq!(
        show(&pool, "lock_timeout").await,
        "0",
        "only the direct pool may set session state on connect"
    );
    assert_eq!(show(&pool, "application_name").await, "attome-migrator");
    pool.close().await;
}
