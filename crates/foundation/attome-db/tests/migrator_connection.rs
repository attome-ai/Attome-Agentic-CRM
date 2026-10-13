//! Integration test for D-497: `create_migrator_connection` must take its
//! endpoint from `database.direct_url` (falling back to `database.host:port`
//! only when unset) and its identity from `database.migrator`.
//!
//! The regression it pins: the connection used to be built from
//! `migrator_database_url()` alone, i.e. `database.host:port`, which in a
//! pooled deployment is a transaction-mode pgbouncer. Its caller,
//! `xrm-entity::provision::sync_attribute_index`, holds a *session* advisory
//! lock across several statements, which pgbouncer does not keep on one
//! backend. The first test here points `database.host:port` at a closed port
//! and `direct_url` at the real database: it can only pass if the connection
//! really goes to `direct_url`.
//!
//! Runs against this binary's throwaway clone (`attome_testkit::test_db_url`),
//! never `attome_dev`. Skips (loudly) when `DATABASE_URL` is unset, except
//! under `ATTOME_TEST_REQUIRE_DB=1` (or the older `CI` alias). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test migrator_connection
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::str::FromStr;

use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;
use sqlx::Connection;
use sqlx::postgres::PgConnectOptions;

/// The throwaway database's identity, split out of its URL.
struct TestDb {
    url: String,
    host: String,
    port: u16,
    user: String,
    password: String,
    dbname: String,
}

fn test_db() -> Option<TestDb> {
    let url = attome_testkit::test_db_url()?;
    let options = PgConnectOptions::from_str(&url).expect("test DATABASE_URL must parse");
    // `PgConnectOptions` has no password getter; the test URLs this suite
    // runs against carry a plain `user:password@` userinfo.
    let userinfo = url
        .split_once("://")
        .and_then(|(_, rest)| rest.rsplit_once('@'))
        .map(|(userinfo, _)| userinfo)
        .expect("test DATABASE_URL must carry user:password@");
    let password = userinfo.split_once(':').map(|(_, p)| p).unwrap_or_default();
    Some(TestDb {
        host: options.get_host().to_string(),
        port: options.get_port(),
        user: options.get_username().to_string(),
        password: password.to_string(),
        dbname: options
            .get_database()
            .expect("test DATABASE_URL must name a database")
            .to_string(),
        url,
    })
}

/// Same minimal-fixture shape as `src/pool.rs`'s unit-test `minimal_config`
/// (duplicated rather than exported, per that fixture's own comment), with
/// the `database` section supplied by the caller.
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

#[tokio::test]
async fn migrator_connection_goes_to_direct_url_not_database_host() {
    let db = skip_if_no_db!(test_db());
    // `database.host:port` is a closed port: connecting there fails, so the
    // only way this test passes is the connection using `direct_url`.
    let config = config_with_database(serde_json::json!({
        "host": "127.0.0.1", "port": 1, "dbname": db.dbname,
        "user": "unused_bootstrap_user", "password": "unused", "schema": "public",
        "connection_number": 1, "timeout": 5.0,
        "direct_url": db.url,
        "migrator": { "user": db.user, "password": db.password },
    }));

    let mut conn = attome_db::create_migrator_connection(&config)
        .await
        .expect("migrator connection must use database.direct_url's endpoint");
    let identity = attome_db::verify_connection_identity(&mut conn, &db.user, &db.dbname).await;
    let _ = conn.close().await;
    assert!(
        identity.is_ok(),
        "the migrator connection must authenticate as database.migrator on the configured \
         database: {identity:?}"
    );
}

#[tokio::test]
async fn migrator_connection_falls_back_to_database_host_without_direct_url() {
    let db = skip_if_no_db!(test_db());
    let config = config_with_database(serde_json::json!({
        "host": db.host, "port": db.port, "dbname": db.dbname,
        "user": "unused_bootstrap_user", "password": "unused", "schema": "public",
        "connection_number": 1, "timeout": 5.0,
        "migrator": { "user": db.user, "password": db.password },
    }));

    let mut conn = attome_db::create_migrator_connection(&config)
        .await
        .expect("without direct_url the migrator connection must use database.host:port");
    let identity = attome_db::verify_connection_identity(&mut conn, &db.user, &db.dbname).await;
    let _ = conn.close().await;
    assert!(identity.is_ok(), "fallback path identity: {identity:?}");
}

#[tokio::test]
async fn migrator_connection_identity_mismatch_is_refused() {
    let db = skip_if_no_db!(test_db());
    let config = config_with_database(serde_json::json!({
        "host": "127.0.0.1", "port": 1, "dbname": db.dbname,
        "user": "unused_bootstrap_user", "password": "unused", "schema": "public",
        "connection_number": 1, "timeout": 5.0,
        "direct_url": db.url,
        "migrator": { "user": db.user, "password": db.password },
    }));

    let mut conn = attome_db::create_migrator_connection(&config)
        .await
        .expect("migrator connection must open");
    let result = attome_db::verify_connection_identity(
        &mut conn,
        "definitely_not_the_real_migrator_d497",
        &db.dbname,
    )
    .await;
    let _ = conn.close().await;
    let message = result
        .expect_err("a migrator connection authenticating as the wrong role must be refused")
        .to_string();
    assert!(
        message.contains("database identity mismatch"),
        "error must explain the mismatch so an operator can act on it, got: {message}"
    );
}
