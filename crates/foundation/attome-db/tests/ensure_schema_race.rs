//! P0-3 (BDB-F5) — `ensure_schema` must tolerate the first-boot race it
//! actually has: `CREATE SCHEMA IF NOT EXISTS` is a check-then-create, so two
//! sessions (multi-node deploy, a `migrate` job starting beside a booting
//! node) can both pass the existence check and one of them gets `42P06`
//! (`duplicate_schema`) or `23505` on `pg_namespace`. The schema exists either
//! way, and refusing to boot on a benign duplicate is the defect.
//!
//! 16 concurrent callers x 20 fresh schema names, against this binary's
//! throwaway clone (`attome_testkit::test_db_url`), never `attome_dev`. Skips
//! (loudly) when `DATABASE_URL` is unset, except under `CI`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test ensure_schema_race
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// The minimal config fixture every attome-db DB-backed suite duplicates; only
/// `database.schema` matters here, so the rest is throwaway.
fn config_for_schema(schema: &str) -> AppConfig {
    let json = serde_json::json!({
        "app": {
            "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
            "log_level": "error", "threads": 1, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
            "keepalive_requests": 100, "static_files_cache_time": 0,
            "server_header_field": "test"
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "unused",
            "user": "unused", "password": "unused", "schema": schema,
            "connection_number": 1, "timeout": 5.0
        },
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

/// BDB-F5: 16 callers, released together by a barrier, each round on a schema
/// nothing has created yet. Every call must return `Ok`; the losing racer must
/// re-check and accept the schema the winner created, not surface `23505`/
/// `42P06`.
#[tokio::test]
async fn concurrent_ensure_schema_never_fails() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    const CALLERS: usize = 16;
    const ROUNDS: usize = 20;

    let pool = PgPoolOptions::new()
        .max_connections(CALLERS as u32)
        .connect(&url)
        .await
        .expect("connect to the test database");

    for round in 0..ROUNDS {
        // `MAX_IDENTIFIER_LEN` is 48, so the name stays short: 4 + 24 chars.
        let schema = format!("esr_{}", &Uuid::now_v7().simple().to_string()[..24]);
        let config = config_for_schema(&schema);
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CALLERS));
        let mut tasks = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let pool = pool.clone();
            let config = config.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                attome_db::ensure_schema(&pool, &config).await
            }));
        }
        for task in tasks {
            let outcome = task.await.expect("ensure_schema task must not panic");
            outcome.unwrap_or_else(|error| {
                panic!("round {round}: a concurrent ensure_schema failed: {error}")
            });
        }
        sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .expect("drop the round's schema");
    }

    pool.close().await;
}
