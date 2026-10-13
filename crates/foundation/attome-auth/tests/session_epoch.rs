//! Integration tests for `attome_auth::epoch` wired into
//! `accounts::issue_access_token` (D-113 Phase 2, wired D-121) — moved out
//! of `accounts.rs`'s unit-test module because `issue_access_token` now
//! reads `user_account.auth_epoch` on every call, with no early-return
//! path for an unconnected pool.
//!
//! Requires a live Postgres with migration 0041 applied — same convention as
//! `refresh_flow.rs`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test session_epoch -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_auth::accounts::issue_access_token;
use attome_auth::epoch;
use attome_config::AppConfig;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

async fn create_test_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at, is_active)
         VALUES ($1, $2, now(), true)",
    )
    .bind(id)
    .bind(format!("epoch-test-{id}@example.invalid"))
    .execute(db)
    .await
    .expect("insert test user");
    id
}

fn test_config(jwt_secret: &str, expiry_mins: u64) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "log_level": "error", "threads": 1, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
                "keepalive_requests": 100, "static_files_cache_time": 0,
                "server_header_field": "test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1,
                "timeout": 5.0
            }},
            "cache": {{
                "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            }},
            "auth": {{
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "test",
                "access_token_expiry_mins": {expiry_mins}
            }},
            "rate_limit": {{ "anonymous_rpm": 100, "authenticated_rpm": 1000 }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c",
                "smtp_from_name": "t", "smtp_use_tls": false,
                "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5
            }},
            "google_ai": {{
                "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5
            }}
        }}"#
    );
    serde_json::from_str(&json).expect("test config must deserialize")
}

#[tokio::test]
async fn issue_access_token_stamps_the_accounts_current_epoch() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let config = test_config("test-secret-value", 15);

    let token = issue_access_token(
        &db,
        user_id,
        Uuid::now_v7(),
        &config.auth.jwt_secret,
        &config.auth.jwt_issuer,
        config.jwt_audience(),
        config.access_token_expiry_secs() as i64,
    )
    .await
    .expect("issue");
    let claims = attome_auth::jwt::validate_token(
        &token,
        &config.auth.jwt_secret,
        &config.auth.jwt_issuer,
        config.jwt_audience(),
    )
    .unwrap();
    assert_eq!(claims.sub, user_id);
    assert_eq!(claims.epoch, 0);

    // Bump the epoch (simulating an admin disable/re-enable) and confirm the
    // next-issued token stamps the new value, not a cached one.
    let mut tx = db.begin().await.unwrap();
    let new_epoch = epoch::bump_in_tx(&mut tx, user_id).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(new_epoch, 1);

    let token2 = issue_access_token(
        &db,
        user_id,
        Uuid::now_v7(),
        &config.auth.jwt_secret,
        &config.auth.jwt_issuer,
        config.jwt_audience(),
        config.access_token_expiry_secs() as i64,
    )
    .await
    .expect("issue after bump");
    let claims2 = attome_auth::jwt::validate_token(
        &token2,
        &config.auth.jwt_secret,
        &config.auth.jwt_issuer,
        config.jwt_audience(),
    )
    .unwrap();
    assert_eq!(claims2.epoch, 1);
}

#[tokio::test]
async fn issue_access_token_fails_for_a_nonexistent_user() {
    let db = skip_if_no_db!(pool().await);
    let config = test_config("test-secret-value", 15);
    let result = issue_access_token(
        &db,
        Uuid::now_v7(),
        Uuid::now_v7(),
        &config.auth.jwt_secret,
        &config.auth.jwt_issuer,
        config.jwt_audience(),
        config.access_token_expiry_secs() as i64,
    )
    .await;
    assert!(result.is_err());
}
