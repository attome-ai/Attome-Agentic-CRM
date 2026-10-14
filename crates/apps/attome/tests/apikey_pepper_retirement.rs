//! attome-auth plan BAU-12d — boot refuses when a live API key is hashed under a
//! pepper id that the configured ring (current + `apikey_hash_previous_peppers`)
//! no longer holds, and names the id. Inactive and expired keys never block.
//!
//! Requires a throwaway database (NEVER attome_dev); skips when unset.
//! Run: `cargo test -p server --test apikey_pepper_retirement -- --test-threads=1`

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

fn config_with_ring(current: u32, previous: &[u32]) -> AppConfig {
    let previous: Vec<serde_json::Value> = previous
        .iter()
        .map(|id| serde_json::json!({ "id": id, "secret": format!("previous-pepper-{id}-at-least-32-bytes-long") }))
        .collect();
    let json = serde_json::json!({
        "app": {
            "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
            "frontend_port": 4200, "log_level": "error", "threads": 1,
            "max_body_size_bytes": 1024, "request_timeout_secs": 5,
            "enable_session": true, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "use_gzip": false,
            "enable_compression": false, "gzip_level": 1, "br_level": 1,
            "idle_connection_timeout": 30, "keepalive_requests": 100,
            "static_files_cache_time": 0, "server_header_field": "attome-test"
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
            "user": "unused", "password": "unused", "schema": "attome_dev",
            "connection_number": 5, "timeout": 5.0
        },
        "cache": {
            "host": "localhost", "port": 6379, "password": "",
            "db": 0, "connection_pool_size": 4, "timeout": 2000,
            "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": false
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
            "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
            "oauth_google_client_id": "", "oauth_google_client_secret": "",
            "apikey_hash_pepper": "current-pepper-at-least-32-bytes-long-xx",
            "apikey_hash_pepper_id": current,
            "apikey_hash_previous_peppers": previous
        },
        "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {} },
        "observability": {
            "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "test@test.local",
            "smtp_from_name": "test", "smtp_use_tls": false,
            "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
        },
        "google_ai": {
            "api_key": "", "base_url": "https://example.invalid",
            "default_model": "none", "timeout_seconds": 1
        },
        "llm_api": {},
        "external_api": {},
        "s2s": { "enabled": false },
        "security": { "bootstrap_admin_email": null }
    });
    serde_json::from_value(json).expect("test config deserializes into AppConfig")
}

async fn seed_key(db: &sqlx::PgPool, user: Uuid, secret_hash: &str, live: bool) {
    sqlx::query(
        "INSERT INTO api_key (id, user_ref, name, public_key, secret_hash, is_active)
         VALUES ($1, $2, 'pepper-retirement-test', $3, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(user)
    .bind(format!("pk-{}", Uuid::now_v7()))
    .bind(secret_hash)
    .bind(live)
    .execute(db)
    .await
    .expect("seed api key");
}

/// The throwaway clone, with the platform schema on the search path (the raw
/// testkit pool has only `public`).
async fn schema_pool() -> Option<sqlx::PgPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO attome_dev, public")
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect(&url)
            .await
            .expect("connect to the throwaway database"),
    )
}

#[tokio::test]
async fn a_boot_with_a_retired_but_referenced_pepper_id_refuses() {
    let db = skip_if_no_db!(schema_pool().await);
    // A per-binary clone may already hold other keys; start from none.
    sqlx::query("DELETE FROM api_key")
        .execute(&db)
        .await
        .expect("clear api keys");
    let user = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at, is_active) VALUES ($1, $2, now(), true)",
    )
    .bind(user)
    .bind(format!("pepper-retirement-{user}@example.invalid"))
    .execute(&db)
    .await
    .expect("seed user");

    seed_key(&db, user, "hmac256:v7$00", true).await;
    seed_key(&db, user, "hmac256$00", true).await;
    // Revoked: never blocks retirement of its id.
    seed_key(&db, user, "hmac256:v9$00", false).await;

    let err = attome::apikey_pepper_registry::check_referenced_peppers_present(
        &db,
        &config_with_ring(8, &[0]),
    )
    .await
    .expect_err("pepper id 7 is referenced by a live key but missing from the ring");
    let message = format!("{err:?}");
    assert!(
        message.contains("pepper id 7"),
        "names the missing id: {message}"
    );
    assert!(
        !message.contains("pepper id 9"),
        "a revoked key never blocks: {message}"
    );
    assert!(
        !message.contains("pepper id 0"),
        "id 0 is in the ring: {message}"
    );

    let missing_zero = attome::apikey_pepper_registry::check_referenced_peppers_present(
        &db,
        &config_with_ring(8, &[7]),
    )
    .await
    .expect_err("a bare hmac256$ row is pepper id 0");
    assert!(format!("{missing_zero:?}").contains("pepper id 0"));

    attome::apikey_pepper_registry::check_referenced_peppers_present(
        &db,
        &config_with_ring(8, &[0, 7]),
    )
    .await
    .expect("every referenced id is in the ring");
}
