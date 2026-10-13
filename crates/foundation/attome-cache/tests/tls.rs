//! Integration test for P-datastore-tls: Redis/Dragonfly TLS (fred's
//! `rediss://` scheme + a pinned custom CA) actually works against a real
//! TLS-enabled server, and a wrong CA is a boot-time connection refusal
//! (fail-closed), not a silent plaintext fallback.
//!
//! Requires a TLS-enabled Redis-compatible server reachable at
//! `REDIS_TLS_TEST_HOST`/`_PORT` (defaults 127.0.0.1:6380) with
//! `REDIS_TLS_TEST_PASSWORD`, plus `REDIS_TLS_TEST_CA_PATH` (the real CA
//! that signed the server cert) and `REDIS_TLS_TEST_WRONG_CA_PATH` (an
//! unrelated CA, for the negative case). Run manually:
//!
//! ```powershell
//! $env:REDIS_TLS_TEST_CA_PATH = "C:\path\to\ca.crt"
//! $env:REDIS_TLS_TEST_WRONG_CA_PATH = "C:\path\to\wrong-ca.crt"
//! $env:REDIS_TLS_TEST_PASSWORD = "..."
//! cargo test -p attome-cache --test tls
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;

fn env_or_panic(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(|_| panic!("set {key} to run the P-datastore-tls integration test"))
}

fn test_config(tls_ca_path: Option<String>) -> AppConfig {
    let host = std::env::var("REDIS_TLS_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("REDIS_TLS_TEST_PORT")
        .unwrap_or_else(|_| "6380".into())
        .parse()
        .expect("REDIS_TLS_TEST_PORT must be a valid port number");
    let password = env_or_panic("REDIS_TLS_TEST_PASSWORD");

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
                "host": "localhost", "port": 5555, "dbname": "unused", "user": "unused",
                "password": "unused", "schema": "public", "connection_number": 1,
                "timeout": 5.0
            }},
            "cache": {{
                "host": "{host}", "port": {port}, "password": "{password}", "db": 0,
                "connection_pool_size": 2, "timeout": 2000, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60,
                "tls_enabled": true
                {tls_ca_path_field}
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test"
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
        }}"#,
        tls_ca_path_field = match &tls_ca_path {
            Some(path) => format!(r#", "tls_ca_path": "{}""#, path.replace('\\', "\\\\")),
            None => String::new(),
        }
    );
    serde_json::from_str(&json).expect("test config must deserialize")
}

#[tokio::test]
#[ignore = "requires a TLS-enabled Redis-compatible server; see this file's header for setup"]
async fn tls_enabled_with_the_real_ca_connects_and_pings() {
    let ca_path = env_or_panic("REDIS_TLS_TEST_CA_PATH");
    let config = test_config(Some(ca_path));

    let pool = attome_cache::create_redis_pool(&config)
        .await
        .expect("tls_enabled with the real CA must connect");

    assert!(
        attome_cache::redis_ping(&pool).await,
        "a real TLS-encrypted connection must still be able to PING"
    );
}

#[tokio::test]
#[ignore = "requires a TLS-enabled Redis-compatible server; see this file's header for setup"]
async fn tls_enabled_with_the_wrong_ca_is_a_connection_refusal() {
    let wrong_ca_path = env_or_panic("REDIS_TLS_TEST_WRONG_CA_PATH");
    let config = test_config(Some(wrong_ca_path));

    let result = attome_cache::create_redis_pool(&config).await;
    assert!(
        result.is_err(),
        "a CA that didn't sign the server's cert must refuse the connection, not silently \
         succeed or fall back to plaintext"
    );
}
