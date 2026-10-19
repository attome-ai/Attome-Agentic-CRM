//! Z1-T15: logging the whole configuration never writes a secret. A
//! configuration holding a sentinel in every secret field is logged with
//! `?config` at `info` through a real tracing subscriber writing to a
//! buffer; the buffer must hold the event and none of the sentinels.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use attome_config::AppConfig;

const PASSWORD: &str = "leak-sentinel-password";
/// A hex key (64 characters), as the key rings require.
const HEX_KEY: &str = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff";
const JWT: &str = "leak-sentinel-jwt-secret-of-enough-length";

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 7865, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "info", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "attome",
                "user": "attome", "password": "{PASSWORD}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "localhost", "port": 6379, "password": "{PASSWORD}",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "access",
                "s3_secret_key": "{PASSWORD}",
                "s3_bucket": "attome", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "{JWT}", "jwt_issuer": "attome", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": "{PASSWORD}"
            }},
            "rate_limit": {{ "anonymous_rpm": 60, "authenticated_rpm": 600, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "mailer",
                "smtp_password": "{PASSWORD}", "smtp_from_address": "a@b.test",
                "smtp_from_name": "a", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            }},
            "google_ai": {{
                "api_key": "{PASSWORD}", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "einvoice": {{ "enabled": true, "key_encryption_key": "{HEX_KEY}" }},
            "integration": {{ "credential_encryption_key": "{HEX_KEY}" }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#
    );
    serde_json::from_str(&json).expect("the test configuration deserializes")
}

#[test]
fn tracing_never_records_secret() {
    let config = config();
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(config = ?config, "configuration loaded");
    });
    let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("configuration loaded"),
        "the event was captured"
    );
    assert!(
        logged.contains("7865"),
        "the configuration itself was logged"
    );
    for sentinel in [PASSWORD, HEX_KEY, JWT] {
        assert!(
            !logged.contains(sentinel),
            "a secret reached the log: {sentinel}"
        );
    }
}
