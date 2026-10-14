//! P-audit-chain-hardening item (b) — live-verified against a real
//! S3-compatible object store (RustFS), per `anchor.rs`'s own doc comment:
//! "an actual put/get cycle... still needs one."
//!
//! Env: S3_ENDPOINT/S3_ACCESS_KEY/S3_SECRET_KEY/S3_BUCKET (defaults match
//! this repo's standard dev stack, RustFS @ :9000, bucket "attomebase").
//! ```powershell
//! cargo test -p attome-audit --test anchor -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::anchor::{anchor_root, fetch_anchored_root};
use attome_config::AppConfig;
use attome_storage::create_storage_client;
use uuid::Uuid;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

async fn test_storage_client() -> attome_storage::StorageClient {
    let json = format!(
        r#"{{
            "app": {{ "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 8, "max_connection_num_per_ip": 8,
                "use_gzip": false, "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 10, "keepalive_requests": 10,
                "static_files_cache_time": 0, "server_header_field": "test" }},
            "database": {{ "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1, "timeout": 5.0 }},
            "cache": {{ "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60 }},
            "storage": {{ "s3_endpoint": "{endpoint}", "s3_region": "us-east-1",
                "s3_access_key": "{access_key}", "s3_secret_key": "{secret_key}",
                "s3_bucket": "{bucket}", "s3_use_path_style": true, "s3_verify_ssl": false }},
            "auth": {{ "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min" }},
            "rate_limit": {{ "anonymous_rpm": 100, "authenticated_rpm": 1000 }},
            "observability": {{ "metrics_port": 0, "log_sampling_rate": 1.0,
                "trace_sampling_rate": 1.0, "enable_distributed_tracing": false }},
            "email": {{ "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c", "smtp_from_name": "t",
                "smtp_use_tls": false, "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5 }},
            "google_ai": {{ "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5 }}
        }}"#,
        endpoint = env_or("S3_ENDPOINT", "http://127.0.0.1:9000"),
        access_key = env_or("S3_ACCESS_KEY", ""),
        secret_key = env_or("S3_SECRET_KEY", ""),
        bucket = env_or("S3_BUCKET", "attomebase"),
    );
    let config: AppConfig = serde_json::from_str(&json).expect("parse throwaway storage config");
    create_storage_client(&config)
        .await
        .expect("connect to the configured S3-compatible store")
}

/// The load-bearing case: `anchor_root` really writes to the external
/// store, and `fetch_anchored_root` really reads it back — not a mock, not
/// a Postgres round trip, an actual object-store put/get cycle.
#[tokio::test]
async fn anchor_root_then_fetch_returns_the_same_merkle_root() {
    if attome_testkit::s3_or_skip().is_none() {
        return;
    }
    let store = test_storage_client().await;
    let org = Uuid::now_v7();
    let batch_id = Uuid::now_v7();
    let root = format!("test-merkle-root-{}", Uuid::now_v7());

    anchor_root(&store, org, batch_id, &root)
        .await
        .expect("anchor_root against a real object store");

    let fetched = fetch_anchored_root(&store, org, batch_id)
        .await
        .expect("fetch_anchored_root against a real object store");

    assert_eq!(fetched, Some(root));
}

/// A batch that was never anchored (or predates `external_anchoring_enabled`)
/// must return `Ok(None)`, not an error — the plan's own documented "not
/// distinguished from a best-effort anchoring failure" contract.
#[tokio::test]
async fn fetch_anchored_root_returns_none_for_an_unanchored_batch() {
    if attome_testkit::s3_or_skip().is_none() {
        return;
    }
    let store = test_storage_client().await;
    let org = Uuid::now_v7();
    let batch_id = Uuid::now_v7();

    let fetched = fetch_anchored_root(&store, org, batch_id)
        .await
        .expect("fetch_anchored_root must not error on a missing object");

    assert_eq!(fetched, None);
}

/// `PutMode::Create` idempotency: re-anchoring the exact same `(org,
/// batch_id)` (e.g. a retry after a network blip that actually succeeded)
/// must succeed, not surface the underlying `AlreadyExists` conflict as an
/// error — `anchor_root`'s own doc comment names this explicitly.
#[tokio::test]
async fn re_anchoring_the_same_batch_is_idempotent_not_an_error() {
    if attome_testkit::s3_or_skip().is_none() {
        return;
    }
    let store = test_storage_client().await;
    let org = Uuid::now_v7();
    let batch_id = Uuid::now_v7();
    let root = format!("test-merkle-root-{}", Uuid::now_v7());

    anchor_root(&store, org, batch_id, &root)
        .await
        .expect("first anchor_root call");
    anchor_root(&store, org, batch_id, &root)
        .await
        .expect("re-anchoring the same batch must be treated as success, not AlreadyExists");
}
