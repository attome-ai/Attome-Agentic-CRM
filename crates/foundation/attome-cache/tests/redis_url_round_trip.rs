//! BCF-P0.3 / BCF-8 — the Redis URL this deployment builds must round-trip
//! through fred's own parser, credentials included.
//!
//! fred 9.4 percent-*decodes* URL userinfo (`fred::utils::parse_url_credentials`
//! -> `urlencoding::decode`), so a password containing `%`, `@`, `/`, `#` or `?`
//! only survives if `AppConfig::redis_url()` percent-encodes it first. This
//! suite parses with fred itself, needs no Redis server, and therefore runs in
//! the default `cargo test` tier.

use attome_config::AppConfig;
use fred::prelude::*;

/// A complete, otherwise-valid `AppConfig` whose cache section differs only in
/// the password (and optionally sentinel mode).
fn config_with_cache(cache: serde_json::Value) -> AppConfig {
    let value = serde_json::json!({
        "app": {
            "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
            "log_level": "error", "threads": 1, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
            "keepalive_requests": 100, "static_files_cache_time": 0,
            "server_header_field": "test"
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
            "password": "test", "schema": "test", "connection_number": 1,
            "timeout": 5.0
        },
        "cache": cache,
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
            "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-32-bytes-min",
            "jwt_issuer": "test",
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
        }
    });
    serde_json::from_value(value).expect("fixture config must deserialize")
}

fn central_cache(password: &str) -> serde_json::Value {
    serde_json::json!({
        "host": "redis.internal", "port": 6379, "password": password, "db": 0,
        "connection_pool_size": 1, "timeout": 500,
        "l1_cache_size_mb": 1, "l1_cache_ttl_seconds": 60
    })
}

/// Every password that the URL grammar treats specially must arrive at fred
/// byte-for-byte. `p%41ss` is the case the finding names: today the URL holds
/// it raw, fred decodes it to `pAss`, and the client authenticates with a
/// password the operator never set.
#[test]
fn redis_url_password_round_trips_through_fred() {
    for password in [
        "plain-password",
        "p%41ss",
        "a/b@c#d?",
        "colon:in:password",
        "sp ace",
        "100%secret",
    ] {
        let config = config_with_cache(central_cache(password));
        let url = config.redis_url();
        let parsed =
            RedisConfig::from_url(&url).unwrap_or_else(|e| panic!("fred must parse {url:?}: {e}"));
        assert_eq!(
            parsed.password.as_deref(),
            Some(password),
            "password must survive {url:?} byte-for-byte"
        );
    }
}

/// Sentinel mode carries the resolved master's auth in the URL userinfo, so it
/// is the same defect on a second path: `build_redis_sentinel_url` splices the
/// password raw while the query values beside it are already encoded.
#[test]
fn sentinel_url_master_password_round_trips_through_fred() {
    for password in ["plain-password", "p%41ss", "a/b@c#d?"] {
        let config = config_with_cache(serde_json::json!({
            "host": "redis.internal", "port": 6379, "password": password, "db": 0,
            "connection_pool_size": 1, "timeout": 500,
            "l1_cache_size_mb": 1, "l1_cache_ttl_seconds": 60,
            "sentinel": {
                "service_name": "mymaster",
                "nodes": [{ "host": "sentinel.internal", "port": 26379 }],
                "sentinel_password": "sentinel-p@ss/word"
            }
        }));
        let url = config.redis_url();
        let parsed =
            RedisConfig::from_url(&url).unwrap_or_else(|e| panic!("fred must parse {url:?}: {e}"));
        assert_eq!(
            parsed.password.as_deref(),
            Some(password),
            "sentinel master auth must survive {url:?} byte-for-byte"
        );
    }
}
