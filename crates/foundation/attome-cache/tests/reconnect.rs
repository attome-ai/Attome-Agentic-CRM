//! BCA-01 (attome-cache plan, G-2): a pool and a subscriber built by this
//! crate's own factories must recover after the store restarts, without a
//! process restart — over **plaintext and TLS** (BCA-01b).
//!
//! Before BCA-11 no factory set a `ReconnectPolicy`. In fred 9.4 a client
//! without one ends its router task on the first failed write after the
//! socket drops, and nothing calls `connect()` again, so every node stayed
//! disconnected until it was restarted (BCA-F1).
//!
//! `#[ignore]`d because it restarts a Docker container. It needs a
//! **throwaway** Redis-compatible container that nothing else uses:
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT` point at it and `TEST_REDIS_CONTAINER`
//! names it. Never point it at the dev or test stacks' containers.
//! `scripts/test-attome-cache-backends.ps1` runs it against every pinned image,
//! once on the plaintext container and once on the TLS one.
//!
//! The TLS leg is selected by the same `REDIS_TLS_TEST_*` variables
//! `tests/tls.rs` uses (see `test_config`): the matrix sets them for its TLS
//! container, so this suite reconnects over TLS without a second code path.
//! That leg also exercises `redis_pool`'s rustls crypto-provider install —
//! without it, building a TLS config in a test binary panics (BCA-01b).
//!
//! ```powershell
//! docker run -d --name attome-cache-reconnect -p 127.0.0.1:16392:6379 redis:7
//! $env:TEST_REDIS_PORT = "16392"; $env:TEST_REDIS_CONTAINER = "attome-cache-reconnect"
//! cargo test -p attome-cache --test reconnect -- --ignored --test-threads=1
//! ```

use std::time::{Duration, Instant};

use attome_cache::rate_limit;
use attome_cache::redis_pool::{create_redis_pool, create_subscriber_client, redis_ping};
use attome_config::AppConfig;
use fred::prelude::*;
use uuid::Uuid;

/// How long the pool and the subscriber get to recover after the restart.
const RECOVERY_DEADLINE: Duration = Duration::from_secs(10);

/// A minimal valid config with a plaintext placeholder endpoint; `test_config`
/// rewrites just the `cache` block from the environment, so there is no JSON
/// escaping to get wrong for a Windows CA path or a generated password.
const BASE_CONFIG_JSON: &str = r#"{
            "app": {
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "log_level": "error", "threads": 1, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
                "keepalive_requests": 100, "static_files_cache_time": 0,
                "server_header_field": "test"
            },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "unused", "user": "unused",
                "password": "unused", "schema": "public", "connection_number": 1,
                "timeout": 5.0
            },
            "cache": {
                "host": "127.0.0.1", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 2, "timeout": 2000, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60
            },
            "storage": {
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            },
            "auth": {
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test"
            },
            "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
            "observability": {
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
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
        }"#;

/// BCA-01b — the matrix's TLS leg sets `REDIS_TLS_TEST_CA_PATH` (plus host,
/// port and password) on the same throwaway container this test restarts, so
/// the reconnect proof runs over TLS too.
///
/// That CA path is the mode selector, so the matrix **clears every
/// `REDIS_TLS_TEST_*` variable at the start of each plaintext leg**: those
/// variables are set once per TLS leg in the same PowerShell process and
/// otherwise leak into the next plaintext leg, which would aim this test at a
/// TLS port whose container no longer exists (observed 2026-09-25 on the
/// redis:7 plaintext leg: `reconnect` timed out while `fail_closed`, using
/// `TEST_REDIS_*`, connected to the same container immediately).
fn test_config() -> AppConfig {
    let tls_ca_path = std::env::var("REDIS_TLS_TEST_CA_PATH").ok();
    let (host, port, password) = match &tls_ca_path {
        Some(_) => (
            std::env::var("REDIS_TLS_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            std::env::var("REDIS_TLS_TEST_PORT").unwrap_or_else(|_| "6380".into()),
            std::env::var("REDIS_TLS_TEST_PASSWORD")
                .expect("REDIS_TLS_TEST_PASSWORD must be set for the TLS reconnect leg"),
        ),
        None => (
            std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
            String::new(),
        ),
    };
    let port: u16 = port
        .parse()
        .expect("TEST_REDIS_PORT/REDIS_TLS_TEST_PORT must be a valid port number");

    let mut document: serde_json::Value =
        serde_json::from_str(BASE_CONFIG_JSON).expect("base test config must parse");
    document["cache"]["host"] = serde_json::json!(host);
    document["cache"]["port"] = serde_json::json!(port);
    document["cache"]["password"] = serde_json::json!(password);
    if let Some(path) = &tls_ca_path {
        document["cache"]["tls_enabled"] = serde_json::json!(true);
        document["cache"]["tls_ca_path"] = serde_json::json!(path);
    }

    serde_json::from_value(document).expect("test config must deserialize")
}

fn restart_container(container: &str) {
    let status = std::process::Command::new("docker")
        .args(["restart", "-t", "0", container])
        .status()
        .expect("run docker restart");
    assert!(status.success(), "docker restart {container} failed");
}

#[tokio::test]
#[ignore = "restarts a throwaway Redis container; see this file's header"]
async fn a_pool_and_a_subscriber_recover_after_the_store_restarts() {
    let container = std::env::var("TEST_REDIS_CONTAINER")
        .expect("set TEST_REDIS_CONTAINER to the throwaway container this test may restart");
    let config = test_config();

    let pool = create_redis_pool(&config).await.expect("create the pool");
    let subscriber = create_subscriber_client(&config)
        .await
        .expect("create the subscriber");
    let channel = format!("test:reconnect:{}", Uuid::now_v7());
    subscriber
        .subscribe(channel.clone())
        .await
        .expect("subscribe before the restart");
    let _manager = subscriber.manage_subscriptions();
    let mut messages = subscriber.message_rx();
    assert!(
        redis_ping(&pool).await,
        "the pool must work before the restart"
    );

    restart_container(&container);

    // (a) The pool answers again, without a new `connect()` from the caller.
    let started = Instant::now();
    while !redis_ping(&pool).await {
        assert!(
            started.elapsed() < RECOVERY_DEADLINE,
            "(a) the pool did not reconnect within {RECOVERY_DEADLINE:?} of the store restarting"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // (b) A request-path primitive works again.
    let key = format!("test:reconnect:rl:{}", Uuid::now_v7());
    let outcome = rate_limit::check(&pool, &key, 10)
        .await
        .expect("(b) rate_limit::check must succeed after the reconnect");
    assert!(outcome.allowed);

    // (c) The subscriber is subscribed again: a message published after the
    // restart arrives. Publish repeatedly, because re-subscribing races the
    // first publish.
    let marker = format!("after-restart-{}", Uuid::now_v7());
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < RECOVERY_DEADLINE,
            "(c) the subscriber did not receive a message published after the restart within {RECOVERY_DEADLINE:?}"
        );
        let _: Result<i64, _> = pool.next().publish(channel.clone(), marker.clone()).await;
        if let Ok(Ok(message)) =
            tokio::time::timeout(Duration::from_millis(500), messages.recv()).await
            && message.value.as_string().as_deref() == Some(marker.as_str())
        {
            break;
        }
    }
}
