//! Base-auth hardening 1.7: `oidc::resolve_signing_key`'s single-flight,
//! bounded JWKS refetch, against a real Redis and a local JWKS endpoint that
//! counts every fetch (security contract I10, traceability row F7).
//!
//! Requires Redis/Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT` (defaults
//! 127.0.0.1:6379), same convention as `login_mfa.rs`. Run manually:
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-auth --test oidc_jwks_refetch
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use attome_auth::oidc::resolve_signing_key;
use attome_types::AppError;
use fred::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

async fn redis_pool() -> RedisPool {
    let host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("TEST_REDIS_PORT")
        .unwrap_or_else(|_| "6379".into())
        .parse()
        .expect("TEST_REDIS_PORT must be a valid port number");

    let config = RedisConfig::from_url(&format!("redis://{host}:{port}"))
        .expect("build redis config from test host/port");
    let pool = RedisPool::new(config, None, None, None, 4).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to local test Redis/Dragonfly");
    pool
}

/// A provider key no other test run shares, so cache and gate keys never
/// collide.
fn unique_provider() -> String {
    format!("jwks-refetch-test-{}", Uuid::now_v7())
}

/// A JWKS document publishing one RSA signing key per `kid`. The key material
/// is a placeholder: lookup matches on `kid` alone.
fn jwks(kids: &[&str]) -> String {
    let keys: Vec<serde_json::Value> = kids
        .iter()
        .map(|kid| {
            serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": "AQAB",
                "e": "AQAB",
            })
        })
        .collect();
    serde_json::json!({ "keys": keys }).to_string()
}

/// The JWKS cache key, as documented in `oidc`'s module doc.
fn cache_key(provider: &str) -> String {
    format!("oidc:jwks:{provider}")
}

async fn seed_cache(redis: &RedisPool, provider: &str, body: &str) {
    redis
        .set::<(), _, _>(
            cache_key(provider),
            body,
            Some(Expiration::EX(300)),
            None,
            false,
        )
        .await
        .expect("seed the JWKS cache");
}

async fn cached(redis: &RedisPool, provider: &str) -> Option<String> {
    redis
        .get::<Option<String>, _>(cache_key(provider))
        .await
        .expect("read the JWKS cache")
}

enum Reply {
    Body(String),
    /// Accept the request and never answer.
    Stall,
}

/// A local JWKS endpoint that counts every request it receives.
async fn jwks_endpoint(reply: Reply) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/jwks", listener.local_addr().unwrap());
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    let reply = Arc::new(reply);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = counter.clone();
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                match &*reply {
                    Reply::Body(body) => {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    Reply::Stall => tokio::time::sleep(Duration::from_secs(30)).await,
                }
            });
        }
    });
    (url, fetches)
}

#[tokio::test]
async fn a_cached_kid_resolves_without_a_fetch() {
    let redis = redis_pool().await;
    let provider = unique_provider();
    seed_cache(&redis, &provider, &jwks(&["current"])).await;
    let (uri, fetches) = jwks_endpoint(Reply::Body(jwks(&["current"]))).await;

    let jwk = resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "current",
    )
    .await
    .expect("a cached kid must resolve");

    assert_eq!(jwk.common.key_id.as_deref(), Some("current"));
    assert_eq!(fetches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_rotated_key_is_found_by_exactly_one_refetch() {
    let redis = redis_pool().await;
    let provider = unique_provider();
    seed_cache(&redis, &provider, &jwks(&["old"])).await;
    let (uri, fetches) = jwks_endpoint(Reply::Body(jwks(&["old", "rotated"]))).await;

    let jwk = resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "rotated",
    )
    .await
    .expect("one refetch must find the rotated key");
    assert_eq!(jwk.common.key_id.as_deref(), Some("rotated"));
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    assert!(
        cached(&redis, &provider)
            .await
            .is_some_and(|body| body.contains("rotated")),
        "the refetched set must replace the cached one"
    );

    resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "rotated",
    )
    .await
    .expect("the rotated key is cached now");
    let result = resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "never-published",
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "an unpublished kid must be rejected, got {:?}",
        result.err()
    );
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "a second unknown kid inside the refetch window must not fetch again"
    );
}

#[tokio::test]
async fn parallel_unknown_kids_cause_at_most_one_upstream_fetch() {
    let redis = redis_pool().await;
    let provider = unique_provider();
    seed_cache(&redis, &provider, &jwks(&["old"])).await;
    let (uri, fetches) = jwks_endpoint(Reply::Body(jwks(&["old"]))).await;

    let mut handles = Vec::with_capacity(100);
    for i in 0..100 {
        let redis = redis.clone();
        let provider = provider.clone();
        let uri = uri.clone();
        handles.push(tokio::spawn(async move {
            resolve_signing_key(
                &attome_cache::Store::Redis(redis.clone()),
                &provider,
                &uri,
                &format!("unknown-{i}"),
            )
            .await
        }));
    }
    for handle in handles {
        let result = handle.await.expect("task must not panic");
        assert!(
            matches!(result, Err(AppError::Unauthorized)),
            "an unpublished kid must be rejected, got {:?}",
            result.err()
        );
    }

    assert!(
        fetches.load(Ordering::SeqCst) <= 1,
        "100 parallel unknown kids made {} upstream fetches",
        fetches.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn a_malformed_refetch_is_rejected_and_keeps_the_cached_set() {
    let redis = redis_pool().await;
    let provider = unique_provider();
    seed_cache(&redis, &provider, &jwks(&["old"])).await;
    let original = cached(&redis, &provider).await;
    let (uri, fetches) = jwks_endpoint(Reply::Body("not a jwks document".into())).await;

    let result = resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "rotated",
    )
    .await;

    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a malformed refetch must reject, got {:?}",
        result.err()
    );
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    assert_eq!(
        cached(&redis, &provider).await,
        original,
        "a malformed document must not replace the cached set"
    );
    resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "old",
    )
    .await
    .expect("the cached key must still resolve");
}

#[tokio::test]
async fn an_upstream_stall_on_refetch_is_bounded_and_keeps_the_cached_set() {
    let redis = redis_pool().await;
    let provider = unique_provider();
    seed_cache(&redis, &provider, &jwks(&["old"])).await;
    let original = cached(&redis, &provider).await;
    let (uri, fetches) = jwks_endpoint(Reply::Stall).await;

    let started = Instant::now();
    let result = resolve_signing_key(
        &attome_cache::Store::Redis(redis.clone()),
        &provider,
        &uri,
        "rotated",
    )
    .await;

    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a stalled refetch must reject, got {:?}",
        result.err()
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the refetch must be bounded by the HTTP timeout, took {:?}",
        started.elapsed()
    );
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    assert_eq!(cached(&redis, &provider).await, original);
}
