//! BAU-F2 / P0.3 (G-10) — the OIDC single-use `state` must be consumed
//! **atomically**.
//!
//! Before this test's fix, `complete_login` read the state with `GET` and
//! only then issued a `DEL`, ignoring its result. Two concurrent callbacks on
//! one `state` both read it, both exchanged the code, and a `DEL` timeout
//! left the state replayable for the rest of its 300 s TTL. The IdP's
//! single-use `code` bounds the impact, but the comment "single-use
//! regardless" was false.
//!
//! The mock token endpoint below counts every exchange and always answers 400,
//! so the test needs no RSA key, no JWKS and no IdP: what it measures is how
//! many callers got *past* the state gate. With an atomic consume exactly one
//! can; with GET-then-DEL up to all twenty can.
//!
//! Needs Redis/Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT` (defaults
//! 127.0.0.1:6379), same convention as `oidc_jwks_refetch.rs`. Run manually:
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-auth --test oidc_state -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use attome_auth::oidc::{self, complete_login};
use attome_config::OidcProviderConfig;
use fred::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// A pool against the local test Redis/Dragonfly. The state and cache roles
/// are the same instance here — their split is what `BAU-9` is about, not
/// this test.
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

/// A pool that can never be reached: nothing listens on port 1.
fn unreachable_pool() -> RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

/// A provider key no other test run shares, so state, discovery and cache keys
/// never collide.
fn unique_provider() -> String {
    format!("oidc-state-test-{}", Uuid::now_v7())
}

/// The provider under test. Its `token_endpoint` lives only in the primed
/// discovery document below, so nothing here names one.
fn provider(issuer: &str) -> OidcProviderConfig {
    OidcProviderConfig {
        display_name: "State test IdP".into(),
        issuer: issuer.to_string(),
        client_id: "state-test-client".into(),
        client_secret: "state-test-client-secret-throwaway".into(),
        scopes: vec!["openid".into(), "email".into()],
        email_claim: "email".into(),
        require_email_verified_claim: false,
    }
}

/// A token endpoint that counts every exchange and always refuses, so no
/// JWT/JWKS work is needed to prove "this caller got past the state gate".
async fn counting_token_endpoint() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/token", listener.local_addr().unwrap());
    let exchanges = Arc::new(AtomicUsize::new(0));
    let counter = exchanges.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    (url, exchanges)
}

async fn prime_discovery(redis: &RedisPool, provider_key: &str, token_endpoint: &str) {
    let doc = serde_json::json!({
        "authorization_endpoint": "http://127.0.0.1:1/authorize",
        "token_endpoint": token_endpoint,
        "jwks_uri": "http://127.0.0.1:1/jwks",
    })
    .to_string();
    redis
        .set::<(), _, _>(
            format!("oidc:discovery:{provider_key}"),
            doc,
            Some(Expiration::EX(300)),
            None,
            false,
        )
        .await
        .expect("prime the discovery cache");
}

/// Writes one single-use state, exactly as `start_login` would.
async fn seed_state(redis: &RedisPool, state_id: &str) {
    let state = serde_json::json!({
        "code_verifier": "throwaway-verifier",
        "nonce": "throwaway-nonce",
        "redirect_uri": "https://app.example/api/v1/auth/oidc/test/callback",
    })
    .to_string();
    redis
        .set::<(), _, _>(
            format!("oidc:state:{state_id}"),
            state,
            Some(Expiration::EX(300)),
            Some(SetOptions::NX),
            false,
        )
        .await
        .expect("seed the single-use state");
}

/// P0.3 — twenty callbacks race one `state`. At most one may reach the token
/// exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_callbacks_on_one_state_admit_at_most_one() {
    let redis = redis_pool().await;
    let provider_key = unique_provider();
    let (token_endpoint, exchanges) = counting_token_endpoint().await;
    prime_discovery(&redis, &provider_key, &token_endpoint).await;
    let state_id = Uuid::now_v7().to_string();
    seed_state(&redis, &state_id).await;
    let provider = provider("http://127.0.0.1:1");

    let mut handles = Vec::new();
    for _ in 0..20 {
        let state_redis = redis.clone();
        let cache_redis = redis.clone();
        let provider = provider.clone();
        let provider_key = provider_key.clone();
        let state_id = state_id.clone();
        handles.push(tokio::spawn(async move {
            complete_login(
                &state_redis,
                &cache_redis,
                &provider,
                &provider_key,
                "throwaway-code",
                // This task is the browser that started the flow (BAU-4b).
                oidc::bind_to_browser(Some(&state_id), &state_id)
                    .expect("the browser that started the flow"),
            )
            .await
        }));
    }
    let mut oks = 0;
    for handle in handles {
        if handle.await.expect("callback task must not panic").is_ok() {
            oks += 1;
        }
    }

    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        1,
        "exactly one of twenty concurrent callbacks on one state may reach the          token exchange; the rest must be refused by the atomic consume          (none may succeed: the mock endpoint refuses every exchange)"
    );
    assert_eq!(oks, 0, "the mock endpoint refuses every exchange");
    let left: i64 = redis
        .exists(format!("oidc:state:{state_id}"))
        .await
        .expect("EXISTS oidc:state");
    assert_eq!(left, 0, "the state must be gone after it was consumed");
}

/// P0.3's negative half, and BAU-5's second acceptance test: a second callback
/// replaying the same state after the first consumed it reaches no exchange.
#[tokio::test]
async fn a_replayed_state_reaches_no_exchange() {
    let redis = redis_pool().await;
    let provider_key = unique_provider();
    let (token_endpoint, exchanges) = counting_token_endpoint().await;
    prime_discovery(&redis, &provider_key, &token_endpoint).await;
    let state_id = Uuid::now_v7().to_string();
    seed_state(&redis, &state_id).await;
    let provider = provider("http://127.0.0.1:1");

    let first = complete_login(
        &redis,
        &redis,
        &provider,
        &provider_key,
        "throwaway-code",
        oidc::bind_to_browser(Some(&state_id), &state_id).expect("the starting browser"),
    )
    .await;
    assert!(first.is_err(), "the mock endpoint refuses the exchange");

    let replay = complete_login(
        &redis,
        &redis,
        &provider,
        &provider_key,
        "throwaway-code",
        oidc::bind_to_browser(Some(&state_id), &state_id).expect("the starting browser"),
    )
    .await;
    assert!(
        replay.is_err(),
        "a replayed state must be refused (Unauthorized)"
    );
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        1,
        "the replay must be refused before any token exchange"
    );
}

/// BAU-5 — an unreachable state store rejects *before* the IdP is contacted,
/// rather than degrading to "no state = proceed".
#[tokio::test]
async fn an_unreachable_state_store_rejects_without_an_exchange() {
    let cache = redis_pool().await;
    let state_store = unreachable_pool();
    let provider_key = unique_provider();
    let (token_endpoint, exchanges) = counting_token_endpoint().await;
    prime_discovery(&cache, &provider_key, &token_endpoint).await;
    let provider = provider("http://127.0.0.1:1");
    let state_id = Uuid::now_v7().to_string();

    let result = complete_login(
        &state_store,
        &cache,
        &provider,
        &provider_key,
        "throwaway-code",
        oidc::bind_to_browser(Some(&state_id), &state_id).expect("the starting browser"),
    )
    .await;

    assert!(result.is_err(), "an unreachable state store must reject");
    assert_eq!(
        exchanges.load(Ordering::SeqCst),
        0,
        "the rejection must happen before the IdP is contacted"
    );
}
