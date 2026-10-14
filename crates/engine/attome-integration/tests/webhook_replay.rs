//! M59 §4.1 (MASTER-PLAN P0 row 0.6) — the inbound webhook's replay
//! protection against a real Redis/Dragonfly: a signed request is admitted
//! once, and every replay of it (byte-for-byte, or with its signature
//! re-cased) is refused with 409 while the timestamp is still in-window.
//!
//! The negative paths that need no store (tampered body, stale timestamp,
//! Redis down) are unit tests in `src/webhook.rs`.
//!
//! Requires a Redis/Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT`
//! (defaults 127.0.0.1:6379), same convention as `attome-s2s/tests/rate_limit.rs`:
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-integration --test webhook_replay
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_integration::webhook::{self, SIGNATURE_HEADER, TIMESTAMP_HEADER};
use attome_types::AppError;
use axum::http::{HeaderMap, HeaderValue};
use fred::interfaces::ClientLike;
use fred::prelude::*;
use uuid::Uuid;

const CRED: &str = "replay-test-credential";

async fn test_pool() -> RedisPool {
    let host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("TEST_REDIS_PORT")
        .unwrap_or_else(|_| "6379".into())
        .parse()
        .expect("TEST_REDIS_PORT must be a valid port number");
    let config = RedisConfig::from_url(&format!("redis://{host}:{port}"))
        .expect("build redis config from test host/port");
    let pool = RedisPool::new(config, None, None, None, 2).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to local test Redis/Dragonfly");
    pool
}

fn sign(parts: &[&[u8]]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(CRED.as_bytes()).unwrap();
    for p in parts {
        mac.update(p);
    }
    hex::encode(mac.finalize().into_bytes())
}

fn signed(ts: i64, body: &[u8]) -> (HeaderMap, String) {
    let ts = ts.to_string();
    let sig = sign(&[ts.as_bytes(), b".", body]);
    let mut h = HeaderMap::new();
    h.insert(TIMESTAMP_HEADER, HeaderValue::from_str(&ts).unwrap());
    h.insert(SIGNATURE_HEADER, HeaderValue::from_str(&sig).unwrap());
    (h, sig)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::test]
async fn a_replayed_signed_request_is_refused_with_409() {
    let pool = test_pool().await;
    let system = Uuid::now_v7();
    let body = br#"{"event":"x"}"#;
    let (h, _) = signed(now(), body);

    let first = webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h,
        body,
        now(),
    )
    .await
    .expect("first delivery is admitted");
    assert!(!first.nonce_key.is_empty());

    let replay = webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h,
        body,
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(replay, AppError::Conflict(_)), "{replay:?}");
}

/// `hex::decode` accepts either case, so the nonce is keyed on the decoded
/// bytes: an upper-cased copy of a captured signature is the same nonce.
#[tokio::test]
async fn a_replay_with_a_recased_signature_is_still_refused() {
    let pool = test_pool().await;
    let system = Uuid::now_v7();
    let body = b"{}";
    let (h, sig) = signed(now(), body);
    webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h,
        body,
        now(),
    )
    .await
    .expect("first delivery is admitted");

    let mut recased = h.clone();
    recased.insert(
        SIGNATURE_HEADER,
        HeaderValue::from_str(&sig.to_uppercase()).unwrap(),
    );
    let replay = webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &recased,
        body,
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(replay, AppError::Conflict(_)), "{replay:?}");
}

/// A re-signed delivery (fresh timestamp) of the same body is a new
/// delivery, and the same signed request to a different system is that
/// system's own first delivery — nonces are scoped per system.
#[tokio::test]
async fn distinct_deliveries_and_distinct_systems_are_each_admitted() {
    let pool = test_pool().await;
    let system = Uuid::now_v7();
    let body = b"{}";
    let t = now();
    let (h1, _) = signed(t, body);
    let (h2, _) = signed(t - 1, body);
    webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h1,
        body,
        t,
    )
    .await
    .expect("first");
    webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h2,
        body,
        t,
    )
    .await
    .expect("re-signed delivery");
    webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        Uuid::now_v7(),
        CRED,
        &h1,
        body,
        t,
    )
    .await
    .expect("other system");
}

/// A call that wrote nothing releases its nonce, so the provider's retry of
/// the identical request is admitted rather than refused as a replay.
#[tokio::test]
async fn a_released_nonce_admits_the_retry() {
    let pool = test_pool().await;
    let system = Uuid::now_v7();
    let body = b"{}";
    let (h, _) = signed(now(), body);
    let admission = webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h,
        body,
        now(),
    )
    .await
    .expect("first");
    webhook::release(&attome_cache::Store::Redis(pool.clone()), &admission).await;
    webhook::admit(
        &attome_cache::Store::Redis(pool.clone()),
        system,
        CRED,
        &h,
        body,
        now(),
    )
    .await
    .expect("retry after release is admitted");
}
