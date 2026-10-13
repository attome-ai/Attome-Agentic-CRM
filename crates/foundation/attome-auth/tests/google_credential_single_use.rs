//! A Google ID token is accepted once.
//!
//! Google Identity Services hands the browser the ID token directly, so the
//! flow has no nonce, and since D-628 the token's verified `auth_time` can
//! satisfy a step-up. Without a single-use marker a captured credential could
//! be replayed to `POST /api/v1/auth/google` for about an hour, each time
//! minting a fresh session that passes a 5- or 15-minute step-up.
//! `accounts::verify_google_id_token` now consumes a marker per credential on
//! the coordination pool, through `consume_google_credential`, which this
//! suite drives against a live store.
//!
//! Needs Redis/Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT` (defaults
//! 127.0.0.1:6379), same convention as `oidc_state.rs`. Run manually:
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-auth --test google_credential_single_use
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::consume_google_credential;
use attome_types::AppError;
use fred::prelude::*;
use uuid::Uuid;

async fn redis_pool() -> RedisPool {
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

/// A pool that can never be reached: nothing listens on port 1.
fn unreachable_pool() -> RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

/// A credential no other test run shares.
fn unique_credential() -> String {
    format!("header.payload-{}.signature", Uuid::now_v7())
}

fn in_an_hour() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::hours(1)
}

#[tokio::test]
async fn a_second_presentation_of_the_same_credential_is_refused() {
    let redis = redis_pool().await;
    let credential = unique_credential();

    consume_google_credential(&redis, &credential, in_an_hour())
        .await
        .expect("the first presentation is accepted");

    let replay = consume_google_credential(&redis, &credential, in_an_hour()).await;
    assert!(
        matches!(replay, Err(AppError::Unauthorized)),
        "a replayed credential must be refused, got {replay:?}"
    );

    // A different credential is unaffected.
    consume_google_credential(&redis, &unique_credential(), in_an_hour())
        .await
        .expect("a different credential is its own first presentation");
}

/// Exactly one of many concurrent presentations of one credential succeeds.
#[tokio::test]
async fn concurrent_presentations_admit_exactly_one() {
    let redis = redis_pool().await;
    let credential = unique_credential();

    let attempts = (0..16).map(|_| {
        let redis = redis.clone();
        let credential = credential.clone();
        tokio::spawn(async move {
            consume_google_credential(&redis, &credential, in_an_hour())
                .await
                .is_ok()
        })
    });
    let mut admitted = 0;
    for attempt in attempts.collect::<Vec<_>>() {
        if attempt.await.unwrap() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1, "exactly one presentation may pass");
}

/// The marker lives until the token could no longer verify: `exp` plus the
/// 60 s leeway, capped at two hours.
#[tokio::test]
async fn the_marker_expires_with_the_token() {
    let redis = redis_pool().await;
    let credential = unique_credential();
    let exp = chrono::Utc::now() + chrono::Duration::seconds(600);

    consume_google_credential(&redis, &credential, exp)
        .await
        .expect("first presentation");

    use sha2::Digest as _;
    let key = format!(
        "attome-auth:google-credential:{}",
        hex::encode(sha2::Sha256::digest(credential.as_bytes()))
    );
    let ttl: i64 = redis.ttl(&key).await.expect("read the marker's TTL");
    assert!(
        (600..=661).contains(&ttl),
        "TTL should be exp - now + 60 s, got {ttl}"
    );

    let far = unique_credential();
    consume_google_credential(
        &redis,
        &far,
        chrono::Utc::now() + chrono::Duration::days(30),
    )
    .await
    .expect("first presentation");
    let far_key = format!(
        "attome-auth:google-credential:{}",
        hex::encode(sha2::Sha256::digest(far.as_bytes()))
    );
    let far_ttl: i64 = redis.ttl(&far_key).await.expect("read the marker's TTL");
    assert!(far_ttl <= 7200, "TTL is capped at two hours, got {far_ttl}");
}

/// Fail closed (D-027): an unreachable store refuses rather than admits.
#[tokio::test]
async fn an_unreachable_store_refuses() {
    let result =
        consume_google_credential(&unreachable_pool(), &unique_credential(), in_an_hour()).await;
    assert!(
        result.is_err(),
        "an unreachable single-use store must refuse"
    );
}
