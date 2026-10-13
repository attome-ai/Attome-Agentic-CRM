//! P-read-your-writes-lsn Phase 1: integration coverage for
//! `sticky_primary::check_pin`'s four-way branch and `pin_write_with_lsn`'s
//! round trip against a real Redis (fred's `RedisPool`, not a mock) — same
//! convention as `rate_limit.rs` in this directory.
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379).
//! `scripts/test-attome-cache-backends.ps1` runs it against every pinned image.
//! Run manually:
//!
//! ```powershell
//! cargo test -p attome-cache --test sticky_primary
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::sticky_primary::{PinCheck, check_pin, pin_key, pin_write_with_lsn};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::*;
use uuid::Uuid;

async fn test_pool() -> Option<RedisPool> {
    let (host, port) = attome_testkit::test_redis()?;

    let config = RedisConfig::from_url(&format!("redis://{host}:{port}"))
        .expect("build redis config from test host/port");
    let pool = RedisPool::new(config, None, None, None, 2).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to local test Redis/Dragonfly");
    Some(pool)
}

#[tokio::test]
async fn check_pin_returns_none_when_no_pin_exists() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let user_id = Uuid::now_v7();

    assert_eq!(check_pin(&pool, user_id).await, PinCheck::None);
}

#[tokio::test]
async fn check_pin_returns_pinned_with_the_stored_lsn() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let user_id = Uuid::now_v7();

    pin_write_with_lsn(&pool, user_id, "16/B374D848", 30)
        .await
        .expect("pin_write_with_lsn must not error");

    assert_eq!(
        check_pin(&pool, user_id).await,
        PinCheck::Pinned("16/B374D848".to_string())
    );
}

#[tokio::test]
async fn check_pin_treats_a_legacy_bare_sentinel_as_legacy() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let user_id = Uuid::now_v7();
    // Simulates a pin written by an old node still running pre-P-read-your-
    // writes-lsn code (rolling upgrade window) — the exact P1.12 sentinel
    // the deleted `pin_write` used to write.
    let key = pin_key(user_id);
    pool.set::<(), _, _>(&key, 1, Some(Expiration::EX(30)), None, false)
        .await
        .expect("seed legacy sentinel value");

    assert_eq!(check_pin(&pool, user_id).await, PinCheck::Legacy);
}

#[tokio::test]
async fn check_pin_treats_any_other_unexpected_value_as_legacy_defensively() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let user_id = Uuid::now_v7();
    let key = pin_key(user_id);
    pool.set::<(), _, _>(
        &key,
        "garbage-not-an-lsn-pin",
        Some(Expiration::EX(30)),
        None,
        false,
    )
    .await
    .expect("seed unexpected value");

    assert_eq!(check_pin(&pool, user_id).await, PinCheck::Legacy);
}

#[tokio::test]
async fn pin_write_with_lsn_sets_the_configured_ttl() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let user_id = Uuid::now_v7();
    let key = pin_key(user_id);

    pin_write_with_lsn(&pool, user_id, "0/0", 30)
        .await
        .expect("pin_write_with_lsn must not error");

    let ttl: i64 = pool.ttl(&key).await.expect("TTL query must not error");
    assert!(
        (1..=30).contains(&ttl),
        "expected TTL in (0, 30] seconds, got {ttl}"
    );
}

#[tokio::test]
async fn two_different_users_get_independent_pins() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();

    pin_write_with_lsn(&pool, user_a, "16/B374D848", 30)
        .await
        .expect("pin user_a");

    assert_eq!(check_pin(&pool, user_b).await, PinCheck::None);
    assert_eq!(
        check_pin(&pool, user_a).await,
        PinCheck::Pinned("16/B374D848".to_string())
    );
}
