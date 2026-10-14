//! Enterprise-audit remediation (Phase 2.3): integration coverage for
//! `attome_cache::rate_limit::check`'s atomic Lua-script rewrite — proves the
//! window actually evicts/counts/expires correctly against a real Redis
//! (fred's `RedisPool`, not a mock), and that concurrent calls in the same
//! millisecond no longer collide into a single zset entry (the bug the
//! four-round-trip version had: `now_ms` used as both score and member).
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `xrm-server/tests/record_level_security.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-cache --test rate_limit
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::rate_limit;
use fred::interfaces::ClientLike;
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
async fn allows_requests_under_the_limit() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:rl:{}", Uuid::new_v4());

    for _ in 0..5 {
        let outcome = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 10)
            .await
            .expect("check must not error");
        assert!(outcome.allowed, "under-limit request must be allowed");
    }
}

#[tokio::test]
async fn rejects_once_the_limit_is_exceeded() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:rl:{}", Uuid::new_v4());

    for _ in 0..3 {
        let outcome = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 3)
            .await
            .expect("check must not error");
        assert!(outcome.allowed, "requests up to the limit must be allowed");
    }

    let outcome = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 3)
        .await
        .expect("check must not error");
    assert!(
        !outcome.allowed,
        "the request past the limit must be rejected"
    );
    assert_eq!(outcome.remaining, 0);
    assert_eq!(outcome.limit, 3);
}

/// Regression test for the exact bug the audit flagged: the old
/// implementation used `now_ms` as both the zset score AND member, so two
/// requests landing in the same millisecond collided into a single entry
/// and undercounted. Firing a burst of concurrent requests (near-guaranteed
/// millisecond collisions under `tokio`'s scheduler) must still count every
/// one of them individually.
#[tokio::test]
async fn concurrent_requests_in_the_same_millisecond_are_not_undercounted() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:rl:{}", Uuid::new_v4());
    let limit = 5;

    let mut handles = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, limit).await
        }));
    }

    let mut allowed = 0;
    let mut rejected = 0;
    for handle in handles {
        match handle.await.expect("task must not panic") {
            Ok(outcome) if outcome.allowed => allowed += 1,
            Ok(_) => rejected += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(
        allowed, limit as usize,
        "exactly `limit` concurrent requests must be allowed, proving no \
         two requests silently collided into the same zset member"
    );
    assert_eq!(rejected, 10 - limit as usize);
}

#[tokio::test]
async fn the_window_expires_so_an_old_burst_does_not_permanently_block_the_key() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:rl:{}", Uuid::new_v4());

    let first = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 1)
        .await
        .expect("check must not error");
    assert!(first.allowed, "first request must be allowed");
    let second = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 1)
        .await
        .expect("check must not error");
    assert!(
        !second.allowed,
        "second request past limit=1 must be rejected"
    );

    // The key must carry a TTL (not linger forever) — proves the script's
    // EXPIRE actually ran, same guarantee the old four-call version gave.
    let ttl: i64 = pool
        .ttl(&rate_limit::storage_key(&key))
        .await
        .expect("read ttl");
    assert!(
        ttl > 0 && ttl <= 61,
        "the rate-limit key must have a bounded TTL after check(), got {ttl}"
    );
}

/// P-rate-limit-atomicity §4.1's deliberate anti-lockout property: a
/// rejected request is never recorded, so the zset's cardinality (and
/// therefore its `ZCARD`) never grows past `limit` no matter how many
/// requests are rejected on top of it. Without this, a sustained flood past
/// the limit would keep re-adding entries and re-extending the TTL forever,
/// turning a transient burst into an unbounded lockout for legitimate
/// traffic sharing the bucket.
#[tokio::test]
async fn a_rejected_request_is_never_recorded_in_the_window() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:rl:{}", Uuid::new_v4());
    let limit = 2;

    for _ in 0..limit {
        let outcome = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, limit)
            .await
            .expect("check must not error");
        assert!(outcome.allowed);
    }

    // Ten more rejected requests on top of the limit must not grow the
    // window past `limit` members.
    for _ in 0..10 {
        let outcome = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, limit)
            .await
            .expect("check must not error");
        assert!(!outcome.allowed);
        assert_eq!(
            outcome.remaining, 0,
            "a rejected request must never report positive remaining capacity"
        );
    }

    let cardinality: i64 = pool
        .zcard(&rate_limit::storage_key(&key))
        .await
        .expect("read zset cardinality");
    assert_eq!(
        cardinality, limit as i64,
        "rejected requests must never be added to the window"
    );
}

/// `Retry-After`/`X-RateLimit-Reset` must be derived from the window's own
/// state, never a hardcoded constant (ENTERPRISE-AUDIT-2026-07-24.md #7(c)).
/// A limit=1 bucket rejected immediately after its one admitted request must
/// report a `retry_after_secs` close to the full 60s window, not some
/// unrelated fixed value.
#[tokio::test]
async fn retry_after_is_derived_from_the_windows_actual_remaining_time() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:rl:{}", Uuid::new_v4());

    let first = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 1)
        .await
        .expect("check must not error");
    assert!(first.allowed);

    let rejected = rate_limit::check(&attome_cache::Store::Redis(pool.clone()), &key, 1)
        .await
        .expect("check must not error");
    assert!(!rejected.allowed);
    assert!(
        rejected.retry_after_secs > 55 && rejected.retry_after_secs <= 60,
        "retry_after_secs should be close to the full 60s window right after \
         the sole admitted request, got {}",
        rejected.retry_after_secs
    );
    assert_eq!(rejected.limit, 1);
}
