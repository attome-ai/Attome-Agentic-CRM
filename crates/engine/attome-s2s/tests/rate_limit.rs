//! Regression coverage for the same collision bug `attome-cache::rate_limit`
//! was audited and fixed for (Enterprise-audit remediation Phase 2.3): the
//! sliding-window `ZADD` must not use `now_ms` as both score and member, or
//! two requests landing in the same millisecond collide into one zset entry
//! and the window undercounts bursts. `attome_s2s::rate_limit::check_with_nonce`
//! is the script that fix's own comment names as the pattern's origin, so it
//! gets the identical proof: fire concurrent requests and confirm every one
//! is counted individually.
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `attome-cache/tests/rate_limit.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-s2s --test rate_limit
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_s2s::rate_limit;
use attome_types::AppError;
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
    let client_id = format!("test-client-{}", Uuid::new_v4());

    for _ in 0..5 {
        let nonce = Uuid::new_v4().to_string();
        rate_limit::check_with_nonce(
            &attome_cache::Store::Redis(pool.clone()),
            &client_id,
            &nonce,
            10,
        )
        .await
        .expect("under-limit request must be allowed");
    }
}

#[tokio::test]
async fn rejects_a_replayed_nonce() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let client_id = format!("test-client-{}", Uuid::new_v4());
    let nonce = Uuid::new_v4().to_string();

    rate_limit::check_with_nonce(
        &attome_cache::Store::Redis(pool.clone()),
        &client_id,
        &nonce,
        10,
    )
    .await
    .expect("first use of the nonce must be allowed");

    let result = rate_limit::check_with_nonce(
        &attome_cache::Store::Redis(pool.clone()),
        &client_id,
        &nonce,
        10,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a replayed nonce must be rejected as a conflict, got {result:?}"
    );
}

#[tokio::test]
async fn rejects_once_the_limit_is_exceeded() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let client_id = format!("test-client-{}", Uuid::new_v4());

    for _ in 0..3 {
        let nonce = Uuid::new_v4().to_string();
        rate_limit::check_with_nonce(
            &attome_cache::Store::Redis(pool.clone()),
            &client_id,
            &nonce,
            3,
        )
        .await
        .expect("requests up to the limit must be allowed");
    }

    let nonce = Uuid::new_v4().to_string();
    let result = rate_limit::check_with_nonce(
        &attome_cache::Store::Redis(pool.clone()),
        &client_id,
        &nonce,
        3,
    )
    .await;
    assert!(
        matches!(
            result,
            Err(AppError::TooManyRequests {
                retry_after_secs: None
            })
        ),
        "the request past the limit must be rejected, got {result:?}"
    );
}

/// Regression test for the exact bug the audit flagged in the sibling
/// `attome-cache` limiter and that was never ported here: the script's `ZADD`
/// used `now_ms` as both score and member, so two requests landing in the
/// same millisecond collided into a single zset entry and undercounted.
/// Firing a burst of concurrent requests (near-guaranteed millisecond
/// collisions under `tokio`'s scheduler) must still count every one of them
/// individually.
#[tokio::test]
async fn concurrent_requests_in_the_same_millisecond_are_not_undercounted() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let client_id = format!("test-client-{}", Uuid::new_v4());
    let limit = 5;

    let mut handles = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        let client_id = client_id.clone();
        handles.push(tokio::spawn(async move {
            let nonce = Uuid::new_v4().to_string();
            rate_limit::check_with_nonce(
                &attome_cache::Store::Redis(pool.clone()),
                &client_id,
                &nonce,
                limit,
            )
            .await
        }));
    }

    let mut allowed = 0;
    let mut rejected = 0;
    for handle in handles {
        match handle.await.expect("task must not panic") {
            Ok(()) => allowed += 1,
            Err(AppError::TooManyRequests {
                retry_after_secs: None,
            }) => rejected += 1,
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
async fn the_window_expires_so_an_old_burst_does_not_permanently_block_the_client() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let client_id = format!("test-client-{}", Uuid::new_v4());
    let rl_key = format!("s2s:rl:{client_id}");

    let nonce_a = Uuid::new_v4().to_string();
    rate_limit::check_with_nonce(
        &attome_cache::Store::Redis(pool.clone()),
        &client_id,
        &nonce_a,
        1,
    )
    .await
    .expect("first request must be allowed");

    let nonce_b = Uuid::new_v4().to_string();
    assert!(matches!(
        rate_limit::check_with_nonce(
            &attome_cache::Store::Redis(pool.clone()),
            &client_id,
            &nonce_b,
            1
        )
        .await,
        Err(AppError::TooManyRequests {
            retry_after_secs: None
        })
    ));

    // The zset key must carry a TTL (not linger forever) — proves the
    // script's EXPIRE actually ran, same guarantee the four-call version gave.
    let ttl: i64 = pool.ttl(&rl_key).await.expect("read ttl");
    assert!(
        ttl > 0 && ttl <= 61,
        "the rate-limit key must have a bounded TTL, got {ttl}"
    );
}

/// B10 boundary: the middleware accepts a timestamp anywhere in
/// `now ± TIMESTAMP_WINDOW_SECS`, so a request stamped a full window in the
/// future is still acceptable `2·window` seconds after the server received
/// it. The nonce Redis actually stores must therefore outlive a single
/// window, or a byte-for-byte replay at `t0 + window + Δ` lands on an
/// already-expired nonce and is accepted as fresh. The guard script takes
/// its TTL from `NONCE_TTL_SECS` (not a caller argument), so this reads the
/// live TTL back and pins it strictly above the window.
#[tokio::test]
async fn a_used_nonce_outlives_the_whole_timestamp_window() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let client_id = format!("test-client-{}", Uuid::new_v4());
    let nonce = Uuid::new_v4().to_string();
    let nonce_key = format!("s2s:nonce:{client_id}:{nonce}");

    rate_limit::check_with_nonce(
        &attome_cache::Store::Redis(pool.clone()),
        &client_id,
        &nonce,
        10,
    )
    .await
    .expect("first use of the nonce must be allowed");

    let ttl: i64 = pool.ttl(&nonce_key).await.expect("read nonce ttl");
    let window = rate_limit::TIMESTAMP_WINDOW_SECS as i64;
    let configured = rate_limit::NONCE_TTL_SECS as i64;
    assert!(
        ttl > window,
        "a used nonce must stay stored past the {window}s timestamp window \
         (a replay at t0 + window + delta is still timestamp-valid), got ttl={ttl}"
    );
    assert!(
        ttl <= configured && ttl >= configured - 5,
        "the stored TTL must be the derived NONCE_TTL_SECS={configured}, got {ttl}"
    );
}
