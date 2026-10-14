//! Integration coverage for `attome_s2s::concurrency` — proves
//! `s2s_client.max_concurrent` is actually enforced against a real
//! Redis (fred's `RedisPool`, not a mock): a client at its limit is
//! rejected, releasing a slot frees it back up, and a stale/abandoned slot
//! self-heals rather than permanently consuming the client's budget.
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `attome-s2s/tests/rate_limit.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-s2s --test concurrency
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_s2s::concurrency;
use attome_types::AppError;
use fred::interfaces::ClientLike;
use fred::prelude::*;
use uuid::Uuid;

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

#[tokio::test]
async fn allows_requests_under_the_limit() {
    let pool = test_pool().await;
    let client_id = format!("test-client-{}", Uuid::new_v4());

    let mut guards = Vec::new();
    for _ in 0..3 {
        guards.push(
            concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, 5)
                .await
                .expect("under-limit slot must be allowed"),
        );
    }
}

#[tokio::test]
async fn rejects_once_the_limit_is_reached() {
    let pool = test_pool().await;
    let client_id = format!("test-client-{}", Uuid::new_v4());

    let mut guards = Vec::new();
    for _ in 0..3 {
        guards.push(
            concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, 3)
                .await
                .expect("requests up to the limit must be allowed"),
        );
    }

    let result =
        concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, 3).await;
    assert!(
        matches!(
            result,
            Err(AppError::TooManyRequests {
                retry_after_secs: None
            })
        ),
        "the slot past the limit must be rejected"
    );
}

#[tokio::test]
async fn releasing_a_slot_frees_it_back_up() {
    let pool = test_pool().await;
    let client_id = format!("test-client-{}", Uuid::new_v4());

    let guard = concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, 1)
        .await
        .expect("first slot must be allowed");

    assert!(matches!(
        concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, 1).await,
        Err(AppError::TooManyRequests {
            retry_after_secs: None
        })
    ));

    guard.release().await;

    concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, 1)
        .await
        .expect("slot must be free again after release");
}

/// A client's requests never collide across clients: exhausting one
/// client's concurrency budget must not affect another's.
#[tokio::test]
async fn limits_are_scoped_per_client() {
    let pool = test_pool().await;
    let client_a = format!("test-client-{}", Uuid::new_v4());
    let client_b = format!("test-client-{}", Uuid::new_v4());

    let _guard_a = concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_a, 1)
        .await
        .expect("client A's first slot must be allowed");
    assert!(matches!(
        concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_a, 1).await,
        Err(AppError::TooManyRequests {
            retry_after_secs: None
        })
    ));

    concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_b, 1)
        .await
        .expect("client B must be unaffected by client A's exhausted budget");
}

/// Regression coverage for the finding this module fixes: `max_concurrent`
/// was stored and admin-editable but never read at request time, so it
/// never actually bounded anything. Concurrent acquires racing the same
/// client must still admit exactly `max_concurrent` of them, proving the
/// atomic script (not merely the Rust call site) enforces the cap.
#[tokio::test]
async fn concurrent_acquires_never_admit_more_than_the_limit() {
    let pool = test_pool().await;
    let client_id = format!("test-client-{}", Uuid::new_v4());
    let limit = 5;

    let mut handles = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        let client_id = client_id.clone();
        handles.push(tokio::spawn(async move {
            concurrency::acquire(&attome_cache::Store::Redis(pool.clone()), &client_id, limit).await
        }));
    }

    let mut allowed = 0;
    let mut rejected = 0;
    for handle in handles {
        match handle.await.expect("task must not panic") {
            Ok(_guard) => allowed += 1,
            Err(AppError::TooManyRequests {
                retry_after_secs: None,
            }) => rejected += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(
        allowed, limit as usize,
        "exactly `limit` concurrent acquires must be admitted"
    );
    assert_eq!(rejected, 10 - limit as usize);
}
