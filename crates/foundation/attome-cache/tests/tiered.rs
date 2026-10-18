//! Z3-T11: the tiered cache against a real Redis or Dragonfly: two nodes share
//! the Redis tier, a store that is down falls back to the source or fails
//! closed as its spec says, and a sealed cache never stores the value as is.
//!
//! Requires a Redis or Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT`
//! (defaults 127.0.0.1:6379), like `rate_limit.rs`; skipped without one.
//!
//! ```powershell
//! cargo test -p attome-cache --test tiered
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;
use std::time::Duration;

use attome_cache::Store;
use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
use attome_cache::tiered::{TieredCache, ValueSealer};
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

/// A pool pointed at a port nothing listens on: every call fails or times
/// out, as a Redis that is down does.
fn dead_store() -> Store {
    let config = RedisConfig::from_url("redis://127.0.0.1:1").expect("config");
    let pool = RedisPool::new(config, None, None, None, 1).expect("pool");
    pool.connect();
    Store::Redis(pool)
}

const fn spec(
    name: &'static str,
    purpose: &'static str,
    sensitivity: CacheSensitivity,
    failure: FailureMode,
) -> CacheSpec {
    CacheSpec {
        name,
        crate_name: "cache",
        purpose,
        source_of_truth: "a test",
        ttl: Duration::from_secs(60),
        jitter_pct: 10,
        l1_capacity: 100,
        partition: Partition::Shared,
        sensitivity,
        failure,
        invalidation: "none",
        cold_start: "empty",
        warm_on_start: false,
    }
}

static SHARED: CacheSpec = spec(
    "cache:it_shared",
    "it_shared",
    CacheSensitivity::Plain,
    FailureMode::FallBackToSource,
);
static FALLBACK: CacheSpec = spec(
    "cache:it_fallback",
    "it_fallback",
    CacheSensitivity::Plain,
    FailureMode::FallBackToSource,
);
static CLOSED: CacheSpec = spec(
    "cache:it_closed",
    "it_closed",
    CacheSensitivity::Plain,
    FailureMode::FailClosed,
);
static SEALED: CacheSpec = spec(
    "cache:it_sealed",
    "it_sealed",
    CacheSensitivity::EncryptedInRedis,
    FailureMode::FallBackToSource,
);

/// A reversible stand-in for `attome_auth::envelope::CacheSealer`.
struct Reverse;

impl ValueSealer for Reverse {
    fn seal(&self, plaintext: &str) -> Result<String, AppError> {
        Ok(format!(
            "sealed:{}",
            plaintext.chars().rev().collect::<String>()
        ))
    }

    fn open(&self, sealed: &str) -> Result<String, AppError> {
        sealed
            .strip_prefix("sealed:")
            .map(|s| s.chars().rev().collect())
            .ok_or(AppError::NotFound)
    }
}

#[tokio::test]
async fn redis_tier_shared_between_two_instances() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let id = Uuid::new_v4().to_string();
    let a = TieredCache::<u32>::new(&SHARED, Some(Store::Redis(pool.clone()))).unwrap();
    let b = TieredCache::<u32>::new(&SHARED, Some(Store::Redis(pool))).unwrap();
    assert_eq!(a.get_or_load(&id, async { Ok(7) }).await.unwrap(), 7);
    let from_b = b
        .get_or_load(&id, async {
            Err(AppError::internal("the loader must not run"))
        })
        .await
        .unwrap();
    assert_eq!(from_b, 7, "node B reads node A's value from Redis");
}

#[tokio::test]
async fn fallback_on_redis_down_runs_loader() {
    let cache = TieredCache::<u32>::new(&FALLBACK, Some(dead_store())).unwrap();
    let value = tokio::time::timeout(
        Duration::from_secs(5),
        cache.get_or_load("k", async { Ok(3) }),
    )
    .await
    .expect("a down store is bounded, never a hang")
    .unwrap();
    assert_eq!(value, 3);
}

#[tokio::test]
async fn fail_closed_spec_errors_on_redis_down() {
    let cache = TieredCache::<u32>::new(&CLOSED, Some(dead_store())).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        cache.get_or_load("k", async { Ok(3) }),
    )
    .await
    .expect("a down store is bounded, never a hang");
    assert!(
        matches!(result, Err(AppError::Overloaded("cache"))),
        "{result:?}"
    );
}

#[tokio::test]
async fn encrypted_spec_stores_ciphertext() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let store = Store::Redis(pool);
    let sealer: Arc<dyn ValueSealer> = Arc::new(Reverse);
    assert!(
        TieredCache::<String>::new(&SEALED, Some(store.clone())).is_err(),
        "a sealed cache over Redis needs a sealer"
    );
    let id = Uuid::new_v4().to_string();
    let a =
        TieredCache::<String>::with_sealer(&SEALED, Some(store.clone()), Some(Arc::clone(&sealer)))
            .unwrap();
    a.get_or_load(&id, async { Ok("salary 18250".to_owned()) })
        .await
        .unwrap();
    let raw = store.get(SEALED.key(&id)).await.unwrap().expect("stored");
    assert!(raw.starts_with("sealed:"), "{raw}");
    assert!(!raw.contains("18250"), "{raw}");
    let b = TieredCache::<String>::with_sealer(&SEALED, Some(store), Some(sealer)).unwrap();
    let read = b
        .get_or_load(&id, async {
            Err(AppError::internal("the loader must not run"))
        })
        .await
        .unwrap();
    assert_eq!(read, "salary 18250");
}
