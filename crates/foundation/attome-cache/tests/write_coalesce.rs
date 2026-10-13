//! P-job-system-hardening (b) — integration coverage for
//! `attome_cache::write_coalesce`'s atomic Lua-script drain against a real
//! Redis/Dragonfly (fred's `RedisPool`, not a mock): proves concurrent
//! `set` calls for the same field coalesce to the last write, and that
//! `drain` empties the hash atomically (a second drain sees nothing left).
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `tests/rate_limit.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-cache --test write_coalesce
//! ```
//!
//! These are the live round trips: `scripts/test-attome-cache-backends.ps1` runs
//! this suite against every pinned Dragonfly/Redis image, plaintext, as part of
//! the crate's release gate. (The header used to say they had never been run —
//! true when written, and false since the local matrix replaced the retired CI
//! lane; BCA-44/BCA-F8.)

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::write_coalesce;
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

fn test_key() -> String {
    format!("test:write-coalesce:{}", Uuid::new_v4())
}

#[tokio::test]
async fn drain_returns_every_field_set_since_the_last_drain() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    write_coalesce::set(&pool, &key, "a", "1")
        .await
        .expect("set a");
    write_coalesce::set(&pool, &key, "b", "2")
        .await
        .expect("set b");

    let mut drained = write_coalesce::drain(&pool, &key).await.expect("drain");
    drained.sort();
    assert_eq!(
        drained,
        vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string())
        ]
    );
}

#[tokio::test]
async fn a_second_write_to_the_same_field_before_drain_coalesces_to_the_latest_value() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    write_coalesce::set(&pool, &key, "field", "first")
        .await
        .expect("set first");
    write_coalesce::set(&pool, &key, "field", "second")
        .await
        .expect("set second");

    let drained = write_coalesce::drain(&pool, &key).await.expect("drain");
    assert_eq!(
        drained,
        vec![("field".to_string(), "second".to_string())],
        "only the latest write for a field must survive to the drain, not both"
    );
}

#[tokio::test]
async fn drain_clears_the_hash_so_a_second_drain_finds_nothing_left() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    write_coalesce::set(&pool, &key, "field", "value")
        .await
        .expect("set");
    let first_drain = write_coalesce::drain(&pool, &key)
        .await
        .expect("first drain");
    assert_eq!(first_drain.len(), 1);

    let second_drain = write_coalesce::drain(&pool, &key)
        .await
        .expect("second drain");
    assert!(
        second_drain.is_empty(),
        "draining an already-drained hash must return nothing, not the same values again"
    );
}

#[tokio::test]
async fn draining_a_hash_that_was_never_written_to_returns_empty() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    let drained = write_coalesce::drain(&pool, &key).await.expect("drain");
    assert!(drained.is_empty());
}

/// M61 Phase 1 (API usage analytics, D-438) — `incr`'s whole point: unlike
/// `set`, concurrent writes to the same field must sum, not overwrite.
#[tokio::test]
async fn concurrent_incr_calls_to_the_same_field_sum_rather_than_overwrite() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    write_coalesce::incr(&pool, &key, "route", 1, 60)
        .await
        .expect("incr 1");
    write_coalesce::incr(&pool, &key, "route", 1, 60)
        .await
        .expect("incr 2");
    write_coalesce::incr(&pool, &key, "route", 3, 60)
        .await
        .expect("incr 3");

    let drained = write_coalesce::drain(&pool, &key).await.expect("drain");
    assert_eq!(
        drained,
        vec![("route".to_string(), "5".to_string())],
        "three increments (1+1+3) must sum to 5, not overwrite to the last write's value"
    );
}

/// `drain` is shape-agnostic — a hash with fields written by both `set` and
/// `incr` drains all of them together in one atomic HGETALL+DEL.
#[tokio::test]
async fn drain_reads_fields_written_by_either_set_or_incr() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    write_coalesce::set(&pool, &key, "touched_at", "2026-08-28T00:00:00Z")
        .await
        .expect("set");
    write_coalesce::incr(&pool, &key, "count", 4, 60)
        .await
        .expect("incr");

    let mut drained = write_coalesce::drain(&pool, &key).await.expect("drain");
    drained.sort();
    assert_eq!(
        drained,
        vec![
            ("count".to_string(), "4".to_string()),
            ("touched_at".to_string(), "2026-08-28T00:00:00Z".to_string()),
        ]
    );
}
