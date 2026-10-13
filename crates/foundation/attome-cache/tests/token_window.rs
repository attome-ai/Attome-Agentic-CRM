//! BCA-41 — live coverage for `attome_cache::token_window` (bucketed token
//! accumulator) and BCA-31's atomic `reserve_all` admission.
//!
//! The module shipped with no live suite at all (BCA-F7): its Lua scripts — the
//! only place `HDEL`/`HINCRBY`/`PEXPIRE` semantics for an AI budget are
//! expressed — had never run outside a manual check. This file is what
//! `scripts/test-attome-cache-backends.ps1` runs against every pinned
//! Dragonfly/Redis image, so a Lua portability break (the `unpack` class of
//! bug) surfaces on the matrix rather than in production.
//!
//! The concurrency case is BCA-31's acceptance: 20 concurrent
//! `reserve_all(estimate)` calls against an allowance of 5 x estimate must
//! reserve exactly 5. Under the old read-three-windows-then-add sequence that
//! number was unbounded (BCA-F2).
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `tests/rate_limit.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-cache --test token_window
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_cache::token_window::{self, Reservation, ReserveWindow, WindowState};
use fred::interfaces::{ClientLike, HashesInterface, KeysInterface};
use fred::prelude::*;
use uuid::Uuid;

const HOUR: Duration = Duration::from_secs(60 * 60);

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
    format!("test:token-window:{}", Uuid::new_v4())
}

#[tokio::test]
async fn an_absent_key_reads_as_zero_consumed_and_zero_elapsed() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let state = token_window::read(&pool, &test_key(), HOUR)
        .await
        .expect("read an absent window");
    assert_eq!(state.consumed, 0);
    assert_eq!(state.elapsed, Duration::ZERO);
}

#[tokio::test]
async fn charge_then_read_reports_the_tokens_and_an_elapsed_inside_the_window() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    token_window::add(&pool, &key, 250, HOUR)
        .await
        .expect("charge 250");
    token_window::add(&pool, &key, 125, HOUR)
        .await
        .expect("charge 125");

    let state = token_window::read(&pool, &key, HOUR).await.expect("read");
    assert_eq!(state.consumed, 375, "charges must sum, not overwrite");
    assert!(
        state.elapsed < HOUR,
        "a just-written window cannot be a full window old: {:?}",
        state.elapsed
    );
}

/// The key's TTL must outlive the window it covers, or a still-relevant bucket
/// disappears and the caller silently gets allowance back (the failure mode the
/// module doc calls out).
#[tokio::test]
async fn the_key_ttl_outlives_the_window() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    token_window::add(&pool, &key, 10, HOUR)
        .await
        .expect("charge");

    let ttl_ms: i64 = pool.ttl(&key).await.expect("read TTL");
    assert!(
        ttl_ms > 0,
        "a charged window must carry a TTL, got {ttl_ms}"
    );
    // `ttl` is whole seconds; the window is an hour plus one bucket.
    assert!(
        ttl_ms > 3_600,
        "TTL must outlive the one-hour window: {ttl_ms}"
    );
}

/// Eviction is by explicit bucket cutoff, not by the key TTL — a
/// continuously-active caller must not keep counting buckets from previous
/// windows. Planting a bucket far older than the cutoff is the only way to age
/// one without sleeping for a whole window.
#[tokio::test]
async fn eviction_drops_buckets_that_aged_out() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    // `bucket_secs(1 hour)` is 60, so the cutoff is `now_bucket - 60`.
    let now_bucket = chrono::Utc::now().timestamp() / 60;
    let stale_bucket = (now_bucket - 100).to_string();
    let _: i64 = pool
        .hset(&key, (stale_bucket.as_str(), 999_i64))
        .await
        .expect("plant a stale bucket");

    let state = token_window::read(&pool, &key, HOUR).await.expect("read");
    assert_eq!(
        state.consumed, 0,
        "a bucket from a previous window must not be counted"
    );
    let fields: i64 = pool.hlen(&key).await.expect("HLEN");
    assert_eq!(
        fields, 0,
        "the stale field must be deleted, not just skipped"
    );
}

/// A reconciliation refund must only ever under-count inside a window, never
/// wrap: the read path clamps the summed total at zero.
#[tokio::test]
async fn a_refund_below_zero_clamps_the_reported_sum_at_zero() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    token_window::charge(&pool, &key, -100_000, HOUR)
        .await
        .expect("an over-refund must be accepted");

    let state = token_window::read(&pool, &key, HOUR).await.expect("read");
    assert_eq!(state.consumed, 0, "a negative sum must clamp at zero");
}

fn window(key: &str, limit: u64) -> ReserveWindow<'_> {
    ReserveWindow {
        key,
        window: HOUR,
        limit,
    }
}

/// BCA-31 acceptance: 20 concurrent reservations of `estimate` against an
/// allowance of exactly 5 x estimate must reserve exactly 5, and the window
/// must hold exactly 5 x estimate afterwards — no over-admission, no leak.
#[tokio::test]
async fn concurrent_reservations_reserve_exactly_the_allowance() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();
    let estimate = 10u64;
    let limit = estimate * 5;

    let mut handles = Vec::new();
    for _ in 0..20 {
        let pool = pool.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            token_window::reserve_all(&pool, &[window(&key, limit)], estimate).await
        }));
    }

    let mut reserved = 0usize;
    let mut refused = 0usize;
    for handle in handles {
        match handle.await.expect("task must not panic") {
            Ok(Reservation::Reserved(r)) => {
                assert_eq!(r.tokens, estimate);
                reserved += 1;
            }
            Ok(Reservation::Refused(_)) => refused += 1,
            Err(e) => panic!("reserve_all must not fail closed against a live store: {e}"),
        }
    }

    assert_eq!(
        reserved, 5,
        "exactly the allowance's worth of reservations must be admitted"
    );
    assert_eq!(refused, 15);

    let state = token_window::read(&pool, &key, HOUR).await.expect("read");
    assert_eq!(
        state.consumed, limit,
        "the stored window must hold exactly the admitted total, never more"
    );
}

/// A sequential reservation past the limit is refused with the window that ran
/// out and what it held, so the caller can build `retry_after` from it.
#[tokio::test]
async fn reserve_all_refuses_once_the_window_is_full() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    let first = token_window::reserve_all(&pool, &[window(&key, 50)], 50)
        .await
        .expect("reserve the whole allowance");
    assert!(matches!(first, Reservation::Reserved(_)));

    let second = token_window::reserve_all(&pool, &[window(&key, 50)], 1)
        .await
        .expect("a refusal is not an error");
    match second {
        Reservation::Refused(refusal) => {
            assert_eq!(refusal.index, 0);
            assert_eq!(refusal.state.consumed, 50);
            // The window was filled moments ago, so its oldest bucket is the
            // current one and its age is legitimately zero — `elapsed` is the
            // age of the oldest *counted* bucket, not a measure of occupancy.
            // `a_full_window_is_not_a_reset_at_the_boundary` pins that reading;
            // here the point is only that it stays inside the window.
            assert!(
                refusal.state.elapsed < HOUR,
                "a just-written window cannot be a full window old: {:?}",
                refusal.state.elapsed
            );
        }
        Reservation::Reserved(_) => panic!("a full window must refuse"),
    }
}

/// All-or-nothing across windows: if the second window has no room, the first
/// must not be charged. This is the property the read-then-add sequence could
/// not have.
#[tokio::test]
async fn reserve_all_charges_nothing_when_any_window_refuses() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let full = test_key();
    let empty = test_key();

    token_window::reserve_all(&pool, &[window(&full, 5)], 5)
        .await
        .expect("fill the second window");

    let outcome = token_window::reserve_all(&pool, &[window(&empty, 1_000), window(&full, 5)], 1)
        .await
        .expect("a refusal is not an error");
    match outcome {
        Reservation::Refused(refusal) => assert_eq!(refusal.index, 1, "window 1 is the full one"),
        Reservation::Reserved(_) => panic!("a full window must refuse the whole reservation"),
    }

    let untouched = token_window::read(&pool, &empty, HOUR).await.expect("read");
    assert_eq!(
        untouched.consumed, 0,
        "no window may be charged when another refuses"
    );
}

/// BIN-5.2's row: an estimate larger than the whole allowance can never be
/// admitted, however empty the window — the pure policy refuses it, so the
/// atomic path must too.
#[tokio::test]
async fn reserve_all_refuses_an_estimate_larger_than_the_whole_allowance() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    let outcome = token_window::reserve_all(&pool, &[window(&key, 100)], 101)
        .await
        .expect("a refusal is not an error");
    assert!(matches!(outcome, Reservation::Refused(_)));

    let state: WindowState = token_window::read(&pool, &key, HOUR).await.expect("read");
    assert_eq!(
        state.consumed, 0,
        "a refused reservation must charge nothing"
    );
}

/// The window boundary is not a reset: a full window with `elapsed` at the
/// boundary still has no room (BIN-F7). Planting the current bucket keeps the
/// sum at the limit without waiting an hour.
#[tokio::test]
async fn a_full_window_is_not_a_reset_at_the_boundary() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();

    let now_bucket = chrono::Utc::now().timestamp() / 60;
    let current = now_bucket.to_string();
    let _: i64 = pool
        .hset(&key, (current.as_str(), 100_i64))
        .await
        .expect("plant the current bucket at the limit");

    let outcome = token_window::reserve_all(&pool, &[window(&key, 100)], 1)
        .await
        .expect("a refusal is not an error");
    match outcome {
        Reservation::Refused(refusal) => {
            assert_eq!(refusal.state.consumed, 100);
            assert_eq!(
                refusal.state.elapsed,
                Duration::ZERO,
                "the current bucket has just started, so its age is zero"
            );
        }
        Reservation::Reserved(_) => panic!("a full window must not be treated as reset"),
    }
}
