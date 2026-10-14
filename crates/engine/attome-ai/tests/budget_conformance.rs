//! **ai-10-10 A0.1 × attome-inference BIN-G1** — the atomic admission path
//! `budget_guard::admit` uses (`budget_guard::reserve`: one `reserve_all` Lua
//! script, then `budget::check` for the retry hint) driven through
//! `attome_inference::budget::CONFORMANCE`, row by row, against a live
//! Redis/Dragonfly. The pure table proves the policy; this proves the store
//! and the policy agree, so the atomic path cannot quietly re-grow the deleted
//! "the window rolled, allow it" branch (BIN-F7/BIN-D8).
//!
//! The store counts spend in buckets (`token_window::bucket_secs`), so a row's
//! `elapsed_secs` is planted as the bucket that many seconds old, rounded **up**
//! to the bucket width. A row whose rounded age lies beyond the window cannot
//! exist in the store — the script evicts that bucket — and is asserted from
//! the store's side instead: eviction is the reset, and the request is admitted.
//!
//! Needs only Redis (no Postgres): `TEST_REDIS_HOST`/`TEST_REDIS_PORT`,
//! defaults 127.0.0.1:6379, the same convention as attome-cache's
//! `tests/token_window.rs`.
//!
//! ```powershell
//! $env:TEST_REDIS_PORT="6380"; cargo test -p attome-ai --test budget_conformance
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_ai::budget_guard::{Admission, reserve};
use attome_cache::RedisPool;
use attome_cache::token_window::{self, ReserveWindow};
use attome_inference::budget::{self, Budget, BudgetVerdict, CONFORMANCE};
use fred::interfaces::{ClientLike, HashesInterface, KeysInterface};
use fred::prelude::RedisConfig;

async fn test_pool() -> Option<RedisPool> {
    let (host, port) = attome_testkit::test_redis()?;
    let config = RedisConfig::from_url(&format!("redis://{host}:{port}")).expect("redis config");
    let pool = RedisPool::new(config, None, None, None, 2).expect("redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to the local test Redis/Dragonfly");
    Some(pool)
}

fn test_key() -> String {
    format!("test:attome-ai:budget-conformance:{}", uuid::Uuid::new_v4())
}

/// Waits out the last seconds of the current bucket, so a bucket planted now
/// and the script's own "now" agree on which bucket is current.
async fn away_from_a_bucket_edge(width: u64) {
    let into = chrono::Utc::now().timestamp().rem_euclid(width as i64) as u64;
    if width - into < 3 {
        tokio::time::sleep(Duration::from_secs(width - into + 1)).await;
    }
}

/// Plants `tokens` in the bucket `age_buckets` behind the current one.
async fn plant(pool: &RedisPool, key: &str, window: Duration, age_buckets: u64, tokens: u64) {
    let width = token_window::bucket_secs(window) as i64;
    let bucket = chrono::Utc::now().timestamp() / width - age_buckets as i64;
    let _: i64 = pool
        .hset(key, (bucket.to_string().as_str(), tokens as i64))
        .await
        .expect("plant a bucket");
    let _: bool = pool
        .pexpire(key, (window.as_millis() as i64) * 2, None)
        .await
        .expect("expire the planted key");
}

#[tokio::test]
async fn the_atomic_admission_path_holds_every_conformance_row() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let mut driven = 0usize;
    let mut evicted = 0usize;
    for case in CONFORMANCE {
        let window = Duration::from_secs(case.window_secs);
        let width = token_window::bucket_secs(window);
        let key = test_key();
        away_from_a_bucket_edge(width).await;

        let age_buckets = case.elapsed_secs.div_ceil(width);
        let representable = case.consumed == 0 || age_buckets * width <= case.window_secs;
        if case.consumed > 0 {
            plant(&pool, &key, window, age_buckets, case.consumed).await;
        }
        let windows = [ReserveWindow {
            key: &key,
            window,
            limit: case.tokens,
        }];
        let admission = reserve(
            &attome_cache::Store::Redis(pool.clone()),
            &windows,
            case.estimated,
        )
        .await
        .unwrap_or_else(|e| panic!("row `{}`: reserve failed: {e}", case.name));
        let held = token_window::read(&attome_cache::Store::Redis(pool.clone()), &key, window)
            .await
            .expect("read back")
            .consumed;

        if !representable {
            // The planted bucket is older than the window: the script evicts
            // it, and the empty window admits whatever fits the budget.
            assert!(
                case.estimated <= case.tokens,
                "row `{}` is only meaningful here when the estimate fits",
                case.name
            );
            assert_eq!(admission, Admission::Reserved, "row `{}`", case.name);
            assert_eq!(
                held, case.estimated,
                "row `{}`: eviction is the reset",
                case.name
            );
            evicted += 1;
            continue;
        }

        match (case.allowed, admission) {
            (true, Admission::Reserved) => assert_eq!(
                held,
                case.consumed + case.estimated,
                "row `{}`: an admission charges its estimate",
                case.name
            ),
            (
                false,
                Admission::Refused {
                    index,
                    consumed,
                    retry_after,
                },
            ) => {
                assert_eq!(index, 0, "row `{}`", case.name);
                assert_eq!(consumed, case.consumed, "row `{}`", case.name);
                assert_eq!(
                    held, case.consumed,
                    "row `{}`: a refusal charges nothing",
                    case.name
                );
                let store_elapsed = if case.consumed == 0 {
                    0
                } else {
                    age_buckets * width
                };
                let expected = match budget::check(
                    Budget {
                        tokens: case.tokens,
                        window,
                    },
                    case.consumed,
                    case.estimated,
                    Duration::from_secs(store_elapsed),
                ) {
                    BudgetVerdict::Rejected { retry_after } => retry_after,
                    other => panic!("row `{}`: the policy admitted: {other:?}", case.name),
                };
                assert_eq!(retry_after, expected, "row `{}`", case.name);
                // Rounding the age up can only shorten the hint, so a pinned
                // floor of 1 s holds at either age.
                if let Some(pinned) = case.retry_after_secs
                    && (case.consumed == 0 || store_elapsed == case.elapsed_secs || pinned == 1)
                {
                    assert_eq!(
                        retry_after,
                        Duration::from_secs(pinned),
                        "row `{}`: the table's pinned hint",
                        case.name
                    );
                }
                assert!(
                    retry_after >= Duration::from_secs(1) && retry_after <= window,
                    "row `{}`: {retry_after:?}",
                    case.name
                );
            }
            (allowed, admission) => panic!(
                "row `{}` expected allowed={allowed}, the atomic path said {admission:?}",
                case.name
            ),
        }
        driven += 1;
    }
    assert_eq!(driven + evicted, CONFORMANCE.len());
    assert!(
        driven >= CONFORMANCE.len() - 1,
        "only the past-the-window row may be evicted"
    );
}

/// A refusal on the last window (the deployment-wide web-chat key, in
/// `admit`'s order) charges neither the session nor the caller window.
#[tokio::test]
async fn a_refusal_on_any_window_charges_none_of_them() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let hour = Duration::from_secs(3_600);
    let day = Duration::from_secs(86_400);
    let (session, caller, deployment) = (test_key(), test_key(), test_key());
    away_from_a_bucket_edge(token_window::bucket_secs(day)).await;
    plant(&pool, &deployment, day, 0, 1_000).await;
    let windows = [
        ReserveWindow {
            key: &session,
            window: hour,
            limit: 10_000,
        },
        ReserveWindow {
            key: &caller,
            window: day,
            limit: 10_000,
        },
        ReserveWindow {
            key: &deployment,
            window: day,
            limit: 1_000,
        },
    ];
    let admission = reserve(&attome_cache::Store::Redis(pool.clone()), &windows, 10)
        .await
        .expect("reserve");
    assert!(
        matches!(
            admission,
            Admission::Refused {
                index: 2,
                consumed: 1_000,
                ..
            }
        ),
        "{admission:?}"
    );
    for (key, window) in [(&session, hour), (&caller, day)] {
        let held = token_window::read(&attome_cache::Store::Redis(pool.clone()), key, window)
            .await
            .expect("read")
            .consumed;
        assert_eq!(held, 0, "a refused admission charged {key}");
    }
}

/// ai-10-10 A0.1: a Redis outage refuses. `reserve` against a store that is
/// not there is `Err` (which `admit` returns as the refusal), never an
/// admission, and it comes back inside the request-path bound rather than
/// hanging the generation behind it.
#[tokio::test]
async fn an_unreachable_store_refuses_the_admission() {
    // Port 1 on loopback: nothing listens, so every connect is refused.
    let config = RedisConfig::from_url("redis://127.0.0.1:1").expect("redis config");
    let pool = RedisPool::new(config, None, None, None, 1).expect("redis pool");
    pool.connect();
    let key = test_key();
    let windows = [ReserveWindow {
        key: &key,
        window: Duration::from_secs(3_600),
        limit: 1_000_000,
    }];
    let started = std::time::Instant::now();
    let outcome = reserve(&attome_cache::Store::Redis(pool.clone()), &windows, 10).await;
    assert!(
        outcome.is_err(),
        "an unreachable budget store must fail closed, got {outcome:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the refusal is bounded: {:?}",
        started.elapsed()
    );
}

/// ai-10-10 A0.1's exit test, through the path `admit` takes: 50 concurrent
/// admissions against a budget fitting 10 admit exactly 10.
#[tokio::test]
async fn fifty_concurrent_admissions_against_room_for_ten_admit_exactly_ten() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = test_key();
    let hour = Duration::from_secs(3_600);
    let estimate = 100u64;
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let (pool, key) = (pool.clone(), key.clone());
        tasks.push(tokio::spawn(async move {
            let windows = [ReserveWindow {
                key: &key,
                window: hour,
                limit: 10 * estimate,
            }];
            reserve(
                &attome_cache::Store::Redis(pool.clone()),
                &windows,
                estimate,
            )
            .await
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        if task.await.expect("join").expect("reserve") == Admission::Reserved {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 10);
    let held = token_window::read(&attome_cache::Store::Redis(pool.clone()), &key, hour)
        .await
        .expect("read")
        .consumed;
    assert_eq!(
        held,
        10 * estimate,
        "the window holds exactly the allowance"
    );
}
