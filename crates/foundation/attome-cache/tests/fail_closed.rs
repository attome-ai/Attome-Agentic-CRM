//! BCA-42 — proof that every request-path control in this crate **fails
//! closed** and **inside its own bound** when the store stops answering.
//!
//! The crate declares a failure class for each Redis dependency (D-027):
//! rate limiting, the rw-pin, and the token window fail closed; coalescing and
//! the probes degrade. What was never tested is the *bound* — an operation that
//! eventually fails is still an outage if it holds the request for the
//! operator's `cache.timeout` (2000 ms) or, before BCA-13, forever.
//!
//! The stall is `docker pause`: the container's processes freeze but the TCP
//! connection stays open, so a command is written and simply never answered —
//! exactly the wedge a dead-but-connected store produces in production.
//! (`CLIENT PAUSE` was rejected: Dragonfly support for it is not part of the
//! matrix, and a paused container needs no server cooperation at all.)
//!
//! `#[ignore]`d because it pauses a Docker container. It needs a **throwaway**
//! Redis-compatible container that nothing else uses: `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` point at it and `TEST_REDIS_CONTAINER` names it. Never
//! point it at the dev or test stacks' containers.
//! `scripts/test-attome-cache-backends.ps1` runs it against every pinned image.
//!
//! ```powershell
//! docker run -d --name attome-cache-stall -p 127.0.0.1:16393:6379 redis:7
//! $env:TEST_REDIS_PORT = "16393"; $env:TEST_REDIS_CONTAINER = "attome-cache-stall"
//! cargo test -p attome-cache --test fail_closed -- --ignored --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_cache::{
    persistence, rate_limit, redis_ping, sticky_primary, token_window, write_coalesce,
};
use fred::interfaces::ClientLike;
use fred::prelude::*;
use uuid::Uuid;

/// Mirrors `attome_cache::timeouts::REQUEST_PATH`. The crate keeps these
/// `pub(crate)`, so an integration test cannot import them; the source-scan
/// test in `src/timeouts.rs` is what keeps the crate honest, and this file
/// repeats the values.
const REQUEST_PATH: Duration = Duration::from_millis(300);
/// Mirrors `attome_cache::timeouts::BACKGROUND`.
const BACKGROUND: Duration = Duration::from_millis(500);
/// Scheduler and Docker-CLI jitter on top of the bound itself. Still far
/// below fred's configured `cache.timeout` (2000 ms), which is what makes
/// these assertions prove the *crate's* bound fired rather than the operator's.
const SLACK: Duration = Duration::from_millis(700);

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

fn docker(args: &[&str]) {
    let status = std::process::Command::new("docker")
        .args(args)
        .status()
        .expect("run docker");
    assert!(status.success(), "docker {} failed", args.join(" "));
}

/// What one control did while the store was stalled: its name, how long it
/// took, and whether it failed closed.
type Measurement = (&'static str, Duration, bool);

#[tokio::test]
#[ignore = "pauses a throwaway Redis container; see this file's header"]
async fn every_control_fails_closed_within_its_crate_bound_while_the_store_is_stalled() {
    let container = std::env::var("TEST_REDIS_CONTAINER")
        .expect("set TEST_REDIS_CONTAINER to the throwaway container this test may pause");
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    assert!(
        redis_ping(&pool).await,
        "the store must answer before it is stalled, or this test proves nothing"
    );

    let key = format!("test:fail-closed:{}", Uuid::new_v4());
    let user = Uuid::now_v7();

    docker(&["pause", &container]);
    let mut measured: Vec<Measurement> = Vec::new();

    let started = Instant::now();
    let outcome = rate_limit::check(&pool, &key, 10).await;
    measured.push(("rate_limit::check", started.elapsed(), outcome.is_err()));

    let started = Instant::now();
    let outcome = token_window::read(&pool, &key, Duration::from_secs(3600)).await;
    measured.push(("token_window::read", started.elapsed(), outcome.is_err()));

    let started = Instant::now();
    let outcome = sticky_primary::check_pin(&pool, user).await;
    measured.push((
        "sticky_primary::check_pin",
        started.elapsed(),
        outcome == sticky_primary::PinCheck::RedisError,
    ));

    let started = Instant::now();
    let outcome = sticky_primary::pin_write_with_lsn(&pool, user, "0/0", 30).await;
    measured.push((
        "sticky_primary::pin_write_with_lsn",
        started.elapsed(),
        outcome.is_err(),
    ));

    let started = Instant::now();
    let outcome = write_coalesce::set(&pool, &key, "field", "value").await;
    measured.push(("write_coalesce::set", started.elapsed(), outcome.is_err()));

    let started = Instant::now();
    let outcome = write_coalesce::set_with_ttl(&pool, &key, "field", "value", 60).await;
    measured.push((
        "write_coalesce::set_with_ttl",
        started.elapsed(),
        outcome.is_err(),
    ));

    let started = Instant::now();
    let outcome = write_coalesce::incr(&pool, &key, "field", 1, 60).await;
    measured.push(("write_coalesce::incr", started.elapsed(), outcome.is_err()));

    let started = Instant::now();
    let outcome = persistence::probe(&pool).await;
    measured.push(("persistence::probe", started.elapsed(), outcome.is_err()));

    let started = Instant::now();
    let alive = redis_ping(&pool).await;
    measured.push(("redis_ping", started.elapsed(), !alive));

    // Unpause before asserting, so a failed assertion never leaves the
    // container frozen for the next suite.
    docker(&["unpause", &container]);

    for (name, elapsed, failed_closed) in &measured {
        assert!(
            *failed_closed,
            "{name} did not fail closed while the store was stalled"
        );
        let allowed = match *name {
            "persistence::probe" | "redis_ping" => BACKGROUND + SLACK,
            _ => REQUEST_PATH + SLACK,
        };
        assert!(
            *elapsed < allowed,
            "{name} took {elapsed:?}, past its crate bound ({allowed:?}) — a stalled store must \
             not hold a request for the operator's cache.timeout"
        );
    }
}

/// Second half of BCA-42: the controls that must NOT fail closed when the
/// store merely degrades. The coalescing buffer is the platform's declared
/// degrade-and-recover class, so a stalled store must not make it panic or
/// admit anything — it returns an error and the caller logs and continues. This
/// is the same measurement as above, kept separate so the intent is explicit
/// rather than an absence of assertions.
#[tokio::test]
#[ignore = "pauses a throwaway Redis container; see this file's header"]
async fn the_degrade_class_reports_an_error_rather_than_panicking() {
    let container = std::env::var("TEST_REDIS_CONTAINER")
        .expect("set TEST_REDIS_CONTAINER to the throwaway container this test may pause");
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let key = format!("test:fail-closed-degrade:{}", Uuid::new_v4());

    docker(&["pause", &container]);
    let set_result = write_coalesce::set(&pool, &key, "field", "value").await;
    let drain_result = write_coalesce::drain(&pool, &key).await;
    docker(&["unpause", &container]);

    assert!(set_result.is_err(), "set must return an error, not panic");
    assert!(
        drain_result.is_err(),
        "drain must return an error, not panic"
    );
}
