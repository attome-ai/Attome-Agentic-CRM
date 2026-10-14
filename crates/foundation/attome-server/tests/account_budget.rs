//! Base-auth hardening 1.5: `middleware::rate_limit::enforce_account_budget`
//! against a real Redis — the shared per-account MFA bucket admits exactly
//! `MFA_ATTEMPTS_PER_ACCOUNT_RPM` attempts, answers the next one with a
//! finished 429, and holds that ceiling under concurrent attempts.
//!
//! Requires Redis/Dragonfly at `TEST_REDIS_HOST`/`TEST_REDIS_PORT` (defaults
//! 127.0.0.1:6379), same convention as `attome-cache/tests/rate_limit.rs`:
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-server --test account_budget
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::middleware::rate_limit::{
    MFA_ATTEMPTS_PER_ACCOUNT_RPM, enforce_account_budget, mfa_account_key,
};
use axum::http::{StatusCode, header::RETRY_AFTER};
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
async fn the_attempt_after_the_budget_gets_a_finished_429() {
    let pool = test_pool().await;
    let key = mfa_account_key(Uuid::now_v7());

    for attempt in 1..=MFA_ATTEMPTS_PER_ACCOUNT_RPM {
        let rejected = enforce_account_budget(
            &attome_cache::Store::Redis(pool.clone()),
            &key,
            MFA_ATTEMPTS_PER_ACCOUNT_RPM,
            "test",
        )
        .await
        .expect("a reachable Redis must not error");
        assert!(rejected.is_none(), "attempt {attempt} must be admitted");
    }

    let rejected = enforce_account_budget(
        &attome_cache::Store::Redis(pool.clone()),
        &key,
        MFA_ATTEMPTS_PER_ACCOUNT_RPM,
        "test",
    )
    .await
    .expect("a reachable Redis must not error")
    .expect("the attempt past the budget must be rejected");
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        rejected.headers().contains_key(RETRY_AFTER),
        "a 429 must say when to retry"
    );
    assert!(rejected.headers().contains_key("x-ratelimit-reset"));
}

#[tokio::test]
async fn concurrent_attempts_never_exceed_the_shared_budget() {
    let pool = test_pool().await;
    let key = mfa_account_key(Uuid::now_v7());
    let attempts = 3 * MFA_ATTEMPTS_PER_ACCOUNT_RPM as usize;

    let mut handles = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let pool = pool.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            enforce_account_budget(
                &attome_cache::Store::Redis(pool.clone()),
                &key,
                MFA_ATTEMPTS_PER_ACCOUNT_RPM,
                "test",
            )
            .await
        }));
    }

    let mut admitted = 0;
    for handle in handles {
        let rejected = handle
            .await
            .expect("task must not panic")
            .expect("a reachable Redis must not error");
        if rejected.is_none() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, MFA_ATTEMPTS_PER_ACCOUNT_RPM as usize,
        "exactly the budget may be admitted, however the attempts interleave"
    );
}
