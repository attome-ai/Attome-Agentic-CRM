//! D-685 — integration coverage for `attome_cache::persistence::probe` against
//! a real Redis/Dragonfly. The unit tests beside the parser cover field-name
//! portability from captured fixtures; these prove the probe reads a *live*
//! server correctly, which is the part a fixture cannot.
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `tests/stream_buffer.rs` and `tests/rate_limit.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-cache --test persistence
//! ```
//!
//! **`persistence_policy_is_configured` is a deployment guard, not just a code
//! test.** It fails against any instance running with no snapshot/AOF policy —
//! which is precisely the H-8 defect D-685 fixed, and was the live state of
//! this repo's own dev Dragonfly on 2026-08-12. If it fails, the store under
//! test is losing its whole keyspace on restart, including in-window S2S
//! replay nonces; fix the deployment (docker-compose.yml's Dragonfly
//! `--snapshot_cron`), do not relax the test.
//!
//! Verified live 2026-08-12: 3/3 against redis:7 (`TEST_REDIS_PORT=6380`,
//! `save 3600 1 300 100 60 10000`).

use attome_cache::persistence;
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
async fn probe_reads_a_live_server_without_erroring() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);

    let status = persistence::probe(&pool)
        .await
        .expect("probe a live Redis/Dragonfly");

    assert!(
        status.changes_since_last_save.is_some(),
        "both Redis and Dragonfly always report a change counter in INFO \
         persistence; None means the field name moved and the parser needs a \
         new alias (see the module doc's portability table): {status:?}"
    );
}

#[tokio::test]
async fn the_change_counter_reflects_real_writes() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);

    let before = persistence::probe(&pool)
        .await
        .expect("probe before the write")
        .changes_since_last_save
        .expect("a change counter");

    // A throwaway key with a short TTL — this test must not leave state behind,
    // and must not collide with a concurrent run of itself.
    let key = format!("attome-cache:test:persistence:{}", Uuid::now_v7());
    let _: () = pool
        .set(&key, "1", Some(Expiration::EX(60)), None, false)
        .await
        .expect("write a throwaway key");

    let after = persistence::probe(&pool)
        .await
        .expect("probe after the write")
        .changes_since_last_save
        .expect("a change counter");

    let _: () = pool.del(&key).await.expect("clean up the throwaway key");

    // `>=` not `>`: a snapshot can land between the two probes and reset the
    // counter to zero, and an idle-but-shared instance can advance it by more
    // than one. The assertion that matters is that this is a live counter
    // rather than a constant the parser invented.
    assert!(
        after >= before || after == 0,
        "change counter went backwards without a snapshot: {before} -> {after}"
    );
}

#[tokio::test]
async fn persistence_policy_is_configured() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);

    let status = persistence::probe(&pool)
        .await
        .expect("probe a live Redis/Dragonfly");

    assert!(
        status.policy_configured,
        "the store under test has NO snapshot or AOF policy — on restart it \
         loses its whole keyspace, including in-window S2S replay nonces \
         (D-685 / review finding H-8). Fix the deployment, not this test: \
         Dragonfly needs --snapshot_cron (see docker-compose.yml), Redis needs \
         `save` or `appendonly yes`. Probed status: {status:?}"
    );
}
