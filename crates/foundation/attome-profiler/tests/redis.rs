//! BPR-41 (attome-profiler plan, Phase 4) — the live Redis suite. Every other
//! test in this crate is pure; this is the one that proves the Lua write path,
//! the keyspace bounds and the read path against a real store (Redis 7 and
//! Dragonfly v2.0.0 in `scripts/test-attome-cache-backends.ps1`), because the
//! BUMP/FLUSH script otherwise never runs outside production.
//!
//! Covers the plan's S1/S2/S4/S5/S7 measures that need a store:
//!
//! - aggregates: count / sum / min / max / avg per probe and per sub-part,
//!   plus one capped trace sample per flush (newest first);
//! - `TRACE_CAP`: a 60-flush ring still returns exactly 50 samples;
//! - the name cap (`MAX_NAMES`): 3,000 distinct names leave
//!   `SCARD attome-profiler:names` <= 2,000 and no more than 2,000 stat rows,
//!   with the refusals counted as `DroppedReason::Cardinality`;
//! - TTL: every written `attome-profiler:*` key has `0 < PTTL <=` its
//!   retention, and the TTL slides forward on the next flush;
//! - one command per flush: an `INFO commandstats` delta shows exactly one
//!   `EVAL` for a flush of a top-level probe plus a sub-part;
//! - reset: every key goes, and a second call is a no-op;
//! - fail-open: an unreachable store returns `Err` (never a panic) and counts
//!   a drop reason.
//!
//! ## Running it
//!
//! Needs a throwaway Redis-compatible store; nothing here assumes it is
//! empty, and no test asserts an empty keyspace on the shared default DB.
//!
//! ```powershell
//! $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-profiler --test redis -- --test-threads=1
//! ```
//!
//! `--test-threads=1` is not required for correctness — the name-cap and reset
//! tests use dedicated logical databases (`TEST_REDIS_DB_CAP`, default 9;
//! `TEST_REDIS_DB_RESET`, default 10) and every probe name is unique — but it
//! keeps the `INFO commandstats` delta measurement quiet, which is the one
//! assertion a concurrent `EVAL` elsewhere on the server could perturb (it
//! retries up to 8 times before failing for exactly that reason).
//!
//! `recovers_after_the_store_restarts` is `#[ignore]`d: it restarts a Docker
//! container and needs `TEST_REDIS_CONTAINER` naming a throwaway one. Pointing
//! it at the shared dev/test stack would restart that stack under every other
//! agent on the machine.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_profiler::{
    DroppedReason, MAX_NAMES, NAMES_KEY, ProbeRecord, STAT_PREFIX, STAT_TTL, TRACE_CAP,
    TRACE_PREFIX, TRACE_TTL, corrupt_trace_samples, dropped, flush, parse_commandstat, read_stats,
    read_trace, reset,
};
use fred::prelude::*;
use fred::types::InfoKind;
use futures_util::TryStreamExt;

/// How long a test waits for the store before reporting itself skipped.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn env_db(name: &str, default: u8) -> u8 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A pool pointed at the shared throwaway store, in a logical DB chosen by the
/// caller so tests do not fight over the profile name set. `None` (with a loud
/// line) when nothing is listening — the same "skip, don't fail" convention
/// `attome_testkit::skip_if_no_db` uses for Postgres.
async fn test_pool(db: u8) -> Option<RedisPool> {
    let (host, port) = attome_testkit::test_redis()?;
    let url = format!("redis://{host}:{port}/{db}");
    let config = RedisConfig::from_url(&url).expect("test redis url must parse");
    let mut builder = Builder::from_config(config);
    // Same reconnect posture attome-cache's factories use (BCA-F1), so a store
    // blip does not end the router task.
    builder
        .set_policy(ReconnectPolicy::new_exponential(0, 100, 5_000, 2))
        .with_connection_config(|c| {
            c.connection_timeout = Duration::from_secs(2);
        });
    let pool = builder.build_pool(2).expect("build test redis pool");
    pool.connect();
    match tokio::time::timeout(CONNECT_TIMEOUT, pool.wait_for_connect()).await {
        Ok(Ok(())) => Some(pool),
        _ => {
            assert!(
                std::env::var_os(attome_testkit::REQUIRE_REDIS_ENV).is_none(),
                "no test Redis at {url}, and {} requires one",
                attome_testkit::REQUIRE_REDIS_ENV
            );
            eprintln!("skipping: no test Redis at {url} (set TEST_REDIS_HOST/TEST_REDIS_PORT)");
            None
        }
    }
}

/// Every key matching `pattern`, via cursor-based `SCAN` (never `KEYS`).
async fn scan_all(pool: &RedisPool, pattern: &str) -> Vec<String> {
    use fred::types::Scanner;

    let mut keys = Vec::new();
    let mut stream = pool.next().scan(pattern, Some(200u32), None);
    while let Some(mut page) = stream.try_next().await.expect("scan test keys") {
        if let Some(page_keys) = page.take_results() {
            keys.extend(page_keys.into_iter().filter_map(|k| k.into_string()));
        }
    }
    keys
}

/// A probe name no other run can collide with.
fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the epoch")
        .as_nanos();
    format!("test.{prefix}.{}.{nanos}", std::process::id())
}

async fn eval_calls(pool: &RedisPool) -> u64 {
    let info: String = pool
        .info(Some(InfoKind::CommandStats))
        .await
        .expect("INFO commandstats");
    parse_commandstat(&info, "eval").unwrap_or(0)
}

/// The aggregate write path: one flush of a top-level probe plus a dotted
/// sub-part must aggregate count/sum/min/max for both and store exactly one
/// trace sample carrying the sub-part.
#[tokio::test]
async fn flush_aggregates_the_whole_batch_and_stores_one_trace_sample() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("agg");
    let sub = format!("{top}.db_insert");

    for (total_ms, part_ms) in [(100u64, 40u64), (200, 60)] {
        flush(
            &attome_cache::Store::Redis(pool.clone()),
            &top,
            Duration::from_millis(total_ms),
            &[ProbeRecord {
                name: sub.clone(),
                duration: Duration::from_millis(part_ms),
            }],
        )
        .await
        .expect("flush must succeed against a live store");
    }

    let rows = read_stats(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("read_stats");
    let top_row = rows
        .iter()
        .find(|r| r.name == top)
        .unwrap_or_else(|| panic!("no stat row for {top}: {rows:?}"));
    assert_eq!(top_row.count, 2);
    assert!((top_row.total_ms - 300.0).abs() < 1.0, "{top_row:?}");
    assert!((top_row.avg_ms - 150.0).abs() < 1.0, "{top_row:?}");
    assert!((top_row.min_ms - 100.0).abs() < 1.0, "{top_row:?}");
    assert!((top_row.max_ms - 200.0).abs() < 1.0, "{top_row:?}");

    let sub_row = rows
        .iter()
        .find(|r| r.name == sub)
        .unwrap_or_else(|| panic!("no stat row for {sub}: {rows:?}"));
    assert_eq!(sub_row.count, 2);
    assert!((sub_row.total_ms - 100.0).abs() < 1.0, "{sub_row:?}");

    let samples = read_trace(&attome_cache::Store::Redis(pool.clone()), &top, 10)
        .await
        .expect("read_trace");
    assert_eq!(samples.len(), 2, "one trace sample per flush: {samples:?}");
    assert!(
        (samples[0].total_ms - 200.0).abs() < 1.0,
        "newest sample first: {samples:?}"
    );
    assert_eq!(samples[0].parts.len(), 1);
    assert_eq!(samples[0].parts[0].name, sub);
    assert!((samples[0].parts[0].ms - 60.0).abs() < 1.0);
}

/// The trace ring is capped at `TRACE_CAP` entries.
#[tokio::test]
async fn the_trace_ring_is_capped_at_fifty_samples() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("tracecap");
    for i in 0..(TRACE_CAP + 10) {
        flush(
            &attome_cache::Store::Redis(pool.clone()),
            &top,
            Duration::from_millis(i as u64 + 1),
            &[],
        )
        .await
        .expect("flush");
    }

    let samples = read_trace(&attome_cache::Store::Redis(pool.clone()), &top, TRACE_CAP)
        .await
        .expect("read_trace");
    assert_eq!(
        samples.len() as i64,
        TRACE_CAP,
        "the ring must hold exactly TRACE_CAP={TRACE_CAP} samples"
    );
    let stored: i64 = pool
        .llen(format!("{TRACE_PREFIX}{top}"))
        .await
        .expect("llen");
    assert_eq!(
        stored, TRACE_CAP,
        "the stored list must be trimmed to the cap"
    );
}

/// S2: every key the write path creates is namespaced `attome-profiler:*` and
/// carries `0 < PTTL <=` its retention; a second flush slides the TTL forward.
#[tokio::test]
async fn every_profiler_key_is_namespaced_and_expires() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("ttl");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &top,
        Duration::from_millis(5),
        &[ProbeRecord {
            name: format!("{top}.part"),
            duration: Duration::from_millis(1),
        }],
    )
    .await
    .expect("flush");

    let keys = scan_all(&pool, "attome-profiler:*").await;
    assert!(!keys.is_empty(), "the flush must have written keys");
    assert!(
        keys.iter().any(|k| k == &format!("{STAT_PREFIX}{top}")),
        "the stat hash must exist: {keys:?}"
    );
    assert!(
        keys.contains(&NAMES_KEY.to_string()),
        "the names set must exist: {keys:?}"
    );

    for key in &keys {
        assert!(
            key.starts_with("attome-profiler:"),
            "key outside the namespace: {key}"
        );
        let pttl: i64 = pool.pttl(key.as_str()).await.expect("pttl");
        let retention = if key.starts_with(TRACE_PREFIX) {
            TRACE_TTL
        } else {
            STAT_TTL
        };
        assert!(
            pttl > 0 && pttl <= retention.as_millis() as i64,
            "{key} pttl {pttl} must be within 0 < pttl <= {}",
            retention.as_millis()
        );
    }

    let stat_key = format!("{STAT_PREFIX}{top}");
    let first: i64 = pool.pttl(stat_key.as_str()).await.expect("pttl");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &top,
        Duration::from_millis(5),
        &[],
    )
    .await
    .expect("second flush");
    let second: i64 = pool.pttl(stat_key.as_str()).await.expect("pttl");
    assert!(
        second > first,
        "the TTL must slide forward on every write (first {first}, second {second})"
    );
}

/// The names set's TTL slides on every flush, not only when a new name is
/// admitted: a stable name set must not expire out from under its stat hashes.
#[tokio::test]
async fn the_names_set_ttl_slides_on_a_flush_of_known_names() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("namesttl");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &top,
        Duration::from_millis(5),
        &[],
    )
    .await
    .expect("first flush");

    let _: bool = pool
        .pexpire(NAMES_KEY, 10_000, None)
        .await
        .expect("shorten the names ttl");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &top,
        Duration::from_millis(5),
        &[],
    )
    .await
    .expect("flush of an already-admitted name");

    let pttl: i64 = pool.pttl(NAMES_KEY).await.expect("pttl");
    assert!(
        pttl > 10_000,
        "a flush of known names must slide the names set's TTL, got {pttl}"
    );
}

/// S1: 3,000 distinct names leave the names set at `MAX_NAMES` and the stat
/// rows at or below it, with the refusals counted as `Cardinality`.
#[tokio::test]
async fn the_name_cap_bounds_the_keyspace() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB_CAP", 9)).await else {
        return;
    };
    reset(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("reset before the cap run");
    let before = dropped(DroppedReason::Cardinality);

    for i in 0..3_000 {
        flush(
            &attome_cache::Store::Redis(pool.clone()),
            &format!("cap.probe.{i}"),
            Duration::from_millis(1),
            &[],
        )
        .await
        .expect("flush");
    }

    let scard: i64 = pool.scard(NAMES_KEY).await.expect("scard");
    assert!(
        scard <= MAX_NAMES,
        "SCARD {NAMES_KEY} = {scard} must be <= {MAX_NAMES}"
    );
    let start = Instant::now();
    let rows = read_stats(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("read_stats");
    let read_elapsed = start.elapsed();
    assert!(
        rows.len() as i64 <= MAX_NAMES,
        "stat rows {} must be <= {MAX_NAMES}",
        rows.len()
    );
    // S5 / BPR-24: a full 2,000-row read is one pipelined pass under the 2 s
    // hard deadline; locally it must sit under the 300 ms target.
    assert!(
        read_elapsed < Duration::from_millis(300),
        "read_stats over {} rows took {read_elapsed:?}, target is 300 ms",
        rows.len()
    );
    assert!(
        dropped(DroppedReason::Cardinality) > before,
        "refused names must be counted as cardinality drops"
    );

    reset(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("reset after the cap run");
}

/// S4 (BPR-21): a flush of a top-level probe plus a sub-part is exactly one
/// `EVAL`. Retried a few times because `INFO commandstats` is server-global
/// and a concurrent `EVAL` from another suite would show up in the delta.
#[tokio::test]
async fn a_flush_is_exactly_one_redis_command() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("onecmd");

    let mut deltas = Vec::new();
    for _ in 0..8 {
        let before = eval_calls(&pool).await;
        flush(
            &attome_cache::Store::Redis(pool.clone()),
            &top,
            Duration::from_millis(3),
            &[ProbeRecord {
                name: format!("{top}.part"),
                duration: Duration::from_millis(1),
            }],
        )
        .await
        .expect("flush");
        let after = eval_calls(&pool).await;
        let delta = after.saturating_sub(before);
        if delta == 1 {
            return;
        }
        deltas.push(delta);
    }
    panic!("a flush must issue exactly one EVAL; observed deltas {deltas:?}");
}

/// S7 (BPR-31 backing function): `reset` unlinks every profiler key and is
/// idempotent.
#[tokio::test]
async fn reset_removes_every_key_and_is_idempotent() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB_RESET", 10)).await else {
        return;
    };
    reset(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("reset to a clean slate");

    let a = unique("reset.a");
    let b = unique("reset.b");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &a,
        Duration::from_millis(2),
        &[],
    )
    .await
    .expect("flush a");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &b,
        Duration::from_millis(2),
        &[],
    )
    .await
    .expect("flush b");
    assert_eq!(
        read_stats(&attome_cache::Store::Redis(pool.clone()))
            .await
            .expect("read_stats")
            .len(),
        2
    );

    let deleted = reset(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("reset");
    assert!(
        deleted >= 2,
        "reset must remove the keys this test wrote, removed {deleted}"
    );
    let rows = read_stats(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("read_stats");
    assert!(
        rows.is_empty(),
        "no stat rows may survive a reset: {rows:?}"
    );

    let again = reset(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("second reset");
    assert_eq!(again, 0, "a second reset must be a no-op");
}

/// Fail-open: an unreachable store returns an error (never panics), fast, and
/// counts a drop reason instead of propagating into the caller's latency.
#[tokio::test]
async fn an_unreachable_store_fails_open() {
    let config = RedisConfig::from_url("redis://127.0.0.1:1").expect("dead url must parse");
    let dead = Builder::from_config(config)
        .build_pool(1)
        .expect("build dead pool");
    // Same non-awaited start attome-cache's factories use; the store is dead,
    // so every command below fails and `flush` must return Err (never panic).
    dead.connect();

    let before = dropped(DroppedReason::RedisError) + dropped(DroppedReason::Timeout);
    let start = Instant::now();
    let result = flush(
        &attome_cache::Store::Redis(dead.clone()),
        "fail.open",
        Duration::from_millis(1),
        &[],
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "an unreachable store must return Err, not block or panic"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "fail-open must not stall the caller (took {elapsed:?})"
    );
    assert!(
        dropped(DroppedReason::RedisError) + dropped(DroppedReason::Timeout) > before,
        "a failed flush must be counted"
    );
}

/// A read path that tolerates a hand-corrupted sample: it is skipped and
/// counted, not turned into an error (BPR-24).
#[tokio::test]
async fn unparsable_trace_samples_are_counted_not_fatal() {
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("corrupt");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &top,
        Duration::from_millis(7),
        &[],
    )
    .await
    .expect("flush");
    let key = format!("{TRACE_PREFIX}{top}");
    let _: i64 = pool
        .lpush(&key, "not-json")
        .await
        .expect("push a corrupt sample");

    let before = corrupt_trace_samples();
    let samples = read_trace(&attome_cache::Store::Redis(pool.clone()), &top, 10)
        .await
        .expect("read_trace");
    assert_eq!(samples.len(), 1, "the valid sample must still come back");
    assert!(
        corrupt_trace_samples() > before,
        "the corrupt sample must be counted"
    );
}

/// BPR-41's recovery leg. Requires a **throwaway** container:
///
/// ```powershell
/// docker run -d --name attome-profiler-redis -p 127.0.0.1:16393:6379 redis:7
/// $env:TEST_REDIS_PORT = "16393"; $env:TEST_REDIS_CONTAINER = "attome-profiler-redis"
/// cargo test -p attome-profiler --test redis -- --ignored recovers_after
/// ```
#[tokio::test]
#[ignore = "restarts a Docker container; needs TEST_REDIS_CONTAINER naming a throwaway one"]
async fn recovers_after_the_store_restarts() {
    let container = std::env::var("TEST_REDIS_CONTAINER")
        .expect("TEST_REDIS_CONTAINER must name a throwaway container to restart");
    let Some(pool) = test_pool(env_db("TEST_REDIS_DB", 0)).await else {
        return;
    };
    let top = unique("recovery");
    flush(
        &attome_cache::Store::Redis(pool.clone()),
        &top,
        Duration::from_millis(3),
        &[],
    )
    .await
    .expect("flush before the restart");

    let status = std::process::Command::new("docker")
        .args(["restart", "-t", "0", &container])
        .status()
        .expect("run docker restart");
    assert!(status.success(), "docker restart {container} failed");

    // The pool must recover on its own (ReconnectPolicy), with no restart of
    // this process: retry the flush until it succeeds.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if flush(
            &attome_cache::Store::Redis(pool.clone()),
            &top,
            Duration::from_millis(3),
            &[],
        )
        .await
        .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the pool never recovered after restarting {container}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let rows = read_stats(&attome_cache::Store::Redis(pool.clone()))
        .await
        .expect("read_stats after recovery");
    assert!(
        rows.iter().any(|r| r.name == top),
        "the probe must be readable again after recovery: {rows:?}"
    );
}
