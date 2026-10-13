//! P-job-system-hardening (b) — integration coverage for
//! `attome_cache::stream_buffer`'s consumer-group helpers against a real
//! Redis/Dragonfly (fred's `RedisPool`, not a mock, using fred 9's
//! `i-streams` feature): proves the produce → read → ack round trip, that
//! an unacked entry is reclaimable via `autoclaim`, and that
//! `pending_count` reflects delivered-not-yet-acked entries accurately
//! (including the `NOGROUP` → zero case for a stream nothing has ever
//! consumed from).
//!
//! Requires a local Redis/Dragonfly reachable at `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT` (defaults 127.0.0.1:6379) — same convention as
//! `tests/rate_limit.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-cache --test stream_buffer
//! ```
//!
//! First verified live against Dragonfly on 2026-07-30; since then
//! `scripts/test-attome-cache-backends.ps1` runs it against every pinned
//! Dragonfly/Redis image on every release gate, so a Lua or reply-shape
//! regression surfaces there rather than in production. See `stream_buffer.rs`'s
//! module doc for the bugs the first manual run found and fixed (`read_group`'s
//! RESP2 array-wrapper handling, `pending_count`'s Dragonfly-specific NOGROUP
//! error text, the `BLOCK 0` inversion, the bare-`Null` reply).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::stream_buffer;
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

fn test_stream() -> String {
    format!("test:stream-buffer:{}", Uuid::new_v4())
}

const GROUP: &str = "test-group";
const CONSUMER: &str = "test-consumer";

#[tokio::test]
async fn a_produced_entry_is_read_back_with_its_fields_intact() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();
    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("ensure group");

    let fields = vec![
        ("method".to_string(), "POST".to_string()),
        ("status".to_string(), "200".to_string()),
    ];
    stream_buffer::add(&pool, &stream, fields.clone(), 1000)
        .await
        .expect("add");

    let entries = stream_buffer::read_group(&pool, &stream, GROUP, CONSUMER, 10, 0)
        .await
        .expect("read_group");
    assert_eq!(entries.len(), 1, "exactly one entry must be delivered");
    let mut got = entries[0].fields.clone();
    got.sort();
    let mut want = fields;
    want.sort();
    assert_eq!(got, want);
}

#[tokio::test]
async fn reading_an_empty_stream_returns_no_entries() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();
    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("ensure group");

    let entries = stream_buffer::read_group(&pool, &stream, GROUP, CONSUMER, 10, 0)
        .await
        .expect("read_group");
    assert!(entries.is_empty());
}

#[tokio::test]
async fn calling_ensure_group_twice_on_the_same_stream_does_not_error() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();

    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("first ensure_group");
    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("second ensure_group must swallow BUSYGROUP, not error");
}

#[tokio::test]
async fn an_entry_read_but_not_acked_is_reclaimable_via_autoclaim() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();
    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("ensure group");

    stream_buffer::add(
        &pool,
        &stream,
        vec![("k".to_string(), "v".to_string())],
        1000,
    )
    .await
    .expect("add");

    let delivered = stream_buffer::read_group(&pool, &stream, GROUP, CONSUMER, 10, 0)
        .await
        .expect("read_group");
    assert_eq!(delivered.len(), 1);

    // min_idle_ms = 0: eligible for reclaim immediately, no sleep needed —
    // this test isn't proving the idle-time threshold itself, only that a
    // delivered-not-acked entry is genuinely still reclaimable at all.
    let (_next_cursor, reclaimed) =
        stream_buffer::autoclaim(&pool, &stream, GROUP, "a-different-consumer", 0, "0-0", 10)
            .await
            .expect("autoclaim");

    assert_eq!(reclaimed.len(), 1, "the unacked entry must be reclaimed");
    assert_eq!(reclaimed[0].id, delivered[0].id);
}

#[tokio::test]
async fn acked_entries_are_never_reclaimed() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();
    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("ensure group");

    stream_buffer::add(
        &pool,
        &stream,
        vec![("k".to_string(), "v".to_string())],
        1000,
    )
    .await
    .expect("add");

    let delivered = stream_buffer::read_group(&pool, &stream, GROUP, CONSUMER, 10, 0)
        .await
        .expect("read_group");
    let ids: Vec<String> = delivered.iter().map(|e| e.id.clone()).collect();
    stream_buffer::ack(&pool, &stream, GROUP, &ids)
        .await
        .expect("ack");

    let (_next_cursor, reclaimed) =
        stream_buffer::autoclaim(&pool, &stream, GROUP, "a-different-consumer", 0, "0-0", 10)
            .await
            .expect("autoclaim");
    assert!(
        reclaimed.is_empty(),
        "an acked entry must never be reclaimed"
    );
}

#[tokio::test]
async fn pending_count_reflects_delivered_unacked_entries_and_drops_to_zero_after_ack() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();
    stream_buffer::ensure_group(&pool, &stream, GROUP)
        .await
        .expect("ensure group");

    stream_buffer::add(
        &pool,
        &stream,
        vec![("k".to_string(), "v".to_string())],
        1000,
    )
    .await
    .expect("add");

    let before_read = stream_buffer::pending_count(&pool, &stream, GROUP)
        .await
        .expect("pending_count before read");
    assert_eq!(
        before_read, 0,
        "nothing is pending before anything reads it"
    );

    let delivered = stream_buffer::read_group(&pool, &stream, GROUP, CONSUMER, 10, 0)
        .await
        .expect("read_group");

    let after_read = stream_buffer::pending_count(&pool, &stream, GROUP)
        .await
        .expect("pending_count after read");
    assert_eq!(
        after_read, 1,
        "one delivered-unacked entry must count as pending"
    );

    let ids: Vec<String> = delivered.iter().map(|e| e.id.clone()).collect();
    stream_buffer::ack(&pool, &stream, GROUP, &ids)
        .await
        .expect("ack");

    let after_ack = stream_buffer::pending_count(&pool, &stream, GROUP)
        .await
        .expect("pending_count after ack");
    assert_eq!(after_ack, 0, "acked entries must not count as pending");
}

#[tokio::test]
async fn pending_count_is_zero_for_a_group_that_was_never_created() {
    let pool = attome_testkit::skip_if_no_redis!(test_pool().await);
    let stream = test_stream();

    let count = stream_buffer::pending_count(&pool, &stream, GROUP)
        .await
        .expect("pending_count must treat NOGROUP as zero, not error");
    assert_eq!(count, 0);
}
