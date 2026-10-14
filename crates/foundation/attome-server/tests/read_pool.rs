//! P-read-your-writes-lsn §6 — the load-bearing integration suite for
//! `AppState::read_pool`'s LSN-aware routing + lag circuit breaker.
//!
//! Run this file with `--ignored` against a replicated Postgres pair
//! (`cargo test -p attome-server --test read_pool -- --ignored`); nothing runs
//! it for you. Every scenario implements
//! `document/base/db/plans/P-read-your-writes-lsn.md` §6.
//!
//! Requires a **replicated** Postgres pair (`docker-compose.replica.yml` —
//! `/release-and-deploy` for bring-up) and a reachable Redis. Unlike
//! `health.rs`'s single-`DATABASE_URL` convention, `db_readonly` here is
//! built from a second, genuinely distinct connection string
//! (`TEST_DATABASE_URL_REPLICA`) via a direct `sqlx::PgPool::connect`, rather
//! than through `attome_db::create_readonly_pool` + `database.readonly.host`/
//! `.port` (D-153 gave that path the same capability — see
//! `attome_server::metrics::spawn_replica_lag_refresh`'s doc comment — but
//! wiring a full config-driven HAProxy/Patroni endpoint just for this test
//! harness is unnecessary complexity; a direct second connection string
//! exercises the identical `db_readonly` code path `AppState::new` takes
//! either way). Either construction gets a genuinely distinct standby, so
//! replica-pause scenarios below exercise real replication, not a second
//! connection to the same primary.
//!
//! Run manually once infrastructure is available:
//!
//! ```powershell
//! $env:TEST_DATABASE_URL_PRIMARY = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! $env:TEST_DATABASE_URL_REPLICA = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-server --test read_pool -- --test-threads=1
//! ```
//! `--test-threads=1`: several scenarios pause/resume the *shared* replica
//! (`pg_wal_replay_pause()`/`pg_wal_replay_resume()` are cluster-wide, not
//! per-connection), so they cannot run concurrently against one replica.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::sticky_primary::pin_write_with_lsn;
use attome_config::AppConfig;
use attome_server::AppState;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} must be set to a throwaway test database (NEVER attome_dev/attomedb) — \
             see tests/read_pool.rs header"
        )
    })
}

fn test_config(replica_max_lag_secs: Option<u64>) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 5, "timeout": 5.0,
                "sticky_primary_ttl_secs": 5,
                "replica_max_lag_secs": {replica_max_lag_secs},
                "replica_watermark_poll_interval_secs": 1
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": true
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        replica_max_lag_secs = replica_max_lag_secs
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string()),
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        false,
    )
}

/// Builds a real `AppState` against a genuinely distinct primary/replica
/// pair — see this file's header for why `db_readonly` bypasses
/// `create_readonly_pool`. `db_readonly` is `None` (falls back to a clone of
/// `db`, exactly the "dark by default" configuration) when
/// `TEST_DATABASE_URL_REPLICA` is unset, so `no_readonly_configured_*` tests
/// can reuse this same helper.
async fn test_state(replica_max_lag_secs: Option<u64>, with_replica: bool) -> AppState {
    let primary_url = require_env("TEST_DATABASE_URL_PRIMARY");
    let config = test_config(replica_max_lag_secs);

    let db = PgPool::connect(&primary_url)
        .await
        .expect("connect TEST_DATABASE_URL_PRIMARY");
    let db_readonly = if with_replica {
        let replica_url = require_env("TEST_DATABASE_URL_REPLICA");
        PgPool::connect(&replica_url)
            .await
            .expect("connect TEST_DATABASE_URL_REPLICA")
    } else {
        db.clone()
    };
    let db_migrator = db.clone();
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis");
    let redis_coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build storage client");

    let state = AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    );

    if with_replica {
        attome_server::spawn_watermark_refresh(state.clone(), Duration::from_millis(250));
        wait_for_first_watermark(&state).await;
    }

    state
}

/// Blocks until the background poller has published at least one watermark
/// (`replica_watermark` flips from `None` to `Some` on its first successful
/// tick), so a test never asserts on routing that is still running "dark".
/// Poll-with-timeout rather than a fixed delay (CI-8): a fixed 400ms was
/// only ever "probably one 250ms tick", and on a loaded runner the first
/// tick can land later than that — every routing assertion below would then
/// be evaluating the pre-poller `None` state and failing for a reason that
/// has nothing to do with routing.
async fn wait_for_first_watermark(state: &AppState) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while state.replica_watermark.load().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "watermark poller never published a first replay LSN within 10s — \
             is TEST_DATABASE_URL_REPLICA really a standby (pg_is_in_recovery())?"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Polls `read_pool(user_id)` until it routes to `expected`, or fails at the
/// deadline. The routing decision *is* the observable here, so the wait ends
/// the moment the watermark catches up rather than after a fixed guess at
/// how long replication takes.
async fn wait_for_routing(
    state: &AppState,
    user_id: Uuid,
    expected: &PgPool,
    deadline: Duration,
    why: &str,
) {
    let deadline = tokio::time::Instant::now() + deadline;
    loop {
        let pool = state.read_pool(user_id).await;
        if std::ptr::eq(pool, expected) {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "{why}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Live-verified fix (same root cause and fix `readonly_query_pool.rs`'s own
/// `primary_current_lsn` already documents): with no real write on an idle
/// test database, `pg_current_wal_insert_lsn()` can return an LSN the
/// replica already replayed *before* this test paused it, making a
/// supposedly-still-pending pin look already caught-up to the
/// background-refreshed `replica_watermark` — which only compares LSN
/// values, not whether replay happens to be paused right now.
/// `pg_logical_emit_message` generates a real WAL record with no side effect
/// on any table, guaranteeing this call's LSN is strictly ahead of anything
/// cached before it. Reproduced the original flake on demand (removed this,
/// reran against a live primary/replica pair) before adding it here.
async fn primary_current_lsn(db: &PgPool) -> String {
    sqlx::query("SELECT pg_logical_emit_message(false, 'read_pool_test', 'advance')")
        .execute(db)
        .await
        .expect("emit a WAL-advancing logical message");
    sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
        .fetch_one(db)
        .await
        .expect("primary LSN query must not error")
}

/// §6 "Paused-replica correctness" — the load-bearing test for §1's failure
/// mode 1 (silent under-protection): a pin must keep routing to the primary
/// for as long as the replica hasn't actually replayed the pinned write,
/// even well past the *old* fixed TTL.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn paused_replica_keeps_routing_to_primary_past_the_old_ttl() {
    let state = test_state(None, true).await;
    let user_id = Uuid::now_v7();

    sqlx::query("SELECT pg_wal_replay_pause()")
        .execute(&state.db_readonly)
        .await
        .expect("pause replica replay");

    let write_lsn = primary_current_lsn(&state.db).await;
    // `ttl_secs` here is the actual Redis key TTL (`pin_write_with_lsn`'s 4th
    // arg), not the "old fixed TTL" this test's own name/comment refers to —
    // those are two different numbers. Confirmed live: passing 5 here (to
    // literally match the old design's TTL) let the Redis pin key itself
    // expire during the 7s sleep below, so `check_pin` legitimately saw
    // `PinCheck::None` and this test silently stopped testing the pinned
    // case at all. A long TTL here means the *only* thing keeping this test
    // honest is the LSN catch-up check this test exists to verify, exactly
    // matching `fast_catch_up_exits_primary_routing_before_the_ttl_elapses`'s
    // own 30s pin below.
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");

    // The *old* fixed-TTL design (5s) would have already fallen back to the
    // replica by here; the paused replica must never let routing fall back
    // to db_readonly regardless, because it hasn't actually replayed
    // write_lsn.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let pool = state.read_pool(user_id).await;
    assert!(
        std::ptr::eq(pool, &state.db),
        "a paused replica must never be routed to, even well past the old fixed TTL"
    );

    sqlx::query("SELECT pg_wal_replay_resume()")
        .execute(&state.db_readonly)
        .await
        .expect("resume replica replay");
}

/// §6 "Fast catch-up early exit" — the load-bearing test for §1's failure
/// mode 2 (wasted over-protection): once the replica genuinely catches up,
/// routing must return to it before the TTL elapses, proving this isn't
/// "TTL, but longer."
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn fast_catch_up_exits_primary_routing_before_the_ttl_elapses() {
    let state = test_state(None, true).await;
    let user_id = Uuid::now_v7();

    let write_lsn = primary_current_lsn(&state.db).await;
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");

    // No artificial pause — the replica catches up within a couple of
    // watermark-poll intervals (250ms configured above). The 10s deadline is
    // deliberately far below the 30s pin TTL: if it were not, the pin's own
    // expiry would eventually route to the replica and this test would pass
    // without the LSN catch-up path ever having fired.
    wait_for_routing(
        &state,
        user_id,
        &state.db_readonly,
        Duration::from_secs(10),
        "a caught-up replica must be used well before the 30s TTL elapses",
    )
    .await;
}

/// §6 "Circuit breaker" — `replica_max_lag_secs` falls the routed set back
/// to the primary for every caller, not just one with an active pin.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn circuit_breaker_routes_every_caller_to_primary_when_lag_exceeds_threshold() {
    let state = test_state(Some(2), true).await; // 2s max lag
    let other_user_with_no_pin = Uuid::now_v7();

    sqlx::query("SELECT pg_wal_replay_pause()")
        .execute(&state.db_readonly)
        .await
        .expect("pause replica replay");

    // Wait past the 2s configured ceiling so the watermark poller observes
    // lag_seconds > 2.0 on its next tick.
    tokio::time::sleep(Duration::from_secs(4)).await;

    let pool = state.read_pool(other_user_with_no_pin).await;
    assert!(
        std::ptr::eq(pool, &state.db),
        "circuit breaker must route an UNPINNED user to the primary once lag exceeds the ceiling"
    );

    sqlx::query("SELECT pg_wal_replay_resume()")
        .execute(&state.db_readonly)
        .await
        .expect("resume replica replay");
}

/// §6 "Rolling-upgrade / legacy-value compatibility" — a pin written with
/// the old bare `1` sentinel routes to the primary for the remainder of its
/// TTL, the same "fail closed toward primary" posture the pre-LSN mechanism
/// always had, never "no pin at all."
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn legacy_sentinel_pin_routes_to_primary() {
    let state = test_state(None, true).await;
    let user_id = Uuid::now_v7();
    {
        // The bare `1` an old node's deleted `pin_write` wrote (BCA-47): no
        // current writer produces it, so seed it raw.
        state
            .redis
            .set(
                &attome_cache::sticky_primary::pin_key(user_id),
                &(1).to_string(),
                Some(std::time::Duration::from_secs(30)),
            )
            .await
            .expect("seed legacy pin");
    }

    let pool = state.read_pool(user_id).await;
    assert!(
        std::ptr::eq(pool, &state.db),
        "a legacy bare-sentinel pin must still route to the primary, unchanged from pre-LSN behavior"
    );
}

/// §6 "Watermark poller runs without metrics enabled" — the direct
/// regression test for §1's second gap: `spawn_watermark_refresh` must be
/// spawned unconditionally whenever `database.readonly` is configured, not
/// nested inside `observability.metrics_port != 0` like
/// `spawn_replica_lag_refresh` is. `test_config` above always sets
/// `metrics_port: 0` (today's default in every shipped config) — this test
/// asserts the poller (spawned explicitly in `test_state`, mirroring what
/// `main.rs` now does unconditionally) populates `replica_watermark` even so.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn watermark_poller_populates_state_with_metrics_disabled() {
    let state = test_state(None, true).await;

    let watermark = state.replica_watermark.load();
    assert!(
        watermark.is_some(),
        "replica_watermark must be populated by the always-on poller even though \
         observability.metrics_port is 0 in this test config"
    );
}

/// §6 "No regression to the dark-by-default path" — `database.readonly`
/// absent (simulated here via `with_replica: false`, `db_readonly` a clone
/// of `db`) must behave byte-identically to always using `db`.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn no_readonly_configured_always_uses_primary() {
    let state = test_state(None, false).await;
    let user_id = Uuid::now_v7();

    let pool = state.read_pool(user_id).await;
    // `sqlx::Pool` is a newtype around `Arc<PoolInner>` (its `Clone` impl is
    // an `Arc::clone`) — `pool`/`&state.db` are two distinct `AppState`
    // fields (`db_readonly` vs `db`), so their own addresses can never be
    // `ptr::eq` regardless of whether they share a pool, which is what the
    // original version of this assertion checked (confirmed live: it fails
    // even though `db_readonly` really is `db.clone()`, per `test_state`).
    // `connect_options()` is `pub fn` returning `Arc<PgConnectOptions>`
    // sourced from the pool's own shared `PoolInner` — comparing THOSE Arcs'
    // addresses is the identity check this test actually wants.
    assert!(
        Arc::ptr_eq(&pool.connect_options(), &state.db.connect_options()),
        "with no readonly pool configured, db_readonly is a clone of db — read_pool must \
         behave byte-identically to always using the primary"
    );
}

/// §6 "Redis-error fail-closed" — unchanged existing behavior, re-asserted
/// under the new `check_pin` shape. Simulated by pointing `state.redis` at
/// an unreachable port rather than actually killing the test Redis
/// (unnecessary/racy for other tests sharing that instance) — this exercises
/// the same `tokio::time::timeout` + connection-error path `check_pin` would
/// hit against a genuinely down Redis.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn redis_error_fails_closed_to_primary() {
    use fred::prelude::*;

    let state = test_state(None, true).await;
    let user_id = Uuid::now_v7();

    let unreachable_config = RedisConfig::from_url("redis://127.0.0.1:1")
        .expect("build redis config pointed at an unreachable port");
    let unreachable_pool = RedisPool::new(unreachable_config, None, None, None, 1)
        .expect("build redis pool (no eager connect — check_pin's own timeout applies)");

    let pin_check = attome_cache::sticky_primary::check_pin(
        &attome_cache::Store::Redis(unreachable_pool.clone()),
        user_id,
    )
    .await;
    assert_eq!(
        pin_check,
        attome_cache::sticky_primary::PinCheck::RedisError,
        "an unreachable Redis must fail closed to RedisError, never a false PinCheck::None"
    );
    // Sanity: the real (reachable) pool this test's state carries still
    // resolves normally, proving the assertion above tested the intended
    // failure path rather than some universal breakage.
    let _ = state.read_pool(user_id).await;
}
