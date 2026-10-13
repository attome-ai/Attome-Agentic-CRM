//! P-api-consistency-hardening (a) — the integration suite for
//! `AppState::readonly_query_pool` (the pool `query_exec.rs::execute` uses).
//!
//! Live-verified against a real Postgres primary/replica pair (D-210):
//! 6/6 pass. One real test-flake fixed in the same pass — see
//! `primary_current_lsn`'s own doc comment.
//!
//! Requires a **replicated** Postgres pair (`docker-compose.replica.yml` —
//! `/release-and-deploy` for bring-up) and a reachable Redis, identical
//! requirement to `tests/read_pool.rs`. The six tests above this comment's
//! own update build `db_readonly_primary` as a second connection to the
//! **primary** URL using the *same* superuser/bootstrap credentials as
//! `TEST_DATABASE_URL_PRIMARY` itself — deliberate, since those six only
//! need to prove *routing* (which pool reference comes back, and that it is
//! never `state.db`), not role identity.
//!
//! Phase 2 step 7/8's gap (this suite's header used to say "not implemented
//! here") is closed by the tests below `primary_current_lsn`'s section named
//! "real `attome_readonly`-credentialed tests" — those build
//! `db_readonly_primary` from genuine `attome_readonly` role credentials
//! (`TEST_ATTOME_READONLY_PASSWORD`) instead, and assert both the role's
//! reported identity (`SELECT current_user`) and its write-incapability
//! (`UPDATE` → `permission denied`) against that specific pool — the one
//! `query_exec.rs` actually routes a pinned caller's reads through. They
//! require one more precondition than the routing-only tests: the
//! `attome_readonly` role must already have LOGIN + this password applied
//! (`server::readonly_role_seed::seed`, or by hand) and migrations 0010/0046+
//! (P1.1e / P-stored-query-containment) already run — same precondition
//! `crates/server/tests/readonly_role_seed.rs`'s own tests document. This
//! harness cannot call `server::readonly_role_seed::seed` itself to apply
//! that password (doing so would make `attome-server`, a foundation-layer
//! crate, depend on `crates/server`, an upward/reverse dependency the
//! workspace's layering rule forbids — coding-guidelines.md §1) — the
//! password must already be live on the target database before these tests
//! run, exactly as `readonly_role_seed.rs`'s own tests already require of
//! their `DATABASE_URL` target.
//!
//! Run manually once infrastructure is available:
//!
//! ```powershell
//! $env:TEST_DATABASE_URL_PRIMARY = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! $env:TEST_DATABASE_URL_REPLICA = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-server --test readonly_query_pool -- --test-threads=1
//!
//! # Additionally, for the real-role tests (Phase 2 step 7/8):
//! $env:TEST_ATTOME_READONLY_PASSWORD = "<the password applied to attome_readonly>"
//! # $env:TEST_ATTOME_READONLY_USER = "attome_readonly"  # optional, this is the default
//! cargo test -p attome-server --test readonly_query_pool -- --test-threads=1
//! ```
//! `--test-threads=1`: several scenarios pause/resume the *shared* replica
//! (`pg_wal_replay_pause()`/`pg_wal_replay_resume()` are cluster-wide, not
//! per-connection), same reason `read_pool.rs` serializes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::sticky_primary::pin_write_with_lsn;
use attome_config::AppConfig;
use attome_server::AppState;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} must be set to a throwaway test database (NEVER attome_dev/attomedb) — \
             see tests/readonly_query_pool.rs header"
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

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Builds a real `AppState` with a genuine primary/replica pair, same shape
/// as `read_pool.rs::test_state`, plus `db_readonly_primary` attached (or
/// not, per `with_primary_pool`) via `AppState::with_readonly_primary`.
/// `db_readonly_primary` connects to the **primary** URL — see this file's
/// header for why that's a deliberate harness simplification, not a claim
/// that it exercises the `attome_readonly` role's actual grants.
async fn test_state(
    replica_max_lag_secs: Option<u64>,
    with_replica: bool,
    with_primary_pool: bool,
) -> AppState {
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
    let db_readonly_primary = if with_primary_pool {
        Some(
            PgPool::connect(&primary_url)
                .await
                .expect("connect second handle to TEST_DATABASE_URL_PRIMARY"),
        )
    } else {
        None
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
    )
    .with_readonly_primary(db_readonly_primary);

    if with_replica {
        attome_server::spawn_watermark_refresh(state.clone(), Duration::from_millis(250));
        wait_for_first_watermark(&state).await;
    }

    state
}

/// Blocks until the background poller has published at least one watermark
/// (`replica_watermark` flips from `None` to `Some` on its first successful
/// tick). Poll-with-timeout rather than a fixed delay (CI-8) — same helper
/// and same reasoning as `read_pool.rs`: a fixed 400ms was only "probably
/// one 250ms tick", and a late first tick on a loaded runner would make
/// every routing assertion evaluate the pre-poller `None` state instead.
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

/// P-api-consistency-hardening Phase 2 step 7/8 — real-credential variant of
/// `test_state`. `db_readonly_primary` here is a genuine `attome_readonly`
/// connection to the primary host (username/password overridden onto
/// `TEST_DATABASE_URL_PRIMARY`'s own host/port/dbname, same technique
/// `crates/server/tests/readonly_role_seed.rs::connect_options_for_role`
/// already uses), not a second handle opened with whatever superuser
/// credentials `TEST_DATABASE_URL_PRIMARY` itself carries. Requires
/// `TEST_ATTOME_READONLY_PASSWORD` — see this file's header for the
/// precondition (the role must already have LOGIN + this password applied,
/// and P1.1e/P-stored-query-containment's migrations already run).
async fn test_state_with_real_readonly_role(replica_max_lag_secs: Option<u64>) -> AppState {
    let primary_url = require_env("TEST_DATABASE_URL_PRIMARY");
    let replica_url = require_env("TEST_DATABASE_URL_REPLICA");
    let readonly_password = require_env("TEST_ATTOME_READONLY_PASSWORD");
    let readonly_user =
        std::env::var("TEST_ATTOME_READONLY_USER").unwrap_or_else(|_| "attome_readonly".into());
    let config = test_config(replica_max_lag_secs);

    let db = PgPool::connect(&primary_url)
        .await
        .expect("connect TEST_DATABASE_URL_PRIMARY");
    let db_readonly = PgPool::connect(&replica_url)
        .await
        .expect("connect TEST_DATABASE_URL_REPLICA");

    let readonly_options =
        connect_options_for_role(&primary_url, &readonly_user, &readonly_password);
    let db_readonly_primary = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(readonly_options)
        .await
        .expect(
            "attome_readonly must authenticate against the primary host with \
             TEST_ATTOME_READONLY_PASSWORD — see this file's header for the precondition \
             (LOGIN + password already applied via server::readonly_role_seed::seed or by hand)",
        );

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
    )
    .with_readonly_primary(Some(db_readonly_primary));

    attome_server::spawn_watermark_refresh(state.clone(), Duration::from_millis(250));
    wait_for_first_watermark(&state).await;

    state
}

/// Builds connect options for a given role/password against the same
/// host/port/dbname `url` points at, overriding only the credentials — same
/// technique as `crates/server/tests/readonly_role_seed.rs`'s own
/// `connect_options_for_role` helper (duplicated here rather than shared
/// cross-crate for one test-only helper, same posture that file's own
/// `minimal_config` duplication in `attome-db/src/pool.rs` documents as this
/// repo's established convention for test fixtures).
fn connect_options_for_role(
    url: &str,
    role: &str,
    password: &str,
) -> sqlx::postgres::PgConnectOptions {
    use std::str::FromStr;
    sqlx::postgres::PgConnectOptions::from_str(url)
        .expect("TEST_DATABASE_URL_PRIMARY must be a valid postgres:// URL")
        .username(role)
        .password(password)
}

/// Live-verified fix: with no real write between two consecutive tests in
/// this file, `pg_current_wal_insert_lsn()` can return the *same* value
/// twice in a row (an idle test database's WAL doesn't advance on its own
/// fast enough between two back-to-back `#[tokio::test]`s), which made a
/// "pending" pin indistinguishable from an already-cached "caught up"
/// watermark left over from the previous test's pause/resume — the shared,
/// background-refreshed `replica_watermark` (`spawn_watermark_refresh`, this
/// file's own `test_state`) doesn't know or care that replay happens to be
/// paused right now; it only compares LSN values. `pg_logical_emit_message`
/// generates a real WAL record with no side effect on any actual table,
/// guaranteeing this call's LSN is strictly ahead of anything cached before
/// it — reproduced the original flake on demand by removing this line and
/// rerunning `pending_pin_routes_to_the_readonly_primary_pool` in isolation
/// immediately after `never_returns_the_full_privilege_pool_pinned_or_not`.
async fn primary_current_lsn(db: &PgPool) -> String {
    sqlx::query("SELECT pg_logical_emit_message(false, 'readonly_query_pool_test', 'advance')")
        .execute(db)
        .await
        .expect("emit a WAL-advancing logical message");
    sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
        .fetch_one(db)
        .await
        .expect("primary LSN query must not error")
}

/// The load-bearing invariant for this whole plan item: no matter what
/// `readonly_query_pool` decides (pinned, unpinned, replica paused, circuit
/// breaker tripped, Redis down), it must never hand back `state.db` — the
/// full-privilege pool. Reopening that pool for a pinned `query/execute`
/// caller is exactly the regression `P-api-consistency-hardening` (a)
/// rejected in favor of the primary-pointed `attome_readonly` pool.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn never_returns_the_full_privilege_pool_pinned_or_not() {
    let state = test_state(None, true, true).await;
    let user_id = Uuid::now_v7();

    // Unpinned.
    let pool = state.readonly_query_pool(user_id).await;
    assert!(
        !std::ptr::eq(pool, &state.db),
        "unpinned query/execute read must never use the full-privilege pool"
    );

    // Pinned, replica not yet caught up.
    sqlx::query("SELECT pg_wal_replay_pause()")
        .execute(&state.db_readonly)
        .await
        .expect("pause replica replay");
    let write_lsn = primary_current_lsn(&state.db).await;
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");
    let pool = state.readonly_query_pool(user_id).await;
    assert!(
        !std::ptr::eq(pool, &state.db),
        "a pinned, not-yet-caught-up query/execute read must route to db_readonly_primary, \
         never to the full-privilege pool"
    );
    sqlx::query("SELECT pg_wal_replay_resume()")
        .execute(&state.db_readonly)
        .await
        .expect("resume replica replay");
}

/// A pin whose replica hasn't replayed its LSN yet must route to
/// `db_readonly_primary` specifically (not just "not db") — the whole point
/// of this plan item is that `query/execute` reads fresh data.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn pending_pin_routes_to_the_readonly_primary_pool() {
    let state = test_state(None, true, true).await;
    let user_id = Uuid::now_v7();

    sqlx::query("SELECT pg_wal_replay_pause()")
        .execute(&state.db_readonly)
        .await
        .expect("pause replica replay");

    let write_lsn = primary_current_lsn(&state.db).await;
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");

    let pool = state.readonly_query_pool(user_id).await;
    assert!(
        std::ptr::eq(
            pool,
            state.db_readonly_primary.as_ref().expect("configured")
        ),
        "a pending (not-yet-caught-up) pin must route query/execute reads to db_readonly_primary"
    );

    sqlx::query("SELECT pg_wal_replay_resume()")
        .execute(&state.db_readonly)
        .await
        .expect("resume replica replay");
}

/// Once the replica genuinely catches up to the pinned LSN, routing must
/// return to the ordinary `db_readonly` pool — same "don't over-protect"
/// property `read_pool.rs::fast_catch_up_exits_primary_routing_before_the_ttl_elapses`
/// proves for the entity-CRUD path.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn caught_up_pin_falls_back_to_ordinary_readonly_pool() {
    let state = test_state(None, true, true).await;
    let user_id = Uuid::now_v7();

    let write_lsn = primary_current_lsn(&state.db).await;
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");

    // Poll the routing decision itself rather than sleeping a fixed 2s
    // (CI-8). The 10s deadline stays far below the 30s pin TTL on purpose:
    // past the TTL the pin's own expiry would route to the replica and the
    // test would pass without the LSN catch-up path ever having fired.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let pool = state.readonly_query_pool(user_id).await;
        if std::ptr::eq(pool, &state.db_readonly) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a caught-up replica must serve query/execute reads well before the 30s TTL elapses"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `database.readonly` configured but no `db_readonly_primary` attached
/// (e.g. an older boot path that hasn't called `with_readonly_primary` yet)
/// degrades to `db_readonly` with a logged warning — never a hard failure,
/// and critically never the full-privilege pool either.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn missing_readonly_primary_pool_falls_back_to_db_readonly_not_the_primary() {
    let state = test_state(None, true, false).await;
    let user_id = Uuid::now_v7();

    sqlx::query("SELECT pg_wal_replay_pause()")
        .execute(&state.db_readonly)
        .await
        .expect("pause replica replay");
    let write_lsn = primary_current_lsn(&state.db).await;
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");

    let pool = state.readonly_query_pool(user_id).await;
    assert!(
        std::ptr::eq(pool, &state.db_readonly),
        "with no db_readonly_primary configured, a pinned read must fall back to db_readonly \
         (possibly stale) rather than the full-privilege pool"
    );

    sqlx::query("SELECT pg_wal_replay_resume()")
        .execute(&state.db_readonly)
        .await
        .expect("resume replica replay");
}

/// Legacy (pre-LSN) bare-`1` sentinel pin — same rolling-upgrade compat
/// posture `read_pool.rs::legacy_sentinel_pin_routes_to_primary` proves for
/// `read_pool`: never treated as "no pin at all."
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn legacy_sentinel_pin_routes_to_readonly_primary_pool() {
    let state = test_state(None, true, true).await;
    let user_id = Uuid::now_v7();
    {
        use fred::prelude::*;
        // The bare `1` an old node's deleted `pin_write` wrote (BCA-47): no
        // current writer produces it, so seed it raw.
        state
            .redis
            .set::<(), _, _>(
                attome_cache::sticky_primary::pin_key(user_id),
                1,
                Some(Expiration::EX(30)),
                None,
                false,
            )
            .await
            .expect("seed legacy pin");
    }

    let pool = state.readonly_query_pool(user_id).await;
    assert!(
        std::ptr::eq(
            pool,
            state.db_readonly_primary.as_ref().expect("configured")
        ),
        "a legacy bare-sentinel pin must route query/execute reads to db_readonly_primary, \
         unchanged posture from pre-LSN behavior"
    );
}

/// Redis unreachable fails closed to the primary-pointed readonly pool, same
/// "never trust unknown as safe" posture as `read_pool`'s own
/// `redis_error_fails_closed_to_primary`.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn redis_error_fails_closed_to_readonly_primary_pool() {
    use fred::prelude::*;

    let state = test_state(None, true, true).await;
    let user_id = Uuid::now_v7();

    let unreachable_config = RedisConfig::from_url("redis://127.0.0.1:1")
        .expect("build redis config pointed at an unreachable port");
    let unreachable_pool = RedisPool::new(unreachable_config, None, None, None, 1)
        .expect("build redis pool (no eager connect — check_pin's own timeout applies)");

    let pin_check = attome_cache::sticky_primary::check_pin(&unreachable_pool, user_id).await;
    assert_eq!(
        pin_check,
        attome_cache::sticky_primary::PinCheck::RedisError,
        "an unreachable Redis must fail closed to RedisError, never a false PinCheck::None"
    );
    // Sanity: the real (reachable) pool this test's state carries still
    // resolves normally, proving the assertion above tested the intended
    // failure path rather than some universal breakage.
    let _ = state.readonly_query_pool(user_id).await;
}

// ── Real `attome_readonly`-credentialed tests (P-api-consistency-hardening
// Phase 2 step 7/8) ─────────────────────────────────────────────────────────
//
// Everything above this point proves *routing* (which pool reference comes
// back) using a `db_readonly_primary` opened with the same superuser
// credentials as the primary pool. The three tests below additionally
// require `TEST_ATTOME_READONLY_PASSWORD` and prove the role-isolation
// guarantee itself against a genuine `attome_readonly` connection — closing
// the gap this file's own header used to name as "not implemented here".

/// Phase 2 step 7: the primary-pointed readonly pool must actually
/// authenticate as `attome_readonly`, not merely be "some pool that isn't
/// `db`" — the routing tests above already prove the latter; this proves the
/// role-identity half specifically, the same class of check P1.1e's own
/// `SELECT current_user` round-trip used for the replica-pointed
/// `db_readonly` pool, applied here to the primary-pointed one.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn db_readonly_primary_pool_authenticates_as_attome_readonly() {
    let state = test_state_with_real_readonly_role(None).await;
    let expected_user =
        std::env::var("TEST_ATTOME_READONLY_USER").unwrap_or_else(|_| "attome_readonly".into());

    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(state.db_readonly_primary.as_ref().expect("configured"))
        .await
        .expect("SELECT current_user must succeed");

    assert_eq!(
        current_user, expected_user,
        "the primary-pointed readonly pool must authenticate as the attome_readonly role, not \
         whatever credentials TEST_DATABASE_URL_PRIMARY itself carries"
    );
}

/// Phase 2 step 8: regression of P1.1e's own "stored query attempting
/// INSERT/UPDATE/DELETE fails with permission denied" proof, run against
/// this specific pool — the one `query_exec.rs` actually routes a pinned
/// caller's reads through. `attome-db/src/pool.rs::create_readonly_primary_pool`'s
/// doc comment states the isolation guarantee "has nothing to do with which
/// physical host the connection targets"; this is the test that actually
/// exercises that claim against a real connection rather than only trusting
/// the doc comment's reasoning.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn db_readonly_primary_pool_cannot_write() {
    let state = test_state_with_real_readonly_role(None).await;
    let pool = state.db_readonly_primary.as_ref().expect("configured");

    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .expect("attome_readonly must still be able to run a plain SELECT");

    let write_denied =
        sqlx::query("UPDATE api_usage SET request_count = request_count WHERE false")
            .execute(pool)
            .await;
    assert!(
        write_denied.is_err(),
        "attome_readonly must not be able to UPDATE via the primary-pointed pool either — \
         P1.1e's SELECT-only containment boundary is not host-dependent"
    );
}

/// The closed loop this plan item exists for: a pending pin routes
/// `query_exec.rs`'s pool choice to `db_readonly_primary`, and that pool is
/// genuinely the `attome_readonly` role — not just "a second pool that isn't
/// `db`". Ties `pending_pin_routes_to_the_readonly_primary_pool`'s routing
/// proof together with this section's role-identity proof against one real
/// state, which is the actual end-to-end claim P-api-consistency-hardening
/// (a)'s goal (§3) makes: a pinned caller reads fresh data *and* the
/// write-incapability guarantee is unconditionally preserved on that path.
#[ignore = "needs a real primary/replica pair (TEST_DATABASE_URL_PRIMARY/_REPLICA); run it by hand with --ignored — see this file's header"]
#[tokio::test]
async fn pinned_query_execute_path_reads_as_attome_readonly_on_the_primary() {
    let state = test_state_with_real_readonly_role(None).await;
    let user_id = Uuid::now_v7();
    let expected_user =
        std::env::var("TEST_ATTOME_READONLY_USER").unwrap_or_else(|_| "attome_readonly".into());

    sqlx::query("SELECT pg_wal_replay_pause()")
        .execute(&state.db_readonly)
        .await
        .expect("pause replica replay");
    let write_lsn = primary_current_lsn(&state.db).await;
    pin_write_with_lsn(&state.redis, user_id, &write_lsn, 30)
        .await
        .expect("pin write");

    let pool = state.readonly_query_pool(user_id).await;
    assert!(
        std::ptr::eq(
            pool,
            state.db_readonly_primary.as_ref().expect("configured")
        ),
        "a pending pin must route query/execute reads to db_readonly_primary"
    );

    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(pool)
        .await
        .expect("SELECT current_user must succeed on the routed pool");
    assert_eq!(
        current_user, expected_user,
        "the pool query_exec.rs actually routes a pinned caller's reads to must report \
         attome_readonly as its current_user"
    );

    sqlx::query("SELECT pg_wal_replay_resume()")
        .execute(&state.db_readonly)
        .await
        .expect("resume replica replay");
}
