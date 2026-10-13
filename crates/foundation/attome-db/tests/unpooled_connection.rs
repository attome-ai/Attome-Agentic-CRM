//! Integration tests for attome-db hardening Phase 1.3a/1.3b: the unpooled
//! connections are bounded.
//!
//! - Connecting is bounded by `database.timeout` (`connect_unpooled`), so an
//!   unreachable direct endpoint fails fast instead of waiting out the OS
//!   TCP timeout. This test needs no database.
//! - `create_runtime_session` bounds lock waits (`lock_timeout`, the same
//!   value as `create_direct_pool`) and never bounds statements (pinned in
//!   `direct_session_authenticates_as_the_runtime_role`; the deprecated
//!   `create_direct_connection` that first carried this contract is removed).
//! - `create_migrator_connection` has no `lock_timeout` (1.3c's decision; see
//!   `create_migrator_connection`'s doc comment).
//! - An `UnpooledSession` is counted while open (plan 4.1), and
//!   `runtime_session_connect_cost` (ignored) measures a session's connect
//!   cost (plan 4.2).
//!
//! The database-backed tests use this binary's throwaway clone
//! (`attome_testkit::test_db_url`), never `attome_dev`, and skip (loudly) when
//! `DATABASE_URL` is unset, except under `ATTOME_TEST_REQUIRE_DB=1` (the older `CI` alias still works). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test unpooled_connection
//! ```

#![allow(
    unsafe_code,
    reason = "`NonDebugAppEnv` sets APP_ENV for one test and restores it on drop"
)]

use std::str::FromStr;
use std::time::{Duration, Instant};

use attome_config::AppConfig;
use attome_testkit::skip_if_no_db;
use sqlx::Connection;
use sqlx::postgres::PgConnectOptions;

/// Same minimal-fixture shape as `tests/migrator_connection.rs`, with the
/// `database` section supplied by the caller.
fn config_with_database(database: serde_json::Value) -> AppConfig {
    let json = serde_json::json!({
        "app": {
            "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
            "log_level": "error", "threads": 1, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
            "keepalive_requests": 100, "static_files_cache_time": 0,
            "server_header_field": "test"
        },
        "database": database,
        "cache": {
            "host": "localhost", "port": 6379, "password": "", "db": 0,
            "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
            "l1_cache_ttl_seconds": 60
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
            "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
            "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
        },
        "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
        "observability": {
            "metrics_port": 0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "a@b.c",
            "smtp_from_name": "t", "smtp_use_tls": false,
            "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5
        },
        "google_ai": {
            "api_key": "test", "base_url": "http://localhost",
            "default_model": "test", "timeout_seconds": 5
        },
    });
    serde_json::from_value(json).expect("test config must deserialize")
}

/// The throwaway database's user, password, and name, for building a
/// `database.migrator` block and `dbname` that match it.
fn identity(url: &str) -> (String, String, String) {
    let options = PgConnectOptions::from_str(url).expect("test DATABASE_URL must parse");
    let password = url
        .split_once("://")
        .and_then(|(_, rest)| rest.rsplit_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .map(|(_, password)| password.to_string())
        .unwrap_or_default();
    (
        options.get_username().to_string(),
        password,
        options
            .get_database()
            .expect("test DATABASE_URL must name a database")
            .to_string(),
    )
}

async fn show(conn: &mut sqlx::PgConnection, setting: &str) -> String {
    sqlx::query_scalar(&format!("SHOW {setting}"))
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("SHOW {setting} must succeed: {e}"))
}

/// `192.0.2.1` is TEST-NET-1 (RFC 5737) and is never routed, so the connect
/// either hangs until our timeout or is refused immediately by the local
/// network stack. Both satisfy the property under test: a bounded failure.
/// `APP_ENV` is forced non-debug so a debug `DATABASE_URL` override cannot
/// redirect the connect to a reachable server.
#[tokio::test]
async fn runtime_session_to_an_unreachable_host_fails_within_the_timeout() {
    let config = config_with_database(serde_json::json!({
        "host": "127.0.0.1", "port": 1, "dbname": "unused",
        "user": "unused", "password": "unused", "schema": "public",
        "connection_number": 1, "timeout": 0.5,
        "direct_url": "postgres://unused:unused@192.0.2.1:5432/unused",
        "runtime": { "user": "unused", "password": "unused" },
    }));

    let started = Instant::now();
    let result = {
        let _env = NonDebugAppEnv::set();
        attome_db::create_runtime_session(&config).await
    };
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "connecting to an unroutable address must fail"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the connect must be bounded by database.timeout (0.5s), took {elapsed:?}"
    );
}

/// Pins 1.3c's outcome: the migrator connection runs `CREATE`/`DROP INDEX
/// CONCURRENTLY`, and it carries no `lock_timeout`. Change this test only
/// together with that decision.
#[tokio::test]
async fn migrator_connection_has_no_lock_timeout() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let (user, password, dbname) = identity(&url);
    let config = config_with_database(serde_json::json!({
        "host": "127.0.0.1", "port": 1, "dbname": dbname,
        "user": "unused", "password": "unused", "schema": "public",
        "connection_number": 1, "timeout": 5.0,
        "direct_url": url,
        "migrator": { "user": user, "password": password },
    }));

    let mut conn = attome_db::create_migrator_connection(&config)
        .await
        .expect("migrator connection must open");
    let lock_timeout = show(&mut conn, "lock_timeout").await;
    let statement_timeout = show(&mut conn, "statement_timeout").await;
    let application_name = show(&mut conn, "application_name").await;
    let _ = conn.close().await;

    assert_eq!(lock_timeout, "0");
    assert_eq!(statement_timeout, "0");
    assert_eq!(application_name, "attome-migrator");
}

/// The throwaway login role P0-1 configures as `database.runtime`. Returns the
/// role's name and password; the caller drops the role.
async fn create_throwaway_runtime_role(admin: &mut sqlx::PgConnection) -> (String, String) {
    let role = format!("attome_runtime_probe_{}", uuid::Uuid::now_v7().simple());
    let password = "throwaway-runtime-probe-pw";
    sqlx::query(&format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"
    ))
    .execute(&mut *admin)
    .await
    .expect("create the throwaway runtime login role");
    (role, password.to_string())
}

/// Forces `APP_ENV` to a non-debug value for the duration of a test, restoring
/// it on drop. `create_runtime_session` reads `APP_ENV`/`DATABASE_URL` from the
/// process environment, and F1's real-world failure is on a production-shaped
/// deployment (no debug `DATABASE_URL` override); without this the test would
/// exercise the tolerated debug path instead of the one it exists to pin.
struct NonDebugAppEnv(Option<String>);

impl NonDebugAppEnv {
    fn set() -> Self {
        let previous = std::env::var("APP_ENV").ok();
        // SAFETY: the acceptance command for this file serializes the binary
        // (`--test-threads=1`), and the guard restores the previous value.
        unsafe { std::env::set_var("APP_ENV", "production") };
        Self(previous)
    }
}

impl Drop for NonDebugAppEnv {
    fn drop(&mut self) {
        // SAFETY: see `set`.
        unsafe {
            match &self.0 {
                Some(value) => std::env::set_var("APP_ENV", value),
                None => std::env::remove_var("APP_ENV"),
            }
        }
    }
}

/// P0-1 (BDB-F1 / D-612) — a session-pinned runtime call must authenticate as
/// `database.runtime` on the `database.direct_url` endpoint, never as the
/// schema-bootstrap `database.user`.
///
/// The defect this pins: the removed `create_direct_connection` took **endpoint and
/// credentials** from `direct_database_url()`, so every workflow execution
/// claim and every secret-rewrap lock ran as the bootstrap identity —
/// contradicting D-324/D-204 and failing `pg_hba` on a runtime-shaped
/// deployment. Here `database.user` is the harness superuser, `database.password`
/// is absent (the D-324 shape) and the runtime identity is a throwaway login
/// role: the connection must report the latter. `database.host:port` is a closed
/// port, so the test can only pass if the endpoint really comes from
/// `direct_url`.
#[tokio::test]
async fn direct_session_authenticates_as_the_runtime_role() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let (admin_user, _, dbname) = identity(&url);
    let mut admin = sqlx::PgConnection::connect(&url)
        .await
        .expect("connect as the harness superuser");
    let (runtime_user, runtime_password) = create_throwaway_runtime_role(&mut admin).await;

    let config = config_with_database(serde_json::json!({
        "host": "127.0.0.1", "port": 1, "dbname": dbname,
        "user": admin_user, "password": serde_json::Value::Null, "schema": "public",
        "connection_number": 1, "timeout": 5.0,
        "direct_url": url,
        "runtime": { "user": runtime_user, "password": runtime_password },
    }));

    // `APP_ENV` is non-debug: the connection must use the runtime identity it
    // was configured with, not the bootstrap identity.
    let mut conn = {
        let _env = NonDebugAppEnv::set();
        attome_db::create_runtime_session(&config)
            .await
            .expect("the runtime session must open on database.direct_url")
    };
    let identity_check =
        attome_db::verify_connection_identity(&mut conn, &runtime_user, &dbname).await;
    let application_name = show(&mut conn, "application_name").await;
    let lock_timeout = show(&mut conn, "lock_timeout").await;
    let statement_timeout = show(&mut conn, "statement_timeout").await;
    let _ = conn.close().await;
    sqlx::query(&format!("DROP ROLE \"{runtime_user}\""))
        .execute(&mut admin)
        .await
        .expect("drop the throwaway runtime role");

    identity_check.expect(
        "P0-1 (BDB-F1/D-612): a session-pinned runtime call must authenticate as \
         database.runtime, never as the schema-bootstrap database.user",
    );
    assert_eq!(application_name, "attome-runtime-session");
    assert_eq!(lock_timeout, attome_db::MIGRATION_LOCK_TIMEOUT);
    assert_eq!(statement_timeout, "0");
}

/// A runtime-session config whose runtime identity is the harness's own, so
/// the session opens whether or not `APP_ENV` is `debug`.
fn runtime_session_config(url: &str) -> AppConfig {
    let (user, password, dbname) = identity(url);
    config_with_database(serde_json::json!({
        "host": "127.0.0.1", "port": 1, "dbname": dbname,
        "user": user, "password": serde_json::Value::Null, "schema": "public",
        "connection_number": 1, "timeout": 5.0,
        "direct_url": url,
        "runtime": { "user": user, "password": password },
    }))
}

/// Plan 4.1 (BDB-F11): an unpooled session is counted for exactly as long as
/// it lives — open 3 → 3, drop 2 (one by `close`, one by plain drop) → 1.
/// Relative to a baseline, because other tests in this binary may hold
/// sessions of their own when run in parallel.
#[tokio::test]
async fn unpooled_sessions_are_counted_while_open() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let config = runtime_session_config(&url);
    let baseline = attome_db::unpooled_sessions_open();

    let mut sessions = Vec::new();
    for _ in 0..3 {
        let conn = attome_db::create_runtime_session(&config)
            .await
            .expect("the runtime session must open");
        sessions.push(attome_db::UnpooledSession::new(conn));
    }
    assert_eq!(attome_db::unpooled_sessions_open(), baseline + 3);

    let (one,): (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&mut *sessions[0])
        .await
        .expect("a counted session is still an ordinary connection");
    assert_eq!(one, 1);

    let closed = sessions.pop().expect("three sessions");
    closed.close().await.expect("a graceful close");
    drop(sessions.pop());
    assert_eq!(attome_db::unpooled_sessions_open(), baseline + 1);

    drop(sessions);
    assert_eq!(attome_db::unpooled_sessions_open(), baseline);
}

/// Plan 4.2 (S7) — what one runtime session costs to open: 200 sequential
/// `create_runtime_session` calls, p50/p99 printed. Ignored because it is a
/// measurement, not a regression check; run it with
/// `cargo test -p attome-db --test unpooled_connection -- --ignored --nocapture runtime_session_connect_cost`.
/// Against a TLS server, point `DATABASE_URL` at it with `sslmode=verify-full`.
#[tokio::test]
#[ignore = "measurement (attome-db plan 4.2), not a regression check"]
async fn runtime_session_connect_cost() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let config = runtime_session_config(&url);
    const SAMPLES: usize = 200;

    let mut micros = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let conn = attome_db::create_runtime_session(&config)
            .await
            .expect("the runtime session must open");
        micros.push(started.elapsed().as_micros());
        let _ = conn.close().await;
    }
    micros.sort_unstable();
    let pct = |p: usize| micros[(SAMPLES * p / 100).min(SAMPLES - 1)] as f64 / 1000.0;
    println!(
        "runtime_session_connect_cost: samples={SAMPLES} p50={:.2}ms p99={:.2}ms max={:.2}ms",
        pct(50),
        pct(99),
        micros[SAMPLES - 1] as f64 / 1000.0
    );
}
