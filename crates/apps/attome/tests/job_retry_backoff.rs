//! T2-12 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §3.11) — `attome::jobs::handle_platform_job`
//! now wraps `dispatch_platform_job` (`crates/server/src/jobs.rs`) so that
//! any failed attempt gets `attome_jobs::apply_retry_backoff` applied to its
//! row, instead of leaving `run_at` untouched the way apalis-sql 0.7.4's own
//! failure path (`PostgresStorage::update`) does. Without that fix,
//! `apalis.get_jobs`'s `run_at < now()` predicate (migration
//! `0014_apalis_jobs.sql`) re-claims a `Failed` row on the very next ~100ms
//! poll -- a transient outage (SMTP down, an unreachable dependency, ...)
//! burns the whole 25-attempt budget in a couple of seconds and dead-letters
//! the job.
//!
//! This suite calls `handle_platform_job` directly (not through a live
//! apalis `Monitor`/poll loop -- growing a real 10s/20s/40s backoff in a
//! unit test would make it slow and flaky) against a job row this test
//! seeds itself, using the `Unrecognized` envelope arm as a deterministic,
//! side-effect-free failure (no SMTP/network dependency) so the test proves
//! the actual wiring: `Attempt`/`TaskId` extraction -> `apply_retry_backoff`
//! -> `run_at` written on the correct row -- while still exercising the
//! real function apalis calls in production, not a re-implementation of it.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) to build the `EngineState`/`AppState`
//! `handle_platform_job` takes as a parameter -- same convention as
//! `account_throttle.rs`. Skips cleanly when `DATABASE_URL` is unset.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p server --test job_retry_backoff -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use apalis::prelude::{Attempt, Data, TaskId};
use attome::jobs::MigratorDb;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_jobs::JobEnvelope;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use std::str::FromStr;

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4096, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000 }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }},
            "jobs": {{ "history_retention_days": 7 }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

/// Builds just enough state for `handle_platform_job` -- no router, no
/// `EngineSystem`/license (the `Unrecognized` arm this suite drives never
/// touches the metadata registry) -- against a throwaway Postgres + Redis.
async fn test_state(config: AppConfig) -> Option<(EngineState, attome_db::DbPool)> {
    attome_testkit::migrated_db_url()?;

    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
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
    let db_readonly = db.clone();
    let db_migrator = db.clone();

    let base = AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    );
    let db_for_row_ops = base.db.clone();
    Some((EngineState::new(base), db_for_row_ops))
}

/// Inserts a bare `apalis.jobs` row this test fully controls, shaped like a
/// real one (`push_job`'s own status/attempts defaults) but with an id we
/// pick, so we can call `handle_platform_job` directly with a matching
/// `TaskId` and then read back what it wrote to `run_at`.
async fn seed_row(db: &attome_db::DbPool) -> String {
    let id = apalis::prelude::TaskId::new().to_string();
    sqlx::query(
        "INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts, run_at) \
         VALUES ('{}'::jsonb, $1, 'platform_job', 'Pending', 0, 25, now())",
    )
    .bind(&id)
    .execute(db)
    .await
    .expect("seed a bare apalis.jobs row");
    id
}

async fn run_at(db: &attome_db::DbPool, id: &str) -> chrono::DateTime<Utc> {
    sqlx::query_scalar("SELECT run_at FROM apalis.jobs WHERE id = $1")
        .bind(id)
        .fetch_one(db)
        .await
        .expect("fetch run_at")
}

/// A deterministic, side-effect-free failure: an envelope with a version/
/// variant no `EngineJob` recognizes always hits `dispatch_platform_job`'s
/// `Unrecognized` arm and returns `Err`, without touching SMTP, attome-metadata,
/// or any other engine.
fn unrecognized_job() -> JobEnvelope<EngineJob> {
    let envelope = serde_json::json!({
        "version": 255,
        "variant": "NoSuchJobVariant",
        "payload": null,
        "trace_context": null
    });
    serde_json::from_value(envelope).expect(
        "JobEnvelope<EngineJob> must decode an unknown variant \
        into Unrecognized rather than failing to deserialize at all",
    )
}

#[tokio::test]
async fn a_failed_attempt_pushes_run_at_forward_instead_of_leaving_it_untouched() {
    let config = test_config();
    let (attome_state, db) = skip_if_no_db!(test_state(config.clone()).await);
    let id = seed_row(&db).await;

    let before = Utc::now();
    let result = attome::jobs::handle_platform_job(
        unrecognized_job(),
        Data::new(db.clone()),
        Data::new(MigratorDb(db.clone())),
        Data::new(config),
        Data::new(attome_state),
        Attempt::new_with_value(1),
        TaskId::from_str(&id).expect("valid TaskId"),
    )
    .await;

    assert!(
        result.is_err(),
        "an Unrecognized envelope must fail this attempt"
    );

    let after = run_at(&db, &id).await;
    let delta = (after - before).num_seconds();
    assert!(
        delta >= 8,
        "a failed attempt must push run_at forward (~10s for attempt 1), got {delta}s -- if this \
         is ~0s, apalis's next ~100ms poll would re-claim the row instantly, which is exactly the \
         T2-12 bug"
    );
}

#[tokio::test]
async fn repeated_failures_grow_the_backoff_so_a_short_outage_cannot_burn_the_whole_budget() {
    let config = test_config();
    let (attome_state, db) = skip_if_no_db!(test_state(config.clone()).await);
    let id = seed_row(&db).await;

    let mut previous_delta = 0i64;
    for attempt in 1..=3usize {
        let before = Utc::now();
        let result = attome::jobs::handle_platform_job(
            unrecognized_job(),
            Data::new(db.clone()),
            Data::new(MigratorDb(db.clone())),
            Data::new(config.clone()),
            Data::new(attome_state.clone()),
            Attempt::new_with_value(attempt),
            TaskId::from_str(&id).expect("valid TaskId"),
        )
        .await;
        assert!(result.is_err(), "attempt {attempt} must fail");

        let after = run_at(&db, &id).await;
        let delta = (after - before).num_seconds();
        assert!(
            delta > previous_delta,
            "attempt {attempt}'s backoff ({delta}s) must exceed attempt {}'s ({previous_delta}s) \
             -- growth is what keeps a real ~60s outage under the ~3-attempt bound the T2-12 \
             checklist requires, instead of the pre-fix ~100ms-per-attempt spiral that burned all \
             25 attempts in a couple of seconds",
            attempt.saturating_sub(1).max(1)
        );
        previous_delta = delta;
    }
}
