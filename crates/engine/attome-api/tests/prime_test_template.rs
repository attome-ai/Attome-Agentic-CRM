//! Primes a *test template* database with the platform bundles.
//!
//! Every DB-backed suite clones a migrated template per test binary
//! (`attome_testkit::test_db_url`, D-343), and the first `EngineSystem::build` on
//! that clone applies every platform bundle (D-478): about 94 entities, 750
//! attributes, their queries and views, all as runtime DDL. Measured
//! 2026-09-24: ~107 s per test binary, paid again by every binary. Later
//! builds on the same clone take ~2 s because each bundle's watermark hash
//! matches.
//!
//! This target runs that same bare build once, against the template itself,
//! so every clone starts with the bundles applied. It registers no engine
//! models on purpose. Platform bundles apply unconditionally in
//! `EngineSystem::build`, while per-model seeds depend on what a suite registers,
//! so a bare build is exactly the common prefix of every suite's own build.
//! A suite's build then re-checks each bundle watermark (a no-op when the
//! hash matches, a re-apply when a bundle changed) and runs its own seeds, so
//! a stale primed template is still correct, only slower.
//!
//! Suites that must observe a first-time apply use
//! `attome_testkit::test_db_url_unprimed()`.
//!
//! Test-DB exemption (coding-guidelines §4): this writes only to the throwaway
//! test cluster's template, never to a deployment.
//!
//! Run (see `scripts/run-integration-tests.ps1`, which does this for you):
//!   ATTOME_TEST_SHARED_DB=1 DATABASE_URL=<template url> APP_ENV=debug \
//!   cargo test -p attome-api --test prime_test_template -- --ignored --test-threads=1
//!
//! It is `#[ignore]`d rather than behind a cargo feature: a feature on
//! `attome-api` would change its build hash and compile it (and everything
//! above it) a second time, the problem build-loop-opt-review Phase 2 removes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;

fn prime_config() -> AppConfig {
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
                "s3_endpoint": "{s3_endpoint}", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
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
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        s3_endpoint =
            std::env::var("TEST_S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into()),
    );
    serde_json::from_str(&json).expect("prime config JSON must deserialize into AppConfig")
}

#[tokio::test]
#[ignore = "run only by scripts/run-integration-tests.ps1 to prime the test template"]
async fn prime_platform_bundles_into_the_template() {
    assert!(
        std::env::var_os("ATTOME_TEST_SHARED_DB").is_some(),
        "set ATTOME_TEST_SHARED_DB=1 so this writes to the template itself, not a clone"
    );
    let url = attome_testkit::configured_db_url().expect("DATABASE_URL must name the template");

    let mut config = prime_config();
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect template");
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
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        redis_coordination,
        storage,
    );

    let started = std::time::Instant::now();
    let system = EngineSystem::builder(EngineState::new(base))
        .build()
        .await
        .expect("bare EngineSystem::build primes the platform bundles");
    eprintln!(
        "primed the template in {:.1}s",
        started.elapsed().as_secs_f64()
    );

    // Stamp the `seed_for_tests` fixtures every DB-backed test setup calls.
    // Each is a no-op on this metadata (the bundles above already applied it),
    // but running it here writes the stamp into the template, so a clone starts
    // with the fixtures already verified instead of re-walking ~430 attributes
    // on its first test.
    attome_service::seed::seed_for_tests(&db)
        .await
        .expect("stamp the attome-service fixture");
    attome_project::seed::seed_for_tests(&db)
        .await
        .expect("stamp the attome-project fixture");
    attome_dashboard::seed::seed_for_tests(&db)
        .await
        .expect("stamp the attome-dashboard fixture");
    attome_audit::seed(&db)
        .await
        .expect("stamp the attome-audit fixture");
    // The dashboard fixture walk rewrites `widget_type`'s choice list to the
    // bundle's placeholder as a side effect (test harnesses call `seed_body`
    // right after it to put the real list back). The walk is skipped from now
    // on, so the template must hold the real list.
    attome_dashboard::seed::seed_body(&db)
        .await
        .expect("resync the widget_type choices after the fixture walk");

    // Clones need a template with no open connections.
    drop(system);
    db.close().await;
}
