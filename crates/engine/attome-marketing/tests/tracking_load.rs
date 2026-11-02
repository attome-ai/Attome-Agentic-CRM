//! E14-T13: collection under load. Posts 2,000 events a second (100 batches
//! of 20) for 60 seconds through the collect route's queueing half
//! (`collect::queue`, the code behind `POST /api/v1/track/collect`, after
//! the licence and flag gate), from many visitors and sixteen /24 networks so
//! no rate limit trips, then writes the same batches as the
//! `marketing_web_event_batch` job does. Passes when every batch is queued,
//! the queueing p95 is under 20 ms and the writer keeps up: it finishes
//! within five seconds of the time the load took to send.
//!
//! The HTTP layers in front of the route are not in the measurement; their
//! cost is `crates/apps/attome/tests/pipeline_overhead.rs`'s.
//!
//! Slow tier, ignored by default; run it on the release machine against the
//! throwaway test stack and record what it prints:
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --release --test tracking_load -- --ignored --nocapture"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]
#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "this measurement test prints its report for the reader"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_marketing::tracking::collect::{CollectRequest, Collected, queue};
use attome_marketing::tracking::writer::{self, WebEventBatch, write_batch};
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use chrono::{SecondsFormat, Utc};
use serde_json::json;
use uuid::Uuid;

fn test_config() -> AppConfig {
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
                "connection_number": 8, "timeout": 5.0
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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod", "jwt_issuer": "attome-test",
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
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_state() -> Option<EngineState> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config).await.expect("connect");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("redis");
    let coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("storage");
    let id = attome_metadata::provision::ensure_entity(
        &db,
        "marketing_tracked_site",
        "marketing_tracked_site",
        None,
        false,
    )
    .await
    .expect("provision marketing_tracked_site");
    for (field, field_type) in [
        ("site_key", "text"),
        ("domains", "text"),
        ("office_networks", "text"),
        ("enabled", "bool"),
    ] {
        attome_metadata::provision::ensure_attribute(
            &db, id, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .expect("provision attribute");
    }
    // The app registers the writer's job type; this binary stands in for it.
    let _ = attome_core::jobs::JOB_TYPES.register(
        attome_jobs::JobType::new(writer::JOB, 1),
        |_state: EngineState, _job: attome_jobs::RegisteredJob| async move {
            Ok::<(), attome_jobs::registry::BoxError>(())
        },
    );
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        coordination,
        storage,
    );
    Some(EngineState::new(base))
}

/// A new enabled site on `domains`; returns its key.
async fn site(state: &EngineState, domains: &str) -> String {
    let key = format!("site-{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO marketing_tracked_site (site_key, domains, enabled) VALUES ($1, $2, true)",
    )
    .bind(&key)
    .bind(domains)
    .execute(&state.base.db)
    .await
    .expect("insert tracked site");
    key
}

/// Events a second the collection must take.
const EVENTS_PER_SECOND: usize = 2_000;
/// Events per batch, as the script sends them.
const PER_BATCH: usize = 20;
/// How long the load runs.
const SECONDS: u64 = 60;
/// Distinct /24 networks the load comes from: each may send 600 batches a
/// minute, so 100 batches a second need at least ten.
const NETWORKS: usize = 16;

fn batch_body(site_key: &str, visitor: Uuid, session: Uuid, n: usize) -> serde_json::Value {
    let at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let events: Vec<_> = (0..PER_BATCH)
        .map(|i| json!({"kind": "page_view", "at": at, "url": format!("https://example.com/p/{n}/{i}"), "title": "p"}))
        .collect();
    json!({
        "site": site_key,
        "visitor": visitor.to_string(),
        "session": session.to_string(),
        "events": events,
    })
}

fn p95(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples
        .get((samples.len() * 95).div_ceil(100).saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "load: run before release (E14-T13)"]
async fn collect_takes_2000_events_a_second() {
    let state = skip_if_no_db!(test_state().await);
    let key = site(&state, "https://example.com").await;
    let batches_per_second = EVENTS_PER_SECOND / PER_BATCH;
    let total = batches_per_second * SECONDS as usize;
    let limit = Arc::new(tokio::sync::Semaphore::new(64));
    let mut tick = tokio::time::interval(Duration::from_secs(1) / batches_per_second as u32);
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(total);
    let mut written = Vec::with_capacity(total);
    for n in 0..total {
        tick.tick().await;
        // A visitor sends a batch a second at most, well under its limit.
        let visitor = Uuid::now_v7();
        let session = Uuid::now_v7();
        let body = batch_body(&key, visitor, session, n);
        written.push(WebEventBatch {
            site_key: key.clone(),
            ip_prefix: format!("198.51.{}.0", n % NETWORKS),
            country: Some("sa".into()),
            user_agent_class: "desktop".into(),
            batch: body.clone(),
        });
        let req = CollectRequest {
            origin: Some("https://example.com".into()),
            client_ip: format!("198.51.{}.7", n % NETWORKS).parse().unwrap(),
            country: Some("SA".into()),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0".into(),
            body,
        };
        let state = state.clone();
        let permit = limit.clone().acquire_owned().await.unwrap();
        tasks.push(tokio::spawn(async move {
            let at = Instant::now();
            let outcome = queue(&state, req).await;
            drop(permit);
            (at.elapsed(), outcome)
        }));
    }
    let mut latencies = Vec::with_capacity(total);
    let mut queued = 0usize;
    for task in tasks {
        let (took, outcome) = task.await.unwrap();
        latencies.push(took);
        if matches!(outcome, Ok(Collected::Queued)) {
            queued += 1;
        }
    }
    let sent_in = started.elapsed();
    let collect_p95 = p95(latencies);

    // The writer's side: the same batches written as the job writes them.
    let write_started = Instant::now();
    let writers = Arc::new(tokio::sync::Semaphore::new(8));
    let mut jobs = Vec::with_capacity(total);
    for batch in written {
        let db = state.base.db.clone();
        let permit = writers.clone().acquire_owned().await.unwrap();
        jobs.push(tokio::spawn(async move {
            let counts = write_batch(&db, &batch).await;
            drop(permit);
            counts
        }));
    }
    let mut events = 0u64;
    for job in jobs {
        events += job.await.unwrap().expect("write batch").written;
    }
    let write_took = write_started.elapsed();
    let write_rate = events as f64 / write_took.as_secs_f64();

    println!(
        "tracking load: {total} batches ({} events) sent in {:.1} s, {queued} queued; \
         collect p95 {:.2} ms; writer {events} events in {:.1} s ({write_rate:.0} events/s)",
        total * PER_BATCH,
        sent_in.as_secs_f64(),
        collect_p95.as_secs_f64() * 1000.0,
        write_took.as_secs_f64(),
    );
    assert_eq!(queued, total, "every batch is queued");
    assert!(
        collect_p95 < Duration::from_millis(20),
        "collect p95 {collect_p95:?}"
    );
    // The queue drains within five seconds of the last request when the
    // writer keeps up with the load.
    assert!(
        write_took <= sent_in + Duration::from_secs(5),
        "the writer took {write_took:?} for load sent in {sent_in:?}"
    );
}
