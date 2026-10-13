//! P1.8d / P1.13 step 7 — the "running-server load exercise" P1.13's plan
//! calls for: concurrent-mutation throughput, synchronous audit path
//! (`audit.chainer_enabled = false`) vs the cutover path (`= true`). Both
//! values are set explicitly in this file's own `test_config`, so the
//! comparison is unaffected by which one is the code default.
//!
//! **The default has since flipped (D-316), and not on this test's evidence.**
//! This file was written as the thing that would justify the flip; what
//! actually justified it was the sync path *failing* (F-001/F-010 — a shed
//! audit write rolling back a business write), not the latency delta measured
//! here. What this exercise still owns is the absolute number: D-045's
//! measurement was taken on a single-instance local topology where neither
//! path met guidelines §14.5's budget, and re-running it against a
//! deployment-shaped topology (pgbouncer + replica) remains open.
//!
//! Same `DATABASE_URL`/`TEST_REDIS_HOST`/`TEST_REDIS_PORT` convention as
//! `entity_round_trip.rs` — skips (loudly) when `DATABASE_URL`
//! is unset, except under `CI` (see `attome_testkit`). Run manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test audit_throughput_load -- --test-threads=1 --nocapture
//! ```
//!
//! Deliberately reports numbers rather than hard-asserting an absolute
//! millisecond ceiling: this runs on whatever machine/CI runner happens to
//! execute it, and guidelines §14.5's budgets are explicitly unenforced
//! TARGETs, not yet a gate. What IS asserted is the actual P1.13 claim: the
//! synchronous path's P50 latency scales with concurrency (every mutation
//! serializes on the single per-organization advisory lock — D-002 means
//! there is exactly one, for the whole deployment) while the cutover path's
//! does not (each mutation is an independent, lock-free `audit_ingest`
//! insert).
//!
//! **Deployment-shaped topology (P-audit-chain-hardening item (d), external
//! feedback item 18):** `DATABASE_URL` is a plain connection string — pointing
//! it at a local pgbouncer instance instead of Postgres directly (e.g.
//! `postgres://.../attomedb_test` through pgbouncer's transaction-pooling
//! port) exercises this same test through the pooling layer with no code
//! change here; that re-measurement (and standing up a read replica alongside
//! it) is an infrastructure/ops step this environment cannot perform — see
//! this file's own TODO note below and `P-audit-chain-hardening.md`'s status
//! line. `CONCURRENT_WRITERS` is env-overridable (`AUDIT_LOAD_CONCURRENT_WRITERS`)
//! specifically so that re-run can go well past this file's default of 50
//! (already past the feedback's "N=20+" floor) without recompiling.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::time::{Duration, Instant};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const DEFAULT_CONCURRENT_WRITERS: usize = 50;

/// External feedback item 18 ("run at N=20+ through pgbouncer"): overridable
/// so a deployment-shaped re-run can raise concurrency without recompiling.
/// Read once per test run rather than cached — this is a handful of calls
/// per `#[tokio::test]` invocation, not a hot path.
fn concurrent_writers() -> usize {
    std::env::var("AUDIT_LOAD_CONCURRENT_WRITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CONCURRENT_WRITERS)
}

fn test_config(chainer_enabled: bool) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 4,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 256,
                "max_connection_num_per_ip": 256, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": {conn_num}, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": {conn_num}, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 100000, "authenticated_rpm": 100000, "per_endpoint_limits": {{}} }},
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
            "audit": {{ "chainer_enabled": {chainer_enabled} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        conn_num = concurrent_writers() + 10,
        chainer_enabled = chainer_enabled,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(chainer_enabled: bool) -> Option<EngineSystem> {
    attome_testkit::migrated_db_url()?;

    let config = test_config(chainer_enabled);
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
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));
    Some(system)
}

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
}

fn session_cookie(user_id: Uuid) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: "attome-test".into(),
        aud: "attome-test".into(),
        typ: attome_auth::TokenType::Session,
    };
    let signing_ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &signing_ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

async fn seed_admin(system: &EngineSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("load-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded by attome_security::seed::seed");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway admin grant");

    session_cookie(user_id)
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    let idx = ((sorted.len() as f64 - 1.0) * pct / 100.0).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Provisions one entity with a representative field mix — not just a
/// single text field — creates `concurrent_writers()` records (untimed
/// setup), then fires that many `PATCH`es *concurrently* — each against its
/// own record, so there is no `row_version`/`If-Match` contention muddying
/// the result; the only thing they can possibly serialize on is the audit
/// path itself. Returns the per-request latencies, one per writer.
///
/// External feedback item 18 ("use a representative dataset"): a
/// single-text-field record understates a real audit event's JSONB payload
/// size (P1.5c stores the full event, field-by-field) — `title`/`amount`/
/// `due_on`/`status` below mirror the text/number/date/choice mix any real
/// entity in this platform is likely to have, per `attome_core::FieldType`.
/// `None` when there is no throwaway database configured — propagated so the
/// calling test can `skip_if_no_db!` it and return with a printed reason.
async fn run_concurrent_mutations(chainer_enabled: bool) -> Option<Vec<Duration>> {
    let system = test_system(chainer_enabled).await?;
    let admin_cookie = seed_admin(&system).await;
    // Captured before `system` is consumed below — closed at the end of this
    // function so this mode's connections are fully released before the
    // caller starts the next mode's pool. Without this, two modes' pools
    // (each sized for concurrent_writers()) can overlap and exceed the local
    // Postgres instance's max_connections, surfacing as a raw connection
    // reset under load rather than anything P1.13-related (found by actually
    // running this at 50-way concurrency).
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let writers = concurrent_writers();

    let logicalname = provision_load_test_entity(&app, &admin_cookie).await;

    // Warm the pool: sqlx opens physical connections lazily, so an
    // untimed-phase burst of concurrent_writers() trivial queries forces it
    // to actually establish that many connections *before* the timed phase —
    // otherwise the first measurement is dominated by cold TCP/auth
    // handshake cost common to both modes, masking the audit-path signal
    // this test exists to isolate (found by actually running this: both
    // modes clustered near ~1s P50 until this warm-up was added).
    let mut warmup = tokio::task::JoinSet::new();
    for _ in 0..writers {
        let db = db.clone();
        warmup.spawn(async move {
            sqlx::query("SELECT 1").execute(&db).await.unwrap();
        });
    }
    while warmup.join_next().await.is_some() {}

    let latencies = run_mutation_round(&app, &admin_cookie, &logicalname, writers, 0).await;

    db.close().await;
    Some(latencies)
}

/// Shared by `run_concurrent_mutations` and the soak test below: creates the
/// load-test entity with a representative text/number/date/choice field mix
/// (external feedback item 18) and returns its logicalname.
async fn provision_load_test_entity(app: &axum::Router, admin_cookie: &str) -> String {
    let logicalname = format!("load_test_{}", Uuid::now_v7().simple());

    // sec-fetch-site: same-origin on every cookie-authenticated mutation
    // below — csrf_protect (P-cookie-csrf-hardening) rejects a cookie-
    // authenticated unsafe-method request with neither this nor an allow-
    // listed Origin, and this file's test_config() never sets
    // cors.allowed_origins, so Sec-Fetch-Site is the only viable signal here
    // (same middleware_pipeline.rs/account_disable.rs gap, never reached by
    // CI until this session).
    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Load Test"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(create_entity_req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    for field_body in [
        r#"{"logicalname":"title","name":"Title","field_type":"text"}"#.to_string(),
        r#"{"logicalname":"amount","name":"Amount","field_type":"number"}"#.to_string(),
        r#"{"logicalname":"due_on","name":"Due On","field_type":"date"}"#.to_string(),
        r#"{"logicalname":"status","name":"Status","field_type":"choice",
            "options":{"choices":["open","in_progress","closed"],"multi":false}}"#
            .to_string(),
    ] {
        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .body(Body::from(field_body))
            .unwrap();
        let res = app.clone().oneshot(create_field_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    logicalname
}

/// Shared by `run_concurrent_mutations` and the soak test below: creates
/// `writers` records (untimed, tagged with `round` so values stay distinct
/// across repeated rounds against the same entity) then fires that many
/// `PATCH`es *concurrently* — each against its own record, so there is no
/// `row_version`/`If-Match` contention muddying the result. Returns the
/// per-request latencies, one per writer.
async fn run_mutation_round(
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    writers: usize,
    round: usize,
) -> Vec<Duration> {
    let mut record_ids = Vec::with_capacity(writers);
    for i in 0..writers {
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"title":"seed-{round}-{i}","amount":{i},"due_on":"2026-08-01","status":"open"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let record = body_json(res).await;
        record_ids.push(record["id"].as_str().unwrap().to_owned());
    }

    let mut tasks = tokio::task::JoinSet::new();
    for (i, record_id) in record_ids.into_iter().enumerate() {
        let app = app.clone();
        let logicalname = logicalname.to_owned();
        let admin_cookie = admin_cookie.to_owned();
        tasks.spawn(async move {
            let req = Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/{logicalname}/{record_id}"))
                .header("cookie", &admin_cookie)
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/json")
                // Every seed record above is freshly created (row_version 0,
                // D-005 default), and this is each record's first mutation —
                // If-Match is mandatory on every generic UPDATE (D-079).
                .header("if-match", "\"0\"")
                .body(Body::from(format!(
                    r#"{{"title":"updated-{round}-{i}","amount":{},"due_on":"2026-08-15","status":"closed"}}"#,
                    i * 2
                )))
                .unwrap();
            let start = Instant::now();
            let res = app.oneshot(req).await.unwrap();
            let elapsed = start.elapsed();
            let status = res.status();
            if status != StatusCode::OK {
                let body = body_json(res).await;
                panic!("PATCH #{i} (round {round}) must succeed, got {status}: {body}");
            }
            elapsed
        });
    }

    let mut latencies = Vec::with_capacity(writers);
    while let Some(result) = tasks.join_next().await {
        latencies.push(result.expect("mutation task must not panic"));
    }
    latencies
}

/// External feedback item 18 ("run a long soak test", and a bounded-backlog
/// restatement of "validate ... during failures" for this cutover path):
/// fires several rounds of concurrent mutations against the chainer path
/// (`chainer_enabled = true`), running `attome_audit::chainer::run_once`
/// between rounds — standing in for the supervised `audit_chainer` process
/// this test doesn't spawn — and asserts the ingest backlog is fully
/// drained at the end, not merely "the test didn't crash".
///
/// Rounds/inter-round delay are env-overridable so a real soak run can scale
/// this well past the smoke-sized default: `AUDIT_SOAK_ROUNDS` (default 5),
/// `AUDIT_SOAK_ROUND_DELAY_MS` (default 0). For an actual multi-hour soak
/// (the feedback's literal ask), set `AUDIT_SOAK_ROUNDS` high and
/// `AUDIT_SOAK_ROUND_DELAY_MS` to space rounds out — this environment has no
/// way to run that multi-hour version itself (no live Postgres/Redis), see
/// this file's own TODO note and `P-audit-chain-hardening.md`'s status line.
#[tokio::test]
async fn sustained_chainer_load_keeps_ingest_backlog_bounded() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .with_test_writer()
        .try_init();

    let rounds: usize = std::env::var("AUDIT_SOAK_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let round_delay_ms: u64 = std::env::var("AUDIT_SOAK_ROUND_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let system = skip_if_no_db!(test_system(true).await);
    let admin_cookie = seed_admin(&system).await;
    let db = system.state().base.db.clone();
    // Matches `crates/server/src/bin/audit_chainer.rs`'s CHAIN_BATCH_SIZE
    // constant (config-surface reduction, item 23 — no longer config-driven).
    let batch_size: i64 = 500;
    let app = full_app(system);
    let writers = concurrent_writers();

    let logicalname = provision_load_test_entity(&app, &admin_cookie).await;

    for round in 0..rounds {
        run_mutation_round(&app, &admin_cookie, &logicalname, writers, round).await;

        // Drain whatever this round ingested — mirrors one `audit_chainer`
        // poll iteration (no signer/no external store configured by
        // test_config, matching this file's other test's chainer_enabled
        // path).
        attome_audit::chainer::run_once(&db, None, batch_size, None)
            .await
            .expect("chainer run_once must not error mid-soak");

        let agg = attome_audit::chainer::aggregate_lag(&db)
            .await
            .expect("aggregate_lag");
        println!(
            "soak round {round}/{rounds}: pending_ingest={} max_lag_seconds={}",
            agg.total_pending_ingest, agg.max_lag_seconds
        );

        if round_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(round_delay_ms)).await;
        }
    }

    // Drain any stragglers left by the watermark's contiguous-prefix rule
    // (see chainer.rs module doc) before asserting a clean end state.
    for _ in 0..3 {
        attome_audit::chainer::run_once(&db, None, batch_size, None)
            .await
            .expect("final chainer drain must not error");
    }
    let final_agg = attome_audit::chainer::aggregate_lag(&db)
        .await
        .expect("final aggregate_lag");
    assert_eq!(
        final_agg.total_pending_ingest, 0,
        "chainer must fully drain the ingest backlog across a sustained run, not fall \
         permanently behind — {rounds} rounds of {writers} writers each left \
         {} rows undrained",
        final_agg.total_pending_ingest
    );

    db.close().await;
}

#[tokio::test]
async fn cutover_path_p50_latency_does_not_scale_with_concurrency_like_the_sync_path_does() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .with_test_writer()
        .try_init();

    let mut sync_latencies = skip_if_no_db!(run_concurrent_mutations(false).await);
    let mut cutover_latencies = skip_if_no_db!(run_concurrent_mutations(true).await);

    sync_latencies.sort();
    cutover_latencies.sort();

    let sync_p50 = percentile(&sync_latencies, 50.0);
    let sync_p99 = percentile(&sync_latencies, 99.0);
    let cutover_p50 = percentile(&cutover_latencies, 50.0);
    let cutover_p99 = percentile(&cutover_latencies, 99.0);

    println!(
        "\n=== P1.8d / P1.13 step 7 — {} concurrent mutations ===\n\
         sync    (chainer_enabled=false): P50={sync_p50:?}  P99={sync_p99:?}\n\
         cutover (chainer_enabled=true):  P50={cutover_p50:?}  P99={cutover_p99:?}\n\
         guidelines §14.5 budget for this class: P50<50ms, P99<200ms\n",
        concurrent_writers()
    );

    // The actual P1.13 claim: removing the per-organization advisory lock
    // from the write path must not leave the cutover path *slower* under
    // concurrency than the lock-serialized sync path — P50 is the
    // steady-state number that matters here (P99 is noisier on a shared
    // dev/CI machine and not what this specific claim is about).
    assert!(
        cutover_p50 <= sync_p50,
        "cutover-path P50 ({cutover_p50:?}) must not exceed sync-path P50 ({sync_p50:?}) — \
         if it does, P1.13's whole premise (removing the lock helps throughput) does not hold \
         on this run — and since D-316 the cutover path is what every production deployment \
         runs, so this is now a regression signal, not a pre-flip gate"
    );
}
