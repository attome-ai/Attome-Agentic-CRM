//! Regression coverage for `profiler_admin.rs` — the admin-only read API for
//! the "Profiler" dashboard (aggregate call count/avg/min/max/total-since-
//! start per `measure!()` probe, plus a recent-trace waterfall sample per
//! top-level probe, both backed by `attome-profiler` in Redis). This surface
//! previously had zero test coverage.
//!
//! Covers:
//! - non-admin rejection (`403`) on both `GET .../profiler/stats` and
//!   `GET .../profiler/trace` — the "wrong grant" case, matching
//!   `rewrap_admin.rs`'s pattern for the same `strict_authz` + in-handler
//!   `ctx.require_admin()` combination,
//! - the empty-state happy path: no probes recorded yet -> `stats` returns
//!   `200` with an empty array,
//! - `trace`'s `name` validation: empty or whitespace-only `name` is a `422`
//!   even for an admin caller,
//! - `trace`'s `limit` clamping (`q.limit.clamp(1, 50)`): `limit=0` clamps up
//!   to `1`, observed by seeding multiple samples and checking exactly one
//!   comes back,
//! - the real read path: seeding one probe measurement (a top-level probe
//!   plus one dotted sub-part) directly through `attome_profiler::flush` (the
//!   same function `attome-server`'s profiler middleware calls once per
//!   request) and asserting both `stats` (grouped `ApiGroupOut` shape) and
//!   `trace` (`TraceSampleOut` shape) return it with the right numbers,
//! - the audited admin reset (`DELETE /api/v1/admin/profiler/stats`, BPR-31):
//!   non-admin 403, admin 204, the keys actually gone, a second call still
//!   204 — plus the Phase 0 `two_unmatched_paths_record_one_probe_name`
//!   (BPR-01), `#[ignore]`d until BPR-11 collapses unmatched paths.
//!
//! `attome-profiler`'s keyspace (`attome-profiler:stat:*` /
//! `attome-profiler:trace:*`) is flat and global in Redis — `read_stats` scans
//! the *entire* `attome-profiler:stat:*` keyspace, not just keys this test
//! wrote. Tests that assert an exact/empty result set therefore call
//! `clear_profiler_keys` first to get a deterministic baseline, same spirit as
//! `rewrap_admin.rs` using a fresh throwaway Postgres per run — here it's a
//! fresh logical slice of the shared throwaway Redis instead.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `rewrap_admin.rs`/`jobs_admin.rs`.
//! **Verified 2026-08-24 (MAINT-10): 5 passed, 0 failed, 39.71s** against a
//! real Postgres and Redis, retiring the "Not run in this session (code-only,
//! no DB/Redis access) — TODO: run against a throwaway database" note this
//! header carried. The **elapsed time** is the evidence, not the `ok`: this
//! suite reports green in ~0.01s when `DATABASE_URL` is absent, so a pass
//! alone does not distinguish a real run from a skipped one.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test profiler_admin -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::time::Duration;

use attome_api::EngineSystem;
use attome_cache::RedisPool;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_profiler::ProbeRecord;
use attome_server::AppState;
use attome_testkit::point_config_at;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use fred::prelude::*;
use fred::types::Scanner;
use futures_util::TryStreamExt;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    // The database block above is a placeholder (`user`/`password` "unused");
    // `attome_testkit::migrated_db_url()` has already rewritten `DATABASE_URL` to this
    // binary's throwaway clone, so point the pool at exactly that URL. Without
    // this the suite only runs against a trust-auth Postgres — the same helper
    // `audit_coverage_emission.rs` carries for the same reason.
    if let Some(url) = attome_testkit::migrated_db_url() {
        point_config_at(&mut config, &url);
    }
    config
}

async fn build_test_system() -> Option<EngineSystem> {
    attome_testkit::migrated_db_url()?;

    let config = test_config();
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
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    Some(system)
}

/// The system and router every test in this binary shares (build-loop plan,
/// Phase 3 task 4). Building a fresh `EngineSystem` per test cost ~0.3 s each;
/// the tests already share this binary's database, and each one provisions
/// its own uniquely named entities, users and roles, so sharing the in-memory
/// system adds no coupling the database did not already have. Tests run on
/// `attome_testkit::shared_runtime`, which keeps the pools' connections alive
/// between tests.
#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn state(&self) -> &EngineState {
        &self.state
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            Some(TestSystem {
                state,
                app: build_app(system),
            })
        })
        .await
        .clone()
}

fn full_app(system: TestSystem) -> axum::Router {
    system.app
}

fn build_app(system: EngineSystem) -> axum::Router {
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

async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("profiler-admin-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    if admin {
        let privilege_id: Uuid =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
                .fetch_one(db)
                .await
                .expect("system.admin privilege must already be seeded by attome_security::seed");
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
    }

    (user_id, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn stats_request(cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/v1/admin/profiler/stats")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

fn trace_request(cookie: &str, name: &str, limit: Option<i64>) -> Request<Body> {
    let mut uri = format!("/api/v1/admin/profiler/trace?name={name}");
    if let Some(limit) = limit {
        uri.push_str(&format!("&limit={limit}"));
    }
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

/// `DELETE /api/v1/admin/profiler/stats` with a cookie session. Carries
/// `origin`/`sec-fetch-site` so `attome_server::middleware::csrf::csrf_protect`
/// treats it as same-origin (the header a real browser sends) — without them a
/// mutating cookie request is refused by CSRF, and the 403/204 assertions below
/// would be measuring the wrong middleware.
fn reset_request(cookie: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri("/api/v1/admin/profiler/stats")
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

/// Deletes every profiler key in the general Redis pool — the current
/// `attome-profiler:*` namespace and the pre-rename `profiler:*` one.
/// `read_stats` scans the whole `attome-profiler:stat:*` keyspace regardless
/// of which test wrote it, so tests asserting an exact or empty result set need
/// a clean slate rather than assuming no other test (or prior failed run
/// against the same throwaway Redis) left data behind.
async fn clear_profiler_keys(redis: &RedisPool) {
    let mut keys = Vec::new();
    for pattern in ["attome-profiler:*", "profiler:*"] {
        let mut stream = redis.next().scan(pattern, Some(200u32), None);
        while let Some(mut page) = stream.try_next().await.expect("scan profiler keys") {
            if let Some(page_keys) = page.take_results() {
                keys.extend(page_keys.into_iter().filter_map(|k| k.into_string()));
            }
        }
    }
    for key in keys {
        let _: i64 = redis.del(&key).await.expect("del profiler key");
    }
}

/// Wrong-grant rejection: a non-admin session must never be able to read
/// profiler stats or traces, even though this data isn't customer data — it's
/// still an internal-operations surface.
#[test]
fn non_admin_gets_403_on_stats_and_trace() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, non_admin_cookie) = seed_user(&system, false).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(stats_request(&non_admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = app
            .clone()
            .oneshot(trace_request(&non_admin_cookie, "some.probe", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    })
}

/// Empty-state happy path: with no probes recorded (in this test's cleared
/// slice of Redis), `stats` still returns `200` — `group_hierarchy(vec![])`
/// produces an empty `Vec`, not an error.
#[test]
fn admin_with_no_probes_recorded_gets_empty_stats() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        clear_profiler_keys(&system.state().base.redis).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(stats_request(&admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body, serde_json::json!([]));
    })
}

/// `trace`'s `name` query param must be a real, non-blank probe name — an
/// empty or whitespace-only value is a `422 Validation`, even for an admin
/// caller who is otherwise fully entitled to read the endpoint.
#[test]
fn trace_rejects_empty_or_whitespace_name_even_as_admin() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(trace_request(&admin_cookie, "", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // `%20` = a single space — whitespace-only, not merely empty.
        let resp = app
            .clone()
            .oneshot(trace_request(&admin_cookie, "%20", None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

/// `limit` clamping (`q.limit.clamp(1, 50)`): `limit=0` must clamp up to `1`,
/// observed here by seeding several trace samples for one probe and checking
/// exactly one comes back. The upper bound (`limit=999` clamping to `50`)
/// isn't independently observable this way — `TRACE_CAP` already caps the
/// stored ring at 50 entries, so a large requested limit and the storage cap
/// look identical from the outside unless the test first pushes more than 50
/// real samples through `flush`. That's a source-code-verified invariant
/// (`attome-profiler/src/lib.rs`'s `q.limit.clamp(1, 50)` and `TRACE_CAP: i64 =
/// 50`) rather than one this test independently proves; a `limit=999` request
/// is still exercised below to confirm it doesn't error or truncate below
/// what's actually stored.
#[test]
fn trace_limit_clamps_zero_up_to_one() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let redis = system.state().base.redis.clone();
        let probe_name = format!("clamp.probe.{}", Uuid::now_v7());

        for i in 0..5u64 {
            attome_profiler::flush(&redis, &probe_name, Duration::from_millis(10 + i), &[])
                .await
                .expect("seed trace sample");
        }

        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(trace_request(&admin_cookie, &probe_name, Some(0)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let samples = body.as_array().expect("trace response must be an array");
        assert_eq!(
            samples.len(),
            1,
            "limit=0 must clamp up to 1, not be treated as 'no limit': {body:?}"
        );

        let resp = app
            .clone()
            .oneshot(trace_request(&admin_cookie, &probe_name, Some(999)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let samples = body.as_array().expect("trace response must be an array");
        assert_eq!(
            samples.len(),
            5,
            "limit=999 must return every stored sample (5, well under the 50 cap), not error: {body:?}"
        );
    })
}

/// The real read path: seed one probe measurement (a top-level probe plus one
/// dotted sub-part) through `attome_profiler::flush` — the same function
/// `attome-server`'s profiler middleware calls once per request — then confirm
/// both `stats` (`ApiGroupOut` shape from `group_hierarchy`) and `trace`
/// (`TraceSampleOut` shape) return it with the right numbers.
#[test]
fn stats_and_trace_return_a_seeded_probe_measurement() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let redis = system.state().base.redis.clone();
        clear_profiler_keys(&redis).await;

        let top_level = "entity.create";
        let sub_part = "entity.create.db_insert";
        attome_profiler::flush(
            &redis,
            top_level,
            Duration::from_millis(120),
            &[ProbeRecord {
                name: sub_part.to_string(),
                duration: Duration::from_millis(80),
            }],
        )
        .await
        .expect("seed a real probe measurement");

        let app = full_app(system);

        // `stats`: one ApiGroupOut, sub-part nested under it by dotted prefix.
        let resp = app
            .clone()
            .oneshot(stats_request(&admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let groups = body.as_array().expect("stats response must be an array");
        assert_eq!(groups.len(), 1, "exactly one top-level group: {body:?}");
        let group = &groups[0];
        assert_eq!(group["api"]["name"], top_level);
        assert_eq!(group["api"]["count"].as_u64().unwrap(), 1);
        let avg_ms = group["api"]["avg_ms"].as_f64().unwrap();
        assert!(
            (avg_ms - 120.0).abs() < 0.5,
            "api avg_ms should be ~120, got {avg_ms}"
        );
        let parts = group["parts"].as_array().expect("parts must be an array");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0]["name"], sub_part);
        assert_eq!(parts[0]["count"].as_u64().unwrap(), 1);
        let part_avg_ms = parts[0]["avg_ms"].as_f64().unwrap();
        assert!(
            (part_avg_ms - 80.0).abs() < 0.5,
            "sub-part avg_ms should be ~80, got {part_avg_ms}"
        );

        // `trace`: one TraceSampleOut for the top-level probe name, carrying the
        // same sub-part.
        let resp = app
            .clone()
            .oneshot(trace_request(&admin_cookie, top_level, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let samples = body.as_array().expect("trace response must be an array");
        assert_eq!(samples.len(), 1, "exactly one trace sample: {body:?}");
        let total_ms = samples[0]["total_ms"].as_f64().unwrap();
        assert!(
            (total_ms - 120.0).abs() < 0.5,
            "trace total_ms should be ~120, got {total_ms}"
        );
        let trace_parts = samples[0]["parts"]
            .as_array()
            .expect("trace parts must be an array");
        assert_eq!(trace_parts.len(), 1);
        assert_eq!(trace_parts[0]["name"], sub_part);
        let trace_part_ms = trace_parts[0]["ms"].as_f64().unwrap();
        assert!(
            (trace_part_ms - 80.0).abs() < 0.5,
            "trace sub-part ms should be ~80, got {trace_part_ms}"
        );
    })
}

/// BPR-01 (Phase 0, failing test first): two different unmatched request paths
/// must land on **one** probe name per method. Until BPR-11, `attome-server`'s
/// profiler middleware named an unmatched request from the raw
/// `req.uri().path()`, so each scanned path became its own key — the
/// unbounded, pre-auth key cardinality BPR-F1 describes. BPR-11 made it
/// `"{METHOD} (unmatched)"`, so this test is green and no longer ignored.
#[test]
fn two_unmatched_paths_record_one_probe_name() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let redis = system.state().base.redis.clone();
        clear_profiler_keys(&redis).await;

        let app = attome_server::apply_profiler_layer(full_app(system), redis.clone());

        for path in ["/no-such-a", "/no-such-b"] {
            // No credentials: the request is answered by the auth layer (401)
            // before it ever reaches the router, and the profiler layer is
            // outermost, so it still records a probe — which is exactly why
            // BPR-F1 is a *pre-auth* cardinality problem. The status is
            // irrelevant to what this test measures.
            let _ = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        // The flush is detached from the response, so poll until the GET probe
        // set stops changing (both detached flushes have landed), capped at 2 s.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut settled: Vec<String> = Vec::new();
        loop {
            let rows = attome_profiler::read_stats(&redis)
                .await
                .expect("read_stats");
            let mut get_rows: Vec<String> = rows
                .into_iter()
                .map(|r| r.name)
                .filter(|name| name.starts_with("GET "))
                .collect();
            get_rows.sort();
            if !get_rows.is_empty() && get_rows == settled {
                assert_eq!(
                    get_rows.len(),
                    1,
                    "BPR-11: two unmatched paths must collapse to one probe name, got {get_rows:?}"
                );
                assert_eq!(get_rows[0], "GET (unmatched)");
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the GET probes never settled within 2 s; last {get_rows:?}"
            );
            settled = get_rows;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

/// BPR-31: a non-admin session cannot reset the profiler. The request carries
/// the same-origin CSRF headers a browser would send, so a 403 here is the
/// authorization gate rather than `csrf_protect`.
#[test]
fn non_admin_gets_403_on_reset() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, non_admin_cookie) = seed_user(&system, false).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(reset_request(&non_admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    })
}

/// BPR-31: an admin's reset answers 204, removes every profiler key (so an
/// operator can start a clean measurement window without flushing the store
/// the security controls live on), and is idempotent.
#[test]
fn admin_reset_returns_204_clears_the_keyspace_and_is_idempotent() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let redis = system.state().base.redis.clone();
        clear_profiler_keys(&redis).await;

        for name in ["reset.probe.a", "reset.probe.b"] {
            attome_profiler::flush(&redis, name, Duration::from_millis(5), &[])
                .await
                .expect("seed a probe");
        }
        assert_eq!(
            attome_profiler::read_stats(&redis)
                .await
                .expect("read_stats")
                .len(),
            2,
            "two seeded probes must be visible before the reset"
        );

        let app = full_app(system);
        let resp = app
            .clone()
            .oneshot(reset_request(&admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let remaining = attome_profiler::read_stats(&redis)
            .await
            .expect("read_stats");
        assert!(
            remaining.is_empty(),
            "reset must clear the whole profiler keyspace: {remaining:?}"
        );

        // Idempotent: nothing left to delete, still 204.
        let resp = app
            .clone()
            .oneshot(reset_request(&admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    })
}
