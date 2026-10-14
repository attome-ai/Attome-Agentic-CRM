//! Integration tests for M89 Change Intelligence, item 1 —
//! `GET /api/v1/admin/changes` (`crate::changes_admin`).
//!
//! Seeds rows directly into three source tables that do NOT depend on the
//! audit chainer (`metadata_change_log`, `license`,
//! `metadata_bundle_plan`) — a deliberate choice: `security`/`ai`/
//! `settings` read `audit_header`, which under
//! `audit.chainer_enabled` (default `true`, unset in this test's config)
//! only gets a row once the chainer process drains `audit_ingest`, which
//! this test harness never runs. Direct SQL against a throwaway test
//! database is one of coding-guidelines.md §4's four narrow exemptions.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis — same convention as
//! `settings_admin.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test changes_admin -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &url);
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

async fn seed_user(db: &attome_db::DbPool, label: &str) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("changes-test-{label}-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    (user_id, session_cookie(user_id))
}

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let (user_id, cookie) = seed_user(db, "admin").await;
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
    (user_id, cookie)
}

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Seeds one row each into `metadata_change_log`,
/// `license`, and `metadata_bundle_plan` (`succeeded`),
/// at three distinct, strictly increasing timestamps within `window_start`
/// so the merge/sort/pagination logic under test has real cross-source data
/// to order — not just one source repeated.
async fn seed_three_sources(
    db: &attome_db::DbPool,
    window_start: DateTime<Utc>,
) -> (Uuid, Uuid, Uuid) {
    let t_metadata = window_start + chrono::Duration::minutes(1); // oldest
    let t_license = window_start + chrono::Duration::minutes(2); // middle
    let t_bundle = window_start + chrono::Duration::minutes(3); // newest

    let entity_ref = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_change_log (entity_ref, logicalname, change_kind, created_at) \
         VALUES ($1, $2, 'upsert', $3)",
    )
    .bind(entity_ref)
    .bind("changes_admin_test_entity")
    .bind(t_metadata)
    .execute(db)
    .await
    .expect("insert throwaway metadata_change_log row");

    let license_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO license \
         (id, deployment_id, domain, tier, max_users, expiry, issued_at, signature) \
         VALUES ($1, 'changes-admin-test-deployment', 'changes-admin-test.example', 'paid', 10, \
                 NOW() + interval '1 year', $2, 'test-signature-not-real')",
    )
    .bind(license_id)
    .bind(t_license)
    .execute(db)
    .await
    .expect("insert throwaway license row");

    let plan_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_bundle_plan \
         (id, status, bundle, plan, bundle_hash, basis_hash, format_version, platform_version, \
          applied_count, finished_at) \
         VALUES ($1, 'succeeded', '{}'::jsonb, '{}'::jsonb, 'test-bundle-hash', 'test-basis-hash', \
                 'attome-bundle/v1', 'test-platform', 3, $2)",
    )
    .bind(plan_id)
    .bind(t_bundle)
    .execute(db)
    .await
    .expect("insert throwaway succeeded bundle plan row");

    (entity_ref, license_id, plan_id)
}

/// The core aggregation/ordering proof: three sources (metadata, license,
/// bundle) seeded at distinct timestamps come back in one feed, newest
/// first, matching the DB insert order's inverse.
#[test]
fn feed_aggregates_and_orders_across_sources() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;

        // A window far enough in the past that no other test in this binary
        // (run with --test-threads=1, per this repo's DB-suite convention)
        // plausibly writes into it.
        let window_start = Utc::now() - chrono::Duration::days(3000);
        let (entity_ref, license_id, plan_id) = seed_three_sources(&db, window_start).await;
        let from = window_start;
        let to = window_start + chrono::Duration::minutes(10);

        let app = full_app(system);
        // `Z`, not `+00:00`: an unencoded `+` in a query string decodes to a
        // space, and the handler rightly rejects that timestamp with 400.
        let uri = format!(
            "/api/v1/admin/changes?from={}&to={}",
            from.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            to.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        );
        let resp = app.oneshot(get_req(&uri, &admin_cookie)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        let items = body["items"].as_array().expect("items array");
        assert_eq!(
            items.len(),
            3,
            "expected exactly the 3 seeded rows within [from, to], got: {items:?}"
        );
        assert_eq!(body["total"], 3);

        // Newest first: bundle (t+3m), then license (t+2m), then metadata (t+1m).
        assert_eq!(items[0]["kind"], "bundle");
        assert_eq!(items[0]["reference"], plan_id.to_string());
        assert_eq!(items[1]["kind"], "license");
        assert_eq!(items[1]["reference"], license_id.to_string());
        assert_eq!(items[2]["kind"], "metadata");
        assert_eq!(items[2]["reference"], entity_ref.to_string());

        // Metadata carries no actor (no column exists); license carries no
        // actor either (issued outside the app); bundle's actor is the
        // requesting user when one was recorded (none was bound here, so NULL).
        assert!(items[0]["actor"].is_null());
        assert!(items[1]["actor"].is_null());
        assert!(items[2]["actor"].is_null());
    })
}

/// The `kind` filter narrows the feed to exactly one source.
#[test]
fn kind_filter_narrows_to_one_source() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;

        let window_start = Utc::now() - chrono::Duration::days(3100);
        let (_, license_id, _) = seed_three_sources(&db, window_start).await;
        let from = window_start;
        let to = window_start + chrono::Duration::minutes(10);

        let app = full_app(system);
        let uri = format!(
            "/api/v1/admin/changes?from={}&to={}&kind=license",
            from.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            to.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        );
        let resp = app.oneshot(get_req(&uri, &admin_cookie)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        let items = body["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["kind"], "license");
        assert_eq!(items[0]["reference"], license_id.to_string());
    })
}

/// An unrecognized `kind` value is a validation error naming it, not a
/// silently-empty result.
#[test]
fn unknown_kind_is_validation_error() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let app = full_app(system);

        let resp = app
            .oneshot(get_req(
                "/api/v1/admin/changes?kind=not_a_real_kind",
                &admin_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("not_a_real_kind"),
            "validation error should name the bad kind: {body:?}"
        );
    })
}

/// A non-admin caller is refused — this is a `system.admin`-gated surface
/// like every other admin route in this crate.
#[test]
fn non_admin_caller_is_forbidden() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, member_cookie) = seed_user(&db, "member").await;
        let app = full_app(system);

        let resp = app
            .oneshot(get_req("/api/v1/admin/changes", &member_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    })
}

// ── keyset (cursor) paging ────────────────────────────────────────────────

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// A window no other test (or earlier run of this one) writes into: a
/// random day between ~9 and ~64 years back.
fn private_window_start() -> DateTime<Utc> {
    let days = 3300 + (Uuid::new_v4().as_u128() % 20_000) as i64;
    let t = Utc::now() - chrono::Duration::days(days);
    // Whole seconds, so `t + n s` round-trips exactly through the wire.
    DateTime::from_timestamp(t.timestamp(), 0).unwrap()
}

const BULK_METADATA: i64 = 520;

/// Seeds, at `t0 + n seconds`:
/// - `BULK_METADATA` metadata rows, one per second `n = 0..BULK_METADATA`
///   (more than the old 500-per-source cap on its own);
/// - one extra metadata row at `n = 100` (a same-source timestamp tie,
///   inserted last so it has the larger bigserial id);
/// - one license row and one bundle row at each of `n = 0, 100, 200, 300,
///   400` — identical timestamps across three sources.
///
/// Returns `(t0, tie_entity_ref)`.
async fn seed_interleaved(db: &attome_db::DbPool) -> (DateTime<Utc>, Uuid) {
    let t0 = private_window_start();
    sqlx::query(
        "INSERT INTO metadata_change_log (entity_ref, logicalname, change_kind, created_at) \
         SELECT gen_random_uuid(), 'changes_keyset_' || g, 'upsert', $1 + g * interval '1 second' \
         FROM generate_series(0, $2 - 1) AS g",
    )
    .bind(t0)
    .bind(BULK_METADATA)
    .execute(db)
    .await
    .expect("bulk metadata rows");
    let tie_ref = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_change_log (entity_ref, logicalname, change_kind, created_at) \
         VALUES ($1, 'changes_keyset_tie', 'upsert', $2)",
    )
    .bind(tie_ref)
    .bind(t0 + chrono::Duration::seconds(100))
    .execute(db)
    .await
    .expect("tie metadata row");
    for n in [0i64, 100, 200, 300, 400] {
        let at = t0 + chrono::Duration::seconds(n);
        sqlx::query(
            "INSERT INTO license \
             (id, deployment_id, domain, tier, max_users, expiry, issued_at, signature) \
             VALUES ($1, 'changes-keyset-test', 'changes-keyset.example', 'paid', 10, \
                     NOW() + interval '1 year', $2, 'test-signature-not-real')",
        )
        .bind(Uuid::now_v7())
        .bind(at)
        .execute(db)
        .await
        .expect("license row");
        sqlx::query(
            "INSERT INTO metadata_bundle_plan \
             (id, status, bundle, plan, bundle_hash, basis_hash, format_version, platform_version, \
              applied_count, finished_at) \
             VALUES ($1, 'succeeded', '{}'::jsonb, '{}'::jsonb, 'test-bundle-hash', \
                     'test-basis-hash', 'attome-bundle/v1', 'test-platform', 1, $2)",
        )
        .bind(Uuid::now_v7())
        .bind(at)
        .execute(db)
        .await
        .expect("bundle row");
    }
    (t0, tie_ref)
}

/// Pages through `base_query` with `cursor` until `next_cursor` is null.
/// Returns every item plus the first page's `total`.
async fn page_all(
    app: &axum::Router,
    cookie: &str,
    base_query: &str,
) -> (Vec<serde_json::Value>, serde_json::Value) {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    let mut first_total = serde_json::Value::Null;
    for page in 0.. {
        assert!(page < 1000, "paging did not terminate");
        let uri = match &cursor {
            None => format!("/api/v1/admin/changes?{base_query}"),
            Some(c) => format!("/api/v1/admin/changes?{base_query}&cursor={c}"),
        };
        let resp = app.clone().oneshot(get_req(&uri, cookie)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let body = body_json(resp).await;
        if page == 0 {
            first_total = body["total"].clone();
        } else {
            assert!(body["total"].is_null(), "total is only on the first page");
        }
        items.extend(body["items"].as_array().expect("items").iter().cloned());
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    (items, first_total)
}

fn kind_rank(kind: &str) -> usize {
    [
        "metadata",
        "bundle",
        "query",
        "workflow",
        "dashboard",
        "content",
        "license",
        "security",
        "ai",
        "settings",
    ]
    .iter()
    .position(|k| *k == kind)
    .expect("known kind")
}

fn occurred_at(item: &serde_json::Value) -> DateTime<Utc> {
    item["occurred_at"]
        .as_str()
        .expect("occurred_at")
        .parse()
        .expect("RFC 3339 occurred_at")
}

/// The core keyset proof: well over 500 rows in one source plus same-instant
/// rows in three sources come back exactly once each, in the feed's total
/// order, however the pages fall.
#[test]
fn cursor_paging_returns_every_row_once_in_order() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let (t0, tie_ref) = seed_interleaved(&db).await;
        let app = full_app(system);

        let base = format!(
            "from={}&to={}&page_size=37",
            iso(t0),
            iso(t0 + chrono::Duration::seconds(BULK_METADATA))
        );
        let (items, total) = page_all(&app, &admin_cookie, &base).await;

        let expected = BULK_METADATA as usize + 1 + 5 + 5;
        assert_eq!(total, expected as i64, "total is exact, not capped");
        assert_eq!(items.len(), expected, "every row, no more");

        let mut seen = std::collections::HashSet::new();
        for item in &items {
            let key = (
                item["kind"].as_str().unwrap().to_string(),
                item["reference"].as_str().unwrap().to_string(),
            );
            assert!(seen.insert(key.clone()), "row returned twice: {key:?}");
        }
        for pair in items.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            assert!(
                occurred_at(a) >= occurred_at(b),
                "newest first: {a} then {b}"
            );
            if occurred_at(a) == occurred_at(b) {
                assert!(
                    kind_rank(a["kind"].as_str().unwrap())
                        <= kind_rank(b["kind"].as_str().unwrap()),
                    "same instant orders by kind: {a} then {b}"
                );
            }
        }

        // At n = 100: two metadata rows (the later insert, larger id, first),
        // then bundle, then license.
        let at_100 = t0 + chrono::Duration::seconds(100);
        let same_instant: Vec<&serde_json::Value> =
            items.iter().filter(|i| occurred_at(i) == at_100).collect();
        let kinds: Vec<&str> = same_instant
            .iter()
            .map(|i| i["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["metadata", "metadata", "bundle", "license"]);
        assert_eq!(same_instant[0]["reference"], tie_ref.to_string());
    })
}

/// `kind` and the date window still narrow a cursor-paged feed.
#[test]
fn cursor_paging_keeps_kind_and_window_filters() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let (t0, _) = seed_interleaved(&db).await;
        let app = full_app(system);
        let end = iso(t0 + chrono::Duration::seconds(BULK_METADATA));

        let (licenses, total) = page_all(
            &app,
            &admin_cookie,
            &format!("from={}&to={end}&kind=license&page_size=2", iso(t0)),
        )
        .await;
        assert_eq!(total, 5);
        assert_eq!(licenses.len(), 5);
        assert!(licenses.iter().all(|i| i["kind"] == "license"));

        // [t0+100s, t0+200s] inclusive: 101 bulk metadata rows + the tie row,
        // and the license and bundle rows at 100 and 200.
        let (items, total) = page_all(
            &app,
            &admin_cookie,
            &format!(
                "from={}&to={}&page_size=25",
                iso(t0 + chrono::Duration::seconds(100)),
                iso(t0 + chrono::Duration::seconds(200))
            ),
        )
        .await;
        assert_eq!(total, 106);
        assert_eq!(items.len(), 106);
    })
}

/// A cursor that is not one this endpoint issued is a 422.
#[test]
fn malformed_cursor_is_validation_error() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let app = full_app(system);

        // "djE6MDow" is base64url for "v1:0:0" — well-formed base64, too few parts.
        for cursor in ["not-a-cursor", "djE6MDow", "%21%21%21"] {
            let resp = app
                .clone()
                .oneshot(get_req(
                    &format!("/api/v1/admin/changes?cursor={cursor}"),
                    &admin_cookie,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{cursor}");
        }
    })
}
