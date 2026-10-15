//! Integration test for P1.8 money-path #2 (the generic-CRUD half):
//! provision an entity + field through the admin API, then round-trip a
//! record through the generic `entity_crud.rs` handler — create → get →
//! update → soft-delete. Provisioning idempotency itself (re-running
//! `ensure_entity`/`ensure_attribute`) is covered at the DB layer in
//! `attome-metadata/tests/provision.rs`; this file proves the HTTP surface that
//! sits on top of it.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — skips (loudly) when
//! `DATABASE_URL` is unset, except under `CI`, per the P1.8 testing-baseline convention. Run
//! manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test entity_round_trip -- --test-threads=1
//! ```
//!
//! `cache.metadata_registry_enabled: false` below forces the pre-Plan-1.2
//! direct-Postgres `resolve_entity` path (documented rollback switch): the
//! arc-swap metadata registry only refreshes ~250ms after the `meta_version`
//! pub/sub signal, so provisioning an entity and immediately reading/writing
//! a record through it — exactly this test's shape — races the rebuild and
//! 404s with the registry on (same gap noted in tests/authz.rs).

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
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// Test-only, minimal parser for the one URL shape `attome_testkit::test_db_url`
/// ever produces (`postgres://user[:pass]@host:port/dbname[?...]`) — it always
/// starts from the configured `DATABASE_URL` and only swaps the path segment
/// for the per-binary clone's name, so a full URL-parsing dependency isn't
/// warranted for this one call site. Panics (test-only) on anything else.
fn parse_test_database_url(url: &str) -> (String, String, String, u16, String) {
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .unwrap_or_else(|| panic!("test DATABASE_URL must be a postgres:// URL: {url}"));
    let (userinfo, hostpart) = rest
        .split_once('@')
        .unwrap_or_else(|| panic!("test DATABASE_URL must carry userinfo: {url}"));
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_owned(), p.to_owned()),
        None => (userinfo.to_owned(), String::new()),
    };
    let hostpart = hostpart.split(['?', '#']).next().unwrap_or(hostpart);
    let (hostport, dbname) = hostpart
        .split_once('/')
        .unwrap_or_else(|| panic!("test DATABASE_URL must carry a database path: {url}"));
    let (host, port) = hostport
        .split_once(':')
        .unwrap_or_else(|| panic!("test DATABASE_URL must carry an explicit port: {url}"));
    (
        user,
        password,
        host.to_owned(),
        port.parse()
            .unwrap_or_else(|_| panic!("test DATABASE_URL port must be numeric: {url}")),
        dbname.to_owned(),
    )
}

fn test_config() -> AppConfig {
    // T2-1: a Lookup attribute is now always indexed at create time, which
    // (unlike this file's pre-existing tests) exercises
    // `provision::sync_attribute_index`'s `create_migrator_connection` path —
    // a genuinely separate direct connection from the `db` pool below, built
    // straight from `AppConfig.database.*` with no `DATABASE_URL`-env
    // override (unlike `create_pool`'s `APP_ENV=debug` override). It must
    // therefore carry the real per-binary throwaway database's credentials,
    // not a placeholder — `test_system` already rewrote `DATABASE_URL` to
    // that clone via `attome_testkit::migrated_db_url()` before calling this.
    let (db_user, db_password, db_host, db_port, db_name) =
        parse_test_database_url(&attome_testkit::migrated_db_url().expect(
            "DATABASE_URL must be set by attome_testkit::migrated_db_url() before test_config()",
        ));
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
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
            "rate_limit": {{ "anonymous_rpm": 1000000, "authenticated_rpm": 1000000, "per_endpoint_limits": {{}} }},
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
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
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
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    Some(system)
}

/// `oneshot()`-driven test requests carry no `Sec-Fetch-Site`/`Origin`
/// header at all (unlike a real browser), which `csrf_protect`
/// (attome-server/src/middleware/csrf.rs) fails closed on for any
/// cookie-authenticated unsafe-method request — by design, per that
/// module's own doc comment: a non-browser client presenting a cookie is
/// exactly the case it's meant to reject unless its origin is allow-listed.
/// Stamping a matching `Origin` here is the same fix a legitimate non-
/// browser caller would need in production, not a bypass of the check —
/// `test_config()`'s `cors.allowed_origins` carries the matching entry.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
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

/// Builds the full assembled app the same way `main.rs` does (Plan 1.3):
/// inner (authn/authz/RateLimit/Idempotency) → s2s_authn → outer
/// (RequestId..BodyLimit). `core_routes()` alone is bare, middleware-free
/// routes as of this plan — using it directly would silently skip auth.
fn build_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
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

async fn seed_admin(system: &TestSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("round-trip-test-admin-{user_id}"))
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

#[test]
fn create_get_update_soft_delete_round_trip() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let logicalname = format!("round_trip_{}", Uuid::now_v7().simple());

        // ── Provision: entity + one text field ────────────────────────────────────
        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Round Trip Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create field");
        assert_eq!(res.status(), StatusCode::CREATED);

        // ── Create ─────────────────────────────────────────────────────────────────
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"hello"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create record");
        let status = res.status();
        let created = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create record failed: {created:?}"
        );
        let record_id = created["id"].as_str().expect("record id").to_owned();
        assert_eq!(created["data"]["title"], "hello");

        // ── Get ────────────────────────────────────────────────────────────────────
        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get record");
        assert_eq!(res.status(), StatusCode::OK);
        let etag = res
            .headers()
            .get(axum::http::header::ETAG)
            .expect("GET must set an ETag header (caching-efficiency fix, 2026-07-30)")
            .to_str()
            .unwrap()
            .to_owned();
        let fetched = body_json(res).await;
        assert_eq!(fetched["data"]["title"], "hello");

        // ── Conditional GET (ETag/If-None-Match, caching-efficiency fix, 2026-07-30) ─
        // A matching If-None-Match short-circuits to 304 with no body and repeats
        // the same ETag; a stale one still returns the full 200 body.
        let conditional_hit_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("if-none-match", &etag)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(conditional_hit_req)
            .await
            .expect("conditional get (matching etag)");
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            res.headers()
                .get(axum::http::header::ETAG)
                .unwrap()
                .to_str()
                .unwrap(),
            etag.as_str()
        );
        let body_len = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .len();
        assert_eq!(body_len, 0, "304 must not carry a body");

        let conditional_miss_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("if-none-match", "\"999999\"")
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(conditional_miss_req)
            .await
            .expect("conditional get (stale etag)");
        assert_eq!(res.status(), StatusCode::OK);
        let refetched = body_json(res).await;
        assert_eq!(refetched["data"]["title"], "hello");

        // ── Update ─────────────────────────────────────────────────────────────────
        let row_version = created["row_version"].as_i64().expect("row_version");
        let update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{row_version}\""))
            .body(Body::from(r#"{"title":"updated"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(update_req)
            .await
            .expect("update record");
        assert_eq!(res.status(), StatusCode::OK);
        let updated = body_json(res).await;
        assert_eq!(updated["data"]["title"], "updated");

        // ── Soft-delete ────────────────────────────────────────────────────────────
        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_req)
            .await
            .expect("delete record");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // The soft-delete itself is correct: is_active is flipped false at the DB
        // layer (asserted directly here, not through the API).
        let is_active: bool = sqlx::query_scalar(&format!(
            r#"SELECT is_active FROM "{logicalname}" WHERE id = $1"#
        ))
        .bind(Uuid::parse_str(&record_id).unwrap())
        .fetch_one(&db)
        .await
        .expect("query is_active directly");
        assert!(!is_active, "soft-delete must set is_active = false");

        // Fixed by P-data-integrity (D-021): get_record now filters is_active,
        // so a GET after soft-delete 404s instead of returning the "deleted" row.
        let get_after_delete_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_after_delete_req)
            .await
            .expect("get after delete");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "get_record must filter is_active = true"
        );

        // update/delete against a soft-deleted record are also no-ops (D-021).
        let updated_row_version = updated["row_version"].as_i64().expect("row_version");
        let update_after_delete_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{updated_row_version}\""))
            .body(Body::from(r#"{"title":"should not apply"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(update_after_delete_req)
            .await
            .expect("update after delete");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "update_record must filter is_active = true"
        );

        let redelete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(redelete_req).await.expect("re-delete");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "re-deleting an already-deleted record must be a no-op, not a fresh audit entry"
        );
    })
}

/// P-data-integrity (D-021) item (a), revised by D-102 item 2: an
/// `is_sensitive` attribute's value is stripped from a generic-CRUD response
/// for a non-admin caller (on create, get, and update), but an admin caller
/// now legitimately sees it — `build_response`'s strip is conditioned on
/// `!ctx.is_admin`, reusing the same coarse admin bit every other unmigrated
/// admin surface relies on (D-012). Full per-field read grants (F013/F135)
/// are still unbuilt; this only proves the "everyone or nobody" defect D-102
/// closed, not a real field-level-security intersection.
#[test]
fn sensitive_attribute_never_appears_in_response() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let logicalname = format!("sensitive_test_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Sensitive Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let create_field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"secret_hash","name":"Secret Hash","field_type":"text","is_sensitive":true}"#,
        ))
        .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create sensitive field");
        assert_eq!(res.status(), StatusCode::CREATED);

        // Non-admin caller, granted only this entity's read/create/update
        // privileges — the actual masking boundary D-102 fixed.
        let user_id = Uuid::now_v7();
        let user_email = format!("sensitive-reader-{user_id}@test.local");
        sqlx::query(
            "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
        )
        .bind(user_id)
        .bind(&user_email)
        .bind(format!("sensitive-reader-{user_id}"))
        .execute(&db)
        .await
        .expect("insert throwaway non-admin user");
        let reader_cookie = session_cookie(user_id);

        for action in ["read", "create", "update"] {
            let grant_req = Request::builder()
                .method("POST")
                .uri("/api/v1/admin/security/grants")
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_email":"{user_email}","privilege_key":"{logicalname}.{action}"}}"#
                )))
                .unwrap();
            let res = app.clone().oneshot(grant_req).await.expect("grant");
            assert_eq!(
                res.status(),
                StatusCode::CREATED,
                "granting {action} failed"
            );
        }

        // Admin create: the sensitive column IS present (D-102).
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"secret_hash":"top-secret-value"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create record");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        assert_eq!(
            created["data"]["secret_hash"], "top-secret-value",
            "admin create response must include the sensitive column: {created:?}"
        );
        let record_id = created["id"].as_str().expect("record id").to_owned();

        // Non-admin get: the sensitive column must never appear.
        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &reader_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get record");
        assert_eq!(res.status(), StatusCode::OK);
        let fetched = body_json(res).await;
        assert!(
            fetched["data"].get("secret_hash").is_none(),
            "non-admin get response must not include the sensitive column: {fetched:?}"
        );

        // Non-admin update: field-write security rejects the blind write, and
        // the error response must not echo the submitted sensitive value.
        let row_version = created["row_version"].as_i64().expect("row_version");
        let update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &reader_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{row_version}\""))
            .body(Body::from(r#"{"secret_hash":"rotated-secret-value"}"#))
            .unwrap();
        let res = app.oneshot(update_req).await.expect("update record");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let rejected = body_json(res).await;
        assert!(
            !rejected.to_string().contains("rotated-secret-value"),
            "rejected update response must not include the sensitive value: {rejected:?}"
        );
    })
}

/// P-field-write-security (D-141): complements
/// `sensitive_attribute_never_appears_in_response` above (which proves an
/// `is_sensitive` field is masked on the way OUT) by proving the write side
/// is gated too — before this decision, entity-level "update" alone let any
/// caller blind-write a sensitive field's value regardless of field-security
/// read access, since no write path ever consulted
/// `field_security_profile_field.can_update` (the column didn't exist).
///
/// Written in a code-only session with no live Postgres/Redis/Rust
/// toolchain available — same "written, not run" caveat
/// `record_level_security.rs`'s header already carries for D-137/D-138/
/// D-139/D-140; run this against a throwaway database before relying on
/// D-141 in production.
#[test]
fn update_record_rejects_sensitive_field_write_without_can_update_grant() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);

        let logicalname = format!("fws_test_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Field Write Security Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let create_field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"salary","name":"Salary","field_type":"text","is_sensitive":true}"#,
        ))
        .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create sensitive field");
        assert_eq!(res.status(), StatusCode::CREATED);

        let create_ordinary_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"note","name":"Note","field_type":"text"}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_ordinary_field_req)
            .await
            .expect("create ordinary field");
        assert_eq!(res.status(), StatusCode::CREATED);

        // Non-admin caller: ordinary entity-level create/read/update, but no
        // field-security profile at all yet.
        let user_id = Uuid::now_v7();
        let user_email = format!("fws-writer-{user_id}@test.local");
        sqlx::query(
            "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
        )
        .bind(user_id)
        .bind(&user_email)
        .bind(format!("fws-writer-{user_id}"))
        .execute(&db)
        .await
        .expect("insert throwaway non-admin user");
        let writer_cookie = session_cookie(user_id);

        for action in ["read", "create", "update"] {
            let grant_req = Request::builder()
                .method("POST")
                .uri("/api/v1/admin/security/grants")
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_email":"{user_email}","privilege_key":"{logicalname}.{action}"}}"#
                )))
                .unwrap();
            let res = app.clone().oneshot(grant_req).await.expect("grant");
            assert_eq!(
                res.status(),
                StatusCode::CREATED,
                "granting {action} failed"
            );
        }

        // Create without touching the sensitive field — must succeed; the check
        // only fires when the payload actually sets an is_sensitive field.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &writer_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"note":"initial"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create record without sensitive field");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let record_id = created["id"].as_str().expect("record id").to_owned();
        let row_version = created["row_version"].as_i64().expect("row_version");

        // Writing the sensitive field with no field-security profile at all
        // must be rejected outright — not silently dropped from the write.
        let update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &writer_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{row_version}\""))
            .body(Body::from(r#"{"salary":"250000"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(update_req)
            .await
            .expect("rejected sensitive update");
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "writing an is_sensitive field with no can_update grant must be rejected outright"
        );

        // An unrelated non-sensitive field on the same record must still be
        // writable — the check is per-field, not a whole-record lockout, and
        // row_version must be unaffected by the rejected attempt above.
        let ordinary_update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &writer_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{row_version}\""))
            .body(Body::from(r#"{"note":"hello"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(ordinary_update_req)
            .await
            .expect("ordinary update");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "an unrelated non-sensitive field must still be writable"
        );
        let updated = body_json(res).await;
        let row_version = updated["row_version"].as_i64().expect("row_version");

        // Grant can_update on salary via a role, assign the role to the writer,
        // then retry — must now succeed.
        let role_id = Uuid::now_v7();
        sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
            .bind(role_id)
            .bind(format!("fws-test-role-{role_id}"))
            .execute(&db)
            .await
            .expect("insert test role");
        sqlx::query(
            "INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(&db)
        .await
        .expect("assign role to writer");

        let profile_id: Uuid = sqlx::query_scalar(
            "INSERT INTO field_security_profile (id, name, owner_layer) VALUES ($1, $2, 'project') RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(format!("fws-test-profile-{role_id}"))
        .fetch_one(&db)
        .await
        .expect("insert field-security profile");
        sqlx::query(
            "INSERT INTO field_security_profile_field \
         (id, profile_ref, entity_logicalname, field_logicalname, can_read, can_update, owner_layer) \
         VALUES ($1, $2, $3, $4, true, true, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(profile_id)
        .bind(&logicalname)
        .bind("salary")
        .execute(&db)
        .await
        .expect("insert field-security profile field");
        sqlx::query(
        "INSERT INTO role_mm_field_security_profile (id, role_ref, profile_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(profile_id)
    .execute(&db)
    .await
    .expect("assign field-security profile to role");
        // Direct-SQL grant outside the admin API — invalidate explicitly, since
        // only the admin endpoints' own handlers call `invalidate_sync_all`.
        security.invalidate(user_id).await;

        let now_authorized_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &writer_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{row_version}\""))
            .body(Body::from(r#"{"salary":"250000"}"#))
            .unwrap();
        let res = app
            .oneshot(now_authorized_req)
            .await
            .expect("authorized sensitive update");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "once granted can_update, the same write must succeed"
        );
    })
}

/// Sends one JSON request and returns `(status, body)`.
async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    if_match: Option<i64>,
    body: Option<String>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json");
    if let Some(version) = if_match {
        req = req.header("if-match", format!("\"{version}\""));
    }
    let req = req
        .body(body.map(Body::from).unwrap_or_else(Body::empty))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    (status, body_json(res).await)
}

/// D-507: field-level read and write security are independent dimensions,
/// and a field can be write-gated without being read-gated at all. The
/// entity carries `salary` (`is_sensitive`: reads gated by `can_read`, writes
/// by `can_update`) and `approved_amount` (`is_write_restricted`: only writes
/// gated). One non-admin caller walks the matrix:
///
/// | profile rows for both fields      | salary read | salary write | approved_amount read | approved_amount write |
/// |-----------------------------------|-------------|--------------|----------------------|-----------------------|
/// | none                              | denied      | denied       | allowed              | denied                |
/// | can_read=false, can_update=true   | denied      | allowed      | allowed              | allowed               |
/// | can_read=true,  can_update=false  | allowed     | denied       | allowed              | denied                |
#[test]
fn field_read_and_write_security_are_independent_dimensions() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);

        let logicalname = format!("fsrw_test_{}", Uuid::now_v7().simple());
        let (status, entity) = call(
            &app,
            "POST",
            "/api/v1/admin/entities",
            &admin_cookie,
            None,
            Some(format!(
                r#"{{"logicalname":"{logicalname}","name":"Field Read Write Test"}}"#
            )),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{entity:?}");
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();
        let fields_uri = format!("/api/v1/admin/entities/{entity_id}/fields");

        for body in [
            r#"{"logicalname":"salary","name":"Salary","field_type":"text","is_sensitive":true}"#,
            r#"{"logicalname":"note","name":"Note","field_type":"text"}"#,
        ] {
            let (status, field) = call(
                &app,
                "POST",
                &fields_uri,
                &admin_cookie,
                None,
                Some(body.to_owned()),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{field:?}");
        }
        // Created unrestricted, then flagged through the admin PATCH, so both the
        // create and the update wire paths are exercised.
        let (status, field) = call(
            &app,
            "POST",
            &fields_uri,
            &admin_cookie,
            None,
            Some(
                r#"{"logicalname":"approved_amount","name":"Approved Amount","field_type":"text"}"#
                    .to_owned(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{field:?}");
        assert_eq!(field["is_write_restricted"], false);
        let field_id = field["id"].as_str().expect("field id").to_owned();
        let (status, field) = call(
            &app,
            "PATCH",
            &format!("{fields_uri}/{field_id}"),
            &admin_cookie,
            None,
            Some(r#"{"is_write_restricted":true}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{field:?}");
        assert_eq!(field["is_write_restricted"], true);
        assert_eq!(
            field["is_sensitive"], false,
            "a write restriction must not imply read sensitivity"
        );

        let user_id = Uuid::now_v7();
        let user_email = format!("fsrw-writer-{user_id}@test.local");
        sqlx::query(
            "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
        )
        .bind(user_id)
        .bind(&user_email)
        .bind(format!("fsrw-writer-{user_id}"))
        .execute(&db)
        .await
        .expect("insert throwaway non-admin user");
        let writer = session_cookie(user_id);
        for action in ["read", "create", "update"] {
            let (status, _) = call(
                &app,
                "POST",
                "/api/v1/admin/security/grants",
                &admin_cookie,
                None,
                Some(format!(
                    r#"{{"user_email":"{user_email}","privilege_key":"{logicalname}.{action}"}}"#
                )),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "granting {action} failed");
        }

        let collection_uri = format!("/api/v1/{logicalname}");
        let (status, created) = call(
            &app,
            "POST",
            &collection_uri,
            &admin_cookie,
            None,
            Some(r#"{"salary":"100","approved_amount":"5","note":"initial"}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created:?}");
        let record_uri = format!(
            "{collection_uri}/{}",
            created["id"].as_str().expect("record id")
        );
        let mut row_version = created["row_version"].as_i64().expect("row_version");

        // ── No field-security profile at all ────────────────────────────────────
        let (status, fetched) = call(&app, "GET", &record_uri, &writer, None, None).await;
        assert_eq!(status, StatusCode::OK, "{fetched:?}");
        assert_eq!(
            fetched["data"]["approved_amount"], "5",
            "a write-restricted field stays readable with no grant: {fetched:?}"
        );
        assert!(
            fetched["data"].get("salary").is_none(),
            "a sensitive field stays hidden with no grant: {fetched:?}"
        );

        let (status, body) = call(
            &app,
            "PATCH",
            &record_uri,
            &writer,
            Some(row_version),
            Some(r#"{"approved_amount":"6"}"#.to_owned()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "updating a write-restricted field needs can_update: {body:?}"
        );
        let (status, body) = call(
            &app,
            "POST",
            &collection_uri,
            &writer,
            None,
            Some(r#"{"note":"new","approved_amount":"7"}"#.to_owned()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "creating with a write-restricted field needs can_update: {body:?}"
        );
        let (status, body) = call(
            &app,
            "PATCH",
            &record_uri,
            &writer,
            Some(row_version),
            Some(r#"{"salary":"200"}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body:?}");
        let (status, updated) = call(
            &app,
            "PATCH",
            &record_uri,
            &writer,
            Some(row_version),
            Some(r#"{"note":"unrelated"}"#.to_owned()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an ungated field on the same record stays writable: {updated:?}"
        );
        row_version = updated["row_version"].as_i64().expect("row_version");

        // ── Write granted, read denied ──────────────────────────────────────────
        let role_id = Uuid::now_v7();
        sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
            .bind(role_id)
            .bind(format!("fsrw-test-role-{role_id}"))
            .execute(&db)
            .await
            .expect("insert test role");
        sqlx::query(
            "INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(&db)
        .await
        .expect("assign role to writer");
        let profile_id: Uuid = sqlx::query_scalar(
            "INSERT INTO field_security_profile (id, name, owner_layer) VALUES ($1, $2, 'project') RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(format!("fsrw-test-profile-{role_id}"))
        .fetch_one(&db)
        .await
        .expect("insert field-security profile");
        for field in ["salary", "approved_amount"] {
            sqlx::query(
                "INSERT INTO field_security_profile_field \
             (id, profile_ref, entity_logicalname, field_logicalname, can_read, can_update, owner_layer) \
             VALUES ($1, $2, $3, $4, false, true, 'project')",
            )
            .bind(Uuid::now_v7())
            .bind(profile_id)
            .bind(&logicalname)
            .bind(field)
            .execute(&db)
            .await
            .expect("insert field-security profile field");
        }
        sqlx::query(
        "INSERT INTO role_mm_field_security_profile (id, role_ref, profile_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(profile_id)
    .execute(&db)
    .await
    .expect("assign field-security profile to role");
        security.invalidate(user_id).await;

        let (status, updated) = call(
            &app,
            "PATCH",
            &record_uri,
            &writer,
            Some(row_version),
            Some(r#"{"salary":"200"}"#.to_owned()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "can_update alone permits the write: {updated:?}"
        );
        assert!(
            updated["data"].get("salary").is_none(),
            "the write response must not echo a field the caller cannot read: {updated:?}"
        );
        row_version = updated["row_version"].as_i64().expect("row_version");
        let (status, updated) = call(
            &app,
            "PATCH",
            &record_uri,
            &writer,
            Some(row_version),
            Some(r#"{"approved_amount":"6"}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated:?}");
        row_version = updated["row_version"].as_i64().expect("row_version");

        let (_, fetched) = call(&app, "GET", &record_uri, &writer, None, None).await;
        assert_eq!(fetched["data"]["approved_amount"], "6");
        assert!(
            fetched["data"].get("salary").is_none(),
            "can_read=false still hides the sensitive field: {fetched:?}"
        );
        let (_, as_admin) = call(&app, "GET", &record_uri, &admin_cookie, None, None).await;
        assert_eq!(
            as_admin["data"]["salary"], "200",
            "the blind write landed: {as_admin:?}"
        );

        // ── Read granted, write denied ──────────────────────────────────────────
        sqlx::query(
            "UPDATE field_security_profile_field \
         SET can_read = true, can_update = false WHERE profile_ref = $1",
        )
        .bind(profile_id)
        .execute(&db)
        .await
        .expect("flip profile to read-only");
        security.invalidate(user_id).await;

        let (_, fetched) = call(&app, "GET", &record_uri, &writer, None, None).await;
        assert_eq!(
            fetched["data"]["salary"], "200",
            "can_read alone permits the read: {fetched:?}"
        );
        assert_eq!(fetched["data"]["approved_amount"], "6");
        for body in [r#"{"salary":"300"}"#, r#"{"approved_amount":"8"}"#] {
            let (status, rejected) = call(
                &app,
                "PATCH",
                &record_uri,
                &writer,
                Some(row_version),
                Some(body.to_owned()),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "can_read without can_update must refuse {body}: {rejected:?}"
            );
        }
        let (_, as_admin) = call(&app, "GET", &record_uri, &admin_cookie, None, None).await;
        assert_eq!(as_admin["data"]["salary"], "200");
        assert_eq!(as_admin["data"]["approved_amount"], "6");
    })
}

/// P-data-integrity (D-021) item (c): logicalname is immutable after
/// creation — attempting to rename it is rejected, not silently applied.
#[test]
fn entity_rename_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("rename_test_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Rename Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let rename_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/admin/entities/{entity_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}_renamed"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(rename_req)
            .await
            .expect("attempt rename");
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "renaming logicalname must be rejected"
        );

        // Display-name-only update on the same entity still works.
        let rename_display_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/admin/entities/{entity_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Renamed Display Name"}"#))
            .unwrap();
        let res = app
            .oneshot(rename_display_req)
            .await
            .expect("update display name");
        assert_eq!(res.status(), StatusCode::OK);
        let updated = body_json(res).await;
        assert_eq!(
            updated["logicalname"], logicalname,
            "logicalname must be unchanged"
        );
        assert_eq!(updated["name"], "Renamed Display Name");
    })
}

/// Provisions a throwaway entity with one text + one number field and returns
/// (logicalname, admin_cookie, app) — shared setup for the F027/A-1 tests.
async fn provision_test_entity(system: TestSystem, prefix: &str) -> (String, String, axum::Router) {
    let admin_cookie = seed_admin(&system).await;
    let app = full_app(system);
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());

    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"F027 Test"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_entity_req)
        .await
        .expect("create entity");
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    for (ln, ft) in [("title", "text"), ("amount", "number")] {
        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{ln}","name":"{ln}","field_type":"{ft}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create field");
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    (logicalname, admin_cookie, app)
}

/// F027 (P2.2, D-037/D-079): `If-Match: "<row_version>"` is mandatory on every
/// generic UPDATE — a stale version is a 409, and a missing header is a 422.
/// There is no unguarded last-write-wins path (D-079: "version-unaware
/// clients must be upgraded").
#[test]
fn stale_row_version_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "rowver").await;

        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"v0"}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let record_id = created["id"].as_str().expect("record id").to_owned();
        let v0 = created["row_version"]
            .as_i64()
            .expect("row_version present");
        assert_eq!(v0, 0, "fresh records start at row_version 0");

        // Guarded update with the correct version succeeds and increments.
        let update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(r#"{"title":"v1"}"#))
            .unwrap();
        let res = app.clone().oneshot(update_req).await.expect("update");
        assert_eq!(res.status(), StatusCode::OK);
        let updated = body_json(res).await;
        assert_eq!(updated["row_version"].as_i64(), Some(v0 + 1));

        // Replaying the OLD version is a 409 version_conflict.
        let stale_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(r#"{"title":"stale"}"#))
            .unwrap();
        let res = app.clone().oneshot(stale_req).await.expect("stale update");
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let err = body_json(res).await;
        assert_eq!(err["error"], "version_conflict");

        // No If-Match → 422, never a silent last-write-wins (D-079).
        let unguarded_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"v2"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(unguarded_req)
            .await
            .expect("unguarded update");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");

        // The record is untouched by the rejected unguarded attempt.
        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_req).await.expect("get record");
        assert_eq!(res.status(), StatusCode::OK);
        let fetched = body_json(res).await;
        assert_eq!(fetched["row_version"].as_i64(), Some(v0 + 1));
        assert_eq!(fetched["data"]["title"], "v1");
    })
}

/// DATA-7/CONC-1 (PLATFORM-REVIEW-2026-08-24): `If-Match` is **optional** on
/// soft delete and restore — supplied and stale is a 409, malformed is a 422,
/// and omitted keeps the pre-existing unguarded behaviour.
///
/// The asymmetry with `stale_row_version_is_rejected` above is deliberate and
/// is the point of this test: PATCH *requires* the header (D-079), these do
/// not. D-079 covers PATCH and upsert, and these paths had no version guard at
/// all, so making the header optional is purely additive — no existing client
/// breaks. Tightening them to mandatory later is a breaking change and needs
/// its own decision; asserting the omitted-header case here is what stops that
/// happening by accident.
#[test]
fn if_match_is_optional_on_delete_and_restore() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "ifmatchdel").await;

        let create = |title: &str| {
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/{logicalname}"))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"title":"{title}"}}"#)))
                .unwrap()
        };

        // ---- stale If-Match on DELETE is a 409, and the record survives ----
        let res = app.clone().oneshot(create("a")).await.expect("create a");
        assert_eq!(res.status(), StatusCode::CREATED);
        let rec_a = body_json(res).await;
        let id_a = rec_a["id"].as_str().expect("id").to_owned();
        let v0 = rec_a["row_version"].as_i64().expect("row_version");

        let bump = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{id_a}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(r#"{"title":"a2"}"#))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(bump).await.expect("bump").status(),
            StatusCode::OK
        );

        let stale_delete = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{id_a}"))
            .header("cookie", &admin_cookie)
            .header("if-match", format!("\"{v0}\""))
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(stale_delete)
            .await
            .expect("stale delete");
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "a stale If-Match must not delete the record"
        );
        assert_eq!(body_json(res).await["error"], "version_conflict");

        // Still live: the rejected delete changed nothing.
        let get = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{id_a}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(get).await.expect("get a").status(),
            StatusCode::OK,
            "the record must survive a rejected delete"
        );

        // ---- a malformed If-Match is a 422, never a silent unguarded delete ----
        let junk_delete = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{id_a}"))
            .header("cookie", &admin_cookie)
            .header("if-match", "\"not-a-number\"")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(junk_delete).await.expect("junk delete");
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "garbage must not degrade into the unguarded path"
        );
        assert_eq!(body_json(res).await["error"], "validation_error");

        // ---- the CURRENT version deletes, and restore rejects a stale one ----
        let correct_delete = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{id_a}"))
            .header("cookie", &admin_cookie)
            .header("if-match", format!("\"{}\"", v0 + 1))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(correct_delete)
                .await
                .expect("delete")
                .status(),
            StatusCode::NO_CONTENT
        );

        let stale_restore = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{id_a}/restore"))
            .header("cookie", &admin_cookie)
            .header("if-match", format!("\"{v0}\""))
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(stale_restore)
            .await
            .expect("stale restore");
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "a stale If-Match must not restore the record"
        );
        assert_eq!(body_json(res).await["error"], "version_conflict");

        // Restore with no header at all still works — the additive contract.
        let unguarded_restore = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{id_a}/restore"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(unguarded_restore)
            .await
            .expect("unguarded restore");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "omitting If-Match must keep working — this contract is additive"
        );

        // ---- omitting If-Match on DELETE still works, on a second record ----
        let res = app.clone().oneshot(create("b")).await.expect("create b");
        let id_b = body_json(res).await["id"].as_str().expect("id").to_owned();
        let unguarded_delete = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{id_b}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(unguarded_delete)
                .await
                .expect("unguarded delete")
                .status(),
            StatusCode::NO_CONTENT,
            "omitting If-Match must keep working — this contract is additive"
        );
    })
}

/// A-1 (2026-07-13 audit): `attome_field::validate` now runs before any entity
/// write — a type-shape mismatch is a 422 validation_error naming the field,
/// on both create and update, and nothing is persisted.
#[test]
fn semantic_validation_rejects_wrong_types() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "validate").await;

        // Create with a string in a number field → 422, field named in message.
        let bad_create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"ok","amount":"not-a-number"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(bad_create_req)
            .await
            .expect("bad create");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"].as_str().unwrap_or("").contains("amount"),
            "validation error must name the offending field: {err:?}"
        );
        // attome-server hardening I4: the idempotency gate releases a key on a 4xx
        // on the strength of this contract, so prove the rejected create wrote
        // nothing (the entity was provisioned fresh by this test).
        let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM \"{logicalname}\""))
            .fetch_one(&db)
            .await
            .expect("count rows");
        assert_eq!(rows, 0, "a rejected create must not leave a row behind");

        // Valid create, then an update pushing a number into the text field → 422.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"ok","amount":42}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("good create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let record_id = created["id"].as_str().expect("record id").to_owned();

        let bad_update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":123}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(bad_update_req)
            .await
            .expect("bad update");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // The failed update must not have changed the record.
        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_req).await.expect("get");
        assert_eq!(res.status(), StatusCode::OK);
        let fetched = body_json(res).await;
        assert_eq!(fetched["data"]["title"], "ok");
    })
}

// ── Lookup field integrity (P-entity-contract-hardening item (a),
// P-data-lifecycle item (c)) ──────────────────────────────────────────────

/// Creates an entity via the admin API and returns `(logicalname, id)`.
///
/// Uses a 12-hex-char suffix (not the full 32-char `Uuid::simple()`) so the
/// longest prefixes in this file (`bulk_policy_restrictor`, `cascade_restrictor`,
/// …) still fit under `MAX_IDENTIFIER_LEN` (48 bytes, D-101) — a full UUID
/// suffix pushed several call sites over the cap and made entity creation
/// itself 422 before the test's actual assertions ever ran.
async fn create_entity(app: &axum::Router, admin_cookie: &str, prefix: &str) -> (String, String) {
    let suffix = &Uuid::now_v7().simple().to_string()[..12];
    let logicalname = format!("{prefix}_{suffix}");
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"{prefix}"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create entity");
    assert_eq!(res.status(), StatusCode::CREATED);
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();
    (logicalname, entity_id)
}

/// Creates a field via the admin API with an arbitrary extra JSON body
/// (already containing logicalname/name/field_type and anything else).
async fn create_field(app: &axum::Router, admin_cookie: &str, entity_id: &str, body: &str) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create field");
    let status = res.status();
    let created = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create field failed: {created:?}"
    );
}

/// The registry-lag workaround `entity_round_trip.rs`'s own header comment
/// documents for the entity's own resolution (`metadata_registry_enabled:
/// false`) does NOT cover lookup metadata: `resolve_lookup_meta`/
/// `validate_lookup_targets`/`dependents_of` all read the arc-swap
/// `EntityMetaRegistry` directly (same as the D-057 code they replace),
/// regardless of that config flag. Force a synchronous rebuild instead of
/// waiting ~250ms for the real pub/sub doorbell.
async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build_registry");
    state.entities.swap(registry);
}

/// The single most important regression test in P-entity-contract-hardening
/// item (a): a lookup field's target being soft-deleted must never cause the
/// stored UUID to be erased by an unrelated later edit (D-057's read-time
/// `null_stale_lookups` made exactly this mistake — GET returned `null`,
/// and a client PUTting that back permanently nulled the real value). Also
/// covers the write-time liveness gate D-057 left open: a create/update
/// pointing at a missing or soft-deleted target is rejected outright.
#[test]
fn lookup_write_time_validation_and_round_trip_preserves_dangling_reference() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "lookup_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;

        let (referrer_logicalname, referrer_entity_id) =
            create_entity(&app, &admin_cookie, "lookup_referrer").await;
        create_field(
        &app,
        &admin_cookie,
        &referrer_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        ),
    )
    .await;
        create_field(
            &app,
            &admin_cookie,
            &referrer_entity_id,
            r#"{"logicalname":"note","name":"Note","field_type":"text"}"#,
        )
        .await;

        sync_registry(&state).await;

        // Write-time validation: a lookup value that doesn't exist at all is
        // rejected, naming the field.
        let bad_id = Uuid::now_v7();
        let bad_create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{referrer_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{bad_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(bad_create_req)
            .await
            .expect("create with dead lookup target");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"].as_str().unwrap_or("").contains("target_ref"),
            "validation error must name the offending field: {err:?}"
        );

        // A live target: create succeeds, `data` carries the raw UUID, and the
        // sibling `lookups` tombstone map reports it live.
        let create_target_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t1"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_target_req)
            .await
            .expect("create target record");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target = body_json(res).await;
        let target_id = target["id"].as_str().expect("target id").to_owned();

        let create_referrer_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{referrer_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"target_ref":"{target_id}","note":"n1"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_referrer_req)
            .await
            .expect("create referrer record");
        assert_eq!(res.status(), StatusCode::CREATED);
        let referrer = body_json(res).await;
        let referrer_id = referrer["id"].as_str().expect("referrer id").to_owned();
        assert_eq!(referrer["data"]["target_ref"], target_id);
        assert_eq!(referrer["lookups"]["target_ref"]["exists"], true);
        assert_eq!(referrer["lookups"]["target_ref"]["is_active"], true);

        // Soft-delete the target (default on_target_delete = "orphan" — no
        // dependent blocks or cascades from this).
        let delete_target_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_target_req)
            .await
            .expect("delete target");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Write-time validation also rejects a target that exists but is now
        // soft-deleted — not just a target that never existed.
        let dead_target_create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{referrer_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{target_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(dead_target_create_req)
            .await
            .expect("create with soft-deleted lookup target");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // The read contract: `data` still carries the raw UUID (never nulled),
        // and `lookups` now reports the target as existing-but-inactive.
        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_logicalname}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer after target soft-delete");
        assert_eq!(res.status(), StatusCode::OK);
        let fetched = body_json(res).await;
        assert_eq!(
            fetched["data"]["target_ref"], target_id,
            "a soft-deleted lookup target must never be read back as null"
        );
        assert_eq!(fetched["lookups"]["target_ref"]["exists"], true);
        assert_eq!(fetched["lookups"]["target_ref"]["is_active"], false);

        // The regression D-057 introduced: an unrelated field edit that does
        // NOT touch `target_ref` must leave the dangling reference completely
        // untouched (validate_lookup_targets only checks fields present in the
        // body; the read path never mutates the stored value in the first
        // place).
        let referrer_row_version = referrer["row_version"].as_i64().expect("row_version");
        let unrelated_update_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{referrer_logicalname}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{referrer_row_version}\""))
            .body(Body::from(r#"{"note":"n2"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(unrelated_update_req)
            .await
            .expect("unrelated update");
        assert_eq!(res.status(), StatusCode::OK);
        let updated = body_json(res).await;
        assert_eq!(updated["data"]["note"], "n2");
        assert_eq!(
            updated["data"]["target_ref"], target_id,
            "an edit that never touched target_ref must not erase it (the exact D-057 data-loss bug)"
        );

        let final_get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_logicalname}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(final_get_req).await.expect("final get");
        let final_fetched = body_json(res).await;
        assert_eq!(final_fetched["data"]["target_ref"], target_id);
    })
}

/// T2-1 (finding 3.1, TECHNICAL-DUE-DILIGENCE-2026-08-24 §3/§8): a Lookup
/// attribute must get its supporting index even when the admin never opts
/// into `is_sortable`/`is_filterable` (both default `false` via
/// `#[serde(default)]` on `CreateAttributeBody`). Without it,
/// `entity_mutation.rs`'s cascade-delete/restrict check (`SELECT EXISTS …
/// WHERE {dep_field} = $1 AND is_active`) sequential-scans the dependent
/// table under row locks inside the write transaction, bounded by migration
/// `0018`'s 500ms role-level `statement_timeout`.
#[test]
fn lookup_field_gets_index_by_default_without_sortable_or_filterable() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let (_target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "idx_lookup_target").await;
        let (referrer_logicalname, referrer_entity_id) =
            create_entity(&app, &admin_cookie, "idx_lookup_referrer").await;

        // Deliberately no is_sortable/is_filterable in the body.
        let create_field_req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/entities/{referrer_entity_id}/fields"
        ))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create lookup field");
        let status = res.status();
        let created = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create lookup field failed: {created:?}"
        );
        assert_eq!(
            created["is_sortable"], false,
            "the fix must not silently flip is_sortable on to get an index: {created:?}"
        );
        assert_eq!(
            created["is_filterable"], false,
            "the fix must not silently flip is_filterable on to get an index: {created:?}"
        );
        let field_id = created["id"].as_str().expect("field id").to_owned();

        // The physical index must exist despite both flags being false.
        let index_name =
            attome_metadata::provision::attribute_index_name(&referrer_logicalname, "target_ref")
                .expect("index name");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_indexes WHERE tablename = $1 AND indexname = $2",
        )
        .bind(&referrer_logicalname)
        .bind(&index_name)
        .fetch_one(&db)
        .await
        .expect("query pg_indexes");
        assert_eq!(
            count, 1,
            "a Lookup attribute must get its supporting index even with is_sortable/is_filterable both false (T2-1)"
        );

        // Not just present — actually usable, not left invalid mid-build.
        let valid: bool = sqlx::query_scalar(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = $1",
    )
    .bind(&index_name)
    .fetch_one(&db)
    .await
    .expect("query pg_index.indisvalid");
        assert!(
            valid,
            "the lookup's supporting index must be valid, not left invalid mid-build"
        );

        // The admin-facing index-status endpoint must agree it's ready, not
        // report "not_requested" just because both flags are false.
        let status_req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/admin/entities/{referrer_entity_id}/fields/{field_id}/index-status"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(status_req).await.expect("index-status");
        assert_eq!(res.status(), StatusCode::OK);
        let index_status = body_json(res).await;
        assert_eq!(
            index_status["status"], "ready",
            "index-status must report the Lookup's implicit index as ready: {index_status:?}"
        );
    })
}

/// P-data-lifecycle item (c): `restrict` blocks a delete with zero side
/// effects while a live reference exists, and `cascade-deactivate` fires
/// exactly when the delete actually goes through.
#[test]
fn on_target_delete_restrict_blocks_then_cascade_deactivate_cascades() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "cascade_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;

        let (restrictor_logicalname, restrictor_entity_id) =
            create_entity(&app, &admin_cookie, "cascade_restrictor").await;
        create_field(
        &app,
        &admin_cookie,
        &restrictor_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"restrict"}}"#
        ),
    )
    .await;

        let (cascader_logicalname, cascader_entity_id) =
            create_entity(&app, &admin_cookie, "cascade_cascader").await;
        create_field(
        &app,
        &admin_cookie,
        &cascader_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"cascade-deactivate"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        let create_target_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t1"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_target_req)
            .await
            .expect("create target");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target_id = body_json(res).await["id"]
            .as_str()
            .expect("target id")
            .to_owned();

        let create_cascader_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{cascader_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{target_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_cascader_req)
            .await
            .expect("create cascader");
        assert_eq!(res.status(), StatusCode::CREATED);
        let cascader_id = body_json(res).await["id"]
            .as_str()
            .expect("cascader id")
            .to_owned();

        let create_restrictor_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{restrictor_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{target_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_restrictor_req)
            .await
            .expect("create restrictor");
        assert_eq!(res.status(), StatusCode::CREATED);
        let restrictor_id = body_json(res).await["id"]
            .as_str()
            .expect("restrictor id")
            .to_owned();

        // Blocked: the restrictor's live reference must prevent the delete
        // outright, before any cascade runs.
        let blocked_delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(blocked_delete_req)
            .await
            .expect("blocked delete");
        assert_eq!(res.status(), StatusCode::CONFLICT);

        // Zero side effects: the cascader record must be untouched while the
        // delete was blocked.
        let get_cascader_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{cascader_logicalname}/{cascader_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_cascader_req)
            .await
            .expect("get cascader after blocked delete");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "a blocked delete must not have cascaded"
        );

        // Remove the blocker.
        let delete_restrictor_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{restrictor_logicalname}/{restrictor_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_restrictor_req)
            .await
            .expect("delete restrictor");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Now the delete succeeds, and cascades to the cascader record.
        let final_delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(final_delete_req)
            .await
            .expect("final delete");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let get_cascader_after_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{cascader_logicalname}/{cascader_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_cascader_after_req)
            .await
            .expect("get cascader after cascading delete");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "cascade-deactivate must have soft-deleted the dependent record"
        );
    })
}

/// TECHNICAL-DUE-DILIGENCE-2026-08-24 B16 (T2-3) regression: a dependent
/// record deleted BEFORE its parent must stay deleted through a
/// delete-parent-then-restore-parent cycle. The old
/// `reactivate_dependents_on_restore` matched every currently-inactive
/// dependent (`WHERE {fk} = $1 AND is_active = FALSE`) with no record of
/// which rows the delete itself had cascaded, so it wrongly resurrected a
/// dependent that was already dead before the parent's own delete ever ran.
#[test]
fn restore_does_not_resurrect_independently_deleted_dependent() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "b16_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;

        let (cascader_logicalname, cascader_entity_id) =
            create_entity(&app, &admin_cookie, "b16_cascader").await;
        create_field(
        &app,
        &admin_cookie,
        &cascader_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"cascade-deactivate"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        let create_target_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t1"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_target_req)
            .await
            .expect("create target");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target_id = body_json(res).await["id"]
            .as_str()
            .expect("target id")
            .to_owned();

        // Two dependents on the same parent: `independent_dep_id` is deleted
        // BEFORE the parent (never touched by the parent's cascade, since the
        // cascade UPDATE only ever matches `is_active = TRUE`); `cascaded_dep_id`
        // stays live so the parent's delete actually cascades it.
        let create_dep_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{cascader_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{target_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_dep_req)
            .await
            .expect("create independent dependent");
        assert_eq!(res.status(), StatusCode::CREATED);
        let independent_dep_id = body_json(res).await["id"]
            .as_str()
            .expect("independent dependent id")
            .to_owned();

        let create_dep_req2 = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{cascader_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{target_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_dep_req2)
            .await
            .expect("create cascaded dependent");
        assert_eq!(res.status(), StatusCode::CREATED);
        let cascaded_dep_id = body_json(res).await["id"]
            .as_str()
            .expect("cascaded dependent id")
            .to_owned();

        // Independently delete one dependent BEFORE the parent is ever deleted.
        let del_dep_req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/{cascader_logicalname}/{independent_dep_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(del_dep_req)
            .await
            .expect("delete independent dependent");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Delete the parent — cascades only the still-live dependent.
        let del_target_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(del_target_req)
            .await
            .expect("delete target");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Restore the parent.
        let restore_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}/restore"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(restore_req)
            .await
            .expect("restore target");
        assert_eq!(res.status(), StatusCode::OK);

        // The dependent the delete actually cascaded comes back.
        let get_cascaded_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{cascader_logicalname}/{cascaded_dep_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_cascaded_req)
            .await
            .expect("get cascaded dependent after restore");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "the dependent the delete actually cascaded must be reactivated"
        );

        // ...but the independently-deleted one must NOT be resurrected (B16).
        let get_independent_req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/{cascader_logicalname}/{independent_dep_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_independent_req)
            .await
            .expect("get independently-deleted dependent after restore");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "B16: restoring the parent must not resurrect a dependent deleted before the parent was"
        );
    })
}

/// TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.2 (T2-2) regression: a
/// CascadeDeactivate dependent group larger than
/// `entity_mutation::CASCADE_INLINE_ROW_LIMIT` (5,000; hardcoded here as
/// `DEPENDENT_COUNT` since the constant is `pub(crate)` and this is an
/// external integration-test crate) must defer to the durable
/// `EngineJob::CascadeDeactivateDependents` job instead of running one
/// unbounded `UPDATE ... RETURNING` inside the deleting request's own
/// transaction. The delete itself must still succeed synchronously, and the
/// dependent rows must be proven untouched — the job is never actually run by
/// this test (no worker `Monitor` here), which is exactly the point: if the
/// old unbounded inline path had run, every dependent would already be
/// inactive by the time this test asserts.
#[test]
fn large_cascade_deactivate_group_defers_to_async_job() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "t22_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;
        let (cascader_logicalname, cascader_entity_id) =
            create_entity(&app, &admin_cookie, "t22_cascader").await;
        create_field(
        &app,
        &admin_cookie,
        &cascader_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"cascade-deactivate"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        let create_target_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t1"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_target_req)
            .await
            .expect("create target");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target_id = body_json(res).await["id"]
            .as_str()
            .expect("target id")
            .to_owned();
        let target_uuid = Uuid::parse_str(&target_id).expect("target id parses");

        // One row over `CASCADE_INLINE_ROW_LIMIT`. Bulk-inserted directly (not
        // through the HTTP create path) purely for test speed — the cascade
        // delete under test still runs through the real HTTP path below.
        const DEPENDENT_COUNT: i64 = 5_001;
        sqlx::query(&format!(
            "INSERT INTO \"{cascader_logicalname}\" (target_ref) \
         SELECT $1 FROM generate_series(1, {DEPENDENT_COUNT})"
        ))
        .bind(target_uuid)
        .execute(&db)
        .await
        .expect("bulk-insert cascade dependents");

        let del_target_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(del_target_req)
            .await
            .expect("delete target with huge cascade");
        assert_eq!(
            res.status(),
            StatusCode::NO_CONTENT,
            "the parent delete must succeed synchronously even for a huge dependent fan-out"
        );

        // The durable job must have been enqueued, atomically with the parent's
        // own deactivation. `CascadeDeactivateDependents` is a batch-queue
        // variant (`EngineJob::is_batch`, D-165), stored under
        // "attome_job_batch" in `JobEnvelope<EngineJob>`'s envelope shape — same
        // proven pattern as `bulk_enqueue_and_process_end_to_end`'s job-exists
        // check above.
        let job_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM apalis.jobs WHERE job_type = $1 AND job @> $2::jsonb)",
        )
        .bind("attome_job_batch")
        .bind(serde_json::json!({
            "variant": "CascadeDeactivateDependents",
            "payload": {
                "target_entity": target_logicalname,
                "target_record_id": target_id,
                "dependent_entity": cascader_logicalname,
                "dependent_field": "target_ref",
            },
        }))
        .fetch_one(&db)
        .await
        .expect("check cascade job enqueued");
        assert!(
            job_exists,
            "finding 3.2: an over-threshold cascade group must enqueue EngineJob::CascadeDeactivateDependents"
        );

        // And the dependent rows themselves must be untouched — proving the
        // request did not run the old unbounded inline UPDATE ... RETURNING.
        let still_active: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM \"{cascader_logicalname}\" WHERE target_ref = $1 AND is_active = TRUE"
    ))
    .bind(target_uuid)
    .fetch_one(&db)
    .await
    .expect("count still-active dependents");
        assert_eq!(
            still_active, DEPENDENT_COUNT,
            "finding 3.2: an over-threshold cascade group must be deferred to the async job, not run inline on the request thread"
        );
    })
}

/// F004 (P2.1): a Choice field's `options` (`{choices, multi}`, migration
/// 0029) round-trips through the admin API into the metadata registry and is
/// enforced by `attome_field::validate` on every write — an out-of-list value is
/// a 422, not silently accepted (the pre-F004 shape-only behavior).
#[test]
fn multi_select_choice_options_are_enforced_on_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("multiselect_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Multi Select Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"tags","name":"Tags","field_type":"choice",
                "options":{"choices":["red","green","blue"],"multi":true}}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create choice field");
        assert_eq!(res.status(), StatusCode::CREATED);
        let field = body_json(res).await;
        assert_eq!(
            field["options"]["choices"],
            serde_json::json!(["red", "green", "blue"])
        );

        // A valid multi-select value is accepted.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tags":["red","blue"]}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create record");
        assert_eq!(res.status(), StatusCode::CREATED);

        // A value outside the allowed list is rejected before any SQL runs.
        let bad_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tags":["red","purple"]}"#))
            .unwrap();
        let res = app.oneshot(bad_req).await.expect("bad create");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(err["message"].as_str().unwrap_or("").contains("tags"));
    })
}

/// Regression: `GET /api/v1/schema/{entity}` must serve a choice field's
/// stored `options`. It used to hardcode `options: null` for every
/// non-lookup type and never select the column at all, so the Angular
/// `field-input` select — which reads `field().options.choices` — rendered
/// nothing but its placeholder for every choice field in the platform, while
/// `admin/attribute.rs` returned the same column correctly and made the
/// metadata look fine. Asserts the lookup branch keeps its synthesized shape
/// too, since that is what the fix had to leave alone.
#[test]
fn schema_endpoint_serves_stored_choice_options() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("schemaopts_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Schema Options Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"status","name":"Status","field_type":"choice",
                "options":{"choices":["online","away","busy","offline"],"multi":false}}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create choice field");
        assert_eq!(res.status(), StatusCode::CREATED);

        let schema_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/schema/{logicalname}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(schema_req).await.expect("get schema");
        assert_eq!(res.status(), StatusCode::OK);
        let schema = body_json(res).await;

        let status = schema["fields"]
            .as_array()
            .expect("fields array")
            .iter()
            .find(|f| f["name"] == "status")
            .expect("status field present in schema");

        assert_eq!(status["field_type"], "choice");
        assert_eq!(
            status["options"]["choices"],
            serde_json::json!(["online", "away", "busy", "offline"]),
            "the schema endpoint must serve the stored choices, not null"
        );
        assert_eq!(status["options"]["multi"], serde_json::json!(false));
    })
}

/// Regression: `GET /api/v1/schema/{entity}` must resolve a lookup field's
/// `options.display_field` to the *target* entity's `primary_name_attribute`.
/// It used to hardcode `null` there — the same defect shape as
/// `schema_endpoint_serves_stored_choice_options` above, one layer down:
/// `entity.service.ts`'s `lookupSearch()` only builds its `contains` filter
/// when a display field is present, so a null one left the lookup popup's
/// search box inert, re-listing the same first 20 target records for every
/// keystroke while the metadata editor looked correct.
#[test]
fn schema_endpoint_resolves_lookup_display_field_from_target_entity() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let target_ln = format!("lkptarget_{}", Uuid::now_v7().simple());
        let source_ln = format!("lkpsource_{}", Uuid::now_v7().simple());

        // Target entity declares `title` — not the conventional `name` — as its
        // primary name attribute, so a passing assertion cannot be a coincidence
        // of some hardcoded default.
        let create_target = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{target_ln}","name":"Lookup Target",
                 "primary_name_attribute":"title"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_target)
            .await
            .expect("create target entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target_id = body_json(res).await["id"]
            .as_str()
            .expect("target entity id")
            .to_owned();

        let create_source = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{source_ln}","name":"Lookup Source"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_source)
            .await
            .expect("create source entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let source_id = body_json(res).await["id"]
            .as_str()
            .expect("source entity id")
            .to_owned();

        let create_lookup = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{source_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"target_ref","name":"Target","field_type":"lookup",
                 "lookup_entity_ref":"{target_id}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_lookup)
            .await
            .expect("create lookup field");
        assert_eq!(res.status(), StatusCode::CREATED);

        let schema_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/schema/{source_ln}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(schema_req).await.expect("get schema");
        assert_eq!(res.status(), StatusCode::OK);
        let schema = body_json(res).await;

        let lookup = schema["fields"]
            .as_array()
            .expect("fields array")
            .iter()
            .find(|f| f["name"] == "target_ref")
            .expect("lookup field present in schema");

        assert_eq!(lookup["field_type"], "lookup");
        assert_eq!(
            lookup["options"]["display_field"], "title",
            "display_field must resolve to the target entity's primary_name_attribute, not null"
        );
        // The rest of the synthesized lookup shape must be unchanged.
        assert_eq!(lookup["options"]["target_entity_id"], target_id);
        assert_eq!(lookup["options"]["target_entity_name"], target_ln);
    })
}

/// F012 (P2.1): a Text field's `options.pattern` (migration 0029) is enforced
/// by `attome_field::validate` on every write, and a malformed pattern is
/// rejected at attribute-creation time (`attome_field::validate_options`) rather
/// than only failing the first time a record write hits it.
#[test]
fn masked_text_pattern_is_enforced_on_write_and_validated_on_creation() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("masked_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Masked Text Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        // A malformed regex pattern is rejected before the attribute is ever created.
        let bad_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"phone","name":"Phone","field_type":"text",
                "options":{"pattern":"[unterminated"}}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(bad_field_req)
            .await
            .expect("bad field creation");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"phone","name":"Phone","field_type":"text",
                "options":{"pattern":"[0-9]{3}-[0-9]{4}","mask_description":"phone"}}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create masked text field");
        assert_eq!(res.status(), StatusCode::CREATED);

        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"phone":"555-1234"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create record");
        assert_eq!(res.status(), StatusCode::CREATED);

        let bad_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"phone":"not-a-phone"}"#))
            .unwrap();
        let res = app.oneshot(bad_req).await.expect("bad create");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(err["message"].as_str().unwrap_or("").contains("phone"));
    })
}

/// B7-T2: a bulk clone copies each record with the overrides, a preview
/// creates nothing, and undoing a clone removes the copy while it is
/// unchanged; once the copy is edited, undo is a 409 and removes nothing.
#[test]
fn clone_routes_bulk_clone_and_undo() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "clone").await;
        let post = |uri: String, body: serde_json::Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        let res = app
            .clone()
            .oneshot(post(
                format!("/api/v1/{logicalname}"),
                serde_json::json!({"title": "source", "amount": 5}),
            ))
            .await
            .expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let source = body_json(res).await["id"]
            .as_str()
            .expect("record id")
            .to_owned();

        // A preview creates nothing and has nothing to undo.
        let res = app
            .clone()
            .oneshot(post(
                format!("/api/v1/{logicalname}/{source}/clone"),
                serde_json::json!({"preview": true, "overrides": {"title": "preview"}}),
            ))
            .await
            .expect("preview");
        assert_eq!(res.status(), StatusCode::OK);
        let preview = body_json(res).await;
        assert!(preview["id"].is_null());
        assert_eq!(preview["body"]["title"], "preview");
        assert_eq!(preview["undo"], serde_json::json!([]));

        let res = app
            .clone()
            .oneshot(post(
                format!("/api/v1/{logicalname}/clone"),
                serde_json::json!({"ids": [source, Uuid::now_v7()], "overrides": {"title": "copy"}}),
            ))
            .await
            .expect("bulk clone");
        assert_eq!(res.status(), StatusCode::OK);
        let bulk = body_json(res).await;
        assert_eq!(bulk["cloned"].as_array().map(Vec::len), Some(1), "{bulk}");
        assert_eq!(bulk["failed"][0]["code"], "not_found", "{bulk}");
        let copy = bulk["cloned"][0]["id"]
            .as_str()
            .expect("copy id")
            .to_owned();
        let undo = bulk["cloned"][0]["undo"].clone();

        let get = |id: String| {
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/{logicalname}/{id}"))
                .header("cookie", &admin_cookie)
                .body(Body::empty())
                .unwrap()
        };
        let res = app
            .clone()
            .oneshot(get(copy.clone()))
            .await
            .expect("get copy");
        assert_eq!(res.status(), StatusCode::OK);
        let copied = body_json(res).await;
        assert_eq!(copied["data"]["title"], "copy");
        assert!(
            !copied["data"]["amount"].is_null(),
            "the copy keeps the source's values"
        );

        let res = app
            .clone()
            .oneshot(post(
                format!("/api/v1/{logicalname}/{copy}/clone/undo"),
                serde_json::json!({"items": undo}),
            ))
            .await
            .expect("undo");
        assert_eq!(res.status(), StatusCode::OK);
        let undone = body_json(res).await;
        assert_eq!(undone["removed"], 1);
        assert!(undone["operation_id"].is_string());
        let res = app
            .clone()
            .oneshot(get(copy))
            .await
            .expect("get undone copy");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "the copy is in the recycle bin"
        );

        // A copy edited after the clone is not undone.
        let res = app
            .clone()
            .oneshot(post(
                format!("/api/v1/{logicalname}/{source}/clone"),
                serde_json::json!({}),
            ))
            .await
            .expect("clone");
        assert_eq!(res.status(), StatusCode::CREATED);
        let single = body_json(res).await;
        let copy = single["id"].as_str().expect("copy id").to_owned();
        let version = single["undo"][0]["row_version"].as_i64().expect("version");
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/v1/{logicalname}/{copy}"))
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .header("if-match", format!("\"{version}\""))
                    .body(Body::from(r#"{"title":"edited"}"#))
                    .unwrap(),
            )
            .await
            .expect("edit copy");
        assert_eq!(res.status(), StatusCode::OK);
        let res = app
            .clone()
            .oneshot(post(
                format!("/api/v1/{logicalname}/{copy}/clone/undo"),
                serde_json::json!({"items": single["undo"]}),
            ))
            .await
            .expect("undo edited");
        assert_eq!(res.status(), StatusCode::CONFLICT);
        let res = app.oneshot(get(copy)).await.expect("get edited copy");
        assert_eq!(res.status(), StatusCode::OK, "nothing was removed");
    })
}

/// B2-T2: a value an edit replaced comes back through the history restore,
/// which needs `If-Match` like any update; the history names each change's
/// change set and actor (B2-T1).
#[test]
fn history_restore_puts_back_a_replaced_value() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "histrestore").await;
        let send =
            |method: &str, uri: String, if_match: Option<i64>, body: Option<serde_json::Value>| {
                let mut req = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json");
                if let Some(version) = if_match {
                    req = req.header("if-match", format!("\"{version}\""));
                }
                req.body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                    .unwrap()
            };

        let res = app
            .clone()
            .oneshot(send(
                "POST",
                format!("/api/v1/{logicalname}"),
                None,
                Some(serde_json::json!({"title": "first"})),
            ))
            .await
            .expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let id = created["id"].as_str().expect("id").to_owned();
        let version = created["row_version"].as_i64().expect("version");

        let res = app
            .clone()
            .oneshot(send(
                "PATCH",
                format!("/api/v1/{logicalname}/{id}"),
                Some(version),
                Some(serde_json::json!({"title": "second"})),
            ))
            .await
            .expect("edit");
        assert_eq!(res.status(), StatusCode::OK);
        let version = body_json(res).await["row_version"]
            .as_i64()
            .expect("version");
        // The audit chainer turns captured events into the headers the
        // history reads.
        attome_audit::chainer::run_once(&state.base.db, state.audit_signer.as_deref(), 1000, None)
            .await
            .expect("drain the audit ingest queue");

        let res = app
            .clone()
            .oneshot(send(
                "GET",
                format!("/api/v1/{logicalname}/{id}/history?field=title"),
                None,
                None,
            ))
            .await
            .expect("history");
        assert_eq!(res.status(), StatusCode::OK);
        let history = body_json(res).await;
        let edit = history["items"]
            .as_array()
            .and_then(|items| {
                items.iter().find(|c| {
                    c["fields"][0]["new_value"] == "second"
                        && c["fields"][0]["field_name"] == "title"
                })
            })
            .cloned()
            .expect("the edit is in the history");
        assert!(edit["group_id"].is_string(), "{edit}");
        assert_eq!(edit["actor"], "user", "{edit}");
        let audit_id = edit["audit_id"].as_str().expect("audit id").to_owned();

        let restore_uri = format!("/api/v1/{logicalname}/{id}/history/restore");
        let res = app
            .clone()
            .oneshot(send(
                "POST",
                restore_uri.clone(),
                None,
                Some(serde_json::json!({"audit_id": audit_id})),
            ))
            .await
            .expect("restore without If-Match");
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "If-Match is required"
        );

        let res = app
            .clone()
            .oneshot(send(
                "POST",
                restore_uri,
                Some(version),
                Some(serde_json::json!({"audit_id": audit_id})),
            ))
            .await
            .expect("restore");
        assert_eq!(res.status(), StatusCode::OK);
        let restored = body_json(res).await;
        assert_eq!(restored["data"]["title"], "first", "{restored}");
    })
}

/// B2-T4: the history search finds the record whose amount crossed 20,
/// and not one that stayed below it.
#[test]
fn history_search_finds_a_value_crossing() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "histsearch").await;
        let send =
            |method: &str, uri: String, if_match: Option<i64>, body: Option<serde_json::Value>| {
                let mut req = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json");
                if let Some(version) = if_match {
                    req = req.header("if-match", format!("\"{version}\""));
                }
                req.body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                    .unwrap()
            };
        let mut ids = Vec::new();
        for (from, to) in [(10, 25), (5, 15)] {
            let res = app
                .clone()
                .oneshot(send(
                    "POST",
                    format!("/api/v1/{logicalname}"),
                    None,
                    Some(serde_json::json!({"title": "deal", "amount": from})),
                ))
                .await
                .expect("create");
            assert_eq!(res.status(), StatusCode::CREATED);
            let created = body_json(res).await;
            let id = created["id"].as_str().expect("id").to_owned();
            let version = created["row_version"].as_i64().expect("version");
            let res = app
                .clone()
                .oneshot(send(
                    "PATCH",
                    format!("/api/v1/{logicalname}/{id}"),
                    Some(version),
                    Some(serde_json::json!({"amount": to})),
                ))
                .await
                .expect("edit");
            assert_eq!(res.status(), StatusCode::OK);
            ids.push(id);
        }
        attome_audit::chainer::run_once(&state.base.db, state.audit_signer.as_deref(), 1000, None)
            .await
            .expect("drain the audit ingest queue");

        let res = app
            .clone()
            .oneshot(send(
                "GET",
                format!(
                    "/api/v1/history/search?entity={logicalname}&field=amount\
                     &old_op=lte&old_value=20&new_op=gt&new_value=20"
                ),
                None,
                None,
            ))
            .await
            .expect("search");
        assert_eq!(res.status(), StatusCode::OK);
        let found = body_json(res).await;
        let records: Vec<&str> = found["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|m| m["record_id"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(records, vec![ids[0].as_str()], "{found}");

        let res = app
            .oneshot(send(
                "GET",
                format!("/api/v1/history/search?entity={logicalname}&field=amount&new_op=gt&new_value=abc"),
                None,
                None,
            ))
            .await
            .expect("bad search");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

/// B4-T3: merging a tag moves its links (a record carrying both keeps one),
/// its name then finds the other tag, undo moves the links back, and the
/// sweep removes links past their expiry.
#[test]
fn tag_merge_undo_and_expiry() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "tagmerge").await;
        let send = |method: &str, uri: String, body: Option<serde_json::Value>| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                .unwrap()
        };
        let alpha = format!("alpha-{logicalname}");
        let beta = format!("beta-{logicalname}");
        let mut records = Vec::new();
        for _ in 0..2 {
            let res = app
                .clone()
                .oneshot(send(
                    "POST",
                    format!("/api/v1/{logicalname}"),
                    Some(serde_json::json!({"title": "tagged"})),
                ))
                .await
                .expect("create");
            assert_eq!(res.status(), StatusCode::CREATED);
            records.push(body_json(res).await["id"].as_str().expect("id").to_owned());
        }
        let tag = |record: &str, name: &str| {
            send(
                "POST",
                format!("/api/v1/{logicalname}/{record}/tags"),
                Some(serde_json::json!({"name": name})),
            )
        };
        let names = |page: &Value| -> Vec<String> {
            page["items"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|t| t["name"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let res = app
            .clone()
            .oneshot(tag(&records[0], &alpha))
            .await
            .expect("tag");
        assert_eq!(res.status(), StatusCode::OK);
        let alpha_id = body_json(res).await["items"][0]["id"]
            .as_str()
            .expect("tag id")
            .to_owned();
        app.clone()
            .oneshot(tag(&records[1], &alpha))
            .await
            .expect("tag");
        let res = app
            .clone()
            .oneshot(tag(&records[1], &beta))
            .await
            .expect("tag");
        let beta_id = body_json(res).await["items"]
            .as_array()
            .and_then(|items| items.iter().find(|t| t["name"] == beta.as_str()))
            .and_then(|t| t["id"].as_str())
            .expect("beta id")
            .to_owned();

        let res = app
            .clone()
            .oneshot(send(
                "POST",
                format!("/api/v1/admin/tags/{alpha_id}/merge"),
                Some(serde_json::json!({"into": beta_id})),
            ))
            .await
            .expect("merge");
        assert_eq!(res.status(), StatusCode::OK);
        let merged = body_json(res).await;
        assert_eq!(merged["moved"], 1, "{merged}");
        assert_eq!(merged["dropped"], 1, "{merged}");
        let res = app
            .clone()
            .oneshot(send(
                "GET",
                format!("/api/v1/{logicalname}/{}/tags", records[0]),
                None,
            ))
            .await
            .expect("tags");
        assert_eq!(names(&body_json(res).await), vec![beta.clone()]);
        // The merged name now finds the other tag.
        let res = app
            .clone()
            .oneshot(tag(&records[0], &alpha))
            .await
            .expect("tag by old name");
        assert_eq!(names(&body_json(res).await), vec![beta.clone()]);

        let res = app
            .clone()
            .oneshot(send(
                "POST",
                format!("/api/v1/admin/tags/{alpha_id}/unmerge"),
                None,
            ))
            .await
            .expect("unmerge");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_json(res).await["moved"], 1);
        let res = app
            .clone()
            .oneshot(send(
                "GET",
                format!("/api/v1/{logicalname}/{}/tags", records[0]),
                None,
            ))
            .await
            .expect("tags");
        assert_eq!(names(&body_json(res).await), vec![alpha.clone()]);

        // An expired link goes at the next sweep.
        sqlx::query(
            "UPDATE tag_link SET expires_at = now() - interval '1 minute' \
             WHERE entity = $1 AND record_id = $2::uuid",
        )
        .bind(&logicalname)
        .bind(&records[0])
        .execute(&state.base.db)
        .await
        .expect("expire the link");
        let removed = attome_records::entity_crud::tags::sweep_expired_links(&state.base.db)
            .await
            .expect("sweep");
        assert!(removed >= 1);
        let res = app
            .oneshot(send(
                "GET",
                format!("/api/v1/{logicalname}/{}/tags", records[0]),
                None,
            ))
            .await
            .expect("tags");
        assert!(names(&body_json(res).await).is_empty());
    })
}

/// F026 (P2.2): `POST .../restore` undeletes a soft-deleted record. Delete
/// now also bumps `row_version` (P-data-lifecycle's `on_target_delete` work
/// stamps `modified_by`/`modified_at`/`row_version` on every soft-delete, not
/// just a bare `is_active` flip), so a fresh record ends at `row_version ==
/// 2` after one delete + one restore. A second restore on an already-active
/// record is a 409, not a silent no-op.
#[test]
fn restore_undeletes_a_soft_deleted_record() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "restore").await;

        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"before-delete"}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let record_id = created["id"].as_str().expect("record id").to_owned();

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(delete_req).await.expect("delete");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let restore_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{record_id}/restore"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(restore_req).await.expect("restore");
        assert_eq!(res.status(), StatusCode::OK);
        let restored = body_json(res).await;
        assert_eq!(restored["data"]["title"], "before-delete");
        assert_eq!(
            restored["row_version"].as_i64(),
            Some(2),
            "delete and restore each bump row_version once"
        );

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_req)
            .await
            .expect("get after restore");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "restored record must be readable again"
        );

        let restore_again_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{record_id}/restore"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(restore_again_req).await.expect("restore again");
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "restoring an already-active record must not be a silent no-op"
        );
        let err = body_json(res).await;
        assert_eq!(err["error"], "conflict");
    })
}

/// `restore_one`'s `RETURNING` row is decoded through `row_to_json`, the same
/// shape `create_one`/`update_one` use — decoding a multi-column `RETURNING`
/// straight into one JSON value failed sqlx's type check on the leading `id`
/// uuid and masked every restore as a 500. A matching `If-Match` goes all
/// the way through that `UPDATE ... RETURNING`, so it is the path that proves
/// the decode: 200, the row's data intact, and `row_version` bumped by one.
#[test]
fn restore_with_matching_if_match_bumps_row_version() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "rstmatch").await;

        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"match-me"}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let record_id = created["id"].as_str().expect("record id").to_owned();
        let v0 = created["row_version"].as_i64().expect("row_version");

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .header("if-match", format!("\"{v0}\""))
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(delete_req).await.expect("delete");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let deleted_version = v0 + 1;

        let restore_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{record_id}/restore"))
            .header("cookie", &admin_cookie)
            .header("if-match", format!("\"{deleted_version}\""))
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(restore_req).await.expect("restore");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "a restore with the current If-Match must succeed"
        );
        let restored = body_json(res).await;
        assert_eq!(restored["id"].as_str(), Some(record_id.as_str()));
        assert_eq!(restored["data"]["title"], "match-me");
        assert_eq!(
            restored["row_version"].as_i64(),
            Some(deleted_version + 1),
            "restore must bump row_version exactly once"
        );

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_req).await.expect("get after restore");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            body_json(res).await["row_version"].as_i64(),
            Some(deleted_version + 1),
            "the committed row carries the bumped row_version"
        );
    })
}

/// A stale `If-Match` on restore is a 409 `version_conflict`, and the record
/// stays soft-deleted: the rejected restore changed nothing.
#[test]
fn restore_with_stale_if_match_is_a_conflict() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "rststale").await;

        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"stale"}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let record_id = created["id"].as_str().expect("record id").to_owned();
        let v0 = created["row_version"].as_i64().expect("row_version");

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(delete_req).await.expect("delete");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // `v0` is the pre-delete version; the delete bumped it, so it is stale.
        let restore_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{record_id}/restore"))
            .header("cookie", &admin_cookie)
            .header("if-match", format!("\"{v0}\""))
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(restore_req).await.expect("restore");
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "a stale If-Match must not restore the record"
        );
        assert_eq!(body_json(res).await["error"], "version_conflict");

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_req)
            .await
            .expect("get after rejected restore");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "the record must stay deleted after a rejected restore"
        );
    })
}

/// F023 (P2.2): `POST .../upsert` creates when no row matches `match`, then
/// updates that same row (never inserting a duplicate) on a second call with
/// the same match key.
#[test]
fn upsert_creates_then_updates_by_match_key() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("upsert_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Upsert Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let entity = body_json(res).await;
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        for (ln, ft) in [("sku", "text"), ("qty", "number")] {
            let create_field_req = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"logicalname":"{ln}","name":"{ln}","field_type":"{ft}"}}"#
                )))
                .unwrap();
            let res = app
                .clone()
                .oneshot(create_field_req)
                .await
                .expect("create field");
            assert_eq!(res.status(), StatusCode::CREATED);
        }

        // No existing row matches sku="widget" — this creates one.
        let upsert1_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/upsert"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"match":{"sku":"widget"},"data":{"qty":5}}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(upsert1_req)
            .await
            .expect("first upsert");
        assert_eq!(res.status(), StatusCode::CREATED);
        let first = body_json(res).await;
        assert_eq!(first["data"]["sku"], "widget");
        assert_eq!(first["data"]["qty"], 5);
        let record_id = first["id"].as_str().expect("record id").to_owned();

        // Same match key without a version is an attempted update, not a fresh
        // insert, so the enterprise concurrency contract rejects it.
        let upsert2_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/upsert"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"match":{"sku":"widget"},"data":{"qty":9}}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(upsert2_req)
            .await
            .expect("versionless update upsert");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"]
                .as_str()
                .unwrap_or("")
                .contains("row_version")
        );

        // The current version makes the same upsert an update of the row created
        // above, never a duplicate insert.
        let upsert3_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/upsert"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"match":{"sku":"widget"},"data":{"qty":9},"row_version":0}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(upsert3_req)
            .await
            .expect("versioned second upsert");
        assert_eq!(res.status(), StatusCode::OK);
        let second = body_json(res).await;
        assert_eq!(
            second["id"], record_id,
            "second upsert must update the same row, not insert a duplicate"
        );
        assert_eq!(second["data"]["qty"], 9);
        assert_eq!(second["row_version"].as_i64(), Some(1));

        let row_count: i64 = sqlx::query_scalar(&format!(
            r#"SELECT count(*) FROM "{logicalname}" WHERE sku = 'widget' AND is_active = true"#
        ))
        .fetch_one(&db)
        .await
        .expect("count rows directly");
        assert_eq!(
            row_count, 1,
            "upsert on the same match key must never duplicate a row"
        );

        // A stale version remains a conflict after the successful update.
        let stale_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/upsert"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"match":{"sku":"widget"},"data":{"qty":10},"row_version":0}"#,
            ))
            .unwrap();
        let res = app.clone().oneshot(stale_req).await.expect("stale upsert");
        assert_eq!(res.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(res).await["error"], "version_conflict");

        // Explicitly malformed versions must not silently become a versionless
        // update.
        for malformed in [r#""0""#, r#"0.5"#, r#"-1"#] {
            let body = format!(
                r#"{{"match":{{"sku":"widget"}},"data":{{"qty":11}},"row_version":{malformed}}}"#
            );
            let req = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/{logicalname}/upsert"))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.expect("malformed upsert");
            assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(body_json(res).await["error"], "validation_error");
        }
    })
}

/// Provisions an entity with a `name` text field and a `parent_ref` lookup
/// field pointing back at itself — the org/case-tree shape F019 targets.
async fn setup_hierarchy_entity(app: &axum::Router, admin_cookie: &str) -> String {
    let (logicalname, entity_id) = create_entity(app, admin_cookie, "hierarchy").await;
    create_field(
        app,
        admin_cookie,
        &entity_id,
        r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
    )
    .await;
    create_field(
        app,
        admin_cookie,
        &entity_id,
        &format!(
            r#"{{"logicalname":"parent_ref","name":"Parent Ref","field_type":"lookup","lookup_entity_ref":"{entity_id}"}}"#
        ),
    )
    .await;
    logicalname
}

async fn create_hierarchy_node(
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    name: &str,
    parent_id: Option<&str>,
) -> (String, i64) {
    let body = match parent_id {
        Some(p) => format!(r#"{{"name":"{name}","parent_ref":"{p}"}}"#),
        None => format!(r#"{{"name":"{name}"}}"#),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create node");
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let id = created["id"].as_str().expect("node id").to_owned();
    let row_version = created["row_version"].as_i64().expect("row_version");
    (id, row_version)
}

/// F019: `GET .../ancestors` and `GET .../descendants` walk a self-referencing
/// `parent_ref` chain (`a` -> `b` -> `c`) via the recursive-CTE endpoints,
/// nearest-first for ancestors, breadth order for descendants.
#[test]
fn hierarchy_ancestors_and_descendants_walk_the_tree() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", Some(&a_id)).await;
        let (c_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "c", Some(&b_id)).await;

        let ancestors_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{c_id}/ancestors"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(ancestors_req)
            .await
            .expect("list ancestors");
        assert_eq!(res.status(), StatusCode::OK);
        let ancestors = body_json(res).await;
        let items = ancestors["items"].as_array().expect("items array");
        assert_eq!(items.len(), 2, "c's ancestors are b then a: {items:?}");
        assert_eq!(items[0]["data"]["name"], "b", "nearest ancestor first");
        assert_eq!(items[1]["data"]["name"], "a");

        let descendants_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}/descendants"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(descendants_req)
            .await
            .expect("list descendants");
        assert_eq!(res.status(), StatusCode::OK);
        let descendants = body_json(res).await;
        let items = descendants["items"].as_array().expect("items array");
        let names: Vec<&str> = items
            .iter()
            .map(|r| r["data"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["b", "c"],
            "a's descendants are b and c, breadth order"
        );

        // A leaf has no descendants and the root has no ancestors — both are
        // empty lists, not errors.
        let leaf_descendants_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{c_id}/descendants"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(leaf_descendants_req)
            .await
            .expect("leaf descendants");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_json(res).await["items"].as_array().unwrap().len(), 0);

        let root_ancestors_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}/ancestors"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(root_ancestors_req)
            .await
            .expect("root ancestors");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_json(res).await["items"].as_array().unwrap().len(), 0);
    })
}

/// F019: the self-referencing lookup cycle guard rejects both the trivial
/// one-step case (a record naming itself as its own parent) and an indirect
/// cycle (setting a node's parent to its own descendant) — both on update,
/// since a fresh create has no id yet to cycle back to.
#[test]
fn hierarchy_cycle_guard_rejects_self_and_indirect_cycles() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", Some(&a_id)).await;

        // a cannot be its own parent.
        let self_parent_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{a_v0}\""))
            .body(Body::from(format!(r#"{{"parent_ref":"{a_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(self_parent_req)
            .await
            .expect("self-parent attempt");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(err["message"].as_str().unwrap_or("").contains("parent_ref"));

        // a -> b already exists; setting a's parent to b would close the loop
        // (a -> b -> a).
        let cycle_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{a_v0}\""))
            .body(Body::from(format!(r#"{{"parent_ref":"{b_id}"}}"#)))
            .unwrap();
        let res = app.clone().oneshot(cycle_req).await.expect("cycle attempt");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"].as_str().unwrap_or("").contains("cycle"),
            "error must explain the rejection: {err:?}"
        );

        // a is still unparented after both rejected attempts — neither one
        // partially applied.
        let get_a_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_a_req).await.expect("get a");
        assert_eq!(res.status(), StatusCode::OK);
        let a = body_json(res).await;
        assert!(a["data"]["parent_ref"].is_null(), "a: {a:?}");
        assert_eq!(a["row_version"].as_i64(), Some(a_v0), "no partial update");
    })
}

/// F019/D-095: the same cycle guard applies to the upsert conflict-update
/// branch, not only to PATCH. A failed upsert must leave both the hierarchy
/// edge and row_version unchanged.
#[test]
fn hierarchy_upsert_cycle_guard_rejects_self_and_indirect_cycles() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", Some(&a_id)).await;

        // Self-parent (a -> a) and indirect cycle (a -> b -> a) are rejected with
        // distinct messages — same split as the PATCH version of this guard
        // above ("a record cannot be its own parent" vs. "would create a cycle").
        for (parent_id, expected_substring) in [(&a_id, "own parent"), (&b_id, "cycle")] {
            let body = format!(
                r#"{{"match":{{"name":"a"}},"data":{{"parent_ref":"{parent_id}"}},"row_version":{a_v0}}}"#
            );
            let req = Request::builder()
                .method("POST")
                .uri(format!("/api/v1/{logicalname}/upsert"))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.expect("cycle upsert");
            assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let err = body_json(res).await;
            assert_eq!(err["error"], "validation_error");
            assert!(
                err["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains(expected_substring),
                "expected {expected_substring:?} in {err:?}"
            );
        }

        let get_a_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_a_req)
            .await
            .expect("get a after upsert cycles");
        assert_eq!(res.status(), StatusCode::OK);
        let a = body_json(res).await;
        assert!(a["data"]["parent_ref"].is_null(), "a: {a:?}");
        assert_eq!(a["row_version"].as_i64(), Some(a_v0));
    })
}

/// F019/D-095: a hierarchy chain that reaches the safety cap without a root
/// is rejected rather than being treated as a valid, merely deep hierarchy.
#[test]
fn hierarchy_cycle_guard_fails_closed_at_depth_limit() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (candidate_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "candidate", None).await;
        let (mut parent_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "chain-0", None).await;
        // chain-100 has 100 unresolved non-null links when its parent chain is
        // examined, so the guard must refuse to guess beyond the cap.
        for index in 1..=100 {
            let (id, _) = create_hierarchy_node(
                &app,
                &admin_cookie,
                &logicalname,
                &format!("chain-{index}"),
                Some(&parent_id),
            )
            .await;
            parent_id = id;
        }

        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{candidate_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", "\"0\"")
            .body(Body::from(format!(r#"{{"parent_ref":"{parent_id}"}}"#)))
            .unwrap();
        let res = app
            .oneshot(req)
            .await
            .expect("depth-limit hierarchy update");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"]
                .as_str()
                .unwrap_or("")
                .contains("exceeds 100")
        );
    })
}

/// F019/D-095: concurrent reparenting of one record is serialized by the
/// row-scoped advisory lock. One request succeeds and the other receives a
/// conflict; neither request may deadlock or produce an invalid hierarchy.
#[test]
fn concurrent_hierarchy_reparents_are_conflict_safe() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", None).await;
        let (c_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "c", None).await;

        let make_request = |parent_id: &str| {
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/{logicalname}/{a_id}"))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .header("if-match", format!("\"{a_v0}\""))
                .body(Body::from(format!(r#"{{"parent_ref":"{parent_id}"}}"#)))
                .unwrap()
        };

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                app.clone().oneshot(make_request(&b_id)),
                app.clone().oneshot(make_request(&c_id)),
            )
        })
        .await
        .expect("concurrent hierarchy updates must not deadlock");
        let first = result.0.expect("first hierarchy response");
        let second = result.1.expect("second hierarchy response");
        let statuses = [first.status(), second.status()];
        assert!(statuses.contains(&StatusCode::OK), "statuses: {statuses:?}");
        assert!(
            statuses.contains(&StatusCode::CONFLICT),
            "statuses: {statuses:?}"
        );
        drop(first);
        drop(second);

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_req).await.expect("get reparented record");
        assert_eq!(res.status(), StatusCode::OK);
        let row = body_json(res).await;
        let parent = row["data"]["parent_ref"]
            .as_str()
            .expect("reparented parent id");
        assert!(parent == b_id || parent == c_id);
        assert_eq!(row["row_version"].as_i64(), Some(1));
    })
}

/// P-hierarchy-mutation-locking: the race the same-record test above does
/// *not* cover. Two concurrent requests reparenting two *different* records
/// at each other (`a.parent = b` and `b.parent = a`) used to take
/// non-contending per-record advisory locks (`{entity}:hierarchy:{record}`),
/// each read the other's pre-commit (still-unmodified) parent chain, and
/// both passed `guard_hierarchy_cycles` — committing a genuine `a <-> b`
/// cycle with neither request ever seeing a conflict. The entity-level lock
/// (`lock_hierarchy_entity`) serializes every hierarchy-touching write for
/// the whole entity, so exactly one of these requests must succeed; the
/// other must be rejected — either immediately by the lock (409, if it
/// arrives while the winner's transaction is still open) or by
/// `guard_hierarchy_cycles` itself (422, if it arrives after the winner has
/// already committed and can now see the real, live parent chain). Either
/// outcome proves the cross-record race is closed; a and b must never both
/// end up pointing at each other.
#[test]
fn concurrent_cross_record_hierarchy_reparents_are_conflict_safe() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, b_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", None).await;

        let a_to_b = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{a_v0}\""))
            .body(Body::from(format!(r#"{{"parent_ref":"{b_id}"}}"#)))
            .unwrap();
        let b_to_a = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{b_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{b_v0}\""))
            .body(Body::from(format!(r#"{{"parent_ref":"{a_id}"}}"#)))
            .unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(app.clone().oneshot(a_to_b), app.clone().oneshot(b_to_a))
        })
        .await
        .expect("concurrent cross-record hierarchy updates must not deadlock");
        let first = result.0.expect("first hierarchy response");
        let second = result.1.expect("second hierarchy response");
        let statuses = [first.status(), second.status()];
        assert!(
            statuses.contains(&StatusCode::OK),
            "exactly one side must succeed: {statuses:?}"
        );
        assert!(
            statuses.contains(&StatusCode::CONFLICT)
                || statuses.contains(&StatusCode::UNPROCESSABLE_ENTITY),
            "the losing side must be rejected (409 lock conflict or 422 cycle guard), not silently applied: {statuses:?}"
        );
        drop(first);
        drop(second);

        let get_a_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let a_row = body_json(app.clone().oneshot(get_a_req).await.expect("get a")).await;
        let get_b_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{b_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let b_row = body_json(app.oneshot(get_b_req).await.expect("get b")).await;

        let a_parent_is_b = a_row["data"]["parent_ref"].as_str() == Some(b_id.as_str());
        let b_parent_is_a = b_row["data"]["parent_ref"].as_str() == Some(a_id.as_str());
        assert!(
            !(a_parent_is_b && b_parent_is_a),
            "a and b must not both point at each other — that is the committed cycle this test guards against: a={a_row:?} b={b_row:?}"
        );
    })
}

/// P-hierarchy-mutation-locking §6: the interactive-vs-bulk race — this
/// plan's own closing checklist (`P-hierarchy-mutation-locking.md` §10)
/// lists this as still not written after D-138 (only interactive-vs-
/// interactive and the merge-redirect case were covered that session). A
/// bulk `update` job reparenting `a -> b` races a plain interactive `PATCH`
/// reparenting `b -> a`; `lock_hierarchy_entity` must serialize the two
/// exactly as it does two competing interactive requests (D-138's point:
/// one lock function, every call site) — from the lock's perspective a bulk
/// item must be indistinguishable from a second interactive request.
/// `bulk::process` is invoked directly, the same way
/// `bulk_create_processes_all_records_and_isolates_per_record_errors`
/// simulates the worker without a live apalis loop.
#[test]
fn interactive_hierarchy_reparent_races_a_bulk_update_reparent_conflict_safely() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, b_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", None).await;

        // Enqueue the bulk half: a.parent = b. `process` skips already-succeeded
        // items by index, so the item ledger row must exist first, same as
        // every other bulk test in this file.
        let enqueue_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/bulk"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"operation":"update","records":[{{"id":"{a_id}","expected_row_version":{a_v0},"data":{{"parent_ref":"{b_id}"}}}}]}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(enqueue_req)
            .await
            .expect("enqueue bulk reparent");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let bulk_op_id = Uuid::parse_str(body_json(res).await["id"].as_str().unwrap()).unwrap();

        // The interactive half: b.parent = a.
        let interactive_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{b_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{b_v0}\""))
            .body(Body::from(format!(r#"{{"parent_ref":"{a_id}"}}"#)))
            .unwrap();

        let (bulk_result, interactive_result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    attome_records::bulk::process(
                        &state,
                        bulk_op_id,
                        &logicalname,
                        "update",
                        vec![serde_json::json!({
                            "id": a_id,
                            "expected_row_version": a_v0,
                            "data": {"parent_ref": b_id},
                        })],
                        admin_user_id,
                    ),
                    app.clone().oneshot(interactive_req),
                )
            })
            .await
            .expect("interactive-vs-bulk hierarchy race must not deadlock");
        bulk_result.expect(
            "bulk process itself must not error — a losing item is recorded as a failed \
         item, not returned as Err (see bulk::process's own AppError::Internal-only \
         early-return contract)",
        );
        let interactive_res = interactive_result.expect("interactive response");

        let status_req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/{logicalname}/bulk/{bulk_op_id}?include_items=true"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let bulk_status =
            body_json(app.clone().oneshot(status_req).await.expect("bulk status")).await;
        let bulk_item_status = bulk_status["items"][0]["status"].clone();
        let bulk_item_succeeded = bulk_item_status == "succeeded";
        let interactive_status = interactive_res.status();
        let interactive_succeeded = interactive_status == StatusCode::OK;

        assert!(
            bulk_item_succeeded ^ interactive_succeeded,
            "exactly one side must win: bulk item status={bulk_item_status:?}, interactive status={interactive_status}"
        );
        if !interactive_succeeded {
            assert!(
                interactive_status == StatusCode::CONFLICT
                    || interactive_status == StatusCode::UNPROCESSABLE_ENTITY,
                "the losing interactive request must be rejected (409 lock conflict or \
             422 cycle guard), not silently dropped: {interactive_status}"
            );
        }
        drop(interactive_res);

        let get_a_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let a_row = body_json(app.clone().oneshot(get_a_req).await.expect("get a")).await;
        let get_b_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{b_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let b_row = body_json(app.oneshot(get_b_req).await.expect("get b")).await;

        let a_parent_is_b = a_row["data"]["parent_ref"].as_str() == Some(b_id.as_str());
        let b_parent_is_a = b_row["data"]["parent_ref"].as_str() == Some(a_id.as_str());
        assert!(
            !(a_parent_is_b && b_parent_is_a),
            "a and b must not both point at each other — a committed cycle would mean the \
         bulk path never actually contended on the entity lock: a={a_row:?} b={b_row:?}"
        );
    })
}

/// P-hierarchy-mutation-locking §6: bulk-vs-bulk, the third race shape this
/// plan's own closing checklist lists as still open — defense-in-depth for
/// when `P-bulk-batch-integrity.md`'s own `{entity}:bulk-graph-preflight`
/// lock (a *different* lock, scoped to one bulk operation's own
/// enqueue/approval transaction, per that plan's §4) is not yet landed, or
/// does not cover two wholly separate bulk operations racing each other's
/// `process()` runs the way this test does.
#[test]
fn two_bulk_update_reparents_race_conflict_safely() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, b_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", None).await;

        let enqueue = |record_id: &str, version: i64, parent: &str| {
            Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/bulk"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"operation":"update","records":[{{"id":"{record_id}","expected_row_version":{version},"data":{{"parent_ref":"{parent}"}}}}]}}"#
            )))
            .unwrap()
        };

        let res_a = app
            .clone()
            .oneshot(enqueue(&a_id, a_v0, &b_id))
            .await
            .expect("enqueue a->b");
        assert_eq!(res_a.status(), StatusCode::ACCEPTED);
        let bulk_op_a = Uuid::parse_str(body_json(res_a).await["id"].as_str().unwrap()).unwrap();

        let res_b = app
            .clone()
            .oneshot(enqueue(&b_id, b_v0, &a_id))
            .await
            .expect("enqueue b->a");
        assert_eq!(res_b.status(), StatusCode::ACCEPTED);
        let bulk_op_b = Uuid::parse_str(body_json(res_b).await["id"].as_str().unwrap()).unwrap();

        let (result_a, result_b) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                attome_records::bulk::process(
                    &state,
                    bulk_op_a,
                    &logicalname,
                    "update",
                    vec![serde_json::json!({
                        "id": a_id,
                        "expected_row_version": a_v0,
                        "data": {"parent_ref": b_id},
                    })],
                    admin_user_id,
                ),
                attome_records::bulk::process(
                    &state,
                    bulk_op_b,
                    &logicalname,
                    "update",
                    vec![serde_json::json!({
                        "id": b_id,
                        "expected_row_version": b_v0,
                        "data": {"parent_ref": a_id},
                    })],
                    admin_user_id,
                ),
            )
        })
        .await
        .expect("bulk-vs-bulk hierarchy race must not deadlock");
        result_a.expect("bulk process (a->b) must not itself error");
        result_b.expect("bulk process (b->a) must not itself error");

        let status = |bulk_op_id: Uuid| {
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/{logicalname}/bulk/{bulk_op_id}?include_items=true"
                ))
                .header("cookie", &admin_cookie)
                .body(Body::empty())
                .unwrap()
        };
        let status_a = body_json(
            app.clone()
                .oneshot(status(bulk_op_a))
                .await
                .expect("status a"),
        )
        .await;
        let status_b = body_json(
            app.clone()
                .oneshot(status(bulk_op_b))
                .await
                .expect("status b"),
        )
        .await;
        let a_item_status = status_a["items"][0]["status"].clone();
        let b_item_status = status_b["items"][0]["status"].clone();
        let a_succeeded = a_item_status == "succeeded";
        let b_succeeded = b_item_status == "succeeded";
        assert!(
            a_succeeded ^ b_succeeded,
            "exactly one bulk operation must win: a={a_item_status:?} b={b_item_status:?}"
        );

        let get_a_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{a_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let a_row = body_json(app.clone().oneshot(get_a_req).await.expect("get a")).await;
        let get_b_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{b_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let b_row = body_json(app.oneshot(get_b_req).await.expect("get b")).await;

        let a_parent_is_b = a_row["data"]["parent_ref"].as_str() == Some(b_id.as_str());
        let b_parent_is_a = b_row["data"]["parent_ref"].as_str() == Some(a_id.as_str());
        assert!(
            !(a_parent_is_b && b_parent_is_a),
            "a and b must not both point at each other — a committed cycle from two bulk \
         operations racing the same entity-level lock: a={a_row:?} b={b_row:?}"
        );
    })
}

/// F028: merging a duplicate into a canonical record fills the canonical's
/// gaps from the duplicate (never overwriting a value the canonical already
/// has), redirects every other entity's lookup field that pointed at the
/// duplicate to the canonical id instead, and retires the duplicate.
#[test]
fn merge_records_unions_data_redirects_dependents_and_retires_duplicate() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "merge_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"email","name":"Email","field_type":"text"}"#,
        )
        .await;

        let (referrer_logicalname, referrer_entity_id) =
            create_entity(&app, &admin_cookie, "merge_referrer").await;
        create_field(
        &app,
        &admin_cookie,
        &referrer_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        // Canonical has a name but no email; duplicate has both.
        let create_canonical_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Alice"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_canonical_req)
            .await
            .expect("create canonical");
        assert_eq!(res.status(), StatusCode::CREATED);
        let canonical_id = body_json(res).await["id"].as_str().unwrap().to_owned();

        let create_duplicate_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"Alice Duplicate","email":"alice@example.com"}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_duplicate_req)
            .await
            .expect("create duplicate");
        assert_eq!(res.status(), StatusCode::CREATED);
        let duplicate_id = body_json(res).await["id"].as_str().unwrap().to_owned();

        let create_referrer_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{referrer_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{duplicate_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_referrer_req)
            .await
            .expect("create referrer");
        assert_eq!(res.status(), StatusCode::CREATED);
        let referrer = body_json(res).await;
        let referrer_id = referrer["id"].as_str().unwrap().to_owned();

        let merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}/{canonical_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"duplicate_id":"{duplicate_id}"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(merge_req).await.expect("merge");
        assert_eq!(res.status(), StatusCode::OK);
        let merged = body_json(res).await;
        assert_eq!(
            merged["data"]["name"], "Alice",
            "canonical's own value must win over the duplicate's"
        );
        assert_eq!(
            merged["data"]["email"], "alice@example.com",
            "canonical's gap must be filled from the duplicate"
        );

        // The referrer that pointed at the duplicate now points at the canonical.
        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_logicalname}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer");
        assert_eq!(res.status(), StatusCode::OK);
        let referrer = body_json(res).await;
        assert_eq!(
            referrer["data"]["target_ref"], canonical_id,
            "referrer must be redirected to the canonical id: {referrer:?}"
        );

        // The duplicate itself is retired.
        let get_duplicate_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{target_logicalname}/{duplicate_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_duplicate_req)
            .await
            .expect("get duplicate");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "the duplicate must be soft-deleted after merge"
        );

        // Merging an already-inactive duplicate again is rejected, not a silent no-op.
        let remerge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}/{canonical_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"duplicate_id":"{duplicate_id}"}}"#
            )))
            .unwrap();
        let res = app.oneshot(remerge_req).await.expect("remerge attempt");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

/// C-07 — merge now goes through the same mutation primitives ordinary CRUD
/// does (`update_one` for the canonical fill, `delete_one` for retiring the
/// duplicate), so it must emit a change-feed row (`entity_change_event`)
/// for all three things it touches: the canonical record (update), the
/// duplicate (delete), and every dependent row the redirect step repoints —
/// previously none of the three got one at all.
#[test]
fn merge_emits_change_feed_rows_for_canonical_duplicate_and_redirected_dependents() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);
        let db = state.base.db.clone();

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "merge_feed_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"email","name":"Email","field_type":"text"}"#,
        )
        .await;

        let (referrer_logicalname, referrer_entity_id) =
            create_entity(&app, &admin_cookie, "merge_feed_referrer").await;
        create_field(
        &app,
        &admin_cookie,
        &referrer_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        let create_canonical_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Alice"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_canonical_req)
            .await
            .expect("create canonical");
        assert_eq!(res.status(), StatusCode::CREATED);
        let canonical_id: Uuid = body_json(res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let create_duplicate_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"Alice Duplicate","email":"alice@example.com"}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_duplicate_req)
            .await
            .expect("create duplicate");
        assert_eq!(res.status(), StatusCode::CREATED);
        let duplicate_id: Uuid = body_json(res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let create_referrer_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{referrer_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{duplicate_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_referrer_req)
            .await
            .expect("create referrer");
        assert_eq!(res.status(), StatusCode::CREATED);
        let referrer_id: Uuid = body_json(res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}/{canonical_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"duplicate_id":"{duplicate_id}"}}"#
            )))
            .unwrap();
        let res = app.oneshot(merge_req).await.expect("merge");
        assert_eq!(res.status(), StatusCode::OK);

        let canonical_updates: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM entity_change_event \
          WHERE entity_logicalname = $1 AND record_id = $2 AND operation = 'update'",
        )
        .bind(&target_logicalname)
        .bind(canonical_id)
        .fetch_one(&db)
        .await
        .expect("count canonical change events");
        assert!(
            canonical_updates >= 1,
            "the fill must emit an update change-feed row for the canonical record"
        );

        let duplicate_deletes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM entity_change_event \
          WHERE entity_logicalname = $1 AND record_id = $2 AND operation = 'delete'",
        )
        .bind(&target_logicalname)
        .bind(duplicate_id)
        .fetch_one(&db)
        .await
        .expect("count duplicate change events");
        assert!(
            duplicate_deletes >= 1,
            "retiring the duplicate must emit a delete change-feed row for it"
        );

        let referrer_updates: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM entity_change_event \
          WHERE entity_logicalname = $1 AND record_id = $2 AND operation = 'update'",
        )
        .bind(&referrer_logicalname)
        .bind(referrer_id)
        .fetch_one(&db)
        .await
        .expect("count referrer change events");
        assert!(
            referrer_updates >= 1,
            "the redirected referrer must emit its own update change-feed row"
        );
    })
}

/// C-07 — the merge route now accepts an optional `If-Match` for the
/// canonical record (additive: absent still behaves as before). A stale
/// value is a 409, exactly like PATCH/DELETE's own row_version guard, and
/// the rejected merge must not have touched either record.
#[test]
fn merge_rejects_stale_if_match_on_canonical() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (logicalname, entity_id) = create_entity(&app, &admin_cookie, "merge_ifmatch").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;

        let create_canonical_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Alice"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_canonical_req)
            .await
            .expect("create canonical");
        assert_eq!(res.status(), StatusCode::CREATED);
        let canonical = body_json(res).await;
        let canonical_id = canonical["id"].as_str().unwrap().to_owned();
        let v0 = canonical["row_version"].as_i64().expect("row_version");

        let create_duplicate_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Alice Duplicate"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_duplicate_req)
            .await
            .expect("create duplicate");
        assert_eq!(res.status(), StatusCode::CREATED);
        let duplicate_id = body_json(res).await["id"].as_str().unwrap().to_owned();

        // Bump the canonical's own version so `v0` is genuinely stale.
        let bump_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{canonical_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(r#"{"name":"Alice2"}"#))
            .unwrap();
        let res = app.clone().oneshot(bump_req).await.expect("bump");
        assert_eq!(res.status(), StatusCode::OK);

        let stale_merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{canonical_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(format!(
                r#"{{"duplicate_id":"{duplicate_id}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(stale_merge_req)
            .await
            .expect("stale merge");
        assert_eq!(res.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(res).await["error"], "version_conflict");

        // Nothing changed: the duplicate is still live, and the canonical still
        // carries the bumped value and version — the rejected merge must not
        // have partially applied.
        let get_duplicate_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{duplicate_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_duplicate_req)
            .await
            .expect("get duplicate");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "the duplicate must survive a rejected merge"
        );

        let get_canonical_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{canonical_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_canonical_req).await.expect("get canonical");
        assert_eq!(res.status(), StatusCode::OK);
        let canonical_after = body_json(res).await;
        assert_eq!(canonical_after["data"]["name"], "Alice2");
        assert_eq!(canonical_after["row_version"].as_i64(), Some(v0 + 1));
    })
}

/// C-07 — the union-fill now runs through `update_one`, which enforces
/// lookup-liveness (`lock_lookup_targets`) exactly like an ordinary write.
/// A duplicate whose own lookup field points at a target that's since been
/// soft-deleted must not have that dangling reference silently copied onto
/// the canonical record — the merge is refused instead.
#[test]
fn merge_refuses_fill_when_duplicates_lookup_target_is_soft_deleted() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (lookup_target_logicalname, lookup_target_entity_id) =
            create_entity(&app, &admin_cookie, "merge_dead_lookup_target").await;
        create_field(
            &app,
            &admin_cookie,
            &lookup_target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;

        let (source_logicalname, source_entity_id) =
            create_entity(&app, &admin_cookie, "merge_dead_lookup_source").await;
        create_field(
            &app,
            &admin_cookie,
            &source_entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        create_field(
        &app,
        &admin_cookie,
        &source_entity_id,
        &format!(
            r#"{{"logicalname":"manager_ref","name":"Manager Ref","field_type":"lookup","lookup_entity_ref":"{lookup_target_entity_id}"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        let create_lookup_target_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{lookup_target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"manager"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_lookup_target_req)
            .await
            .expect("create lookup target");
        assert_eq!(res.status(), StatusCode::CREATED);
        let lookup_target_id = body_json(res).await["id"].as_str().unwrap().to_owned();

        let create_canonical_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{source_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Alice"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_canonical_req)
            .await
            .expect("create canonical");
        assert_eq!(res.status(), StatusCode::CREATED);
        let canonical = body_json(res).await;
        let canonical_id = canonical["id"].as_str().unwrap().to_owned();
        let canonical_v0 = canonical["row_version"].as_i64().expect("row_version");

        let create_duplicate_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{source_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"Alice Duplicate","manager_ref":"{lookup_target_id}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_duplicate_req)
            .await
            .expect("create duplicate");
        assert_eq!(res.status(), StatusCode::CREATED);
        let duplicate_id = body_json(res).await["id"].as_str().unwrap().to_owned();

        // Soft-delete the lookup target the duplicate's own field still points at.
        let delete_lookup_target_req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/{lookup_target_logicalname}/{lookup_target_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_lookup_target_req)
            .await
            .expect("delete lookup target");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{source_logicalname}/{canonical_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"duplicate_id":"{duplicate_id}"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(merge_req).await.expect("merge");
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a dangling lookup on the duplicate must refuse the fill, not copy it unchecked"
        );
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"]
                .as_str()
                .unwrap_or("")
                .contains("manager_ref"),
            "validation error must name the offending field: {err:?}"
        );

        // Nothing changed: the duplicate is still live, and the canonical still
        // has no manager_ref and its original row_version — the rejected merge
        // must not have partially applied.
        let get_duplicate_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{source_logicalname}/{duplicate_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_duplicate_req)
            .await
            .expect("get duplicate");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "the duplicate must survive a refused merge"
        );

        let get_canonical_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{source_logicalname}/{canonical_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_canonical_req).await.expect("get canonical");
        assert_eq!(res.status(), StatusCode::OK);
        let canonical_after = body_json(res).await;
        assert_eq!(canonical_after["data"]["manager_ref"], Value::Null);
        assert_eq!(canonical_after["row_version"].as_i64(), Some(canonical_v0));
    })
}

/// D-432 / M13 — `entity_crud::merge::do_merge_core` applies a configured
/// `survivorship_rule` instead of the plain "canonical always
/// wins" default: `most_recent` lets the duplicate's value win when it was
/// modified more recently than the canonical's (here: canonical never
/// updated at all, so its `modified_at` is NULL and always loses), and
/// `manual` refuses to auto-decide a genuine disagreement — the field is
/// reported in `survivorship_conflicts` and the canonical's own pre-merge
/// value is left untouched. A field with no configured rule keeps the
/// pre-D-432 `most_complete` behavior (covered by the plain merge test
/// above), so this test only needs to cover the two rule-driven strategies.
#[test]
fn merge_records_applies_configured_survivorship_rules() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (logicalname, entity_id) = create_entity(&app, &admin_cookie, "merge_survivor").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"phone","name":"Phone","field_type":"text"}"#,
        )
        .await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"tax_id","name":"Tax Id","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;

        let make_rule_req = |field: &str, strategy: &str| {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/data/survivorship-rules")
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"entity":"{logicalname}","field":"{field}","strategy":"{strategy}"}}"#
                )))
                .unwrap()
        };
        let res = app
            .clone()
            .oneshot(make_rule_req("phone", "most_recent"))
            .await
            .expect("create phone survivorship rule");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "{:?}",
            body_json(res).await
        );
        let res = app
            .clone()
            .oneshot(make_rule_req("tax_id", "manual"))
            .await
            .expect("create tax_id survivorship rule");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "{:?}",
            body_json(res).await
        );

        // Canonical: both fields set, never updated after creation (modified_at
        // stays NULL — "never modified" always loses to a real timestamp).
        let create_canonical_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"phone":"555-1111","tax_id":"111-22-3333"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_canonical_req)
            .await
            .expect("create canonical");
        assert_eq!(res.status(), StatusCode::CREATED);
        let canonical_id = body_json(res).await["id"].as_str().unwrap().to_owned();

        let create_duplicate_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"phone":"555-2222","tax_id":"999-88-7777"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_duplicate_req)
            .await
            .expect("create duplicate");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let duplicate_id = created["id"].as_str().unwrap().to_owned();
        let duplicate_row_version = created["row_version"].as_i64().unwrap();

        // Touch the duplicate so it has a real `modified_at`, while the
        // canonical's stays NULL — makes `most_recent` deterministic without
        // needing to race two real timestamps against each other.
        let touch_duplicate_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/{logicalname}/{duplicate_id}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("if-match", format!("\"{duplicate_row_version}\""))
            .body(Body::from(r#"{"phone":"555-2222"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(touch_duplicate_req)
            .await
            .expect("touch duplicate");
        assert_eq!(res.status(), StatusCode::OK);

        let merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{canonical_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"duplicate_id":"{duplicate_id}"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(merge_req).await.expect("merge");
        assert_eq!(res.status(), StatusCode::OK);
        let merged = body_json(res).await;

        assert_eq!(
            merged["data"]["phone"], "555-2222",
            "most_recent must let the more-recently-modified duplicate win: {merged:?}"
        );
        assert_eq!(
            merged["data"]["tax_id"], "111-22-3333",
            "manual must leave the canonical's own value untouched on a genuine \
         disagreement: {merged:?}"
        );
        assert_eq!(
            merged["survivorship_conflicts"],
            serde_json::json!(["tax_id"]),
            "manual must report the unresolved field as a conflict: {merged:?}"
        );
    })
}

/// D-432 / M13 — a small matching-precision fixture: an `exact`-comparator
/// rule on `name` at `threshold = 1.0` must flag the one genuine duplicate
/// pair and must NOT flag the unrelated third record (no false positive) —
/// `EngineJob::DataMatchSweep`'s handler, called directly here the same
/// way `attome_workflow::entity_trigger::dispatch_pending` is called directly
/// in attome-workflow's own integration tests.
#[test]
fn data_match_sweep_finds_the_true_duplicate_and_ignores_the_unrelated_record() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (logicalname, entity_id) = create_entity(&app, &admin_cookie, "match_precision").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;

        let create_rule_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/data/match-rules")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"{logicalname}","name":"exact name match","fields":[{{"field":"name","comparator":"exact","weight":1.0}}],"threshold":1.0}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(create_rule_req)
            .await
            .expect("create match rule");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "{:?}",
            body_json(res).await
        );

        let create = |name: &'static str| {
            let app = app.clone();
            let logicalname = logicalname.clone();
            let admin_cookie = admin_cookie.clone();
            async move {
                let req = Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/{logicalname}"))
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"name":"{name}"}}"#)))
                    .unwrap();
                let res = app.oneshot(req).await.expect("create record");
                assert_eq!(res.status(), StatusCode::CREATED);
                body_json(res).await["id"].as_str().unwrap().to_owned()
            }
        };
        let acme_1 = create("Acme Corp").await;
        let acme_2 = create("Acme Corp").await;
        let widget = create("Widget Inc").await;

        let stats = attome_api::duplicates_match::run_match_sweep(&state)
            .await
            .expect("match sweep");
        assert!(
            stats.candidates_written >= 1,
            "the sweep must find the genuine duplicate pair: {stats:?}"
        );

        let list_req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/data/duplicates?status=open")
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(list_req)
            .await
            .expect("list candidates");
        assert_eq!(res.status(), StatusCode::OK);
        let page = body_json(res).await;
        let items = page["items"].as_array().expect("items array");

        let pair_ids = |item: &Value| -> (String, String) {
            (
                item["record_a"].as_str().unwrap().to_owned(),
                item["record_b"].as_str().unwrap().to_owned(),
            )
        };
        let (lo, hi) = if acme_1 < acme_2 {
            (acme_1.clone(), acme_2.clone())
        } else {
            (acme_2.clone(), acme_1.clone())
        };
        assert!(
            items
                .iter()
                .any(|it| pair_ids(it) == (lo.clone(), hi.clone())),
            "the two \"Acme Corp\" records must be flagged as a candidate pair: {items:?}"
        );
        assert!(
            !items.iter().any(|it| {
                let (a, b) = pair_ids(it);
                a == widget || b == widget
            }),
            "the unrelated \"Widget Inc\" record must never appear in a candidate pair: {items:?}"
        );
    })
}

/// REVIEW-2026-09-02 finding #5 — proves `MatchField::is_blocking_key`
/// narrows the candidate set the way it's designed to: a peer that shares
/// the blocking field's value is found even with a weak non-blocking field,
/// while a peer that does NOT share the blocking value is never even
/// considered, no matter how strongly it would otherwise score on a
/// non-blocking field. This is the deliberate blocking trade-off (see
/// `duplicates_match`'s module doc, "Blocking keys"), not a false negative.
#[test]
fn data_match_sweep_blocking_key_narrows_the_candidate_set() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (logicalname, entity_id) = create_entity(&app, &admin_cookie, "match_blocking").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"code","name":"Code","field_type":"text"}"#,
        )
        .await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"notes","name":"Notes","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;

        let create_rule_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/data/match-rules")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"entity":"{logicalname}","name":"blocked code + fuzzy notes","fields":[
                {{"field":"code","comparator":"exact","weight":0.5,"is_blocking_key":true}},
                {{"field":"notes","comparator":"trigram","weight":0.5,"min_similarity":0.3}}
            ],"threshold":0.4}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_rule_req)
            .await
            .expect("create match rule");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "{:?}",
            body_json(res).await
        );

        let create = |code: &'static str, notes: &'static str| {
            let app = app.clone();
            let logicalname = logicalname.clone();
            let admin_cookie = admin_cookie.clone();
            async move {
                let req = Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/{logicalname}"))
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"code":"{code}","notes":"{notes}"}}"#
                    )))
                    .unwrap();
                let res = app.oneshot(req).await.expect("create record");
                assert_eq!(res.status(), StatusCode::CREATED);
                body_json(res).await["id"].as_str().unwrap().to_owned()
            }
        };
        // Shares the blocking field with `target` (code) but has an unrelated
        // `notes` value — must still be found, because the blocking field alone
        // carries enough weight to clear the threshold.
        let target = create("A100", "the quick brown fox jumps over the lazy dog").await;
        let blocked_match = create("A100", "totally unrelated text with no overlap").await;
        // Does NOT share the blocking field, but has near-identical `notes` to
        // `target` — must never be considered a candidate at all, because
        // blocking excludes it from the scored set before `notes` is even read.
        let similar_but_not_blocked =
            create("Z999", "the quick brown fox jumps over the lazy dog").await;

        let stats = attome_api::duplicates_match::run_match_sweep(&state)
            .await
            .expect("match sweep");
        assert!(
            stats.candidates_written >= 1,
            "the blocked pair must be found: {stats:?}"
        );

        let list_req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/data/duplicates?status=open")
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(list_req)
            .await
            .expect("list candidates");
        assert_eq!(res.status(), StatusCode::OK);
        let page = body_json(res).await;
        let items = page["items"].as_array().expect("items array");

        let pair_ids = |item: &Value| -> (String, String) {
            (
                item["record_a"].as_str().unwrap().to_owned(),
                item["record_b"].as_str().unwrap().to_owned(),
            )
        };
        let (lo, hi) = if target < blocked_match {
            (target.clone(), blocked_match.clone())
        } else {
            (blocked_match.clone(), target.clone())
        };
        assert!(
            items
                .iter()
                .any(|it| pair_ids(it) == (lo.clone(), hi.clone())),
            "the record sharing the blocking field must be flagged as a \
         candidate even though its `notes` field doesn't match: {items:?}"
        );
        assert!(
            !items.iter().any(|it| {
                let (a, b) = pair_ids(it);
                a == similar_but_not_blocked || b == similar_but_not_blocked
            }),
            "a record that does not share the blocking field must never appear \
         as a candidate, even with near-identical `notes`: {items:?}"
        );
    })
}

/// F028: a record cannot be merged into itself.
#[test]
fn merge_records_rejects_merging_a_record_into_itself() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (logicalname, admin_cookie, app) = provision_test_entity(system, "mergeself").await;

        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"solo"}"#))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("create");
        assert_eq!(res.status(), StatusCode::CREATED);
        let id = body_json(res).await["id"].as_str().unwrap().to_owned();

        let merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"duplicate_id":"{id}"}}"#)))
            .unwrap();
        let res = app.oneshot(merge_req).await.expect("self-merge attempt");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
    })
}

/// P-hierarchy-mutation-locking / F028: a merge's dependent-redirect step
/// batch-rewrites every row whose hierarchy field pointed at the retired
/// duplicate to point at the canonical record instead — one `UPDATE`, not a
/// single-record write, so the ordinary per-record `guard_hierarchy_cycles`
/// never runs over it. If the canonical record is already a descendant of
/// one of those rewritten rows, that redirect would silently commit a
/// hierarchy cycle. `guard_hierarchy_redirect_cycle` must catch it and
/// reject the whole merge instead — chain: a (root) <- b (parent a) <- c
/// (parent b). Merging duplicate `a` into canonical `c` would redirect b's
/// parent from a to c, but c's own parent is already b, so that redirect
/// would create a two-node cycle (b -> c -> b). The merge must fail closed,
/// and neither record's parent may change.
#[test]
fn merge_redirect_rejects_hierarchy_cycle() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;

        let (a_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, b_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", Some(&a_id)).await;
        let (c_id, _) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "c", Some(&b_id)).await;

        let merge_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/{c_id}/merge"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"duplicate_id":"{a_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(merge_req)
            .await
            .expect("merge that would create a hierarchy cycle");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");

        // Nothing changed: b is still parented to a with its original
        // row_version — the rejected merge must not have partially applied the
        // redirect before the guard ran.
        let get_b_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{b_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_b_req).await.expect("get b");
        assert_eq!(res.status(), StatusCode::OK);
        let b_row = body_json(res).await;
        assert_eq!(
            b_row["data"]["parent_ref"], a_id,
            "b must still be parented to a"
        );
        assert_eq!(
            b_row["row_version"].as_i64(),
            Some(b_v0),
            "b must be untouched by the rejected merge"
        );
    })
}

/// Same as `seed_admin`, but also returns the seeded user's id — needed by
/// the F024 bulk test below to call `attome_records::bulk::process` directly
/// (simulating the worker) as the same user who enqueued the request.
async fn seed_admin_with_id(system: &TestSystem) -> (String, Uuid) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("round-trip-test-admin-{user_id}"))
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

    (session_cookie(user_id), user_id)
}

async fn seed_bulk_user(system: &TestSystem, prefix: &str) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("{prefix}-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("{prefix}-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway bulk user");

    (user_id, session_cookie(user_id), email)
}

async fn grant_bulk_privilege(
    app: &axum::Router,
    admin_cookie: &str,
    user_email: &str,
    privilege_key: &str,
) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/grants")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"user_email":"{user_email}","privilege_key":"{privilege_key}"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("grant bulk privilege");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "granting {privilege_key} failed: {body:?}"
    );
}

async fn create_bulk_fixture_record(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    body: String,
) -> String {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("create bulk fixture record");
    let status = res.status();
    let created = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "fixture create failed: {created:?}"
    );
    created["id"]
        .as_str()
        .expect("fixture record id")
        .to_owned()
}

/// F024: `POST .../bulk` enqueues and records a `automation_bulk_operation` row;
/// running the worker function directly (simulating what the apalis worker
/// does, without spinning up a real worker in-process) processes every
/// record independently — a record missing a required field fails in
/// isolation, the other two still succeed, and `GET .../bulk/{id}` reports
/// the real succeeded/failed split with the failure's index and reason.
#[test]
fn bulk_create_processes_all_records_and_isolates_per_record_errors() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_cookie, _admin_user_id) = seed_admin_with_id(&system).await;
        let (owner_user_id, owner_cookie, owner_email) =
            seed_bulk_user(&system, "bulk-owner").await;
        let (_, reader_cookie, reader_email) = seed_bulk_user(&system, "bulk-reader").await;
        let app = full_app(system);

        let (logicalname, entity_id) = create_entity(&app, &admin_cookie, "bulk_target").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text","required":true}"#,
        )
        .await;

        sync_registry(&state).await;

        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{logicalname}.create"),
        )
        .await;
        let denied_without_bulk = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/bulk"))
            .header("cookie", &owner_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"operation":"create","records":[{"data":{"name":"denied"}}]}"#,
            ))
            .unwrap();
        let denied = app
            .clone()
            .oneshot(denied_without_bulk)
            .await
            .expect("bulk authz check");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{logicalname}.bulk"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{logicalname}.read"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &reader_email,
            &format!("{logicalname}.read"),
        )
        .await;

        let bulk_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/bulk"))
        .header("cookie", &owner_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"operation":"create","records":[{"data":{"name":"a"}},{"data":{"name":"b"}},{"data":{}}]}"#,
        ))
        .unwrap();
        let res = app.clone().oneshot(bulk_req).await.expect("enqueue bulk");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let enqueued = body_json(res).await;
        assert_eq!(enqueued["status"], "pending");
        assert_eq!(enqueued["total"], 3);
        let bulk_op_id = Uuid::parse_str(enqueued["id"].as_str().unwrap()).unwrap();

        let tracking_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM automation_bulk_operation WHERE id = $1)",
        )
        .bind(bulk_op_id)
        .fetch_one(&db)
        .await
        .expect("bulk tracking row exists after commit");
        assert!(tracking_exists);
        let item_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM automation_bulk_operation_item WHERE bulk_operation_id = $1",
        )
        .bind(bulk_op_id)
        .fetch_one(&db)
        .await
        .expect("bulk item ledger rows exist after commit");
        assert_eq!(item_count, 3);

        // BulkEntityOperation is a batch-queue variant (EngineJob::is_batch,
        // D-165) stored under the "attome_job_batch" job_type, and the queue
        // stores jobs in JobEnvelope<EngineJob>'s envelope shape
        // (`{"version","variant","payload"}`), not the bare externally-tagged
        // `{"BulkEntityOperation": {...}}` shape a single-queue/unversioned job
        // would have used.
        let job_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM apalis.jobs WHERE job_type = $1 AND job @> $2::jsonb)",
        )
        .bind("attome_job_batch")
        .bind(serde_json::json!({
            "variant": "BulkEntityOperation",
            "payload": { "bulk_op_id": bulk_op_id },
        }))
        .fetch_one(&db)
        .await
        .expect("bulk Apalis job exists after commit");
        assert!(job_exists);

        // Simulate the worker: run the same processing function
        // `attome-website`'s job handler calls, directly rather than through a
        // live apalis worker loop.
        attome_records::bulk::process(
            &state,
            bulk_op_id,
            &logicalname,
            "create",
            vec![
                serde_json::json!({"data": {"name": "a"}}),
                serde_json::json!({"data": {"name": "b"}}),
                serde_json::json!({"data": {}}),
            ],
            owner_user_id,
        )
        .await
        .expect("process bulk operation");

        // A retry must skip the two committed successes and only revisit the
        // failed item; this is the durable item-ledger contract.
        attome_records::bulk::process(
            &state,
            bulk_op_id,
            &logicalname,
            "create",
            vec![
                serde_json::json!({"data": {"name": "a"}}),
                serde_json::json!({"data": {"name": "b"}}),
                serde_json::json!({"data": {}}),
            ],
            owner_user_id,
        )
        .await
        .expect("retry bulk operation");

        let owner_status_req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/{logicalname}/bulk/{bulk_op_id}?include_items=true&page_size=3"
            ))
            .header("cookie", &owner_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(owner_status_req)
            .await
            .expect("owner gets bulk status");
        assert_eq!(res.status(), StatusCode::OK);
        let status = body_json(res).await;
        assert_eq!(status["status"], "completed");
        assert_eq!(status["total"], 3);
        assert_eq!(status["succeeded"], 2);
        assert_eq!(status["failed"], 1);
        let errors = status["errors"].as_array().expect("errors array");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["index"], 2);
        let items = status["items"].as_array().expect("item status page");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["status"], "succeeded");
        assert_eq!(items[0]["attempts"], 1);
        assert_eq!(items[2]["status"], "failed");
        assert_eq!(items[2]["attempts"], 2);

        let other_user_status_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/bulk/{bulk_op_id}"))
            .header("cookie", &reader_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(other_user_status_req)
            .await
            .expect("other user gets bulk status");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "a read-granted non-owner must not see another user's bulk operation"
        );

        let random_status_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/bulk/{}", Uuid::now_v7()))
            .header("cookie", &reader_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(random_status_req)
            .await
            .expect("reader gets random bulk status");
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let admin_status_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/bulk/{bulk_op_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(admin_status_req)
            .await
            .expect("admin gets bulk status");
        assert_eq!(res.status(), StatusCode::OK);

        let count: i64 = sqlx::query_scalar(&format!(
            r#"SELECT count(*) FROM "{logicalname}" WHERE is_active = true"#
        ))
        .fetch_one(&db)
        .await
        .expect("count records directly");
        assert_eq!(count, 2, "only the two valid records were actually created");
    })
}

/// F024/F019/D-095: bulk update applies the within-record hierarchy guard and
/// still isolates the rejected record from other records in the batch.
#[test]
fn bulk_update_rejects_self_cycle_and_continues_other_records() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;
        let (a_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;
        let (b_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "b", None).await;
        let (c_id, _) = create_hierarchy_node(&app, &admin_cookie, &logicalname, "c", None).await;

        let bulk_op_id = Uuid::now_v7();
        sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by) \
         VALUES ($1, $2, 'update', 'pending', 2, $3)",
    )
    .bind(bulk_op_id)
    .bind(&logicalname)
    .bind(admin_user_id)
    .execute(&state.base.db)
    .await
    .expect("insert bulk tracking row");

        attome_records::bulk::process(
        &state,
        bulk_op_id,
        &logicalname,
        "update",
        vec![
            serde_json::json!({"id": a_id, "expected_row_version": 0, "data": {"parent_ref": a_id}}),
            serde_json::json!({"id": c_id, "expected_row_version": 0, "data": {"parent_ref": b_id}}),
        ],
        admin_user_id,
    )
    .await
    .expect("process bulk hierarchy updates");

        let status: (i32, i32, Value) = sqlx::query_as(
            "SELECT succeeded, failed, errors FROM automation_bulk_operation WHERE id = $1",
        )
        .bind(bulk_op_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read bulk status");
        assert_eq!(status.0, 1);
        assert_eq!(status.1, 1);
        assert_eq!(status.2.as_array().map(Vec::len), Some(1));
        assert_eq!(status.2[0]["index"], 0);

        let row: Value = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t) FROM \"{logicalname}\" t WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&c_id).unwrap())
        .fetch_one(&state.base.db)
        .await
        .expect("read successful bulk update");
        assert_eq!(row["parent_ref"].as_str(), Some(b_id.as_str()));
    })
}

/// Bulk update's per-record `row_version` guard (fix for the gap flagged in
/// review: the original bulk update SQL incremented `row_version` but never
/// checked it, so a bulk job could silently last-write-wins over a
/// concurrent interactive edit). A record missing `row_version` is a 422,
/// isolated from the rest of the batch the same way a self-cycle is; a
/// record with a stale `row_version` is a 409 that leaves the row untouched;
/// a record with the correct version updates and bumps `row_version` exactly
/// like PATCH/upsert do.
#[test]
fn bulk_update_enforces_row_version_per_record() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let (logicalname, entity_id) =
            create_entity(&app, &admin_cookie, "bulk_version_target").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;

        let missing_version_id =
            create_bulk_fixture_record(&app, &admin_cookie, &logicalname, r#"{"name":"a"}"#.into())
                .await;
        let stale_version_id =
            create_bulk_fixture_record(&app, &admin_cookie, &logicalname, r#"{"name":"b"}"#.into())
                .await;
        let correct_version_id =
            create_bulk_fixture_record(&app, &admin_cookie, &logicalname, r#"{"name":"c"}"#.into())
                .await;

        let invalid_enqueue = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/bulk"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"operation":"update","records":[{{"id":"{missing_version_id}","data":{{"name":"rejected"}}}}]}}"#
        )))
        .unwrap();
        let invalid_response = app
            .clone()
            .oneshot(invalid_enqueue)
            .await
            .expect("bulk envelope validation");
        assert_eq!(invalid_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let bulk_op_id = Uuid::now_v7();
        sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by) \
         VALUES ($1, $2, 'update', 'pending', 3, $3)",
    )
    .bind(bulk_op_id)
    .bind(&logicalname)
    .bind(admin_user_id)
    .execute(&db)
    .await
    .expect("insert bulk tracking row");

        attome_records::bulk::process(
        &state,
        bulk_op_id,
        &logicalname,
        "update",
        vec![
            // No expected_row_version at all — must not silently last-write-wins.
            serde_json::json!({"id": missing_version_id, "data": {"name": "a-edited"}}),
            // Fresh rows start at row_version 0, so 5 is stale.
            serde_json::json!({"id": stale_version_id, "expected_row_version": 5, "data": {"name": "b-edited"}}),
            serde_json::json!({"id": correct_version_id, "expected_row_version": 0, "data": {"name": "c-edited"}}),
        ],
        admin_user_id,
    )
    .await
    .expect("process bulk version-guarded updates");

        let status: (i32, i32, Value) = sqlx::query_as(
            "SELECT succeeded, failed, errors FROM automation_bulk_operation WHERE id = $1",
        )
        .bind(bulk_op_id)
        .fetch_one(&db)
        .await
        .expect("read bulk status");
        assert_eq!(status.0, 1, "only the correctly-versioned record succeeds");
        assert_eq!(status.1, 2);
        let errors = status.2.as_array().expect("errors array");
        assert_eq!(errors.len(), 2);
        let missing_err = errors
            .iter()
            .find(|e| e["index"] == 0)
            .expect("missing-version error");
        assert!(
            missing_err["error"]
                .as_str()
                .unwrap_or("")
                .contains("row_version")
        );
        let stale_err = errors
            .iter()
            .find(|e| e["index"] == 1)
            .expect("stale-version error");
        assert!(
            stale_err["error"]
                .as_str()
                .unwrap_or("")
                .contains("version conflict")
        );

        let unchanged: (String, i64) = sqlx::query_as(&format!(
            "SELECT name, row_version FROM \"{logicalname}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&missing_version_id).unwrap())
        .fetch_one(&db)
        .await
        .expect("read missing-version record");
        assert_eq!(
            unchanged.0, "a",
            "record with no row_version must not change"
        );
        assert_eq!(unchanged.1, 0);

        let stale: (String, i64) = sqlx::query_as(&format!(
            "SELECT name, row_version FROM \"{logicalname}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&stale_version_id).unwrap())
        .fetch_one(&db)
        .await
        .expect("read stale-version record");
        assert_eq!(
            stale.0, "b",
            "record with a stale row_version must not change"
        );
        assert_eq!(stale.1, 0);

        let updated: (String, i64) = sqlx::query_as(&format!(
            "SELECT name, row_version FROM \"{logicalname}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&correct_version_id).unwrap())
        .fetch_one(&db)
        .await
        .expect("read correctly-versioned record");
        assert_eq!(updated.0, "c-edited");
        assert_eq!(
            updated.1, 1,
            "a successful bulk update increments row_version"
        );
    })
}

/// F024/D-090: tracking and enqueue writes share a transaction. A rollback
/// must leave neither the status row nor the durable Apalis job behind.
#[test]
fn bulk_enqueue_transaction_rolls_back_both_rows_together() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let bulk_op_id = Uuid::now_v7();

        let mut tx = attome_db::tx::begin(&db)
            .await
            .expect("begin bulk transaction");
        sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by) \
         VALUES ($1, $2, $3, 'pending', $4, $5)",
    )
    .bind(bulk_op_id)
    .bind("bulk_transaction_test")
    .bind("create")
    .bind(1_i32)
    .bind(Uuid::now_v7())
    .execute(&mut *tx)
    .await
    .expect("insert bulk tracking row");

        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::BulkEntityOperation(
                attome_core::jobs::BulkEntityOperationPayload {
                    bulk_op_id,
                    entity_logicalname: "bulk_transaction_test".to_owned(),
                    operation: "create".to_owned(),
                    records: vec![serde_json::json!({"data": {"name": "rollback"}})],
                    user_id: Uuid::now_v7(),
                },
            ),
        )
        .await
        .expect("enqueue bulk job in transaction");
        drop(tx);

        let tracking_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM automation_bulk_operation WHERE id = $1)",
        )
        .bind(bulk_op_id)
        .fetch_one(&db)
        .await
        .expect("check rolled-back bulk tracking row");
        assert!(!tracking_exists);

        let job_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM apalis.jobs WHERE job_type = $1 AND job @> $2::jsonb)",
        )
        .bind("attome_job")
        .bind(serde_json::json!({
            "BulkEntityOperation": { "bulk_op_id": bulk_op_id },
        }))
        .fetch_one(&db)
        .await
        .expect("check rolled-back bulk job");
        assert!(!job_exists);
    })
}

/// F024/D-096: bulk delete uses the same on-target-delete policy as the
/// interactive endpoint for each record. A restrict failure is isolated to
/// its record, cascade-deactivate is atomic with its parent, and an orphan
/// lookup remains active exactly as it does on the single-record path.
#[test]
fn bulk_delete_enforces_delete_policy_per_record_and_continues() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (admin_cookie, _) = seed_admin_with_id(&system).await;
        let (owner_user_id, owner_cookie, owner_email) =
            seed_bulk_user(&system, "bulk-delete-owner").await;
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "bulk_policy_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;

        let (restrictor_logicalname, restrictor_entity_id) =
            create_entity(&app, &admin_cookie, "bulk_policy_restrictor").await;
        create_field(
        &app,
        &admin_cookie,
        &restrictor_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"restrict"}}"#
        ),
    )
    .await;

        let (cascader_logicalname, cascader_entity_id) =
            create_entity(&app, &admin_cookie, "bulk_policy_cascader").await;
        create_field(
        &app,
        &admin_cookie,
        &cascader_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"cascade-deactivate"}}"#
        ),
    )
    .await;

        let (orphan_logicalname, orphan_entity_id) =
            create_entity(&app, &admin_cookie, "bulk_policy_orphan").await;
        create_field(
        &app,
        &admin_cookie,
        &orphan_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"orphan"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{target_logicalname}.delete"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{target_logicalname}.bulk"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{target_logicalname}.read"),
        )
        .await;
        // Cascade-deactivate mutates the dependent row too, so the caller must
        // hold delete permission on that dependent entity. Records with no
        // matching dependent rows must not require this unrelated permission.
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &owner_email,
            &format!("{cascader_logicalname}.delete"),
        )
        .await;

        let blocked_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &target_logicalname,
            r#"{"title":"blocked"}"#.into(),
        )
        .await;
        let safe_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &target_logicalname,
            r#"{"title":"safe"}"#.into(),
        )
        .await;
        let cascade_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &target_logicalname,
            r#"{"title":"cascade"}"#.into(),
        )
        .await;
        let orphan_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &target_logicalname,
            r#"{"title":"orphan"}"#.into(),
        )
        .await;

        let cascader_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &cascader_logicalname,
            format!(r#"{{"target_ref":"{cascade_id}"}}"#),
        )
        .await;
        let orphan_referrer_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &orphan_logicalname,
            format!(r#"{{"target_ref":"{orphan_id}"}}"#),
        )
        .await;
        let _restrictor_id = create_bulk_fixture_record(
            &app,
            &admin_cookie,
            &restrictor_logicalname,
            format!(r#"{{"target_ref":"{blocked_id}"}}"#),
        )
        .await;

        let bulk_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{target_logicalname}/bulk"))
        .header("cookie", &owner_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"operation":"delete","records":[{{"id":"{blocked_id}","expected_row_version":0,"data":{{}}}},{{"id":"{safe_id}","expected_row_version":0,"data":{{}}}},{{"id":"{cascade_id}","expected_row_version":0,"data":{{}}}},{{"id":"{orphan_id}","expected_row_version":0,"data":{{}}}}]}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(bulk_req)
            .await
            .expect("enqueue bulk delete");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let enqueued = body_json(res).await;
        let bulk_op_id = Uuid::parse_str(enqueued["id"].as_str().unwrap()).unwrap();

        attome_records::bulk::process(
            &state,
            bulk_op_id,
            &target_logicalname,
            "delete",
            vec![
                serde_json::json!({"id": blocked_id, "expected_row_version": 0, "data": {}}),
                serde_json::json!({"id": safe_id, "expected_row_version": 0, "data": {}}),
                serde_json::json!({"id": cascade_id, "expected_row_version": 0, "data": {}}),
                serde_json::json!({"id": orphan_id, "expected_row_version": 0, "data": {}}),
            ],
            owner_user_id,
        )
        .await
        .expect("process bulk delete");

        let status_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{target_logicalname}/bulk/{bulk_op_id}"))
            .header("cookie", &owner_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(status_req)
            .await
            .expect("get bulk delete status");
        assert_eq!(res.status(), StatusCode::OK);
        let status = body_json(res).await;
        assert_eq!(status["status"], "completed");
        assert_eq!(status["total"], 4);
        assert_eq!(status["succeeded"], 3);
        assert_eq!(status["failed"], 1);
        let errors = status["errors"].as_array().expect("bulk errors array");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["index"], 0);
        assert!(errors[0]["error"].as_str().unwrap().contains("restrict"));

        for (logicalname, id, expected_status) in [
            (&target_logicalname, &blocked_id, StatusCode::OK),
            (&target_logicalname, &safe_id, StatusCode::NOT_FOUND),
            (&target_logicalname, &cascade_id, StatusCode::NOT_FOUND),
            (&target_logicalname, &orphan_id, StatusCode::NOT_FOUND),
            (&cascader_logicalname, &cascader_id, StatusCode::NOT_FOUND),
            (&orphan_logicalname, &orphan_referrer_id, StatusCode::OK),
        ] {
            let req = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/{logicalname}/{id}"))
                .header("cookie", &admin_cookie)
                .body(Body::empty())
                .unwrap();
            let res = app
                .clone()
                .oneshot(req)
                .await
                .expect("verify bulk delete result");
            assert_eq!(
                res.status(),
                expected_status,
                "unexpected status for {logicalname}/{id}"
            );
        }
    })
}

/// D-096 performance guard: at the current F024 cap, the policy checks must
/// remain within the documented 60-second statement-timeout budget. This is
/// intentionally ignored because it requires a throwaway database and is a
/// release-readiness measurement rather than a per-commit test.
#[test]
#[ignore = "run manually against a throwaway database for the F024 performance budget"]
fn bulk_delete_policy_stays_within_budget_at_max_batch() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "bulk_perf_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;
        let (_, restrictor_entity_id) =
            create_entity(&app, &admin_cookie, "bulk_perf_restrictor").await;
        create_field(
        &app,
        &admin_cookie,
        &restrictor_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","on_target_delete":"restrict"}}"#
        ),
    )
    .await;
        sync_registry(&state).await;

        // 5000 is the production MAX_BULK_RECORDS cap.
        let records = (0..5000)
            .map(|i| serde_json::json!({"data": {"title": format!("perf-{i}")}}))
            .collect::<Vec<_>>();
        let create_bulk_op_id = Uuid::now_v7();
        sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by)
         VALUES ($1, $2, 'create', 'pending', 5000, $3)",
    )
    .bind(create_bulk_op_id)
    .bind(&target_logicalname)
    .bind(admin_user_id)
    .execute(&state.base.db)
    .await
    .expect("insert performance create operation");
        attome_records::bulk::process(
            &state,
            create_bulk_op_id,
            &target_logicalname,
            "create",
            records,
            admin_user_id,
        )
        .await
        .expect("seed performance records");

        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            r#"SELECT id FROM "{target_logicalname}" WHERE is_active = TRUE ORDER BY id LIMIT 5000"#
        ))
        .fetch_all(&state.base.db)
        .await
        .expect("read performance record ids");
        assert_eq!(ids.len(), 5000);
        let delete_bulk_op_id = Uuid::now_v7();
        sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by)
         VALUES ($1, $2, 'delete', 'pending', 5000, $3)",
    )
    .bind(delete_bulk_op_id)
    .bind(&target_logicalname)
    .bind(admin_user_id)
    .execute(&state.base.db)
    .await
    .expect("insert performance delete operation");
        let delete_records = ids
            .into_iter()
            .map(|id| serde_json::json!({"id": id, "expected_row_version": 0, "data": {}}))
            .collect();

        let started = std::time::Instant::now();
        attome_records::bulk::process(
            &state,
            delete_bulk_op_id,
            &target_logicalname,
            "delete",
            delete_records,
            admin_user_id,
        )
        .await
        .expect("run performance bulk delete");

        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "max-size bulk delete exceeded the 60-second budget: {:?}",
            started.elapsed()
        );
    })
}

/// D-100: staged import's whole reason to exist is legacy data with a
/// dangling lookup reference. The dry run at `POST .../staged-import` must
/// fail that record (lookup liveness is still checked pre-approval — this is
/// a review step, not a bypass), while an admin's `.../approve` — enqueued,
/// not run inline — succeeds via `MutationMode::ApprovedStagedImport`, which
/// skips lookup-liveness but never hierarchy/row-version/delete-policy
/// guards. `process_staged_import` is invoked directly here, the same way
/// the bulk tests simulate the apalis worker without spinning one up.
#[test]
fn staged_import_approval_persists_a_dangling_lookup_reference() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let (referrer_logicalname, referrer_entity_id) =
            create_entity(&app, &admin_cookie, "staged_referrer").await;
        let (_target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "staged_target").await;
        create_field(
        &app,
        &admin_cookie,
        &referrer_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        ),
    )
    .await;
        sync_registry(&state).await;

        // A UUID that never existed in the target entity's table at all.
        let dangling_id = Uuid::now_v7();

        let submit_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{referrer_logicalname}/staged-import"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"operation":"create","records":[{{"data":{{"target_ref":"{dangling_id}"}}}}]}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(submit_req)
            .await
            .expect("submit staged import");
        let submit_status = res.status();
        let submitted = body_json(res).await;
        assert_eq!(
            submit_status,
            StatusCode::ACCEPTED,
            "submit failed: {submitted:?}"
        );
        assert_eq!(submitted["status"], "pending_review");
        assert_eq!(submitted["total"], 1);
        assert_eq!(
            submitted["passed"], 0,
            "the dry run must fail the dangling reference, not silently accept it"
        );
        assert_eq!(submitted["failed"], 1);
        let import_id = Uuid::parse_str(submitted["id"].as_str().unwrap()).unwrap();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{referrer_logicalname}/staged-import/{import_id}/approve"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(approve_req)
            .await
            .expect("approve staged import");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let approving = body_json(res).await;
        assert_eq!(approving["status"], "approving");

        let item_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM automation_staged_import_item WHERE staged_import_id = $1",
        )
        .bind(import_id)
        .fetch_one(&db)
        .await
        .expect("staged import item ledger rows exist after commit");
        assert_eq!(item_count, 1);

        // Simulate the worker (same pattern as the bulk tests: call the
        // processing function directly rather than spin up a live apalis loop).
        attome_records::bulk::process_staged_import(
            &state,
            import_id,
            &referrer_logicalname,
            "create",
            vec![serde_json::json!({"data": {"target_ref": dangling_id}})],
            admin_user_id,
        )
        .await
        .expect("process staged import approval");

        let (final_status, report): (String, Value) = sqlx::query_as(
            "SELECT status, validation_report FROM automation_staged_import WHERE id = $1",
        )
        .bind(import_id)
        .fetch_one(&db)
        .await
        .expect("read final staged import status");
        assert_eq!(
            final_status, "approved",
            "ApprovedStagedImport must skip lookup-liveness and let this through: {report:?}"
        );

        let row: Value = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t) FROM \"{referrer_logicalname}\" t WHERE target_ref = $1"
        ))
        .bind(dangling_id)
        .fetch_one(&db)
        .await
        .expect("read the record created with the dangling reference");
        assert_eq!(
            row["target_ref"].as_str(),
            Some(dangling_id.to_string()).as_deref()
        );
    })
}

/// D-100: hierarchy-cycle protection is never skippable, even for an
/// approved staged import — only lookup-liveness is. A self-parent record
/// submitted for staged import must still fail at approval time.
#[test]
fn staged_import_approval_still_rejects_a_hierarchy_cycle() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let logicalname = setup_hierarchy_entity(&app, &admin_cookie).await;
        sync_registry(&state).await;
        let (a_id, a_v0) =
            create_hierarchy_node(&app, &admin_cookie, &logicalname, "a", None).await;

        let submit_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/staged-import"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"operation":"update","records":[{{"id":"{a_id}","expected_row_version":{a_v0},"data":{{"parent_ref":"{a_id}"}}}}]}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(submit_req)
            .await
            .expect("submit staged import");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let submitted = body_json(res).await;
        let import_id = Uuid::parse_str(submitted["id"].as_str().unwrap()).unwrap();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{logicalname}/staged-import/{import_id}/approve"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        app.clone()
            .oneshot(approve_req)
            .await
            .expect("approve staged import");

        attome_records::bulk::process_staged_import(
        &state,
        import_id,
        &logicalname,
        "update",
        vec![serde_json::json!({"id": a_id, "expected_row_version": a_v0, "data": {"parent_ref": a_id}})],
        admin_user_id,
    )
    .await
    .expect("process staged import approval");

        let (final_status, report): (String, Value) = sqlx::query_as(
            "SELECT status, validation_report FROM automation_staged_import WHERE id = $1",
        )
        .bind(import_id)
        .fetch_one(&db)
        .await
        .expect("read final staged import status");
        assert_eq!(final_status, "rejected");
        let items = report.as_array().expect("report array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["status"], "rejected");
        assert!(
            items[0]["error"]
                .as_str()
                .unwrap_or("")
                .contains("own parent"),
            "hierarchy guard must still fire on an approved import: {items:?}"
        );

        let a: (bool, i64) = sqlx::query_as(&format!(
            "SELECT parent_ref IS NULL, row_version FROM \"{logicalname}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&a_id).unwrap())
        .fetch_one(&db)
        .await
        .expect("read node a");
        assert!(a.0, "the rejected cycle must not have been applied");
        assert_eq!(a.1, a_v0, "no partial update from the rejected item");
    })
}

/// D-100: only `system.admin` can approve a staged import — a user with only
/// the entity's own `bulk` grant (enough to submit one) must be rejected.
#[test]
fn staged_import_approval_requires_admin() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (admin_cookie, _admin_user_id) = seed_admin_with_id(&system).await;
        let (_, submitter_cookie, submitter_email) =
            seed_bulk_user(&system, "staged-submitter").await;
        let app = full_app(system);

        let (logicalname, entity_id) =
            create_entity(&app, &admin_cookie, "staged_admin_gate").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &submitter_email,
            &format!("{logicalname}.bulk"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &submitter_email,
            &format!("{logicalname}.create"),
        )
        .await;

        let submit_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}/staged-import"))
            .header("cookie", &submitter_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"operation":"create","records":[{"data":{"name":"a"}}]}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(submit_req)
            .await
            .expect("non-admin submits staged import");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let submitted = body_json(res).await;
        let import_id = Uuid::parse_str(submitted["id"].as_str().unwrap()).unwrap();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{logicalname}/staged-import/{import_id}/approve"
            ))
            .header("cookie", &submitter_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(approve_req)
            .await
            .expect("non-admin attempts approval");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let status: String =
            sqlx::query_scalar("SELECT status FROM automation_staged_import WHERE id = $1")
                .bind(import_id)
                .fetch_one(&state.base.db)
                .await
                .expect("read staged import status");
        assert_eq!(
            status, "pending_review",
            "a rejected approval attempt must not transition the row"
        );
    })
}

/// D-100/D-099: a redelivered `ApplyStagedImport` job resumes rather than
/// double-applies — same item-ledger contract `process()` already gets for
/// regular bulk. Simulates one item already committed as `succeeded` by a
/// prior (crashed) attempt, then runs `process_staged_import` again with a
/// record shape that would fail if it were re-applied (a duplicate-name
/// unique-ish assertion isn't available generically, so instead this proves
/// resumption via attempts/record_id staying untouched on the skipped item).
#[test]
fn staged_import_worker_resumes_without_reapplying_succeeded_items() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_cookie, admin_user_id) = seed_admin_with_id(&system).await;
        let app = full_app(system);

        let (logicalname, entity_id) = create_entity(&app, &admin_cookie, "staged_resume").await;
        create_field(
            &app,
            &admin_cookie,
            &entity_id,
            r#"{"logicalname":"name","name":"Name","field_type":"text"}"#,
        )
        .await;
        sync_registry(&state).await;

        let submit_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/staged-import"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"operation":"create","records":[{"data":{"name":"first"}},{"data":{"name":"second"}}]}"#,
        ))
        .unwrap();
        let res = app
            .clone()
            .oneshot(submit_req)
            .await
            .expect("submit staged import");
        let submitted = body_json(res).await;
        let import_id = Uuid::parse_str(submitted["id"].as_str().unwrap()).unwrap();

        let approve_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{logicalname}/staged-import/{import_id}/approve"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        app.oneshot(approve_req)
            .await
            .expect("approve staged import");

        let records = vec![
            serde_json::json!({"data": {"name": "first"}}),
            serde_json::json!({"data": {"name": "second"}}),
        ];

        attome_records::bulk::process_staged_import(
            &state,
            import_id,
            &logicalname,
            "create",
            records.clone(),
            admin_user_id,
        )
        .await
        .expect("first process_staged_import run");

        let first_run: Vec<(i32, String, i32, Option<Uuid>)> = sqlx::query_as(
            "SELECT item_index, status, attempts, record_id FROM automation_staged_import_item
         WHERE staged_import_id = $1 ORDER BY item_index",
        )
        .bind(import_id)
        .fetch_all(&db)
        .await
        .expect("read item ledger after first run");
        assert_eq!(first_run.len(), 2);
        assert!(
            first_run
                .iter()
                .all(|(_, status, _, _)| status == "succeeded")
        );
        assert!(first_run.iter().all(|(_, _, attempts, _)| *attempts == 1));

        // Redelivery / retry: process again with the same records.
        attome_records::bulk::process_staged_import(
            &state,
            import_id,
            &logicalname,
            "create",
            records,
            admin_user_id,
        )
        .await
        .expect("second process_staged_import run (simulated redelivery)");

        let second_run: Vec<(i32, String, i32, Option<Uuid>)> = sqlx::query_as(
            "SELECT item_index, status, attempts, record_id FROM automation_staged_import_item
         WHERE staged_import_id = $1 ORDER BY item_index",
        )
        .bind(import_id)
        .fetch_all(&db)
        .await
        .expect("read item ledger after second run");
        assert_eq!(
            first_run, second_run,
            "a resumed run must not touch already-succeeded items \
         (unchanged attempts/record_id proves it was skipped, not reprocessed)"
        );

        let record_count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM \"{logicalname}\" WHERE is_active = TRUE"
        ))
        .fetch_one(&db)
        .await
        .expect("count live records");
        assert_eq!(
            record_count, 2,
            "resumption must not create duplicate records for already-succeeded items"
        );
    })
}

/// A record must never be creatable in a state that no later read can see.
///
/// `is_active` is the platform's soft-delete flag, and it is a *registered
/// attribute* on `user_account` (`attome_security::seed::
/// register_readonly_entities`), so the generic create path used to bind
/// whatever the client sent for it. A JSON `null` binds as SQL NULL, NULL
/// overrides the column's `DEFAULT TRUE`, and every generic read filters
/// `is_active = true` — so the record came back 404 from the GET that
/// immediately followed its own 201, and could not be updated, deleted, or
/// restored either. Any metadata-driven form submits exactly that shape: a
/// form control the user never touched posts `null`.
///
/// `entity_mutation::LIFECYCLE_INSERT_COLS` now drops the column from every
/// insert, whatever the body says — asserted below for all three values a
/// client can send.
#[test]
fn create_never_honours_a_client_supplied_is_active() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        for supplied in ["null", "false", "true"] {
            let suffix = Uuid::now_v7().simple().to_string();
            let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/user_account")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"user_name":"lifecycle_{suffix}","email":"lifecycle_{suffix}@example.invalid","is_active":{supplied}}}"#
            )))
            .unwrap();
            let res = app.clone().oneshot(create_req).await.expect("create user");
            assert_eq!(
                res.status(),
                StatusCode::CREATED,
                "create with is_active:{supplied} must succeed"
            );
            let created = body_json(res).await;
            assert_eq!(
                created["data"]["is_active"],
                Value::Bool(true),
                "a new record is live regardless of the is_active the client sent ({supplied})"
            );
            let record_id = created["id"].as_str().expect("record id").to_owned();

            let get_req = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/user_account/{record_id}"))
                .header("cookie", &admin_cookie)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(get_req).await.expect("get user");
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "the record created with is_active:{supplied} must be readable straight after its 201"
            );
        }
    })
}

/// `restore` is the repair path for a row whose `is_active` is NULL, not just
/// for one explicitly soft-deleted.
///
/// Rows in that state exist in any deployment that ran before
/// `LIFECYCLE_INSERT_COLS` (see the test above). They are invisible to
/// GET/PATCH/DELETE — all of which filter `is_active = true` — so when restore
/// matched only `is_active = false` there was no sanctioned way to recover
/// them at all, and no unsanctioned one either short of hand-written SQL,
/// which the API-first rule forbids on a running deployment.
///
/// The NULL row is written directly here because the API no longer has any
/// way to produce one — a throwaway test database is the exemption that
/// covers it. It uses `organization`, a bootstrap table whose
/// `is_active` is still nullable, because `user_account.is_active` is
/// NOT NULL since migration 0460 (attome-auth hardening 2.4).
#[test]
fn restore_repairs_a_record_whose_is_active_is_null() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let record_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO organization (id, name, created_at, is_active) \
         VALUES ($1, $2, now(), NULL)",
        )
        .bind(record_id)
        .bind(format!("legacy_null_{}", record_id.simple()))
        .execute(&db)
        .await
        .expect("insert a legacy NULL-is_active row");

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/organization/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get before");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "a NULL-flagged row is invisible to the generic read — the state this test repairs"
        );

        let restore_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organization/{record_id}/restore"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(restore_req).await.expect("restore");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "restore must accept a NULL row"
        );
        let restored = body_json(res).await;
        assert_eq!(restored["data"]["is_active"], Value::Bool(true));

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/organization/{record_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get after");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "the repaired record must be readable"
        );

        // An already-live record is still a 409, not a silent success.
        let restore_again_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organization/{record_id}/restore"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(restore_again_req)
            .await
            .expect("restore again");
        assert_eq!(res.status(), StatusCode::CONFLICT);
    })
}

/// C-08 (M01-core §7): `restore_record`/`entity_mutation::restore_one` used
/// to skip the same post-commit invalidation hooks `create_record`/
/// `update_record`/`delete_record` already call —
/// `invalidate_privilege_grant_target` (and `invalidate_audit_user_if_systemuser`,
/// not exercised by this table) — so restoring a soft-deleted
/// `user_account_mm_privilege` row re-granted a privilege that no
/// node would see reflected until the resolver's epoch/TTL converged on its
/// own, the opposite of what `entity_crud/access.rs`'s doc comment on
/// `invalidate_privilege_grant_target` documents for every other write on
/// this table.
///
/// Proves the fix by walking grant -> resolve (warms the cache) -> revoke
/// (soft-delete) -> resolve (cache now says "not admin") -> restore ->
/// `resolve_strict` on the SAME node immediately after, with no delay: it
/// must already reflect the restored grant, not the stale pre-restore
/// value.
#[test]
fn restore_of_privilege_grant_is_visible_to_resolve_strict_immediately() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);

        // A throwaway grantee with no privileges of its own yet.
        let grantee_id = Uuid::now_v7();
        sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
            .bind(grantee_id)
            .bind(format!("c08-restore-grantee-{grantee_id}"))
            .execute(&db)
            .await
            .expect("insert throwaway grantee");

        let privilege_id: Uuid =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
                .fetch_one(&db)
                .await
                .expect(
                    "system.admin privilege must already be seeded by attome_security::seed::seed",
                );

        // Grant through the generic entity API — the same path a real admin UI
        // subgrid write (User form's Privileges tab) takes, and the one
        // `create_record` already invalidates correctly today (only `restore`
        // had the gap).
        let create_grant_req = Request::builder()
            .method("POST")
            .uri("/api/v1/user_account_mm_privilege")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"user_ref":"{grantee_id}","privilege_ref":"{privilege_id}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_grant_req)
            .await
            .expect("create grant");
        let status = res.status();
        let grant = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create grant failed: {grant:?}"
        );
        let grant_id = grant["id"].as_str().expect("grant id").to_owned();

        let resolved = state
            .base
            .security
            .resolve_strict(grantee_id)
            .await
            .expect("resolve_strict after grant");
        assert!(
            resolved.is_admin,
            "grant must be visible right after create"
        );

        // Revoke (soft-delete) — `delete_record`'s invalidation hook (already
        // correct today) drops the privilege immediately too.
        let delete_grant_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/user_account_mm_privilege/{grant_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_grant_req)
            .await
            .expect("delete grant");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let resolved = state
            .base
            .security
            .resolve_strict(grantee_id)
            .await
            .expect("resolve_strict after revoke");
        assert!(
            !resolved.is_admin,
            "revoke must drop the privilege immediately"
        );

        // C-08: restore must be exactly as immediate — this is the path that
        // used to skip the invalidation hooks entirely.
        let restore_grant_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/user_account_mm_privilege/{grant_id}/restore"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(restore_grant_req)
            .await
            .expect("restore grant");
        assert_eq!(res.status(), StatusCode::OK);

        let resolved = state
            .base
            .security
            .resolve_strict(grantee_id)
            .await
            .expect("resolve_strict after restore");
        assert!(
            resolved.is_admin,
            "C-08: restore must invalidate the grantee's cached SecurityContext \
         immediately, not leave it stale until the epoch/TTL converges on its own"
        );
    })
}

/// C-08 (M01-core §7): `restore_one` now runs the same `lock_lookup_targets`
/// gate every other write (`create_one`/`update_one`) already runs, against
/// the row's own current field values. Before this, restore only checked
/// `is_active`/`row_version`, so a record whose lookup target was
/// soft-deleted while THIS record was itself already soft-deleted could be
/// restored back into existence pointing at nothing live.
#[test]
fn restore_refuses_a_record_whose_lookup_target_is_no_longer_live() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);

        let (target_logicalname, target_entity_id) =
            create_entity(&app, &admin_cookie, "c08_restore_target").await;
        create_field(
            &app,
            &admin_cookie,
            &target_entity_id,
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        )
        .await;

        let (referrer_logicalname, referrer_entity_id) =
            create_entity(&app, &admin_cookie, "c08_restore_referrer").await;
        create_field(
        &app,
        &admin_cookie,
        &referrer_entity_id,
        &format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        ),
    )
    .await;

        sync_registry(&state).await;

        let create_target_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{target_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"t1"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_target_req)
            .await
            .expect("create target record");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target = body_json(res).await;
        let target_id = target["id"].as_str().expect("target id").to_owned();

        let create_referrer_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{referrer_logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"target_ref":"{target_id}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_referrer_req)
            .await
            .expect("create referrer record");
        assert_eq!(res.status(), StatusCode::CREATED);
        let referrer = body_json(res).await;
        let referrer_id = referrer["id"].as_str().expect("referrer id").to_owned();

        // Soft-delete the referrer first (default on_target_delete = "orphan",
        // so this alone never touches the target).
        let delete_referrer_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{referrer_logicalname}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_referrer_req)
            .await
            .expect("delete referrer");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Now soft-delete the target too — nothing live still points at it (the
        // referrer above is already inactive), so this is unblocked regardless
        // of on_target_delete policy.
        let delete_target_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{target_logicalname}/{target_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_target_req)
            .await
            .expect("delete target");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // C-08: restoring the referrer must be refused — its lookup target is no
        // longer live.
        let restore_referrer_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{referrer_logicalname}/{referrer_id}/restore"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(restore_referrer_req)
            .await
            .expect("restore referrer");
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "restore must refuse a record whose lookup target is no longer live"
        );
        let err = body_json(res).await;
        assert_eq!(err["error"], "validation_error");
        assert!(
            err["message"].as_str().unwrap_or("").contains("target_ref"),
            "the 422 must name the offending field: {err:?}"
        );

        // The referrer must still be soft-deleted — the refused restore must not
        // have partially applied.
        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_logicalname}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer after refused restore");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "a refused restore must not resurrect the record"
        );
    })
}
