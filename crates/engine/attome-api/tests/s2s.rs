//! Integration tests for the S2S HMAC verification matrix (P1.8 money-path
//! #1): valid / expired timestamp / replayed nonce (409) / tampered body /
//! revoked key. Exercises the full Tower pipeline
//! (`attome_s2s::middleware::s2s_authn` → `authn` → `authz`) mounted by
//! `EngineSystem::core_routes()`, against real S2S clients/keys provisioned
//! through the `s2s_admin` HTTP API (not raw SQL) — so this also proves the
//! create-client / generate-key / revoke-key admin surface works end to end.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`, defaulting to `localhost:6379`) —
//! skips (loudly) when `DATABASE_URL` is unset, except under `CI`, per the P1.8
//! testing-baseline convention. NOT wired into any CI run yet (no
//! `attomedb_test` harness runner exists — see P1.8); run manually against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test s2s -- --test-threads=1
//! ```
//!
//! Uses a throwaway JWT secret and a throwaway S2S master key generated per
//! test run — never a real secret (standing rule, `/testing`).

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
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const S2S_NONCE_TTL_SECS: i64 = 300;

// 64 hex chars = 32 bytes, the shape `attome_s2s::crypto::parse_master_key` requires.
fn throwaway_s2s_master_key() -> String {
    "ab".repeat(32)
}

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
            "s2s": {{
                "enabled": true, "key_encryption_key": "{s2s_key}",
                "nonce_ttl_secs": {nonce_ttl}, "access_log_enabled": false
            }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        s2s_key = throwaway_s2s_master_key(),
        nonce_ttl = S2S_NONCE_TTL_SECS,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let db_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &db_url);
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

/// csrf_protect (P-cookie-csrf-hardening) only ever acts on a request
/// carrying a session/refresh cookie (pure S2S-HMAC-authenticated requests
/// never have one, so they're unaffected either way) — but this file also
/// exercises cookie-authenticated scenarios, which need a safe Sec-Fetch-Site
/// or allow-listed Origin same as any other cookie-authenticated unsafe-
/// method request. This file's `test_config()` has no `cors` section, so
/// Sec-Fetch-Site is the only viable signal.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
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

/// Seeds a throwaway user holding `system.admin`. Returns (user_id, session cookie header value).
async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("s2s-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let key = "system.admin";
    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
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

    (user_id, session_cookie(user_id))
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Creates an S2S client whose `service_user_ref` is `admin_id` (so a
/// successfully S2S-authenticated request acts with that user's privileges),
/// generates a primary key, and returns
/// `(client_db_id, client_slug, key_public_id, raw_secret_hex)`.
async fn provision_s2s_client(
    app: axum::Router,
    admin_cookie: &str,
    admin_id: Uuid,
) -> (Uuid, String, String, String) {
    let slug = format!("s2s-test-{}", Uuid::now_v7().simple());
    let create_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/s2s/clients")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"client_id":"{slug}","name":"S2S Test Client","service_user_ref":"{admin_id}"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_req)
        .await
        .expect("create client");
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "client creation must succeed"
    );
    let created = body_json(res).await;
    let client_db_id = Uuid::parse_str(created["id"].as_str().expect("client id")).expect("uuid");

    let key_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/s2s/clients/{client_db_id}/keys"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"slot":"primary"}"#))
        .unwrap();
    let res = app.oneshot(key_req).await.expect("generate key");
    let status = res.status();
    let key = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "key generation must succeed: {key:?}"
    );
    let public_id = key["public_id"].as_str().expect("public_id").to_owned();
    let secret = key["secret"].as_str().expect("secret").to_owned();

    (client_db_id, slug, public_id, secret)
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

fn sha256_hex(data: &[u8]) -> String {
    attome_s2s::crypto::sha256_hex(data)
}

fn sign_hmac_hex(secret_hex: &str, message: &[u8]) -> String {
    let secret_bytes = hex::decode(secret_hex).expect("secret must be hex");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&secret_bytes).expect("hmac key");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

/// Builds a fully-signed S2S request for `method`/`path_and_query`/`body`.
#[allow(clippy::too_many_arguments)]
fn s2s_request(
    method: &str,
    path_and_query: &str,
    body: &'static [u8],
    slug: &str,
    key_public_id: &str,
    secret_hex: &str,
    timestamp_ms: i64,
    nonce: &str,
) -> Request<Body> {
    let body_hash = sha256_hex(body);
    let timestamp_str = timestamp_ms.to_string();
    let canonical = attome_s2s::crypto::canonical_message(
        method,
        path_and_query,
        &body_hash,
        &timestamp_str,
        nonce,
    );
    let signature = sign_hmac_hex(secret_hex, &canonical);

    Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("x-s2s-client-id", slug)
        .header("x-s2s-key-id", key_public_id)
        .header("x-s2s-timestamp", timestamp_str)
        .header("x-s2s-nonce", nonce)
        .header("x-s2s-signature", signature)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[test]
fn valid_s2s_request_succeeds() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (_, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;

        let req = s2s_request(
            "GET",
            "/api/v1/admin/s2s/clients",
            b"",
            &slug,
            &key_public_id,
            &secret,
            now_ms(),
            &Uuid::now_v7().to_string(),
        );
        let res = app.oneshot(req).await.expect("request");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "a correctly signed S2S request must succeed"
        );
    })
}

#[test]
fn bulk_status_is_scoped_to_the_s2s_service_user() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_admin_id, admin_cookie) = seed_admin(&system).await;
        let (service_user_id, _service_cookie, service_email) =
            seed_bulk_user(&system, "s2s-bulk-owner").await;
        let (_, other_cookie, other_email) = seed_bulk_user(&system, "s2s-bulk-other").await;
        let app = full_app(system);

        let logicalname = format!("s2s_bulk_{}", Uuid::now_v7().simple());
        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"S2S Bulk Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create bulk test entity");
        assert_eq!(res.status(), StatusCode::CREATED);

        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &service_email,
            &format!("{logicalname}.create"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &service_email,
            &format!("{logicalname}.bulk"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &service_email,
            &format!("{logicalname}.read"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &other_email,
            &format!("{logicalname}.create"),
        )
        .await;
        grant_bulk_privilege(
            &app,
            &admin_cookie,
            &other_email,
            &format!("{logicalname}.bulk"),
        )
        .await;

        let (_, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, service_user_id).await;

        let enqueue_body: &'static [u8] = br#"{"operation":"create","records":[{"data":{}}]}"#;
        let enqueue_path = format!("/api/v1/{logicalname}/bulk");
        let enqueue_req = s2s_request(
            "POST",
            &enqueue_path,
            enqueue_body,
            &slug,
            &key_public_id,
            &secret,
            now_ms(),
            &Uuid::now_v7().to_string(),
        );
        let res = app
            .clone()
            .oneshot(enqueue_req)
            .await
            .expect("enqueue S2S bulk operation");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let own_operation = body_json(res).await;
        let own_id = own_operation["id"].as_str().expect("own bulk operation id");

        let own_status_path = format!("/api/v1/{logicalname}/bulk/{own_id}");
        let own_status_req = s2s_request(
            "GET",
            &own_status_path,
            b"",
            &slug,
            &key_public_id,
            &secret,
            now_ms(),
            &Uuid::now_v7().to_string(),
        );
        let res = app
            .clone()
            .oneshot(own_status_req)
            .await
            .expect("read own S2S bulk status");
        assert_eq!(res.status(), StatusCode::OK);

        let other_enqueue_req = Request::builder()
            .method("POST")
            .uri(&enqueue_path)
            .header("cookie", &other_cookie)
            .header("content-type", "application/json")
            .body(Body::from(enqueue_body))
            .unwrap();
        let res = app
            .clone()
            .oneshot(other_enqueue_req)
            .await
            .expect("enqueue other user's bulk operation");
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let other_operation = body_json(res).await;
        let other_id = other_operation["id"]
            .as_str()
            .expect("other bulk operation id");

        let other_status_path = format!("/api/v1/{logicalname}/bulk/{other_id}");
        let other_status_req = s2s_request(
            "GET",
            &other_status_path,
            b"",
            &slug,
            &key_public_id,
            &secret,
            now_ms(),
            &Uuid::now_v7().to_string(),
        );
        let res = app
            .oneshot(other_status_req)
            .await
            .expect("read another user's S2S bulk status");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "an S2S service user must not read another principal's bulk operation"
        );
    })
}

#[test]
fn expired_timestamp_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (_, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;

        let stale_ts = now_ms() - (S2S_NONCE_TTL_SECS + 60) * 1000;
        let req = s2s_request(
            "GET",
            "/api/v1/admin/s2s/clients",
            b"",
            &slug,
            &key_public_id,
            &secret,
            stale_ts,
            &Uuid::now_v7().to_string(),
        );
        let res = app.oneshot(req).await.expect("request");
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "a timestamp outside the replay window must be rejected"
        );
    })
}

#[test]
fn replayed_nonce_is_rejected_with_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (_, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;

        let ts = now_ms();
        let nonce = Uuid::now_v7().to_string();

        let first = s2s_request(
            "GET",
            "/api/v1/admin/s2s/clients",
            b"",
            &slug,
            &key_public_id,
            &secret,
            ts,
            &nonce,
        );
        let res = app.clone().oneshot(first).await.expect("first request");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "first use of a nonce must succeed"
        );

        // Identical request, byte-for-byte, replayed — the Redis nonce guard must
        // have persisted the nonce from the first call and reject the replay.
        let second = s2s_request(
            "GET",
            "/api/v1/admin/s2s/clients",
            b"",
            &slug,
            &key_public_id,
            &secret,
            ts,
            &nonce,
        );
        let res = app.oneshot(second).await.expect("replayed request");
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "a replayed nonce must be rejected with 409"
        );
    })
}

#[test]
fn tampered_body_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (_, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;

        let signed_body: &'static [u8] =
            br#"{"client_id":"tamper-test-original","name":"Original"}"#;
        let actually_sent_body: &'static [u8] =
            br#"{"client_id":"tamper-test-mutated","name":"Mutated!"}"#;

        // Sign a canonical message whose body hash matches `signed_body`, but
        // physically send `actually_sent_body` — the middleware recomputes the
        // body hash from the real bytes it reads, so this must fail HMAC
        // verification exactly like a man-in-the-middle body swap would.
        let ts = now_ms();
        let nonce = Uuid::now_v7().to_string();
        let body_hash = sha256_hex(signed_body);
        let canonical = attome_s2s::crypto::canonical_message(
            "POST",
            "/api/v1/admin/s2s/clients",
            &body_hash,
            &ts.to_string(),
            &nonce,
        );
        let signature = sign_hmac_hex(&secret, &canonical);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/s2s/clients")
            .header("x-s2s-client-id", &slug)
            .header("x-s2s-key-id", &key_public_id)
            .header("x-s2s-timestamp", ts.to_string())
            .header("x-s2s-nonce", &nonce)
            .header("x-s2s-signature", signature)
            .header("content-type", "application/json")
            .body(Body::from(actually_sent_body))
            .unwrap();

        let res = app.oneshot(req).await.expect("request");
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "a body swapped after signing must fail HMAC verification"
        );
    })
}

#[test]
fn revoked_key_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (client_db_id, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;

        let revoke_req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/admin/s2s/clients/{client_db_id}/keys/primary"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(revoke_req).await.expect("revoke key");
        assert_eq!(res.status(), StatusCode::OK, "key revocation must succeed");

        let req = s2s_request(
            "GET",
            "/api/v1/admin/s2s/clients",
            b"",
            &slug,
            &key_public_id,
            &secret,
            now_ms(),
            &Uuid::now_v7().to_string(),
        );
        let res = app.oneshot(req).await.expect("request with revoked key");
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "a request signed with a revoked key must be rejected"
        );
    })
}

/// Base-auth hardening 2.1d (D-510 rule 7): an S2S client has no refresh
/// family and can never step up, so the step-up-guarded operations refuse it
/// with 403 even when its signature is valid and its service user is an admin.
#[test]
fn an_s2s_caller_is_refused_on_step_up_guarded_routes() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let (_, slug, key_public_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;

        for (path, body) in [
            ("/api/v1/auth/api-keys", &br#"{"name":"never-created"}"#[..]),
            ("/api/v1/auth/mfa/disable", &br#"{"code":"123456"}"#[..]),
            (
                "/api/v1/auth/mfa/recovery-codes/regenerate",
                &br#"{"code":"123456"}"#[..],
            ),
        ] {
            let req = s2s_request(
                "POST",
                path,
                body,
                &slug,
                &key_public_id,
                &secret,
                now_ms(),
                &Uuid::now_v7().to_string(),
            );
            let res = app.clone().oneshot(req).await.expect("signed request");
            assert_eq!(
                res.status(),
                StatusCode::FORBIDDEN,
                "{path}: a signed S2S request can never pass a step-up guard"
            );
            assert_eq!(body_json(res).await["error"], "forbidden", "{path}");
        }

        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE user_ref = $1")
            .bind(admin_id)
            .fetch_one(&db)
            .await
            .expect("count api keys");
        assert_eq!(keys, 0, "a refused S2S request mints nothing");
    })
}

/// Grants `client_db_id` a D-766 permission row through the admin API.
async fn set_s2s_permission(
    app: &axum::Router,
    admin_cookie: &str,
    client_db_id: Uuid,
    body: &str,
) {
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/s2s/clients/{client_db_id}/permissions"
        ))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("set permission");
    let status = res.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "set permission: {:?}",
        body_json(res).await
    );
}

/// Sends one signed, bodiless S2S request and returns its status.
async fn s2s_status(
    app: &axum::Router,
    method: &str,
    path: &str,
    client: &(String, String, String),
) -> StatusCode {
    let (slug, key_public_id, secret) = client;
    let req = s2s_request(
        method,
        path,
        b"",
        slug,
        key_public_id,
        secret,
        now_ms(),
        &Uuid::now_v7().to_string(),
    );
    app.clone()
        .oneshot(req)
        .await
        .expect("signed request")
        .status()
}

/// Provisions a throwaway entity through the admin API and returns its
/// logical name. A runtime-provisioned table carries the ownership columns
/// row-level security filters on, unlike a migration-owned `*` one.
async fn create_entity(app: &axum::Router, admin_cookie: &str) -> String {
    let name = format!("s2s_ceiling_{}", &Uuid::now_v7().simple().to_string()[20..]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{name}","name":"S2S ceiling test"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create entity");
    let status = res.status();
    assert!(
        status.is_success(),
        "create entity: {status} {:?}",
        body_json(res).await
    );
    name
}

/// D-766: a client's permission rows narrow its service user's roles — a verb
/// the row does not grant is refused even though the role grants it, an entity
/// with no row is refused, and a client with no rows is bounded by the roles
/// alone.
#[test]
fn s2s_permission_rows_narrow_the_service_users_privileges() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_admin_id, admin_cookie) = seed_admin(&system).await;
        let (service_user_id, _cookie, service_email) =
            seed_bulk_user(&system, "s2s-ceiling").await;
        let app = full_app(system);
        let entity = create_entity(&app, &admin_cookie).await;
        for key in [
            format!("{entity}.read"),
            format!("{entity}.delete"),
            "team.read".to_owned(),
        ] {
            grant_bulk_privilege(&app, &admin_cookie, &service_email, &key).await;
        }

        let (bounded_id, slug, key_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, service_user_id).await;
        let bounded = (slug, key_id, secret);
        let (_, slug, key_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, service_user_id).await;
        let unbounded = (slug, key_id, secret);
        set_s2s_permission(
            &app,
            &admin_cookie,
            bounded_id,
            &format!(r#"{{"entity_name":"{entity}","can_read":true}}"#),
        )
        .await;

        let missing = format!("/api/v1/{entity}/{}", Uuid::now_v7());
        let missing_team = format!("/api/v1/team/{}", Uuid::now_v7());

        assert_eq!(
            s2s_status(&app, "GET", &missing, &bounded).await,
            StatusCode::NOT_FOUND,
            "a verb both the row and the role grant passes authz (the record is absent)"
        );
        assert_eq!(
            s2s_status(&app, "DELETE", &missing, &bounded).await,
            StatusCode::FORBIDDEN,
            "the role grants delete but the row does not"
        );
        assert_eq!(
            s2s_status(&app, "GET", &missing_team, &bounded).await,
            StatusCode::FORBIDDEN,
            "an entity with no row is outside the ceiling"
        );

        assert_eq!(
            s2s_status(&app, "DELETE", &missing, &unbounded).await,
            StatusCode::NOT_FOUND,
            "a client with no rows is bounded by its service user's roles only"
        );

        // Self-service routes compute visibility from the user's roles, which
        // the ceiling cannot bind, so a capped client is refused on them.
        assert_eq!(
            s2s_status(&app, "GET", "/api/v1/sidebar/get", &bounded).await,
            StatusCode::FORBIDDEN,
            "a capped client cannot use a self-service route"
        );
        assert_eq!(
            s2s_status(&app, "GET", "/api/v1/sidebar/get", &unbounded).await,
            StatusCode::OK
        );
    })
}

/// D-766: a client with permission rows cannot act as an admin service user —
/// admin implies every entity privilege, and deferred work would re-resolve it
/// as admin — so every request it sends is refused.
#[test]
fn a_capped_client_with_an_admin_service_user_is_refused() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (client_db_id, slug, key_id, secret) =
            provision_s2s_client(app.clone(), &admin_cookie, admin_id).await;
        let client = (slug, key_id, secret);
        let missing = format!("/api/v1/role/{}", Uuid::now_v7());
        assert_eq!(
            s2s_status(&app, "GET", "/api/v1/admin/s2s/clients", &client).await,
            StatusCode::OK,
            "no rows: the admin service user is still admin"
        );

        set_s2s_permission(
            &app,
            &admin_cookie,
            client_db_id,
            r#"{"entity_name":"role","can_read":true}"#,
        )
        .await;
        for (method, path) in [
            ("GET", "/api/v1/admin/s2s/clients"),
            ("GET", missing.as_str()),
        ] {
            assert_eq!(
                s2s_status(&app, method, path, &client).await,
                StatusCode::FORBIDDEN,
                "{method} {path}: a capped client with an admin service user is refused"
            );
        }
    })
}

fn seeded_client(
    client_id: &str,
    public_id: &str,
    email: &str,
    secret: &str,
    entity: &str,
) -> attome_config::S2sSeededClient {
    serde_json::from_value(serde_json::json!({
        "client_id": client_id,
        "name": "Seeded test client",
        "service_user_email": email,
        "public_id": public_id,
        "secret": secret,
        "permissions": [{ "entity": entity, "read": true }],
    }))
    .expect("seeded client JSON")
}

/// D-771: a config-declared client works with the configured secret, a second
/// boot changes nothing, a changed secret rotates the key in place, and a
/// client whose service user is missing is skipped rather than created.
#[test]
fn config_seeded_client_is_reconciled_on_every_boot() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_admin_id, admin_cookie) = seed_admin(&system).await;
        let (_user_id, _cookie, email) = seed_bulk_user(&system, "s2s-seeded").await;
        let state = system.state().clone();
        let app = full_app(system);
        let entity = create_entity(&app, &admin_cookie).await;
        grant_bulk_privilege(&app, &admin_cookie, &email, &format!("{entity}.read")).await;

        let tag = Uuid::now_v7().simple().to_string();
        let slug = format!("seeded-{tag}");
        let public_id = format!("s2s_seeded_{tag}");
        let first = "cd".repeat(32);
        let missing = format!("/api/v1/{entity}/{}", Uuid::now_v7());
        let caller = |secret: &str| (slug.clone(), public_id.clone(), secret.to_owned());

        let cfg = seeded_client(&slug, &public_id, &email, &first, &entity);
        attome_s2s::config_clients::reconcile_clients(&state, std::slice::from_ref(&cfg))
            .await
            .expect("first reconcile");
        assert_eq!(
            s2s_status(&app, "GET", &missing, &caller(&first)).await,
            StatusCode::NOT_FOUND,
            "the seeded key authenticates and its permission row allows read"
        );
        assert_eq!(
            s2s_status(&app, "DELETE", &missing, &caller(&first)).await,
            StatusCode::FORBIDDEN,
            "the seeded permission row is the ceiling"
        );

        attome_s2s::config_clients::reconcile_clients(&state, std::slice::from_ref(&cfg))
            .await
            .expect("second reconcile");
        let keys: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM s2s_client_key k JOIN s2s_client c ON c.id = k.client_ref \
              WHERE c.client_id = $1",
        )
        .bind(&slug)
        .fetch_one(&state.base.db)
        .await
        .expect("count keys");
        assert_eq!(keys, 1, "a second boot adds no key");

        let second = "ef".repeat(32);
        let rotated = seeded_client(&slug, &public_id, &email, &second, &entity);
        attome_s2s::config_clients::reconcile_clients(&state, &[rotated])
            .await
            .expect("rotating reconcile");
        assert_eq!(
            s2s_status(&app, "GET", &missing, &caller(&first)).await,
            StatusCode::UNAUTHORIZED,
            "the old secret stops working"
        );
        assert_eq!(
            s2s_status(&app, "GET", &missing, &caller(&second)).await,
            StatusCode::NOT_FOUND,
            "the new secret works under the same public_id"
        );

        let orphan_slug = format!("seeded-orphan-{tag}");
        let orphan = seeded_client(
            &orphan_slug,
            &format!("s2s_orphan_{tag}"),
            &format!("nobody-{tag}@test.local"),
            &first,
            &entity,
        );
        attome_s2s::config_clients::reconcile_clients(&state, &[orphan])
            .await
            .expect("a missing service user is not a boot error");
        let created: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM s2s_client WHERE client_id = $1)")
                .bind(&orphan_slug)
                .fetch_one(&state.base.db)
                .await
                .expect("look up orphan");
        assert!(!created, "no client is created without its service user");
    })
}
