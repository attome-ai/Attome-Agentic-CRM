//! `attome-testapp`: the whole Attome API in process for integration tests
//! (roadmap Z15-T3).
//!
//! [`TestApp::start`] builds the engine system and the full router (the same
//! middleware stack production runs) on this test process's migrated
//! throwaway database, seeds an administrator, and returns `None` when no
//! test database is configured (the test then skips, or fails under
//! `ATTOME_TEST_REQUIRE_DB`). [`TestApp::request`] sends one request as that
//! administrator, with the `Origin` and `Sec-Fetch-Site` headers a mutation
//! needs.
//!
//! One app is built per test binary and shared, like the per-binary
//! database: tests create their own uniquely named entities, users and
//! records, so sharing adds no coupling the database did not already have.
//! Use it from tests run on `attome_testkit::run_shared`.
//!
//! A dev-dependency only: no production crate depends on this one.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    reason = "test support: a failed setup step should stop the test with its message"
)]

pub mod faults;
pub mod fixtures;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ISSUER: &str = "attome-test";

/// The configuration every test app runs with; the database and Redis come
/// from the test environment.
pub fn test_config() -> AppConfig {
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
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}",
                "s3_secret_key": "{s3_secret_key}",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "{issuer}", "jwt_expiry_hours": 1,
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
            "einvoice": {{ "enabled": true, "key_encryption_key": "{einvoice_key}" }},
            "integration": {{ "credential_encryption_key": "{integration_key}" }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        // The object store CI runs (and `attome_testkit::s3_or_skip` checks
        // for); `TEST_S3_ENDPOINT` moves it off the dev store's port.
        s3_endpoint =
            std::env::var("TEST_S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into()),
        s3_access_key = attome_testkit::s3_env("S3_ACCESS_KEY"),
        s3_secret_key = attome_testkit::s3_env("S3_SECRET_KEY"),
        jwt_secret = THROWAWAY_JWT_SECRET,
        // A throwaway key: the test database is dropped after the run.
        einvoice_key = "5e".repeat(32),
        integration_key = "6a".repeat(32),
        issuer = ISSUER,
    );
    // Through the document, like a configuration loaded from a file, so the
    // secret inventory and fingerprint view are filled (Z1-T15).
    let document: Value = serde_json::from_str(&json).expect("the test configuration parses");
    let config: AppConfig =
        serde_json::from_value(document.clone()).expect("the test configuration deserializes");
    attome_testkit::with_test_database(config.with_document_views(&document), true)
}

/// A session cookie for `user_id`, signed with the test secret.
pub fn session_cookie(user_id: Uuid) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: ISSUER.into(),
        aud: ISSUER.into(),
        typ: attome_auth::TokenType::Session,
    };
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("sign the test session");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// Moves every captured audit event into the hash chain, so a test can read
/// `audit_header`/`audit_detail` (the record history) as the deployment's
/// chainer would have written them.
pub async fn drain_audit(app: &TestApp) {
    for _ in 0..20 {
        let done = attome_audit::chainer::run_once(
            app.db(),
            app.state.audit_signer.as_deref(),
            1000,
            None,
        )
        .await
        .expect("chain the captured audit events");
        if done.is_empty() {
            break;
        }
    }
}

/// A user signed in for tests.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: Uuid,
    pub cookie: String,
}

/// Creates an active user (no privileges) and its session cookie.
pub async fn seed_user(db: &attome_db::DbPool, label: &str) -> TestUser {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', true)",
    )
    .bind(id)
    .bind(format!("testapp-{label}-{id}"))
    .execute(db)
    .await
    .expect("insert a test user");
    TestUser {
        id,
        cookie: session_cookie(id),
    }
}

/// Creates a user holding `system.admin`.
pub async fn seed_admin(db: &attome_db::DbPool) -> TestUser {
    let user = seed_user(db, "admin").await;
    let privilege: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
        .fetch_one(db)
        .await
        .expect("system.admin is seeded by attome_security's seed");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user.id)
    .bind(privilege)
    .execute(db)
    .await
    .expect("grant system.admin");
    user
}

/// The whole API in process, with a seeded administrator.
#[derive(Clone)]
pub struct TestApp {
    pub router: axum::Router,
    pub state: EngineState,
    pub admin: TestUser,
}

impl std::fmt::Debug for TestApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestApp")
            .field("admin", &self.admin.id)
            .finish_non_exhaustive()
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestApp>> = tokio::sync::OnceCell::const_new();

async fn build() -> Option<TestApp> {
    build_with(test_config()).await
}

async fn build_with(config: AppConfig) -> Option<TestApp> {
    attome_testkit::migrated_db_url()?;
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect the test database");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect the test Redis");
    let coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect the coordination Redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build the storage client");
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .register(attome_billing::BillingModel)
        .register(attome_einvoice::EinvoiceModel)
        // F6-T11: delivery proof routes.
        .register(attome_fulfilment::FulfilmentModel)
        // G17-T10: the adherence routes.
        .register(attome_workforce::WorkforceModel)
        .register(attome_document::engine::DocumentModel)
        // AB4-T6: the ops engine's routes (drill evidence, schedules).
        .register(attome_ops::OpsModel)
        // F9, D6: the partner and sales routes their pack tests call.
        .register(attome_partner::PartnerModel)
        .register(attome_sales::SalesModel)
        .register(attome_docgen::model::DocgenModel)
        .build()
        .await
        .expect("build the engine system");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    let state = system.state().clone();
    let base_state = state.base.clone();
    let router =
        attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
            .add_bundle(system.core_routes())
            .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    // Boot seeds this entity; the packs upsert their document templates into it.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-docgen")
        .await
        .expect("apply the docgen platform definition");
    let admin = seed_admin(&state.base.db).await;
    Some(TestApp {
        router,
        state,
        admin,
    })
}

impl TestApp {
    /// The shared app, or `None` when no test database is configured.
    pub async fn start() -> Option<TestApp> {
        SHARED.get_or_init(build).await.clone()
    }

    /// An app of its own (not the shared one) with `edit` applied to the
    /// test configuration: a fault test points the object store at a fake
    /// (`faults::FakeS3`). `None` when no test database is configured.
    pub async fn start_with(edit: impl FnOnce(&mut AppConfig)) -> Option<TestApp> {
        let mut config = test_config();
        edit(&mut config);
        build_with(config).await
    }

    /// The database pool.
    pub fn db(&self) -> &attome_db::DbPool {
        &self.state.base.db
    }

    /// Sends one request as the administrator; returns the status and the
    /// JSON body (`Null` when the body is empty or not JSON).
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let cookie = self.admin.cookie.clone();
        self.request_as(&cookie, method, path, body).await
    }

    /// Sends one request with no credential, the raw `body` and `headers`,
    /// as an outside caller (a gateway's webhook) would.
    pub async fn request_public(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(
                builder
                    .body(Body::from(body))
                    .expect("a well-formed request"),
            )
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read the response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Sends one request as the administrator with extra `headers` (an
    /// `If-Match`, say).
    pub async fn request_with(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", self.admin.cookie.as_str())
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("a well-formed request"))
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read the response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Sends one request with `cookie`.
    pub async fn request_as(
        &self,
        cookie: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin");
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("a well-formed request"))
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read the response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}
