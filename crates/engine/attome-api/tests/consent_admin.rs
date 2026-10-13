//! M24/D-428 — live-database HTTP coverage for
//! `attome_compliance::consent_admin` (mounted in `system.rs`) and the entity
//! metadata `attome_compliance::consent_seed` registers at boot. Same
//! "full_app over `system.core_routes()`" shape `dsr_admin.rs`'s own suite
//! uses, but without that file's real-object-store requirement — none of
//! this file's coverage touches `state.base.storage` (unlike DSR
//! access/portability fulfillment), so `test_config` here uses the simpler,
//! no-real-credentials-needed `storage` block `middleware_pipeline.rs` uses.
//!
//! Requires a live Postgres (`DATABASE_URL`, `APP_ENV=debug`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — see `db-and-migrations`/
//! `testing` skills.
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3D<migrated_schema>"
//! cargo test -p attome-api --test consent_admin -- --test-threads=1
//! ```

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
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
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
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
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
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000 }},
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
            "audit": {{ "chainer_enabled": false }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
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

/// Grants `audit_consent.{read,create}` (minted by
/// `attome_security::entity_privileges::seed_all` once `consent_seed::seed`
/// registers the entity — see `system.rs`'s call ordering) rather than
/// `system.admin`, so this suite also proves the ordinary generic-CRUD
/// privilege model — not a hidden admin-only gate — is what protects
/// `/api/v1/consents/withdraw` (`consent_admin::withdraw_consent`'s own
/// `ctx.require("audit_consent", "create")`).
async fn seed_consent_user(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("consent-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    for action in ["read", "create"] {
        let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
            .bind(format!("audit_consent.{action}"))
            .fetch_one(db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "audit_consent.{action} privilege must already be seeded by \
                 entity_privileges::seed_all once consent_seed::seed has run"
                )
            });
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
             VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("insert throwaway consent grant");
    }

    (user_id, session_cookie(user_id))
}

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("consent-admin-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

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

    (user_id, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

async fn seed_purpose(db: &attome_db::DbPool, key: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO audit_consent_purpose (key, lawful_basis, is_active) \
         VALUES ($1, 'consent', TRUE) RETURNING id",
    )
    .bind(key)
    .fetch_one(db)
    .await
    .expect("insert test consent purpose")
}

/// The one genuinely public route this crate mounts (M24/D-428): no cookie,
/// no `Authorization` header at all — matches `content_public`/
/// `service_public`'s own public-route test convention.
#[test]
fn public_capture_records_a_granted_consent_with_no_auth() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let purpose_key = format!("newsletter-{}", Uuid::now_v7());
        seed_purpose(&db, &purpose_key).await;
        let app = full_app(system);

        let subject_reference = format!("subject-{}@example.com", Uuid::now_v7().simple());
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/consents/capture")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "purpose_key": purpose_key,
                    "subject_reference": subject_reference,
                })
                .to_string(),
            ))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        assert_eq!(created["status"], "granted");

        let (status, source): (String, String) =
            sqlx::query_as("SELECT status, source FROM audit_consent WHERE subject_reference = $1")
                .bind(&subject_reference)
                .fetch_one(&db)
                .await
                .expect("consent row must exist");
        assert_eq!(status, "granted");
        assert_eq!(source, "form");
    })
}

#[test]
fn public_capture_rejects_an_unknown_purpose_key() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let app = full_app(system);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/consents/capture")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "purpose_key": format!("does-not-exist-{}", Uuid::now_v7()),
                    "subject_reference": "someone@example.com",
                })
                .to_string(),
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

/// The withdraw endpoint requires a session/API key — no bypass entry
/// exists for it (only `/api/v1/consents/capture` is bypass-listed).
#[test]
fn withdraw_requires_authentication() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let app = full_app(system);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/consents/withdraw")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "purpose_key": "whatever",
                    "subject_reference": "someone@example.com",
                })
                .to_string(),
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    })
}

/// The headline D-428 property, proven end to end over real HTTP: a grant
/// followed by a withdrawal leaves TWO rows, the first untouched, and the
/// generic entity engine's own append-only enforcement means there was never
/// a PATCH path available to touch it with in the first place.
#[test]
fn withdraw_appends_a_new_row_and_never_touches_the_grant() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let purpose_key = format!("marketing-{}", Uuid::now_v7());
        let purpose_id = seed_purpose(&db, &purpose_key).await;
        let (_, cookie) = seed_consent_user(&db).await;
        let app = full_app(system);

        let subject_reference = format!("subject-{}@example.com", Uuid::now_v7().simple());

        // Grant via the ordinary generic entity create — the withdraw endpoint
        // is the only bespoke workflow piece; recording a grant is plain CRUD.
        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/audit_consent")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(
                serde_json::json!({
                    "purpose_ref": purpose_id.to_string(),
                    "subject_reference": subject_reference,
                    "status": "granted",
                    "source": "api",
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "grant must succeed");
        let granted = body_json(resp).await;
        let granted_id = granted["id"].as_str().unwrap().to_string();

        // Withdraw via the dedicated endpoint.
        let withdraw_req = Request::builder()
            .method("POST")
            .uri("/api/v1/consents/withdraw")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(
                serde_json::json!({
                    "purpose_key": purpose_key,
                    "subject_reference": subject_reference,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(withdraw_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let withdrawn = body_json(resp).await;
        assert_eq!(withdrawn["status"], "withdrawn");
        let withdrawn_id = withdrawn["id"].as_str().unwrap().to_string();
        assert_ne!(
            granted_id, withdrawn_id,
            "withdrawal must be a distinct row from the grant"
        );

        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM audit_consent WHERE subject_reference = $1 ORDER BY created_at",
        )
        .bind(&subject_reference)
        .fetch_all(&db)
        .await
        .expect("query consent rows");
        assert_eq!(
            rows.len(),
            2,
            "grant row and withdrawal row must both exist"
        );
        assert_eq!(rows[0].0, "granted", "the original grant row is untouched");
        assert_eq!(rows[1].0, "withdrawn");

        // The generic engine's own append-only enforcement: nothing could ever
        // have PATCHed the grant row directly, even before the withdraw
        // endpoint existed.
        let patch_req = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/audit_consent/{granted_id}"))
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(
                serde_json::json!({ "status": "expired" }).to_string(),
            ))
            .unwrap();
        let resp = app.oneshot(patch_req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "an append-only entity must refuse PATCH, got {}",
            resp.status()
        );
    })
}

/// M24/D-428's DSR integration: an erasure request withdraws every active
/// consent for its subject by appending withdrawal rows, without touching
/// (let alone crypto-shredding) the ledger itself.
#[test]
fn dsr_erasure_withdraws_active_consents() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let purpose_key = format!("marketing-{}", Uuid::now_v7());
        let purpose_id = seed_purpose(&db, &purpose_key).await;
        let (_, admin_cookie) = seed_admin(&db).await;

        let subject_reference = format!("erasure-subject-{}@example.com", Uuid::now_v7().simple());
        sqlx::query(
        "INSERT INTO audit_consent (purpose_ref, subject_reference, status, granted_at, source) \
         VALUES ($1, $2, 'granted', NOW(), 'api')",
    )
    .bind(purpose_id)
    .bind(&subject_reference)
    .execute(&db)
    .await
    .expect("seed a granted consent");

        let app = full_app(system);

        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/dsr/requests")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(
                serde_json::json!({
                    "subject_reference": subject_reference,
                    "request_type": "erasure",
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        // No other entity scopes named — only the consent-withdrawal side
        // effect has anything to do, proving that alone is a valid erasure
        // fulfillment (M24/D-428's extension of the "nothing to do" guard).
        let fulfill_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/dsr/requests/{request_id}/fulfill-erasure"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(serde_json::json!({ "scopes": [] }).to_string()))
            .unwrap();
        let resp = app.oneshot(fulfill_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let result = body_json(resp).await;
        assert_eq!(result["status"], "fulfilled");
        assert_eq!(result["consents_withdrawn"], 1);

        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM audit_consent WHERE subject_reference = $1 ORDER BY created_at",
        )
        .bind(&subject_reference)
        .fetch_all(&db)
        .await
        .expect("query consent rows");
        assert_eq!(rows.len(), 2, "the original grant plus the new withdrawal");
        assert_eq!(rows[0].0, "granted", "the grant row must be untouched");
        assert_eq!(rows[1].0, "withdrawn");
    })
}
