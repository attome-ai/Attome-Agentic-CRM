//! P-email-hardening — `GET/POST /api/v1/admin/email/deliveries` and
//! `GET/POST/DELETE /api/v1/admin/email/suppressions`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `authz.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test email_admin -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_api::EngineSystem;
use attome_auth::password::hash_password_async;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_email::delivery::{self, EmailDeliveryKind};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
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
                "oauth_google_client_id": "", "oauth_google_client_secret": "",
                "email_verification_token_expiry_hours": 24,
                "password_reset_token_expiry_mins": 30,
                "invitation_token_expiry_hours": 72
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "enabled": true, "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
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
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("email-admin-test-{user_id}"))
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

/// Inserts a throwaway password account (needed for a `password_reset`-kind
/// resend, which calls `attome_auth::reset::request_in_tx` — that only issues
/// a token for an active account that actually has a `password_hash`).
async fn seed_password_account(db: &attome_db::DbPool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("email-admin-pwtest-{id}@example.test");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "throwaway-password-123",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active) \
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(db)
    .await
    .expect("insert throwaway password account");
    (id, email)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn non_admin_gets_403_on_every_email_admin_endpoint() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, non_admin_cookie) = seed_user(&system, false).await;
        let app = full_app(system);

        // Bodies must be well-formed for whatever endpoint they're paired with —
        // a malformed/incomplete `Json<T>` body fails axum's own extraction
        // before the handler's `ctx.require_admin()` line ever runs (same
        // pre-existing behavior every other admin POST endpoint in this
        // codebase has, e.g. `authz.rs`'s `non_admin_gets_403_on_create_entity`
        // sends a real body for the same reason), which would otherwise mask
        // this test's actual assertion behind an unrelated 422.
        for (method, uri, body) in [
            ("GET", "/api/v1/admin/email/deliveries".to_string(), "{}"),
            (
                "GET",
                format!("/api/v1/admin/email/deliveries/{}", Uuid::now_v7()),
                "{}",
            ),
            (
                "POST",
                format!("/api/v1/admin/email/deliveries/{}/resend", Uuid::now_v7()),
                "{}",
            ),
            ("GET", "/api/v1/admin/email/suppressions".to_string(), "{}"),
            (
                "POST",
                "/api/v1/admin/email/suppressions".to_string(),
                r#"{"email":"non-admin-403-test@example.test"}"#,
            ),
            (
                "DELETE",
                format!("/api/v1/admin/email/suppressions/{}", Uuid::now_v7()),
                "{}",
            ),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(&uri)
                .header("cookie", &non_admin_cookie)
                .header("origin", "http://localhost:4200")
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{method} {uri} must require system.admin"
            );
        }
    })
}

#[test]
fn list_and_get_delivery_round_trip_and_filter_by_recipient() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();

        let email = format!("email-admin-list-{}@example.test", Uuid::now_v7());
        let id = Uuid::now_v7();
        let mut tx = db.begin().await.unwrap();
        delivery::record_queued_in_tx(
            &mut tx,
            id,
            EmailDeliveryKind::Invitation,
            &email,
            "You're invited",
            None,
            None,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let app = full_app(system);
        let list_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin/email/deliveries?recipient={email}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(list_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let items = body["items"].as_array().unwrap();
        assert!(
            items
                .iter()
                .any(|item| item["id"].as_str() == Some(id.to_string().as_str()))
        );

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin/email/deliveries/{id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["kind"], "invitation");
        assert_eq!(body["status"], "queued");
        // Never a body/token field -- notification_email_delivery doesn't store one.
        assert!(body.get("text_body").is_none());
        assert!(body.get("html_body").is_none());
    })
}

#[test]
fn resend_on_a_suppressed_recipient_is_a_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();

        let email = format!("email-admin-suppressed-{}@example.test", Uuid::now_v7());
        attome_email::suppression::suppress(
            &db,
            &email,
            attome_email::suppression::SuppressionReason::HardBounce,
            None,
            None,
        )
        .await
        .unwrap();

        let id = Uuid::now_v7();
        let mut tx = db.begin().await.unwrap();
        delivery::record_queued_in_tx(
            &mut tx,
            id,
            EmailDeliveryKind::Invitation,
            &email,
            "You're invited",
            None,
            None,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        delivery::mark_terminal(&db, id, "suppressed", "550 rejected")
            .await
            .unwrap();

        let app = full_app(system);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/email/deliveries/{id}/resend"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    })
}

#[test]
fn resend_password_reset_remints_a_fresh_token_and_a_new_delivery_row() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let (user_id, email) = seed_password_account(&db).await;

        let old_id = Uuid::now_v7();
        let mut tx = db.begin().await.unwrap();
        delivery::record_queued_in_tx(
            &mut tx,
            old_id,
            EmailDeliveryKind::PasswordReset,
            &email,
            "Reset your password",
            Some(user_id),
            None,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        delivery::mark_terminal(&db, old_id, "failed", "smtp timeout")
            .await
            .unwrap();

        let app = full_app(system);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/email/deliveries/{old_id}/resend"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_json(resp).await;
        let new_id: Uuid = body["new_delivery_id"].as_str().unwrap().parse().unwrap();
        assert_ne!(new_id, old_id);

        let new_row = delivery::get_by_id(&db, new_id).await.unwrap().unwrap();
        assert_eq!(new_row.kind, "password_reset");
        assert_eq!(new_row.status, "queued");
        assert_eq!(
            new_row.recipient,
            attome_types::text::normalize_email(&email)
        );

        // Old row is untouched -- resend never mutates history, only adds to it.
        let old_row = delivery::get_by_id(&db, old_id).await.unwrap().unwrap();
        assert_eq!(old_row.status, "failed");
    })
}

#[test]
fn resend_of_a_still_queued_delivery_is_a_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let (user_id, email) = seed_password_account(&db).await;

        let id = Uuid::now_v7();
        let mut tx = db.begin().await.unwrap();
        delivery::record_queued_in_tx(
            &mut tx,
            id,
            EmailDeliveryKind::PasswordReset,
            &email,
            "Reset your password",
            Some(user_id),
            None,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let app = full_app(system);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/email/deliveries/{id}/resend"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "conflict", "{body}");

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_email_delivery WHERE recipient = $1",
        )
        .bind(attome_types::text::normalize_email(&email))
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(rows, 1, "a refused resend must not queue a second delivery");
        let row = delivery::get_by_id(&db, id).await.unwrap().unwrap();
        assert_eq!(row.status, "queued");
    })
}

#[test]
fn resend_generic_kind_is_rejected_no_body_is_ever_stored() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();

        let id = Uuid::now_v7();
        let mut tx = db.begin().await.unwrap();
        delivery::record_queued_in_tx(
            &mut tx,
            id,
            EmailDeliveryKind::Generic,
            &format!("email-admin-generic-{}@example.test", Uuid::now_v7()),
            "A generic notice",
            None,
            None,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        delivery::mark_terminal(&db, id, "failed", "smtp timeout")
            .await
            .unwrap();

        let app = full_app(system);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/email/deliveries/{id}/resend"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

#[test]
fn suppression_list_add_and_remove_round_trip() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_user(&system, true).await;
        let email = format!("email-admin-suppress-http-{}@example.test", Uuid::now_v7());
        let app = full_app(system);

        let add_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/email/suppressions")
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"email": email, "detail": "manual test"}).to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(add_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let list_req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/email/suppressions?page_size=200")
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(list_req).await.unwrap();
        let body = body_json(resp).await;
        let items = body["items"].as_array().unwrap();
        let found = items
            .iter()
            .find(|item| item["email"].as_str() == Some(email.as_str()))
            .expect("newly added suppression must appear in the list");
        assert_eq!(found["reason"], "admin_manual");
        let id: Uuid = found["id"].as_str().unwrap().parse().unwrap();

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/email/suppressions/{id}"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(delete_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Second delete of the same (now-removed) id is a 404, not another 204.
        let delete_again = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/email/suppressions/{id}"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(delete_again).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    })
}
