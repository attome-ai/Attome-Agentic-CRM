//! Integration tests for the P1.1 authorization gate: non-admin sessions must
//! be rejected from `/api/v1/admin/*`, admin sessions must pass, and the
//! unlicensed `attome-security` module's own route must be invisible (404, not
//! 403 — guidelines §6).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`, defaulting to `localhost:6379` per
//! the documented dev stack) — skips (loudly) when `DATABASE_URL`
//! is unset, except under `CI` (see `attome_testkit`). NOT wired into any CI
//! run yet (no `attomedb_test` harness exists — see P1.8); run manually
//! against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test authz -- --test-threads=1
//! ```
//!
//! Uses a throwaway JWT secret generated per test run — never a real secret.
//!
//! `cache.metadata_registry_enabled: false` below forces the pre-Plan-1.2
//! direct-Postgres `resolve_entity` path (the documented rollback switch).
//! With the registry on, `per_entity_read_grant_allows_read_but_not_write`
//! creates an entity and immediately reads/writes a record through it — the
//! arc-swap registry only refreshes ~250ms after the `meta_version` pub/sub
//! signal, so that sequence races the rebuild and 404s. Found while standing
//! up the P1.8 baseline; flagging for whoever owns Plan 1.2 rather than
//! fixing it here — either tests should wait for propagation, or a
//! synchronous test-mode refresh hook is worth adding.

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
use tower::ServiceExt;
use uuid::Uuid;

/// (category, operation, entity_name, record_id, user_id, event_name) — the
/// `audit_header` row shape asserted by the MFA-reset audit test below.
/// Factored out to satisfy clippy's type-complexity lint (pre-existing
/// failure, unrelated to D-111 — see DECISIONS.md D-110's addendum).
type MfaResetAuditRow = (i32, i32, Option<String>, Option<Uuid>, Uuid, Option<String>);

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `audit.chainer_enabled` is pinned false (D-316 made true the code
/// default): this suite asserts `audit_header` rows exist immediately
/// after the mutation that produced them, which is the synchronous path's
/// guarantee. On the cutover path those rows only appear once the separate
/// `audit_chainer` process drains `audit_ingest`, and nothing starts it
/// here.
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
            "cors": {{ "allowed_origins": ["http://test.local"] }},
            "audit": {{ "chainer_enabled": false }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &throwaway_url);
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

    // No database.readonly in test_config() — fall back to the same pool,
    // matching main.rs's documented fallback behavior.
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

/// Seeds a throwaway user with no privileges. Returns (user_id, session cookie header value).
async fn seed_non_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("authz-test-nonadmin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway non-admin user_account");

    (user_id, session_cookie(user_id))
}

/// Seeds a throwaway user holding `system.admin`. Returns (user_id, session cookie header value).
async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("authz-test-admin-{user_id}"))
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

#[test]
fn non_admin_gets_403_on_create_entity() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_non_admin(&system).await;
        let app = full_app(system);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"authz_test_entity","name":"Authz Test"}"#,
            ))
            .unwrap();

        let res = app.oneshot(req).await.expect("request");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    })
}

#[test]
fn non_admin_gets_403_on_hard_delete() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_non_admin(&system).await;
        let app = full_app(system);

        // Any UUID works — the authz check runs before the entity lookup.
        let req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/admin/entities/{}?hard=true",
                Uuid::now_v7()
            ))
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.expect("request");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    })
}

#[test]
fn admin_gets_success_on_create_entity() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("authz_ok_{}", Uuid::now_v7().simple());
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Authz OK Test"}}"#
            )))
            .unwrap();

        let res = app.clone().oneshot(req).await.expect("request");
        assert_eq!(res.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        let entity: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        // Retire the throwaway entity. A hard delete is refused in recording
        // mode (D-785 `hard_delete_not_recordable`); the suite runs on a
        // per-binary clone database, so a soft delete leaks nothing that lasts.
        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/entities/{entity_id}"))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(delete_req).await.expect("retire request");
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("teardown body");
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "teardown: retiring the throwaway entity must succeed: {}",
            String::from_utf8_lossy(&body)
        );
    })
}

#[test]
fn security_admin_routes_reachable_regardless_of_license_state() {
    attome_testkit::run_shared(async {
        // A fresh test DB has no license row, so EngineSystem::build() loads
        // ModuleSet::core_only() (all module bits zero). Unlike genuinely
        // licensable engines, attome-security's admin surface (whoami, privilege
        // grants) is mounted unconditionally in system.rs, NOT through the
        // ModelRegistry/license filter — an expired/degraded license must never
        // lock admins out of the mechanism that manages who IS an admin.
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/security/whoami")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.expect("request");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "security admin routes must stay reachable even when no license is imported"
        );
    })
}

/// A forced MFA reset is a high-impact support action. The reset and the
/// tamper-evident audit entry must commit together so forensic evidence cannot
/// be lost after the credential is cleared.
#[test]
fn admin_mfa_reset_writes_a_security_audit_event() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let target_id = Uuid::now_v7();

        sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
            .bind(target_id)
            .bind(format!("mfa-reset-target-{target_id}"))
            .execute(&db)
            .await
            .expect("insert MFA-reset target user");
        sqlx::query(
            "INSERT INTO user_mfa (id, user_ref, secret_encrypted, confirmed_at) \
         VALUES ($1, $2, $3, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(target_id)
        .bind("test-only-encrypted-secret")
        .execute(&db)
        .await
        .expect("insert active MFA enrollment");
        sqlx::query(
            "INSERT INTO user_mfa_recovery_code (id, user_ref, code_hash) VALUES ($1, $2, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(target_id)
        .bind("test-only-recovery-code-hash")
        .execute(&db)
        .await
        .expect("insert MFA recovery code");

        let app = full_app(system);
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/security/users/{target_id}/mfa/reset"
            ))
            .header("cookie", admin_cookie)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.expect("MFA reset request");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let active_mfa: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_mfa WHERE user_ref = $1 AND is_deleted = false",
        )
        .bind(target_id)
        .fetch_one(&db)
        .await
        .expect("count active MFA enrollments");
        assert_eq!(active_mfa, 0, "reset must disable the active enrollment");

        let recovery_codes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_mfa_recovery_code WHERE user_ref = $1")
                .bind(target_id)
                .fetch_one(&db)
                .await
                .expect("count recovery codes");
        assert_eq!(recovery_codes, 0, "reset must invalidate recovery codes");

        let audit: Option<MfaResetAuditRow> = sqlx::query_as(
            "SELECT category, operation, entity_name, record_id, user_id, event_name \
             FROM audit_header \
             WHERE record_id = $1 AND event_name = 'mfa_reset' \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(target_id)
        .fetch_optional(&db)
        .await
        .expect("fetch MFA-reset audit event");
        assert_eq!(
            audit,
            Some((
                1,
                22,
                Some("user_mfa".to_owned()),
                Some(target_id),
                admin_id,
                Some("mfa_reset".to_owned()),
            )),
            "reset must write a typed security event identifying both target and admin"
        );
    })
}

#[test]
fn admin_can_grant_and_revoke_a_privilege() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_admin(&system).await;
        let (_, target_email) = {
            let db = &system.state().base.db;
            let user_id = Uuid::now_v7();
            let email = format!("authz-grant-target-{user_id}@test.local");
            sqlx::query("INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)")
            .bind(user_id)
            .bind(&email)
            .bind(format!("authz-grant-target-{user_id}"))
            .execute(db)
            .await
            .expect("insert throwaway grant-target user");
            (user_id, email)
        };
        let app = full_app(system);

        let key = format!("test.grant.{admin_id}");
        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/grants")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"user_email":"{target_email}","privilege_key":"{key}"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(create_req).await.expect("request");
        assert_eq!(res.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
        let grant_id = created["id"].as_str().expect("grant id").to_owned();

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/security/grants/{grant_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(delete_req).await.expect("request");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    })
}

#[test]
fn admin_can_grant_and_revoke_a_role_privilege() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;

        let role_id = Uuid::now_v7();
        {
            let db = &system.state().base.db;
            sqlx::query("INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')")
                .bind(role_id)
                .bind(format!("authz-role-{role_id}"))
                .bind("throwaway test role")
                .execute(db)
                .await
                .expect("insert throwaway role");
        }

        let app = full_app(system);
        let key = format!("test.rolegrant.{role_id}");
        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/role-grants")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"role_id":"{role_id}","privilege_key":"{key}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create role grant");
        assert_eq!(res.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
        let grant_id = created["id"].as_str().expect("grant id").to_owned();

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/security/role-grants/{grant_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(delete_req).await.expect("request");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    })
}

/// C-03: `admin::role_grants` invalidation must reach a user who holds the
/// granted role only through team membership (D-133), not just direct
/// `user_account_mm_role` holders — the module-master-plan defect
/// this regression-tests was `crate::db::users_in_role` (direct-only,
/// predates D-133's team path) still being wired into these two call sites.
/// Proves it the way the plan's Proof section specifies: grant a privilege
/// to a role held only through a team, then assert `resolve_strict` for the
/// team member sees it on the very next call — no sleep, so a pass here can
/// only be explained by synchronous invalidation, never by the 60s TTL
/// happening to expire.
#[test]
fn role_grant_invalidation_reaches_a_team_mediated_holder() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;
        let (member_id, _) = seed_non_admin(&system).await;

        let role_id = Uuid::now_v7();
        let team_id = Uuid::now_v7();
        {
            let db = &system.state().base.db;
            sqlx::query("INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')")
                .bind(role_id)
                .bind(format!("authz-team-role-{role_id}"))
                .bind("throwaway test role")
                .execute(db)
                .await
                .expect("insert throwaway role");
            sqlx::query("INSERT INTO team (id, name, description) VALUES ($1, $2, $3)")
                .bind(team_id)
                .bind(format!("authz-team-{team_id}"))
                .bind("throwaway test team")
                .execute(db)
                .await
                .expect("insert throwaway team");
            sqlx::query("INSERT INTO role_mm_team (id, role_ref, team_ref) VALUES ($1, $2, $3)")
                .bind(Uuid::now_v7())
                .bind(role_id)
                .bind(team_id)
                .execute(db)
                .await
                .expect("insert throwaway role->team link");
            sqlx::query(
                "INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3)",
            )
            .bind(Uuid::now_v7())
            .bind(member_id)
            .bind(team_id)
            .execute(db)
            .await
            .expect("insert throwaway user->team link");
        }

        let key = format!("test.teamrolegrant.{role_id}");

        // Cheap `Arc` handle — kept alive after `system` is consumed by
        // `full_app` below, so the same resolver the HTTP layer invalidates can
        // be queried directly via `resolve_strict`.
        let security = system.state().base.security.clone();

        // Warm the cache before the grant exists — member must not see it yet.
        let before = security
            .resolve_strict(member_id)
            .await
            .expect("resolve_strict before grant");
        assert!(
            !before.privileges.contains(&key),
            "team member must not see a privilege that hasn't been granted yet"
        );

        let app = full_app(system);
        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/role-grants")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"role_id":"{role_id}","privilege_key":"{key}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create role grant");
        assert_eq!(res.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
        let grant_id = created["id"].as_str().expect("grant id").to_owned();

        // No sleep: the very next resolve_strict call must already see the
        // grant. If invalidation only reached direct role holders (the C-03
        // defect), this would still read the stale cached value for up to the
        // 60s TTL.
        let after_create = security
            .resolve_strict(member_id)
            .await
            .expect("resolve_strict after grant");
        assert!(
            after_create.privileges.contains(&key),
            "team-mediated role holder must see a role-privilege grant immediately, \
         not after the cache TTL expires"
        );

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/security/role-grants/{grant_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(delete_req).await.expect("request");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let after_delete = security
            .resolve_strict(member_id)
            .await
            .expect("resolve_strict after revoke");
        assert!(
            !after_delete.privileges.contains(&key),
            "revoking a role-privilege grant must also invalidate the team-mediated \
         holder's cache immediately"
        );
    })
}

/// End-to-end: creating an entity auto-seeds its `{logicalname}.{action}`
/// privileges (the `entity_privileges::ensure_entity_privileges` hook in
/// `admin::create_entity`); granting only `.read` to a non-admin lets them
/// read via the generic `entity_crud` API but not create.
#[test]
fn per_entity_read_grant_allows_read_but_not_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let logicalname = format!("authz_rw_{}", Uuid::now_v7().simple());

        let create_entity_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"Authz RW Test"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_entity_req)
            .await
            .expect("create entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        let entity: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
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

        let create_record_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"hello"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_record_req)
            .await
            .expect("create record");
        assert_eq!(res.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        let record: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
        let record_id = record["id"].as_str().expect("record id").to_owned();

        let (_, reader_cookie, reader_email) = {
            let user_id = Uuid::now_v7();
            let email = format!("authz-reader-{user_id}@test.local");
            sqlx::query("INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)")
            .bind(user_id)
            .bind(&email)
            .bind(format!("authz-reader-{user_id}"))
            .execute(&db)
            .await
            .expect("insert throwaway reader user");
            (user_id, session_cookie(user_id), email)
        };

        let grant_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/grants")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"user_email":"{reader_email}","privilege_key":"{logicalname}.read"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(grant_req)
            .await
            .expect("grant read privilege");
        assert_eq!(res.status(), StatusCode::CREATED);

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &reader_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get record");
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("read response body");
        assert_eq!(
            status,
            StatusCode::OK,
            "read-granted user must be able to read; response: {}",
            String::from_utf8_lossy(&body)
        );

        let create_as_reader_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &reader_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"nope"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_as_reader_req)
            .await
            .expect("create as reader");
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "a read-only grant must not allow create"
        );

        // Retire the throwaway entity. A hard delete is refused in recording
        // mode (D-785 `hard_delete_not_recordable`); the suite runs on a
        // per-binary clone database, so a soft delete leaks nothing that lasts.
        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/entities/{entity_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(delete_req).await.expect("retire request");
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("teardown body");
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "teardown: retiring the throwaway entity must succeed: {}",
            String::from_utf8_lossy(&body)
        );
    })
}

/// A non-admin read of a migration-owned entity table used to 500: the RLS
/// predicate names `organization_ref`, which `role` (0040) never had,
/// and nothing backfilled it. The per-table backfill now adds it, and the boot
/// sweep `backfill_rls_columns` heals a table that predates that backfill.
#[test]
fn non_admin_read_of_a_migration_owned_entity_is_not_a_500() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let user_id = Uuid::now_v7();
        let email = format!("authz-role-reader-{user_id}@test.local");
        sqlx::query(
            "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
        )
        .bind(user_id)
        .bind(&email)
        .bind(format!("authz-role-reader-{user_id}"))
        .execute(&db)
        .await
        .expect("insert throwaway reader");
        let reader_cookie = session_cookie(user_id);

        let grant = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/grants")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"user_email":"{email}","privilege_key":"role.read"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(grant).await.expect("grant");
        assert_eq!(res.status(), StatusCode::CREATED, "grant role.read");

        let read = |cookie: String| {
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/role/{}", Uuid::now_v7()))
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap()
        };
        let res = app
            .clone()
            .oneshot(read(reader_cookie.clone()))
            .await
            .expect("read");
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "a non-admin read of an absent role record is a 404, not a 500"
        );

        // Simulate a deployment whose table predates the backfill, then prove
        // the boot sweep heals it. Throwaway test database only.
        sqlx::query("ALTER TABLE role DROP COLUMN organization_ref")
            .execute(&db)
            .await
            .expect("drop organization_ref on the throwaway database");
        attome_metadata::provision::backfill_rls_columns(&db)
            .await
            .expect("rls column sweep");
        let has_column: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
              WHERE table_schema = current_schema() AND table_name = 'role' \
                AND column_name = 'organization_ref')",
        )
        .fetch_one(&db)
        .await
        .expect("column check");
        assert!(has_column, "the boot sweep restores organization_ref");
        let res = app
            .oneshot(read(reader_cookie))
            .await
            .expect("read after sweep");
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    })
}
