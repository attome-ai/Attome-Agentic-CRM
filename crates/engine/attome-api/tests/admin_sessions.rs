//! Q8-T5: an administrator's session lists and revocations through the
//! assembled router: one person's sessions, every session narrowed to a
//! role's holders, ending one session, all of a person's (with the epoch
//! moving on in the same call), and all of a role's holders' — in the
//! request for a small role and through the batched job otherwise, which
//! never ends a sign-in made after the request.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), as `account_disable.rs` does.
//!
//! ```powershell
//! cargo test -p attome-api --test admin_sessions -- --test-threads=1
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

async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("disable-test-admin-{user_id}"))
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

async fn fetch_epoch(db: &attome_db::DbPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT auth_epoch FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("fetch auth_epoch")
}

async fn seed_user(system: &TestSystem, label: &str) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', true)",
    )
    .bind(user_id)
    .bind(format!("admin-sessions-{label}-{user_id}"))
    .execute(&system.state().base.db)
    .await
    .expect("insert throwaway user_account");
    user_id
}

/// A real refresh family for `user_id`, as a sign-in starts one.
async fn sign_in(system: &TestSystem, user_id: Uuid) -> Uuid {
    let state = &system.state().base;
    attome_auth::refresh::issue(
        &state.db,
        user_id,
        &attome_auth::auth_context::AuthContext::password(),
        attome_auth::refresh::RefreshLifetimes {
            idle_secs: state.config.refresh_token_expiry_secs(),
            absolute_secs: state.config.refresh_absolute_lifetime_secs(),
        },
        &state.pepper_ring(),
    )
    .await
    .expect("issue a refresh family")
    .family_id
}

async fn live_families(system: &TestSystem, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM refresh_token \
          WHERE user_ref = $1 AND revoked_at IS NULL AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(user_id)
    .fetch_one(&system.state().base.db)
    .await
    .expect("count live families")
}

async fn call(
    system: &TestSystem,
    method: &str,
    uri: &str,
    cookie: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    let res = full_app(system.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON body")
    };
    (status, body)
}

#[test]
fn admin_lists_user_sessions() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let target = seed_user(&system, "listed").await;
        let first = sign_in(&system, target).await;
        let second = sign_in(&system, target).await;
        let bystander = seed_user(&system, "bystander").await;
        sign_in(&system, bystander).await;

        let (status, body) = call(
            &system,
            "GET",
            &format!("/api/v1/admin/security/users/{target}/sessions"),
            &admin,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 2, "the person's two sessions only");
        let ids: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap().to_owned())
            .collect();
        assert!(ids.contains(&first.to_string()) && ids.contains(&second.to_string()));
        for item in body["items"].as_array().unwrap() {
            assert_eq!(item["user_id"], target.to_string());
            assert!(item["user_email"].is_string());
            assert!(item.get("secret_hash").is_none() && item.get("jti").is_none());
        }

        // Ending one leaves the other.
        let (status, _) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/security/sessions/{first}"),
            &admin,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(live_families(&system, target).await, 1);
        let (status, _) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/security/sessions/{first}"),
            &admin,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "an ended session is gone");

        // A person without the users privilege is refused.
        let plain = seed_user(&system, "plain").await;
        let (status, _) = call(
            &system,
            "GET",
            &format!("/api/v1/admin/security/users/{target}/sessions"),
            &session_cookie(plain),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

#[test]
fn revoke_all_bumps_epoch() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let target = seed_user(&system, "revoke-all").await;
        sign_in(&system, target).await;
        sign_in(&system, target).await;
        let db = system.state().base.db.clone();
        let before = fetch_epoch(&db, target).await;

        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/security/users/{target}/sessions/revoke-all"),
            &admin,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["queued"], false);
        assert_eq!(
            live_families(&system, target).await,
            0,
            "every session ended"
        );
        assert_eq!(
            fetch_epoch(&db, target).await,
            before + 1,
            "the epoch moves on in the same call, so access tokens stop too"
        );
    });
}

#[test]
fn role_revoke_ends_all_holders() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let role_id = Uuid::now_v7();
        sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'customer')")
            .bind(role_id)
            .bind(format!("q8-t5-role-{role_id}"))
            .execute(&db)
            .await
            .expect("insert role");
        let holders = [
            seed_user(&system, "holder-a").await,
            seed_user(&system, "holder-b").await,
        ];
        for holder in holders {
            sqlx::query(
                "INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)",
            )
            .bind(Uuid::now_v7())
            .bind(holder)
            .bind(role_id)
            .execute(&db)
            .await
            .expect("grant role");
            sign_in(&system, holder).await;
        }
        let outsider = seed_user(&system, "outsider").await;
        sign_in(&system, outsider).await;

        let (status, body) = call(
            &system,
            "GET",
            &format!("/api/v1/admin/security/sessions?role_id={role_id}"),
            &admin,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 2, "the role filter lists only holders");

        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/security/roles/{role_id}/sessions/revoke-all"),
            &admin,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ended_users"], 2);
        assert_eq!(body["queued"], false, "two holders fit in the request");
        for holder in holders {
            assert_eq!(live_families(&system, holder).await, 0);
            assert_eq!(fetch_epoch(&db, holder).await, 1);
        }
        assert_eq!(
            live_families(&system, outsider).await,
            1,
            "a non-holder keeps theirs"
        );

        // The job path does the same in batches, and only to sessions
        // started before the request.
        let later = sign_in(&system, holders[0]).await;
        let cutoff: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT NOW() - interval '1 second'")
                .fetch_one(&db)
                .await
                .unwrap();
        let ended =
            attome_security::admin::revoke_role_sessions_job(system.state(), role_id, cutoff)
                .await
                .expect("the job runs");
        assert_eq!(ended, 0, "a sign-in after the cutoff is kept");
        assert_eq!(live_families(&system, holders[0]).await, 1);
        let _ = later;
    });
}
