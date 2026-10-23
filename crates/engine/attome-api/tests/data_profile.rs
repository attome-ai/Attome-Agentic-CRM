//! L6-T6: a staged import is profiled before it is applied, and a holder of
//! `metadata.read` (not an administrator) reads the profile without the
//! sensitive attribute their field security hides.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), as `attribute_retire.rs`.
//!
//! ```powershell
//! cargo test -p attome-api --test data_profile -- --test-threads=1
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

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
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

async fn seed_user(system: &TestSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("attribute-retire-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

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

    session_cookie(user_id)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn json_request(method: &str, uri: String, cookie: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn grant(db: &attome_db::DbPool, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        db,
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(db)
    .await
    .unwrap();
}

#[test]
fn file_profile_and_non_admin_reader() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_user(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);

        let entity = format!("dpf_{}", Uuid::now_v7().simple());
        let (status, created) = send(
            &app,
            json_request(
                "POST",
                "/api/v1/admin/entities".into(),
                &admin_cookie,
                serde_json::json!({ "logicalname": entity, "name": "File Profile Test" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        for (name, sensitive) in [("title", false), ("national_id", true)] {
            let (status, body) = send(
                &app,
                json_request(
                    "POST",
                    format!("/api/v1/admin/entities/{entity_id}/fields"),
                    &admin_cookie,
                    serde_json::json!({ "logicalname": name, "name": name, "field_type": "text", "is_sensitive": sensitive }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }

        // A reader who may read the entity and its metadata, not an admin.
        let reader = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_account (id, user_name, email, is_active) \
             VALUES ($1, $2, $2 || '@test.invalid', true)",
        )
        .bind(reader)
        .bind(format!("profile-reader-{reader}"))
        .execute(&db)
        .await
        .unwrap();
        grant(&db, reader, "metadata.read").await;
        grant(&db, reader, &format!("{entity}.read")).await;
        let reader_cookie = session_cookie(reader);

        // The reader's import, staged with three rows.
        let job = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                     mapping, match_mode, status, created_by) \
             VALUES ($1, $2, 'test/key', 'people.csv', $3, '{}', 'create', 'staged', $4)",
        )
        .bind(job)
        .bind(&entity)
        .bind(job.to_string())
        .bind(reader)
        .execute(&db)
        .await
        .unwrap();
        for (i, (title, id)) in [
            ("Sara", "1045678909"),
            ("Omar", "2123456788"),
            ("", "1045678909"),
        ]
        .into_iter()
        .enumerate()
        {
            sqlx::query("INSERT INTO import_stage (job_id, row_no, raw) VALUES ($1, $2, $3)")
                .bind(job)
                .bind(i as i32)
                .bind(serde_json::json!({ "title": title, "national_id": id }))
                .execute(&db)
                .await
                .unwrap();
        }

        let (status, queued) = send(
            &app,
            json_request(
                "POST",
                "/api/v1/data/profile:file".into(),
                &reader_cookie,
                serde_json::json!({ "import_job_id": job }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        let profile_id: Uuid = queued["id"].as_str().unwrap().parse().unwrap();
        attome_api::data_profile_admin::process(
            &state,
            attome_core::jobs::DataProfilePayload {
                profile_id,
                entity_logicalname: entity.clone(),
                user_id: reader,
                full_scan: true,
                import_job_id: Some(job),
            },
        )
        .await
        .expect("profile the staged rows");

        let read = |cookie: String| {
            let app = app.clone();
            async move {
                send(
                    &app,
                    Request::builder()
                        .uri(format!("/api/v1/admin/data/profile/{profile_id}"))
                        .header("cookie", cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
            }
        };
        let (status, seen) = read(reader_cookie.clone()).await;
        assert_eq!(status, StatusCode::OK, "{seen}");
        assert_eq!(seen["status"], "completed", "{seen}");
        assert_eq!(seen["import_job_ref"], job.to_string());
        assert_eq!(seen["row_count"], 3);
        let fields: Vec<&str> = seen["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["field"].as_str())
            .collect();
        assert_eq!(
            fields,
            vec!["title"],
            "the sensitive column is hidden: {seen}"
        );
        let title = &seen["fields"][0];
        assert_eq!(title["rows"], 3);
        assert_eq!(title["blanks"], 1);

        // The administrator sees both columns, the sensitive one masked.
        let (_, full) = read(admin_cookie.clone()).await;
        let names: Vec<&str> = full["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["field"].as_str())
            .collect();
        assert_eq!(names, vec!["national_id", "title"]);
        assert_eq!(full["fields"][0]["masked"], true);

        // Without metadata.read, no profile.
        let other = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_account (id, user_name, email, is_active) \
             VALUES ($1, $2, $2 || '@test.invalid', true)",
        )
        .bind(other)
        .bind(format!("profile-other-{other}"))
        .execute(&db)
        .await
        .unwrap();
        let (status, _) = read(session_cookie(other)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
}
