//! AG1-T3: the `hijri_month` table and `attome_calendar::hijri` agree, and
//! an administrator's moon-sighting correction moves a month in both.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`):
//!
//! ```powershell
//! cargo test -p attome-api --test hijri_reference -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool; production code uses attome_db::tx::begin"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::NaiveDate;
use serde_json::{Value, json};
use sqlx::PgPool;
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
                "connection_number": 8, "timeout": 5.0
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
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
    let system = EngineSystem::builder(EngineState::new(base))
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

async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
}

fn full_app(system: EngineSystem) -> axum::Router {
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

async fn seed_user(db: &PgPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("ag1-user-{user_id}"))
    .bind(attome_testkit::unique_email("ag1"))
    .execute(db)
    .await
    .expect("insert throwaway user");
    user_id
}

async fn seed_admin(db: &PgPool) -> (Uuid, String) {
    let user_id = seed_user(db).await;
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant system.admin");
    (user_id, session_cookie(user_id))
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let req = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn sql_reference_matches_rust_table() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let calendar = attome_core::hijri_store::load_hijri(&db).await.unwrap();
    let rows: Vec<(i16, i16, NaiveDate, NaiveDate)> = sqlx::query_as(
        "SELECT hijri_year, hijri_month, gregorian_start, gregorian_end FROM hijri_month \
         ORDER BY hijri_year, hijri_month",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(rows.len(), (1500 - 1356 + 1) * 12);
    for (year, month, start, end) in rows {
        let bounds = calendar
            .month_bounds(u16::try_from(year).unwrap(), u8::try_from(month).unwrap())
            .unwrap();
        assert_eq!(bounds, (start, end), "{year}-{month}");
    }
}

#[tokio::test]
async fn sighting_correction_moves_month_start() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (_, admin_cookie) = seed_admin(&db).await;
    let user_cookie = session_cookie(seed_user(&db).await);

    // A month whose start can move one day later: the month before has 29
    // days and it has 30, in the calendar as it stands.
    let current = attome_core::hijri_store::load_hijri(&db).await.unwrap();
    let year = 1462u16;
    let length = |m| current.month_length(year, m).unwrap();
    let month = (2..=12u8)
        .find(|&m| length(m - 1) == 29 && length(m) == 30)
        .expect("a 29-day month followed by a 30-day one");
    let (start, end) = current.month_bounds(year, month).unwrap();
    let moved = start.succ_opt().unwrap();
    let path = format!("/api/v1/admin/hijri-months/{year}/{month}");
    let body = json!({"gregorian_start": moved, "reason": "Supreme Court announcement"});

    let (status, _) = send(&app, "PUT", &path, Some(&user_cookie), Some(body.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "administrators only");

    let too_far = json!({"gregorian_start": moved.succ_opt().unwrap(), "reason": "x"});
    let (status, _) = send(&app, "PUT", &path, Some(&admin_cookie), Some(too_far)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "two days is a data error"
    );

    let (status, doc) = send(&app, "PUT", &path, Some(&admin_cookie), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let row = &doc["items"][usize::from(month) - 1];
    assert_eq!(row["gregorian_start"], moved.to_string());
    assert_eq!(row["source"], "sighting");
    let previous = &doc["items"][usize::from(month) - 2];
    assert_eq!(previous["gregorian_end"], moved.to_string());

    // The serving node uses it at once, and the SQL table agrees.
    let live = state.hijri.load();
    assert_eq!(live.month_bounds(year, month).unwrap(), (moved, end));
    assert_eq!(live.to_hijri(start).unwrap().month, month - 1);
    let reloaded = attome_core::hijri_store::load_hijri(&db).await.unwrap();
    assert_eq!(reloaded.month_bounds(year, month).unwrap(), (moved, end));

    // Undo it, so the rest of the database matches the published table.
    let back = json!({"gregorian_start": start, "reason": "test cleanup"});
    let (status, _) = send(&app, "PUT", &path, Some(&admin_cookie), Some(back)).await;
    assert_eq!(status, StatusCode::OK);
}
