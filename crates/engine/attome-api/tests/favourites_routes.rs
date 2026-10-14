//! B9-T2: recent records and favourites through the real middleware stack.
//!
//! - A person's lists are theirs alone: another person neither sees nor
//!   changes them (404, the same as a list that does not exist).
//! - A list is saved whole, in order; at most nine items are pinned.
//! - A team list is for the team's members: a non-member gets 404, a member
//!   sees it in `GET /api/v1/me/favourites`, and each change writes one
//!   `favourite_list` audit event.
//! - Recent opens of unknown entities are ignored, and the history clears.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`):
//!
//! ```powershell
//! cargo test -p attome-api --test favourites_routes -- --test-threads=1
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
    .bind(format!("b9-user-{user_id}"))
    .bind(attome_testkit::unique_email("b9"))
    .execute(db)
    .await
    .expect("insert throwaway user");
    user_id
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

const MINE: &str = "/api/v1/me/favourites";

async fn team_events(db: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE entity_name = 'favourite_list') \
              + (SELECT COUNT(*) FROM audit_ingest WHERE payload->>'entity_name' = 'favourite_list')",
    )
    .fetch_one(db)
    .await
    .expect("count favourite_list audit events")
}

fn lists(doc: &Value) -> &Vec<Value> {
    doc["items"].as_array().expect("a page of lists")
}

#[tokio::test]
async fn a_persons_lists_are_their_own() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (alice, bob) = (seed_user(&db).await, seed_user(&db).await);
    let (alice_cookie, bob_cookie) = (session_cookie(alice), session_cookie(bob));

    let (status, doc) = send(&app, "GET", MINE, Some(&alice_cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(lists(&doc).is_empty());

    let view = Uuid::now_v7().to_string();
    let body = json!({"name": "Mine", "items": [
        {"kind": "page", "ref": "/dashboard", "label": "Home", "pinned": true},
        {"kind": "view", "ref": view},
    ]});
    let (status, created) = send(
        &app,
        "POST",
        "/api/v1/me/favourites/lists",
        Some(&alice_cookie),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["items"][0]["ref"], "/dashboard");
    assert_eq!(created["items"][0]["pinned"], true);
    let path = format!("/api/v1/me/favourites/lists/{id}");

    // Reordered and renamed by saving the whole list.
    let reordered = json!({"name": "Renamed", "items": [
        {"kind": "view", "ref": view, "pinned": true},
        {"kind": "page", "ref": "/dashboard"},
    ]});
    let (status, saved) = send(&app, "PUT", &path, Some(&alice_cookie), Some(reordered)).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["name"], "Renamed");
    assert_eq!(saved["items"][0]["kind"], "view");
    assert_eq!(saved["items"][1]["pinned"], false);

    // Ten pins is one too many.
    let pins: Vec<Value> = (0..10)
        .map(|n| json!({"kind": "page", "ref": format!("/p{n}"), "pinned": true}))
        .collect();
    let (status, _) = send(
        &app,
        "PUT",
        &path,
        Some(&alice_cookie),
        Some(json!({"name": "Too many", "items": pins})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Bob neither sees nor touches it.
    let (_, doc) = send(&app, "GET", MINE, Some(&bob_cookie), None).await;
    assert!(lists(&doc).is_empty(), "{doc}");
    let (status, _) = send(
        &app,
        "PUT",
        &path,
        Some(&bob_cookie),
        Some(json!({"name": "Mine now", "items": []})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, "DELETE", &path, Some(&bob_cookie), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send(&app, "DELETE", &path, Some(&alice_cookie), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, doc) = send(&app, "GET", MINE, Some(&alice_cookie), None).await;
    assert!(lists(&doc).is_empty(), "{doc}");
}

#[tokio::test]
async fn team_lists_are_for_members_and_audited() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (member, outsider) = (seed_user(&db).await, seed_user(&db).await);
    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(team_id)
        .bind(format!("b9-team-{team_id}"))
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(member)
        .bind(team_id)
        .execute(&db)
        .await
        .unwrap();
    let (member_cookie, outsider_cookie) = (session_cookie(member), session_cookie(outsider));
    let lists_path = format!("/api/v1/teams/{team_id}/favourites/lists");
    let body = json!({"name": "Team", "items": [{"kind": "page", "ref": "/pipeline"}]});

    let (status, _) = send(
        &app,
        "POST",
        &lists_path,
        Some(&outsider_cookie),
        Some(body.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-member cannot add to the team"
    );

    let before = team_events(&db).await;
    let (status, created) = send(&app, "POST", &lists_path, Some(&member_cookie), Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["team_id"], team_id.to_string());
    assert_eq!(
        team_events(&db).await,
        before + 1,
        "the team list's creation is audited"
    );

    let (_, doc) = send(&app, "GET", MINE, Some(&member_cookie), None).await;
    assert_eq!(lists(&doc).len(), 1, "{doc}");
    let (_, doc) = send(&app, "GET", MINE, Some(&outsider_cookie), None).await;
    assert!(lists(&doc).is_empty(), "{doc}");

    let path = format!("{lists_path}/{}", created["id"].as_str().unwrap());
    let (status, _) = send(&app, "DELETE", &path, Some(&outsider_cookie), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, "DELETE", &path, Some(&member_cookie), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        team_events(&db).await,
        before + 2,
        "the deletion is audited"
    );
}

#[tokio::test]
async fn recent_ignores_unknown_entities_and_clears() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let cookie = session_cookie(seed_user(&db).await);

    let report = json!({"items": [{"entity": "no_such_entity", "record_id": Uuid::now_v7()}]});
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/me/recent",
        Some(&cookie),
        Some(report),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, doc) = send(&app, "GET", "/api/v1/me/recent", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert!(doc["items"].as_array().unwrap().is_empty(), "{doc}");

    let too_many: Vec<Value> = (0..51)
        .map(|_| json!({"entity": "x", "record_id": Uuid::now_v7()}))
        .collect();
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/me/recent",
        Some(&cookie),
        Some(json!({"items": too_many})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = send(&app, "DELETE", "/api/v1/me/recent", Some(&cookie), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
