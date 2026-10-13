//! D-535 — regression coverage for
//! `attome_records::entity_mutation::validate_engine_owned_entity`: an API
//! key is minted only through `POST /api/v1/auth/api-keys`, behind D-510's
//! step-up guard. Generic entity CRUD must therefore refuse to create, change
//! or restore `api_key` rows, even for a system admin (who holds every
//! privilege and every field-write grant), while generic delete still revokes.
//!
//! Harness copied from `engine_managed_fields.rs` (this repo's per-test-file
//! convention).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`).
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test engine_owned_entities -- --test-threads=1
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
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const API_KEY_ENTITY: &str = "api_key";
const REFUSAL: &str =
    "validation error: api_key records are managed by their owning engine; use its routes";

// ── Harness ──────────────────────────────────────────────────────────────────

fn test_config(db: &DbUrlParts) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }}
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
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Registers `SecurityModel`, whose `engine_owned_entities()` declaration is
/// what `EngineState::engine_owned_entities` is built from. Returns the frozen
/// state alongside the assembled router (`core_routes` consumes the system).
async fn test_app() -> Option<(EngineState, axum::Router)> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let config = test_config(&db_parts);
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
    // `api_key` is registered as an entity by the server binary's boot
    // (`crates/server/src/boot.rs`), not by `EngineSystem::build`. Apply the same
    // platform bundle, under the licence just stored (it requires `core`), so
    // the generic routes can reach the entity.
    attome_api::bundle::apply_platform_bundle(
        system.state(),
        "api_key",
        include_str!("../../../../platform-bundles/xrm-core-api_key.json"),
    )
    .await
    .expect("apply the api_key platform bundle");

    let state = system.state().clone();
    let base_state = state.base.clone();
    let app = attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    Some((state, app))
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

/// A system admin: holds every privilege and every field-write grant, so
/// nothing but D-535 stands between it and a generic write.
async fn seed_admin(state: &EngineState) -> (Uuid, String) {
    let db = &state.base.db;
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("engine-owned-entities-{user_id}@test.local"))
    .bind(format!("engine-owned-entities-{user_id}"))
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

    (user_id, session_cookie(user_id))
}

/// A key row as the owning route writes it, straight to the throwaway
/// database.
async fn seed_key(state: &EngineState, owner: Uuid) -> Uuid {
    let base = &state.base;
    let public_key = format!("atk_pub_owned{}", Uuid::now_v7().simple());
    let secret_hash = base.pepper_ring().hash("atk_sec_throwaway");
    sqlx::query_scalar(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING id",
    )
    .bind(owner)
    .bind("engine-owned seed")
    .bind(&public_key)
    .bind(&secret_hash)
    .fetch_one(&base.db)
    .await
    .expect("insert throwaway api key")
}

/// `(user_ref, name, public_key, secret_hash, is_active)` of a key row.
async fn key_row(state: &EngineState, id: Uuid) -> (Uuid, String, String, String, bool) {
    sqlx::query_as(
        "SELECT user_ref, name, public_key, secret_hash, is_active FROM api_key WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .expect("key row")
}

async fn key_count_with_public_key(state: &EngineState, public_key: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE public_key = $1")
        .bind(public_key)
        .fetch_one(&state.base.db)
        .await
        .expect("count keys")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn req(method: &str, uri: &str, cookie: &str, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(match body {
            Some(v) => Body::from(v.to_string()),
            None => Body::empty(),
        })
        .unwrap()
}

async fn assert_refused(res: axum::response::Response, what: &str) {
    let status = res.status();
    let seen = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{what} must be refused: {seen:?}"
    );
    assert_eq!(seen["message"], REFUSAL, "{what}: {seen:?}");
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_security_model_declares_the_api_key_entity_engine_owned() {
    let (state, _app) = skip_if_no_db!(test_app().await);
    assert!(
        state.engine_owned_entities.contains(API_KEY_ENTITY),
        "SecurityModel's declaration must be frozen into EngineState at boot"
    );
}

#[tokio::test]
async fn generic_create_of_an_api_key_is_refused_even_for_an_admin() {
    let (state, app) = skip_if_no_db!(test_app().await);
    let (admin, cookie) = seed_admin(&state).await;
    let public_key = format!("atk_pub_forged{}", Uuid::now_v7().simple());

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{API_KEY_ENTITY}"),
            &cookie,
            Some(&json!({
                "user_ref": admin,
                "name": "forged",
                "public_key": public_key,
                "secret_hash": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
            })),
        ))
        .await
        .unwrap();
    assert_refused(res, "a generic create").await;
    assert_eq!(
        key_count_with_public_key(&state, &public_key).await,
        0,
        "no key row may exist after a refused create"
    );
}

#[tokio::test]
async fn generic_update_of_an_api_key_is_refused_even_for_an_admin() {
    let (state, app) = skip_if_no_db!(test_app().await);
    let (admin, cookie) = seed_admin(&state).await;
    let (victim, _) = seed_admin(&state).await;
    let id = seed_key(&state, admin).await;
    let before = key_row(&state, id).await;

    for (what, patch) in [
        ("re-pointing user_ref", json!({ "user_ref": victim })),
        ("rewriting secret_hash", json!({ "secret_hash": "forged" })),
        ("renaming", json!({ "name": "renamed" })),
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/v1/{API_KEY_ENTITY}/{id}"))
                    .header("cookie", &cookie)
                    .header("origin", "http://localhost:4200")
                    .header("sec-fetch-site", "same-origin")
                    .header("content-type", "application/json")
                    .header("if-match", "\"1\"")
                    .body(Body::from(patch.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_refused(res, what).await;
        assert_eq!(key_row(&state, id).await, before, "{what} changed nothing");
    }
}

#[tokio::test]
async fn generic_upsert_of_an_api_key_is_refused_even_for_an_admin() {
    let (state, app) = skip_if_no_db!(test_app().await);
    let (admin, cookie) = seed_admin(&state).await;
    let public_key = format!("atk_pub_upsert{}", Uuid::now_v7().simple());

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{API_KEY_ENTITY}/upsert"),
            &cookie,
            Some(&json!({
                "match": { "public_key": public_key },
                "data": { "user_ref": admin, "name": "upserted", "secret_hash": "forged" },
            })),
        ))
        .await
        .unwrap();
    assert_refused(res, "a generic upsert").await;
    assert_eq!(key_count_with_public_key(&state, &public_key).await, 0);
}

#[tokio::test]
async fn generic_delete_still_revokes_and_restore_is_refused() {
    let (state, app) = skip_if_no_db!(test_app().await);
    let (admin, cookie) = seed_admin(&state).await;
    let id = seed_key(&state, admin).await;

    let res = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/{API_KEY_ENTITY}/{id}"),
            &cookie,
            None,
        ))
        .await
        .unwrap();
    let status = res.status();
    let seen = body_json(res).await;
    assert!(
        status.is_success(),
        "a generic delete only removes access and stays allowed: {status} {seen:?}"
    );
    assert!(!key_row(&state, id).await.4, "the key is revoked");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{API_KEY_ENTITY}/{id}/restore"),
            &cookie,
            None,
        ))
        .await
        .unwrap();
    assert_refused(res, "restoring a revoked key").await;
    assert!(
        !key_row(&state, id).await.4,
        "a refused restore leaves the key revoked"
    );
}
