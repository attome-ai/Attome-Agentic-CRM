//! End-to-end money-path test for `POST /api/v1/search/aggregate`
//! (`attome-search::aggregate`) through the **full assembled middleware
//! stack** — same reasoning as `search_routes.rs`: a unit test of the pure
//! WHERE-builder cannot prove the route is actually reachable, licensed
//! correctly, and wired to a real entity's physical table via the live
//! metadata registry.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-api --test search_aggregate -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::sync::Arc;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// Same shape `search_routes.rs::seed_admin` uses — `SecurityContext::
/// is_admin` derives from holding `system.admin`, not a column.
async fn seed_admin(db: &attome_db::DbPool) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("search-aggregate-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin must already be seeded by attome_security::seed::seed");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege \
            (id, user_ref, privilege_ref, is_active, created_at) \
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

fn test_config(db: &DbUrlParts) -> AppConfig {
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
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<(EngineSystem, attome_db::DbPool)> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let config = test_config(&DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse"));
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

    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    let license = ModuleSet::from_bits([u64::MAX; 4]);
    state.modules.store(Arc::new(license));

    let system = EngineSystem::builder(state)
        .register(attome_search::SearchModel)
        .build()
        .await
        .expect("build EngineSystem");
    Some((system, db))
}

async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
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

async fn post(app: &axum::Router, path: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Provisions a throwaway entity with a `region` (text) and `amount`
/// (number) attribute, inserts rows across three regions, and refreshes the
/// in-process registry `run_aggregate` reads its attribute whitelist from —
/// `attome_core::build_registry` is the same function `EngineSystem::build()`
/// calls at boot and every metadata-mutation path calls after a write.
async fn seed_deal_entity(db: &attome_db::DbPool, state: &EngineState) -> String {
    let logicalname = format!("test_agg_deal_{}", Uuid::now_v7().simple());
    let entity_id =
        attome_metadata::provision::ensure_entity(db, &logicalname, "Deal", None, false)
            .await
            .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        db, entity_id, "region", "Region", "text", false, false, false, true, None, None,
    )
    .await
    .expect("provision region attribute");
    attome_metadata::provision::ensure_attribute(
        db, entity_id, "amount", "Amount", "number", false, false, false, true, None, None,
    )
    .await
    .expect("provision amount attribute");

    for (region, amount) in [("GCC", 100.0), ("GCC", 50.0), ("EU", 30.0), ("APAC", 10.0)] {
        sqlx::query(&format!(
            "INSERT INTO \"{logicalname}\" (region, amount) VALUES ($1, $2)"
        ))
        .bind(region)
        .bind(amount)
        .execute(db)
        .await
        .expect("seed a deal row");
    }

    let registry = attome_core::build_registry(db)
        .await
        .expect("build_registry");
    state.entities.swap(registry);

    logicalname
}

/// The money path: group `amount` by `region` with `SUM`, over real data,
/// through the real HTTP route. Three regions in, three buckets out, GCC's
/// sum reflecting both of its rows.
#[tokio::test]
async fn aggregate_sums_amount_grouped_by_region_over_http() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let cookie = seed_admin(&db).await;
    let logicalname = seed_deal_entity(&db, system.state()).await;
    let app = full_app(system);

    let (status, body) = post(
        &app,
        "/api/v1/search/aggregate",
        &cookie,
        json!({
            "entity": logicalname,
            "group_by": "region",
            "metric_fn": "sum",
            "metric_field": "amount",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let buckets = body["buckets"].as_array().expect("buckets");
    assert_eq!(buckets.len(), 3, "{body}");
    let gcc = buckets
        .iter()
        .find(|b| b["label"] == "GCC")
        .unwrap_or_else(|| panic!("GCC bucket missing: {body}"));
    assert_eq!(gcc["value"], 150.0, "{body}");
    assert_eq!(body["bucket_count"], 3, "{body}");
    assert_eq!(body["truncated"], false, "{body}");
}

/// `count` needs no `metric_field` at all — the other supported shape.
#[tokio::test]
async fn aggregate_counts_rows_grouped_by_region_over_http() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let cookie = seed_admin(&db).await;
    let logicalname = seed_deal_entity(&db, system.state()).await;
    let app = full_app(system);

    let (status, body) = post(
        &app,
        "/api/v1/search/aggregate",
        &cookie,
        json!({
            "entity": logicalname,
            "group_by": "region",
            "metric_fn": "count",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let gcc = body["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["label"] == "GCC")
        .unwrap_or_else(|| panic!("GCC bucket missing: {body}"));
    assert_eq!(gcc["value"], 2.0, "{body}");
}

/// No `group_by` at all — a single ungrouped total (the "Total Revenue"
/// Metric-widget shape), summing every row the filters admit.
#[tokio::test]
async fn aggregate_with_no_group_by_returns_one_ungrouped_bucket() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let cookie = seed_admin(&db).await;
    let logicalname = seed_deal_entity(&db, system.state()).await;
    let app = full_app(system);

    let (status, body) = post(
        &app,
        "/api/v1/search/aggregate",
        &cookie,
        json!({
            "entity": logicalname,
            "metric_fn": "sum",
            "metric_field": "amount",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let buckets = body["buckets"].as_array().expect("buckets");
    assert_eq!(buckets.len(), 1, "{body}");
    assert_eq!(buckets[0]["label"], Value::Null, "{body}");
    assert_eq!(buckets[0]["value"], 190.0, "{body}");
    assert_eq!(body["truncated"], false, "{body}");
}

/// A non-numeric field must be refused for `sum` rather than producing a
/// database type error the caller cannot act on.
#[tokio::test]
async fn aggregate_rejects_a_non_numeric_metric_field() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let cookie = seed_admin(&db).await;
    let logicalname = seed_deal_entity(&db, system.state()).await;
    let app = full_app(system);

    let (status, body) = post(
        &app,
        "/api/v1/search/aggregate",
        &cookie,
        json!({
            "entity": logicalname,
            "group_by": "region",
            "metric_fn": "sum",
            "metric_field": "region",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

/// License gating at the route level — same reasoning as
/// `search_routes.rs`'s equivalent: an unlicensed `search` module must hide
/// this route regardless of `report`'s state, since aggregation is mounted
/// under `MODULE_SEARCH`.
#[tokio::test]
async fn aggregate_is_hidden_when_search_is_unlicensed() {
    let (system, db) = skip_if_no_db!(test_system().await);
    system
        .state()
        .modules
        .store(Arc::new(ModuleSet::core_only()));
    let cookie = seed_admin(&db).await;
    let app = full_app(system);

    let (status, _body) = post(
        &app,
        "/api/v1/search/aggregate",
        &cookie,
        json!({ "entity": "user_account", "group_by": "id", "metric_fn": "count" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
