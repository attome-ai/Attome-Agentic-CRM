//! M92 Extension Management Phase 1 — `POST /api/v1/admin/metadata/bundles/
//! {name}/rollback` (`crates/engine/attome-api/src/bundle/routes.rs::rollback`)
//! against a live, seeded database. Mirrors `bundle_apply.rs`'s test
//! infrastructure (same `test_config`/`test_system`/`full_app`/`seed_admin`
//! helpers — each bundle test binary is self-contained, the repo's existing
//! convention).
//!
//! - **rollback finds and re-applies the prior succeeded snapshot** — a
//!   named/versioned bundle is applied at `1.0.0` (one entity, one
//!   attribute), then again at `2.0.0` (a second attribute added); a
//!   rollback to `1.0.0` finds the `1.0.0` ledger row (not `2.0.0`), plans
//!   it against current live metadata, and — once the queued job is run —
//!   the second attribute is retired while the first survives, matching the
//!   verticals skill's documented undo procedure exactly;
//! - **unknown version is a 404** — a `to_version` that was never
//!   successfully applied under this `name` is refused before any plan is
//!   computed;
//! - **still gated like any other apply** — the rollback plan is a real,
//!   persisted `metadata_bundle_plan` row, visible at
//!   `GET …/plans/{id}`, never a bypass of the ordinary ledger.
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same
//! convention as `bundle_apply.rs`. Run with `--test-threads=1`.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-api --test bundle_rollback -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{AttributeDef, Bundle, EntityDef, export_bundle, ledger, run_apply_job};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::{Body, to_bytes};
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
                "max_body_size_bytes": 16777216, "request_timeout_secs": 5,
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
                "db": 9, "connection_pool_size": 4, "timeout": 2000,
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

async fn seed_admin(state: &EngineState) -> (Uuid, String) {
    let db = &state.base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("bundle-rollback-test-{user_id}"))
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

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn json_request(method: &str, uri: &str, cookie: &str, body: Value) -> Request<Body> {
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

fn attr(name: &str) -> AttributeDef {
    AttributeDef {
        logicalname: name.to_owned(),
        display_name: name.to_uppercase(),
        field_type: "text".to_owned(),
        is_required: false,
        is_sensitive: false,
        is_write_restricted: false,
        is_sortable: false,
        is_filterable: false,
        lookup_entity: None,
        options: None,
        max_length: None,
        on_target_delete: "orphan".to_owned(),
        data_classification: "general".to_owned(),
        purpose: None,
        is_customized: false,
    }
}

/// Plans `bundle` through the ordinary route, asserting it is applicable,
/// and returns its `plan_id`.
async fn plan_via_route(app: &axum::Router, cookie: &str, bundle: &Bundle) -> Uuid {
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/metadata/import?mode=plan",
            cookie,
            serde_json::json!({ "bundle": bundle, "allow_retire": true }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["applicable"], Value::Bool(true), "{body:#}");
    body["plan_id"].as_str().unwrap().parse().unwrap()
}

/// Applies `plan_id` through the ordinary route (queues it; the test config
/// has no `metadata.bundle_apply` in `approval.required_actions`, so this
/// queues directly, same as `bundle_apply.rs`'s tests) and then runs the
/// durable job inline, standing in for the worker.
async fn apply_via_route_and_run(
    state: &EngineState,
    app: &axum::Router,
    cookie: &str,
    plan_id: Uuid,
) {
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/metadata/import?mode=apply",
            cookie,
            serde_json::json!({ "plan_id": plan_id }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    run_apply_job(state, plan_id)
        .await
        .expect("run_apply_job must succeed");
    let row = ledger::get_plan(&state.base.db, plan_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, ledger::PlanStatus::Succeeded, "{row:#?}");
}

#[test]
fn rollback_finds_and_reapplies_the_prior_succeeded_version() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_admin, cookie) = seed_admin(&state).await;
        let app = full_app(system);
        let db = &state.base.db;

        let tag = attome_testkit::unique("rbk");
        let bundle_name = format!("rollback-suite-{tag}");
        let entity = attome_testkit::unique_logicalname("rbk");

        let before = export_bundle(db).await.expect("export before");

        // v1.0.0: the entity with one attribute.
        let mut v1 = before.clone();
        v1.name = Some(bundle_name.clone());
        v1.version = Some("1.0.0".to_owned());
        v1.entities.push(EntityDef {
            logicalname: entity.clone(),
            display_name: "Rollback Test".to_owned(),
            primary_name_attribute: Some("a".to_owned()),
            is_append_only: false,
            is_audited: false,
            category: None,
            is_customized: false,
            attributes: vec![attr("a")],
        });
        v1.normalize();
        let plan_v1 = plan_via_route(&app, &cookie, &v1).await;
        apply_via_route_and_run(&state, &app, &cookie, plan_v1).await;

        // v2.0.0: v1 plus a second attribute.
        let mut v2 = v1.clone();
        v2.version = Some("2.0.0".to_owned());
        v2.entities
            .iter_mut()
            .find(|e| e.logicalname == entity)
            .unwrap()
            .attributes
            .push(attr("b"));
        v2.normalize();
        let plan_v2 = plan_via_route(&app, &cookie, &v2).await;
        apply_via_route_and_run(&state, &app, &cookie, plan_v2).await;

        // Sanity: live metadata now carries both attributes.
        let live = export_bundle(db).await.expect("export after v2");
        let live_entity = live
            .entities
            .iter()
            .find(|e| e.logicalname == entity)
            .expect("entity applied");
        assert_eq!(live_entity.attributes.len(), 2, "{live_entity:#?}");

        // Rolling back to a version that was never applied is a 404 before any
        // plan is computed.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                &format!("/api/v1/admin/metadata/bundles/{bundle_name}/rollback"),
                &cookie,
                serde_json::json!({ "to_version": "9.9.9", "allow_retire": true }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Rollback to 1.0.0: finds the 1.0.0 ledger row (not 2.0.0), plans it
        // against current live metadata, and queues it through the ordinary gate.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                &format!("/api/v1/admin/metadata/bundles/{bundle_name}/rollback"),
                &cookie,
                serde_json::json!({ "to_version": "1.0.0", "allow_retire": true }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "queued", "{body:#}");
        assert_eq!(body["approval_pending"], Value::Bool(false), "{body:#}");
        let rollback_plan_id: Uuid = body["plan_id"].as_str().unwrap().parse().unwrap();
        assert_ne!(rollback_plan_id, plan_v1);
        assert_ne!(rollback_plan_id, plan_v2);

        // It is a real, persisted, ordinary ledger row — visible at GET plans/{id}.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/admin/metadata/plans/{rollback_plan_id}"))
                    .header("cookie", &cookie)
                    .header("origin", "http://localhost:4200")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let row = body_json(resp).await;
        assert_eq!(row["bundle"]["version"], "1.0.0", "{row:#}");

        run_apply_job(&state, rollback_plan_id)
            .await
            .expect("rollback apply must succeed");
        let row = ledger::get_plan(db, rollback_plan_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, ledger::PlanStatus::Succeeded, "{row:#?}");

        // Live metadata is back to the 1.0.0 shape: attribute "b" is gone,
        // attribute "a" survives.
        let after_rollback = export_bundle(db).await.expect("export after rollback");
        let entity_after = after_rollback
            .entities
            .iter()
            .find(|e| e.logicalname == entity)
            .expect("entity still present");
        let names: Vec<&str> = entity_after
            .attributes
            .iter()
            .map(|a| a.logicalname.as_str())
            .collect();
        assert!(names.contains(&"a"), "{names:?}");
        assert!(!names.contains(&"b"), "{names:?}");
    })
}

#[test]
fn rollback_of_a_never_applied_name_is_a_404() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_admin, cookie) = seed_admin(&state).await;
        let app = full_app(system);

        let name = attome_testkit::unique("rbk-never-applied");
        let resp = app
            .oneshot(json_request(
                "POST",
                &format!("/api/v1/admin/metadata/bundles/{name}/rollback"),
                &cookie,
                serde_json::json!({ "to_version": "1.0.0" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    })
}
