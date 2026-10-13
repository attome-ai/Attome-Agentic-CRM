//! M15 (Data Governance, D-413) — live-database HTTP coverage for
//! `attome_compliance::governance_admin`: domain CRUD, entity<->domain
//! assignment, the `resolve_steward_for_domain` hook wired into
//! `legal_hold_admin::place_hold`, and the accountability report endpoint's
//! contract (right shape, classification breakdown matches known seeded
//! data — the plan's own §5 acceptance criterion).
//!
//! No object store is required (unlike `dsr_admin.rs`/`retention.rs`): this
//! surface never touches `state.base.storage`, so `test_config` below uses
//! placeholder `"test"`/`"test"` S3 credentials, matching
//! `sidebar_admin.rs`/`jobs_admin.rs`'s lighter template rather than
//! `dsr_admin.rs`'s.
//!
//! Requires a live Postgres (`DATABASE_URL`, `APP_ENV=debug`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — see `db-and-migrations`/
//! `testing` skills. `DATABASE_URL`'s target schema must already have
//! migration 0171 applied (`data_domain` /
//! `entity_info.domain_ref`).
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3D<migrated_schema>"
//! cargo test -p attome-api --test governance_admin -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::{EngineState, build_registry};
use attome_metadata::provision::{ensure_attribute, ensure_entity};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
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

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("governance-admin-test-{user_id}"))
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

/// Provisions a throwaway entity with one TEXT attribute set to the given
/// `data_classification`, and refreshes the arc-swap registry synchronously
/// — same caveat `dsr_admin.rs::provision_test_entity` documents.
async fn provision_classified_entity(
    state: &EngineState,
    prefix: &str,
    classification: &str,
) -> String {
    let db = &state.base.db;
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(db, &logicalname, "Governance Test Entity", None, false)
        .await
        .expect("ensure_entity");
    let attr_id = ensure_attribute(
        db, entity_id, "notes", "Notes", "text", false, false, false, true, None, None,
    )
    .await
    .expect("ensure_attribute notes");
    sqlx::query("UPDATE attribute_info SET data_classification = $1 WHERE id = $2")
        .bind(classification)
        .bind(attr_id)
        .execute(db)
        .await
        .expect("set data_classification for test attribute");

    let fresh_registry = build_registry(db).await.expect("build_registry");
    state.entities.swap(fresh_registry);
    logicalname
}

fn req_json(method: &str, uri: &str, cookie: &str, body: Option<Value>) -> Request<Body> {
    let payload = body.unwrap_or(Value::Null);
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(if payload.is_null() {
            String::new()
        } else {
            payload.to_string()
        }))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

/// Plan §5 acceptance criterion: the report endpoint returns the right
/// shape, and its classification breakdown matches known seeded test data —
/// one `general` attribute and one `sensitive_special_category` attribute
/// across the domain's two entities. Also covers the entity-assignment round
/// trip and legal-hold-touching-domain reporting in the same flow to avoid
/// re-provisioning entities per assertion.
#[test]
fn domain_report_reflects_classification_breakdown_entities_and_holds() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_id, admin_cookie) = seed_admin(&db).await;

        let entity_general = provision_classified_entity(&state, "gov_general", "general").await;
        let entity_sensitive =
            provision_classified_entity(&state, "gov_sensitive", "sensitive_special_category")
                .await;

        let app = full_app(system);

        // Create the domain with this admin as steward.
        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/api/v1/admin/governance/domains",
                &admin_cookie,
                Some(json!({
                    "name": format!("Test Domain {}", Uuid::now_v7()),
                    "description": "governance report contract test",
                    "steward_ref": admin_id,
                })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let domain = body_json(resp).await;
        let domain_id: Uuid = domain["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            domain["steward_ref"].as_str().unwrap(),
            admin_id.to_string()
        );

        // Assign both entities to the domain.
        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
                &admin_cookie,
                Some(json!({ "entity_logicalnames": [entity_general, entity_sensitive] })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let assigned = body_json(resp).await;
        assert_eq!(assigned.as_array().unwrap().len(), 2);

        // Placing a legal hold on one of the domain's entities resolves this
        // domain's steward (the M15 steward-defaulting hook).
        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/api/v1/admin/legal-holds",
                &admin_cookie,
                Some(json!({
                    "entity_logicalname": entity_sensitive,
                    "matter_reference": "gov-test-matter-1",
                })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let hold = body_json(resp).await;
        assert_eq!(
            hold["resolved_steward_ref"].as_str().unwrap(),
            admin_id.to_string(),
            "the hold's entity is in a domain whose steward is this admin"
        );
        assert_eq!(hold["entity_logicalname"], entity_sensitive);

        // The accountability report.
        let resp = app
            .clone()
            .oneshot(req_json(
                "GET",
                &format!("/api/v1/admin/governance/domains/{domain_id}/report"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let report = body_json(resp).await;

        assert_eq!(report["domain_id"].as_str().unwrap(), domain_id.to_string());
        assert_eq!(
            report["steward_ref"].as_str().unwrap(),
            admin_id.to_string()
        );

        let entities = report["entities"].as_array().expect("entities array");
        assert_eq!(entities.len(), 2);
        let entity_names: Vec<&str> = entities
            .iter()
            .map(|e| e["logicalname"].as_str().unwrap())
            .collect();
        assert!(entity_names.contains(&entity_general.as_str()));
        assert!(entity_names.contains(&entity_sensitive.as_str()));

        let breakdown = &report["classification_breakdown"];
        assert_eq!(breakdown["general"], 1, "breakdown: {breakdown}");
        assert_eq!(breakdown["personal"], 0, "breakdown: {breakdown}");
        assert_eq!(
            breakdown["sensitive_special_category"], 1,
            "breakdown: {breakdown}"
        );

        assert_eq!(
            report["open_issues"].as_array().unwrap().len(),
            0,
            "M13/M14 don't exist yet — always empty"
        );

        let holds = report["legal_holds"].as_array().expect("legal_holds array");
        assert_eq!(holds.len(), 1);
        assert_eq!(holds[0]["entity_logicalname"], entity_sensitive);
        assert_eq!(holds[0]["matter_reference"], "gov-test-matter-1");

        assert!(report["last_review_date"].is_string());
    })
}

/// `PATCH`'s optimistic-concurrency contract: a stale `row_version` is `409`,
/// and the correct one actually updates and bumps `row_version`.
#[test]
fn update_domain_enforces_optimistic_concurrency() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/api/v1/admin/governance/domains",
                &admin_cookie,
                Some(json!({ "name": format!("OCC Domain {}", Uuid::now_v7()) })),
            ))
            .await
            .unwrap();
        let domain = body_json(resp).await;
        let domain_id: Uuid = domain["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(domain["row_version"], 0);

        // Stale row_version.
        let resp = app
            .clone()
            .oneshot(req_json(
                "PATCH",
                &format!("/api/v1/admin/governance/domains/{domain_id}"),
                &admin_cookie,
                Some(json!({ "name": "renamed", "row_version": 7 })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // Correct row_version.
        let resp = app
            .clone()
            .oneshot(req_json(
                "PATCH",
                &format!("/api/v1/admin/governance/domains/{domain_id}"),
                &admin_cookie,
                Some(json!({ "name": "renamed-for-real", "row_version": 0 })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let updated = body_json(resp).await;
        assert_eq!(updated["name"], "renamed-for-real");
        assert_eq!(updated["row_version"], 1);
    })
}

/// Assigning an unknown entity name is rejected wholesale (guidelines §4:
/// never interpolate unvalidated identifiers), and unassigning against the
/// wrong domain id is `404`, not a silent no-op against whatever domain the
/// entity actually has.
#[test]
fn assign_validates_entities_and_unassign_checks_domain_ownership() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let entity = provision_classified_entity(&state, "gov_valid", "general").await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                "/api/v1/admin/governance/domains",
                &admin_cookie,
                Some(json!({ "name": format!("Assign Domain {}", Uuid::now_v7()) })),
            ))
            .await
            .unwrap();
        let domain = body_json(resp).await;
        let domain_id: Uuid = domain["id"].as_str().unwrap().parse().unwrap();

        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
                &admin_cookie,
                Some(json!({ "entity_logicalnames": ["does_not_exist_entity"] })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Real entity, wrong domain id for unassign.
        let resp = app
            .clone()
            .oneshot(req_json(
                "POST",
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
                &admin_cookie,
                Some(json!({ "entity_logicalnames": [entity.clone()] })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let wrong_domain_id = Uuid::now_v7();
        let resp = app
            .clone()
            .oneshot(req_json(
                "DELETE",
                &format!("/api/v1/admin/governance/domains/{wrong_domain_id}/entities/{entity}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Correct domain id actually clears it.
        let resp = app
            .clone()
            .oneshot(req_json(
                "DELETE",
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities/{entity}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    })
}
