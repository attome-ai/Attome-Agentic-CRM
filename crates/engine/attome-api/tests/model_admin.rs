//! Integration tests for the metadata model admin API
//! (`/api/v1/admin/model`, roadmap Y1-T9): only an administrator reaches it.
//! The edit-command test joins once a kind is registered (Y1-T13).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis, same as
//! `settings_admin.rs`, whose harness this copies.

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

async fn seed_user(db: &attome_db::DbPool, label: &str) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("model-admin-test-{label}-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    (user_id, session_cookie(user_id))
}

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let (user_id, cookie) = seed_user(db, "admin").await;
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
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
    (user_id, cookie)
}

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn non_admin_gets_403_on_kinds() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_user(&db, "plain").await;
        let app = full_app(system);
        let resp = app
            .oneshot(get_req("/api/v1/admin/model/kinds", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    });
}

#[test]
fn admin_lists_kinds_and_an_unknown_kind_is_404() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/admin/model/kinds", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["items"].is_array(), "a paginated list: {body}");
        assert_eq!(body["page"], 1);
        // Y1-T13's six first kinds, and N9-T1's agents.
        let mut names: Vec<&str> = body["items"]
            .as_array()
            .expect("items")
            .iter()
            .filter_map(|kind| kind["name"].as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "agent",
                "attribute",
                "business_event",
                "component",
                "entity",
                "environment_variable",
                "eval_suite",
                "flow_template",
                "form",
                "navigation",
                "option_set",
                "page",
                "prompt_override",
                "record_template",
                "record_type",
                "relationship",
                "reply_template",
                "rule",
                "stage_process",
                "state_model",
                "survey",
                "tour"
            ]
        );
        let resp = app
            .oneshot(get_req("/api/v1/admin/model/no_such_kind", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

fn post_req(uri: &str, cookie: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[test]
fn commands_create_a_form_and_report_a_missing_attribute() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        // A real entity and one of its attributes.
        let (entity_id, attribute_id): (Uuid, Uuid) = sqlx::query_as(
            "SELECT e.id, a.id FROM entity_info e JOIN attribute_info a ON a.entity_ref = e.id \
             WHERE e.is_active IS NOT FALSE LIMIT 1",
        )
        .fetch_one(&db)
        .await
        .expect("a seeded entity with an attribute");
        let form_id = Uuid::now_v7();
        let missing = Uuid::now_v7();
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/form/{form_id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": format!("test form {form_id}"),
                    "commands": [
                        { "op": "set", "path": "/entity", "value": entity_id.to_string() },
                        { "op": "set", "path": "/sections", "value": [
                            { "label": "Main", "fields": [attribute_id.to_string(), missing.to_string()] }
                        ]}
                    ]
                }),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let issues = body["issues"].as_array().expect("issues");
        assert_eq!(
            issues.len(),
            1,
            "only the made-up attribute dangles: {body}"
        );
        assert_eq!(issues[0]["code"], "dangling_reference");

        let resp = app
            .oneshot(get_req(
                &format!("/api/v1/admin/model/form/{form_id}"),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let read = body_json(resp).await;
        assert_eq!(read["doc"]["entity"], entity_id.to_string());
        assert_eq!(read["state"], "draft");
    });
}

/// A5-T1: two entities share one option set: once it is published, both
/// choice fields offer its codes (not the retired one), and publishing logs a
/// registry refresh for each entity that uses it.
#[test]
fn two_entities_share_a_published_option_set() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let suffix = Uuid::now_v7().simple().to_string();
        let set_name = format!("stage_{suffix}");
        let set_id = Uuid::now_v7();

        let mut entities = Vec::new();
        for prefix in ["deal", "lead"] {
            let logicalname = format!("{prefix}_{}", &suffix[..12]);
            let entity_id = attome_metadata::provision::ensure_entity(
                &db,
                &logicalname,
                "Option set test",
                None,
                false,
            )
            .await
            .expect("provision entity");
            attome_metadata::provision::ensure_attribute(
                &db,
                entity_id,
                "stage",
                "Stage",
                "choice",
                false,
                false,
                false,
                false,
                None,
                Some(serde_json::json!({ "option_set": set_name, "multi": false })),
            )
            .await
            .expect("provision choice attribute");
            entities.push((entity_id, logicalname));
        }

        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/option_set/{set_id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": set_name,
                    "commands": [{ "op": "set", "path": "/values", "value": [
                        { "code": "won", "label_en": "Won", "order": 2 },
                        { "code": "open", "label_en": "Open", "label_ar": "مفتوح", "order": 1 },
                        { "code": "lost", "label_en": "Lost", "retired": true }
                    ] }]
                }),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let before: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM metadata_change_log")
                .fetch_one(&db)
                .await
                .expect("change log watermark");
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/option_set/{set_id}/publish"),
                &cookie,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let logged: Vec<String> = sqlx::query_scalar(
            "SELECT logicalname FROM metadata_change_log WHERE id > $1 ORDER BY logicalname",
        )
        .bind(before)
        .fetch_all(&db)
        .await
        .expect("change log rows");
        for (_, logicalname) in &entities {
            assert!(
                logged.contains(logicalname),
                "{logicalname} is refreshed: {logged:?}"
            );
        }

        let registry = attome_core::build_registry(&db).await.expect("registry");
        for (_, logicalname) in &entities {
            let meta = registry.get(logicalname).expect("the entity is registered");
            let stage = meta
                .attrs
                .iter()
                .find(|a| a.logicalname == "stage")
                .expect("the choice field");
            assert_eq!(
                stage.options.as_ref().and_then(|o| o.get("choices")),
                Some(&serde_json::json!(["open", "won"])),
                "{logicalname} offers the set's active codes in order"
            );
        }
    });
}

#[test]
fn a_published_form_has_a_render_plan() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let (entity_id, attribute_id, attribute_name): (Uuid, Uuid, String) = sqlx::query_as(
            "SELECT e.id, a.id, a.logicalname FROM entity_info e \
             JOIN attribute_info a ON a.entity_ref = e.id \
             WHERE e.is_active IS NOT FALSE AND a.is_active IS NOT FALSE LIMIT 1",
        )
        .fetch_one(&db)
        .await
        .expect("a seeded entity with an attribute");
        let form_id = Uuid::now_v7();
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/form/{form_id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": format!("plan form {form_id}"),
                    "commands": [
                        { "op": "set", "path": "/entity", "value": entity_id.to_string() },
                        { "op": "set", "path": "/sections", "value": [
                            { "label": "Main", "fields": [attribute_id.to_string()] }
                        ]}
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Not published yet: no plan.
        let resp = app
            .clone()
            .oneshot(get_req(
                &format!("/api/v1/model/forms/{form_id}/plan"),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/form/{form_id}/publish"),
                &cookie,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let resp = app
            .clone()
            .oneshot(get_req(
                &format!("/api/v1/model/forms/{form_id}/plan"),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .expect("the plan carries an ETag")
            .to_owned();
        let plan = body_json(resp).await;
        assert_eq!(plan["sections"][0]["label"], "Main");
        assert_eq!(
            plan["sections"][0]["fields"][0]["attribute"],
            attribute_name
        );

        // Y14-T2: a client holding this plan gets a bodyless 304.
        let mut again = get_req(&format!("/api/v1/model/forms/{form_id}/plan"), &cookie);
        again.headers_mut().insert(
            "if-none-match",
            etag.parse().expect("an ETag is a header value"),
        );
        let resp = app.oneshot(again).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    });
}

/// Y1-T10's done-when: export, then import, gives drafts whose content
/// hashes equal the exported objects' own.
#[test]
fn export_then_import_keeps_content_hashes() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE is_active IS NOT FALSE LIMIT 1")
                .fetch_one(&db)
                .await
                .expect("a seeded entity");
        let form_id = Uuid::now_v7();
        let name = format!("export form {form_id}");
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/form/{form_id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": name,
                    "commands": [
                        { "op": "set", "path": "/entity", "value": entity_id.to_string() },
                        { "op": "set", "path": "/sections", "value": [{ "label": "Main", "fields": [] }] }
                    ]
                }),
            ))
            .await
            .unwrap();
        let saved = body_json(resp).await;
        let hash = saved["content_hash"].as_str().expect("hash").to_owned();

        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/admin/model/export", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let export = body_json(resp).await;
        let file = export["files"]
            .as_array()
            .expect("files")
            .iter()
            .find(|f| f["text"].as_str().is_some_and(|t| t.contains(&name)))
            .cloned()
            .expect("the form is exported");
        let text = file["text"].as_str().expect("text");
        assert!(
            file["path"]
                .as_str()
                .expect("path")
                .starts_with("form/customer/")
        );
        assert!(
            text.ends_with('\n') && !text.contains('\r'),
            "LF only, trailing newline"
        );

        let resp = app
            .clone()
            .oneshot(post_req(
                "/api/v1/admin/model/import",
                &cookie,
                serde_json::json!({ "files": [file] }),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let imported = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{imported}");
        let draft = &imported["drafts"][0];
        assert_eq!(draft["id"], form_id.to_string(), "same name → same object");
        assert_eq!(draft["content_hash"], hash.as_str());

        let resp = app
            .oneshot(post_req(
                "/api/v1/admin/model/import",
                &cookie,
                serde_json::json!({ "files": [{ "path": "form/x/y.json", "text": "{" }] }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    });
}

/// N12-T3: a blueprint plans, applies whole, plans as unchanged afterwards,
/// and a changed apply rolls back to the version it replaced.
#[test]
fn a_blueprint_plans_applies_and_rolls_back() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE is_active IS NOT FALSE LIMIT 1")
                .fetch_one(&db)
                .await
                .expect("a seeded entity");
        let name = format!("blueprint form {}", Uuid::now_v7());
        let file = |label: &str| {
            let text = serde_json::to_string_pretty(&serde_json::json!({
                "kind": "form", "app": "customer", "name": name, "schema_version": 1,
                "doc": { "entity": entity_id.to_string(), "sections": [{ "label": label, "fields": [] }] }
            }))
            .unwrap()
                + "\n";
            serde_json::json!({ "files": [{ "path": "form/customer/x.json", "text": text }] })
        };
        let call = |uri: &'static str, body: serde_json::Value| {
            let app = app.clone();
            let cookie = cookie.clone();
            async move {
                let resp = app.oneshot(post_req(uri, &cookie, body)).await.unwrap();
                let status = resp.status();
                (status, body_json(resp).await)
            }
        };

        let (status, plan) = call("/api/v1/admin/model/blueprint/plan", file("Main")).await;
        assert_eq!(status, StatusCode::OK, "{plan}");
        assert_eq!(plan["items"][0]["status"], "new");

        let (status, applied) = call("/api/v1/admin/model/blueprint/apply", file("Main")).await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert!(applied["items"][0]["previous_version"].is_null());

        let (_, plan) = call("/api/v1/admin/model/blueprint/plan", file("Main")).await;
        assert_eq!(plan["items"][0]["status"], "same");

        let (_, changed) = call("/api/v1/admin/model/blueprint/apply", file("Changed")).await;
        let item = changed["items"][0].clone();
        assert!(item["previous_version"].is_i64(), "{changed}");

        let (status, rolled) = call(
            "/api/v1/admin/model/blueprint/rollback",
            serde_json::json!({ "items": [item] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rolled}");
        let (_, plan) = call("/api/v1/admin/model/blueprint/plan", file("Main")).await;
        assert_eq!(
            plan["items"][0]["status"], "same",
            "back to the first version"
        );
    });
}

/// A30-T1: an environment variable is defined as metadata and published; its
/// value is this deployment's own, checked against the type, kept in the
/// history, and cleared back to the default.
#[test]
fn environment_variable_values_are_set_per_deployment() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let name = format!("erp_url_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let id = Uuid::now_v7();
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/environment_variable/{id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": name,
                    "commands": [
                        { "op": "set", "path": "/type", "value": "url" },
                        { "op": "set", "path": "/required", "value": true }
                    ]
                }),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/environment_variable/{id}/publish"),
                &cookie,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let put = |value: serde_json::Value, version: Option<i64>| {
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/admin/env-variables/{name}"))
                .header("cookie", &cookie)
                .header("origin", "http://localhost:4200")
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "value": value, "row_version": version }).to_string(),
                ))
                .unwrap()
        };
        let resp = app
            .clone()
            .oneshot(put(serde_json::json!("not a url"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let resp = app
            .clone()
            .oneshot(put(serde_json::json!("https://erp.test.local"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let resp = app
            .clone()
            .oneshot(put(serde_json::json!("https://erp2.test.local"), Some(7)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "a stale row version");

        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/admin/env-variables", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let listed = body_json(resp).await;
        let mine = listed["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|v| v["name"] == name.as_str())
            .cloned()
            .expect("the published variable is listed");
        assert_eq!(mine["type"], "url");
        assert_eq!(mine["value"], "https://erp.test.local");
        assert_eq!(mine["is_set"], true);

        let resp = app
            .clone()
            .oneshot(get_req(
                &format!("/api/v1/admin/env-variables/{name}/history"),
                &cookie,
            ))
            .await
            .unwrap();
        let history = body_json(resp).await;
        assert_eq!(history["total"], 1, "{history}");

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/admin/env-variables/{name}"))
                    .header("cookie", &cookie)
                    .header("origin", "http://localhost:4200")
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    });
}

/// Y7-T5: a published business event is raised in the caller's transaction
/// and lands in the change feed under its name; a payload that does not fit
/// the definition is refused and writes nothing.
#[test]
fn a_business_event_is_raised_into_the_change_feed() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (admin_id, cookie) = seed_admin(&db).await;
        let app = full_app(system);
        let name = format!("shipped_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let id = Uuid::now_v7();
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/business_event/{id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": name,
                    "commands": [
                        { "op": "set", "path": "/entity", "value": "user_account" },
                        { "op": "set", "path": "/attributes", "value": {
                            "carrier": { "type": "text", "required": true },
                            "weight_kg": { "type": "number" }
                        } }
                    ]
                }),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/business_event/{id}/publish"),
                &cookie,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let count = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM entity_change_event WHERE event_name = $1 AND record_id = $2",
            )
            .bind(&name)
            .bind(admin_id)
            .fetch_one(&db)
            .await
            .expect("count events")
        };

        let mut tx = db.begin().await.expect("begin");
        let refused = attome_api::business_event::raise_event(
            &mut tx,
            &name,
            admin_id,
            &serde_json::json!({ "weight_kg": "heavy" }),
        )
        .await;
        assert!(
            matches!(refused, Err(attome_types::AppError::Validation(_))),
            "{refused:?}"
        );
        tx.rollback().await.expect("rollback");
        assert_eq!(count().await, 0);

        let mut tx = db.begin().await.expect("begin");
        attome_api::business_event::raise_event(
            &mut tx,
            &name,
            admin_id,
            &serde_json::json!({ "carrier": "Aramex", "weight_kg": 2.5 }),
        )
        .await
        .expect("raise");
        tx.commit().await.expect("commit");
        assert_eq!(count().await, 1);
        let after: serde_json::Value = sqlx::query_scalar(
            "SELECT after FROM entity_change_event WHERE event_name = $1 AND record_id = $2",
        )
        .bind(&name)
        .bind(admin_id)
        .fetch_one(&db)
        .await
        .expect("the event row");
        assert_eq!(after["carrier"], "Aramex");
    });
}

/// Y1-T16: a non-administrator is refused on every model route, reads and
/// writes alike, before anything is looked up.
#[test]
fn non_admin_gets_403_on_every_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_user(&db, "plain-every-route").await;
        let app = full_app(system);
        let id = Uuid::now_v7();
        let gets = [
            "/api/v1/admin/model/kinds".to_owned(),
            "/api/v1/admin/model/form".to_owned(),
            format!("/api/v1/admin/model/form/{id}"),
            format!("/api/v1/admin/model/form/{id}/versions/1"),
            format!("/api/v1/admin/model/form/{id}/history"),
            format!("/api/v1/admin/model/form/{id}/diff?from=1&to=2"),
            format!("/api/v1/admin/model/form/{id}/references"),
            "/api/v1/admin/model/export".to_owned(),
        ];
        for uri in &gets {
            let resp = app.clone().oneshot(get_req(uri, &cookie)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "GET {uri}");
        }
        let posts = [
            format!("/api/v1/admin/model/form/{id}/validate"),
            format!("/api/v1/admin/model/form/{id}/commands"),
            format!("/api/v1/admin/model/form/{id}/publish"),
            "/api/v1/admin/model/blueprint/plan".to_owned(),
        ];
        for uri in &posts {
            let resp = app
                .clone()
                .oneshot(post_req(uri, &cookie, serde_json::json!({})))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "POST {uri}");
        }
    });
}

/// Y1-T16: commands against a draft that changed since the caller read it
/// are refused with 409, and nothing is saved.
#[test]
fn stale_base_hash_on_commands_is_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE is_active IS NOT FALSE LIMIT 1")
                .fetch_one(&db)
                .await
                .expect("a seeded entity");
        let app = full_app(system);
        let form_id = Uuid::now_v7();
        let uri = format!("/api/v1/admin/model/form/{form_id}/commands");
        let first = app
            .clone()
            .oneshot(post_req(
                &uri,
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": format!("stale test {form_id}"),
                    "commands": [
                        { "op": "set", "path": "/entity", "value": entity_id.to_string() },
                        { "op": "set", "path": "/sections", "value": [] }
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let resp = app
            .clone()
            .oneshot(post_req(
                &uri,
                &cookie,
                serde_json::json!({
                    "base_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "name": format!("stale test {form_id}"),
                    "commands": [
                        { "op": "set", "path": "/sections", "value": [{ "label": "Late", "fields": [] }] }
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let read = body_json(
            app.oneshot(get_req(
                &format!("/api/v1/admin/model/form/{form_id}"),
                &cookie,
            ))
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(
            read["doc"]["sections"],
            serde_json::json!([]),
            "nothing was saved"
        );
    });
}

/// Y1-T16: an object's history is the standard paginated envelope.
#[test]
fn history_uses_paginated_shape() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, cookie) = seed_admin(&db).await;
        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE is_active IS NOT FALSE LIMIT 1")
                .fetch_one(&db)
                .await
                .expect("a seeded entity");
        let app = full_app(system);
        let form_id = Uuid::now_v7();
        let saved = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/form/{form_id}/commands"),
                &cookie,
                serde_json::json!({
                    "base_hash": "",
                    "name": format!("history test {form_id}"),
                    "commands": [
                        { "op": "set", "path": "/entity", "value": entity_id.to_string() },
                        { "op": "set", "path": "/sections", "value": [] }
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);
        let resp = app
            .oneshot(get_req(
                &format!("/api/v1/admin/model/form/{form_id}/history?page=1&page_size=10"),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["items"].is_array(), "{body}");
        assert_eq!(body["total"], 1);
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 10);
    });
}

/// AA7-T5: a published option set is listed with its hash-named URL; the
/// artefact there is cached as private and immutable, comes Brotli-encoded
/// when the client accepts it, and answers 304 to its own hash. A kind that
/// is not shared answers 404.
#[test]
fn cooked_artefact_is_immutable_and_brotli() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin) = seed_admin(&db).await;
        let (_, user) = seed_user(&db, "cooked").await;
        let app = full_app(system);
        let set_id = Uuid::now_v7();
        // Enough values that the artefact is over the 1 KiB compression floor.
        let values: Vec<serde_json::Value> = (0..40)
            .map(|n| {
                serde_json::json!({ "code": format!("code_{n}"),
                    "label_en": format!("A fairly long English label for value {n}"), "order": n })
            })
            .collect();
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/option_set/{set_id}/commands"),
                &admin,
                serde_json::json!({
                    "base_hash": "",
                    "name": format!("cooked_{}", set_id.simple()),
                    "commands": [{ "op": "set", "path": "/values", "value": values }]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{}", body_json(resp).await);
        let resp = app
            .clone()
            .oneshot(post_req(
                &format!("/api/v1/admin/model/option_set/{set_id}/publish"),
                &admin,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{}", body_json(resp).await);

        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/cooked/option_set", &user))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list = body_json(resp).await;
        let key = format!("option_set:{set_id}");
        let item = list["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["key"] == key.as_str())
            .unwrap_or_else(|| panic!("{key} is listed: {list}"))
            .clone();
        let url = item["url"].as_str().expect("url").to_owned();
        let hash = item["hash"].as_str().expect("hash").to_owned();

        let mut fetch = get_req(&url, &user);
        fetch
            .headers_mut()
            .insert("accept-encoding", "br".parse().unwrap());
        let resp = app.clone().oneshot(fetch).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(
            header("cache-control"),
            "private, max-age=31536000, immutable"
        );
        assert_eq!(header("content-encoding"), "br");
        assert_eq!(header("etag"), format!("\"{hash}\""));

        let mut again = get_req(&url, &user);
        again
            .headers_mut()
            .insert("if-none-match", format!("\"{hash}\"").parse().unwrap());
        let resp = app.clone().oneshot(again).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

        let resp = app
            .clone()
            .oneshot(get_req(
                &format!("/api/v1/cooked/option_set/{}", "0".repeat(64)),
                &user,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "an unknown hash");
        let resp = app
            .oneshot(get_req("/api/v1/cooked/agent", &user))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "agents are not shared"
        );
    });
}
