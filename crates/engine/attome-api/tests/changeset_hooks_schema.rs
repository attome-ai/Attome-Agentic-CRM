//! Solution 7 Phase 1, lane L3 (D-785, design
//! `document/general/SOLUTION-7-PHASE-1-DESIGN.md` §1.1, §4) — the schema
//! hooks: entities, fields, relationships, labels and governance domains.
//!
//! Proves, through the real admin routes:
//!
//! 1. in `auto` mode every hooked route yields exactly one recorded operation
//!    with the catalogue op name and the logical target (never a UUID), and a
//!    hard entity delete is refused (`hard_delete_not_recordable`);
//! 2. in `required` mode a write with no open changeset is a 409
//!    `changeset_required` and changes nothing, and a write naming an open
//!    changeset (`X-Attome-Changeset`) records into it;
//! 3. a write to a row owned by another layer is a 409 `layer_mismatch` and
//!    records nothing;
//! 4. the governance entity-domain writes append the metadata change-log row
//!    they used to skip.
//!
//! Needs a test database migrated through 0522 and a Redis (same
//! convention as `attribute_retire.rs`). HEAVY: run it on its own.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test changeset_hooks_schema -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test inspects and prepares state on a raw pool"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_core::changeset::store::{self, NewChangeset};
use attome_core::changeset::{CHANGESET_HEADER, Layer};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(mode: &str) -> AppConfig {
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
            "approval": {{ "required_actions": [] }},
            "metadata": {{ "changesets": {{ "mode": "{mode}" }} }}
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

async fn build_test_system(mode: &str) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    attome_testkit::migrated_db_url()?;

    let config = test_config(mode);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let present: bool = sqlx::query_scalar("SELECT to_regclass('changeset_operation') IS NOT NULL")
        .fetch_one(&db)
        .await
        .expect("probe");
    if !present {
        eprintln!(
            "the test database predates migration 0521 (no changeset_operation); \
             skipping — build a private template migrated through 0522"
        );
        return None;
    }
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

#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

static AUTO: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();
static REQUIRED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn system_for(
    cell: &'static tokio::sync::OnceCell<Option<TestSystem>>,
    mode: &'static str,
) -> Option<TestSystem> {
    cell.get_or_init(|| async move {
        let system = build_test_system(mode).await?;
        let state = system.state().clone();
        let base_state = state.base.clone();
        let app =
            attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
                .add_bundle(system.core_routes())
                .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
        Some(TestSystem { state, app })
    })
    .await
    .clone()
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

/// A fresh `system.admin` user; every test uses its own, so its recorded
/// operations are exactly the ones with `actor_ref` = this user.
async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state.base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("changeset-hooks-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege is seeded");
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

fn request(
    method: &str,
    uri: &str,
    cookie: &str,
    changeset: Option<Uuid>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(id) = changeset {
        builder = builder.header(CHANGESET_HEADER, id.to_string());
    }
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    builder.body(body).expect("request")
}

async fn call(
    system: &TestSystem,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call_in(system, method, uri, cookie, None, body).await
}

async fn call_in(
    system: &TestSystem,
    method: &str,
    uri: &str,
    cookie: &str,
    changeset: Option<Uuid>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let resp = system
        .app
        .clone()
        .oneshot(request(method, uri, cookie, changeset, body))
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

/// `(op, target)` of every operation `actor` recorded, in commit order.
async fn ops_of(system: &TestSystem, actor: Uuid) -> Vec<(String, Value)> {
    sqlx::query_as(
        "SELECT o.op, o.target FROM changeset_operation o \
         WHERE o.actor_ref = $1 ORDER BY o.recorded_at, o.changeset_ref, o.seq",
    )
    .bind(actor)
    .fetch_all(&system.state.base.db)
    .await
    .expect("read recorded operations")
}

/// Asserts the one operation recorded since `before` operations.
async fn assert_one_new_op(
    system: &TestSystem,
    actor: Uuid,
    before: &mut usize,
    op: &str,
    target: Value,
) {
    let ops = ops_of(system, actor).await;
    assert_eq!(
        ops.len(),
        *before + 1,
        "exactly one operation for {op}, got {:?}",
        &ops[*before..]
    );
    assert_eq!(ops[*before].0, op);
    assert_eq!(ops[*before].1, target, "{op} target");
    *before = ops.len();
}

fn assert_refused(status: StatusCode, body: &Value, code: &str) {
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains(code), "expected {code}: {body}");
}

fn new_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7().simple())
}

async fn create_entity(
    system: &TestSystem,
    cookie: &str,
    changeset: Option<Uuid>,
) -> (StatusCode, Value, String) {
    let logicalname = new_name("csh");
    let (status, body) = call_in(
        system,
        "POST",
        "/api/v1/admin/entities",
        cookie,
        changeset,
        Some(json!({ "logicalname": logicalname, "name": "Changeset Hooks" })),
    )
    .await;
    (status, body, logicalname)
}

fn id_of(body: &Value) -> Uuid {
    body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no id in {body}"))
}

#[test]
fn entity_and_field_routes_record_one_op_each() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(system_for(&AUTO, "auto").await);
        let (actor, cookie) = seed_admin(&system).await;
        let mut seen = 0;

        let (status, body, entity) = create_entity(&system, &cookie, None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["owner_layer"], "project");
        let entity_id = id_of(&body);
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "create_entity",
            json!({ "entity": entity }),
        )
        .await;

        let (status, body) = call(
            &system,
            "PATCH",
            &format!("/api/v1/admin/entities/{entity_id}"),
            &cookie,
            Some(json!({ "name": "Changeset Hooks Renamed" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "update_entity",
            json!({ "entity": entity }),
        )
        .await;

        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            &cookie,
            Some(json!({ "logicalname": "title", "name": "Title", "field_type": "text" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["owner_layer"], "project");
        let field_id = id_of(&body);
        let field_target = json!({ "entity": entity, "field": "title" });
        assert_one_new_op(&system, actor, &mut seen, "add_field", field_target.clone()).await;

        let (status, body) = call(
            &system,
            "PATCH",
            &format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}"),
            &cookie,
            Some(json!({ "name": "Headline" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "update_field",
            field_target.clone(),
        )
        .await;

        let (status, body) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}"),
            &cookie,
            None,
        )
        .await;
        // D-788: the field DELETE is a real delete, recorded as delete_field.
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(&system, actor, &mut seen, "delete_field", field_target).await;

        // A hard delete drops the table: never recordable, refused before
        // the approval gate, nothing recorded.
        let (status, body) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/entities/{entity_id}?hard=true"),
            &cookie,
            None,
        )
        .await;
        assert_refused(status, &body, "hard_delete_not_recordable");
        assert_eq!(ops_of(&system, actor).await.len(), seen);

        let (status, body) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/entities/{entity_id}"),
            &cookie,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "retire_entity",
            json!({ "entity": entity }),
        )
        .await;

        // Each automatic changeset is closed, `auto` origin, project layer.
        let open: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM changeset \
             WHERE author_ref = $1 AND (status <> 'closed' OR origin <> 'auto' OR layer <> 'project')",
        )
        .bind(actor)
        .fetch_one(&system.state.base.db)
        .await
        .expect("count");
        assert_eq!(open, 0);
    })
}

#[test]
fn relationship_routes_record_one_op_each() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(system_for(&AUTO, "auto").await);
        let (actor, cookie) = seed_admin(&system).await;
        let (_, _, entity_a) = create_entity(&system, &cookie, None).await;
        let (_, _, entity_b) = create_entity(&system, &cookie, None).await;
        let mut seen = ops_of(&system, actor).await.len();
        assert_eq!(seen, 2);

        let name = new_name("rel");
        let (status, body) = call(
            &system,
            "POST",
            "/api/v1/admin/relationships",
            &cookie,
            Some(json!({
                "name": name, "entity_a": entity_a, "entity_b": entity_b,
                "role_a": "As", "role_b": "Bs",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["owner_layer"], "project");
        let id = id_of(&body);
        let target = json!({ "relationship": name });
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "upsert_relationship",
            target.clone(),
        )
        .await;

        let (status, body) = call(
            &system,
            "PATCH",
            &format!("/api/v1/admin/relationships/{id}"),
            &cookie,
            Some(json!({ "role_a": "Owners" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "upsert_relationship",
            target.clone(),
        )
        .await;

        let (status, body) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/relationships/{id}"),
            &cookie,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_one_new_op(&system, actor, &mut seen, "retire_relationship", target).await;
    })
}

#[test]
fn label_routes_record_one_op_each() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(system_for(&AUTO, "auto").await);
        let (actor, cookie) = seed_admin(&system).await;
        let (_, body, entity) = create_entity(&system, &cookie, None).await;
        let entity_id = id_of(&body);
        let mut seen = 1;

        let label = json!({
            "object_kind": "entity", "locale": "ar", "display_name": "حساب",
        });
        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/labels"),
            &cookie,
            Some(label),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["owner_layer"], "project");
        let label_id = id_of(&body);
        let target = json!({ "object_kind": "entity", "object_key": entity, "locale": "ar" });
        assert_one_new_op(&system, actor, &mut seen, "set_label", target.clone()).await;

        let (status, body) = call(
            &system,
            "PATCH",
            &format!("/api/v1/admin/entities/{entity_id}/labels/{label_id}"),
            &cookie,
            Some(json!({
                "object_kind": "entity", "locale": "ar", "display_name": "الحساب",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(&system, actor, &mut seen, "set_label", target.clone()).await;

        let (status, body) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/entities/{entity_id}/labels/{label_id}"),
            &cookie,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_one_new_op(&system, actor, &mut seen, "clear_label", target).await;
    })
}

#[test]
fn governance_domain_routes_record_and_append_the_change_log() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(system_for(&AUTO, "auto").await);
        let (actor, cookie) = seed_admin(&system).await;
        let (_, body, entity) = create_entity(&system, &cookie, None).await;
        let entity_id = id_of(&body);
        // The governance route resolves entities through the registry, which
        // this suite never refreshes in the background.
        system.state.entities.swap(
            attome_core::build_registry(&system.state.base.db)
                .await
                .expect("rebuild the entity registry"),
        );
        let mut seen = 1;

        let domain = new_name("dom");
        let (status, body) = call(
            &system,
            "POST",
            "/api/v1/admin/governance/domains",
            &cookie,
            Some(json!({ "name": domain })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["owner_layer"], "project");
        let domain_id = id_of(&body);
        let row_version = body["row_version"].as_i64().expect("row_version");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "upsert_data_domain",
            json!({ "domain": domain }),
        )
        .await;

        let (status, body) = call(
            &system,
            "PATCH",
            &format!("/api/v1/admin/governance/domains/{domain_id}"),
            &cookie,
            Some(json!({ "description": "Sales data", "row_version": row_version })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "upsert_data_domain",
            json!({ "domain": domain }),
        )
        .await;

        let log_rows = |state: EngineState| async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM metadata_change_log WHERE entity_ref = $1",
            )
            .bind(entity_id)
            .fetch_one(&state.base.db)
            .await
            .expect("count change log")
        };
        let before = log_rows(system.state.clone()).await;

        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
            &cookie,
            Some(json!({ "entity_logicalnames": [entity] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "set_entity_domain",
            json!({ "entity": entity }),
        )
        .await;
        assert_eq!(
            log_rows(system.state.clone()).await,
            before + 1,
            "assign appends the change log"
        );

        let (status, body) = call(
            &system,
            "DELETE",
            &format!("/api/v1/admin/governance/domains/{domain_id}/entities/{entity}"),
            &cookie,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_one_new_op(
            &system,
            actor,
            &mut seen,
            "set_entity_domain",
            json!({ "entity": entity }),
        )
        .await;
        assert_eq!(
            log_rows(system.state.clone()).await,
            before + 2,
            "unassign appends the change log"
        );
    })
}

#[test]
fn required_mode_refuses_a_write_without_a_changeset_and_records_into_a_named_one() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(system_for(&REQUIRED, "required").await);
        let (actor, cookie) = seed_admin(&system).await;

        let (status, body, entity) = create_entity(&system, &cookie, None).await;
        assert_refused(status, &body, "changeset_required");
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM entity_info WHERE logicalname = $1)")
                .bind(&entity)
                .fetch_one(&system.state.base.db)
                .await
                .expect("probe");
        assert!(!exists, "a refused write provisions nothing");
        assert!(ops_of(&system, actor).await.is_empty());

        let changeset = store::open(
            &system.state.base.db,
            &NewChangeset {
                layer: Layer::Project,
                scope: "hooks-test".into(),
                name: format!("t-{}", &Uuid::now_v7().simple().to_string()[22..]),
                title: "Hooks test".into(),
                description: String::new(),
                requires: json!({}),
                author_ref: Some(actor),
                author_label: format!("user:{actor}"),
            },
        )
        .await
        .expect("open a changeset");

        let (status, body, entity) = create_entity(&system, &cookie, Some(changeset.id)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let recorded: Vec<(Uuid, String, i32)> = sqlx::query_as(
            "SELECT changeset_ref, op, seq FROM changeset_operation WHERE actor_ref = $1",
        )
        .bind(actor)
        .fetch_all(&system.state.base.db)
        .await
        .expect("read");
        assert_eq!(
            recorded,
            vec![(changeset.id, "create_entity".to_owned(), 1)]
        );

        // The caller's one open changeset is found without the header too.
        let entity_id = id_of(&body);
        let (status, body) = call(
            &system,
            "PATCH",
            &format!("/api/v1/admin/entities/{entity_id}"),
            &cookie,
            Some(json!({ "name": "Renamed in the open changeset" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let ops = ops_of(&system, actor).await;
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[1],
            ("update_entity".to_owned(), json!({ "entity": entity }))
        );
    })
}

#[test]
fn a_row_of_another_layer_is_refused_with_layer_mismatch() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(system_for(&AUTO, "auto").await);
        let (actor, cookie) = seed_admin(&system).await;
        let (status, body, _) = create_entity(&system, &cookie, None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let entity_id = id_of(&body);
        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            &cookie,
            Some(json!({ "logicalname": "title", "name": "Title", "field_type": "text" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let field_id = id_of(&body);
        let seen = ops_of(&system, actor).await.len();

        // What the boot stamp step does to a platform definition's rows (a
        // throwaway test database: the direct write is the test fixture).
        sqlx::query("UPDATE entity_info SET owner_layer = 'platform' WHERE id = $1")
            .bind(entity_id)
            .execute(&system.state.base.db)
            .await
            .expect("stamp entity");
        sqlx::query("UPDATE attribute_info SET owner_layer = 'platform' WHERE id = $1")
            .bind(field_id)
            .execute(&system.state.base.db)
            .await
            .expect("stamp field");

        for (method, uri, body) in [
            (
                "PATCH",
                format!("/api/v1/admin/entities/{entity_id}"),
                Some(json!({ "name": "Not mine" })),
            ),
            (
                "PATCH",
                format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}"),
                Some(json!({ "name": "Not mine" })),
            ),
            (
                "DELETE",
                format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}"),
                None,
            ),
            (
                "DELETE",
                format!("/api/v1/admin/entities/{entity_id}"),
                None,
            ),
        ] {
            let (status, response) = call(&system, method, &uri, &cookie, body).await;
            assert_refused(status, &response, "layer_mismatch");
        }
        assert_eq!(
            ops_of(&system, actor).await.len(),
            seen,
            "a refused write records nothing"
        );

        // A project changeset may still add a field to a platform entity.
        let (status, body) = call(
            &system,
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            &cookie,
            Some(json!({ "logicalname": "notes", "name": "Notes", "field_type": "text" })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["owner_layer"], "project");
    })
}
