//! P-environment-promotion §3 Phase 1 / §6 — the bundle engine's write half
//! (`bundle::apply::run_apply_job`) and its HTTP surface (`bundle::routes`)
//! against a live, seeded database:
//!
//! - **round trip** — a bundle that adds an entity (+ attributes incl. a
//!   lookup), a stored query, a view, a sidebar group + item, a role with a
//!   grant / entity access / profile link, and a field-security profile is
//!   planned (all `create`), persisted, applied through `run_apply_job`
//!   directly (no worker), and the export afterwards carries every object;
//!   planning the same bundle again is all-`noop`, and a second apply
//!   writes nothing (`applied_count == 0`, change-log row count unchanged);
//!   exactly one `meta_version` doorbell per apply;
//! - **retire round trip** — drop one attribute from the bundle, plan with
//!   `allow_retire` → exactly one `retire`; apply → `is_active = false`,
//!   physical column intact; re-apply the earlier bundle → active again;
//!   then retire the whole object graph (plan the pre-test export with
//!   `allow_retire`), re-apply the full bundle, and the export is
//!   byte-identical to the export taken before the retire — the "export A,
//!   apply to B, export B" acceptance bar, with B being A-after-retire;
//! - **basis hash** — `import?mode=apply` answers 409 once live metadata
//!   moved after the plan; the worker marks a queued plan `failed` with
//!   "basis changed since plan" in the same situation;
//! - **resume** — a stale claim with a mid-way cursor is reclaimed and the
//!   run completes from there, without re-checking the basis;
//! - **drift** — `GET …/drift` reports the hand edit (an `Admin`-policy
//!   reconcile) made after the last successful apply, and `clean` flips.
//! - **relationship cascade wire spelling (C-21, M01 §7)** — a bundle step
//!   whose relationship `cascade` field carries either the legacy
//!   underscore spelling (`cascade_deactivate`) or the canonical hyphenated
//!   one (`cascade-deactivate`) applies successfully, and the stored/
//!   re-exported value always normalizes to the canonical spelling.
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same
//! convention as `bundle_export.rs`. The doorbell assertion reads the
//! `meta_version` counter, so this binary's config selects Redis logical
//! database 9 (every other suite uses 0) — another suite's admin writes on
//! the same Redis cannot bump the counter under it. Run with
//! `--test-threads=1`: the tests share one throwaway database and the
//! metadata write lock.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-api --test bundle_apply -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::model::RelationshipDef;
use attome_api::bundle::{
    AppDef, AttributeDef, Bundle, EntityDef, FieldSecurityProfileDef, PlanAction, PlanOptions,
    PlanStatus, PrivilegeDef, ProfileField, QueryDef, QueryRef, RoleDef, RoleEntityAccess,
    RoleGrant, SidebarDef, ViewDef, bundle_hash, canonical_json, export_bundle, ledger,
    plan_bundle, run_apply_job,
};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_metadata::provision::{AttributeDesc, ReconcilePolicy};
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `config.database.{host,port,dbname,user,password}` must resolve to the
/// exact same database `DATABASE_URL` names, not a placeholder — unlike the
/// single pool `attome_db::create_pool` builds (which honors `DATABASE_URL`
/// directly under `APP_ENV=debug`), `attome_db::create_migrator_pool`/
/// `create_migrator_connection`/`create_readonly_pool` build their own URL
/// straight from these config fields (`AppConfig::migrator_database_url`
/// etc.), with **no `DATABASE_URL` awareness at all** — by design, since
/// those exist specifically to authenticate as a *different*, specific role
/// when one is configured. Left as placeholders ("unused"/port 5555, the
/// **dev** port), any code path that reaches one of those pools — e.g.
/// `attome-metadata::provision::sync_attribute_index`'s inline `CREATE INDEX
/// CONCURRENTLY`, hit here because platform-bundle boot seeding (D-478)
/// creates sortable/filterable attributes on brand-new, empty tables, which
/// always takes the inline (non-async) path — either fails outright
/// ("password authentication failed for user \"unused\"", reproduced
/// against every test in this file, not just one) or, worse, could
/// authenticate against the unrelated **dev** database on port 5555 if a
/// role named "unused" ever existed there. Parsing `DATABASE_URL` (which
/// `attome_testkit::migrated_db_url()` has already rewritten to this binary's own
/// throwaway clone by the time `test_config` runs — see `test_system`'s
/// call order) and threading its real parts through here is what makes every
/// pool this test harness builds land on the same, correct, isolated
/// database.
fn test_config() -> AppConfig {
    // Read directly, not via `attome_testkit::configured_db_url()` — that
    // function deliberately returns the *pre-rewrite* URL the harness
    // configured (the template `test_db_url()` clones from), and this needs
    // the post-rewrite one pointing at this binary's own throwaway clone.
    let db_url = attome_testkit::migrated_db_url().expect(
        "DATABASE_URL must be set (by attome_testkit::migrated_db_url(), called before \
         test_config in test_system) to build a working AppConfig",
    );
    let db = DbUrlParts::parse(&db_url).expect("DATABASE_URL must parse");

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
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
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
            "approval": {{ "required_actions": [] }},
            "audit": {{ "chainer_enabled": false }}
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
        .bind(format!("bundle-apply-test-{user_id}"))
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

fn get_request(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

// ── The test object graph ───────────────────────────────────────────────────

/// Everything one bundle adds on top of a live export. Names are unique per
/// run so a re-run against the same throwaway database does not collide.
struct Graph {
    entity: String,
    query_name: String,
    view_name: String,
    group: String,
    item: String,
    role: String,
    profile: String,
    app_name: String,
}

impl Graph {
    fn new() -> Self {
        let entity = attome_testkit::unique_logicalname("bndl");
        let tag = attome_testkit::unique("bndl");
        Graph {
            entity,
            query_name: format!("{tag}-list"),
            view_name: format!("{tag}-all"),
            group: format!("Bundle Group {tag}"),
            item: format!("Bundle Item {tag}"),
            role: format!("bundle-role-{tag}"),
            profile: format!("bundle-profile-{tag}"),
            app_name: format!("bundle-app-{tag}"),
        }
    }

    fn attr(name: &str, field_type: &str) -> AttributeDef {
        AttributeDef {
            logicalname: name.to_owned(),
            display_name: name.to_uppercase(),
            field_type: field_type.to_owned(),
            is_required: false,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity: (field_type == "lookup").then(|| "user_account".to_owned()),
            options: None,
            max_length: None,
            on_target_delete: "orphan".to_owned(),
            data_classification: "general".to_owned(),
            purpose: None,
            is_customized: false,
        }
    }

    /// `base` + this graph, normalized.
    fn bundle_on(&self, base: &Bundle) -> Bundle {
        let mut b = base.clone();
        b.entities.push(EntityDef {
            logicalname: self.entity.clone(),
            display_name: "Bundle Apply Test".to_owned(),
            primary_name_attribute: Some("name".to_owned()),
            is_append_only: false,
            is_audited: false,
            category: None,
            is_customized: false,
            attributes: vec![
                Self::attr("name", "text"),
                Self::attr("amount", "number"),
                Self::attr("owner", "lookup"),
            ],
        });
        for action in ["read", "create", "update", "delete", "bulk"] {
            let key = format!("{}.{action}", self.entity);
            b.privileges.push(PrivilegeDef {
                key: key.clone(),
                name: key,
                description: Some(format!("Per-entity privilege: {action} on {}", self.entity)),
            });
        }
        b.queries.push(QueryDef {
            entity: Some(self.entity.clone()),
            name: self.query_name.clone(),
            sql: format!("SELECT id, name FROM {}", self.entity),
            table_definition: Some("[]".to_owned()),
            required_privilege: Some(format!("{}.read", self.entity)),
            is_report: false,
            entity_mappings: Vec::new(),
            is_customized: false,
        });
        b.views.push(ViewDef {
            entity: self.entity.clone(),
            name: self.view_name.clone(),
            query: QueryRef {
                entity: Some(self.entity.clone()),
                name: self.query_name.clone(),
            },
            icon: "las la-table".to_owned(),
            table_definition: Value::Array(Vec::new()),
            is_default: true,
            is_customized: false,
            kind: "list".to_owned(),
            view_metadata: Value::Object(serde_json::Map::new()),
        });
        b.sidebar.push(SidebarDef {
            path: vec![self.group.clone()],
            route: None,
            icon: Some("las la-folder".to_owned()),
            color: None,
            display_order: 900,
            is_container: true,
            entity: None,
            module_key: None,
            is_disabled: false,
            privileges: Vec::new(),
            is_customized: false,
        });
        b.sidebar.push(SidebarDef {
            path: vec![self.group.clone(), self.item.clone()],
            route: Some(format!("/entity/{}", self.entity)),
            icon: Some("las la-table".to_owned()),
            color: None,
            display_order: 1,
            is_container: false,
            entity: Some(self.entity.clone()),
            module_key: None,
            is_disabled: false,
            privileges: vec![format!("{}.read", self.entity)],
            is_customized: false,
        });
        b.field_security_profiles.push(FieldSecurityProfileDef {
            name: self.profile.clone(),
            description: Some("bundle apply test profile".to_owned()),
            is_customized: false,
            fields: vec![ProfileField {
                entity: self.entity.clone(),
                field: "amount".to_owned(),
                can_read: true,
                can_update: false,
            }],
        });
        b.roles.push(RoleDef {
            name: self.role.clone(),
            description: Some("bundle apply test role".to_owned()),
            access_level: 3,
            position_hierarchy_enabled: false,
            is_customized: false,
            privileges: vec![RoleGrant {
                privilege: format!("{}.read", self.entity),
                conditions: Vec::new(),
            }],
            entity_access: vec![RoleEntityAccess {
                entity: self.entity.clone(),
                read_access_level: 3,
                write_access_level: 1,
                delete_access_level: 0,
                read_owner_visible: false,
                write_owner_visible: false,
                delete_owner_visible: false,
                operations: Default::default(),
            }],
            field_security_profiles: vec![self.profile.clone()],
        });
        b.apps.push(AppDef {
            name: self.app_name.clone(),
            icon: "las la-th-large".to_owned(),
            entities: serde_json::json!([self.entity.clone()]),
            roles: serde_json::json!([]),
            display_order: 0,
            is_active: true,
        });
        b.normalize();
        b
    }
}

// ── Ledger / apply helpers ──────────────────────────────────────────────────

/// Plan `bundle` against live, persist it, queue it, run the job inline, and
/// return the finished row.
async fn plan_queue_apply(
    state: &EngineState,
    bundle: &Bundle,
    allow_retire: bool,
) -> ledger::PlanRow {
    let plan_id = plan_and_persist(state, bundle, allow_retire).await;
    assert!(
        ledger::mark_queued(&state.base.db, plan_id, None)
            .await
            .expect("mark_queued"),
        "plan must move planned -> queued"
    );
    run_apply_job(state, plan_id)
        .await
        .expect("run_apply_job must succeed");
    ledger::get_plan(&state.base.db, plan_id)
        .await
        .expect("get_plan")
        .expect("plan row exists")
}

async fn plan_and_persist(state: &EngineState, bundle: &Bundle, allow_retire: bool) -> Uuid {
    let license = state.modules.load_full();
    let plan = plan_bundle(
        &state.base.db,
        &license,
        bundle,
        PlanOptions {
            allow_retire,
            additive_only: false,
        },
    )
    .await
    .expect("plan_bundle");
    assert!(
        plan.blocked.is_empty(),
        "unexpected blocked: {:#?}",
        plan.blocked
    );
    let bundle_json: Value = serde_json::from_slice(&canonical_json(bundle)).unwrap();
    let plan_json = serde_json::to_value(&plan).unwrap();
    ledger::insert_plan(
        &state.base.db,
        &bundle_json,
        &plan_json,
        &plan.bundle_hash,
        &plan.basis_hash,
        attome_api::bundle::BUNDLE_FORMAT,
        attome_api::bundle::PLATFORM_VERSION,
        allow_retire,
        None,
    )
    .await
    .expect("insert_plan")
}

async fn change_log_rows(state: &EngineState) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM metadata_change_log")
        .fetch_one(&state.base.db)
        .await
        .expect("count change log")
}

async fn meta_version(state: &EngineState) -> i64 {
    let v: Option<String> = state
        .base
        .redis
        .get("meta_version")
        .await
        .expect("GET meta_version");
    v.and_then(|raw| raw.parse().ok()).unwrap_or(0)
}

async fn attribute_state(state: &EngineState, entity: &str, field: &str) -> Option<(bool, bool)> {
    sqlx::query_as::<_, (bool, bool)>(
        "SELECT (a.is_active IS NULL OR a.is_active = true) AS live, \
                EXISTS (SELECT 1 FROM information_schema.columns c \
                        WHERE c.table_name = e.logicalname AND c.column_name = a.logicalname) AS has_column \
         FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND a.logicalname = $2 \
         ORDER BY (a.is_active IS NULL OR a.is_active = true) DESC LIMIT 1",
    )
    .bind(entity)
    .bind(field)
    .fetch_optional(&state.base.db)
    .await
    .expect("attribute state")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn apply_creates_the_graph_then_is_idempotent_with_one_doorbell() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let license = state.modules.load_full();
        let db = &state.base.db;

        let graph = Graph::new();
        let before = export_bundle(db).await.expect("export before");
        let desired = graph.bundle_on(&before);

        // Plan: only creates, nothing blocked, nothing to retire.
        let plan = plan_bundle(db, &license, &desired, PlanOptions::default())
            .await
            .expect("plan");
        assert!(plan.blocked.is_empty(), "{:#?}", plan.blocked);
        assert!(plan.retires.is_empty(), "{:#?}", plan.retires);
        assert_eq!(plan.summary.updates, 0, "{:#?}", plan.entries);
        assert!(plan.summary.creates >= 10, "{:?}", plan.summary);

        // Apply, counting doorbells and change-log rows.
        let doorbells_before = meta_version(&state).await;
        let row = plan_queue_apply(&state, &desired, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        assert!(row.applied_count > 0, "{row:#?}");
        assert!(row.error_message.is_none(), "{row:#?}");
        assert_eq!(
            meta_version(&state).await - doorbells_before,
            1,
            "exactly one meta_version doorbell per apply"
        );

        // D-494: a brand-new entity/attribute gets the deterministic
        // bundle-derived id, not a random one — unit tests only prove
        // `derived_id` itself is a pure deterministic function; this proves
        // `apply` actually binds its result into the created row.
        let entity_row_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
                .bind(&graph.entity)
                .fetch_one(db)
                .await
                .expect("entity row exists");
        assert_eq!(
            entity_row_id,
            attome_api::bundle::derived_id(
                attome_api::bundle::model::COMPONENT_ENTITY,
                &graph.entity
            ),
            "bundle-created entity id must be the deterministic derived id"
        );
        let owner_attr_id: Uuid = sqlx::query_scalar(
            "SELECT a.id FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND a.logicalname = 'owner'",
        )
        .bind(&graph.entity)
        .fetch_one(db)
        .await
        .expect("owner attribute row exists");
        assert_eq!(
            owner_attr_id,
            attome_api::bundle::derived_id(
                attome_api::bundle::model::COMPONENT_ATTRIBUTE,
                &format!("{}.owner", graph.entity)
            ),
            "bundle-created attribute id must be the deterministic derived id"
        );

        // The export afterwards carries the whole graph.
        let after = export_bundle(db).await.expect("export after");
        let entity = after
            .entities
            .iter()
            .find(|e| e.logicalname == graph.entity)
            .expect("entity applied");
        assert_eq!(entity.attributes.len(), 3, "{entity:#?}");
        assert!(entity.attributes.iter().any(|a| a.logicalname == "owner"
            && a.field_type == "lookup"
            && a.lookup_entity.as_deref() == Some("user_account")));
        assert!(
            after.queries.iter().any(|q| q.name == graph.query_name
                && q.entity.as_deref() == Some(graph.entity.as_str()))
        );
        assert!(
            after
                .views
                .iter()
                .any(|v| v.name == graph.view_name && v.entity == graph.entity)
        );
        assert!(
            after
                .sidebar
                .iter()
                .any(|s| s.path == vec![graph.group.clone(), graph.item.clone()])
        );
        let role = after
            .roles
            .iter()
            .find(|r| r.name == graph.role)
            .expect("role applied");
        assert_eq!(role.privileges.len(), 1, "{role:#?}");
        assert_eq!(role.entity_access.len(), 1, "{role:#?}");
        assert_eq!(role.field_security_profiles, vec![graph.profile.clone()]);
        let profile = after
            .field_security_profiles
            .iter()
            .find(|p| p.name == graph.profile)
            .expect("profile applied");
        assert_eq!(profile.fields.len(), 1, "{profile:#?}");
        assert!(
            after
                .privileges
                .iter()
                .any(|p| p.key == format!("{}.read", graph.entity))
        );
        // M65 Phase 1 (D-467) — Step::App round trips through the same
        // plan -> apply -> export path every other component above just proved.
        let app = after
            .apps
            .iter()
            .find(|a| a.name == graph.app_name)
            .expect("app applied");
        assert_eq!(app.entities, serde_json::json!([graph.entity]), "{app:#?}");
        assert!(app.is_active, "{app:#?}");

        // Idempotence: planning the same bundle again is all-noop, and applying
        // it again writes nothing.
        let again = plan_bundle(db, &license, &desired, PlanOptions::default())
            .await
            .expect("plan again");
        assert!(again.retires.is_empty(), "{:#?}", again.retires);
        assert!(again.blocked.is_empty(), "{:#?}", again.blocked);
        assert!(
            again.entries.iter().all(|e| e.action == PlanAction::Noop),
            "{:#?}",
            again
                .entries
                .iter()
                .filter(|e| e.action != PlanAction::Noop)
                .collect::<Vec<_>>()
        );
        let log_before = change_log_rows(&state).await;
        let hash_before = bundle_hash(&after);
        let second = plan_queue_apply(&state, &desired, false).await;
        assert_eq!(second.status, PlanStatus::Succeeded, "{second:#?}");
        assert_eq!(second.applied_count, 0, "{second:#?}");
        assert_eq!(
            change_log_rows(&state).await,
            log_before,
            "no change-log row on an all-noop apply"
        );
        assert_eq!(
            bundle_hash(&export_bundle(db).await.expect("export")),
            hash_before
        );
    })
}

/// `document/xrm/pending_full_plan/plan.md` Phase 1 — audit-trail parity
/// between admin-API and bundle-driven metadata changes. Before this test's
/// corresponding fix, `bundle::apply::run_step`'s `Step::Entity`/
/// `Step::Attribute` arms wrote no `AuditEvent` at all (confirmed by grep:
/// zero references to `AuditEvent`/`audit_service` anywhere under
/// `bundle::apply` prior to this change), unlike `admin/entity.rs`'s and
/// `admin/attribute.rs`'s own equivalent handlers, which always have. A
/// bundle-created entity and attribute must now leave the same
/// `audit_header` shape an admin-API create does — `category = Entity`
/// (0), `operation = Create` (0) — distinguished only by `source = Import`
/// (3) instead of `Api` (1), so the audit trail is complete regardless of
/// which path a schema change came through.
/// One `audit_header` row's shape, for comparing a bundle-created and an
/// admin-API-created object's audit events field by field.
#[derive(Debug, PartialEq, sqlx::FromRow)]
struct AuditRowShape {
    category: i32,
    operation: i32,
    entity_name: Option<String>,
    event_name: Option<String>,
    source: i32,
}

async fn audit_row_for(db: &attome_db::DbPool, record_id: Uuid) -> Vec<AuditRowShape> {
    sqlx::query_as(
        "SELECT category, operation, entity_name, event_name, source \
         FROM audit_header WHERE record_id = $1 ORDER BY id",
    )
    .bind(record_id)
    .fetch_all(db)
    .await
    .expect("query audit rows")
}

#[test]
fn apply_writes_entity_and_attribute_audit_events_with_import_source() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = &state.base.db;

        let graph = Graph::new();
        let before = export_bundle(db).await.expect("export before");
        let desired = graph.bundle_on(&before);
        plan_queue_apply(&state, &desired, false).await;

        let entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
                .bind(&graph.entity)
                .fetch_one(db)
                .await
                .expect("entity row exists");
        let entity_rows = audit_row_for(db, entity_id).await;
        assert_eq!(
            entity_rows,
            vec![AuditRowShape {
                category: 0,
                operation: 0,
                entity_name: Some(graph.entity.clone()),
                event_name: Some("entity_created".to_owned()),
                source: 3,
            }],
            "bundle-created entity must leave exactly one Entity/Create/Import audit row, \
         naming the entity and matching admin/entity.rs's own 'entity_created' event_name"
        );

        let owner_attr_id: Uuid = sqlx::query_scalar(
            "SELECT a.id FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND a.logicalname = 'owner'",
        )
        .bind(&graph.entity)
        .fetch_one(db)
        .await
        .expect("owner attribute row exists");
        let attr_rows = audit_row_for(db, owner_attr_id).await;
        assert_eq!(
            attr_rows,
            vec![AuditRowShape {
                category: 0,
                operation: 0,
                entity_name: Some(graph.entity.clone()),
                event_name: Some("attribute_created".to_owned()),
                source: 3,
            }],
            "bundle-created attribute must leave exactly one Entity/Create/Import audit row, \
         attributed to its owning entity's name, matching admin/attribute.rs's own \
         'attribute_created' event_name"
        );

        // Re-applying the identical bundle is all-noop (proven by the first
        // test), so no second audit row should appear — `audit_entity_change` is
        // only called when `wrote(outcome)`, gated the same way `summary.record`
        // is.
        plan_queue_apply(&state, &desired, false).await;
        assert_eq!(
            audit_row_for(db, entity_id).await.len(),
            1,
            "a no-op re-apply must not fabricate another audit row"
        );

        // Equivalent granularity, proven directly against the real admin-API
        // route (not just by code-reading `admin/entity.rs`): create a second
        // entity through POST /api/v1/admin/entities and compare its audit row
        // to the bundle-created one above. Every field must match except
        // `source` (Api vs Import) — same category, same operation, same
        // entity_name-carries-the-logicalname convention, same event_name.
        let (_admin_user, cookie) = seed_admin(&state).await;
        let app = full_app(system);
        let admin_entity_name = attome_testkit::unique_logicalname("bndladm");
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/entities",
                &cookie,
                serde_json::json!({
                    "logicalname": admin_entity_name,
                    "name": "Admin Created",
                }),
            ))
            .await
            .expect("POST /api/v1/admin/entities");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "admin entity create must succeed"
        );
        let created = body_json(resp).await;
        let admin_entity_id: Uuid = created["id"]
            .as_str()
            .expect("response carries an id")
            .parse()
            .expect("id is a UUID");

        let admin_rows = audit_row_for(db, admin_entity_id).await;
        assert_eq!(
            admin_rows,
            vec![AuditRowShape {
                category: 0,
                operation: 0,
                entity_name: Some(admin_entity_name),
                event_name: Some("entity_created".to_owned()),
                source: 1, // AuditSource::Api
            }],
            "admin-API entity create's own audit row"
        );
        // The two rows differ only in `source` (1 = Api vs 3 = Import) and the
        // entity-specific fields (id used to look each up, entity_name) —
        // everything about *what the audit trail records* (category, operation,
        // event_name) is identical regardless of which path created the entity.
        assert_eq!(admin_rows[0].category, entity_rows[0].category);
        assert_eq!(admin_rows[0].operation, entity_rows[0].operation);
        assert_eq!(admin_rows[0].event_name, entity_rows[0].event_name);
        assert_ne!(
            admin_rows[0].source, entity_rows[0].source,
            "source must distinguish the two callers, everything else must agree"
        );
    })
}

#[test]
fn retire_round_trip_soft_retires_and_reapply_reactivates_byte_identically() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let license = state.modules.load_full();
        let db = &state.base.db;

        let graph = Graph::new();
        let before = export_bundle(db).await.expect("export before");
        let full = graph.bundle_on(&before);
        let row = plan_queue_apply(&state, &full, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        let exported_full = export_bundle(db).await.expect("export full");

        // (1) One attribute dropped from the bundle → exactly one retire.
        let mut minus_amount = full.clone();
        let entity = minus_amount
            .entities
            .iter_mut()
            .find(|e| e.logicalname == graph.entity)
            .unwrap();
        entity.attributes.retain(|a| a.logicalname != "amount");
        // The profile field that names `amount` goes with it, or the planner
        // would (rightly) keep asking for a field that no longer exists.
        minus_amount
            .field_security_profiles
            .iter_mut()
            .find(|p| p.name == graph.profile)
            .unwrap()
            .fields
            .clear();
        minus_amount.normalize();

        let refused = plan_bundle(db, &license, &minus_amount, PlanOptions::default())
            .await
            .expect("plan without allow_retire");
        assert!(
            refused
                .blocked
                .iter()
                .any(|b| b.component == "attribute" && b.key == format!("{}.amount", graph.entity)),
            "{:#?}",
            refused.blocked
        );
        let allowed = plan_bundle(
            db,
            &license,
            &minus_amount,
            PlanOptions {
                allow_retire: true,
                additive_only: false,
            },
        )
        .await
        .expect("plan with allow_retire");
        let attribute_retires: Vec<_> = allowed
            .retires
            .iter()
            .filter(|r| r.component == "attribute")
            .collect();
        assert_eq!(attribute_retires.len(), 1, "{:#?}", allowed.retires);
        assert_eq!(attribute_retires[0].key, format!("{}.amount", graph.entity));

        let row = plan_queue_apply(&state, &minus_amount, true).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        let (live, has_column) = attribute_state(&state, &graph.entity, "amount")
            .await
            .expect("attribute row still exists");
        assert!(!live, "attribute must be soft-retired");
        assert!(
            has_column,
            "the physical column is kept (D-055 has no drop)"
        );

        // (2) Re-apply the earlier bundle → the attribute is active again, and
        // the export is byte-identical to the one taken before the retire.
        let row = plan_queue_apply(&state, &full, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        let (live, _) = attribute_state(&state, &graph.entity, "amount")
            .await
            .expect("attribute row");
        assert!(
            live,
            "re-applying the earlier bundle reactivates the attribute"
        );
        assert_eq!(
            canonical_json(&export_bundle(db).await.expect("export")),
            canonical_json(&exported_full),
            "export after reactivate must equal the export before the retire"
        );

        // (3) Retire the whole graph (plan the pre-test export with allow_retire),
        // then re-apply the full bundle: A → retire → apply(A) → export == A.
        let retire_all = plan_bundle(
            db,
            &license,
            &before,
            PlanOptions {
                allow_retire: true,
                additive_only: false,
            },
        )
        .await
        .expect("plan retire-all");
        assert!(retire_all.blocked.is_empty(), "{:#?}", retire_all.blocked);
        assert!(
            retire_all
                .retires
                .iter()
                .any(|r| r.component == "entity" && r.key == graph.entity),
            "{:#?}",
            retire_all.retires
        );
        let row = plan_queue_apply(&state, &before, true).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        let retired = export_bundle(db).await.expect("export after retire-all");
        assert!(
            !retired
                .entities
                .iter()
                .any(|e| e.logicalname == graph.entity)
        );
        assert!(!retired.roles.iter().any(|r| r.name == graph.role));
        assert!(
            !retired
                .sidebar
                .iter()
                .any(|s| s.path.first() == Some(&graph.group))
        );
        // M65 Phase 1 (D-467) — Step::App retires through the same
        // whole-graph retire path proved above for every other component.
        // Unlike entity/role/sidebar, a retired app is NOT dropped from the
        // export — same "carry `is_active` through, never filter it out"
        // convention D-455's `export_relationships` already established (the
        // table itself is never dropped, D-005's soft-delete posture) — so the
        // assertion here is `is_active == false`, not absence.
        let retired_app = retired
            .apps
            .iter()
            .find(|a| a.name == graph.app_name)
            .expect("retired app is still exported, just inactive");
        assert!(!retired_app.is_active, "{retired_app:#?}");

        let row = plan_queue_apply(&state, &full, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        assert_eq!(
            canonical_json(&export_bundle(db).await.expect("export")),
            canonical_json(&exported_full),
            "round trip: export(A) → retire → apply(A) → export must be byte-identical to A"
        );
    })
}

#[test]
fn apply_refuses_once_the_basis_moved_route_409_and_worker_marks_failed() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_admin, cookie) = seed_admin(&state).await;
        let app = full_app(system);
        let db = &state.base.db;

        let graph = Graph::new();
        let before = export_bundle(db).await.expect("export before");
        let desired = graph.bundle_on(&before);

        // Plan through the route.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/metadata/import?mode=plan",
                &cookie,
                serde_json::json!({ "bundle": desired, "allow_retire": false }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let planned = body_json(resp).await;
        let plan_id: Uuid = planned["plan_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(planned["applicable"], Value::Bool(true), "{planned:#}");
        assert_eq!(
            planned["basis_hash"].as_str().unwrap(),
            bundle_hash(&before)
        );

        // Move live metadata under the plan.
        let other = attome_testkit::unique_logicalname("bndlbasis");
        attome_metadata::provision::ensure_entity(db, &other, "Basis Mover", None, false)
            .await
            .expect("provision an unrelated entity");

        // Route: 409.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/metadata/import?mode=apply",
                &cookie,
                serde_json::json!({ "plan_id": plan_id }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let row = ledger::get_plan(db, plan_id).await.unwrap().unwrap();
        assert_eq!(
            row.status,
            PlanStatus::Planned,
            "a refused apply leaves the row planned"
        );

        // Worker: a row that got queued anyway (say, through an approval that
        // raced the metadata change) fails with the same reason, writes nothing.
        assert!(ledger::mark_queued(db, plan_id, None).await.unwrap());
        let log_before = change_log_rows(&state).await;
        let err = run_apply_job(&state, plan_id)
            .await
            .expect_err("basis mismatch must fail the job");
        assert!(
            err.to_string().contains("basis changed since plan"),
            "{err}"
        );
        let row = ledger::get_plan(db, plan_id).await.unwrap().unwrap();
        assert_eq!(row.status, PlanStatus::Failed, "{row:#?}");
        assert!(
            row.error_message
                .as_deref()
                .is_some_and(|m| m.contains("basis changed since plan")),
            "{row:#?}"
        );
        assert_eq!(row.cursor, 0);
        assert_eq!(change_log_rows(&state).await, log_before);
        assert!(
            !export_bundle(db)
                .await
                .unwrap()
                .entities
                .iter()
                .any(|e| e.logicalname == graph.entity),
            "nothing from the plan may have been applied"
        );

        // Status endpoint and list see the row.
        let resp = app
            .clone()
            .oneshot(get_request(
                &format!("/api/v1/admin/metadata/plans/{plan_id}"),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let status = body_json(resp).await;
        assert_eq!(status["status"], "failed");
        let resp = app
            .oneshot(get_request("/api/v1/admin/metadata/plans?limit=5", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list = body_json(resp).await;
        assert!(
            list["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["id"] == plan_id.to_string()),
            "{list:#}"
        );
    })
}

#[test]
fn a_stale_claim_is_resumed_from_its_cursor_without_rechecking_the_basis() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = &state.base.db;

        let graph = Graph::new();
        let before = export_bundle(db).await.expect("export before");
        let full = graph.bundle_on(&before);
        let row = plan_queue_apply(&state, &full, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");

        // A second bundle with two updates: the entity's display name (an early
        // step) and the view's icon (a late step).
        let mut desired = full.clone();
        desired
            .entities
            .iter_mut()
            .find(|e| e.logicalname == graph.entity)
            .unwrap()
            .display_name = "Bundle Apply Test (renamed)".to_owned();
        desired
            .views
            .iter_mut()
            .find(|v| v.name == graph.view_name)
            .unwrap()
            .icon = "las la-star".to_owned();
        desired.normalize();
        let plan_id = plan_and_persist(&state, &desired, false).await;
        assert!(ledger::mark_queued(db, plan_id, None).await.unwrap());

        // Pretend a worker applied the entity step and then died: do that step
        // by hand, advance the cursor past it, and age the claim past the
        // stale-claim timeout. The step list is privileges first, then entities
        // in logicalname order.
        let entity_desc = attome_metadata::provision::EntityDesc {
            logicalname: graph.entity.clone(),
            display_name: "Bundle Apply Test (renamed)".to_owned(),
            primary_name_attribute: Some("name".to_owned()),
            is_append_only: false,
            is_audited: false,
            category: None,
        };
        attome_metadata::provision::reconcile_entity(
            db,
            &entity_desc,
            ReconcilePolicy::Bundle {
                is_customized: false,
            },
        )
        .await
        .expect("apply the entity step by hand");
        let entity_index = desired
            .entities
            .iter()
            .position(|e| e.logicalname == graph.entity)
            .unwrap();
        let cursor = i32::try_from(desired.privileges.len() + entity_index + 1).unwrap();
        assert!(
            ledger::claim(db, plan_id, "crashed-worker")
                .await
                .unwrap()
                .is_some()
        );
        ledger::advance(db, plan_id, cursor, 1).await.unwrap();
        sqlx::query(
            "UPDATE metadata_bundle_plan \
         SET claimed_at = NOW() - INTERVAL '2 hours', updated_at = NOW() - INTERVAL '2 hours' \
         WHERE id = $1",
        )
        .bind(plan_id)
        .execute(db)
        .await
        .expect("age the claim");

        // Live metadata no longer hashes to the basis (the entity step moved
        // it) — a resume must not care.
        run_apply_job(&state, plan_id)
            .await
            .expect("resume must complete");
        let row = ledger::get_plan(db, plan_id).await.unwrap().unwrap();
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");
        assert!(row.cursor > cursor, "{row:#?}");
        assert_eq!(
            row.applied_count, 2,
            "the hand-applied step + the view: {row:#?}"
        );

        let after = export_bundle(db).await.expect("export after resume");
        assert_eq!(
            after
                .entities
                .iter()
                .find(|e| e.logicalname == graph.entity)
                .map(|e| e.display_name.as_str()),
            Some("Bundle Apply Test (renamed)")
        );
        assert_eq!(
            after
                .views
                .iter()
                .find(|v| v.name == graph.view_name)
                .map(|v| v.icon.as_str()),
            Some("las la-star")
        );
        let license = state.modules.load_full();
        let converged = plan_bundle(db, &license, &desired, PlanOptions::default())
            .await
            .expect("plan after resume");
        assert!(
            converged.retires.is_empty()
                && converged.blocked.is_empty()
                && converged
                    .entries
                    .iter()
                    .all(|e| e.action == PlanAction::Noop),
            "resumed apply must converge on the desired bundle: {:#?}",
            converged
                .entries
                .iter()
                .filter(|e| e.action != PlanAction::Noop)
                .collect::<Vec<_>>()
        );
    })
}

#[test]
fn drift_reports_a_hand_edit_after_the_last_apply() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_admin, cookie) = seed_admin(&state).await;
        let app = full_app(system);
        let db = &state.base.db;

        let graph = Graph::new();
        let before = export_bundle(db).await.expect("export before");
        let full = graph.bundle_on(&before);
        let row = plan_queue_apply(&state, &full, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");

        // Clean right after the apply.
        let resp = app
            .clone()
            .oneshot(get_request("/api/v1/admin/metadata/drift", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let clean = body_json(resp).await;
        assert_eq!(clean["applied"]["plan_id"], row.id.to_string(), "{clean:#}");
        assert_eq!(clean["drift"]["clean"], Value::Bool(true), "{clean:#}");

        // A hand edit (an admin relabel) of one applied field.
        let entity_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM entity_info WHERE logicalname = $1 \
         AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&graph.entity)
        .fetch_one(db)
        .await
        .unwrap();
        let mut edited = Graph::attr("name", "text");
        edited.display_name = "Name (relabelled by hand)".to_owned();
        attome_metadata::provision::reconcile_attribute(
            db,
            entity_id,
            &AttributeDesc {
                logicalname: edited.logicalname.clone(),
                display_name: edited.display_name.clone(),
                field_type: edited.field_type.clone(),
                is_required: edited.is_required,
                is_sensitive: edited.is_sensitive,
                is_write_restricted: Some(edited.is_write_restricted),
                is_sortable: edited.is_sortable,
                is_filterable: edited.is_filterable,
                lookup_entity: None,
                options: None,
                max_length: None,
                on_target_delete: Some("orphan".to_owned()),
                data_classification: Some("general".to_owned()),
                purpose: None,
            },
            ReconcilePolicy::Admin,
        )
        .await
        .expect("hand edit");

        let resp = app
            .oneshot(get_request("/api/v1/admin/metadata/drift", &cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let drifted = body_json(resp).await;
        assert_eq!(drifted["drift"]["clean"], Value::Bool(false), "{drifted:#}");
        let key = format!("{}.name", graph.entity);
        let entry = drifted["drift"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["component"] == "attribute" && e["key"] == key)
            .unwrap_or_else(|| panic!("drift must name {key}: {drifted:#}"));
        assert_eq!(entry["action"], "update", "{entry:#}");
        let changes = entry["changes"].as_array().unwrap();
        assert!(
            changes
                .iter()
                .any(|c| c.as_str().unwrap().starts_with("display_name:")),
            "{changes:#?}"
        );
        assert!(
            changes
                .iter()
                .any(|c| c.as_str().unwrap().starts_with("is_customized:")),
            "the admin write marked the row customized: {changes:#?}"
        );
    })
}

/// `AttributePatch` — the additive cross-module field promotion fixing the
/// M77/M78/M82/M74 gap: adding a field to an entity another module owns
/// must never create that entity, only augment it. Two cases in one test
/// (deliberately sharing setup — the "must not create" guarantee only means
/// something once we've also proven the "does augment" half works):
///
/// 1. A patch naming an entity that does not exist live is `Blocked`, never
///    `Create` — the load-bearing guarantee this component exists for.
/// 2. A patch naming a real, already-applied entity actually adds the field,
///    and — critically — leaves every other attribute on that entity
///    untouched, proving it never re-asserts the entity's full definition.
#[test]
fn attribute_patch_never_creates_a_missing_entity_and_augments_an_existing_one() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let license = state.modules.load_full();
        let db = &state.base.db;

        // ── Case 1: target entity does not exist live ──────────────────────────
        let missing_entity = attome_testkit::unique_logicalname("bndl_missing");
        let mut blocked_bundle = export_bundle(db).await.expect("export before");
        blocked_bundle
            .attribute_patches
            .push(attome_api::bundle::AttributePatch {
                entity: missing_entity.clone(),
                attribute: Graph::attr("extra_field", "text"),
            });
        blocked_bundle.normalize();
        let blocked_plan = plan_bundle(db, &license, &blocked_bundle, PlanOptions::default())
            .await
            .expect("plan (missing entity)");
        let key = format!("{missing_entity}.extra_field");
        let entry = blocked_plan
            .blocked
            .iter()
            .find(|e| e.component == "attribute_patch" && e.key == key)
            .unwrap_or_else(|| {
                panic!("expected a blocked attribute_patch entry: {blocked_plan:#?}")
            });
        assert_eq!(entry.action, PlanAction::Blocked, "{entry:#?}");
        assert!(
            entry
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("does not exist") && r.contains("never creates")),
            "{entry:#?}"
        );
        assert!(
            !blocked_plan
                .entries
                .iter()
                .any(|e| e.component == "attribute_patch" && e.key == key),
            "a blocked patch must not also appear as a create: {:#?}",
            blocked_plan.entries
        );

        // ── Case 2: target entity is real — the patch augments it ──────────────
        let graph = Graph::new();
        let base = export_bundle(db).await.expect("export before graph");
        let with_entity = graph.bundle_on(&base);
        let row = plan_queue_apply(&state, &with_entity, false).await;
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");

        let mut patched = export_bundle(db).await.expect("export after graph");
        patched
            .attribute_patches
            .push(attome_api::bundle::AttributePatch {
                entity: graph.entity.clone(),
                attribute: Graph::attr("extra_field", "text"),
            });
        patched.normalize();
        let patch_plan = plan_bundle(db, &license, &patched, PlanOptions::default())
            .await
            .expect("plan (real entity)");
        assert!(patch_plan.blocked.is_empty(), "{:#?}", patch_plan.blocked);
        let patch_key = format!("{}.extra_field", graph.entity);
        assert!(
            patch_plan
                .entries
                .iter()
                .any(|e| e.component == "attribute_patch"
                    && e.key == patch_key
                    && e.action == PlanAction::Create),
            "{:#?}",
            patch_plan.entries
        );

        let patch_row = plan_queue_apply(&state, &patched, false).await;
        assert_eq!(patch_row.status, PlanStatus::Succeeded, "{patch_row:#?}");

        let after = export_bundle(db).await.expect("export after patch");
        let entity = after
            .entities
            .iter()
            .find(|e| e.logicalname == graph.entity)
            .expect("entity still present");
        // The three attributes Graph::bundle_on defined, plus the one patch —
        // never a full re-assertion that could have dropped or altered the rest.
        assert_eq!(
            entity.attributes.len(),
            4,
            "patch must only add the new field, not touch the entity's own attributes: {entity:#?}"
        );
        assert!(
            entity
                .attributes
                .iter()
                .any(|a| a.logicalname == "extra_field" && a.field_type == "text"),
            "{entity:#?}"
        );
        for original in ["name", "amount", "owner"] {
            assert!(
                entity.attributes.iter().any(|a| a.logicalname == original),
                "patch must not have dropped the entity's own attribute '{original}': {entity:#?}"
            );
        }
    })
}

/// C-21 (M01 §7) — `RelationshipCascade`'s canonical wire spelling is
/// hyphenated (`"cascade-deactivate"`, matching `OnTargetDelete`'s existing
/// D-088 vocabulary); the original underscore spelling
/// (`"cascade_deactivate"`) it used before this fix must still parse for one
/// release, since an already-exported bundle could carry it. Proves a
/// bundle `Step::Relationship` (`apply.rs`) applies successfully with EITHER
/// spelling in its `cascade` field, and that the value `export_bundle` hands
/// back afterward is always the normalized, canonical one — never the raw
/// string the bundle carried in.
#[test]
fn relationship_cascade_wire_spelling_round_trips_through_bundle_apply() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = &state.base.db;

        let entity_a = attome_testkit::unique_logicalname("bndlrela");
        let entity_b = attome_testkit::unique_logicalname("bndlrelb");
        attome_metadata::provision::ensure_entity(db, &entity_a, "Rel Cascade A", None, false)
            .await
            .expect("provision entity_a");
        attome_metadata::provision::ensure_entity(db, &entity_b, "Rel Cascade B", None, false)
            .await
            .expect("provision entity_b");

        for (tag, wire_cascade) in [
            ("legacy_underscore", "cascade_deactivate"),
            ("canonical_hyphen", "cascade-deactivate"),
        ] {
            // A relationship name is at most 48 characters.
            let suffix = Uuid::now_v7().simple().to_string();
            let name = format!("bndlrc_{tag}_{}", &suffix[suffix.len() - 12..]);
            let before = export_bundle(db).await.expect("export before");
            let mut desired = before.clone();
            desired.relationships.push(RelationshipDef {
                name: name.clone(),
                entity_a: entity_a.clone(),
                entity_b: entity_b.clone(),
                role_a: "As".to_owned(),
                role_b: "Bs".to_owned(),
                cascade: wire_cascade.to_owned(),
                is_active: true,
            });
            desired.normalize();

            let row = plan_queue_apply(&state, &desired, false).await;
            assert_eq!(row.status, PlanStatus::Succeeded, "{tag}: {row:#?}");

            let after = export_bundle(db).await.expect("export after");
            let applied = after
                .relationships
                .iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| {
                    panic!("{tag}: relationship {name} missing from export: {after:#?}")
                });
            assert_eq!(
                applied.cascade, "cascade-deactivate",
                "{tag}: input spelling '{wire_cascade}' must normalize to the canonical \
             hyphenated spelling on export"
            );
        }
    })
}
