//! D-133 (P-record-level-security item (a)): integration coverage for the
//! record-level access predicate (`attome_security::rls_predicate`) wired into
//! `entity_crud.rs`'s four generic handlers.
//!
//! Some grants (role/privilege/team/organization membership,
//! `role_mm_entity_access` depth) are still seeded directly via SQL
//! (same pattern `seed_admin`'s own privilege grant already uses) rather
//! than through the Phase 4 admin API this file also exercises further
//! down — this file's tests drive the real HTTP surface (`entity_crud.rs`)
//! on top of either seeding path, proving enforcement end-to-end rather
//! than only at the `rls_predicate` unit-test level (`attome-security/src/rls.rs`).
//!
//! D-136 (see DECISIONS.md) moved record-level scoping from a single
//! role-wide `role.access_level` scalar to per-`(role, entity, action)`
//! depth (`role_mm_entity_access`) — that column no longer exists.
//! `scope_role_for_entity` is this file's seeding helper for the new shape;
//! `seed_user_with_privileges` now bundles its privilege grant onto a role
//! (rather than a direct user grant) specifically so there is a role for
//! `scope_role_for_entity` to narrow — see both functions' doc comments.
//!
//! D-137 added `create_record_sets_owner_ref_to_creator`,
//! `reassign_owner_updates_owner_columns_and_grants_new_owner_access`,
//! `reassign_owner_to_team_supports_queue_ownership`, and
//! `reassign_owner_rejects_non_admin_callers` — written in a code-only
//! session with no live Postgres/Redis/Rust toolchain available, so **not
//! run or compiled in that session**; run them (and the rest of this file)
//! against a throwaway database before relying on D-137 in production, same
//! caveat D-134's addendum recorded for its own then-unrun endpoint test.
//!
//! D-141 (P-field-write-security) added
//! `merge_rejects_when_a_dependent_sensitive_field_lacks_write_grant` —
//! same "written and not run" caveat as D-137/D-138/D-139/D-140 above.
//!
//! 2026-07-30 added `bulk_and_entity_crud_agree_across_the_access_ownership_share_matrix`
//! — a security-review finding raised the concern that record-level
//! enforcement is "fragmented across query paths" (CRUD, bulk, files,
//! reports) and easy to desync. `attome_security::rls_predicate` is already the
//! single shared boundary every one of those paths calls into
//! (`entity_crud.rs`, `bulk.rs`, `files.rs`, `query_exec.rs`), so the
//! meaningful test isn't "does the predicate function work" (already covered
//! by `attome-security/src/rls.rs`'s own unit tests and
//! `attome-security/tests/rls_property.rs`'s property suite) but "do two
//! independently-written call sites reach the SAME allow/deny answer for the
//! identical scenario." This test drives the same access-level x share-state
//! scenario through both `entity_crud.rs` (HTTP GET) and `bulk.rs`
//! (`process`, the worker-side entry point `bulk_apply_and_wait` calls
//! directly) and asserts they agree. Same "written and not run" caveat as
//! D-137/D-138/D-139/D-140/D-141 above — no live Postgres/Redis available in
//! that session either; verify against a throwaway database before relying
//! on it. Deliberately NOT written with `proptest`: this is a small, finite
//! (access_level x share-state) space better served by an explicit,
//! readable scenario matrix than by randomized generation — see the
//! rationale in the workspace `Cargo.toml`'s "Testing" section and
//! `rls_property.rs`'s header, where `proptest` IS the right tool (pure
//! functions, a much larger combinatorial input space).
//!
//! 2026-07-31 added
//! `files_endpoints_deny_access_to_a_caller_outside_the_records_rls_scope`,
//! closing the gap this comment used to describe. All four `files.rs`
//! handlers (`create_upload_session`/`finalize_upload_session`/
//! `get_upload_session_status`/`get_download_url`) call
//! `require_record_access` before touching storage or a session's
//! `owner_user_ref`, so the RLS gate itself needs no S3/RustFS bucket to
//! exercise — only `file_upload_pipeline.rs`'s full clean-upload/scan
//! pipeline does. Same "written and not run" caveat as
//! D-137/D-138/D-139/D-140/D-141 above — no live Postgres/Redis/Rust
//! toolchain available in this session either; run it against a throwaway
//! database before relying on it.
//!
//! `polymorphic_audit_predicate` (D-140/D-147, `attome-security/src/rls.rs`) IS
//! now live-verified: `get_record_shows_an_audit_header_row_via_referenced_record_share_despite_narrowed_audit_scope`
//! and `query_execute_filters_audit_header_rows_by_the_referenced_record_when_callers_own_audit_scope_is_narrowed`
//! cover the target-bearing-row case (9ec8c7a); `query_execute_still_scopes_target_less_audit_rows_by_the_callers_own_audit_access`
//! covers the target-less-row case (login/logout events) that 9ec8c7a's own
//! list-path fix regressed — see that test's doc comment and `rls.rs`'s
//! updated `polymorphic_audit_predicate` doc comment for the full history.
//!
//! 2026-09-06 added `state_routes_enforce_record_level_access_not_just_entity_level`
//! (C-01): `attome-state::record_routes`'s two per-record HTTP routes
//! (`GET .../transitions`, `POST .../transition`) authorized only the
//! entity-level `RecordScoped<A>` privilege and never called
//! `require_record_access`, unlike every other record-level route this file
//! already covers (`entity_crud.rs`, `bulk.rs`, `files.rs`) — see that
//! test's doc comment for the exact gap and the fix
//! (`attome-state/src/record_routes.rs`).
//!
//! M01-core C-05 added `lookup_display_name_honours_target_entity_rls`:
//! lookup/polymorphic-reference display-name resolution
//! (`entity_crud::resolve_visible`, shared by `entity_crud::response`'s
//! single-record path, `query_exec.rs`'s list/grid path, and
//! `attome_document::documents_tree`'s Documents-browser grouping) used to read a
//! lookup target's `primary_name_attribute` with no predicate at all,
//! leaking an unreadable target's display name into a caller's own,
//! otherwise-authorized read.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as
//! `entity_round_trip.rs`/`authz.rs`. Run manually against a throwaway
//! database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test record_level_security -- --test-threads=1
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
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
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
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        // C-01: registers attome-state's admin CRUD + per-record routes
        // (`/transitions`, `/transition`) so
        // `state_routes_enforce_record_level_access_not_just_entity_level`
        // below can drive them through the real HTTP surface, same as every
        // other test in this file does for entity_crud/bulk/files.
        .register(attome_state::StateModel)
        .build()
        .await
        .expect("build EngineSystem");
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    Some(system)
}

/// See `entity_round_trip.rs`/`authz.rs`'s identical helper: `oneshot()`
/// test requests carry no `Sec-Fetch-Site`/`Origin` header, which
/// `csrf_protect` fails closed on for cookie-authenticated unsafe methods
/// by design. Stamping a matching `Origin` is the fix a real non-browser
/// caller would need too — `test_config()`'s `cors.allowed_origins` carries
/// the matching entry.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
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

async fn seed_admin(db: &PgPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("rls-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

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

    (user_id, session_cookie(user_id))
}

/// Creates a fresh `role` granting `"{logicalname}.{action}"` for each
/// of `actions` (via `role_mm_privilege`/`privilege`) — the shared
/// plumbing behind `seed_user_with_privileges` below and the D-136
/// regression test further down this file (which needs a SECOND role, for a
/// second entity, added to an ALREADY-EXISTING user rather than a
/// brand-new one).
///
/// Post-D-136 (see DECISIONS.md): a role's `role_mm_entity_access` depth
/// is only ever consulted for a privilege that role ITSELF grants
/// (`resolve_entity_access_level`'s `role_depth` CTE joins
/// `role_mm_privilege` on the exact same role) — so bundling the
/// privilege grant onto a role here, rather than a direct
/// `user_account_mm_privilege` grant, is what makes `scope_role_for_entity`
/// below meaningful at all. A direct grant (no role) would keep resolving
/// `Global` forever, same as pre-D-133 — the whole point of this helper
/// existing is to give the test a role to narrow.
async fn create_role_with_privileges(db: &PgPool, logicalname: &str, actions: &[&str]) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("rls-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");

    for action in actions {
        let key = format!("{logicalname}.{action}");
        let privilege_id: Uuid = sqlx::query_scalar(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
             VALUES ($1, $2, $3, $3, true, NOW(), 'project') \
             ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(&key)
        .bind(&key)
        .fetch_one(db)
        .await
        .expect("ensure privilege");

        sqlx::query(
            "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("grant role privilege");
    }

    role_id
}

/// Direct `user_account_mm_role` insert — no invalidation of its own
/// (callers that add a role to a user who may already have a cached
/// `SecurityContext` must invalidate themselves; a brand-new user, e.g. from
/// `seed_user_with_privileges`, has nothing cached yet so needs none).
async fn assign_role_to_user(db: &PgPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
}

/// A non-admin user granted `{entity}.{action}` for each action in
/// `actions` — via a freshly-created `role` that holds those
/// privileges (D-136: post-D-136, privilege and record-level depth live on
/// the SAME role, since `resolve_entity_access_level` only ever consults a
/// role's `role_mm_entity_access` row for a privilege that role itself
/// grants — see `create_role_with_privileges`'s doc comment). Returns the
/// role id too so a caller can layer record-level scoping onto it via
/// `scope_role_for_entity`.
async fn seed_user_with_privileges(
    db: &PgPool,
    logicalname: &str,
    actions: &[&str],
) -> (Uuid, String, Uuid) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("rls-test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway non-admin user");

    let role_id = create_role_with_privileges(db, logicalname, actions).await;
    assign_role_to_user(db, user_id, role_id).await;

    (user_id, session_cookie(user_id), role_id)
}

/// Upserts ONE row into `role_mm_entity_access` for `(role_id,
/// entity_id)`, uniform across all three actions (`read`/`write`/`delete`
/// access level all set to `access_level`) — none of this file's tests
/// distinguish update-depth from delete-depth, so a single scalar matches
/// every test's expectation exactly (see
/// `read_and_write_access_levels_resolve_independently_per_action` further
/// down for the one test that deliberately does NOT use this helper,
/// because it needs an asymmetric row).
///
/// Supersedes the pre-D-136 `assign_role_with_access_level`, which wrote a
/// single `role.access_level` scalar — that column (and the whole
/// role-wide ladder) no longer exists; migration `0054` moved it onto
/// `(role, entity)`. See DECISIONS.md D-136. `role_id` must already hold the
/// relevant `"{entity}.{action}"` privilege (e.g. via
/// `seed_user_with_privileges`/`create_role_with_privileges`) for this row
/// to be consulted at all.
///
/// Invalidates `user_id`'s cached `SecurityContext` afterward (D-012's 60s
/// TTL, same call every real grant-admin handler makes,
/// `attome-security/src/admin.rs`) — without this, a caller whose
/// `SecurityContext` was already resolved and cached (e.g. by an earlier
/// request in the same test, before this scoping write) would keep seeing
/// its pre-scoping depth for up to the TTL, since this raw-SQL seeding
/// bypasses every code path that would normally trigger invalidation.
async fn scope_role_for_entity(
    db: &PgPool,
    security: &attome_server::security::SecurityResolverHandle,
    role_id: Uuid,
    user_id: Uuid,
    entity_id: Uuid,
    access_level: i16,
) {
    sqlx::query(
        r#"
        INSERT INTO role_mm_entity_access
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer)
        VALUES ($1, $2, $3, $4, $4, $4, 'project')
        ON CONFLICT (role_ref, entity_ref) DO UPDATE SET
            read_access_level = EXCLUDED.read_access_level,
            write_access_level = EXCLUDED.write_access_level,
            delete_access_level = EXCLUDED.delete_access_level,
            is_deleted = false,
            updated_at = NOW()
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(access_level)
    .execute(db)
    .await
    .expect("upsert role entity-access grant");

    security.invalidate(user_id).await;
}

async fn create_team(db: &PgPool, name: &str) -> Uuid {
    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(team_id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test team");
    team_id
}

/// See `scope_role_for_entity`'s doc comment on why this invalidates —
/// team membership is also part of the cached `SecurityContext`
/// (`team_ids`) since D-133.
async fn add_user_to_team(
    db: &PgPool,
    security: &attome_server::security::SecurityResolverHandle,
    user_id: Uuid,
    team_id: Uuid,
) {
    sqlx::query("INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(team_id)
        .execute(db)
        .await
        .expect("add user to team");
    security.invalidate(user_id).await;
}

async fn create_organization(db: &PgPool, name: &str, parent: Option<Uuid>) -> Uuid {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organization (id, name, organization_ref, is_active) VALUES ($1, $2, $3, true)")
        .bind(org_id)
        .bind(name)
        .bind(parent)
        .execute(db)
        .await
        .expect("insert test organization");
    org_id
}

/// See `scope_role_for_entity`'s doc comment on why this invalidates —
/// `accessible_org_ids` is also part of the cached `SecurityContext` since
/// D-133.
async fn add_user_to_organization(
    db: &PgPool,
    security: &attome_server::security::SecurityResolverHandle,
    user_id: Uuid,
    org_id: Uuid,
) {
    sqlx::query(
        "INSERT INTO user_account_mm_organization (id, user_ref, organization_ref) VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(org_id)
    .execute(db)
    .await
    .expect("add user to organization");
    security.invalidate(user_id).await;
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Tests disable the background metadata registry subscriber, so lookup
/// validation and reverse-dependency discovery need an explicit refresh
/// after dynamically provisioning a lookup field.
async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build metadata registry");
    state.entities.swap(registry);
}

async fn provision_entity(app: &axum::Router, admin_cookie: &str, logicalname: &str) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"RLS Test"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create entity");
    let status = res.status();
    let entity = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create entity failed: {entity:?}"
    );
    Uuid::parse_str(entity["id"].as_str().expect("entity id")).expect("entity id is a uuid")
}

async fn provision_text_field(app: &axum::Router, admin_cookie: &str, entity_id: Uuid) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create field");
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// Creates a record as `creator_cookie` — the implicit-creator-share write
/// (D-133 (2)) means the creator always has `action` access to what they
/// just made, regardless of any access_level scoping layered on top.
async fn create_record_as(
    app: &axum::Router,
    creator_cookie: &str,
    logicalname: &str,
    title: &str,
) -> (String, i64) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", creator_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"title":"{title}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create record");
    assert_eq!(res.status(), StatusCode::CREATED, "creating {title} failed");
    let created = body_json(res).await;
    let id = created["id"].as_str().expect("record id").to_owned();
    let row_version = created["row_version"].as_i64().expect("row_version");
    (id, row_version)
}

async fn get_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.expect("get record").status()
}

async fn update_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
    row_version: i64,
) -> StatusCode {
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(r#"{"title":"updated"}"#))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("update record")
        .status()
}

async fn delete_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
    row_version: i64,
) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", cookie)
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("delete record")
        .status()
}

async fn restore_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/{record_id}/restore"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("restore record")
        .status()
}

async fn merge_records_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    canonical_id: &str,
    duplicate_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/{canonical_id}/merge"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"duplicate_id":"{duplicate_id}"}}"#
        )))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("merge records")
        .status()
}

async fn ancestors_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/{logicalname}/{record_id}/ancestors"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("list ancestors")
        .status()
}

async fn descendants_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/{logicalname}/{record_id}/descendants"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("list descendants")
        .status()
}

async fn upsert_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    match_field: &str,
    match_value: &str,
    row_version: Option<i64>,
) -> StatusCode {
    // `data` is deliberately empty (`upsert_record`'s own semantics: `data`
    // overrides `match` on any overlapping key) — an upsert test that
    // matches on "title" must not also write "title" via `data`, or the
    // merged field set used to build the precheck's WHERE clause would
    // filter on the `data` value instead of `match_value`, silently missing
    // the very row the test means to target.
    let body = match row_version {
        Some(v) => format!(
            r#"{{"match":{{"{match_field}":"{match_value}"}},"data":{{}},"row_version":{v}}}"#
        ),
        None => format!(r#"{{"match":{{"{match_field}":"{match_value}"}},"data":{{}}}}"#),
    };
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/upsert"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("upsert record")
        .status()
}

/// Drives `bulk.rs::process` directly (worker-side entry point) against a
/// fresh `automation_bulk_operation` row seeded the same shape `enqueue` writes —
/// this test file exercises HTTP handlers everywhere else, but bulk mutation
/// actually applies on the *worker* path (D-100: `enqueue` only queues the
/// job), so proving `bulk.rs`'s record-level gate requires calling `process`
/// the way the Apalis worker would, not going through `POST .../bulk` and
/// waiting on a real queue.
async fn bulk_apply_and_wait(
    state: &EngineState,
    logicalname: &str,
    operation: &str,
    records: Vec<serde_json::Value>,
    user_id: Uuid,
) -> (i32, i32) {
    let bulk_op_id = Uuid::now_v7();
    let total = records.len() as i32;
    sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by) \
         VALUES ($1, $2, $3, 'pending', $4, $5)",
    )
    .bind(bulk_op_id)
    .bind(logicalname)
    .bind(operation)
    .bind(total)
    .bind(user_id)
    .execute(&state.base.db)
    .await
    .expect("seed automation_bulk_operation");

    attome_records::bulk::process(state, bulk_op_id, logicalname, operation, records, user_id)
        .await
        .expect("bulk process");

    sqlx::query_as("SELECT succeeded, failed FROM automation_bulk_operation WHERE id = $1")
        .bind(bulk_op_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read bulk operation result")
}

/// D-133 backward-compatibility regression guard: a user with direct
/// (table-level) privilege grants but assigned to NO role at all must
/// resolve to `AccessLevel::Global` (fully unfiltered — `rls_predicate`
/// returns `None`, exactly as it does for `is_admin`), not `AccessLevel::None`
/// — this is the exact defect the entity_round_trip.rs backward-compat gate
/// caught during D-133's own implementation (see D-133's fix to
/// `resolve_access_level`). A caller who never touches the new role/team
/// system stays byte-identical to pre-D-133 behavior: table-level privilege
/// alone is sufficient to see every record of that entity, same as before
/// D-133 existed.
#[test]
fn caller_with_no_role_defaults_to_global_access() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_noroletest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) = create_record_as(&app, &creator_cookie, &logicalname, "mine").await;

        // A second user, also holding a role that grants table-level read but
        // no entity-access row narrowing it — sees the creator's record via the
        // Global default, matching pre-D-133 (table-level-only) behavior
        // exactly. This is what "zero behavior change until an admin explicitly
        // narrows a grant" means in practice — Global is not "ownership plus
        // nothing," it is genuinely unfiltered.
        let (_reader_id, reader_cookie, _reader_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        assert_eq!(
            get_record_as(&app, &reader_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "a no-role reader with table-level read privilege must see any record \
         of that entity — Global (the default for a role-less caller) applies \
         no record-level filtering at all, matching pre-D-133 behavior"
        );

        // The creator, also with no role assigned, still sees their own record
        // (via Global here, not the creator-share — both agree in this case).
        assert_eq!(
            get_record_as(&app, &creator_cookie, &logicalname, &record_id).await,
            StatusCode::OK
        );
        let _ = creator_id;
    })
}

/// `Team`-tier access: a role's `access_level = Team` (1) makes a caller's
/// team membership matter — `entity_default_share` targeting the
/// caller's team grants access to every record of that entity, without a
/// per-record share.
#[test]
fn team_tier_grants_access_via_entity_default_share() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_teamtest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "team-owned").await;

        let (teammate_id, teammate_cookie, teammate_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        // Scope the teammate's own privilege-granting role to Team-tier BEFORE
        // the negative check below — without this, the teammate's unscoped
        // default (Global, unfiltered) would let them see the record regardless
        // of team/share state, which would defeat the point of this test
        // (proving the Team tier itself is filtering, not just "no narrowing
        // happened yet").
        let team_id = create_team(&db, &format!("rls-test-team-{}", Uuid::now_v7())).await;
        add_user_to_team(&db, &security, teammate_id, team_id).await;
        scope_role_for_entity(
            &db,
            &security,
            teammate_role_id,
            teammate_id,
            entity_id,
            1, // Team
        )
        .await;

        // Team-tier, but no entity-default share targeting the team yet: the
        // teammate must not see the creator's record.
        assert_eq!(
            get_record_as(&app, &teammate_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "a Team-tier caller must not see another user's record before any \
         team-targeted share exists"
        );

        sqlx::query(
        "INSERT INTO entity_default_share (entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, 1, $2, 0, 'project')", // principal_type=team, capability=view
    )
    .bind(entity_id)
    .bind(team_id)
    .execute(&db)
    .await
    .expect("insert entity default share for team");

        assert_eq!(
            get_record_as(&app, &teammate_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "a Team-tier caller whose team has a view default-share on this entity \
         must see every record of it, including one they didn't create"
        );
        let _ = creator_id;
    })
}

/// `BusinessUnit`-tier access: a role's `access_level = BusinessUnit` (2)
/// scopes visibility to the caller's accessible org set (own org +
/// descendants, via `organization`'s self-referential hierarchy).
#[test]
fn business_unit_tier_scopes_by_org_hierarchy() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_butest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        // Parent org + child org — the manager sits in the parent, the creator
        // in the child, proving descendant-walk, not just exact-org match.
        let parent_org = create_organization(&db, "rls-test-parent-org", None).await;
        let child_org = create_organization(&db, "rls-test-child-org", Some(parent_org)).await;
        let sibling_org = create_organization(&db, "rls-test-sibling-org", None).await;

        let (creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        add_user_to_organization(&db, &security, creator_id, child_org).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "org-scoped").await;

        // Stamp the record's organization_ref to the child org directly — the
        // generic entity_crud create path doesn't accept organization_ref as a
        // user-writable field (system column, set from fetch_audit_ctx's
        // resolution of the *creator's* primary org, attome_server-side); setting
        // it explicitly here isolates this test from that resolution path so it
        // tests the BusinessUnit predicate itself, not organization_ref
        // assignment plumbing.
        sqlx::query(&format!(
            "UPDATE \"{logicalname}\" SET organization_ref = $1 WHERE id = $2"
        ))
        .bind(child_org)
        .bind(Uuid::parse_str(&record_id).unwrap())
        .execute(&db)
        .await
        .expect("stamp organization_ref for test");

        let (manager_id, manager_cookie, manager_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        add_user_to_organization(&db, &security, manager_id, parent_org).await;
        scope_role_for_entity(
            &db,
            &security,
            manager_role_id,
            manager_id,
            entity_id,
            2, // BusinessUnit
        )
        .await;

        assert_eq!(
            get_record_as(&app, &manager_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "a BusinessUnit-tier manager in the parent org must see a record \
         scoped to a descendant (child) org"
        );

        let (outsider_id, outsider_cookie, outsider_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        add_user_to_organization(&db, &security, outsider_id, sibling_org).await;
        scope_role_for_entity(
            &db,
            &security,
            outsider_role_id,
            outsider_id,
            entity_id,
            2, // BusinessUnit
        )
        .await;

        assert_eq!(
            get_record_as(&app, &outsider_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "a BusinessUnit-tier caller in an unrelated sibling org must not see \
         a record scoped to a different org tree"
        );
    })
}

/// D-136 regression: closes the exact cross-entity privilege-escalation gap
/// D-136 fixed (see DECISIONS.md's `## D-136` entry). Before the fix,
/// `resolve_access_level` took a bare `MAX` across every role a user held,
/// with no entity boundary — so a role scoped Global for one entity (here,
/// Employee) silently widened a DIFFERENT entity's scope too (here,
/// Customer), for any user who also held a role scoped narrower for that
/// second entity (here, Team).
///
/// One user holds TWO independent roles on TWO different entities: an
/// Employee role left at the (unscoped) Global default, and a Customer role
/// scoped Team via an entity-default share targeting a team the user
/// belongs to (mirroring `team_tier_grants_access_via_entity_default_share`'s
/// own setup for the Customer side). This proves, in both directions, that
/// neither role's resolution leaks into the other entity: the Employee-Global
/// role must never widen Customer access (the actual pre-D-136 bug), and the
/// Customer-Team role must never narrow the already-Global Employee access
/// either (the same bug, mirrored) — each role must keep working correctly
/// on its own entity despite the other role's presence.
#[test]
fn cross_entity_scope_never_leaks_between_roles() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let employee_name = format!("rls_d136_emp_{}", Uuid::now_v7().simple());
        let customer_name = format!("rls_d136_cust_{}", Uuid::now_v7().simple());
        let employee_entity_id = provision_entity(&app, &admin_cookie, &employee_name).await;
        provision_text_field(&app, &admin_cookie, employee_entity_id).await;
        let customer_entity_id = provision_entity(&app, &admin_cookie, &customer_name).await;
        provision_text_field(&app, &admin_cookie, customer_entity_id).await;

        // The user under test: Role A grants Employee read, left at the
        // (unscoped) Global default — no role_mm_entity_access row at all.
        let (user_id, user_cookie, _employee_role_id) =
            seed_user_with_privileges(&db, &employee_name, &["read"]).await;

        // Role B — a SECOND, independent role on the SAME user — grants
        // Customer read, scoped Team via a team the user is added to.
        let customer_role_id = create_role_with_privileges(&db, &customer_name, &["read"]).await;
        assign_role_to_user(&db, user_id, customer_role_id).await;
        let team_id = create_team(&db, &format!("rls-d136-team-{}", Uuid::now_v7())).await;
        add_user_to_team(&db, &security, user_id, team_id).await;
        scope_role_for_entity(
            &db,
            &security,
            customer_role_id,
            user_id,
            customer_entity_id,
            1, // Team
        )
        .await;

        // (1) The Employee-Global role, on its own: the user must see an
        // Employee record someone else created — proves the role still works
        // correctly by itself, closing the loop with (2)/(3) below.
        let (_other_id, other_cookie, _other_role_id) =
            seed_user_with_privileges(&db, &employee_name, &["read", "create"]).await;
        let (employee_record_id, _) = create_record_as(
            &app,
            &other_cookie,
            &employee_name,
            "someone-elses-employee-row",
        )
        .await;
        assert_eq!(
            get_record_as(&app, &user_cookie, &employee_name, &employee_record_id).await,
            StatusCode::OK,
            "the Employee-Global role must grant access to any Employee record \
         on its own, unaffected by the user also holding a second, \
         Customer-scoped role"
        );

        // (2) The core regression check: a Customer record created OUTSIDE the
        // user's team must stay invisible. If the Employee role's Global scope
        // ever leaked into Customer resolution (the pre-D-136 bug), this would
        // incorrectly succeed.
        let (_outsider_id, outsider_cookie, _outsider_role_id) =
            seed_user_with_privileges(&db, &customer_name, &["read", "create"]).await;
        let (customer_record_outside, _) = create_record_as(
            &app,
            &outsider_cookie,
            &customer_name,
            "outside-team-customer",
        )
        .await;
        assert_eq!(
            get_record_as(&app, &user_cookie, &customer_name, &customer_record_outside).await,
            StatusCode::NOT_FOUND,
            "D-136: the user's Employee role is Global-scoped, but that must \
         never leak into Customer resolution — a Customer record outside \
         the user's team must stay invisible, exactly as the Customer-Team \
         role alone dictates"
        );

        // (3) The Customer-Team role must still genuinely work: a Customer
        // record created by a teammate, with a view default-share targeting the
        // team, must be visible — proving the narrower role isn't ALSO being
        // wrongly suppressed by the presence of the other role.
        let (teammate_id, teammate_cookie, _teammate_role_id) =
            seed_user_with_privileges(&db, &customer_name, &["read", "create"]).await;
        add_user_to_team(&db, &security, teammate_id, team_id).await;
        let (customer_record_inside, _) = create_record_as(
            &app,
            &teammate_cookie,
            &customer_name,
            "inside-team-customer",
        )
        .await;

        sqlx::query(
        "INSERT INTO entity_default_share (entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, 1, $2, 0, 'project')", // principal_type=team, capability=view
    )
    .bind(customer_entity_id)
    .bind(team_id)
    .execute(&db)
    .await
    .expect("insert entity default share for team");

        assert_eq!(
            get_record_as(&app, &user_cookie, &customer_name, &customer_record_inside).await,
            StatusCode::OK,
            "the Customer-Team role must still genuinely grant access to a \
         teammate's Customer record, despite the user also holding a \
         Global-scoped Employee role"
        );
    })
}

/// D-136 (independent per-action resolution): `role_mm_entity_access`
/// carries three separate columns (`read_access_level`/`write_access_level`/
/// `delete_access_level`) — this proves a single role, scoped wide (`Team`)
/// for read and narrow (`None`) for update on the very SAME entity, actually
/// resolves each action from its own column rather than one shared value.
/// Also closes two items from the record-level-security checklist: "Global
/// (or Team) read permission does not grant update" and "Team update does
/// not grant team read unless read is separately granted" — both reduce to
/// the same per-action independence this test exercises directly.
#[test]
fn read_and_write_access_levels_resolve_independently_per_action() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_peraction_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "mine").await;

        let team_id = create_team(&db, &format!("rls-test-team-{}", Uuid::now_v7())).await;
        sqlx::query(
        "INSERT INTO entity_default_share (entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, 1, $2, 0, 'project')", // team, view
    )
    .bind(entity_id)
    .bind(team_id)
    .execute(&db)
    .await
    .expect("insert entity default share for team");

        let (caller_id, caller_cookie, role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "update"]).await;
        add_user_to_team(&db, &security, caller_id, team_id).await;

        // read_access_level = Team (1), write_access_level = None (0) — the
        // same role, the same entity, two different depths.
        sqlx::query(
            r#"
        INSERT INTO role_mm_entity_access
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer)
        VALUES ($1, $2, $3, 1, 0, 0, 'project')
        "#,
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(entity_id)
        .execute(&db)
        .await
        .expect("insert asymmetric entity-access row");
        security.invalidate(caller_id).await;

        assert_eq!(
            get_record_as(&app, &caller_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "Team-scoped read, backed by the team's view default-share, must \
         grant read access"
        );
        assert_eq!(
            update_record_as(&app, &caller_cookie, &logicalname, &record_id, row_version).await,
            StatusCode::NOT_FOUND,
            "the SAME role's write_access_level (None) must resolve \
         independently of its read_access_level (Team) — a caller who can \
         read a record via Team-tier default-share must not also be able \
         to update it just because read succeeded"
        );
    })
}

/// F137 explicit per-record sharing: `record_share` grants access
/// outside any hierarchy/team relationship entirely — the "share this one
/// record with that one person" case neither ownership nor BU/Team scoping
/// can express.
#[test]
fn explicit_record_share_grants_access_outside_any_hierarchy() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_sharetest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "shared-record").await;

        let (stranger_id, stranger_cookie, stranger_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "update"]).await;
        scope_role_for_entity(
            &db,
            &security,
            stranger_role_id,
            stranger_id,
            entity_id,
            0, // None
        )
        .await;

        assert_eq!(
            get_record_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "before any share exists, a None-tier stranger must not see the record"
        );

        // Grant only `view` first — proves view/action are independently
        // enforced, not a single "has access" boolean.
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)", // principal_type=user, capability=view
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(stranger_id)
    .execute(&db)
    .await
    .expect("insert view share");

        assert_eq!(
            get_record_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "a view-capability share must grant read access"
        );
        assert_eq!(
            update_record_as(
                &app,
                &stranger_cookie,
                &logicalname,
                &record_id,
                row_version
            )
            .await,
            StatusCode::NOT_FOUND,
            "a view-only share must NOT grant update (action-capability) access"
        );

        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)", // capability=action
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(stranger_id)
    .execute(&db)
    .await
    .expect("insert action share");

        assert_eq!(
            update_record_as(
                &app,
                &stranger_cookie,
                &logicalname,
                &record_id,
                row_version
            )
            .await,
            StatusCode::OK,
            "adding an action-capability share must grant update access"
        );
    })
}

/// Deny (D-133 (4)): an explicit `deny` share row overrides an otherwise-
/// valid grant (here, the implicit creator-share itself), but `is_admin`
/// bypasses the deny check unconditionally — a deny row can never lock out
/// a platform admin.
#[test]
fn deny_overrides_an_otherwise_valid_grant_but_never_blocks_admin() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_denytest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "denied-record").await;

        // Narrow the creator to None-tier (deliberately the least permissive):
        // with the unscoped Global default, rls_predicate would return None
        // (no filtering at all) and never consult record_share's deny
        // capability in the first place — this test needs record-level
        // filtering active so the deny row's effect is actually exercised.
        scope_role_for_entity(
            &db,
            &security,
            creator_role_id,
            creator_id,
            entity_id,
            0, /* None */
        )
        .await;

        // Sanity: the creator still sees their own record via the implicit
        // creator-share (D-133 (2)), even at the None access-level tier, before
        // any deny row exists.
        assert_eq!(
            get_record_as(&app, &creator_cookie, &logicalname, &record_id).await,
            StatusCode::OK
        );

        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 2)", // capability=deny
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(creator_id)
    .execute(&db)
    .await
    .expect("insert deny share");

        assert_eq!(
            get_record_as(&app, &creator_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "an explicit deny row must override the creator's own implicit action-share"
        );

        // The platform admin (is_admin = true) must still see the record
        // despite the deny row targeting the creator, not the admin — proving
        // the deny mechanism is scoped per-principal AND that is_admin bypasses
        // the deny check entirely regardless of whom it targets.
        assert_eq!(
            get_record_as(&app, &admin_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "is_admin must bypass every rls_predicate check, including deny"
        );
    })
}

// ── D-133 Phase 4: admin API for roles.access_level, teams, and shares ────────
// The tests above seed access_level/teams/shares directly via SQL (no admin
// API existed yet when they were written). These tests instead exercise the
// admin endpoints themselves end-to-end — the real HTTP surface an operator
// now has instead of raw SQL.

/// Creates a role via the real (unchanged) admin endpoint — post-D-136,
/// `CreateRoleBody`/`RoleItem` no longer carry `access_level` at all (see
/// `crates/engine/attome-security/src/admin.rs`), so this helper no longer takes
/// or asserts one.
async fn create_role_via_api(app: &axum::Router, admin_cookie: &str) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/roles")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"name":"rls-api-role-{}"}}"#,
            Uuid::now_v7()
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create role");
    assert_eq!(res.status(), StatusCode::CREATED);
    let role = body_json(res).await;
    Uuid::parse_str(role["id"].as_str().unwrap()).unwrap()
}

/// Grants `role_id` a privilege via the real (unchanged) `/role-grants`
/// endpoint (`create_role_grant`/`list_role_grants` in admin.rs).
async fn grant_role_privilege_via_api(
    app: &axum::Router,
    admin_cookie: &str,
    role_id: Uuid,
    privilege_key: &str,
) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/role-grants")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"role_id":"{role_id}","privilege_key":"{privilege_key}"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create role grant");
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// Upserts a role's entity-access grant via `POST /role-entity-access`
/// (`upsert_entity_access_grant` in admin.rs) — the D-136 replacement for
/// the removed `PUT /roles/{id}/access-level`. Sets all three action depths
/// to the same `level`, matching every other helper in this file.
async fn upsert_entity_access_via_api(
    app: &axum::Router,
    admin_cookie: &str,
    role_id: Uuid,
    entity: &str,
    level: i16,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/role-entity-access")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"role_id":"{role_id}","entity":"{entity}","read_access_level":{level},"write_access_level":{level},"delete_access_level":{level}}}"#
        )))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("upsert entity-access grant")
        .status()
}

/// Confirms `POST /role-entity-access` actually changes enforcement, not
/// just the stored row — supersedes the removed `PUT
/// /roles/{id}/access-level` (D-136: role-wide `access_level` no longer
/// exists, see DECISIONS.md). Creates a role via the real API, grants it
/// the entity's `read` privilege via `/role-grants`, narrows/widens its
/// depth live via `/role-entity-access`, and proves a holder's next request
/// reflects the change immediately (the endpoint's `invalidate_sync_all`
/// fan-out via `users_holding_role`), not the test-helper
/// `scope_role_for_entity`.
///
/// The reader here is a bare user with NO privilege of its own — not
/// `seed_user_with_privileges` — because that helper now bundles its own
/// privilege-granting role at the (unscoped) Global default; if the reader
/// also held that role, `resolve_entity_access_level`'s cross-role `MAX`
/// would keep resolving Global regardless of what this test narrows the
/// role under test to, defeating the point of the test.
#[test]
fn update_role_access_level_endpoint_changes_enforcement_live() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_arole_{}", Uuid::now_v7().simple());
        provision_text_field(
            &app,
            &admin_cookie,
            provision_entity(&app, &admin_cookie, &logicalname).await,
        )
        .await;

        let (creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) = create_record_as(&app, &creator_cookie, &logicalname, "mine").await;

        let reader_id = Uuid::now_v7();
        sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
            .bind(reader_id)
            .bind(format!("rls-test-reader-{reader_id}"))
            .execute(&db)
            .await
            .expect("insert throwaway reader");
        let reader_cookie = session_cookie(reader_id);

        let role_id = create_role_via_api(&app, &admin_cookie).await;
        grant_role_privilege_via_api(&app, &admin_cookie, role_id, &format!("{logicalname}.read"))
            .await;
        sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(reader_id)
        .bind(role_id)
        .execute(&db)
        .await
        .expect("assign role directly via SQL (keeps this test focused on its own subject; see user_role_admin_endpoints_end_to_end for the dedicated endpoint test)");

        assert_eq!(
            get_record_as(&app, &reader_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "Global-tier (the default for a role with no entity-access row) must not filter"
        );

        // Narrow via the real endpoint.
        assert_eq!(
            upsert_entity_access_via_api(&app, &admin_cookie, role_id, &logicalname, 0).await,
            StatusCode::CREATED
        );

        assert_eq!(
            get_record_as(&app, &reader_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "after POST /role-entity-access narrows this role to None for this \
         entity, the reader must lose access to another user's record — \
         proves the endpoint's invalidate_sync_all fan-out actually takes \
         effect, not just the stored row"
        );

        // Widen back via the same endpoint.
        assert_eq!(
            upsert_entity_access_via_api(&app, &admin_cookie, role_id, &logicalname, 3).await,
            StatusCode::CREATED
        );

        assert_eq!(
            get_record_as(&app, &reader_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "widening back to Global must restore access on the reader's very \
         next request"
        );

        // Out-of-range access level is rejected with a clear validation error,
        // not a raw constraint-violation 500.
        let bad_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/role-entity-access")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"role_id":"{role_id}","entity":"{logicalname}","read_access_level":99,"write_access_level":99,"delete_access_level":99}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(bad_req)
            .await
            .expect("bad access level");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let _ = creator_id;
    })
}

/// Team CRUD + membership + role-assignment, entirely through the admin API
/// — create a team, add a member by email, assign a role to the whole team,
/// prove a Team-tier member gains access via an entity-default share
/// created through the API, then remove the member and prove access is
/// lost on their very next request.
#[test]
fn team_admin_endpoints_end_to_end() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_ateam_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "team-owned").await;

        let (member_id, member_cookie, member_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        let member_email = format!("sensitive-reader-{member_id}@test.local");
        // seed_user_with_privileges doesn't set email; set it directly so the
        // team-membership endpoint (which resolves by email) can find this user.
        sqlx::query("UPDATE user_account SET email = $1 WHERE id = $2")
            .bind(&member_email)
            .bind(member_id)
            .execute(&db)
            .await
            .expect("set member email");

        // Create team via API.
        let create_team_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/teams")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"rls-api-team-{}"}}"#,
                Uuid::now_v7()
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_team_req)
            .await
            .expect("create team");
        assert_eq!(res.status(), StatusCode::CREATED);
        let team = body_json(res).await;
        let team_id = team["id"].as_str().unwrap().to_owned();

        // List teams includes it.
        let list_req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/security/teams")
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(list_req).await.expect("list teams");
        assert_eq!(res.status(), StatusCode::OK);
        let teams = body_json(res).await;
        assert!(
            teams["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == team_id),
            "newly created team must appear in the list"
        );

        // Add member by email.
        let add_member_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/security/teams/{team_id}/members"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"user_email":"{member_email}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(add_member_req)
            .await
            .expect("add member");
        assert_eq!(res.status(), StatusCode::CREATED);

        // Scope the member's own privilege-granting role to Team-tier so
        // Team-tier filtering actually applies (matching the raw-SQL tests'
        // own reasoning — the unscoped Global default would bypass filtering).
        scope_role_for_entity(
            &db,
            &security,
            member_role_id,
            member_id,
            entity_id,
            1, /* Team */
        )
        .await;

        assert_eq!(
            get_record_as(&app, &member_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "Team-tier member with no default-share yet must not see the record"
        );

        // Grant an entity-default view share to the team via the API.
        let share_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/entity-default-shares")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"entity":"{logicalname}","capability":"view","team_name":"{}"}}"#,
                team["name"].as_str().unwrap()
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(share_req)
            .await
            .expect("create default share");
        assert_eq!(res.status(), StatusCode::CREATED);

        assert_eq!(
            get_record_as(&app, &member_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "after the team gains a view default-share via the API, the member \
         must see the record"
        );

        // Remove the member via the API — must lose team-mediated access
        // immediately (invalidate_sync in remove_team_member).
        let remove_req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/admin/security/teams/{team_id}/members/{member_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(remove_req)
            .await
            .expect("remove member");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            get_record_as(&app, &member_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "after removal, the ex-member must lose team-mediated access on \
         their very next request, not after a cache TTL"
        );

        let _ = creator_id;
    })
}

/// Record-share admin API: create a view share via the endpoint, list it
/// back, then revoke it via DELETE and confirm access is actually removed
/// on the sharee's next request.
#[test]
fn record_share_admin_endpoints_end_to_end() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_ashare_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "api-shared-record").await;

        let (stranger_id, stranger_cookie, stranger_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        let stranger_email = format!("stranger-{stranger_id}@test.local");
        sqlx::query("UPDATE user_account SET email = $1 WHERE id = $2")
            .bind(&stranger_email)
            .bind(stranger_id)
            .execute(&db)
            .await
            .expect("set stranger email");

        // Narrow the stranger's own privilege-granting role to None so
        // record-level filtering actually applies (same reasoning as every
        // other test in this file).
        scope_role_for_entity(
            &db,
            &security,
            stranger_role_id,
            stranger_id,
            entity_id,
            0, /* None */
        )
        .await;

        assert_eq!(
            get_record_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND
        );

        // Create the share via the API.
        let create_share_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/record-shares")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"{logicalname}","record_id":"{record_id}","capability":"view","user_email":"{stranger_email}"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(create_share_req)
            .await
            .expect("create record share");
        assert_eq!(res.status(), StatusCode::CREATED);
        let share = body_json(res).await;
        let share_id = share["id"].as_str().unwrap().to_owned();
        assert_eq!(share["capability"], "view");
        assert_eq!(share["principal_type"], "user");

        assert_eq!(
            get_record_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "after the API-created view share, the stranger must see the record"
        );

        // List shares on this record includes it.
        let list_req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/admin/security/record-shares?entity={logicalname}&record_id={record_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(list_req).await.expect("list shares");
        assert_eq!(res.status(), StatusCode::OK);
        let shares = body_json(res).await;
        assert!(
            shares["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["id"] == share_id),
            "the created share must appear in the list: {shares:?}"
        );

        // Revoke via DELETE.
        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/security/record-shares/{share_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(delete_req).await.expect("delete share");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            get_record_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "after DELETE, the stranger must lose access on their very next request"
        );
    })
}

/// D-137: `create_record` must set the denormalized `owner_ref`/`owner_type`
/// columns to the creator (0=user) — independent of, and in addition to,
/// `grant_creator_share`'s `record_share` row (D-133 (2)), which stays
/// the actual access-check mechanism and is not exercised again here (see
/// `record_share_admin_endpoints_end_to_end`/every access-scoping test above
/// for that coverage).
#[test]
fn create_record_sets_owner_ref_to_creator() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_owner_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, _role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "owner-on-create").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &creator_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("get record");
        assert_eq!(res.status(), StatusCode::OK);
        let record = body_json(res).await;
        assert_eq!(
            record["data"]["owner_ref"],
            creator_id.to_string(),
            "owner_ref must be the creator immediately after create: {record:?}"
        );
        assert_eq!(
            record["data"]["owner_type"], 0,
            "owner_type must be 0 (user) for a normal create: {record:?}"
        );
    })
}

/// D-137: `PUT .../record-shares/reassign-owner` changes the denormalized
/// owner columns AND grants the new owner real access (an `action`-capability
/// `record_share` row) in one call — proven end-to-end via the actual
/// entity_crud HTTP surface, not just the admin response shape. Also proves
/// the previous owner's original access is left untouched (D-133 (2)'s
/// existing "no automatic cascade on reassignment" posture, carried forward
/// by this decision rather than silently changed).
#[test]
fn reassign_owner_updates_owner_columns_and_grants_new_owner_access() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_reassign_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, row_version_before) =
            create_record_as(&app, &creator_cookie, &logicalname, "reassign-me").await;

        let (new_owner_id, new_owner_cookie, new_owner_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        let new_owner_email = format!("new-owner-{new_owner_id}@test.local");
        sqlx::query("UPDATE user_account SET email = $1 WHERE id = $2")
            .bind(&new_owner_email)
            .bind(new_owner_id)
            .execute(&db)
            .await
            .expect("set new owner email");

        // Narrow the new owner's own role to None so any success reading the
        // record afterward is provably coming from the reassignment's share
        // grant, not from a still-Global default.
        scope_role_for_entity(
            &db,
            &security,
            new_owner_role_id,
            new_owner_id,
            entity_id,
            0, /* None */
        )
        .await;
        assert_eq!(
            get_record_as(&app, &new_owner_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "sanity check: before reassignment the new owner must not see the record"
        );

        let reassign_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/admin/security/record-shares/reassign-owner")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"{logicalname}","record_id":"{record_id}","user_email":"{new_owner_email}"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(reassign_req)
            .await
            .expect("reassign owner");
        assert_eq!(res.status(), StatusCode::OK);
        let owner = body_json(res).await;
        assert_eq!(owner["owner_type"], "user");
        assert_eq!(owner["owner_id"], new_owner_id.to_string());

        assert_eq!(
            get_record_as(&app, &new_owner_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "reassignment must grant the new owner real access on their very next request"
        );

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &new_owner_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get record");
        let record = body_json(res).await;
        assert_eq!(record["data"]["owner_ref"], new_owner_id.to_string());
        assert_eq!(
            record["row_version"].as_i64().unwrap(),
            row_version_before + 1,
            "reassignment must bump row_version like any other entity-table write"
        );

        assert_eq!(
            get_record_as(&app, &creator_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "the previous owner's original creator-share must be left untouched by reassignment"
        );
    })
}

/// D-137: reassignment supports `owner_type = 1` (team) for queue-style
/// ownership — "Unassigned Leads" assigned to a team rather than a person —
/// admin-driven only (see `reassign_owner`'s doc comment on why a non-admin
/// self-service "claim" action is explicitly out of scope for this decision).
#[test]
fn reassign_owner_to_team_supports_queue_ownership() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_queue_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "queue-me").await;

        let team_name = format!("rls-queue-team-{}", Uuid::now_v7());
        let team_id = create_team(&db, &team_name).await;

        let reassign_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/admin/security/record-shares/reassign-owner")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"{logicalname}","record_id":"{record_id}","team_name":"{team_name}"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(reassign_req)
            .await
            .expect("reassign owner to team");
        assert_eq!(res.status(), StatusCode::OK);
        let owner = body_json(res).await;
        assert_eq!(owner["owner_type"], "team");
        assert_eq!(owner["owner_id"], team_id.to_string());

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &creator_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(get_req).await.expect("get record");
        let record = body_json(res).await;
        assert_eq!(record["data"]["owner_ref"], team_id.to_string());
        assert_eq!(record["data"]["owner_type"], 1, "1 = team");
    })
}

/// D-137: `reassign_owner` is `system.admin`-gated, same as every other
/// `record-shares` mutation (see `reassign_owner`'s doc comment on why
/// opening this to a non-admin `Team+`/`BusinessUnit+` actor needs a
/// dedicated privilege verb this decision deliberately does not add).
#[test]
fn reassign_owner_rejects_non_admin_callers() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_reown_noadm_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "no-admin-reassign").await;

        let (_other_id, other_cookie, _other_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;

        let reassign_req = Request::builder()
        .method("PUT")
        .uri("/api/v1/admin/security/record-shares/reassign-owner")
        .header("cookie", &other_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"{logicalname}","record_id":"{record_id}","user_email":"nobody@test.local"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(reassign_req)
            .await
            .expect("reassign owner as non-admin");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    })
}

/// Direct user↔role admin endpoint (post-D-134 remainder item): assign a
/// role straight to a user via the API instead of the team-mediated path or
/// raw SQL (every other test in this file that needed this seeded it
/// directly, noting "no per-user role-assignment endpoint exists yet").
/// Confirms list/assign/revoke all work and that assignment/revocation each
/// take effect on the callers's very next request via `invalidate_sync`, not
/// after the cache TTL.
///
/// The target here is a genuinely bare user (no privilege, no role at all)
/// rather than `seed_user_with_privileges` — post-D-136, that helper always
/// bundles its own privilege-granting role, so "no roles yet" would no
/// longer be literally true and, more importantly, assigning a SECOND role
/// via the endpoint under test could never be observed to narrow/widen
/// anything: `resolve_entity_access_level`'s cross-role `MAX` would keep
/// resolving whatever the bundled role's own (Global) default already gives.
/// Starting bare means the assignment endpoint is what supplies the read
/// privilege in the first place — the most direct way to prove its
/// `invalidate_sync` actually takes effect immediately.
#[test]
fn user_role_admin_endpoints_end_to_end() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_auserrole_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (_creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let (record_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "user-role-owned").await;

        let target_id = Uuid::now_v7();
        sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
            .bind(target_id)
            .bind(format!("rls-test-target-{target_id}"))
            .execute(&db)
            .await
            .expect("insert throwaway bare target user");
        let target_cookie = session_cookie(target_id);

        // No roles yet -> the list is genuinely empty.
        let list_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin/security/users/{target_id}/roles"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(list_req)
            .await
            .expect("list user roles");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_json(res).await["items"].as_array().unwrap().len(), 0);

        // No privilege at all -> forbidden, not merely filtered (there is no
        // record-level tier to even resolve without holding the "read"
        // privilege in the first place).
        assert_eq!(
            get_record_as(&app, &target_cookie, &logicalname, &record_id).await,
            StatusCode::FORBIDDEN,
            "a caller holding no role and no privilege at all must be forbidden"
        );

        let role_id = create_role_via_api(&app, &admin_cookie).await;
        grant_role_privilege_via_api(&app, &admin_cookie, role_id, &format!("{logicalname}.read"))
            .await;

        let assign_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/security/users/{target_id}/roles"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"role_id":"{role_id}"}}"#)))
            .unwrap();
        let res = app.clone().oneshot(assign_req).await.expect("assign role");
        assert_eq!(res.status(), StatusCode::CREATED);
        let assigned = body_json(res).await;
        assert_eq!(assigned["user_id"], target_id.to_string());
        assert_eq!(assigned["role_id"], role_id.to_string());

        assert_eq!(
            get_record_as(&app, &target_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "after being assigned a role granting the read privilege (Global by \
         default — no entity-access row narrows it), the target gains \
         access on its very next request, not after a cache TTL"
        );

        let list_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin/security/users/{target_id}/roles"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(list_req)
            .await
            .expect("list user roles");
        let roles = body_json(res).await;
        assert!(
            roles["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["role_id"] == role_id.to_string()),
            "the newly assigned role must appear in the list: {roles:?}"
        );

        let remove_req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/admin/security/users/{target_id}/roles/{role_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(remove_req).await.expect("remove role");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            get_record_as(&app, &target_cookie, &logicalname, &record_id).await,
            StatusCode::FORBIDDEN,
            "after revoking the only role held, the target loses the read \
         privilege entirely (it held no other grant), reverting to \
         forbidden rather than merely filtered"
        );
    })
}

/// F138 position hierarchy, end to end via the admin API: two positions in a
/// parent/child relationship, a subordinate who owns a record, and a manager
/// placed in the parent position whose role has `position_hierarchy_enabled`
/// turned on. Proves: (1) position CRUD + reparent-cycle rejection work,
/// (2) the manager gains access to the subordinate's record purely through
/// the position link (not through any share or BU/Team tier — the manager's
/// role is `None`-tier otherwise), and (3) an otherwise-identical caller
/// holding the same role but NOT placed in the position hierarchy sees
/// nothing extra, proving the position link itself is what's load-bearing,
/// not merely the flag.
#[test]
fn position_hierarchy_admin_endpoints_end_to_end() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_aposn_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        // Create parent ("region-manager") and child ("rep") positions via the API.
        let create_parent_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/positions")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"rls-region-manager-{}"}}"#,
                Uuid::now_v7()
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_parent_req)
            .await
            .expect("create parent position");
        assert_eq!(res.status(), StatusCode::CREATED);
        let parent = body_json(res).await;
        let parent_id = parent["id"].as_str().unwrap().to_owned();
        assert!(parent["parent_position_id"].is_null());

        let create_child_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/positions")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"rls-rep-{}","parent_position_id":"{parent_id}"}}"#,
                Uuid::now_v7()
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_child_req)
            .await
            .expect("create child position");
        assert_eq!(res.status(), StatusCode::CREATED);
        let child = body_json(res).await;
        let child_id = child["id"].as_str().unwrap().to_owned();
        assert_eq!(child["parent_position_id"], parent_id);

        // List includes both.
        let list_req = Request::builder()
            .method("GET")
            .uri("/api/v1/admin/security/positions")
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(list_req).await.expect("list positions");
        assert_eq!(res.status(), StatusCode::OK);
        let positions = body_json(res).await;
        let ids: Vec<_> = positions["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].clone())
            .collect();
        assert!(ids.contains(&serde_json::Value::String(parent_id.clone())));
        assert!(ids.contains(&serde_json::Value::String(child_id.clone())));

        // Reparenting the parent under its own child would create a cycle — rejected.
        let cycle_req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/api/v1/admin/security/positions/{parent_id}/parent"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"parent_position_id":"{child_id}"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(cycle_req).await.expect("cycle attempt");
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "reparenting a position under its own descendant must be rejected as a cycle"
        );

        // Subordinate creates and owns a record.
        let (subordinate_id, subordinate_cookie, _subordinate_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let subordinate_email = format!("rls-subordinate-{subordinate_id}@test.local");
        sqlx::query("UPDATE user_account SET email = $1 WHERE id = $2")
            .bind(&subordinate_email)
            .bind(subordinate_id)
            .execute(&db)
            .await
            .expect("set subordinate email");
        let (record_id, _) = create_record_as(
            &app,
            &subordinate_cookie,
            &logicalname,
            "owned-by-subordinate",
        )
        .await;

        let add_child_member_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/security/positions/{child_id}/members"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"user_email":"{subordinate_email}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(add_child_member_req)
            .await
            .expect("add child member");
        assert_eq!(res.status(), StatusCode::CREATED);

        // Manager: same read privilege, None-tier (own privilege-granting role
        // narrowed via `scope_role_for_entity`), position_hierarchy_enabled
        // turned on (via the real, unchanged PUT endpoint, applied to the
        // manager's own role — post-D-136 there is no separate role-wide
        // access_level to attach a decoration role to; the manager already
        // holds this role directly from `seed_user_with_privileges`), placed in
        // the PARENT position (an ancestor of the subordinate's position).
        let (manager_id, manager_cookie, manager_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        let manager_email = format!("rls-manager-{manager_id}@test.local");
        sqlx::query("UPDATE user_account SET email = $1 WHERE id = $2")
            .bind(&manager_email)
            .bind(manager_id)
            .execute(&db)
            .await
            .expect("set manager email");

        scope_role_for_entity(
            &db,
            &security,
            manager_role_id,
            manager_id,
            entity_id,
            0, // None
        )
        .await;

        let enable_hierarchy_req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/api/v1/admin/security/roles/{manager_role_id}/position-hierarchy"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"position_hierarchy_enabled":true}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(enable_hierarchy_req)
            .await
            .expect("enable position hierarchy");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        security.invalidate(manager_id).await;

        // Manager not yet placed in any position — None-tier, no share, no
        // position link yet: must NOT see the subordinate's record.
        assert_eq!(
            get_record_as(&app, &manager_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "a None-tier caller with position_hierarchy_enabled but no position \
         assignment yet must not see another user's record"
        );

        let add_parent_member_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/security/positions/{parent_id}/members"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"user_email":"{manager_email}"}}"#)))
            .unwrap();
        let res = app
            .clone()
            .oneshot(add_parent_member_req)
            .await
            .expect("add parent member");
        assert_eq!(res.status(), StatusCode::CREATED);

        assert_eq!(
            get_record_as(&app, &manager_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "once placed in the position ancestor of the subordinate's position, \
         the manager must see the subordinate's record on their very next \
         request, with no explicit share ever granted"
        );

        // Control: an otherwise-identical caller with the SAME settings on its
        // OWN role (None-tier + position_hierarchy_enabled=true) but never
        // placed in any position must see nothing extra — proves the position
        // link, not the flag/tier alone, is what's load-bearing. (Post-D-136,
        // each `seed_user_with_privileges` call creates its own role rather than
        // sharing one, so "same settings" is reproduced on the control's own
        // role instead of assigning it the manager's.)
        let (control_id, control_cookie, control_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        scope_role_for_entity(
            &db,
            &security,
            control_role_id,
            control_id,
            entity_id,
            0, // None
        )
        .await;
        let enable_control_hierarchy_req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/api/v1/admin/security/roles/{control_role_id}/position-hierarchy"
            ))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"position_hierarchy_enabled":true}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(enable_control_hierarchy_req)
            .await
            .expect("enable position hierarchy for control");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        security.invalidate(control_id).await;

        assert_eq!(
            get_record_as(&app, &control_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "holding a position_hierarchy_enabled role without any position \
         assignment must never grant access on its own"
        );

        // Remove the subordinate from the child position — the manager's own
        // cached subordinate_user_ids is not fanned out to by this removal
        // (update_position_parent/remove_position_member's doc comments: only
        // the changed user's own cache is invalidated directly, same accepted
        // bounded-staleness posture organization's hierarchy already has in
        // this codebase). Force it here the same way the raw-SQL seeding
        // helpers above this test file do, to assert the eventual (not
        // immediate-by-this-call) effect deterministically instead of sleeping
        // out a 60s cache TTL.
        let remove_child_member_req = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/admin/security/positions/{child_id}/members/{subordinate_id}"
            ))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(remove_child_member_req)
            .await
            .expect("remove child member");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        security.invalidate(manager_id).await;

        assert_eq!(
            get_record_as(&app, &manager_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "once the subordinate leaves the child position (and the manager's \
         cache is refreshed), the manager loses position-hierarchy access to \
         their former record"
        );

        // Position CRUD: delete succeeds.
        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/security/positions/{child_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(delete_req)
            .await
            .expect("delete position");
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    })
}

/// Non-admin callers are rejected on every new D-133 Phase 4 endpoint —
/// the same coarse `system.admin` gate every other admin surface in this
/// codebase uses (D-011), verified explicitly rather than assumed from
/// `ctx.require_admin()`'s presence in the source.
#[test]
fn phase4_endpoints_reject_non_admin_callers() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_anonad_{}", Uuid::now_v7().simple());
        provision_text_field(
            &app,
            &admin_cookie,
            provision_entity(&app, &admin_cookie, &logicalname).await,
        )
        .await;

        let (_non_admin_id, non_admin_cookie, _non_admin_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;

        let team_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/teams")
            .header("cookie", &non_admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"should-not-be-created"}"#))
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(team_req)
                .await
                .expect("team req")
                .status(),
            StatusCode::FORBIDDEN
        );

        let share_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/record-shares")
        .header("cookie", &non_admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"{logicalname}","record_id":"{}","capability":"view","user_email":"nobody@test.local"}}"#,
            Uuid::now_v7()
        )))
        .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(share_req)
                .await
                .expect("share req")
                .status(),
            StatusCode::FORBIDDEN
        );

        let assign_role_req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/security/users/{}/roles",
                Uuid::now_v7()
            ))
            .header("cookie", &non_admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"role_id":"{}"}}"#, Uuid::now_v7())))
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(assign_role_req)
                .await
                .expect("assign role req")
                .status(),
            StatusCode::FORBIDDEN
        );

        // D-136: `POST /role-entity-access` (the replacement for the removed
        // `PUT /roles/{id}/access-level`) carries the exact same coarse
        // `system.admin` gate as every other endpoint checked above.
        let entity_access_req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/security/role-entity-access")
            .header("cookie", &non_admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"role_id":"{}","entity":"{logicalname}"}}"#,
                Uuid::now_v7()
            )))
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(entity_access_req)
                .await
                .expect("entity access req")
                .status(),
            StatusCode::FORBIDDEN
        );
    })
}

// ── D-133 follow-up: record-level gate on restore/upsert/merge/hierarchy/
// bulk/files (Phase 1 of the enterprise-audit remediation plan) ────────────
// `entity_crud.rs`'s get/create/update/delete already carry
// `require_record_access` (proven by the tests above). These handlers are
// separate code paths in the same file (plus `bulk.rs`/`files.rs`) that the
// original D-133 rollout didn't reach — each test below proves a caller
// outside the record's granted scope gets NOT_FOUND, and a caller inside
// scope still succeeds, matching `get_record`'s existing soft-delete-style
// not-found convention.

/// Shared setup for the tests below: a fresh entity/field, a creator who
/// makes one record then gets narrowed to None-tier (so `rls_predicate`
/// actually filters instead of short-circuiting via the Global default —
/// same reasoning every other test in this file uses), and a stranger with
/// the requested privileges but no share on the creator's record.
async fn setup_none_tier_pair(
    logicalname: &str,
    stranger_actions: &[&str],
) -> Option<(
    axum::Router,
    PgPool,
    attome_server::security::SecurityResolverHandle,
    String, // admin_cookie
    Uuid,   // entity_id
    Uuid,   // creator_id
    String, // record_id
    i64,    // row_version
    Uuid,   // stranger_id
    String, // stranger_cookie
)> {
    let system = test_system().await?;
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let app = full_app(system);
    let (_admin_id, admin_cookie) = seed_admin(&db).await;

    let entity_id = provision_entity(&app, &admin_cookie, logicalname).await;
    provision_text_field(&app, &admin_cookie, entity_id).await;

    let (creator_id, creator_cookie, creator_role_id) =
        seed_user_with_privileges(&db, logicalname, &["read", "create", "update", "delete"]).await;
    scope_role_for_entity(
        &db,
        &security,
        creator_role_id,
        creator_id,
        entity_id,
        0, /* None */
    )
    .await;
    let (record_id, row_version) =
        create_record_as(&app, &creator_cookie, logicalname, "mine").await;

    let mut stranger_actions_all = stranger_actions.to_vec();
    if !stranger_actions_all.contains(&"read") {
        stranger_actions_all.push("read");
    }
    let (stranger_id, stranger_cookie, stranger_role_id) =
        seed_user_with_privileges(&db, logicalname, &stranger_actions_all).await;
    scope_role_for_entity(
        &db,
        &security,
        stranger_role_id,
        stranger_id,
        entity_id,
        0, /* None */
    )
    .await;

    Some((
        app,
        db,
        security,
        admin_cookie,
        entity_id,
        creator_id,
        record_id,
        row_version,
        stranger_id,
        stranger_cookie,
    ))
}

#[test]
fn restore_rejects_a_caller_outside_record_scope() {
    attome_testkit::run_shared(async {
        let logicalname = format!("rls_restore_{}", Uuid::now_v7().simple());
        let (
            app,
            db,
            _security,
            _admin,
            _entity_id,
            creator_id,
            record_id,
            row_version,
            _stranger_id,
            stranger_cookie,
        ) = skip_if_no_db!(setup_none_tier_pair(&logicalname, &["update"]).await);

        // Soft-delete the record as its creator first, so there's something to
        // restore.
        assert_eq!(
            delete_record_as(
                &app,
                &session_cookie(creator_id),
                &logicalname,
                &record_id,
                row_version
            )
            .await,
            StatusCode::NO_CONTENT
        );

        assert_eq!(
            restore_record_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "a None-tier stranger with entity-level update privilege must not be \
         able to restore a record outside their record-level scope"
        );

        // The creator, via their implicit creator-share, can restore their own
        // record even at None-tier.
        assert_eq!(
            restore_record_as(&app, &session_cookie(creator_id), &logicalname, &record_id).await,
            StatusCode::OK,
            "the creator must still be able to restore their own record"
        );
        let _ = db;
    })
}

#[test]
fn upsert_update_branch_rejects_a_caller_outside_record_scope() {
    attome_testkit::run_shared(async {
        let logicalname = format!("rls_upsert_{}", Uuid::now_v7().simple());
        let (
            app,
            _db,
            _security,
            admin_cookie,
            _entity_id,
            creator_id,
            _record_id,
            row_version,
            _stranger_id,
            stranger_cookie,
        ) = skip_if_no_db!(setup_none_tier_pair(&logicalname, &["create", "update"]).await);

        // Provision the unique upsert key through an administrator first. A
        // non-admin is deliberately forbidden from creating production DDL, and
        // this test is specifically about record-level access on the existing
        // update branch rather than that independent schema-provisioning guard.
        assert_eq!(
            upsert_record_as(
                &app,
                &admin_cookie,
                &logicalname,
                "title",
                "upsert-index-seed",
                None
            )
            .await,
            StatusCode::CREATED,
            "an administrator must be able to provision the upsert key"
        );

        assert_eq!(
            upsert_record_as(
                &app,
                &stranger_cookie,
                &logicalname,
                "title",
                "mine",
                Some(row_version)
            )
            .await,
            StatusCode::NOT_FOUND,
            "upsert's update branch must not let a None-tier stranger update a \
         record outside their record-level scope, even though the match \
         predicate resolves to an existing row"
        );

        assert_eq!(
            upsert_record_as(
                &app,
                &session_cookie(creator_id),
                &logicalname,
                "title",
                "mine",
                Some(row_version)
            )
            .await,
            StatusCode::OK,
            "the creator must still be able to upsert-update their own record"
        );
    })
}

#[test]
fn merge_rejects_when_either_record_is_outside_caller_scope() {
    attome_testkit::run_shared(async {
        let logicalname = format!("rls_merge_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create", "update", "delete"])
                .await;
        scope_role_for_entity(
            &db,
            &security,
            creator_role_id,
            creator_id,
            entity_id,
            0, /* None */
        )
        .await;
        let (canonical_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "canonical").await;
        let (duplicate_id, _) =
            create_record_as(&app, &creator_cookie, &logicalname, "duplicate").await;

        let (stranger_id, stranger_cookie, stranger_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "update", "delete"]).await;
        scope_role_for_entity(
            &db,
            &security,
            stranger_role_id,
            stranger_id,
            entity_id,
            0, /* None */
        )
        .await;

        assert_eq!(
            merge_records_as(
                &app,
                &stranger_cookie,
                &logicalname,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::NOT_FOUND,
            "a None-tier stranger with no share on either record must not be \
         able to merge them"
        );

        // Share only the canonical record with the stranger — merge must still
        // fail because the duplicate is out of scope.
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)", // capability=action
    )
    .bind(Uuid::parse_str(&canonical_id).unwrap())
    .bind(entity_id)
    .bind(stranger_id)
    .execute(&db)
    .await
    .expect("share canonical record");

        assert_eq!(
            merge_records_as(
                &app,
                &stranger_cookie,
                &logicalname,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::NOT_FOUND,
            "a share on only the canonical record must not be enough — the \
         duplicate is still out of scope"
        );

        assert_eq!(
            merge_records_as(
                &app,
                &creator_cookie,
                &logicalname,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::OK,
            "the creator, with an implicit action-share on both records, must \
         be able to merge them"
        );
    })
}

/// merge-dependent-authz regression (checklist item 8): merging redirects
/// every OTHER entity's lookup field that pointed at the duplicate — the
/// coarse `ctx.require(dep_entity, "update")` gate proves the caller can
/// update SOME row of the dependent entity, not the specific dependent row
/// about to be rewritten. A caller who clears the coarse gate but lacks
/// record-level (RLS) access to a particular dependent record must fail the
/// whole merge, not have that one dependent silently left pointing at the
/// (about-to-be-retired) duplicate while everything else goes through.
#[test]
fn merge_rejects_when_a_dependent_record_is_outside_caller_scope() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_mdep_t_{}", Uuid::now_v7().simple());
        let referrer_name = format!("rls_mdep_r_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let state = system.state().clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;

        let referrer_entity_id = provision_entity(&app, &admin_cookie, &referrer_name).await;
        let field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{referrer_entity_id}/fields"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(field_req)
            .await
            .expect("create referrer lookup field");
        assert_eq!(res.status(), StatusCode::CREATED);
        sync_registry(&state).await;

        // The merging user: full CRUD on the target entity (None-tier — relies
        // on the implicit creator share for the canonical/duplicate records they
        // create themselves below), plus a SECOND role granting only coarse
        // "update" on the referrer entity, also scoped None-tier — enough to
        // clear `ctx.require(referrer, "update")` but not enough to see a
        // referrer record someone else created (same "second role, second
        // entity" pattern `cross_entity_scope_never_leaks_between_roles` uses).
        let (merger_id, merger_cookie, merger_role_id) =
            seed_user_with_privileges(&db, &target_name, &["read", "create", "update", "delete"])
                .await;
        scope_role_for_entity(
            &db,
            &security,
            merger_role_id,
            merger_id,
            target_entity_id,
            0, // None
        )
        .await;

        let referrer_role_id = create_role_with_privileges(&db, &referrer_name, &["update"]).await;
        assign_role_to_user(&db, merger_id, referrer_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            referrer_role_id,
            merger_id,
            referrer_entity_id,
            0, // None
        )
        .await;

        let (canonical_id, _) =
            create_record_as(&app, &merger_cookie, &target_name, "canonical").await;
        let (duplicate_id, _) =
            create_record_as(&app, &merger_cookie, &target_name, "duplicate").await;

        // A referrer record pointing at the duplicate. Seed it directly because
        // this test is about merge authorization, not generic lookup creation;
        // direct fixture seeding also keeps the owner free of unrelated access
        // to the target entity.
        let (_owner_id, owner_cookie, _owner_role_id) =
            seed_user_with_privileges(&db, &referrer_name, &["read", "create"]).await;
        let referrer_id: Uuid = sqlx::query_scalar(&format!(
            "INSERT INTO \"{referrer_name}\" (target_ref) VALUES ($1) RETURNING id"
        ))
        .bind(Uuid::parse_str(&duplicate_id).expect("duplicate id"))
        .fetch_one(&db)
        .await
        .expect("insert referrer fixture");
        let referrer_id = referrer_id.to_string();

        assert_eq!(
            merge_records_as(
                &app,
                &merger_cookie,
                &target_name,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::FORBIDDEN,
            "a dependent record the caller cannot update at the record level \
         must fail the whole merge, not be silently left un-redirected"
        );

        // The merge must not have partially applied: the referrer still points
        // at the duplicate, and the duplicate is still active.
        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_name}/{referrer_id}"))
            .header("cookie", &owner_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer");
        assert_eq!(res.status(), StatusCode::OK);
        let referrer = body_json(res).await;
        assert_eq!(
            referrer["data"]["target_ref"], duplicate_id,
            "a rejected merge must not have redirected any dependent, \
         including ones the caller could otherwise see: {referrer:?}"
        );
        assert_eq!(
            get_record_as(&app, &merger_cookie, &target_name, &duplicate_id).await,
            StatusCode::OK,
            "a rejected merge must not have retired the duplicate either"
        );

        // Sharing the referrer record with the merging user closes the gap — now
        // every dependent is within scope and the merge succeeds.
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)", // capability=action
    )
    .bind(Uuid::parse_str(&referrer_id).unwrap())
    .bind(referrer_entity_id)
    .bind(merger_id)
    .execute(&db)
    .await
    .expect("share referrer record");

        assert_eq!(
            merge_records_as(
                &app,
                &merger_cookie,
                &target_name,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::OK,
            "once every dependent record is within the caller's scope, the \
         merge must succeed"
        );

        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_name}/{referrer_id}"))
            .header("cookie", &owner_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer after successful merge");
        assert_eq!(res.status(), StatusCode::OK);
        let referrer = body_json(res).await;
        assert_eq!(
            referrer["data"]["target_ref"], canonical_id,
            "after the successful merge, the referrer must be redirected to \
         the canonical id: {referrer:?}"
        );
    })
}

/// P-field-write-security (D-141): merge's dependent-redirect writes
/// `dep_field` on every dependent row it repoints — if that field is
/// `is_sensitive`, entity-level "update" and full record-level (RLS) access
/// on the dependent row are both necessary but not sufficient, same as an
/// ordinary create/update payload. Deliberately gives the merging user
/// GLOBAL-tier record-level access on both entities (no
/// `scope_role_for_entity` call, unlike the sibling
/// `merge_rejects_when_a_dependent_record_is_outside_caller_scope` test) so
/// this test isolates the field-write-grant gate specifically — record-level
/// scope is never the reason the merge fails here.
#[test]
fn merge_rejects_when_a_dependent_sensitive_field_lacks_write_grant() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_mfws_t_{}", Uuid::now_v7().simple());
        let referrer_name = format!("rls_mfws_r_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let state = system.state().clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;

        let referrer_entity_id = provision_entity(&app, &admin_cookie, &referrer_name).await;
        // The redirected lookup field itself is `is_sensitive` — this is the
        // write P-field-write-security gates.
        let field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{referrer_entity_id}/fields"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"target_ref","name":"Target Ref","field_type":"lookup","lookup_entity_ref":"{target_entity_id}","is_sensitive":true}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(field_req)
            .await
            .expect("create referrer lookup field");
        assert_eq!(res.status(), StatusCode::CREATED);
        sync_registry(&state).await;

        // Merging user: full CRUD on target, "update" on referrer — both roles
        // left at their default (no role_mm_entity_access row = Global,
        // D-133's zero-behavior-change default) so record-level scope never
        // blocks this merge; only the new field-write-grant check can.
        let (merger_id, merger_cookie, _merger_role_id) =
            seed_user_with_privileges(&db, &target_name, &["read", "create", "update", "delete"])
                .await;
        let referrer_role_id = create_role_with_privileges(&db, &referrer_name, &["update"]).await;
        assign_role_to_user(&db, merger_id, referrer_role_id).await;

        let (canonical_id, _) =
            create_record_as(&app, &merger_cookie, &target_name, "canonical").await;
        let (duplicate_id, _) =
            create_record_as(&app, &merger_cookie, &target_name, "duplicate").await;

        // Seed the sensitive-field fixture directly: an ordinary create must
        // fail closed without a field-security grant, while this test isolates
        // that same check on merge's dependent redirect. The merger's role is
        // Global-tier, so ownership is not part of the later assertion.
        let referrer_id: Uuid = sqlx::query_scalar(&format!(
            "INSERT INTO \"{referrer_name}\" (target_ref) VALUES ($1) RETURNING id"
        ))
        .bind(Uuid::parse_str(&duplicate_id).expect("duplicate id"))
        .fetch_one(&db)
        .await
        .expect("insert sensitive referrer fixture");
        let referrer_id = referrer_id.to_string();

        // No field-security profile exists yet for referrer.target_ref — the
        // merge must fail closed before redirecting anything.
        assert_eq!(
            merge_records_as(
                &app,
                &merger_cookie,
                &target_name,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::FORBIDDEN,
            "redirecting an is_sensitive lookup field with no can_update grant \
         must fail the whole merge, not silently redirect it anyway"
        );

        // Verified via the admin cookie, deliberately: the merger holds no
        // `can_read` grant on `target_ref` either at this point (no profile
        // exists yet at all), so a merger-authenticated GET would have this
        // sensitive field stripped from the response regardless of what value
        // it holds — that's `has_field_read_grant`'s unrelated, already-covered
        // behavior, not what this test is isolating. An admin caller bypasses
        // field-security entirely, so its response reflects the true DB state.
        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_name}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .clone()
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer");
        assert_eq!(res.status(), StatusCode::OK);
        let referrer = body_json(res).await;
        assert_eq!(
            referrer["data"]["target_ref"], duplicate_id,
            "a rejected merge must not have redirected the sensitive field: {referrer:?}"
        );
        assert_eq!(
            get_record_as(&app, &admin_cookie, &target_name, &duplicate_id).await,
            StatusCode::OK,
            "a rejected merge must not have retired the duplicate either"
        );

        // Grant can_update on referrer.target_ref to the merger's referrer role
        // — the merge must now succeed.
        let profile_id: Uuid = sqlx::query_scalar(
            "INSERT INTO field_security_profile (id, name, owner_layer) VALUES ($1, $2, 'project') RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(format!("fws-merge-profile-{referrer_role_id}"))
        .fetch_one(&db)
        .await
        .expect("insert field-security profile");
        sqlx::query(
            "INSERT INTO field_security_profile_field \
         (id, profile_ref, entity_logicalname, field_logicalname, can_read, can_update, owner_layer) \
         VALUES ($1, $2, $3, $4, true, true, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(profile_id)
        .bind(&referrer_name)
        .bind("target_ref")
        .execute(&db)
        .await
        .expect("insert field-security profile field");
        sqlx::query(
        "INSERT INTO role_mm_field_security_profile (id, role_ref, profile_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(referrer_role_id)
    .bind(profile_id)
    .execute(&db)
    .await
    .expect("assign field-security profile to role");
        // Direct-SQL grant outside the admin API — invalidate explicitly rather
        // than relying on `set_field_profile_field`'s own `invalidate_sync_all`,
        // same convention this suite already follows for SQL-seeded grants.
        security.invalidate(merger_id).await;

        assert_eq!(
            merge_records_as(
                &app,
                &merger_cookie,
                &target_name,
                &canonical_id,
                &duplicate_id
            )
            .await,
            StatusCode::OK,
            "once the merger holds can_update on the sensitive lookup field, \
         the merge must succeed"
        );

        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_name}/{referrer_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer after successful merge");
        assert_eq!(res.status(), StatusCode::OK);
        let referrer = body_json(res).await;
        assert_eq!(
            referrer["data"]["target_ref"], canonical_id,
            "after the successful merge, the referrer must be redirected to \
         the canonical id: {referrer:?}"
        );
    })
}

/// M01-core C-05: a lookup field's display-name resolution
/// (`entity_crud::response::resolve_lookup_meta`, via the shared
/// `entity_crud::resolve_visible` helper) must honour the *target*
/// entity's own RLS, not just the reader's access to the row actually being
/// read. Before this fix, `data.target_ref`'s stored UUID was resolved
/// against `primary_name_attribute` with no predicate at all — a caller
/// with zero read access to the target entity, and no share on a specific
/// target record, could still read that record's display name straight off
/// any referrer row with a lookup pointing at it.
///
/// Also covers the batching claim: `target_ref` and `target_ref2` both
/// point at the SAME target entity, and both ids are populated on the SAME
/// referrer row, so `resolve_lookup_meta`'s `by_target` grouping must
/// resolve both through one call to `resolve_visible` (one `WHERE id =
/// ANY($1)` query covering both ids) — proven here by the visible id and
/// the RLS-hidden id resolving correctly in the SAME response.
#[test]
fn lookup_display_name_honours_target_entity_rls() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_lkpname_t_{}", Uuid::now_v7().simple());
        let referrer_name = format!("rls_lkpname_r_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let state = system.state().clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        // Target entity declares `title` as its primary name attribute — the
        // value that must never leak past this caller's RLS on the target
        // entity.
        let create_target_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{target_name}","name":"RLS Lookup Target","primary_name_attribute":"title"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(create_target_req)
            .await
            .expect("create target entity");
        assert_eq!(res.status(), StatusCode::CREATED);
        let target_entity_id = Uuid::parse_str(
            body_json(res).await["id"]
                .as_str()
                .expect("target entity id"),
        )
        .expect("target entity id is a uuid");
        provision_text_field(&app, &admin_cookie, target_entity_id).await;

        let referrer_entity_id = provision_entity(&app, &admin_cookie, &referrer_name).await;
        for field_name in ["target_ref", "target_ref2"] {
            let field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{referrer_entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{field_name}","name":"{field_name}","field_type":"lookup","lookup_entity_ref":"{target_entity_id}"}}"#
            )))
            .unwrap();
            let res = app
                .clone()
                .oneshot(field_req)
                .await
                .expect("create referrer lookup field");
            assert_eq!(res.status(), StatusCode::CREATED);
        }
        sync_registry(&state).await;

        // The owner: full CRUD on the target entity — creates both target
        // records with the implicit creator share (D-133 (2)).
        let (_owner_id, owner_cookie, _owner_role_id) =
            seed_user_with_privileges(&db, &target_name, &["read", "create"]).await;
        let (visible_id, _) =
            create_record_as(&app, &owner_cookie, &target_name, "Acme Corp").await;
        let (hidden_id, _) = create_record_as(&app, &owner_cookie, &target_name, "Secret Co").await;

        // A single referrer row with both lookup fields populated — one
        // pointing at the visible target, one at the hidden one. Seeded
        // directly: this test is about display-name RLS, not generic write
        // validation.
        let referrer_id: Uuid = sqlx::query_scalar(&format!(
            "INSERT INTO \"{referrer_name}\" (target_ref, target_ref2) VALUES ($1, $2) RETURNING id"
        ))
        .bind(Uuid::parse_str(&visible_id).expect("visible id"))
        .bind(Uuid::parse_str(&hidden_id).expect("hidden id"))
        .fetch_one(&db)
        .await
        .expect("insert referrer fixture");
        let referrer_id = referrer_id.to_string();

        // The reader: Global-tier read on the referrer entity (default, no
        // scoping row — sees the referrer row regardless of who created it),
        // but None-tier read on the TARGET entity with an explicit
        // view-capability share on ONLY the visible target record.
        let referrer_role_id = create_role_with_privileges(&db, &referrer_name, &["read"]).await;
        let (reader_id, reader_cookie, reader_target_role_id) =
            seed_user_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, referrer_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            reader_target_role_id,
            reader_id,
            target_entity_id,
            0, // None
        )
        .await;
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)", // principal_type=user, capability=view
    )
    .bind(Uuid::parse_str(&visible_id).unwrap())
    .bind(target_entity_id)
    .bind(reader_id)
    .execute(&db)
    .await
    .expect("insert view share on the visible target");

        // Sanity: the reader genuinely cannot read the hidden target record
        // directly either — the display-name assertion below is testing the
        // SAME boundary, reached through a lookup field instead of a direct GET.
        assert_eq!(
            get_record_as(&app, &reader_cookie, &target_name, &hidden_id).await,
            StatusCode::NOT_FOUND,
            "precondition: the reader must have no direct read access to the hidden target"
        );

        let get_referrer_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/{referrer_name}/{referrer_id}"))
            .header("cookie", &reader_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app
            .oneshot(get_referrer_req)
            .await
            .expect("get referrer as reader");
        assert_eq!(res.status(), StatusCode::OK);
        let referrer = body_json(res).await;

        // The stored UUID is always returned raw, readable target or not.
        assert_eq!(referrer["data"]["target_ref"], visible_id);
        assert_eq!(referrer["data"]["target_ref2"], hidden_id);

        // A readable target resolves its real name.
        assert_eq!(referrer["lookups"]["target_ref"]["exists"], true);
        assert_eq!(referrer["lookups"]["target_ref"]["is_active"], true);
        assert_eq!(referrer["lookups"]["target_ref"]["name"], "Acme Corp");

        // An RLS-hidden target renders exactly like a target that doesn't exist
        // — never leaking "Secret Co".
        assert_eq!(
            referrer["lookups"]["target_ref2"]["exists"], false,
            "an RLS-hidden lookup target must not report exists:true: {referrer:?}"
        );
        assert_eq!(
            referrer["lookups"]["target_ref2"]["is_active"], false,
            "an RLS-hidden lookup target must not report is_active:true: {referrer:?}"
        );
        assert_eq!(
            referrer["lookups"]["target_ref2"]["name"],
            serde_json::Value::Null,
            "an RLS-hidden lookup target's name must never leak: {referrer:?}"
        );
    })
}

#[test]
fn ancestors_and_descendants_reject_a_caller_outside_record_scope() {
    attome_testkit::run_shared(async {
        let logicalname = format!("rls_hier_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;
        // Self-referencing hierarchy lookup field required by `hierarchy_field`.
        let field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"parent_ref","name":"Parent","field_type":"lookup","lookup_entity_ref":"{entity_id}"}}"#
        )))
        .unwrap();
        let res = app
            .clone()
            .oneshot(field_req)
            .await
            .expect("create hierarchy field");
        let field_status = res.status();
        let field_body = body_json(res).await;
        assert_eq!(
            field_status,
            StatusCode::CREATED,
            "hierarchy field creation failed: {field_body:?}"
        );

        let (creator_id, creator_cookie, creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        scope_role_for_entity(
            &db,
            &security,
            creator_role_id,
            creator_id,
            entity_id,
            0, /* None */
        )
        .await;
        let (record_id, _) = create_record_as(&app, &creator_cookie, &logicalname, "root").await;

        let (stranger_id, stranger_cookie, stranger_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read"]).await;
        scope_role_for_entity(
            &db,
            &security,
            stranger_role_id,
            stranger_id,
            entity_id,
            0, /* None */
        )
        .await;

        assert_eq!(
            ancestors_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "a None-tier stranger must not be able to list ancestors of a \
         record outside their record-level scope"
        );
        assert_eq!(
            descendants_as(&app, &stranger_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "a None-tier stranger must not be able to list descendants of a \
         record outside their record-level scope"
        );

        assert_eq!(
            ancestors_as(&app, &creator_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "the creator must still be able to walk their own record's hierarchy"
        );
    })
}

#[test]
fn bulk_update_and_delete_skip_items_outside_caller_scope() {
    attome_testkit::run_shared(async {
        let logicalname = format!("rls_bulk_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let state = system.state().clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let (creator_id, creator_cookie, creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create", "update", "bulk"])
                .await;
        scope_role_for_entity(
            &db,
            &security,
            creator_role_id,
            creator_id,
            entity_id,
            0, /* None */
        )
        .await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "mine").await;

        let (stranger_id, _stranger_cookie, stranger_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "update", "delete", "bulk"])
                .await;
        scope_role_for_entity(
            &db,
            &security,
            stranger_role_id,
            stranger_id,
            entity_id,
            0, /* None */
        )
        .await;

        let records = vec![serde_json::json!({
            "id": record_id,
            "expected_row_version": row_version,
            "data": { "title": "bulk-updated" }
        })];
        let (succeeded, failed) =
            bulk_apply_and_wait(&state, &logicalname, "update", records, stranger_id).await;
        assert_eq!(
            (succeeded, failed),
            (0, 1),
            "a bulk update item outside the caller's record-level scope must \
         fail that item, not silently apply it"
        );

        let title: String = sqlx::query_scalar(&format!(
            "SELECT title FROM \"{logicalname}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&record_id).unwrap())
        .fetch_one(&db)
        .await
        .expect("read record title");
        assert_eq!(
            title, "mine",
            "the out-of-scope bulk update must not have actually changed the record"
        );

        // The creator (in scope via their implicit share) can bulk-update their
        // own record.
        let records = vec![serde_json::json!({
            "id": record_id,
            "expected_row_version": row_version,
            "data": { "title": "bulk-updated" }
        })];
        let (succeeded, failed) =
            bulk_apply_and_wait(&state, &logicalname, "update", records, creator_id).await;
        assert_eq!((succeeded, failed), (1, 0));
    })
}

/// D-140 / checklist item 6 (record-reading-path RLS audit):
/// `audit_header` rows describe a business record
/// (`entity_name`/`record_id`) whose own record-level access the audit
/// entity's own RLS (`record_share`/`entity_default_share` keyed
/// on `audit_header`'s own `entity_ref`) says nothing about. Without
/// `entity_crud.rs`'s `require_referenced_record_access`, a caller holding
/// `audit_header.read` at Global tier could read the change history of
/// ANY business record on ANY entity, including ones they hold no
/// record-level (or even entity-level) access to directly.
#[test]
fn get_record_rejects_audit_header_referencing_a_record_outside_caller_scope() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_audit_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;

        // Admin creates the target record directly (bypasses RLS entirely, same
        // as every other admin-seeded fixture in this file) — this test only
        // cares about the READER's access below, not who owns the record.
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;

        // Seed a throwaway audit row directly. `record_id` is intentionally a
        // polymorphic reference with no `lookup_entity_ref`, so generic CRUD's
        // ordinary lookup validator must reject it; the audit subsystem is the
        // sanctioned writer for this special table in production.
        let audit_id: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_header \
         (entity_name, record_id, category, operation, event_hash) \
         VALUES ($1, $2, 1, 1, 'test-only-placeholder') RETURNING id",
        )
        .bind(&target_name)
        .bind(Uuid::parse_str(&record_id).expect("record id"))
        .fetch_one(&db)
        .await
        .expect("insert audit header fixture");
        let audit_id = audit_id.to_string();

        // Reader: Global (unrestricted) read on audit_header itself, but
        // only None-tier read on the target entity with no share on this
        // specific record — a broader audit grant than target-entity grant, the
        // exact shape this check exists to close.
        let (reader_id, reader_cookie, _reader_role_id) =
            seed_user_with_privileges(&db, "audit_header", &["read"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0, // None
        )
        .await;

        assert_eq!(
            get_record_as(&app, &reader_cookie, "audit_header", &audit_id).await,
            StatusCode::NOT_FOUND,
            "reader holds audit_header.read at Global but no access to the \
         referenced target record — must not see its audit trail"
        );

        // Scoping the reader's target-entity role to Global flips the same
        // audit row back to visible — proving this is the same
        // `require_record_access` check re-evaluated live, not an unconditional
        // block on any non-owner reader.
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            3, // Global
        )
        .await;
        assert_eq!(
            get_record_as(&app, &reader_cookie, "audit_header", &audit_id).await,
            StatusCode::OK,
            "Global-tier access to the target entity must make its audit trail visible again"
        );
    })
}

/// D-147 companion to the rejection test above, for the grant side:
/// `audit_header` rows have no meaningful RLS of their own (nobody
/// shares an individual audit-log entry via `record_share` keyed to
/// its own id), so a caller whose *own* access to `audit_header` is
/// narrowed below Global must still be able to read a specific audit row
/// when they're independently entitled to see the business record it
/// references — via `require_referenced_record_access` alone, not
/// additionally gated by `require_record_access` against the audit row's
/// own (unsatisfiable) scope. Regression for the bug the live-Postgres
/// verification pass on 2026-07-30 found: both checks used to be required,
/// so a Team-tier audit-scope reader with an explicit share on the
/// referenced record still got 404.
#[test]
fn get_record_shows_an_audit_header_row_via_referenced_record_share_despite_narrowed_audit_scope() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_audit_share_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;

        let (record_a, _) = create_record_as(&app, &admin_cookie, &target_name, "a").await;
        let (record_b, _) = create_record_as(&app, &admin_cookie, &target_name, "b").await;
        let record_a_id = Uuid::parse_str(&record_a).expect("record a id");
        let record_b_id = Uuid::parse_str(&record_b).expect("record b id");

        let audit_a: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_header \
         (entity_name, record_id, category, operation, event_hash) \
         VALUES ($1, $2, 1, 1, 'test-only-placeholder-a') RETURNING id",
        )
        .bind(&target_name)
        .bind(record_a_id)
        .fetch_one(&db)
        .await
        .expect("insert audit header fixture a");
        let audit_b: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_header \
         (entity_name, record_id, category, operation, event_hash) \
         VALUES ($1, $2, 1, 1, 'test-only-placeholder-b') RETURNING id",
        )
        .bind(&target_name)
        .bind(record_b_id)
        .fetch_one(&db)
        .await
        .expect("insert audit header fixture b");

        // Reader: Team-tier on `audit_header` itself (narrowed, no share on
        // either audit row) plus None-tier on the target entity, then an
        // explicit view share on record A only — same fixture shape as the
        // list-path test below, single-record path this time.
        let (reader_id, reader_cookie, reader_audit_role_id) =
            seed_user_with_privileges(&db, "audit_header", &["read"]).await;
        let audit_entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'audit_header'")
                .fetch_one(&db)
                .await
                .expect("audit_header must be seeded by attome_audit::seed::seed");
        scope_role_for_entity(
            &db,
            &security,
            reader_audit_role_id,
            reader_id,
            audit_entity_id,
            1, // Team
        )
        .await;

        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0, // None
        )
        .await;

        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)", // view
    )
    .bind(record_a_id)
    .bind(target_entity_id)
    .bind(reader_id)
    .execute(&db)
    .await
    .expect("insert view share on record A only");

        assert_eq!(
            get_record_as(&app, &reader_cookie, "audit_header", &audit_a.to_string()).await,
            StatusCode::OK,
            "explicit share on the referenced record A must grant access to its \
         audit row even though the reader's own audit_header scope is \
         narrowed to Team with no share on the audit row itself"
        );
        assert_eq!(
            get_record_as(&app, &reader_cookie, "audit_header", &audit_b.to_string()).await,
            StatusCode::NOT_FOUND,
            "record B was never shared — its audit row must stay hidden"
        );
    })
}

/// Minimal fixture for the D-364 (Documents feature) tests below — provisions
/// `attome_document` itself with just the two columns the polymorphic-reference
/// predicate reads (`entity_name`, `record_id`), since `POLYMORPHIC_AUDIT_ENTITIES`
/// (`access.rs`) is keyed on the literal entity name. Unlike `audit_header`,
/// `attome_document` isn't seeded by any crate — every test that needs it
/// provisions it itself, same as any other admin-created entity.
async fn provision_xrm_document_minimal(app: &axum::Router, admin_cookie: &str) -> Uuid {
    let entity_id = provision_entity(app, admin_cookie, "attome_document").await;
    for logicalname in ["entity_name", "record_id"] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname}","name":"{logicalname}","field_type":"text"}}"#
            )))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("create field");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "create {logicalname} field"
        );
    }
    entity_id
}

/// D-364's RLS generalization: `attome_document` joined `POLYMORPHIC_AUDIT_ENTITIES`
/// (`access.rs`), so a `attome_document` row's visibility must be gated purely by
/// the caller's access to the record it's attached to — direct analog of
/// `get_record_rejects_audit_header_referencing_a_record_outside_caller_scope`
/// above, same fixture shape, `attome_document` in place of `audit_header`.
/// Unlike that test, `record_id` is bound as `.to_string()` (a plain `text`
/// column, not a native `uuid` one — see `access.rs::polymorphic_audit_target`'s
/// comment on why `attome_document.record_id` can't be `lookup`-typed like
/// audit's is), proving the `record_id::uuid` cast in the shared predicate SQL
/// round-trips correctly for that physical shape too.
#[test]
fn get_record_rejects_xrm_document_referencing_a_record_outside_caller_scope() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_doc_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        provision_xrm_document_minimal(&app, &admin_cookie).await;

        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;

        let doc_id: Uuid = sqlx::query_scalar(
            "INSERT INTO attome_document (entity_name, record_id) VALUES ($1, $2) RETURNING id",
        )
        .bind(&target_name)
        .bind(Uuid::parse_str(&record_id).expect("record id").to_string())
        .fetch_one(&db)
        .await
        .expect("insert attome_document fixture");
        let doc_id = doc_id.to_string();

        // Reader: Global (unrestricted) read on attome_document itself, but only
        // None-tier read on the target entity with no share on this specific
        // record — a broader attome_document grant than target-entity grant, the
        // exact shape this check exists to close.
        let (reader_id, reader_cookie, _reader_role_id) =
            seed_user_with_privileges(&db, "attome_document", &["read"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0, // None
        )
        .await;

        assert_eq!(
            get_record_as(&app, &reader_cookie, "attome_document", &doc_id).await,
            StatusCode::NOT_FOUND,
            "reader holds attome_document.read at Global but no access to the \
         referenced target record — must not see its attached documents"
        );

        // Scoping the reader's target-entity role to Global flips the same
        // document row back to visible — proving this is the same
        // `require_record_access` check re-evaluated live, not an unconditional
        // block on any non-owner reader.
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            3, // Global
        )
        .await;
        assert_eq!(
            get_record_as(&app, &reader_cookie, "attome_document", &doc_id).await,
            StatusCode::OK,
            "Global-tier access to the target entity must make its documents visible again"
        );
    })
}

/// D-140 / checklist item 6, list-path: `query_exec.rs` used to fail the
/// whole list closed the moment the caller's OWN access to the audit entity
/// was anything less than Global (an N+1-avoidance stopgap). This session's
/// follow-up (D-147) replaced that with a genuine per-row predicate
/// (`attome_security::polymorphic_audit_predicate`, bulk-resolved via
/// `attome_security::resolve_all_entity_access_levels`) — a narrowed-but-
/// non-Global caller now gets a *filtered* 200, not a blanket 403. A
/// Global-tier caller (the D-133 default) remains unaffected either way.
///
/// Live-verified against a real Postgres/Redis (D-147's own TODO, closed):
/// `polymorphic_audit_predicate`/`resolve_all_entity_access_levels` correctly
/// scope the narrowed-tier list to the explicitly-shared row and exclude the
/// unshared one. The Global-tier assertion below follows the response cursor
/// rather than assuming both fixture rows land on page 1 — a Global-tier list
/// is intentionally unfiltered, so in a long-lived shared local test database
/// with many pre-existing `audit_header` rows (`id` is UUIDv7, so older
/// rows always sort first), a single default-page-size request can miss this
/// test's own brand-new rows even though the access-control logic is correct.
#[test]
fn query_execute_filters_audit_header_rows_by_the_referenced_record_when_callers_own_audit_scope_is_narrowed()
 {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let audit_entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'audit_header'")
                .fetch_one(&db)
                .await
                .expect("audit_header must be seeded by attome_audit::seed::seed");

        let target_name = format!("rls_audit_list_{}", Uuid::now_v7().simple());
        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;

        let (record_a, _) = create_record_as(&app, &admin_cookie, &target_name, "a").await;
        let (record_b, _) = create_record_as(&app, &admin_cookie, &target_name, "b").await;
        let record_a_id = Uuid::parse_str(&record_a).expect("record a id");
        let record_b_id = Uuid::parse_str(&record_b).expect("record b id");

        let audit_a: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_header \
         (entity_name, record_id, category, operation, event_hash) \
         VALUES ($1, $2, 1, 1, 'test-only-placeholder-a') RETURNING id",
        )
        .bind(&target_name)
        .bind(record_a_id)
        .fetch_one(&db)
        .await
        .expect("insert audit header fixture a");
        let audit_b: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_header \
         (entity_name, record_id, category, operation, event_hash) \
         VALUES ($1, $2, 1, 1, 'test-only-placeholder-b') RETURNING id",
        )
        .bind(&target_name)
        .bind(record_b_id)
        .fetch_one(&db)
        .await
        .expect("insert audit header fixture b");

        // Reader: Team-tier on `audit_header` itself (narrowed below
        // Global, so the old containment used to fire) plus None-tier read on
        // the target entity (holds the privilege at all, but no hierarchy
        // access) — then an explicit view-capability share on record A only.
        let (reader_id, reader_cookie, reader_audit_role_id) =
            seed_user_with_privileges(&db, "audit_header", &["read"]).await;
        scope_role_for_entity(
            &db,
            &security,
            reader_audit_role_id,
            reader_id,
            audit_entity_id,
            1, // Team
        )
        .await;

        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0, // None
        )
        .await;

        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)", // view
    )
    .bind(record_a_id)
    .bind(target_entity_id)
    .bind(reader_id)
    .execute(&db)
    .await
    .expect("insert view share on record A only");

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/query/execute")
            .header("cookie", &reader_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"entity":"audit_header"}"#))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("query execute");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "a narrowed-but-non-Global audit-scope caller must get a filtered \
         list back, not a blanket 403 — the whole point of D-147's per-row \
         predicate replacing the old containment"
        );
        let body = body_json(res).await;
        let body_text = body.to_string();
        assert!(
            body_text.contains(&audit_a.to_string()),
            "the audit row referencing record A (explicitly shared with the \
         reader) must be visible: {body_text}"
        );
        assert!(
            !body_text.contains(&audit_b.to_string()),
            "the audit row referencing record B (never shared with the reader) \
         must be excluded, not merely hidden behind a blanket 403: {body_text}"
        );

        // Global (the D-133 default for any caller who never narrows a grant)
        // must remain unaffected — sees both rows regardless of either share.
        scope_role_for_entity(
            &db,
            &security,
            reader_audit_role_id,
            reader_id,
            audit_entity_id,
            3, // Global
        )
        .await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            3, // Global
        )
        .await;
        // A Global-tier list is intentionally unfiltered (no per-row predicate
        // at all), so it can return any pre-existing row in this shared local
        // test database ahead of these two brand-new ones — `id` is UUIDv7,
        // time-ordered, so older rows always sort first under the endpoint's
        // default ascending-by-id cursor order. Follow the cursor across pages
        // instead of assuming both fixture rows land on the first one.
        let (mut found_a, mut found_b) = (false, false);
        let mut after_id: Option<Uuid> = None;
        for _ in 0..500 {
            let body = match after_id {
                Some(id) => format!(r#"{{"entity":"audit_header","after_id":"{id}"}}"#),
                None => r#"{"entity":"audit_header"}"#.to_owned(),
            };
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/query/execute")
                .header("cookie", &reader_cookie)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.expect("query execute");
            assert_eq!(res.status(), StatusCode::OK);
            let page = body_json(res).await;
            let page_text = page.to_string();
            found_a |= page_text.contains(&audit_a.to_string());
            found_b |= page_text.contains(&audit_b.to_string());
            if found_a && found_b {
                break;
            }
            match page["data"]["next_cursor"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                Some(id) => after_id = Some(id),
                None => break,
            }
        }
        assert!(
            found_a,
            "Global-tier access to both the audit entity and the target entity \
         must show every row, share or no share (audit_a not found across \
         all pages)"
        );
        assert!(
            found_b,
            "Global-tier access to both the audit entity and the target entity \
         must show every row, share or no share (audit_b not found across \
         all pages)"
        );
    })
}

/// Regression for a gap introduced by 9ec8c7a's list-path fix (itself fixing
/// D-147's original bug): that commit made `query_exec.rs` apply
/// `polymorphic_audit_predicate` alone for the three polymorphic-audit
/// entities, dropping `rls_predicate` (the audit entity's own scope) from
/// the list path entirely. `polymorphic_audit_predicate` unconditionally
/// admitted a target-less row (no resolvable business record — e.g. a
/// login/logout audit entry) at the time, so a narrowed-tier caller who
/// merely held the `audit_header.read` privilege could list every
/// target-less row with no scoping at all — a real widening of audit-log
/// visibility, live and untested until this test. Fixed by having
/// `polymorphic_audit_predicate` evaluate `false` for target-less rows on
/// its own (see its doc comment) and OR-ing in `rls_predicate` as the
/// fallback scope for exactly those rows, mirroring
/// `entity_crud.rs::get_record`'s `None` arm.
#[test]
fn query_execute_still_scopes_target_less_audit_rows_by_the_callers_own_audit_access() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);

        let audit_entity_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'audit_header'")
                .fetch_one(&db)
                .await
                .expect("audit_header must be seeded by attome_audit::seed::seed");

        // A target-less row: no `entity_name`/`record_id` at all, the shape a
        // real login/logout event takes (category 1 = Security, operation 9 =
        // Login) — `polymorphic_audit_target` resolves `Ok(None)` for these.
        let login_event: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_header \
         (entity_name, record_id, category, operation, event_hash) \
         VALUES (NULL, NULL, 1, 9, 'test-only-placeholder-login') RETURNING id",
        )
        .fetch_one(&db)
        .await
        .expect("insert target-less login-event fixture");

        // Reader: Team-tier on `audit_header` (narrowed below Global) and
        // nothing else — no share is possible on a target-less row at all (no
        // referenced record to share), so a correctly-scoped narrowed caller
        // must see none of them.
        let (reader_id, reader_cookie, reader_audit_role_id) =
            seed_user_with_privileges(&db, "audit_header", &["read"]).await;
        scope_role_for_entity(
            &db,
            &security,
            reader_audit_role_id,
            reader_id,
            audit_entity_id,
            1, // Team
        )
        .await;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/query/execute")
            .header("cookie", &reader_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"entity":"audit_header"}"#))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("query execute");
        assert_eq!(res.status(), StatusCode::OK);
        let body_text = body_json(res).await.to_string();
        assert!(
            !body_text.contains(&login_event.to_string()),
            "a Team-tier (narrowed, non-Global) caller must NOT see a \
         target-less audit row just because they hold the read privilege \
         at all — there is no share mechanism that could legitimately grant \
         this: {body_text}"
        );

        // Global (the D-133 default) must remain unaffected — sees the
        // target-less row like every other row, no per-row predicate at all.
        scope_role_for_entity(
            &db,
            &security,
            reader_audit_role_id,
            reader_id,
            audit_entity_id,
            3, // Global
        )
        .await;
        let (mut found, mut after_id) = (false, None::<Uuid>);
        for _ in 0..500 {
            let body = match after_id {
                Some(id) => format!(r#"{{"entity":"audit_header","after_id":"{id}"}}"#),
                None => r#"{"entity":"audit_header"}"#.to_owned(),
            };
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/query/execute")
                .header("cookie", &reader_cookie)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.expect("query execute");
            assert_eq!(res.status(), StatusCode::OK);
            let page = body_json(res).await;
            found |= page.to_string().contains(&login_event.to_string());
            if found {
                break;
            }
            match page["data"]["next_cursor"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                Some(id) => after_id = Some(id),
                None => break,
            }
        }
        assert!(
            found,
            "Global-tier access to the audit entity must still show a \
         target-less row (login_event not found across all pages)"
        );
    })
}

/// Cross-path consistency: `entity_crud.rs` (HTTP GET/PATCH) and `bulk.rs`
/// (`process`, driven here via `bulk_apply_and_wait`) both call
/// `entity_crud::require_record_access`, which itself calls the same
/// `attome_security::rls_predicate` every other record-level check uses. This
/// test does not re-verify the predicate's logic (see `rls.rs`'s own unit
/// tests and `attome-security/tests/rls_property.rs`) — it verifies the two
/// call sites AGREE, for the same caller/record/share state, across every
/// branch of the access-level ladder: `None` (with no/view/action/deny
/// share), `Team` (via entity-default share), and `BusinessUnit` (via org
/// hierarchy, with and without an overriding deny share). See this file's
/// header for why this isn't a `proptest` suite and what it does not cover.
#[test]
fn bulk_and_entity_crud_agree_across_the_access_ownership_share_matrix() {
    attome_testkit::run_shared(async {
        let logicalname = format!("rls_matrix_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let state = system.state().clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        // Shared across scenarios: one creator (left at the Global default) so
        // every scenario's record can be created regardless of which tier the
        // scenario is testing; one team and one parent/child org pair for the
        // Team- and BusinessUnit-tier scenarios respectively.
        let (_creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create"]).await;
        let team_id = create_team(&db, &format!("rls-matrix-team-{}", Uuid::now_v7())).await;
        let parent_org = create_organization(&db, "rls-matrix-parent-org", None).await;
        let child_org = create_organization(&db, "rls-matrix-child-org", Some(parent_org)).await;

        async fn fresh_viewer(db: &PgPool, logicalname: &str) -> (Uuid, String, Uuid) {
            seed_user_with_privileges(db, logicalname, &["read", "update", "bulk"]).await
        }

        async fn bulk_update(
            state: &EngineState,
            logicalname: &str,
            record_id: &str,
            row_version: i64,
            user_id: Uuid,
        ) -> (i32, i32) {
            let records = vec![serde_json::json!({
                "id": record_id,
                "expected_row_version": row_version,
                "data": { "title": "matrix-bulk-updated" }
            })];
            bulk_apply_and_wait(state, logicalname, "update", records, user_id).await
        }

        // ── S1: Global (no scoping at all) — both paths must allow. ────────────
        let (viewer_id, viewer_cookie, _role_id) = fresh_viewer(&db, &logicalname).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s1").await;
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "S1 (Global): entity_crud must allow"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (1, 0),
            "S1 (Global): bulk must agree with entity_crud and allow"
        );

        // ── S2: None tier, no share — both paths must deny. ─────────────────────
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 0).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s2").await;
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "S2 (None, no share): entity_crud must deny"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (0, 1),
            "S2 (None, no share): bulk must agree with entity_crud and deny"
        );

        // ── S3: None tier, view-only share — read allowed, update denied on
        //        BOTH paths (a view share must never satisfy an action check). ──
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 0).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s3").await;
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)", // principal_type=user, capability=view
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(viewer_id)
    .execute(&db)
    .await
    .expect("insert view share for S3");
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "S3 (None, view share): entity_crud must allow read"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (0, 1),
            "S3 (None, view share): bulk must agree with entity_crud and deny update \
         (view capability must not satisfy an action check)"
        );

        // ── S4: None tier, action share — both paths must allow update. ────────
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 0).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s4").await;
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)", // capability=action
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(viewer_id)
    .execute(&db)
    .await
    .expect("insert action share for S4");
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "S4 (None, action share): entity_crud must allow"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (1, 0),
            "S4 (None, action share): bulk must agree with entity_crud and allow"
        );

        // ── S5: None tier, action share ALSO deny-shared — deny must override
        //        the action share on BOTH paths. ────────────────────────────────
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 0).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s5").await;
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)",
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(viewer_id)
    .execute(&db)
    .await
    .expect("insert action share for S5");
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 2)", // capability=deny
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(viewer_id)
    .execute(&db)
    .await
    .expect("insert deny share for S5");
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "S5 (None, action+deny share): entity_crud must deny — deny always \
         overrides an otherwise-valid grant"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (0, 1),
            "S5 (None, action+deny share): bulk must agree with entity_crud and deny"
        );

        // ── S6: Team tier via entity-default share — both paths must allow. ────
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 1).await;
        add_user_to_team(&db, &security, viewer_id, team_id).await;
        sqlx::query(
        "INSERT INTO entity_default_share (entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, 1, $2, 1, 'project')", // principal_type=team, capability=action
    )
    .bind(entity_id)
    .bind(team_id)
    .execute(&db)
    .await
    .expect("insert team default share for S6");
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s6").await;
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "S6 (Team, default share): entity_crud must allow"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (1, 0),
            "S6 (Team, default share): bulk must agree with entity_crud and allow"
        );

        // ── S7: BusinessUnit tier via org hierarchy, no share needed — both
        //        paths must allow (org-tier membership alone grants access,
        //        unconditional on capability — see rls.rs's `build_predicate`).
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 2).await;
        add_user_to_organization(&db, &security, viewer_id, parent_org).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s7").await;
        sqlx::query(&format!(
            "UPDATE \"{logicalname}\" SET organization_ref = $1 WHERE id = $2"
        ))
        .bind(child_org)
        .bind(Uuid::parse_str(&record_id).unwrap())
        .execute(&db)
        .await
        .expect("stamp organization_ref for S7");
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "S7 (BusinessUnit, org hierarchy): entity_crud must allow"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (1, 0),
            "S7 (BusinessUnit, org hierarchy): bulk must agree with entity_crud \
         and allow — the org fast path is unconditional on capability"
        );

        // ── S8: BusinessUnit tier via org hierarchy, but deny-shared — deny
        //        must override the org fast path on BOTH paths. ────────────────
        let (viewer_id, viewer_cookie, role_id) = fresh_viewer(&db, &logicalname).await;
        scope_role_for_entity(&db, &security, role_id, viewer_id, entity_id, 2).await;
        add_user_to_organization(&db, &security, viewer_id, parent_org).await;
        let (record_id, row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "s8").await;
        sqlx::query(&format!(
            "UPDATE \"{logicalname}\" SET organization_ref = $1 WHERE id = $2"
        ))
        .bind(child_org)
        .bind(Uuid::parse_str(&record_id).unwrap())
        .execute(&db)
        .await
        .expect("stamp organization_ref for S8");
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 2)", // capability=deny
    )
    .bind(Uuid::parse_str(&record_id).unwrap())
    .bind(entity_id)
    .bind(viewer_id)
    .execute(&db)
    .await
    .expect("insert deny share for S8");
        assert_eq!(
            get_record_as(&app, &viewer_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "S8 (BusinessUnit, org hierarchy + deny share): entity_crud must deny \
         — deny overrides the org fast path too"
        );
        assert_eq!(
            bulk_update(&state, &logicalname, &record_id, row_version, viewer_id).await,
            (0, 1),
            "S8 (BusinessUnit, org hierarchy + deny share): bulk must agree with \
         entity_crud and deny"
        );
    })
}

/// Closes the gap this file's own header used to flag: `files.rs`'s four
/// handlers were untested for the RLS-denial case, and the obvious place to
/// test them (`file_upload_pipeline.rs`) requires a reachable S3/RustFS
/// bucket. But every one of `create_upload_session`/`finalize_upload_session`/
/// `get_upload_session_status`/`get_download_url` calls
/// `require_record_access` (the same `rls_predicate`-backed gate
/// `entity_crud.rs` uses) BEFORE touching storage or a session's
/// `owner_user_ref` — so the gate itself is fully exercisable with only
/// Postgres/Redis. This proves an RLS-scoped-out caller is denied at all
/// four endpoints, including against a session they don't own either,
/// showing it's the record-level gate stopping them and not the
/// ownership check that runs after it.
///
/// Written in a code-only session with no live Postgres/Redis/Rust
/// toolchain available — **not run or compiled in this session**; run it
/// against a throwaway database before relying on it, same caveat
/// D-137/D-138/D-139/D-140/D-141 recorded for their own then-unrun tests.
#[test]
fn files_endpoints_deny_access_to_a_caller_outside_the_records_rls_scope() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_filetest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;

        let field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"attachment","name":"Attachment","field_type":"file"}"#,
            ))
            .unwrap();
        let res = app
            .clone()
            .oneshot(field_req)
            .await
            .expect("create file field");
        assert_eq!(res.status(), StatusCode::CREATED, "create file field");

        let (creator_id, creator_cookie, _creator_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create", "update"]).await;
        let (record_id, _row_version) =
            create_record_as(&app, &creator_cookie, &logicalname, "has-a-file-field").await;

        // Narrow an outsider to None-tier — mirrors
        // `explicit_record_share_grants_access_outside_any_hierarchy`'s
        // "stranger" setup. The outsider holds real table-level read/update
        // privilege, so `ctx.require` passes and it's genuinely the
        // record-level gate under test, not a missing table-level grant.
        let (outsider_id, outsider_cookie, outsider_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "update"]).await;
        scope_role_for_entity(
            &db,
            &security,
            outsider_role_id,
            outsider_id,
            entity_id,
            0, // None
        )
        .await;
        assert_eq!(
            get_record_as(&app, &outsider_cookie, &logicalname, &record_id).await,
            StatusCode::NOT_FOUND,
            "sanity: the outsider must not see the record via ordinary entity_crud \
         GET either"
        );

        let upload_session_body =
            r#"{"filename":"hello.txt","content_type":"text/plain","declared_size_bytes":11}"#;

        // (1) upload-session: an outsider must not be able to create one at all.
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session"
            ))
            .header("cookie", &outsider_cookie)
            .header("content-type", "application/json")
            .body(Body::from(upload_session_body))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "an RLS-scoped-out caller must not be able to create an upload \
         session for a record they cannot see"
        );

        // The creator (who genuinely has record access) can — proves the denial
        // above is the RLS gate itself, not a provisioning problem with the file
        // field. `files.rs::resolve_file_field` only ever reads the arc-swap
        // metadata registry, which rebuilds ~250ms after provisioning's
        // `meta_version` pub/sub signal — same race `tests/file_upload_pipeline.
        // rs::create_upload_session_with_retry` bounds, applied inline here since
        // this is the only call site in this file that needs it.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let (status, session) = loop {
            let req = Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session"
                ))
                .header("cookie", &creator_cookie)
                .header("content-type", "application/json")
                .body(Body::from(upload_session_body))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let status = res.status();
            if status != StatusCode::NOT_FOUND || tokio::time::Instant::now() >= deadline {
                break (status, body_json(res).await);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "creator's own upload-session failed: {session:?}"
        );
        let session_id = session["session_id"]
            .as_str()
            .expect("session_id")
            .to_owned();

        // (2) status poll: the outsider must be denied by the RLS gate before
        // ever reaching the owner_user_ref check — they aren't the session
        // owner either, but this proves WHICH check stops them.
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}"
            ))
            .header("cookie", &outsider_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "an RLS-scoped-out caller must not be able to poll another user's \
         upload session status for a record they cannot see"
        );

        // (3) finalize: same gate, before any storage HEAD call.
        let req = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/{logicalname}/{record_id}/files/attachment/upload-session/{session_id}/finalize"
        ))
        .header("cookie", &outsider_cookie)
        .body(Body::empty())
        .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "an RLS-scoped-out caller must not be able to finalize another \
         user's upload session for a record they cannot see"
        );

        // (4) download-url: same gate, before ever reading the file-field column.
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/api/v1/{logicalname}/{record_id}/files/attachment/download-url"
            ))
            .header("cookie", &outsider_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "an RLS-scoped-out caller must not be able to request a download URL \
         for a record they cannot see, even before checking whether the \
         field has ever been uploaded to"
        );

        let _ = creator_id;
    })
}

// ── C-01: record-level gate on attome-state's per-record routes ────────────────
//
// `attome_server::authz::RecordScoped<A>` (used by both
// `attome-state::record_routes` handlers) authorizes only the entity-level
// privilege `"{entity}.{action}"` — its own doc comment names "record-level
// scope" as something the handler must still check itself via
// `require_record_access`, exactly as `entity_crud.rs`'s handlers do (every
// test above this section proves that side of the boundary). Before this
// fix, `GET /{entity}/{id}/transitions` and `POST /{entity}/{id}/transition`
// never made that second call, so a Team/BusinessUnit-scoped caller holding
// only the table-level privilege could read the lifecycle state of, and
// drive a transition on, ANY record of that entity — including one owned by
// a different team entirely. The two tests below close that gap and prove
// the fix reduces to the exact same 404 the generic GET already gives the
// same caller.

async fn provision_choice_field(
    app: &axum::Router,
    admin_cookie: &str,
    entity_id: Uuid,
    logicalname: &str,
    choices: &[&str],
) {
    let choices_json = choices
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"{logicalname}","field_type":"choice","options":{{"choices":[{choices_json}],"multi":false}}}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create choice field");
    assert_eq!(res.status(), StatusCode::CREATED, "create choice field");
}

/// Creates a state model bound to `state_field`, `is_active`, via
/// `attome-state`'s own admin API — mirrors `state_lifecycle.rs`'s
/// `create_ticket_lifecycle`, trimmed to the one model+transition this
/// file's tests need.
async fn create_state_model(
    app: &axum::Router,
    admin_cookie: &str,
    entity: &str,
    state_field: &str,
    initial_state: &str,
) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/state-models")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity_logicalname":"{entity}","name":"RLS State Test","state_field":"{state_field}","initial_state":"{initial_state}","is_active":true}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create state model");
    assert_eq!(res.status(), StatusCode::CREATED, "create state model");
    let body = body_json(res).await;
    Uuid::parse_str(body["id"].as_str().expect("state model id")).expect("state model id is a uuid")
}

async fn create_state_transition(
    app: &axum::Router,
    admin_cookie: &str,
    model_id: Uuid,
    from_state: &str,
    to_state: &str,
    name: &str,
) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/state-models/{model_id}/transitions"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"from_state":"{from_state}","to_state":"{to_state}","name":"{name}"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create transition");
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create transition {from_state}->{to_state}"
    );
}

async fn list_transitions_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/{logicalname}/{record_id}/transitions"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("list transitions")
        .status()
}

async fn transition_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
    to_state: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}/{record_id}/transition"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"to_state":"{to_state}"}}"#)))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("post transition")
        .status()
}

/// C-01's core proof: a Team-scoped caller holding table-level
/// `{entity}.read`+`{entity}.update`, but no team/share reach into a
/// specific record, must be denied by BOTH `GET .../transitions` and `POST
/// .../transition` — the same `404` the generic `GET /{entity}/{id}`
/// already gives that caller for that same record — while the record's
/// owner (who genuinely has record-level access via the implicit
/// creator-share, D-133 (2)) still gets through both routes.
#[test]
fn state_routes_enforce_record_level_access_not_just_entity_level() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let logicalname = format!("rls_statetest_{}", Uuid::now_v7().simple());
        let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;
        provision_choice_field(
            &app,
            &admin_cookie,
            entity_id,
            "status",
            &["new", "in_progress"],
        )
        .await;

        let model_id = create_state_model(&app, &admin_cookie, &logicalname, "status", "new").await;
        create_state_transition(&app, &admin_cookie, model_id, "new", "in_progress", "Start").await;

        // Owner: creates the record and keeps access via the implicit
        // creator-share, regardless of any tier scoping (D-133 (2)).
        let (_owner_id, owner_cookie, _owner_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "create", "update"]).await;
        let (record_id, _row_version) =
            create_record_as(&app, &owner_cookie, &logicalname, "owner-record").await;

        // Outsider: holds the SAME table-level privileges, but is Team-scoped
        // (access_level = Team) on a team with no share reaching the owner's
        // record — the exact shape `team_tier_grants_access_via_entity_default_share`
        // proves denies the generic GET.
        let (outsider_id, outsider_cookie, outsider_role_id) =
            seed_user_with_privileges(&db, &logicalname, &["read", "update"]).await;
        let outsider_team =
            create_team(&db, &format!("rls-state-outsider-team-{}", Uuid::now_v7())).await;
        add_user_to_team(&db, &security, outsider_id, outsider_team).await;
        scope_role_for_entity(
            &db,
            &security,
            outsider_role_id,
            outsider_id,
            entity_id,
            1, // Team
        )
        .await;

        // Sanity: the generic GET already denies the outsider — proves the
        // scoping setup itself works before checking the two state routes this
        // test actually guards.
        let generic_get_status =
            get_record_as(&app, &outsider_cookie, &logicalname, &record_id).await;
        assert_eq!(
            generic_get_status,
            StatusCode::NOT_FOUND,
            "sanity: the outsider must not see the record via the generic GET either"
        );

        // The bug this test closes: both state routes must deny the outsider
        // the SAME way the generic GET does, not merely check
        // {logicalname}.read/{logicalname}.update table-wide.
        assert_eq!(
            list_transitions_as(&app, &outsider_cookie, &logicalname, &record_id).await,
            generic_get_status,
            "GET .../transitions must deny a Team-scoped outsider identically to \
         the generic GET, not just their table-level {logicalname}.read privilege"
        );
        assert_eq!(
            transition_record_as(
                &app,
                &outsider_cookie,
                &logicalname,
                &record_id,
                "in_progress"
            )
            .await,
            StatusCode::NOT_FOUND,
            "POST .../transition must deny a Team-scoped outsider identically to \
         the generic GET/PATCH, not just their table-level \
         {logicalname}.update privilege"
        );

        // The denied attempt above must not have mutated the record.
        let table = attome_core::quote_ident(&logicalname);
        let status_after_denied_attempt: String =
            sqlx::query_scalar(&format!("SELECT status FROM {table} WHERE id = $1"))
                .bind(Uuid::parse_str(&record_id).unwrap())
                .fetch_one(&db)
                .await
                .expect("read record status");
        assert_eq!(
            status_after_denied_attempt, "new",
            "a denied transition attempt must never mutate the record"
        );

        // And the owner still gets through both routes.
        assert_eq!(
            list_transitions_as(&app, &owner_cookie, &logicalname, &record_id).await,
            StatusCode::OK,
            "the owner must still see the record's available transitions"
        );
        assert_eq!(
            transition_record_as(&app, &owner_cookie, &logicalname, &record_id, "in_progress")
                .await,
            StatusCode::OK,
            "the owner must still be able to perform the transition"
        );

        let status_after_owner_transition: String =
            sqlx::query_scalar(&format!("SELECT status FROM {table} WHERE id = $1"))
                .bind(Uuid::parse_str(&record_id).unwrap())
                .fetch_one(&db)
                .await
                .expect("read record status");
        assert_eq!(
            status_after_owner_transition, "in_progress",
            "the owner's legitimate transition must have applied"
        );
    })
}

/// D-589: bulk surfaces show a `listed` role's holder only the fields it
/// lists (plus id, system columns and the primary name); interactive reads
/// are unchanged; a role created through the admin API is `listed`, a role
/// that predates migration 0491 stays `legacy`; and the admin route that
/// edits the list takes effect for current holders at once.
#[test]
fn bulk_surfaces_show_a_listed_role_only_its_listed_fields() {
    attome_testkit::run_shared(async {
        let entity = format!("rls_bulk_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let state = system.state().clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let entity_id = provision_entity(&app, &admin_cookie, &entity).await;
        provision_text_field(&app, &admin_cookie, entity_id).await;
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"logicalname":"phone","name":"Phone","field_type":"text"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );
        sync_registry(&state).await;

        // A role created through the admin API is `listed`; one inserted the way
        // pre-0491 roles exist keeps the column default, `legacy`.
        let listed_role = create_role_via_api(&app, &admin_cookie).await;
        for action in ["read", "create"] {
            grant_role_privilege_via_api(
                &app,
                &admin_cookie,
                listed_role,
                &format!("{entity}.{action}"),
            )
            .await;
        }
        let legacy_role = create_role_with_privileges(&db, &entity, &["read"]).await;
        let modes: Vec<(Uuid, i16)> =
            sqlx::query_as("SELECT id, bulk_field_mode FROM role WHERE id = ANY($1) ORDER BY id")
                .bind(vec![listed_role, legacy_role])
                .fetch_all(&db)
                .await
                .unwrap();
        let mode_of = |id| modes.iter().find(|(r, _)| *r == id).unwrap().1;
        assert_eq!(mode_of(listed_role), 1, "admin-created roles are listed");
        assert_eq!(mode_of(legacy_role), 0, "existing roles stay legacy");

        let mut users = Vec::new();
        for role in [listed_role, legacy_role] {
            let user_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)",
            )
            .bind(user_id)
            .bind(format!("rls-bulk-user-{user_id}"))
            .execute(&db)
            .await
            .unwrap();
            assign_role_to_user(&db, user_id, role).await;
            users.push(user_id);
        }
        let (listed_user, legacy_user) = (users[0], users[1]);

        // A record with both fields, written by the admin.
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{entity}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"title":"Acme","phone":"555-0100"}"#))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let record_id = Uuid::parse_str(body_json(res).await["id"].as_str().unwrap()).unwrap();

        let fields = |v: &serde_json::Value| -> (bool, bool, bool) {
            (
                v.get("id").is_some(),
                v.get("title").is_some(),
                v.get("phone").is_some(),
            )
        };
        // Interactive: D-111 unchanged for both.
        assert_eq!(
            fields(&read_as(&state, &db, &entity, record_id, listed_user, false).await),
            (true, true, true)
        );
        // Bulk: the listed role lists nothing yet, so only id.
        assert_eq!(
            fields(&read_as(&state, &db, &entity, record_id, listed_user, true).await),
            (true, false, false)
        );
        // Bulk, legacy role: today's behaviour.
        assert_eq!(
            fields(&read_as(&state, &db, &entity, record_id, legacy_user, true).await),
            (true, true, true)
        );

        // List `phone`, through the admin route; the holder sees it at once.
        let put = |body: String| {
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/api/v1/admin/security/roles/{listed_role}/bulk-fields"
                ))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let res = app
            .clone()
            .oneshot(put(format!(
                r#"{{"mode":"listed","fields":[{{"entity":"{entity}","attribute":"phone"}}]}}"#
            )))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            fields(&read_as(&state, &db, &entity, record_id, listed_user, true).await),
            (true, false, true)
        );

        // Unknown attributes are refused.
        let res = app
            .clone()
            .oneshot(put(format!(
                r#"{{"mode":"listed","fields":[{{"entity":"{entity}","attribute":"nope"}}]}}"#
            )))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Back to legacy restores today's behaviour for the holder.
        let res = app
            .clone()
            .oneshot(put(r#"{"mode":"legacy","fields":[]}"#.to_owned()))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            fields(&read_as(&state, &db, &entity, record_id, listed_user, true).await),
            (true, true, true)
        );
    })
}

/// One record's `data`, read as `user` on an interactive or a bulk surface.
async fn read_as(
    state: &EngineState,
    db: &PgPool,
    entity: &str,
    record_id: Uuid,
    user: Uuid,
    bulk: bool,
) -> serde_json::Value {
    let ctx = attome_security::resolver::resolve_uncached(db, user)
        .await
        .expect("resolve");
    let record = if bulk {
        attome_records::entity_crud::read_record_bulk(state, &ctx, entity, record_id).await
    } else {
        attome_records::entity_crud::read_record(state, &ctx, entity, record_id).await
    };
    record.expect("read").data().clone()
}

// ── U1 (basic-units plan B-R1): polymorphic child entities ───────────────────
//
// `note` (and `communication`, `tag_item`, `follow`) hang off
// another record through a text `entity_name` + `record_id`. Before U1 they
// were read under their own row security alone, so a caller holding
// `note.read` at Global saw the notes of records hidden from them. These
// pin the fix: the parent check is ADDED to the row's own check (never
// substituted for it), on the single-read, list and create paths.

async fn entity_id_of(db: &PgPool, logicalname: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
        .bind(logicalname)
        .fetch_one(db)
        .await
        .unwrap_or_else(|_| panic!("{logicalname} must be provisioned by its platform bundle"))
}

async fn insert_note(db: &PgPool, parent_entity: &str, parent_id: &str, title: &str) -> String {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO note (title, note_text, entity_name, record_id) \
         VALUES ($1, 'body', $2, $3) RETURNING id",
    )
    .bind(title)
    .bind(parent_entity)
    .bind(parent_id)
    .fetch_one(db)
    .await
    .expect("insert note fixture");
    id.to_string()
}

async fn list_notes_about(
    app: &axum::Router,
    cookie: &str,
    parent_entity: &str,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"note","page_size":200,"filters":[{{"field":"entity_name","op":"eq","value":"{parent_entity}"}}]}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("query execute");
    let status = res.status();
    (status, body_json(res).await.to_string())
}

async fn create_note_as(
    app: &axum::Router,
    cookie: &str,
    parent_entity: &str,
    parent_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/note")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"title":"t","note_text":"n","entity_name":"{parent_entity}","record_id":"{parent_id}"}}"#
        )))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("create note")
        .status()
}

#[test]
fn note_on_a_hidden_record_is_not_readable_even_with_global_note_read() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_note_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;
        let note_id = insert_note(&db, &target_name, &record_id, "about a private record").await;

        // Global (the unscoped default) read on note; None on the target.
        let (reader_id, reader_cookie, _) = seed_user_with_privileges(&db, "note", &["read"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0,
        )
        .await;

        assert_eq!(
            get_record_as(&app, &reader_cookie, "note", &note_id).await,
            StatusCode::NOT_FOUND,
            "Global note.read must not expose the note of a record the reader cannot see"
        );

        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            3,
        )
        .await;
        assert_eq!(
            get_record_as(&app, &reader_cookie, "note", &note_id).await,
            StatusCode::OK,
            "once the parent record is visible its note is readable again"
        );
    })
}

#[test]
fn parent_access_is_added_to_the_notes_own_scope_never_substituted_for_it() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_note_and_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "open").await;
        let note_id = insert_note(&db, &target_name, &record_id, "someone else's note").await;

        // Parent fully visible (Global), but the reader's own note scope is
        // None and nobody shared this note with them. Substituting the parent
        // check for the note's own would wrongly make it visible.
        let note_entity_id = entity_id_of(&db, "note").await;
        let (reader_id, reader_cookie, note_role_id) =
            seed_user_with_privileges(&db, "note", &["read"]).await;
        scope_role_for_entity(&db, &security, note_role_id, reader_id, note_entity_id, 0).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            3,
        )
        .await;

        assert_eq!(
            get_record_as(&app, &reader_cookie, "note", &note_id).await,
            StatusCode::NOT_FOUND,
            "a visible parent must not widen the reader's own note scope"
        );
        let (status, body) = list_notes_about(&app, &reader_cookie, &target_name).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !body.contains(&note_id),
            "the list must honour the note's own scope too: {body}"
        );
    })
}

#[test]
fn note_list_keeps_only_notes_whose_parent_record_is_visible() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_note_list_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_a, _) = create_record_as(&app, &admin_cookie, &target_name, "a").await;
        let (record_b, _) = create_record_as(&app, &admin_cookie, &target_name, "b").await;
        let note_a = insert_note(&db, &target_name, &record_a, "on a").await;
        let note_b = insert_note(&db, &target_name, &record_b, "on b").await;
        // A malformed parent id must be hidden, not turn the page into a 500.
        let note_bad = insert_note(&db, &target_name, "not-a-uuid", "on nothing").await;

        let (reader_id, reader_cookie, _) = seed_user_with_privileges(&db, "note", &["read"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0,
        )
        .await;
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)",
    )
    .bind(Uuid::parse_str(&record_a).expect("record a id"))
    .bind(target_entity_id)
    .bind(reader_id)
    .execute(&db)
    .await
    .expect("share record A only");

        let (status, body) = list_notes_about(&app, &reader_cookie, &target_name).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(&note_a),
            "the note on shared record A must be listed: {body}"
        );
        assert!(
            !body.contains(&note_b),
            "the note on unshared record B must not be listed: {body}"
        );
        assert!(
            !body.contains(&note_bad),
            "a note with no resolvable parent must not be listed: {body}"
        );

        let (status, body) = list_notes_about(&app, &admin_cookie, &target_name).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(&note_a) && body.contains(&note_b) && body.contains(&note_bad),
            "an admin is not narrowed: {body}"
        );
    })
}

#[test]
fn creating_a_note_on_a_hidden_record_is_refused() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_note_create_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;

        let (writer_id, writer_cookie, _) =
            seed_user_with_privileges(&db, "note", &["read", "create"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, writer_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            writer_id,
            target_entity_id,
            0,
        )
        .await;

        assert_eq!(
            create_note_as(&app, &writer_cookie, &target_name, &record_id).await,
            StatusCode::NOT_FOUND,
            "a note cannot be attached to a record the writer cannot read"
        );
        assert_eq!(
            create_note_as(&app, &writer_cookie, &target_name, "not-a-uuid").await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a note must name its parent by a record UUID"
        );

        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            writer_id,
            target_entity_id,
            3,
        )
        .await;
        assert_eq!(
            create_note_as(&app, &writer_cookie, &target_name, &record_id).await,
            StatusCode::CREATED,
            "with the parent visible the same note is accepted"
        );
    })
}

async fn upsert_note_as(
    app: &axum::Router,
    cookie: &str,
    title: &str,
    parent_entity: &str,
    parent_id: &str,
    row_version: Option<i64>,
) -> StatusCode {
    let version = row_version
        .map(|v| format!(r#","row_version":{v}"#))
        .unwrap_or_default();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/note/upsert")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"match":{{"title":"{title}"}},"data":{{"note_text":"n","entity_name":"{parent_entity}","record_id":"{parent_id}"}}{version}}}"#
        )))
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("upsert note")
        .status()
}

/// D-593 follow-up: upsert and merge are write paths too. Before this they ran
/// only the note's own record check, so a note could be upserted onto a hidden
/// record, and notes on a hidden record could be updated or merged.
#[test]
fn upsert_and_merge_of_notes_respect_the_parent_record() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_note_upsert_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;

        let (writer_id, writer_cookie, _) =
            seed_user_with_privileges(&db, "note", &["read", "create", "update", "delete"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, writer_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            writer_id,
            target_entity_id,
            0,
        )
        .await;

        // The first upsert on a match key provisions its unique index, which only an
        // administrator may do (production DDL) — seed it so the non-admin calls
        // below reach the record-level checks this test is about.
        assert_eq!(
            upsert_note_as(
                &app,
                &admin_cookie,
                &format!("upsert-index-seed-{}", Uuid::now_v7().simple()),
                &target_name,
                &record_id,
                None,
            )
            .await,
            StatusCode::CREATED,
            "an administrator must be able to provision the upsert key"
        );

        // Upsert that would create a note on the hidden record.
        let new_title = format!("upsert-new-{}", Uuid::now_v7().simple());
        assert_eq!(
            upsert_note_as(
                &app,
                &writer_cookie,
                &new_title,
                &target_name,
                &record_id,
                None
            )
            .await,
            StatusCode::NOT_FOUND,
            "upsert must not create a note on a record the writer cannot read"
        );

        // Upsert that would update an existing note on the hidden record.
        let existing_title = format!("upsert-existing-{}", Uuid::now_v7().simple());
        let existing_id = insert_note(&db, &target_name, &record_id, &existing_title).await;
        let existing_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM note WHERE id = $1")
                .bind(Uuid::parse_str(&existing_id).expect("note id"))
                .fetch_one(&db)
                .await
                .expect("note row_version");
        assert_eq!(
            upsert_note_as(
                &app,
                &writer_cookie,
                &existing_title,
                &target_name,
                &record_id,
                Some(existing_version),
            )
            .await,
            StatusCode::NOT_FOUND,
            "upsert must not update a note hanging off a record the writer cannot read"
        );

        // Merging two notes on the hidden record.
        let note_a = insert_note(&db, &target_name, &record_id, "merge a").await;
        let note_b = insert_note(&db, &target_name, &record_id, "merge b").await;
        assert_eq!(
            merge_records_as(&app, &writer_cookie, "note", &note_a, &note_b).await,
            StatusCode::NOT_FOUND,
            "merge must not touch notes on a record the writer cannot read"
        );

        // With the parent visible, the same upsert creates the note.
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            writer_id,
            target_entity_id,
            3,
        )
        .await;
        assert_eq!(
            upsert_note_as(
                &app,
                &writer_cookie,
                &new_title,
                &target_name,
                &record_id,
                None
            )
            .await,
            StatusCode::CREATED,
            "with the parent visible the upsert is accepted"
        );
    })
}

// ── U2 (basic-units plan, D-600): `activity` is a polymorphic child too ──
//
// D-593's list was extended with `activity` when the entity landed. These
// mirror the `note_*` tests above: a hidden parent hides the activity on the
// single-read and list paths and refuses a create, and the seeded lifecycle
// (open -> completed / cancelled, reopen) is enforced on a generic PATCH.

async fn insert_activity(
    db: &PgPool,
    parent_entity: &str,
    parent_id: &str,
    subject: &str,
) -> String {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO activity (subject, activity_type, status, entity_name, record_id) \
         VALUES ($1, 'task', 'open', $2, $3) RETURNING id",
    )
    .bind(subject)
    .bind(parent_entity)
    .bind(parent_id)
    .fetch_one(db)
    .await
    .expect("insert activity fixture");
    id.to_string()
}

async fn list_activities_about(
    app: &axum::Router,
    cookie: &str,
    parent_entity: &str,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"entity":"activity","page_size":200,"filters":[{{"field":"entity_name","op":"eq","value":"{parent_entity}"}}]}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("query execute");
    let status = res.status();
    (status, body_json(res).await.to_string())
}

async fn create_activity_as(
    app: &axum::Router,
    cookie: &str,
    parent_entity: &str,
    parent_id: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/activity")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"subject":"call back","activity_type":"phone_call","direction":"outbound","entity_name":"{parent_entity}","record_id":"{parent_id}"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create activity");
    let status = res.status();
    (status, body_json(res).await)
}

async fn set_activity_status_as(
    app: &axum::Router,
    cookie: &str,
    activity_id: &str,
    row_version: i64,
    status: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/activity/{activity_id}"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(format!(r#"{{"status":"{status}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("patch activity");
    let code = res.status();
    (code, body_json(res).await)
}

#[test]
fn activity_on_a_hidden_record_is_not_readable_even_with_global_activity_read() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_act_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;
        let activity_id =
            insert_activity(&db, &target_name, &record_id, "about a private record").await;

        let (reader_id, reader_cookie, _) =
            seed_user_with_privileges(&db, "activity", &["read"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0,
        )
        .await;

        assert_eq!(
            get_record_as(&app, &reader_cookie, "activity", &activity_id).await,
            StatusCode::NOT_FOUND,
            "Global activity.read must not expose the activity of a record the reader cannot see"
        );

        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            3,
        )
        .await;
        assert_eq!(
            get_record_as(&app, &reader_cookie, "activity", &activity_id).await,
            StatusCode::OK,
            "once the parent record is visible its activity is readable again"
        );
    })
}

#[test]
fn activity_list_keeps_only_activities_whose_parent_record_is_visible() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_act_list_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_a, _) = create_record_as(&app, &admin_cookie, &target_name, "a").await;
        let (record_b, _) = create_record_as(&app, &admin_cookie, &target_name, "b").await;
        let act_a = insert_activity(&db, &target_name, &record_a, "on a").await;
        let act_b = insert_activity(&db, &target_name, &record_b, "on b").await;
        // A malformed parent id must be hidden, not turn the page into a 500.
        let act_bad = insert_activity(&db, &target_name, "not-a-uuid", "on nothing").await;

        let (reader_id, reader_cookie, _) =
            seed_user_with_privileges(&db, "activity", &["read"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, reader_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            reader_id,
            target_entity_id,
            0,
        )
        .await;
        sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)",
    )
    .bind(Uuid::parse_str(&record_a).expect("record a id"))
    .bind(target_entity_id)
    .bind(reader_id)
    .execute(&db)
    .await
    .expect("share record A only");

        let (status, body) = list_activities_about(&app, &reader_cookie, &target_name).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(&act_a),
            "the activity on shared record A must be listed: {body}"
        );
        assert!(
            !body.contains(&act_b),
            "the activity on unshared record B must not be listed: {body}"
        );
        assert!(
            !body.contains(&act_bad),
            "an activity with no resolvable parent must not be listed: {body}"
        );

        let (status, body) = list_activities_about(&app, &admin_cookie, &target_name).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(&act_a) && body.contains(&act_b) && body.contains(&act_bad),
            "an admin is not narrowed: {body}"
        );
    })
}

#[test]
fn creating_an_activity_on_a_hidden_record_is_refused() {
    attome_testkit::run_shared(async {
        let target_name = format!("rls_act_create_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "private").await;

        let (writer_id, writer_cookie, _) =
            seed_user_with_privileges(&db, "activity", &["read", "create"]).await;
        let target_role_id = create_role_with_privileges(&db, &target_name, &["read"]).await;
        assign_role_to_user(&db, writer_id, target_role_id).await;
        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            writer_id,
            target_entity_id,
            0,
        )
        .await;

        let (status, body) =
            create_activity_as(&app, &writer_cookie, &target_name, &record_id).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an activity cannot be attached to a record the writer cannot read: {body}"
        );
        let (status, body) =
            create_activity_as(&app, &writer_cookie, &target_name, "not-a-uuid").await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "an activity must name its parent by a record UUID: {body}"
        );

        scope_role_for_entity(
            &db,
            &security,
            target_role_id,
            writer_id,
            target_entity_id,
            3,
        )
        .await;
        let (status, body) =
            create_activity_as(&app, &writer_cookie, &target_name, &record_id).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "with the parent visible the same activity is accepted: {body}"
        );
        assert_eq!(
            body["data"]["status"], "open",
            "a new activity lands in the seeded initial state: {body}"
        );
    })
}

#[test]
fn activity_lifecycle_is_enforced_on_a_generic_patch() {
    attome_testkit::run_shared(async {
        let target_name = format!("act_lifecycle_{}", Uuid::now_v7().simple());
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (_admin_id, admin_cookie) = seed_admin(&db).await;

        let target_entity_id = provision_entity(&app, &admin_cookie, &target_name).await;
        provision_text_field(&app, &admin_cookie, target_entity_id).await;
        let (record_id, _) = create_record_as(&app, &admin_cookie, &target_name, "parent").await;

        let (status, created) =
            create_activity_as(&app, &admin_cookie, &target_name, &record_id).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["data"]["status"], "open", "{created}");
        let id = created["id"].as_str().expect("activity id").to_owned();
        let rv = created["row_version"].as_i64().expect("row_version");

        let (status, completed) =
            set_activity_status_as(&app, &admin_cookie, &id, rv, "completed").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "open -> completed is a seeded transition: {completed}"
        );
        let rv = completed["row_version"].as_i64().expect("row_version");

        let (status, body) =
            set_activity_status_as(&app, &admin_cookie, &id, rv, "cancelled").await;
        assert!(
            status.is_client_error() && status != StatusCode::NOT_FOUND,
            "completed -> cancelled is not a transition and must be refused, got {status}: {body}"
        );

        let (status, body) = set_activity_status_as(&app, &admin_cookie, &id, rv, "open").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "completed -> open (reopen) is allowed: {body}"
        );
    })
}
