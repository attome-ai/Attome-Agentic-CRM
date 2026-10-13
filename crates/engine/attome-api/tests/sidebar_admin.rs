//! Regression coverage for `sidebar.rs`/`sidebar_seed.rs` — the admin HTTP
//! surface for managing the app's sidebar navigation tree, and the idempotent
//! seed that provisions its built-in items at boot. This surface previously
//! had zero test coverage: a regression in the privilege gate, the
//! optimistic-concurrency check, the parent/cycle validation, or the
//! is_active/is_deleted split between the admin list and the live end-user
//! tree would not have been caught by CI.
//!
//! Covers:
//! - non-admin rejection (`403`) on every `/api/v1/sidebar/admin*` route,
//! - `GET /api/v1/sidebar/get` (the live end-user nav tree) is NOT gated by
//!   the `sidebar.manage` privilege the way the admin routes are — a
//!   non-admin session can still read it, just filtered to items it has
//!   privilege visibility into,
//! - `sidebar_seed::seed` (run automatically by `EngineSystemBuilder::build()`,
//!   and not reachable directly from this crate's tests since `mod
//!   sidebar_seed;` is private) is idempotent: building a second `EngineSystem`
//!   against the same database does not change the `sidebar` row count,
//! - the create/list/update/deactivate round trip as an admin, including
//!   assigning/clearing a privilege gate on an item,
//! - create-time validation: empty name, a route not starting with `/`, an
//!   unknown `module_key`, a nonexistent `parent_ref`,
//! - create-time privilege-assignment validation: duplicate `privilege_ids`,
//!   an unknown/inactive privilege id,
//! - update-time validation: an item cannot be its own parent, and a parent
//!   selection that would create a cycle through an existing descendant,
//! - update's optimistic-concurrency contract: a stale `row_version` is `409
//!   VersionConflict`, a truly nonexistent id is `404 NotFound` — two
//!   different outcomes for two different failure shapes,
//! - deactivate's contract is NOT the same as update's: it never
//!   distinguishes "not found" from "stale row_version" — both come back
//!   `409`,
//! - deactivate cascades to every descendant (`WITH RECURSIVE`), and the
//!   deactivated subtree disappears from the live `/sidebar/get` tree while
//!   still showing up in the admin list (which only filters `is_deleted`,
//!   not `is_active`) — the DELETE verb here means "deactivate", not "purge",
//!   there is no handler that ever sets `is_deleted = true`,
//! - `display_order` changes made through the ordinary update endpoint
//!   actually persist and re-sort the admin list's global `ORDER BY
//!   display_order, name`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `rewrap_admin.rs`/`jobs_admin.rs`.
//! **Verified 2026-08-24 (MAINT-10): 11 passed, 0 failed, 81.70s** against a
//! real Postgres and Redis, retiring the "Not run in this session (code-only,
//! no DB/Redis access)" note this header carried.
//!
//! Both runs are recorded deliberately. The first failed — **9 passed / 2
//! failed in 177.24s** — and a plain retry with no code change passed clean.
//! Note the direction: the *failing* run took **more than twice as long** as
//! the passing one, which is the contention signature rather than a slow
//! assertion. Five concurrent cargo builds were running at the time.
//! **Retry once before concluding**, and record which run you are quoting.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test sidebar_admin -- --test-threads=1
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
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

fn full_app(system: EngineSystem) -> axum::Router {
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("sidebar-admin-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    if admin {
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
    }

    (user_id, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

// ── request builders ─────────────────────────────────────────────────────

fn get_request(cookie: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
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

fn list_admin_request(cookie: &str) -> Request<Body> {
    get_request(cookie, "/api/v1/sidebar/admin?page=1&page_size=200")
}

fn list_privileges_request(cookie: &str) -> Request<Body> {
    get_request(
        cookie,
        "/api/v1/sidebar/admin/privileges?page=1&page_size=200",
    )
}

fn sidebar_get_request(cookie: &str) -> Request<Body> {
    get_request(cookie, "/api/v1/sidebar/get")
}

fn create_request(cookie: &str, body: Value) -> Request<Body> {
    json_request("POST", "/api/v1/sidebar/admin", cookie, body)
}

fn update_request(cookie: &str, id: Uuid, body: Value) -> Request<Body> {
    json_request(
        "PATCH",
        &format!("/api/v1/sidebar/admin/{id}"),
        cookie,
        body,
    )
}

fn deactivate_request(cookie: &str, id: Uuid, row_version: i64) -> Request<Body> {
    json_request(
        "DELETE",
        &format!("/api/v1/sidebar/admin/{id}"),
        cookie,
        json!({ "row_version": row_version }),
    )
}

// ── tree/list search helpers ────────────────────────────────────────────

/// Recursively searches a `GET /api/v1/sidebar/get` response tree (an array
/// of `SidebarItem`, each with an optional `child` array) for a node whose
/// `id` matches.
fn tree_contains_id(nodes: &[Value], id: &str) -> bool {
    nodes.iter().any(|n| {
        n["id"] == id
            || n["child"]
                .as_array()
                .is_some_and(|c| tree_contains_id(c, id))
    })
}

/// Recursively searches a `GET /api/v1/sidebar/get` response tree for a node
/// whose `name` matches.
fn tree_contains_name(nodes: &[Value], name: &str) -> bool {
    nodes.iter().any(|n| {
        n["name"] == name
            || n["child"]
                .as_array()
                .is_some_and(|c| tree_contains_name(c, name))
    })
}

fn find_item(items: &[Value], id: Uuid) -> Option<&Value> {
    let id = id.to_string();
    items.iter().find(|item| item["id"] == id)
}

async fn sidebar_privilege_id(system: &EngineSystem) -> Uuid {
    sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'sidebar.manage'")
        .fetch_one(&system.state().base.db)
        .await
        .expect("sidebar.manage privilege must already be seeded by attome_security::seed")
}

/// Non-admin rejection: every `/api/v1/sidebar/admin*` route calls
/// `ctx.require_key(SIDEBAR_MANAGE_PRIVILEGE_KEY)` before doing anything
/// else — a session without `system.admin` or the `sidebar.manage` grant
/// must never be able to read or mutate the sidebar admin surface.
#[tokio::test]
async fn non_admin_gets_403_on_every_admin_sidebar_route() {
    let system = skip_if_no_db!(test_system().await);
    let (_, non_admin_cookie) = seed_user(&system, false).await;
    let app = full_app(system);

    let list_resp = app
        .clone()
        .oneshot(list_admin_request(&non_admin_cookie))
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::FORBIDDEN);

    let privileges_resp = app
        .clone()
        .oneshot(list_privileges_request(&non_admin_cookie))
        .await
        .unwrap();
    assert_eq!(privileges_resp.status(), StatusCode::FORBIDDEN);

    let create_resp = app
        .clone()
        .oneshot(create_request(
            &non_admin_cookie,
            json!({ "name": "Should Not Be Created", "display_order": 1 }),
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::FORBIDDEN);

    let random_id = Uuid::now_v7();
    let update_resp = app
        .clone()
        .oneshot(update_request(
            &non_admin_cookie,
            random_id,
            json!({ "name": "x", "display_order": 1, "row_version": 0 }),
        ))
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::FORBIDDEN);

    let deactivate_resp = app
        .clone()
        .oneshot(deactivate_request(&non_admin_cookie, random_id, 0))
        .await
        .unwrap();
    assert_eq!(deactivate_resp.status(), StatusCode::FORBIDDEN);
}

/// Contrast case for the test above: `GET /api/v1/sidebar/get` (the live
/// end-user nav tree) does NOT call `require_key` at all — a non-admin
/// session must still get `200` back, just filtered to items it has no
/// privilege gate on. "Sidebar Manager" is tagged with the `sidebar.manage`
/// privilege by `sidebar_seed::seed`'s own `ensure_sidebar_privilege` call,
/// so it must be absent from a non-admin's tree even though the endpoint
/// itself is reachable.
#[tokio::test]
async fn sidebar_get_is_reachable_by_a_non_admin_but_hides_privilege_gated_items() {
    let system = skip_if_no_db!(test_system().await);
    let (_, non_admin_cookie) = seed_user(&system, false).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(sidebar_get_request(&non_admin_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let nodes = body.as_array().expect("sidebar tree must be a JSON array");
    assert!(
        !nodes.is_empty(),
        "the seeded sidebar tree must be non-empty"
    );
    assert!(
        !tree_contains_name(nodes, "Sidebar Manager"),
        "a non-admin session with no sidebar.manage grant must not see the \
         privilege-gated Sidebar Manager link"
    );
}

/// Basic Units P1 follow-up: the governance screens, the state-model editor
/// and the change feed sit behind `system.admin`-only routes, so their seeded
/// rows are linked to `system.admin` — present in an admin's tree, absent
/// from a non-admin's. "My Approvals" is every signed-in user's own inbox and
/// must reach both.
#[tokio::test]
async fn basic_units_rows_are_admin_gated_except_my_approvals() {
    let system = skip_if_no_db!(test_system().await);
    let (_, non_admin_cookie) = seed_user(&system, false).await;
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let admin_only = [
        "Data Quality",
        "Data Catalog",
        "Change Feed",
        "State Models",
        // Web portal admin (Phase 13 step 6): `system.admin`-only routes.
        "Web Portals",
        "Portals",
    ];

    let resp = app
        .clone()
        .oneshot(sidebar_get_request(&admin_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let admin_tree = body_json(resp).await;
    let admin_nodes = admin_tree
        .as_array()
        .expect("sidebar tree must be a JSON array");
    for name in admin_only.iter().chain(std::iter::once(&"My Approvals")) {
        assert!(
            tree_contains_name(admin_nodes, name),
            "an admin's sidebar must list the seeded '{name}' row"
        );
    }

    let resp = app
        .clone()
        .oneshot(sidebar_get_request(&non_admin_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let user_tree = body_json(resp).await;
    let user_nodes = user_tree
        .as_array()
        .expect("sidebar tree must be a JSON array");
    for name in admin_only {
        assert!(
            !tree_contains_name(user_nodes, name),
            "a non-admin must not see the admin-only '{name}' row"
        );
    }
    assert!(
        tree_contains_name(user_nodes, "My Approvals"),
        "every signed-in user must see the My Approvals inbox"
    );
}

/// `sidebar_seed::seed` runs automatically inside `EngineSystemBuilder::build()`
/// and cannot be called directly from this crate's tests (`mod sidebar_seed;`
/// is private in `lib.rs`) — so idempotency is proven the same way any other
/// caller would exercise it: building a second `EngineSystem` against the same
/// database. The total `sidebar` row count must not change between the
/// two builds — a regression here would mean every restart duplicates the
/// built-in navigation tree.
#[tokio::test]
async fn seed_runs_twice_without_duplicating_sidebar_rows() {
    let first_system = skip_if_no_db!(test_system().await);
    let db = first_system.state().base.db.clone();
    let count_after_first: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sidebar")
        .fetch_one(&db)
        .await
        .expect("count sidebar rows after first build");
    drop(first_system);

    let second_system = skip_if_no_db!(test_system().await);
    let count_after_second: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sidebar")
        .fetch_one(&second_system.state().base.db)
        .await
        .expect("count sidebar rows after second build");

    assert_eq!(
        count_after_first, count_after_second,
        "a second EngineSystem build must not insert duplicate sidebar rows \
         (sidebar_seed::seed upserts by name+parent)"
    );
}

/// Full admin round trip: create an item (with a privilege gate assigned),
/// confirm it in the admin list, update it (clearing the privilege gate and
/// renaming/rerouting it), confirm the change persisted, then deactivate it
/// and confirm it disappears from the live `/sidebar/get` tree while still
/// showing up in the admin list — deactivate only ever sets `is_active =
/// false`, never `is_deleted = true`, so `list_sidebar_admin` (which filters
/// only on `is_deleted`) must keep showing it.
#[tokio::test]
async fn admin_create_list_update_deactivate_round_trip() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let privilege_id = sidebar_privilege_id(&system).await;
    let app = full_app(system);

    let create_resp = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({
                "name": "QA Round Trip Item",
                "route": "/qa/round-trip",
                "icon": "las la-flask",
                "color": "#112233",
                "parent_ref": null,
                "display_order": 12345,
                "module_key": "core",
                "privilege_ids": [privilege_id],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let created = body_json(create_resp).await;
    let item_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(created["name"], "QA Round Trip Item");
    assert_eq!(created["route"], "/qa/round-trip");
    assert_eq!(created["module_key"], "core");
    assert_eq!(created["is_active"], true);
    assert_eq!(created["is_disabled"], false);
    assert!(
        created["privilege_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &Value::String(privilege_id.to_string())),
        "the assigned privilege must round-trip in the create response"
    );
    let created_row_version = created["row_version"].as_i64().unwrap();

    let list_resp = app
        .clone()
        .oneshot(list_admin_request(&admin_cookie))
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = body_json(list_resp).await;
    let items = list_body["items"].as_array().unwrap();
    let listed = find_item(items, item_id).expect("created item must appear in the admin list");
    assert_eq!(listed["name"], "QA Round Trip Item");

    let update_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            item_id,
            json!({
                "name": "QA Round Trip Item Updated",
                "route": "/qa/round-trip-updated",
                "icon": "las la-flask",
                "color": "#112233",
                "parent_ref": null,
                "display_order": 12345,
                "is_active": true,
                "is_disabled": false,
                "row_version": created_row_version,
                "module_key": "core",
                "privilege_ids": [],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(update_resp.status(), StatusCode::OK);
    let updated = body_json(update_resp).await;
    assert_eq!(updated["name"], "QA Round Trip Item Updated");
    assert_eq!(updated["route"], "/qa/round-trip-updated");
    assert!(
        updated["privilege_ids"].as_array().unwrap().is_empty(),
        "an update with an empty privilege_ids list must clear the prior grant"
    );
    let updated_row_version = updated["row_version"].as_i64().unwrap();
    assert_eq!(
        updated_row_version,
        created_row_version + 1,
        "a successful update must increment row_version by exactly 1"
    );

    let relisted = body_json(
        app.clone()
            .oneshot(list_admin_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    let relisted_item = find_item(relisted["items"].as_array().unwrap(), item_id)
        .expect("updated item must still appear in the admin list");
    assert_eq!(relisted_item["name"], "QA Round Trip Item Updated");

    let deactivate_resp = app
        .clone()
        .oneshot(deactivate_request(
            &admin_cookie,
            item_id,
            updated_row_version,
        ))
        .await
        .unwrap();
    assert_eq!(deactivate_resp.status(), StatusCode::OK);
    let deactivated_list = body_json(deactivate_resp).await;
    let deactivated_items = deactivated_list
        .as_array()
        .expect("deactivate response must be a plain JSON array, not a paginated envelope");
    let deactivated_item = find_item(deactivated_items, item_id)
        .expect("deactivated item must be in the returned list");
    assert_eq!(deactivated_item["is_active"], false);

    let admin_list_after_deactivate = body_json(
        app.clone()
            .oneshot(list_admin_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    let still_in_admin_list = find_item(
        admin_list_after_deactivate["items"].as_array().unwrap(),
        item_id,
    )
    .expect("a deactivated item must still show in the admin list (only is_deleted is filtered)");
    assert_eq!(still_in_admin_list["is_active"], false);

    let live_tree = body_json(
        app.clone()
            .oneshot(sidebar_get_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !tree_contains_id(live_tree.as_array().unwrap(), &item_id.to_string()),
        "a deactivated item must disappear from the live end-user sidebar tree"
    );
}

/// Create-time field validation: an empty name, a route not beginning with
/// `/`, an unknown `module_key`, and a `parent_ref` pointing at a sidebar
/// item that does not exist must each be rejected `422` before anything is
/// written.
#[tokio::test]
async fn create_rejects_invalid_payloads() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let empty_name = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({ "name": "   ", "display_order": 1 }),
        ))
        .await
        .unwrap();
    assert_eq!(empty_name.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let bad_route = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({ "name": "Bad Route Item", "route": "no-leading-slash", "display_order": 1 }),
        ))
        .await
        .unwrap();
    assert_eq!(bad_route.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let unknown_module = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({
                "name": "Unknown Module Item",
                "display_order": 1,
                "module_key": "not-a-real-module",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(unknown_module.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let missing_parent = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({
                "name": "Orphan Item",
                "display_order": 1,
                "parent_ref": Uuid::now_v7(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(missing_parent.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// `replace_privileges` validates the assigned privilege set itself: a
/// duplicated id in the same request, and an id that doesn't name an
/// existing/active `privilege` row, must both be rejected `422`.
#[tokio::test]
async fn create_rejects_duplicate_and_unknown_privilege_ids() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let privilege_id = sidebar_privilege_id(&system).await;
    let app = full_app(system);

    let duplicate_resp = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({
                "name": "Duplicate Privilege Item",
                "display_order": 1,
                "privilege_ids": [privilege_id, privilege_id],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(duplicate_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let unknown_resp = app
        .clone()
        .oneshot(create_request(
            &admin_cookie,
            json!({
                "name": "Unknown Privilege Item",
                "display_order": 1,
                "privilege_ids": [Uuid::now_v7()],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(unknown_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// Update-time parent validation: an item cannot name itself as its own
/// parent, and cannot be re-parented under one of its own descendants (the
/// `WITH RECURSIVE descendants` cycle check in `update_sidebar_item`).
#[tokio::test]
async fn update_rejects_self_parent_and_parent_cycle() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let parent = body_json(
        app.clone()
            .oneshot(create_request(
                &admin_cookie,
                json!({ "name": "Cycle Test Parent", "display_order": 500001 }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let parent_id: Uuid = parent["id"].as_str().unwrap().parse().unwrap();
    let parent_row_version = parent["row_version"].as_i64().unwrap();

    let child = body_json(
        app.clone()
            .oneshot(create_request(
                &admin_cookie,
                json!({
                    "name": "Cycle Test Child",
                    "display_order": 500002,
                    "parent_ref": parent_id,
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let child_id: Uuid = child["id"].as_str().unwrap().parse().unwrap();

    let self_parent_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            parent_id,
            json!({
                "name": "Cycle Test Parent",
                "display_order": 500001,
                "parent_ref": parent_id,
                "row_version": parent_row_version,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(self_parent_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let cycle_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            parent_id,
            json!({
                "name": "Cycle Test Parent",
                "display_order": 500001,
                "parent_ref": child_id,
                "row_version": parent_row_version,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(
        cycle_resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "re-parenting an item under its own child must be rejected as a cycle"
    );
}

/// Update's optimistic-concurrency contract: a stale `row_version` against
/// an item that genuinely exists is `409 VersionConflict`; a `row_version`
/// against an id that does not exist at all is `404 NotFound` — two
/// different outcomes, not collapsed into one. Also covers the
/// `row_version` field itself being required on update.
#[tokio::test]
async fn update_row_version_conflict_and_missing_row_not_found() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let created = body_json(
        app.clone()
            .oneshot(create_request(
                &admin_cookie,
                json!({ "name": "Version Conflict Item", "display_order": 500101 }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let item_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let original_row_version = created["row_version"].as_i64().unwrap();

    let missing_row_version_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            item_id,
            json!({ "name": "Version Conflict Item", "display_order": 500101 }),
        ))
        .await
        .unwrap();
    assert_eq!(
        missing_row_version_resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "row_version must be required on update"
    );

    // A successful update bumps row_version by 1 — the original value is now stale.
    let first_update_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            item_id,
            json!({
                "name": "Version Conflict Item",
                "display_order": 500101,
                "row_version": original_row_version,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(first_update_resp.status(), StatusCode::OK);

    let stale_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            item_id,
            json!({
                "name": "Version Conflict Item Again",
                "display_order": 500101,
                "row_version": original_row_version,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(stale_resp.status(), StatusCode::CONFLICT);

    let not_found_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            Uuid::now_v7(),
            json!({
                "name": "Does Not Exist",
                "display_order": 1,
                "row_version": 0,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(not_found_resp.status(), StatusCode::NOT_FOUND);
}

/// Deactivate cascades to every descendant via a `WITH RECURSIVE` update —
/// deactivating a parent must also deactivate its children, and the whole
/// subtree must disappear from the live `/sidebar/get` tree while remaining
/// visible (as inactive) in the admin list.
#[tokio::test]
async fn deactivate_cascades_to_children_and_hides_from_live_sidebar() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let parent = body_json(
        app.clone()
            .oneshot(create_request(
                &admin_cookie,
                json!({ "name": "Cascade Parent", "display_order": 500201 }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let parent_id: Uuid = parent["id"].as_str().unwrap().parse().unwrap();
    let parent_row_version = parent["row_version"].as_i64().unwrap();

    let child = body_json(
        app.clone()
            .oneshot(create_request(
                &admin_cookie,
                json!({
                    "name": "Cascade Child",
                    "display_order": 500202,
                    "parent_ref": parent_id,
                    "route": "/cascade/child",
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let child_id: Uuid = child["id"].as_str().unwrap().parse().unwrap();

    let live_tree_before = body_json(
        app.clone()
            .oneshot(sidebar_get_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    assert!(tree_contains_id(
        live_tree_before.as_array().unwrap(),
        &parent_id.to_string()
    ));
    assert!(tree_contains_id(
        live_tree_before.as_array().unwrap(),
        &child_id.to_string()
    ));

    let deactivate_resp = app
        .clone()
        .oneshot(deactivate_request(
            &admin_cookie,
            parent_id,
            parent_row_version,
        ))
        .await
        .unwrap();
    assert_eq!(deactivate_resp.status(), StatusCode::OK);
    let returned = body_json(deactivate_resp).await;
    let returned_items = returned.as_array().unwrap();
    let returned_parent =
        find_item(returned_items, parent_id).expect("parent must be in the returned list");
    let returned_child =
        find_item(returned_items, child_id).expect("child must be in the returned list");
    assert_eq!(returned_parent["is_active"], false);
    assert_eq!(
        returned_child["is_active"], false,
        "deactivating the parent must cascade is_active=false to its children"
    );

    let live_tree_after = body_json(
        app.clone()
            .oneshot(sidebar_get_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    let nodes_after = live_tree_after.as_array().unwrap();
    assert!(!tree_contains_id(nodes_after, &parent_id.to_string()));
    assert!(
        !tree_contains_id(nodes_after, &child_id.to_string()),
        "the cascaded-deactivated child must also disappear from the live tree"
    );

    let admin_list_after = body_json(
        app.clone()
            .oneshot(list_admin_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    let admin_items = admin_list_after["items"].as_array().unwrap();
    assert!(
        find_item(admin_items, parent_id).is_some(),
        "a deactivated parent must still be visible in the admin list"
    );
    assert!(
        find_item(admin_items, child_id).is_some(),
        "a cascade-deactivated child must still be visible in the admin list"
    );
}

/// Unlike `update_sidebar_item`, `deactivate_sidebar_item` never
/// distinguishes "the id doesn't exist" from "the row_version is stale" —
/// both come back `409 VersionConflict`, never `404`. This locks down that
/// (perhaps surprising) behavior so a future change doesn't silently start
/// returning 404s for a nonexistent id without a deliberate decision.
#[tokio::test]
async fn deactivate_conflict_covers_missing_and_stale_row_version() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let created = body_json(
        app.clone()
            .oneshot(create_request(
                &admin_cookie,
                json!({ "name": "Deactivate Conflict Item", "display_order": 500301 }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let item_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let row_version = created["row_version"].as_i64().unwrap();

    let stale_resp = app
        .clone()
        .oneshot(deactivate_request(&admin_cookie, item_id, row_version + 1))
        .await
        .unwrap();
    assert_eq!(stale_resp.status(), StatusCode::CONFLICT);

    let missing_resp = app
        .clone()
        .oneshot(deactivate_request(&admin_cookie, Uuid::now_v7(), 0))
        .await
        .unwrap();
    assert_eq!(
        missing_resp.status(),
        StatusCode::CONFLICT,
        "a nonexistent id must come back 409, not 404, from deactivate"
    );
}

/// `display_order` is an ordinary field on the update endpoint (there is no
/// separate reorder route) — changing it must actually persist and change
/// the admin list's global `ORDER BY display_order, name` result. Uses
/// display_order values far outside the seeded range (900000+) so the three
/// test items sort contiguously regardless of what the built-in seed used.
#[tokio::test]
async fn display_order_change_persists_and_reorders_the_admin_list() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let mut ids = Vec::new();
    for (name, order) in [
        ("Order Test A", 900001),
        ("Order Test B", 900002),
        ("Order Test C", 900003),
    ] {
        let created = body_json(
            app.clone()
                .oneshot(create_request(
                    &admin_cookie,
                    json!({ "name": name, "display_order": order }),
                ))
                .await
                .unwrap(),
        )
        .await;
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let row_version = created["row_version"].as_i64().unwrap();
        ids.push((name.to_string(), id, row_version));
    }

    let ordered_ids = |items: &[Value]| -> Vec<String> {
        let our_ids: Vec<String> = ids.iter().map(|(_, id, _)| id.to_string()).collect();
        items
            .iter()
            .filter_map(|item| item["id"].as_str().map(|s| s.to_string()))
            .filter(|id| our_ids.contains(id))
            .collect()
    };

    let before = body_json(
        app.clone()
            .oneshot(list_admin_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    let before_order = ordered_ids(before["items"].as_array().unwrap());
    assert_eq!(
        before_order,
        vec![
            ids[0].1.to_string(),
            ids[1].1.to_string(),
            ids[2].1.to_string(),
        ],
        "initial admin-list order must follow ascending display_order"
    );

    // Move "Order Test C" to the front by giving it the lowest display_order.
    let c_id = ids[2].1;
    let c_row_version = ids[2].2;
    let reorder_resp = app
        .clone()
        .oneshot(update_request(
            &admin_cookie,
            c_id,
            json!({
                "name": "Order Test C",
                "display_order": 900000,
                "row_version": c_row_version,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(reorder_resp.status(), StatusCode::OK);

    let after = body_json(
        app.clone()
            .oneshot(list_admin_request(&admin_cookie))
            .await
            .unwrap(),
    )
    .await;
    let after_order = ordered_ids(after["items"].as_array().unwrap());
    assert_eq!(
        after_order,
        vec![
            ids[2].1.to_string(),
            ids[0].1.to_string(),
            ids[1].1.to_string(),
        ],
        "after lowering its display_order, the item must sort first in the admin list"
    );
}
