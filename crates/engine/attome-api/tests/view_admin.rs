//! Regression coverage for `view_admin.rs` — the admin surface that manages
//! entity list "views" (`view`, each one binding a display name/icon
//! to an entity plus the `sql_query` row that actually produces its
//! rows). This surface previously had zero dedicated test coverage.
//!
//! Covers:
//! - the admin/non-admin split: `GET/POST /api/v1/admin/views`,
//!   `GET/PATCH/DELETE /api/v1/admin/views/{id}` all `403` for a non-admin
//!   caller, while `GET /api/v1/views?entity=...` (the caller-facing "which
//!   views can I actually run" endpoint) is not admin-gated at all,
//! - `create_view` validation: a blank/whitespace `name` is `422`,
//! - the happy-path create -> response shape (`ViewDetail`) -> a follow-up
//!   `GET` returns the identical row,
//! - the single-default-per-entity invariant `create_view`/`update_view` both
//!   enforce by hand (unsetting `is_default` on every other active view for
//!   the same `entity_logical_name`) — the most important behavior in this
//!   module to regression-test, since it is easy to silently break by
//!   touching only one of the two call sites,
//! - `update_view`/`delete_view` against a nonexistent or already-inactive id
//!   is `404` (`rows_affected() == 0`),
//! - `delete_view` is a soft-deactivate (`is_active=false, is_default=false`):
//!   the row disappears from `list_views`/`get_view` but the row itself is
//!   never removed, and a second delete of the same id is `404`, not a
//!   silent no-op,
//! - `list_available_views`'s privilege filter — and a real finding from
//!   reading `list_available_views` closely rather than trusting a
//!   paraphrase of it: when a view's underlying query has **no**
//!   `required_privilege` set at all, the match arm is
//!   `None => ctx.is_admin`, i.e. a non-admin caller never sees an
//!   unrestricted view through this endpoint — only admins do. That is the
//!   opposite of the intuitive "no privilege required means open to
//!   everyone" reading, so it gets its own explicit assertion below rather
//!   than being assumed away,
//! - `list_available_views`'s org-scoping predicate (a view with a non-null
//!   `organization_ref` is excluded unless the caller is a member of that
//!   org, via `user_account.organization_ref` or
//!   `user_account_mm_organization`),
//! - pagination on `GET /api/v1/admin/views` (`page`/`page_size`) partitions
//!   the result set with no overlap and no gaps.
//!
//! `entity_info`/`sql_query` fixture rows are inserted
//! directly via `sqlx::query(...)` rather than through an admin HTTP
//! endpoint: `POST /api/v1/admin/entities` provisions a full physical entity
//! table with the whole standard column set, and `POST /api/v1/admin/queries`
//! runs a live `EXPLAIN`-based publish-time lint that needs a real queryable
//! relation — neither is worth the extra setup for view_admin's own fixture
//! data, and this repo's convention (see `entity_round_trip.rs`) is that a
//! direct INSERT for fixture setup only, never for the behavior under test,
//! is acceptable. `seed_entity` does still create a one-column stand-in for
//! the physical table, which is not optional — see its doc comment for the
//! cross-suite failure that omitting it caused. The `is_default`
//! single-winner and pagination tests, by
//! contrast, only ever mutate `view` through the real HTTP
//! `view_admin.rs` handlers — that invariant is the actual behavior under
//! test.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `rewrap_admin.rs`/
//! `entity_round_trip.rs`. Tests share one physical database and table
//! (`--test-threads=1`, serial execution) without per-test cleanup, so the
//! pagination test measures its own fixture rows as a *delta* against a
//! measured baseline rather than assuming an exact global row count — see
//! that test's doc comment.
//!
//! **Verified 2026-08-24 (MAINT-10): 11 passed, 0 failed, 254.07s** against a
//! real Postgres and Redis, retiring the "Not run in this session (code-only,
//! no DB/Redis access) — TODO: run against a throwaway database" note this
//! header carried. The **elapsed time** is the evidence, not the `ok`: this
//! suite reports green in ~0.01s when `DATABASE_URL` is absent, so a pass
//! alone does not distinguish a real run from a skipped one.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test view_admin -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::collections::HashSet;
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

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
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

/// Seeds a throwaway `user_account` row (with a unique email — needed
/// so this file's privilege-grant test can look the user up via
/// `POST /api/v1/admin/security/grants`'s `user_email` field) and, when
/// `admin` is true, grants it the `system.admin` privilege the same way
/// `rewrap_admin.rs`/`entity_round_trip.rs` do. Returns `(user_id, email,
/// session_cookie)`.
async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("view-admin-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("view-admin-test-{user_id}"))
    .bind(&email)
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

    (user_id, email, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

// ── Fixtures: entity_info / sql_query rows ────────────────
//
// Inserted directly (not through an admin HTTP endpoint) — see this file's
// header for why. `entity_info.id` has a `uuidv7()` column default
// (migration 0013), so it is left unbound; `sql_query.id` has no
// default (query_admin.rs's own comment on this, "legacy table") and must be
// supplied explicitly.

/// Inserts a throwaway `entity_info` row and returns
/// `(id, logicalname)` — `id` is what `ViewBody.entity_logical_name` (a
/// foreign key into this table, despite its name) expects; `logicalname` is
/// what `list_available_views`'s `?entity=` query string expects instead.
///
/// **Also creates the physical table the row names, and that is load-bearing
/// rather than tidiness.** These fixture rows are never deleted (this suite
/// has no per-test cleanup by design — see the module doc), and they are
/// inserted `is_active = true`, so every one of them is picked up forever
/// afterwards by `attome_metadata::provision::backfill_readonly_grants`, which
/// `EngineSystem::builder().build()` runs on every boot: it selects each active
/// `logicalname` and issues `GRANT SELECT ON <logicalname> TO
/// attome_readonly`. A metadata row with no table behind it therefore
/// poisons the shared test database permanently — the next suite in the run
/// that builds an `EngineSystem` dies at startup with
/// `relation "va_perm_…" does not exist`, nowhere near this file. That is
/// exactly what happened to all 13 of `crates/server/tests/
/// middleware_pipeline.rs`'s tests, which only ever passed because they
/// happened to run before this suite.
///
/// One bare column is enough: `backfill_readonly_grants` only needs the
/// relation to exist to grant on it, and nothing in this suite reads the
/// table's contents. `IF NOT EXISTS` keeps re-runs idempotent.
async fn seed_entity(db: &DbPool, prefix: &str) -> (Uuid, String) {
    // Only the last 12 hex digits of the UUID, not all 32. A full
    // `{prefix}_{simple}` runs to 50 characters for the longer prefixes here
    // ("va_default_create"), and `attome_metadata::provision::MAX_IDENTIFIER_LEN`
    // is 48 — so `backfill_readonly_grants` rejected the name outright on the
    // NEXT boot ("invalid entity logicalname for readonly grant"), which is
    // the same cross-suite poisoning the doc above describes, just reached by
    // a different route than a missing table. UUIDv7's trailing bytes are its
    // random ones, so 12 hex digits is ample for fixture uniqueness.
    let suffix = Uuid::now_v7().simple().to_string();
    let logicalname = format!("{prefix}_{}", &suffix[suffix.len() - 12..]);
    assert!(
        logicalname.len() <= 48,
        "fixture entity name {logicalname:?} exceeds MAX_IDENTIFIER_LEN (48); \
         shorten the prefix"
    );
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO entity_info (logicalname, name, is_active, owner_layer) \
         VALUES ($1, $2, true, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .bind(&logicalname)
    .fetch_one(db)
    .await
    .expect("insert throwaway entity_info fixture row");

    // Interpolated, not bound: PostgreSQL does not accept a bind parameter
    // for a DDL identifier. Safe here because `logicalname` is built two
    // lines up from a caller-supplied literal prefix plus a hyphen-free UUID
    // — no request data reaches this string. The assertion pins that.
    assert!(
        logicalname
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "fixture entity name must be a bare identifier, got {logicalname:?}"
    );
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS \"{logicalname}\" (id uuid PRIMARY KEY)"
    ))
    .execute(db)
    .await
    .expect("create the throwaway entity's physical table");

    (id, logicalname)
}

/// Inserts a throwaway `sql_query` row and returns its id.
/// `table_definition` here is the *query's* legacy `varchar` column
/// (`sql_query.table_definition`, bootstrap schema) — unrelated to
/// `view.table_definition`, which migration 0079 added as its own
/// `JSONB` column; `ViewBody.table_definition` refers to the latter.
async fn seed_query(db: &DbPool, required_privilege: Option<&str>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query \
         (id, sql_query, table_definition, record_no, is_active, required_privilege, created_at, owner_layer) \
         VALUES ($1, $2, $3, $4, true, $5, NOW(), 'project')",
    )
    .bind(id)
    .bind("SELECT 1")
    .bind("[]")
    .bind(format!("view-admin-test-query-{id}"))
    .bind(required_privilege)
    .execute(db)
    .await
    .expect("insert throwaway sql_query fixture row");
    id
}

// ── HTTP request builders ────────────────────────────────────────────────

/// POST/PATCH/DELETE with a cookie session carry `origin`/`sec-fetch-site`
/// headers so `attome_server::middleware::csrf::csrf_protect` treats them as
/// same-origin (its `sec_fetch_site_is_safe` check) — the same fix a real
/// browser request would already carry, matching `rewrap_admin.rs`'s
/// convention, not a bypass of the check.
fn admin_create_req(cookie: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/admin/views")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn admin_list_req(cookie: &str, page: Option<i64>, page_size: Option<i64>) -> Request<Body> {
    let mut uri = "/api/v1/admin/views".to_string();
    let mut params = Vec::new();
    if let Some(p) = page {
        params.push(format!("page={p}"));
    }
    if let Some(ps) = page_size {
        params.push(format!("page_size={ps}"));
    }
    if !params.is_empty() {
        uri.push('?');
        uri.push_str(&params.join("&"));
    }
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

fn admin_get_req(cookie: &str, id: Uuid) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/v1/admin/views/{id}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

fn admin_update_req(cookie: &str, id: Uuid, body: &str) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(format!("/api/v1/admin/views/{id}"))
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn admin_delete_req(cookie: &str, id: Uuid) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/admin/views/{id}"))
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

fn available_views_req(cookie: &str, entity: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/v1/views?entity={entity}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

/// D-429: `POST /api/v1/views` — self-service "save as my view".
fn create_personal_view_req(cookie: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/views")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn share_personal_view_req(cookie: &str, id: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/views/{id}/share"))
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

fn personal_view_body(
    name: &str,
    entity: &str,
    query_id: Uuid,
    kind: &str,
    metadata: Value,
) -> String {
    serde_json::json!({
        "name": name,
        "entity": entity,
        "sql_query_ref": query_id,
        "table_definition": [],
        "kind": kind,
        "view_metadata": metadata,
    })
    .to_string()
}

fn grant_req(admin_cookie: &str, user_email: &str, privilege_key: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/admin/security/grants")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "user_email": user_email, "privilege_key": privilege_key })
                .to_string(),
        ))
        .unwrap()
}

/// Builds a `ViewBody`-shaped JSON payload. `table_definition` is always
/// `[]` here — `ViewBody`'s `#[serde(default)]` would accept an omitted
/// field as JSON `null` instead, but an explicit `[]` keeps the happy-path
/// response assertion unambiguous.
fn view_body(name: &str, entity_id: Uuid, query_id: Uuid, is_default: bool) -> String {
    serde_json::json!({
        "name": name,
        "entity_logical_name": entity_id,
        "sql_query_ref": query_id,
        "table_definition": [],
        "is_default": is_default,
    })
    .to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Wrong-grant rejection: every `/api/v1/admin/views...` route must reject a
/// non-admin session with `403`, while `GET /api/v1/views?entity=...` (the
/// caller-facing endpoint, gated only by ordinary authentication) must
/// succeed for that same non-admin session.
#[test]
fn admin_routes_require_admin_but_available_views_does_not() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, non_admin_cookie) = seed_user(&system, false).await;
        let (entity_id, logicalname) = seed_entity(&db, "va_perm").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let list_resp = app
            .clone()
            .oneshot(admin_list_req(&non_admin_cookie, None, None))
            .await
            .unwrap();
        assert_eq!(list_resp.status(), StatusCode::FORBIDDEN, "GET admin/views");

        let create_resp = app
            .clone()
            .oneshot(admin_create_req(
                &non_admin_cookie,
                &view_body("perm test view", entity_id, query_id, false),
            ))
            .await
            .unwrap();
        assert_eq!(
            create_resp.status(),
            StatusCode::FORBIDDEN,
            "POST admin/views"
        );

        let some_id = Uuid::now_v7();
        let get_resp = app
            .clone()
            .oneshot(admin_get_req(&non_admin_cookie, some_id))
            .await
            .unwrap();
        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "GET admin/views/{{id}}"
        );

        let update_resp = app
            .clone()
            .oneshot(admin_update_req(
                &non_admin_cookie,
                some_id,
                &view_body("x", entity_id, query_id, false),
            ))
            .await
            .unwrap();
        assert_eq!(
            update_resp.status(),
            StatusCode::FORBIDDEN,
            "PATCH admin/views/{{id}}"
        );

        let delete_resp = app
            .clone()
            .oneshot(admin_delete_req(&non_admin_cookie, some_id))
            .await
            .unwrap();
        assert_eq!(
            delete_resp.status(),
            StatusCode::FORBIDDEN,
            "DELETE admin/views/{{id}}"
        );

        // Not admin-gated: a non-admin caller can call the caller-facing
        // endpoint at all (even though, per the required_privilege tests below,
        // which specific views come back is filtered).
        let available_resp = app
            .oneshot(available_views_req(&non_admin_cookie, &logicalname))
            .await
            .unwrap();
        assert_eq!(
            available_resp.status(),
            StatusCode::OK,
            "GET /api/v1/views is not admin-gated"
        );
    })
}

/// `create_view`: a blank/whitespace `name` is rejected `422`, never
/// silently trimmed down to an empty string and persisted.
#[test]
fn create_view_rejects_blank_name() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_blank").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        for blank in ["", "   "] {
            let resp = app
                .clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body(blank, entity_id, query_id, false),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "blank name {blank:?} must be rejected"
            );
        }
    })
}

/// Happy path: `create_view` returns `201` with a `ViewDetail` matching what
/// was sent (plus the joined `entity_name`/`query_name`), and a follow-up
/// `GET` returns the identical row.
#[test]
fn create_view_happy_path_and_get_returns_same_row() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, logicalname) = seed_entity(&db, "va_happy").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let create_resp = app
            .clone()
            .oneshot(admin_create_req(
                &admin_cookie,
                &view_body("Happy Path View", entity_id, query_id, false),
            ))
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let created = body_json(create_resp).await;

        assert_eq!(created["name"], "Happy Path View");
        assert_eq!(created["icon"], "las la-table", "default icon");
        assert_eq!(created["entity_logical_name"], entity_id.to_string());
        assert_eq!(created["entity_name"], logicalname);
        assert_eq!(created["sql_query_ref"], query_id.to_string());
        assert_eq!(
            created["query_name"],
            format!("view-admin-test-query-{query_id}")
        );
        assert_eq!(created["table_definition"], serde_json::json!([]));
        assert_eq!(created["is_default"], false);
        assert_eq!(created["is_active"], true);
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        let get_resp = app.oneshot(admin_get_req(&admin_cookie, id)).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let fetched = body_json(get_resp).await;
        assert_eq!(
            fetched, created,
            "GET must return the identical row create_view returned"
        );
    })
}

/// The single-default-per-entity invariant, `create_view` side: creating a
/// second `is_default: true` view for the same entity must flip the first
/// one's `is_default` back to `false` — never two simultaneous defaults for
/// one entity.
#[test]
fn is_default_single_winner_on_create() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_default_create").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let a_resp = app
            .clone()
            .oneshot(admin_create_req(
                &admin_cookie,
                &view_body("View A", entity_id, query_id, true),
            ))
            .await
            .unwrap();
        assert_eq!(a_resp.status(), StatusCode::CREATED);
        let a = body_json(a_resp).await;
        assert_eq!(a["is_default"], true);
        let a_id: Uuid = a["id"].as_str().unwrap().parse().unwrap();

        let b_resp = app
            .clone()
            .oneshot(admin_create_req(
                &admin_cookie,
                &view_body("View B", entity_id, query_id, true),
            ))
            .await
            .unwrap();
        assert_eq!(b_resp.status(), StatusCode::CREATED);
        let b = body_json(b_resp).await;
        assert_eq!(
            b["is_default"], true,
            "the newly created view is the default"
        );

        let a_refetched = body_json(
            app.oneshot(admin_get_req(&admin_cookie, a_id))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            a_refetched["is_default"], false,
            "creating a new default view for the same entity must unset the previous default"
        );
    })
}

/// The single-default-per-entity invariant, `update_view` side: flipping an
/// existing non-default view to `is_default: true` must unset every OTHER
/// active default view for the same entity — the same invariant as the
/// create-side test above, but exercised through `update_view`'s separate
/// unset query (`... AND id <> $2 ...`, vs. `create_view`'s unconditional
/// unset), which is easy to break independently of the create path.
#[test]
fn is_default_single_winner_on_update() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_default_update").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let b = body_json(
            app.clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body("View B2", entity_id, query_id, true),
                ))
                .await
                .unwrap(),
        )
        .await;
        let b_id: Uuid = b["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(b["is_default"], true);

        let c = body_json(
            app.clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body("View C2", entity_id, query_id, false),
                ))
                .await
                .unwrap(),
        )
        .await;
        let c_id: Uuid = c["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(c["is_default"], false);

        // Flip C to the default via update_view.
        let update_resp = app
            .clone()
            .oneshot(admin_update_req(
                &admin_cookie,
                c_id,
                &view_body("View C2", entity_id, query_id, true),
            ))
            .await
            .unwrap();
        assert_eq!(update_resp.status(), StatusCode::OK);
        let c_updated = body_json(update_resp).await;
        assert_eq!(c_updated["is_default"], true);

        let b_refetched = body_json(
            app.oneshot(admin_get_req(&admin_cookie, b_id))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            b_refetched["is_default"], false,
            "update_view flipping C to default must unset B's default"
        );
    })
}

/// `update_view` against a nonexistent id, and against an id that exists but
/// is already soft-deleted (`is_active = false`), is `404` either way — the
/// handler's `WHERE id=$1 AND is_active=true` clause treats both the same.
#[test]
fn update_view_missing_or_deleted_id_is_404() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_upd404").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let nonexistent_resp = app
            .clone()
            .oneshot(admin_update_req(
                &admin_cookie,
                Uuid::now_v7(),
                &view_body("nope", entity_id, query_id, false),
            ))
            .await
            .unwrap();
        assert_eq!(nonexistent_resp.status(), StatusCode::NOT_FOUND);

        let created = body_json(
            app.clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body("To Be Deleted", entity_id, query_id, false),
                ))
                .await
                .unwrap(),
        )
        .await;
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let delete_resp = app
            .clone()
            .oneshot(admin_delete_req(&admin_cookie, id))
            .await
            .unwrap();
        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        let update_after_delete_resp = app
            .oneshot(admin_update_req(
                &admin_cookie,
                id,
                &view_body("To Be Deleted", entity_id, query_id, false),
            ))
            .await
            .unwrap();
        assert_eq!(
            update_after_delete_resp.status(),
            StatusCode::NOT_FOUND,
            "update_view must not resurrect a soft-deleted view"
        );
    })
}

/// `delete_view` is a soft-deactivate: the row disappears from
/// `list_views`/`get_view` (both filter `is_active = true`) but is never
/// physically removed, and a second delete of the same id is `404`
/// (`rows_affected() == 0`), not a silent no-op.
#[test]
fn delete_view_deactivates_excludes_from_list_and_second_delete_404s() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_delete").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let created = body_json(
            app.clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body("Deletable View", entity_id, query_id, false),
                ))
                .await
                .unwrap(),
        )
        .await;
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        let delete_resp = app
            .clone()
            .oneshot(admin_delete_req(&admin_cookie, id))
            .await
            .unwrap();
        assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

        let get_after_delete = app
            .clone()
            .oneshot(admin_get_req(&admin_cookie, id))
            .await
            .unwrap();
        assert_eq!(
            get_after_delete.status(),
            StatusCode::NOT_FOUND,
            "get_view must filter is_active = true"
        );

        // The row must still physically exist, just inactive — never removed.
        let still_present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM view WHERE id = $1 AND is_active = false)",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .expect("query view directly");
        assert!(
            still_present,
            "delete_view must deactivate, not hard-delete"
        );

        // Paginate through every active row and confirm the deleted id is absent.
        let list_resp = app
            .clone()
            .oneshot(admin_list_req(&admin_cookie, Some(1), Some(200)))
            .await
            .unwrap();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_body = body_json(list_resp).await;
        let ids: HashSet<&str> = list_body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            !ids.contains(id.to_string().as_str()),
            "a deactivated view must not appear in list_views"
        );

        let second_delete_resp = app
            .oneshot(admin_delete_req(&admin_cookie, id))
            .await
            .unwrap();
        assert_eq!(
            second_delete_resp.status(),
            StatusCode::NOT_FOUND,
            "deleting an already-inactive view must be a 404, not a silent no-op"
        );
    })
}

/// `list_available_views`'s privilege filter. Two things are asserted here,
/// the second one a real finding from reading the handler's match arm
/// directly rather than trusting a paraphrase of it (see this file's
/// header):
///
/// - a view whose query's `required_privilege` names a key the caller does
///   NOT hold is excluded for a non-admin caller, included once granted, and
///   always included for an admin caller;
/// - a view whose query has NO `required_privilege` at all
///   (`required_privilege IS NULL`) is excluded for every non-admin caller,
///   regardless of any privilege they hold — `list_available_views`'s
///   `None => ctx.is_admin` arm makes an unrestricted query admin-only
///   through this endpoint, not open to everyone.
#[test]
fn list_available_views_filters_by_required_privilege_admin_sees_everything() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (_, non_admin_email, non_admin_cookie) = seed_user(&system, false).await;
        let (entity_id, logicalname) = seed_entity(&db, "va_priv").await;

        let privilege_key = format!("va-priv-test-{}", Uuid::now_v7().simple());
        let gated_query_id = seed_query(&db, Some(&privilege_key)).await;
        let open_query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let gated_view = body_json(
            app.clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body("Gated View", entity_id, gated_query_id, false),
                ))
                .await
                .unwrap(),
        )
        .await;
        let gated_id = gated_view["id"].as_str().unwrap().to_owned();

        let open_view = body_json(
            app.clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body("Open View", entity_id, open_query_id, false),
                ))
                .await
                .unwrap(),
        )
        .await;
        let open_id = open_view["id"].as_str().unwrap().to_owned();

        // Non-admin, no grant yet: neither view is visible — the gated one
        // because the caller lacks the privilege, the "open" one because of the
        // `None => ctx.is_admin` arm.
        let before_grant = body_json(
            app.clone()
                .oneshot(available_views_req(&non_admin_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let ids_before: HashSet<&str> = before_grant
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            !ids_before.contains(gated_id.as_str()),
            "gated view must be hidden before the grant: {before_grant:?}"
        );
        assert!(
            !ids_before.contains(open_id.as_str()),
            "a view whose query has no required_privilege must be hidden from a \
         non-admin caller too (None => ctx.is_admin): {before_grant:?}"
        );

        let grant_resp = app
            .clone()
            .oneshot(grant_req(&admin_cookie, &non_admin_email, &privilege_key))
            .await
            .unwrap();
        assert_eq!(grant_resp.status(), StatusCode::CREATED);

        let after_grant = body_json(
            app.clone()
                .oneshot(available_views_req(&non_admin_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let ids_after: HashSet<&str> = after_grant
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            ids_after.contains(gated_id.as_str()),
            "gated view must appear once the privilege is granted: {after_grant:?}"
        );
        assert!(
            !ids_after.contains(open_id.as_str()),
            "granting an unrelated privilege must not surface the open (no \
         required_privilege) view for a non-admin caller: {after_grant:?}"
        );

        // Admin caller: is_admin always passes, both views are visible, with no
        // grant needed at all.
        let admin_view = body_json(
            app.oneshot(available_views_req(&admin_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let ids_admin: HashSet<&str> = admin_view
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(ids_admin.contains(gated_id.as_str()));
        assert!(ids_admin.contains(open_id.as_str()));
    })
}

/// `list_available_views`'s org-scoping predicate: a view with a non-null
/// `organization_ref` is excluded unless the caller belongs to that
/// organization, either directly (`user_account.organization_ref`) or
/// via `user_account_mm_organization`. Uses the direct-column path
/// (simpler fixture) since either satisfies the same `OR`-ed SQL predicate.
///
/// The view under test has no `required_privilege` (query created with
/// `None`), so per the finding in the privilege test above a non-admin
/// caller would be excluded by the privilege arm regardless — this test
/// grants that query's (unique, per-test) `required_privilege` to the
/// caller up front so the only remaining variable is org membership.
#[test]
fn list_available_views_excludes_views_scoped_to_a_different_organization() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (caller_id, caller_email, caller_cookie) = seed_user(&system, false).await;
        let (entity_id, logicalname) = seed_entity(&db, "va_org").await;

        let privilege_key = format!("va-org-test-{}", Uuid::now_v7().simple());
        let query_id = seed_query(&db, Some(&privilege_key)).await;
        let app = full_app(system);

        let grant_resp = app
            .clone()
            .oneshot(grant_req(&admin_cookie, &caller_email, &privilege_key))
            .await
            .unwrap();
        assert_eq!(grant_resp.status(), StatusCode::CREATED);

        let other_org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO organization (id, name, is_active) VALUES (gen_random_uuid(), $1, true) RETURNING id",
    )
    .bind(format!("va-org-other-{caller_id}"))
    .fetch_one(&db)
    .await
    .expect("insert throwaway organization");

        let view_id = Uuid::now_v7();
        sqlx::query(
        "INSERT INTO view \
         (id, name, entity_logical_name, sql_query_ref, is_default, is_active, organization_ref, table_definition, created_at, owner_layer) \
         VALUES ($1, $2, $3, $4, false, true, $5, '[]'::jsonb, NOW(), 'project')",
    )
    .bind(view_id)
    .bind("Org Scoped View")
    .bind(entity_id)
    .bind(query_id)
    .bind(other_org_id)
    .execute(&db)
    .await
    .expect("insert throwaway org-scoped view row directly (no admin endpoint takes organization_ref today)");

        let before = body_json(
            app.clone()
                .oneshot(available_views_req(&caller_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let ids_before: HashSet<&str> = before
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            !ids_before.contains(view_id.to_string().as_str()),
            "a view scoped to an org the caller does not belong to must be hidden: {before:?}"
        );

        sqlx::query("UPDATE user_account SET organization_ref = $1 WHERE id = $2")
            .bind(other_org_id)
            .bind(caller_id)
            .execute(&db)
            .await
            .expect("assign caller to the org directly");

        let after = body_json(
            app.oneshot(available_views_req(&caller_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let ids_after: HashSet<&str> = after
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            ids_after.contains(view_id.to_string().as_str()),
            "once the caller belongs to the view's org, it must appear: {after:?}"
        );
    })
}

/// Pagination on `GET /api/v1/admin/views` partitions the full active-row
/// set with no overlap and no gaps.
///
/// `list_views` has no entity/caller filter — it's a flat global list — and
/// this file's tests all share one physical database/table with
/// `--test-threads=1` and no per-test cleanup, so an earlier test's views
/// are still present when this one runs. Asserting an exact "page_size=2 ->
/// exactly 2 items" against a hardcoded total would be fragile against test
/// order/count changes elsewhere in this file. Instead this measures a
/// baseline total via a direct COUNT, adds exactly 3 fresh fixture rows, and
/// then proves LIMIT/OFFSET correctness against the new (measured, not
/// assumed) total: page 1 with `page_size = total - 1` must return exactly
/// `total - 1` rows, page 2 with the same `page_size` must return exactly
/// the 1 remaining row, and the two pages' ids must be disjoint and together
/// cover every id `list_views` reports (including the 3 just-created ones).
#[test]
fn admin_list_views_pagination_partitions_without_overlap() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_page").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let mut created_ids = Vec::new();
        for i in 0..3 {
            let created = body_json(
                app.clone()
                    .oneshot(admin_create_req(
                        &admin_cookie,
                        &view_body(&format!("Page Test View {i}"), entity_id, query_id, false),
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            created_ids.push(created["id"].as_str().unwrap().to_owned());
        }

        // Walk every page at a fixed, modest size instead of asking for
        // `total - 1` in one request.
        //
        // The old shape measured `baseline + 3` and asserted it fit under
        // `MAX_PAGE_SIZE`, which made the test's premise decay with use: this
        // suite leaves its 3 active `view` fixtures behind on every run
        // against the shared throwaway database, so the baseline climbs 3 per run
        // until the guard trips. It did — `test fixture total (535) exceeds
        // MAX_PAGE_SIZE (200)` on the rerun. The guard was well built (it failed
        // loudly and named the reason rather than silently clamping), but a test
        // whose premise is "the whole table fits in one page" is not hermetic on
        // a database that accumulates. Paging through proves the same
        // LIMIT/OFFSET property and gets stronger, not weaker, as the table grows
        // — it now spans many page boundaries instead of exactly one
        // (F-006/TODO-008).
        const PAGE_SIZE: i64 = 50;
        let mut seen: HashSet<String> = HashSet::new();
        let mut duplicates: Vec<String> = Vec::new();
        let mut pages_walked = 0;

        for page in 1.. {
            let body = body_json(
                app.clone()
                    .oneshot(admin_list_req(&admin_cookie, Some(page), Some(PAGE_SIZE)))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(body["page_size"], PAGE_SIZE);
            let items = body["items"].as_array().unwrap();
            for item in items {
                let id = item["id"].as_str().unwrap().to_owned();
                if !seen.insert(id.clone()) {
                    duplicates.push(id);
                }
            }
            pages_walked += 1;
            if (items.len() as i64) < PAGE_SIZE {
                break;
            }
            assert!(
                pages_walked < 500,
                "list_views never returned a short page — pagination is not terminating"
            );
        }

        assert!(
            duplicates.is_empty(),
            "adjacent pages must partition without overlap; these ids appeared \
         on more than one page: {duplicates:?}"
        );
        for id in &created_ids {
            assert!(
                seen.contains(id.as_str()),
                "fixture view {id} missing from the paged walk ({} ids over {pages_walked} pages)",
                seen.len()
            );
        }
        // Deliberately not asserting `seen.len() == total`: `total` is recomputed
        // per request, and a sibling test creating a view mid-walk would shift it.
        // No-overlap plus every fixture present is the claim this test owns.
    })
}

/// Pins the *page base* of this list: one-based (D-793).
///
/// `admin_list_views_pagination_partitions_without_overlap` above proves the
/// windows partition, but it cannot tell which page number is the first one.
/// This test asserts the thing that walk cannot: that `page=1` is the *first*
/// page, that `page=2` is the next window, that omitting `page` means 1, and
/// that `page=0` is clamped up to the first page (echoed as 1) rather than
/// served as a page of its own.
#[test]
fn admin_list_views_page_base_is_one() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_base").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        // Two fresh rows guarantee the table holds at least two, so `page_size=1`
        // makes page 1 and page 2 genuinely distinct windows.
        for i in 0..2 {
            let resp = app
                .clone()
                .oneshot(admin_create_req(
                    &admin_cookie,
                    &view_body(&format!("Base Test View {i}"), entity_id, query_id, false),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let page_at = |p: Option<i64>| {
            let app = app.clone();
            let cookie = admin_cookie.clone();
            async move {
                body_json(
                    app.oneshot(admin_list_req(&cookie, p, Some(1)))
                        .await
                        .unwrap(),
                )
                .await
            }
        };

        let p0 = page_at(Some(0)).await;
        let p1 = page_at(Some(1)).await;
        let p2 = page_at(Some(2)).await;
        let dflt = page_at(None).await;

        assert_eq!(p1["page"], 1, "one-based: page 1 is the first page");
        assert_eq!(p2["page"], 2);
        assert_eq!(
            dflt["page"], 1,
            "omitting `page` must mean the first page, 1"
        );
        assert_eq!(
            p0["page"], 1,
            "page 0 must be clamped up to the first page, 1"
        );

        assert_eq!(p1["items"].as_array().unwrap().len(), 1);
        assert_eq!(p2["items"].as_array().unwrap().len(), 1);
        assert_ne!(
            p1["items"][0]["id"], p2["items"][0]["id"],
            "page 1 and page 2 must be different windows — if they match, offset \
         is not (page - 1) * page_size"
        );
        assert_eq!(
            dflt["items"][0]["id"], p1["items"][0]["id"],
            "the default page must be the same window as page 1"
        );
        assert_eq!(
            p0["items"][0]["id"], p1["items"][0]["id"],
            "page 0 must serve the same window as page 1"
        );
    })
}

// ── D-429: personal views, kinds, sharing ───────────────────────────────────

/// A personal view (`POST /api/v1/views`) is visible to its owner via
/// `GET /api/v1/views?entity=...` and completely invisible to a second,
/// unrelated user — even one holding the underlying query's
/// `required_privilege` — because `scope = 'personal'` bypasses the
/// privilege gate entirely and is owner-only (D-429).
#[test]
fn personal_view_is_invisible_to_another_user() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (owner_id, owner_email, owner_cookie) = seed_user(&system, false).await;
        let (_, other_email, other_cookie) = seed_user(&system, false).await;
        let (_entity_id, logicalname) = seed_entity(&db, "va_mine").await;

        let privilege_key = format!("va-mine-test-{}", Uuid::now_v7().simple());
        let query_id = seed_query(&db, Some(&privilege_key)).await;
        let app = full_app(system);

        // Both the owner and the other user hold the query's privilege — proves
        // the exclusion below is scope-based, not a privilege gap.
        for email in [&owner_email, &other_email] {
            let resp = app
                .clone()
                .oneshot(grant_req(&admin_cookie, email, &privilege_key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED, "grant to {email}");
        }

        let create_resp = app
            .clone()
            .oneshot(create_personal_view_req(
                &owner_cookie,
                &personal_view_body(
                    "My Pipeline",
                    &logicalname,
                    query_id,
                    "list",
                    serde_json::json!({}),
                ),
            ))
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let created = body_json(create_resp).await;
        assert_eq!(created["scope"], "personal");
        assert_eq!(created["owner_ref"], owner_id.to_string());
        let view_id = created["id"].as_str().unwrap().to_owned();

        let owner_view = body_json(
            app.clone()
                .oneshot(available_views_req(&owner_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let owner_ids: HashSet<&str> = owner_view
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            owner_ids.contains(view_id.as_str()),
            "the owner must see their own personal view: {owner_view:?}"
        );

        let other_view = body_json(
            app.oneshot(available_views_req(&other_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        let other_ids: HashSet<&str> = other_view
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(
            !other_ids.contains(view_id.as_str()),
            "a personal view must be invisible to another user, even one holding \
         the same query privilege: {other_view:?}"
        );
    })
}

/// `POST /api/v1/views/{id}/share` promotes a personal view to `shared`,
/// which (a) makes it visible to any caller who holds the underlying
/// query's `required_privilege` — not just the owner — and (b) writes an
/// audited `PermissionChange`/`view_shared` row to `audit_header`.
#[test]
fn sharing_a_personal_view_is_visible_to_others_and_audited() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (owner_id, owner_email, owner_cookie) = seed_user(&system, false).await;
        let (_, other_email, other_cookie) = seed_user(&system, false).await;
        let (_entity_id, logicalname) = seed_entity(&db, "va_share").await;

        let privilege_key = format!("va-share-test-{}", Uuid::now_v7().simple());
        let query_id = seed_query(&db, Some(&privilege_key)).await;
        let app = full_app(system);

        for email in [&owner_email, &other_email] {
            let resp = app
                .clone()
                .oneshot(grant_req(&admin_cookie, email, &privilege_key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED, "grant to {email}");
        }

        let created = body_json(
            app.clone()
                .oneshot(create_personal_view_req(
                    &owner_cookie,
                    &personal_view_body(
                        "Team Pipeline",
                        &logicalname,
                        query_id,
                        "list",
                        serde_json::json!({}),
                    ),
                ))
                .await
                .unwrap(),
        )
        .await;
        let view_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        // Not shared yet: the other privileged user cannot see it.
        let before = body_json(
            app.clone()
                .oneshot(available_views_req(&other_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            !before
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["id"] == view_id.to_string()),
            "must not be visible before sharing: {before:?}"
        );

        // Only the owner may share it.
        let forbidden_share = app
            .clone()
            .oneshot(share_personal_view_req(&other_cookie, view_id))
            .await
            .unwrap();
        assert_eq!(
            forbidden_share.status(),
            StatusCode::NOT_FOUND,
            "share must scope by owner_ref -- a non-owner gets the same 404 as a \
         nonexistent id, not a 403 that would confirm the id exists"
        );

        let share_resp = app
            .clone()
            .oneshot(share_personal_view_req(&owner_cookie, view_id))
            .await
            .unwrap();
        assert_eq!(share_resp.status(), StatusCode::OK);
        let shared = body_json(share_resp).await;
        assert_eq!(shared["scope"], "shared");
        assert_eq!(
            shared["owner_ref"],
            owner_id.to_string(),
            "owner_ref is preserved as provenance after sharing"
        );

        // Now visible to the other privileged user through the normal
        // required_privilege gate, same as a system view.
        let after = body_json(
            app.oneshot(available_views_req(&other_cookie, &logicalname))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            after
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["id"] == view_id.to_string()),
            "a shared view must be visible to another privileged caller: {after:?}"
        );

        // Audited: a PermissionChange row with event_name = 'view_shared' and
        // record_id = the view's id. `AuditService::write_in_tx` routes through
        // `audit_ingest` (JSONB payload) rather than the synchronous
        // `audit_header` path whenever `audit.chainer_enabled` is true —
        // this test harness's `test_config()` omits the `audit` section
        // entirely, so `AppConfig`'s D-316 code default (chainer_enabled: true)
        // applies, and that is the path this assertion checks.
        let (record_id, event_name, operation): (Option<String>, Option<String>, Option<String>) =
            sqlx::query_as(
                "SELECT payload->>'record_id', payload->>'event_name', payload->>'operation' \
             FROM audit_ingest \
             WHERE payload->>'event_name' = 'view_shared' AND payload->>'record_id' = $1",
            )
            .bind(view_id.to_string())
            .fetch_one(&db)
            .await
            .expect("promoting to shared must write an audit event");
        assert_eq!(record_id.as_deref(), Some(view_id.to_string().as_str()));
        assert_eq!(event_name.as_deref(), Some("view_shared"));
        assert_eq!(
            operation.as_deref(),
            Some("PermissionChange"),
            "operation: {operation:?}"
        );
    })
}

/// `create_personal_view` never grants new data access: a caller who does
/// NOT hold the underlying query's `required_privilege` cannot "save as my
/// view" against it, `403`.
#[test]
fn create_personal_view_requires_query_access() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, caller_cookie) = seed_user(&system, false).await;
        let (_entity_id, logicalname) = seed_entity(&db, "va_noaccess").await;
        let privilege_key = format!("va-noaccess-test-{}", Uuid::now_v7().simple());
        let query_id = seed_query(&db, Some(&privilege_key)).await;
        let app = full_app(system);

        let resp = app
            .oneshot(create_personal_view_req(
                &caller_cookie,
                &personal_view_body(
                    "Cannot Have This",
                    &logicalname,
                    query_id,
                    "list",
                    serde_json::json!({}),
                ),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    })
}

/// `kind`/`view_metadata` validation (D-429): a `kanban` view requires
/// `state_field`; a `calendar` view requires `start_field`/`end_field`.
/// Exercised through the admin surface (simpler fixture — no query privilege
/// dance needed) since both admin and self-service creation share the same
/// `validate_view_kind_metadata` function.
#[test]
fn kind_metadata_validation_rejects_missing_required_keys() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_kind").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let kanban_missing_state_field = serde_json::json!({
            "name": "Bad Kanban",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "kanban",
            "view_metadata": {},
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &kanban_missing_state_field))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let calendar_missing_end_field = serde_json::json!({
            "name": "Bad Calendar",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "calendar",
            "view_metadata": { "start_field": "start_date" },
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &calendar_missing_end_field))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // The happy path for both, proving the validation is exact (rejects only
        // what's actually missing) rather than accidentally rejecting everything.
        let good_kanban = serde_json::json!({
            "name": "Good Kanban",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "kanban",
            "view_metadata": { "state_field": "status", "wip_limits": { "in_progress": 5 } },
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &good_kanban))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let good_calendar = serde_json::json!({
        "name": "Good Calendar",
        "entity_logical_name": entity_id,
        "sql_query_ref": query_id,
        "table_definition": [],
        "kind": "calendar",
        "view_metadata": { "start_field": "start_date", "end_field": "end_date", "color_field": "priority" },
    })
    .to_string();
        let resp = app
            .oneshot(admin_create_req(&admin_cookie, &good_calendar))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    })
}

/// `kind = "chart"` (migration 0447 follow-up to D-429) delegates to
/// `chart_view_metadata::validate` — a stricter, closed-schema validator than
/// kanban/calendar's few `non_empty_string` checks (see that module's doc
/// comment). Exercised the same way as the kanban/calendar cases above: an
/// invalid config (unknown `chart_type`) is rejected, a well-formed one is
/// accepted.
#[test]
fn kind_metadata_validation_covers_chart() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_kind_chart").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let bad_chart_type = serde_json::json!({
            "name": "Bad Chart",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "chart",
            "view_metadata": {
                "chart_type": "waffle",
                "x_field": "created_on",
                "y_fields": [{ "field": "amount", "aggregation": "sum", "label": "Amount" }],
            },
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &bad_chart_type))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // An empty `y_fields`/`x_field` is a "not configured yet" chart, not an
        // error — exactly the shape `WidgetInspectorComponent`'s "Create Chart"
        // flow creates a view with before an admin has picked any settings
        // (`chart_view_metadata::validate`'s own doc comment: every create/
        // update of a `kind = chart` view must pass this validator, unlike
        // `declarative_widget`'s opt-in one, so a brand-new view's `{}` must
        // itself be accepted).
        let not_yet_configured = serde_json::json!({
            "name": "Not Yet Configured Chart",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "chart",
            "view_metadata": {},
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &not_yet_configured))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let too_many_y_fields = serde_json::json!({
        "name": "Too Many Y Fields",
        "entity_logical_name": entity_id,
        "sql_query_ref": query_id,
        "table_definition": [],
        "kind": "chart",
        "view_metadata": {
            "chart_type": "line",
            "x_field": "created_on",
            "y_fields": std::iter::repeat_n(
                serde_json::json!({ "field": "amount", "aggregation": "sum", "label": "Amount" }),
                9,
            ).collect::<Vec<_>>(),
        },
    })
    .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &too_many_y_fields))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let good_chart = serde_json::json!({
        "name": "Good Chart",
        "entity_logical_name": entity_id,
        "sql_query_ref": query_id,
        "table_definition": [],
        "kind": "chart",
        "view_metadata": {
            "chart_type": "line",
            "x_field": "created_on",
            "x_bucket": "month",
            "y_fields": [{ "field": "amount", "aggregation": "sum", "label": "Amount", "color": "#22c55e" }],
            "sort": "x_asc",
            "show_legend": true,
        },
    })
    .to_string();
        let resp = app
            .oneshot(admin_create_req(&admin_cookie, &good_chart))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    })
}

/// B15-T2: `kind = "map"` needs a `location_field`; `label_field` and
/// `color_field` are optional names. The kind passes the table's CHECK
/// (migration 0332).
#[test]
fn kind_metadata_validation_covers_map() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let (entity_id, _) = seed_entity(&db, "va_kind_map").await;
        let query_id = seed_query(&db, None).await;
        let app = full_app(system);

        let missing_location = serde_json::json!({
            "name": "Bad Map",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "map",
            "view_metadata": { "label_field": "name" },
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(admin_create_req(&admin_cookie, &missing_location))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let good_map = serde_json::json!({
            "name": "Good Map",
            "entity_logical_name": entity_id,
            "sql_query_ref": query_id,
            "table_definition": [],
            "kind": "map",
            "view_metadata": { "location_field": "location", "label_field": "name", "color_field": null },
        })
        .to_string();
        let resp = app
            .oneshot(admin_create_req(&admin_cookie, &good_map))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    })
}
