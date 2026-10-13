//! Runtime proof that the admin surface actually rejects an unprivileged
//! principal — the executable counterpart to `route_authz.rs`.
//!
//! `route_authz.rs` proves every mounted route *names* a policy by parsing the
//! source. That is a structural check: it cannot tell you the policy is wired
//! to anything real. This file closes that by driving the fully composed
//! router — the same `ServerBuilder` stack `main.rs` builds — and asserting
//! that every `/api/v1/admin/**` route returns 403 for a real, authenticated,
//! non-admin principal resolved through the real `attome-security` resolver.
//!
//! # Why API-key auth, not a session cookie
//!
//! CSRF rejection (`middleware::csrf`) also returns 403, and it fires on an
//! unsafe method carrying a session cookie without a safe `Sec-Fetch-Site` or
//! allow-listed `Origin`. A cookie-driven version of this test would therefore
//! have passed for the wrong reason on every POST/PATCH/DELETE — a vacuous
//! green. `csrf::should_reject` short-circuits when no session cookie is
//! present, so authenticating with `Authorization: ApiKey <pub>:<secret>`
//! removes that confound entirely: a 403 here can only have come from an
//! authorization policy.
//!
//! The test's second half is the other half of the argument — it proves the
//! same requests are *not* 403 for an admin, so the 403s above are the gate
//! doing its job rather than some ambient rejection.
//!
//! # Running it
//!
//! Requires a live throwaway Postgres (`DATABASE_URL`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`), same convention as
//! `middleware_pipeline.rs` — NEVER point `DATABASE_URL` at `attome_dev`.
//!
//! ```powershell
//! $env:DATABASE_URL  = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p server --test admin_routes_forbid_non_admin -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::path::{Path, PathBuf};

use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use rand::distributions::{Alphanumeric, DistString};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const THROWAWAY_PEPPER: &str = "test-only-throwaway-pepper-32-bytes-min";
const ALLOWED_ORIGIN: &str = "http://allowed.test";

/// A syntactically valid substitution for any `{param}` segment. Every admin
/// path parameter in this codebase is a UUID; a well-formed value that matches
/// no row keeps the request in "authorize, then 404" territory rather than
/// failing path parsing for an unrelated reason.
const PLACEHOLDER: &str = "00000000-0000-7000-8000-000000000000";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 10,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5556, "dbname": "unused_overridden_by_env",
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
                "apikey_hash_pepper": "{pepper}",
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 100000, "authenticated_rpm": 100000 }},
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
            "cors": {{ "allowed_origins": ["{allowed_origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        pepper = THROWAWAY_PEPPER,
        allowed_origin = ALLOWED_ORIGIN,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn test_app(config: AppConfig) -> Option<(axum::Router, AppState)> {
    attome_testkit::migrated_db_url()?;

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
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    let system = attome::boot::register_engines(EngineSystem::builder(state))
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));

    let base_state = system.state().base.clone();
    let license = system.state().modules.clone();
    let auth_bundle = attome_server::RouteBundle::new(
        attome::auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );

    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

/// Creates a throwaway user plus an API key, returning the `Authorization`
/// header value. `admin` grants the reserved `system.admin` privilege.
async fn seed_principal(state: &AppState, admin: bool) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, created_at)
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(user_id)
    .bind(format!("authz-probe-{user_id}"))
    .bind(format!("authz-probe-{user_id}@example.invalid"))
    .execute(&state.db)
    .await
    .expect("insert throwaway user");

    if admin {
        let privilege_id: Uuid = sqlx::query_scalar(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer)
             VALUES ($1, 'system.admin', 'System Admin', 'test', true, NOW(), 'project')
             ON CONFLICT (key) DO UPDATE SET is_active = true
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .fetch_one(&state.db)
        .await
        .expect("ensure system.admin privilege");

        sqlx::query(
            "INSERT INTO user_account_mm_privilege
                 (id, user_ref, privilege_ref, is_active, created_at)
             VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(privilege_id)
        .execute(&state.db)
        .await
        .expect("grant system.admin");
    }

    let public_key = format!(
        "atk_pub_{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
    );
    let secret = format!(
        "atk_sec_{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
    );
    let ring = attome_auth::PepperRing::new(0, THROWAWAY_PEPPER, &[]);
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
         VALUES ($1, 'authz-probe', $2, $3)",
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(ring.hash(&secret))
    .execute(&state.db)
    .await
    .expect("insert throwaway api key");

    format!("ApiKey {public_key}:{secret}")
}

// ── Route discovery (shared shape with route_authz.rs) ──────────────────────

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "target" && name != "tests" {
                rust_sources(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// Every `(METHOD, path)` registered under `/api/v1/admin/`.
fn admin_routes() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_sources(&workspace_root().join("crates"), &mut files);

    let mut out = Vec::new();
    for path in files {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(".route(") {
            let open = from + rel + ".route(".len() - 1;
            from = open + 1;

            let mut depth = 0i32;
            let (mut in_str, mut escaped) = (false, false);
            let mut end = None;
            for (off, c) in src[open..].char_indices() {
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                    continue;
                }
                match c {
                    '"' => in_str = true,
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(open + off);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else { continue };
            let inner = &src[open + 1..end];

            let Some(q1) = inner.find('"') else { continue };
            let Some(q2) = inner[q1 + 1..].find('"') else {
                continue;
            };
            let route_path = &inner[q1 + 1..q1 + 1 + q2];
            if !route_path.starts_with("/api/v1/admin/") {
                continue;
            }

            for (verb, method) in [
                ("get(", "GET"),
                ("post(", "POST"),
                ("put(", "PUT"),
                ("patch(", "PATCH"),
                ("delete(", "DELETE"),
            ] {
                let mut vfrom = 0usize;
                while let Some(vrel) = inner[vfrom..].find(verb) {
                    let vstart = vfrom + vrel;
                    vfrom = vstart + verb.len();
                    if vstart > 0 {
                        let prev = inner[..vstart].chars().next_back().unwrap_or(' ');
                        if prev.is_alphanumeric() || prev == '_' {
                            continue;
                        }
                    }
                    out.push((method.to_string(), route_path.to_string()));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Substitutes `{param}` segments with a well-formed UUID.
fn concrete_path(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        out.push_str(PLACEHOLDER);
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

fn probe(auth: &str, method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", auth)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("build probe request")
}

/// Routes under `/api/v1/admin/` that are deliberately NOT admin-gated.
///
/// `whoami` returns the caller's *own* resolved `SecurityContext` and is typed
/// `Authorized<SelfService>`. It sits under the `/admin/` prefix for historical
/// reasons (D-011 grouped it with the grants surface it was built alongside),
/// not because it exposes anything privileged — the response is exactly the
/// caller's own identity, which they already hold. Path prefix is not the
/// authority on a route's policy; the handler's signature is.
const NON_ADMIN_ROUTES_UNDER_ADMIN_PREFIX: &[(&str, &str)] =
    &[("GET", "/api/v1/admin/security/whoami")];

// ── The test ────────────────────────────────────────────────────────────────

/// Every admin route rejects an authenticated non-admin with 403, and the same
/// routes are reachable for an admin.
///
/// Both halves live in one test deliberately. They share a single
/// `test_app` — `EngineSystem::builder().build()` runs the full boot seed
/// (entity provisioning, privilege seeding, registry pre-warm), and doing that
/// concurrently from two tests against one database made the second boot fail
/// on a statement timeout waiting for the first's locks. One build, two
/// principals.
///
/// The admin half is the control: without it, the 403s prove nothing, because
/// a blanket rejection anywhere in the stack would look identical. It is
/// restricted to `GET` so the control cannot mutate the test database.
#[tokio::test]
async fn admin_routes_forbid_a_non_admin_and_admit_an_admin() {
    let (app, state) = skip_if_no_db!(test_app(test_config()).await);
    let routes = admin_routes();

    assert!(
        routes.len() > 40,
        "only {} admin routes discovered — the parser has stopped matching the \
         codebase and this test would be vacuous",
        routes.len()
    );

    let exempt = |method: &str, path: &str| {
        NON_ADMIN_ROUTES_UNDER_ADMIN_PREFIX
            .iter()
            .any(|(m, p)| *m == method && *p == path)
    };

    // ── Half 1: a non-admin is refused everywhere ───────────────────────
    let non_admin = seed_principal(&state, false).await;
    let mut wrong = Vec::new();
    let mut checked = 0usize;
    for (method, template) in &routes {
        if exempt(method, template) {
            continue;
        }
        checked += 1;
        let res = app
            .clone()
            .oneshot(probe(&non_admin, method, &concrete_path(template)))
            .await
            .expect("request");
        if res.status() != StatusCode::FORBIDDEN {
            wrong.push(format!("  {method:6} {template}  ->  {}", res.status()));
        }
    }

    assert!(
        wrong.is_empty(),
        "\n{} of {checked} admin route(s) did NOT return 403 for an authenticated \
         non-admin principal.\n\n{}\n\nA 401 means the request never resolved a \
         principal (check the API-key seed). Anything else means the route's \
         authorization gate is missing or too weak.\n",
        wrong.len(),
        wrong.join("\n")
    );

    // ── Half 2 (control): an admin is not refused ───────────────────────
    let admin = seed_principal(&state, true).await;
    let mut rejected = Vec::new();
    for (method, template) in routes.iter().filter(|(m, _)| m == "GET") {
        let res = app
            .clone()
            .oneshot(probe(&admin, method, &concrete_path(template)))
            .await
            .expect("request");
        if matches!(
            res.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            rejected.push(format!("  {method:6} {template}  ->  {}", res.status()));
        }
    }

    assert!(
        rejected.is_empty(),
        "\nan admin principal was rejected on {} admin GET route(s) — so the 403s \
         asserted above are NOT proof that authorization works; something is \
         rejecting every caller regardless of privilege.\n\n{}\n",
        rejected.len(),
        rejected.join("\n")
    );
}
