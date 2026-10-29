//! Q4-T1: signing in with a directory account through the assembled HTTP
//! stack, against a real directory over LDAPS.
//!
//! A directory person signs in, gets an Attome account and the role their
//! group maps to, and loses that role (only that one) once the group no
//! longer lists them. A wrong password is a 401 with a `FailedLogin` event,
//! and a deployment without `auth.ldap` answers 404.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database), Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) and the throwaway directory
//! `attome-auth`'s `tests/ldap_directory.rs` describes (`TEST_LDAP_URL`,
//! `TEST_LDAP_CA_FILE`, `TEST_LDAP_ADMIN_PASSWORD`). Skips cleanly when
//! `DATABASE_URL` or `TEST_LDAP_URL` is unset.
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome --test ldap_http -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashSet;

use attome::auth;
use attome_api::EngineSystem;
use attome_config::{AppConfig, LdapSection};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ldap3::{LdapConnAsync, LdapConnSettings, Mod};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "ldap-http-password-1";
const SESSION_COOKIE: &str = "__Host-session_token";
const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4096, "request_timeout_secs": 5,
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
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000
            }},
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
        allowed_origin = ALLOWED_ORIGIN,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// The full `main.rs` stack around both auth bundles.
async fn test_app(ldap: Option<LdapSection>) -> Option<(axum::Router, AppState)> {
    let mut config = test_config();
    config.auth.ldap = ldap;
    let throwaway_url = attome_testkit::migrated_db_url()?;
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
        config.clone(),
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

    let base_state = system.state().base.clone();
    let license = system.state().modules.clone();
    let public_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );
    let protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(attome_audit::security::SecurityAuditor::from_state(
            system.state(),
        ))
        .with_state(base_state.clone()),
    );

    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

fn cookie_value(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<String>,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ALLOWED_ORIGIN)
        .header(header::USER_AGENT, BROWSER);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let body = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .expect("request")
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

/// Mandatory events of `category`/`operation` written so far.
async fn events(state: &AppState, category: &str, operation: &str) -> i64 {
    let c: attome_audit::AuditCategory =
        serde_json::from_value(serde_json::json!(category)).expect("known category");
    let o: attome_audit::AuditOperation =
        serde_json::from_value(serde_json::json!(operation)).expect("known operation");
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE category = $1 AND operation = $2) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'category' = $3 AND payload->>'operation' = $4)",
    )
    .bind(c as i32)
    .bind(o as i32)
    .bind(category)
    .bind(operation)
    .fetch_one(&state.db)
    .await
    .expect("count audit events")
}

/// The throwaway directory, from the environment.
struct Directory {
    url: String,
    ca_file: String,
    admin_dn: String,
    admin_password: String,
    base_dn: String,
}

fn directory() -> Option<Directory> {
    let url = std::env::var("TEST_LDAP_URL").ok()?;
    Some(Directory {
        url,
        ca_file: std::env::var("TEST_LDAP_CA_FILE").expect("TEST_LDAP_CA_FILE"),
        admin_dn: std::env::var("TEST_LDAP_ADMIN_DN")
            .unwrap_or_else(|_| "cn=admin,dc=example,dc=test".to_owned()),
        admin_password: std::env::var("TEST_LDAP_ADMIN_PASSWORD")
            .expect("TEST_LDAP_ADMIN_PASSWORD"),
        base_dn: std::env::var("TEST_LDAP_BASE_DN")
            .unwrap_or_else(|_| "dc=example,dc=test".to_owned()),
    })
}

macro_rules! directory_or_skip {
    () => {
        match directory() {
            Some(directory) => directory,
            None => {
                eprintln!("TEST_LDAP_URL is not set; skipping");
                return;
            }
        }
    };
}

/// `auth.ldap` for `directory`, mapping `group` to the role `role`.
fn section(directory: &Directory, group: &str, role: &str) -> LdapSection {
    serde_json::from_value(serde_json::json!({
        "url": directory.url,
        "ca_file": directory.ca_file,
        "bind_dn": directory.admin_dn,
        "bind_password": directory.admin_password,
        "base_dn": directory.base_dn,
        "user_filter": "(uid={username})",
        "timeout_secs": 5,
        "group_roles": [{ "group": group, "role": role }],
    }))
    .expect("an ldap section")
}

/// An administrator's connection to the directory.
async fn admin(directory: &Directory) -> ldap3::Ldap {
    let probe = section(directory, "cn=none", "none");
    let tls = attome_auth::ldap::Directory::load(&probe)
        .await
        .expect("directory settings")
        .tls_config_for_tests();
    let (conn, mut ldap) =
        LdapConnAsync::with_settings(LdapConnSettings::new().set_config(tls), &directory.url)
            .await
            .expect("connect to the directory");
    tokio::spawn(async move { conn.drive().await });
    ldap.simple_bind(&directory.admin_dn, &directory.admin_password)
        .await
        .expect("admin bind")
        .success()
        .expect("admin bind accepted");
    ldap
}

struct Person {
    uid: String,
    dn: String,
    email: String,
    group: String,
}

/// A person with [`PASSWORD`] and a group listing them, named for one test.
async fn seed_person(directory: &Directory) -> Person {
    let tag = Uuid::now_v7().simple().to_string();
    let uid = format!("ldap-http-{tag}");
    let dn = format!("uid={uid},{}", directory.base_dn);
    let email = format!("{uid}@example.test");
    let group = format!("cn=sales-{tag},{}", directory.base_dn);
    let mut ldap = admin(directory).await;
    ldap.add(
        &dn,
        vec![
            ("objectClass", HashSet::from(["inetOrgPerson"])),
            ("uid", HashSet::from([uid.as_str()])),
            ("cn", HashSet::from([uid.as_str()])),
            ("sn", HashSet::from(["Test"])),
            ("mail", HashSet::from([email.as_str()])),
            ("userPassword", HashSet::from([PASSWORD])),
        ],
    )
    .await
    .expect("add person")
    .success()
    .expect("person added");
    let cn = format!("sales-{tag}");
    ldap.add(
        &group,
        vec![
            ("objectClass", HashSet::from(["groupOfUniqueNames"])),
            ("cn", HashSet::from([cn.as_str()])),
            ("uniqueMember", HashSet::from([dn.as_str()])),
        ],
    )
    .await
    .expect("add group")
    .success()
    .expect("group added");
    let _ = ldap.unbind().await;
    Person {
        uid,
        dn,
        email,
        group,
    }
}

/// A new customer role called `name`.
async fn seed_role(state: &AppState, name: &str) -> Uuid {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'customer')")
        .bind(role)
        .bind(name)
        .execute(&state.db)
        .await
        .expect("insert a role");
    role
}

async fn ldap_login(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> axum::response::Response {
    send(
        app,
        "POST",
        "/api/v1/auth/ldap/login",
        None,
        Some(serde_json::json!({ "username": username, "password": password })),
    )
    .await
}

/// The live roles of `user_id`, with whether the directory gave each.
async fn roles_of(state: &AppState, user_id: Uuid) -> Vec<(Uuid, bool)> {
    sqlx::query_as(
        "SELECT role_ref, source_directory FROM user_account_mm_role \
          WHERE user_ref = $1 AND NOT is_deleted ORDER BY role_ref",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .expect("read roles")
}

async fn user_by_email(state: &AppState, email: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM user_account WHERE email = $1 AND is_active")
        .bind(email)
        .fetch_one(&state.db)
        .await
        .expect("the account the directory sign-in created")
}

#[tokio::test]
async fn q4_a_directory_person_signs_in_and_gets_roles_from_groups() {
    let directory = directory_or_skip!();
    let person = seed_person(&directory).await;
    let role_name = format!("ldap-http-{}", Uuid::now_v7());
    let (app, state) = skip_if_no_db!(
        test_app(Some(section(
            &directory,
            &person.group.to_uppercase(),
            &role_name
        )))
        .await
    );
    let role = seed_role(&state, &role_name).await;

    let logins = events(&state, "Security", "Login").await;
    let grants = events(&state, "Access", "Grant").await;
    let res = ldap_login(&app, &person.uid, PASSWORD).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the directory signs the person in"
    );
    assert!(
        cookie_value(&res, SESSION_COOKIE).is_some(),
        "a session cookie"
    );
    let user_id = user_by_email(&state, &person.email).await;
    assert_eq!(json_of(res).await["user_id"], user_id.to_string());
    assert_eq!(roles_of(&state, user_id).await, vec![(role, true)]);
    assert_eq!(events(&state, "Security", "Login").await, logins + 1);
    assert_eq!(events(&state, "Access", "Grant").await, grants + 1);
    let linked: String = sqlx::query_scalar(
        "SELECT provider_sub FROM user_identity WHERE user_ref = $1 AND provider_key = 'ldap'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .expect("the directory link");
    assert_eq!(linked, person.dn.to_lowercase());

    // An administrator also gives a role of their own.
    let own_role = seed_role(&state, &format!("ldap-http-{}", Uuid::now_v7())).await;
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(own_role)
        .execute(&state.db)
        .await
        .expect("grant a role");

    // Signing in again changes nothing.
    let res = ldap_login(&app, &person.uid, PASSWORD).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(events(&state, "Access", "Grant").await, grants + 1);

    // The group no longer lists them: the directory's role goes, the
    // administrator's stays.
    let mut ldap = admin(&directory).await;
    ldap.modify(
        &person.group,
        vec![Mod::Add(
            "uniqueMember",
            HashSet::from([directory.admin_dn.as_str()]),
        )],
    )
    .await
    .expect("add another member")
    .success()
    .expect("member added");
    ldap.modify(
        &person.group,
        vec![Mod::Delete(
            "uniqueMember",
            HashSet::from([person.dn.as_str()]),
        )],
    )
    .await
    .expect("remove the person")
    .success()
    .expect("person removed");
    let _ = ldap.unbind().await;
    let revokes = events(&state, "Access", "Revoke").await;
    let res = ldap_login(&app, &person.uid, PASSWORD).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(roles_of(&state, user_id).await, vec![(own_role, false)]);
    assert_eq!(events(&state, "Access", "Revoke").await, revokes + 1);
}

#[tokio::test]
async fn q4_a_wrong_password_is_a_failed_login_and_no_account() {
    let directory = directory_or_skip!();
    let person = seed_person(&directory).await;
    let (app, state) =
        skip_if_no_db!(test_app(Some(section(&directory, &person.group, "none"))).await);
    let failed = events(&state, "Security", "FailedLogin").await;
    let res = ldap_login(&app, &person.uid, "not-the-password").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(events(&state, "Security", "FailedLogin").await, failed + 1);
    let created: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_account WHERE email = $1)")
            .bind(&person.email)
            .fetch_one(&state.db)
            .await
            .expect("read accounts");
    assert!(!created, "a refused sign-in creates no account");

    let res = ldap_login(&app, "*", PASSWORD).await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "a wildcard names no one"
    );
}

#[tokio::test]
async fn q4_without_a_directory_the_route_is_not_found() {
    let (app, _) = skip_if_no_db!(test_app(None).await);
    let res = ldap_login(&app, "anyone", "anything").await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
