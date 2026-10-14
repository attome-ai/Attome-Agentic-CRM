//! Solution 7 Phase 1 (D-785) — the done-when tests of plan items 1.2 and
//! 1.7, lane L7 (design `document/general/SOLUTION-7-PHASE-1-DESIGN.md` §4,
//! §6, §8).
//!
//! 1. `every_admin_change_yields_exactly_one_op_in_order` — in `required`
//!    mode, one open changeset, a feature built across the three hook groups
//!    (schema, UI metadata, engines) through the real admin routes: every
//!    request adds exactly one operation, `seq` runs 1..N in request order,
//!    close returns a document whose operations are in that same order, and
//!    adopt records it in the ledger with its Configuration/Import audit
//!    event (the D-542 emission proof for `…/metadata/changesets/adopt`, which
//!    `crates/server/tests/audit_coverage_emission.rs` cannot drive: it runs
//!    in `auto` mode).
//! 2. `a_closed_changeset_replays_onto_an_empty_database_with_the_same_result`
//!    — the same kind of feature, closed, then planned and applied
//!    (`source = 'replay'`) onto a brand-new database migrated from scratch:
//!    every object the changeset touched exports identically on both
//!    (`is_customized` normalised away, design §6), and is stamped with the
//!    changeset's layer. The whole-deployment replay is
//!    `crates/server/src/bin/changeset_replay.rs`.
//!
//! "A write with no open changeset is refused in `required` mode" is proved
//! per route group by `changeset_hooks_{schema,ui,engines}.rs`
//! (`required_mode_*`); not repeated here.
//!
//! Needs a test database migrated through 0522, a Redis, and (test 2) a role
//! that may `CREATE DATABASE` (same as `attome_testkit::empty_database`). HEAVY:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test changeset_replay -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures and inspects state on a raw pool"
)]

use std::str::FromStr;

use attome_api::EngineSystem;
use attome_api::changeset::apply::{self, RunOutcome};
use attome_api::changeset::ledger::{self, ApplySource};
use attome_api::changeset::plan::{self, PlanContext};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../apps/attome/migrations");

fn test_config(mode: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 30,
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
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn db(&self) -> DbPool {
        self.state.base.db.clone()
    }
}

/// An `EngineSystem` over `db` (every pool role on the one pool), every module
/// licensed, with the core routes mounted.
async fn system_over(config: AppConfig, db: DbPool) -> TestSystem {
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
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
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
    let state = system.state().clone();
    let base_state = state.base.clone();
    let app = attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    TestSystem { state, app }
}

/// The authoring deployment: the migrated test database, `required` mode.
async fn authoring_system() -> Option<TestSystem> {
    static SYSTEM: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();
    SYSTEM
        .get_or_init(|| async {
            let url = attome_testkit::migrated_db_url()?;
            let mut config = test_config("required");
            point_config_at(&mut config, &url);
            let db = attome_db::create_pool(&config)
                .await
                .expect("connect DATABASE_URL");
            let present: bool =
                sqlx::query_scalar("SELECT to_regclass('changeset_apply') IS NOT NULL")
                    .fetch_one(&db)
                    .await
                    .expect("probe the changeset ledger");
            if !present {
                eprintln!(
                    "the test database predates migration 0522 (no changeset_apply); \
                     skipping — build a private template migrated through 0522"
                );
                return None;
            }
            Some(system_over(config, db).await)
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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// A throwaway `system.admin` user: `(user_id, session_cookie)`.
async fn seed_admin(db: &DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("changeset-replay-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must be seeded by attome_security::seed");
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

fn suffix() -> String {
    let hex = Uuid::now_v7().simple().to_string();
    hex[hex.len() - 12..].to_owned()
}

fn request(
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
    changeset: Option<Uuid>,
    if_match: Option<i64>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(id) = changeset {
        builder = builder.header("x-attome-changeset", id.to_string());
    }
    if let Some(v) = if_match {
        builder = builder.header("if-match", format!("\"{v}\""));
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request")
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

fn id_of(body: &Value) -> Uuid {
    body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no id in {body}"))
}

/// Opens a `project` changeset through the route; returns its id.
async fn open(system: &TestSystem, cookie: &str, name: &str) -> Uuid {
    let (status, body) = send(
        &system.app,
        request(
            "POST",
            "/api/v1/admin/changesets",
            cookie,
            Some(json!({
                "layer": "project", "scope": "l7-replay", "name": name,
                "title": "L7 replay test", "description": "changeset_replay.rs",
            })),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    id_of(&body)
}

/// `(seq, op)` of every operation of `changeset`, in seq order.
async fn ops_of(db: &DbPool, changeset: Uuid) -> Vec<(i32, String)> {
    sqlx::query_as("SELECT seq, op FROM changeset_operation WHERE changeset_ref = $1 ORDER BY seq")
        .bind(changeset)
        .fetch_all(db)
        .await
        .expect("read the changeset's operations")
}

/// The unique names of one feature built through the admin API: an entity
/// with a field, an app, a calendar and a role.
struct Feature {
    entity: String,
    app: String,
    calendar: String,
    role: String,
}

impl Feature {
    fn new() -> Self {
        let s = suffix();
        Self {
            entity: format!("l7rp_{s}"),
            app: format!("l7-replay-{s}"),
            calendar: format!("L7 replay {s}"),
            role: format!("L7 replay role {s}"),
        }
    }
}

/// Builds `feature` inside `changeset`, asserting that each request adds
/// exactly one operation with the next seq. Returns the ops in order.
async fn build_feature(
    system: &TestSystem,
    cookie: &str,
    changeset: Uuid,
    feature: &Feature,
) -> Vec<&'static str> {
    let mut expected: Vec<&'static str> = Vec::new();

    let entity = step(
        system,
        cookie,
        changeset,
        &mut expected,
        ("POST", "/api/v1/admin/entities".into()),
        json!({ "logicalname": feature.entity, "name": "L7 Replay" }),
        ("create_entity", StatusCode::CREATED),
    )
    .await;
    let entity_id = id_of(&entity);
    let steps: [(&'static str, String, Value, &'static str, StatusCode); 5] = [
        (
            "POST",
            format!("/api/v1/admin/entities/{entity_id}/fields"),
            json!({ "logicalname": "title", "name": "Title", "field_type": "text" }),
            "add_field",
            StatusCode::CREATED,
        ),
        (
            "PATCH",
            format!("/api/v1/admin/entities/{entity_id}"),
            json!({ "name": "L7 Replay Renamed" }),
            "update_entity",
            StatusCode::OK,
        ),
        (
            "POST",
            "/api/v1/admin/apps".into(),
            json!({ "name": feature.app }),
            "upsert_app",
            StatusCode::CREATED,
        ),
        (
            "POST",
            "/api/v1/admin/calendars".into(),
            json!({ "name": feature.calendar, "tz": "UTC" }),
            "upsert_calendar",
            StatusCode::CREATED,
        ),
        (
            "POST",
            "/api/v1/admin/security/roles".into(),
            json!({ "name": feature.role }),
            "upsert_role",
            StatusCode::CREATED,
        ),
    ];
    for (method, uri, body, op, status) in steps {
        step(
            system,
            cookie,
            changeset,
            &mut expected,
            (method, uri),
            body,
            (op, status),
        )
        .await;
    }
    expected
}

/// Sends one recorded write and asserts it added exactly one operation,
/// `op`, as the next seq.
async fn step(
    system: &TestSystem,
    cookie: &str,
    changeset: Uuid,
    expected: &mut Vec<&'static str>,
    (method, uri): (&'static str, String),
    body: Value,
    (op, status): (&'static str, StatusCode),
) -> Value {
    let what = format!("{method} {uri}");
    let (got, response) = send(
        &system.app,
        request(method, &uri, cookie, Some(body), Some(changeset), None),
    )
    .await;
    assert_eq!(got, status, "{what}: {response}");
    expected.push(op);
    let want: Vec<(i32, String)> = expected
        .iter()
        .enumerate()
        .map(|(i, o)| (i32::try_from(i + 1).expect("small"), (*o).to_owned()))
        .collect();
    assert_eq!(
        ops_of(&system.db(), changeset).await,
        want,
        "{what} must add exactly one operation, `{op}`, as seq {}",
        expected.len()
    );
    response
}

/// Closes `changeset` through the route; returns the v1 document.
async fn close(system: &TestSystem, cookie: &str, changeset: Uuid) -> Value {
    let uri = format!("/api/v1/admin/changesets/{changeset}");
    let (status, detail) = send(&system.app, request("GET", &uri, cookie, None, None, None)).await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    let version = detail["changeset"]["row_version"]
        .as_i64()
        .expect("row_version");
    let (status, closed) = send(
        &system.app,
        request(
            "POST",
            &format!("{uri}/close"),
            cookie,
            None,
            None,
            Some(version),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    closed["changeset"].clone()
}

/// Configuration/Import audit rows, on either write path.
async fn import_events(db: &DbPool) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE category = $1 AND operation = $2) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'category' = 'Configuration' AND payload->>'operation' = 'Import')",
    )
    .bind(attome_audit::AuditCategory::Configuration as i32)
    .bind(attome_audit::AuditOperation::Import as i32)
    .fetch_one(db)
    .await
    .expect("count Configuration/Import events")
}

#[test]
fn every_admin_change_yields_exactly_one_op_in_order() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(authoring_system().await);
        let db = system.db();
        let (_, cookie) = seed_admin(&db).await;
        let changeset = open(&system, &cookie, &format!("l7-order-{}", suffix())).await;
        let feature = Feature::new();
        let expected = build_feature(&system, &cookie, changeset, &feature).await;

        let count: i32 = sqlx::query_scalar("SELECT op_count FROM changeset WHERE id = $1")
            .bind(changeset)
            .fetch_one(&db)
            .await
            .expect("op_count");
        assert_eq!(usize::try_from(count).expect("positive"), expected.len());

        // Close keeps the order: the document's operations are the recorded
        // ops, seq 1..N.
        let document = close(&system, &cookie, changeset).await;
        let ops: Vec<(i64, String)> = document["operations"]
            .as_array()
            .expect("operations")
            .iter()
            .map(|o| {
                (
                    o["seq"].as_i64().expect("seq"),
                    o["op"].as_str().expect("op").to_owned(),
                )
            })
            .collect();
        let want: Vec<(i64, String)> = expected
            .iter()
            .enumerate()
            .map(|(i, o)| (i64::try_from(i + 1).expect("small"), (*o).to_owned()))
            .collect();
        assert_eq!(ops, want, "the closed document keeps the recording order");

        // Adopt records it as applied here, with its audit event (D-542).
        let before = import_events(&db).await;
        let (status, adopted) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/metadata/changesets/adopt",
                &cookie,
                Some(json!({ "changesets": [document] })),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{adopted}");
        assert_eq!(
            adopted["changesets"][0]["adopted"],
            json!(["expand"]),
            "{adopted}"
        );
        assert!(
            import_events(&db).await > before,
            "adopt wrote no Configuration/Import audit event"
        );
        let statuses: Vec<String> =
            sqlx::query_scalar("SELECT status FROM changeset_apply WHERE changeset_id = $1")
                .bind(changeset)
                .fetch_all(&db)
                .await
                .expect("ledger rows");
        assert_eq!(statuses, vec!["adopted".to_owned()]);
    })
}

/// The replay target: a brand-new database, every migration applied, no
/// metadata but what `EngineSystem::build` seeds. Mode `auto` (the applier
/// never records either way).
async fn replay_system(fresh: &attome_testkit::EmptyDatabase) -> TestSystem {
    let options = sqlx::postgres::PgConnectOptions::from_str(fresh.url())
        .expect("the empty database URL parses")
        .options([("search_path", "attome_dev,public")]);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(180))
        .connect_with(options)
        .await
        .expect("connect to the empty database");
    let (current,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("current_database()");
    assert_eq!(current, fresh.name(), "writes only to its own database");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS attome_dev")
        .execute(&pool)
        .await
        .expect("create the deployment schema");
    MIGRATOR.run(&pool).await.expect("apply every migration");
    let mut config = test_config("auto");
    point_config_at(&mut config, fresh.url());
    system_over(config, pool).await
}

/// Plans and applies `document` on `state` as the replay tool does.
async fn replay(state: &EngineState, document: &Value) {
    let ctx = PlanContext {
        source: ApplySource::Replay,
        requested_by: None,
        trusted: false,
    };
    let mut planned = plan::plan(state, std::slice::from_ref(document), ctx)
        .await
        .expect("plan the changeset");
    assert!(
        planned.plan.applicable,
        "the replay plan is blocked: {}",
        serde_json::to_string_pretty(&planned.plan).unwrap_or_default()
    );
    let mut tx = attome_db::tx::begin(&state.base.db).await.expect("begin");
    plan::persist(&mut tx, &mut planned, ctx)
        .await
        .expect("persist the plan");
    let ids: Vec<Uuid> = planned
        .plan
        .apply_ids
        .iter()
        .chain(&planned.plan.contract_apply_ids)
        .copied()
        .collect();
    assert!(
        !ids.is_empty(),
        "nothing to apply: {:?}",
        planned.plan.changesets
    );
    ledger::mark_queued(&mut tx, &ids, None, None)
        .await
        .expect("queue");
    attome_db::tx::commit(tx).await.expect("commit");
    for id in ids {
        match apply::run_one(state, id).await.expect("apply") {
            RunOutcome::Applied(_) => {}
            RunOutcome::NotClaimed => panic!("ledger row {id} was not claimable"),
        }
        let row = ledger::get(&state.base.db, id)
            .await
            .expect("read the ledger row")
            .expect("the ledger row exists");
        assert_eq!(row.source, ApplySource::Replay);
    }
}

/// Removes `is_customized` everywhere (design §6 normalises it away).
fn normalise(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("is_customized");
            map.values_mut().for_each(normalise);
        }
        Value::Array(items) => items.iter_mut().for_each(normalise),
        _ => {}
    }
}

/// The exported component of `section` whose `field` is `key`, normalised.
async fn exported(db: &DbPool, section: &str, field: &str, key: &str) -> Value {
    let bundle = attome_api::bundle::export_bundle(db).await.expect("export");
    let mut value = serde_json::to_value(&bundle).expect("serialize the export");
    normalise(&mut value);
    value[section]
        .as_array()
        .and_then(|items| items.iter().find(|i| i[field] == key))
        .cloned()
        .unwrap_or_else(|| panic!("{section} `{key}` is not in the export"))
}

#[test]
fn a_closed_changeset_replays_onto_an_empty_database_with_the_same_result() {
    attome_testkit::run_shared(async {
        let authoring = skip_if_no_db!(authoring_system().await);
        let fresh = skip_if_no_db!(attome_testkit::empty_database("changeset_replay").await);
        let db = authoring.db();
        let (_, cookie) = seed_admin(&db).await;
        let changeset = open(&authoring, &cookie, &format!("l7-replay-{}", suffix())).await;
        let feature = Feature::new();
        build_feature(&authoring, &cookie, changeset, &feature).await;
        let document = close(&authoring, &cookie, changeset).await;

        let target = replay_system(&fresh).await;
        replay(&target.state, &document).await;
        let replayed = target.db();

        for (section, field, key) in [
            ("entities", "logicalname", feature.entity.as_str()),
            ("apps", "name", feature.app.as_str()),
            ("calendars", "name", feature.calendar.as_str()),
            ("roles", "name", feature.role.as_str()),
        ] {
            assert_eq!(
                exported(&replayed, section, field, key).await,
                exported(&db, section, field, key).await,
                "{section} `{key}` differs between the authoring deployment and the replay"
            );
        }

        // The applier stamps the changeset's layer on what it creates.
        for (table, column, key) in [
            ("entity_info", "logicalname", feature.entity.as_str()),
            ("app", "name", feature.app.as_str()),
            ("calendar", "name", feature.calendar.as_str()),
            ("role", "name", feature.role.as_str()),
        ] {
            // Table and column are the literals above, not input.
            let layer: String = sqlx::query_scalar(&format!(
                "SELECT owner_layer FROM {table} WHERE {column} = $1"
            ))
            .bind(key)
            .fetch_one(&replayed)
            .await
            .unwrap_or_else(|e| panic!("{table} `{key}` on the replay: {e}"));
            assert_eq!(layer, "project", "{table} `{key}`");
        }

        // The replay recorded nothing: the applier is not an author.
        let recorded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM changeset_operation")
            .fetch_one(&replayed)
            .await
            .expect("count operations");
        assert_eq!(recorded, 0);
        drop(target);
        drop(fresh);
    })
}
