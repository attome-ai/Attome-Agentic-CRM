//! Dashboard 10/10 Phase 2 — correct numbers, proven against a real database.
//!
//! Two layers:
//!
//! - `attome_search::run_structured_aggregate` in-process (Phase 2.2): server-side
//!   counts over every live row, inactive rows excluded, month buckets in an
//!   IANA zone across a DST change, NULL buckets, several measures, series,
//!   honest truncation, an Other bucket that sums to the total, and a scoped
//!   caller counting exactly the rows they can list.
//! - The dashboard data routes over HTTP (Phase 2.3): published vs preview,
//!   parameter validation and binding, `@current_user`, 404s, timezone
//!   precedence, the D-523 entitlement split, the page batch, write-time
//!   validation of `config.data`, widget registry honesty and the governed KPI
//!   path held to its captured metric definition.
//!
//! Harness copied from `dashboard_http.rs` (this crate's per-file convention).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"; $env:TEST_REDIS_HOST = "127.0.0.1"
//! cargo test -p attome-api --test dashboard_data -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeMap;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::data_definition::DataDefinition;
use attome_search::{BucketKey, StructuredAggregate, StructuredBucket};
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (see `dashboard_access.rs`'s identical helpers for the doc
// comments this file omits to avoid repeating them) ─────────────────────────

/// `required_actions` — same D-195 knob `approval_query_publish.rs` exposes,
/// empty by default (ungated).
fn test_config(db: &DbUrlParts, required_actions: &[&str]) -> AppConfig {
    let required_actions_json = serde_json::to_string(required_actions).unwrap();
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }}
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
            "approval": {{ "required_actions": {required_actions_json} }}
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

async fn test_system(required_actions: &[&str]) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let config = test_config(&db_parts, required_actions);
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
    let state = attome_core::EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .register(attome_dashboard::DashboardModel)
        .register(attome_search::SearchModel)
        .register(attome_metric::MetricModel)
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
    let email = format!("dashhttp-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("dashhttp-test-{user_id}"))
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
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn req(method: &str, uri: &str, cookie: Option<&str>, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn create_role(db: &PgPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("dashhttp-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");
    role_id
}

async fn grant_privileges(db: &PgPool, role_id: Uuid, logicalname: &str, actions: &[&str]) {
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
}

async fn assign_role_to_user(db: &PgPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
}

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

async fn entity_id_for(db: &PgPool, logicalname: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("entity must already be provisioned by attome_dashboard::seed")
}

// ── Dashboard rows ───────────────────────────────────────────────────────────

async fn insert_dashboard(db: &PgPool, owner_id: Uuid, name: &str) -> (Uuid, i64) {
    let id = Uuid::now_v7();
    let (row_version,): (i64,) = sqlx::query_as(
        "INSERT INTO attome_dashboard (id, name, dashboard_type, owner_id, is_active) \
         VALUES ($1, $2, 'personal', $3, true) RETURNING row_version",
    )
    .bind(id)
    .bind(name)
    .bind(owner_id)
    .fetch_one(db)
    .await
    .expect("insert test attome_dashboard row");
    (id, row_version)
}

async fn insert_page(db: &PgPool, dashboard_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_page (id, dashboard_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(dashboard_id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test dashboard_page row");
    id
}

async fn insert_section(db: &PgPool, page_id: Uuid, layout_mode: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_section (id, page_id, section_type, layout_mode) \
         VALUES ($1, $2, 'container', $3)",
    )
    .bind(id)
    .bind(page_id)
    .bind(layout_mode)
    .execute(db)
    .await
    .expect("insert test dashboard_section row");
    id
}

// ── Fixture data ─────────────────────────────────────────────────────────────

const STATUSES: [&str; 3] = ["open", "won", "lost"];

/// A throwaway `deal` entity: `status` (single choice), `amount` (number),
/// `closed_on` (date), `region` (text). Registered in the in-process metadata
/// registry the way `EngineSystem::build` would.
async fn provision_deals(system: &EngineSystem) -> (String, Uuid) {
    let db = &system.state().base.db;
    let logicalname = format!("dash_data_deal_{}", Uuid::now_v7().simple());
    let entity_id =
        attome_metadata::provision::ensure_entity(db, &logicalname, "Deal", None, false)
            .await
            .expect("provision deal entity");
    let attributes: [(&str, &str, Option<Value>); 4] = [
        (
            "status",
            "choice",
            Some(json!({ "choices": STATUSES, "multi": false })),
        ),
        ("amount", "number", None),
        ("closed_on", "date", None),
        ("region", "text", None),
    ];
    for (name, field_type, options) in attributes {
        attome_metadata::provision::ensure_attribute(
            db, entity_id, name, name, field_type, false, false, true, true, None, options,
        )
        .await
        .expect("provision deal attribute");
    }
    sync_registry(system).await;
    (logicalname, entity_id)
}

async fn sync_registry(system: &EngineSystem) {
    let registry = attome_core::build_registry(&system.state().base.db)
        .await
        .expect("build_registry");
    system.state().entities.swap(registry);
}

#[allow(clippy::too_many_arguments)]
async fn insert_deal(
    db: &PgPool,
    logicalname: &str,
    status: Option<&str>,
    amount: f64,
    closed_on: &str,
    owner: Option<Uuid>,
    is_active: Option<bool>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (id, status, amount, closed_on, owner_ref, is_active) \
         VALUES ($1, $2, $3, $4::timestamptz, $5, $6)"
    ))
    .bind(id)
    .bind(status)
    .bind(amount)
    .bind(closed_on)
    .bind(owner)
    .bind(is_active)
    .execute(db)
    .await
    .expect("insert deal");
    id
}

/// 250 live rows across three statuses (so any 50-row client cap would be
/// visible), 20 inactive rows that must never count, and 5 rows whose
/// `is_active` is NULL, which counts as live. Returns the live count per status.
async fn seed_ground_truth(db: &PgPool, logicalname: &str) -> BTreeMap<String, i64> {
    let mut expected = BTreeMap::new();
    for i in 0..250 {
        let status = STATUSES[i % 3];
        insert_deal(
            db,
            logicalname,
            Some(status),
            10.0,
            "2026-05-10T10:00:00Z",
            None,
            Some(true),
        )
        .await;
        *expected.entry(status.to_string()).or_insert(0) += 1;
    }
    for _ in 0..20 {
        insert_deal(
            db,
            logicalname,
            Some("open"),
            999.0,
            "2026-05-10T10:00:00Z",
            None,
            Some(false),
        )
        .await;
    }
    for _ in 0..5 {
        insert_deal(
            db,
            logicalname,
            Some("won"),
            10.0,
            "2026-05-10T10:00:00Z",
            None,
            None,
        )
        .await;
        *expected.get_mut("won").unwrap() += 1;
    }
    expected
}

async fn admin_ctx(
    system: &EngineSystem,
    user_id: Uuid,
) -> std::sync::Arc<attome_server::security::SecurityContext> {
    system
        .state()
        .base
        .security
        .resolve(user_id)
        .await
        .expect("resolve admin context")
}

fn definition(raw: Value) -> DataDefinition {
    serde_json::from_value(raw).expect("test definition deserializes")
}

fn value_bucket<'a>(aggregate: &'a StructuredAggregate, value: &str) -> &'a StructuredBucket {
    aggregate
        .buckets
        .iter()
        .find(|b| {
            b.key
                == BucketKey::Value {
                    value: value.into(),
                }
        })
        .unwrap_or_else(|| panic!("bucket {value} missing"))
}

// ── Search: structured aggregation (Phase 2.2) ──────────────────────────────

/// Counts and sums run over every matching live row — past any 50-row cap —
/// exclude inactive rows, and count NULL `is_active` as live.
#[tokio::test]
async fn structured_counts_every_live_row_and_never_an_inactive_one() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, _) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let expected = seed_ground_truth(&db, &deals).await;
    let ctx = admin_ctx(&system, admin_id).await;

    let grouped = attome_search::run_structured_aggregate(
        system.state(),
        &ctx,
        &definition(json!({
            "source": deals,
            "measures": [{ "aggregation": "count" }, { "aggregation": "sum", "field": "amount" }],
            "group": { "field": "status" },
        })),
        &[],
        chrono_tz::UTC,
    )
    .await
    .expect("grouped aggregate");
    assert!(!grouped.truncated);
    assert_eq!(grouped.buckets.len(), 3);
    for (status, count) in &expected {
        let bucket = value_bucket(&grouped, status);
        assert_eq!(bucket.values[0], Some(*count as f64), "count for {status}");
        assert_eq!(
            bucket.values[1],
            Some(*count as f64 * 10.0),
            "sum for {status}"
        );
    }

    let total = attome_search::run_structured_aggregate(
        system.state(),
        &ctx,
        &definition(json!({ "source": deals, "measures": [{ "aggregation": "count" }] })),
        &[],
        chrono_tz::UTC,
    )
    .await
    .expect("ungrouped aggregate");
    assert_eq!(total.buckets.len(), 1);
    assert_eq!(total.buckets[0].key, BucketKey::Total);
    assert_eq!(
        total.buckets[0].values[0],
        Some(expected.values().sum::<i64>() as f64)
    );
}

/// Month buckets are computed in the resolved zone: a row near midnight lands
/// in a different month in Bahrain (UTC+3), London (BST from 2026-03-29) and
/// UTC, and every bucket reports its half-open range as UTC instants.
#[tokio::test]
async fn month_buckets_follow_the_timezone_across_a_dst_change() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, _) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    // 2026-03-31T22:30Z — Bahrain: April 1 01:30; London (BST): March 31 23:30.
    insert_deal(
        &db,
        &deals,
        Some("open"),
        1.0,
        "2026-03-31T22:30:00Z",
        None,
        Some(true),
    )
    .await;
    // Midnight UTC on April 1 — London: 01:00 April 1; New York: March 31 20:00.
    insert_deal(
        &db,
        &deals,
        Some("open"),
        1.0,
        "2026-04-01T00:00:00Z",
        None,
        Some(true),
    )
    .await;
    // 2026-02-28T21:30Z — Bahrain: March 1 00:30; UTC/London: February.
    insert_deal(
        &db,
        &deals,
        Some("open"),
        1.0,
        "2026-02-28T21:30:00Z",
        None,
        Some(true),
    )
    .await;
    let ctx = admin_ctx(&system, admin_id).await;
    let monthly = definition(json!({
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "closed_on", "bucket": "month" },
    }));

    let run = |tz: &'static str| {
        let (system, ctx, monthly) = (&system, ctx.clone(), monthly.clone());
        async move {
            let tz: chrono_tz::Tz = tz.parse().unwrap();
            let result =
                attome_search::run_structured_aggregate(system.state(), &ctx, &monthly, &[], tz)
                    .await
                    .expect("monthly aggregate");
            result
                .buckets
                .iter()
                .map(|b| (b.label.clone().unwrap(), b.values[0].unwrap() as i64))
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(
        run("Asia/Bahrain").await,
        vec![("2026-03".to_string(), 1), ("2026-04".to_string(), 2)]
    );
    assert_eq!(
        run("Europe/London").await,
        vec![
            ("2026-02".to_string(), 1),
            ("2026-03".to_string(), 1),
            ("2026-04".to_string(), 1)
        ]
    );
    assert_eq!(
        run("America/New_York").await,
        vec![("2026-02".to_string(), 1), ("2026-03".to_string(), 2)]
    );

    let london: chrono_tz::Tz = "Europe/London".parse().unwrap();
    let result =
        attome_search::run_structured_aggregate(system.state(), &ctx, &monthly, &[], london)
            .await
            .unwrap();
    let april = result
        .buckets
        .iter()
        .find(|b| b.label.as_deref() == Some("2026-04"))
        .unwrap();
    assert_eq!(
        april.key,
        BucketKey::Range {
            start: "2026-03-31T23:00:00Z".parse().unwrap(),
            end: "2026-04-30T23:00:00Z".parse().unwrap(),
        },
        "April in London starts at 00:00 BST"
    );
}

/// A NULL group is its own typed bucket, several measures share one statement,
/// and a series splits each group.
#[tokio::test]
async fn null_bucket_multiple_measures_and_series() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, _) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    insert_deal(
        &db,
        &deals,
        None,
        5.0,
        "2026-01-05T00:00:00Z",
        None,
        Some(true),
    )
    .await;
    insert_deal(
        &db,
        &deals,
        Some("won"),
        7.0,
        "2026-01-05T00:00:00Z",
        None,
        Some(true),
    )
    .await;
    insert_deal(
        &db,
        &deals,
        Some("won"),
        9.0,
        "2026-02-05T00:00:00Z",
        None,
        Some(true),
    )
    .await;
    let ctx = admin_ctx(&system, admin_id).await;

    let result = attome_search::run_structured_aggregate(
        system.state(),
        &ctx,
        &definition(json!({
            "source": deals,
            "measures": [
                { "aggregation": "count" },
                { "aggregation": "avg", "field": "amount" },
                { "aggregation": "max", "field": "amount" }
            ],
            "group": { "field": "status" },
            "presentation": { "sort": "key_asc" }
        })),
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    assert_eq!(
        result.buckets[0].key,
        BucketKey::Null,
        "NULLS FIRST on key order"
    );
    assert_eq!(
        result.buckets[0].values,
        vec![Some(1.0), Some(5.0), Some(5.0)]
    );
    assert_eq!(
        value_bucket(&result, "won").values,
        vec![Some(2.0), Some(8.0), Some(9.0)]
    );

    let series = attome_search::run_structured_aggregate(
        system.state(),
        &ctx,
        &definition(json!({
            "source": deals,
            "measures": [{ "aggregation": "count" }],
            "group": { "field": "closed_on", "bucket": "month" },
            "series": "status"
        })),
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    let january: Vec<_> = series
        .buckets
        .iter()
        .filter(|b| b.label.as_deref() == Some("2026-01"))
        .map(|b| b.series_key.clone().unwrap())
        .collect();
    assert_eq!(
        january,
        vec![
            BucketKey::Null,
            BucketKey::Value {
                value: "won".into()
            }
        ]
    );
}

/// Past the cap the response says so, and an explicit Other bucket folds the
/// rest — including NULL rows the plain `NOT IN` form would drop — so the
/// buckets sum to the ungrouped count.
#[tokio::test]
async fn truncation_is_honest_and_other_sums_to_the_total() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, _) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    for i in 0..201 {
        sqlx::query(&format!(
            "INSERT INTO \"{deals}\" (id, region, amount, is_active) VALUES ($1, $2, 1, true)"
        ))
        .bind(Uuid::now_v7())
        .bind(format!("region-{i:03}"))
        .execute(&db)
        .await
        .unwrap();
    }
    for _ in 0..4 {
        sqlx::query(&format!(
            "INSERT INTO \"{deals}\" (id, region, amount, is_active) VALUES ($1, NULL, 1, true)"
        ))
        .bind(Uuid::now_v7())
        .execute(&db)
        .await
        .unwrap();
    }
    let ctx = admin_ctx(&system, admin_id).await;

    let capped = attome_search::run_structured_aggregate(
        system.state(),
        &ctx,
        &definition(json!({
            "source": deals,
            "measures": [{ "aggregation": "count" }],
            "group": { "field": "region" }
        })),
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    assert!(capped.truncated, "202 groups must report truncation at 200");
    assert_eq!(capped.buckets.len(), 200);

    let folded = attome_search::run_structured_aggregate(
        system.state(),
        &ctx,
        &definition(json!({
            "source": deals,
            "measures": [{ "aggregation": "count" }],
            "group": { "field": "region" },
            "presentation": { "limit": 3, "other_bucket": true, "sort": "key_desc" }
        })),
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    assert!(folded.truncated);
    assert!(
        !folded.buckets.iter().any(|b| b.key == BucketKey::Null),
        "key_desc puts NULL last, so it is not among the top three"
    );
    let other = folded.other.expect("other bucket");
    let top: f64 = folded.buckets.iter().map(|b| b.values[0].unwrap()).sum();
    assert_eq!(
        top + other.values[0].unwrap(),
        205.0,
        "top + other = every row, NULLs included"
    );
}

/// A caller scoped to None-tier with shares on some rows counts exactly the
/// rows they can list; an unrelated admin still counts all of them.
#[tokio::test]
async fn a_scoped_callers_count_equals_the_rows_they_can_list() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let (admin_id, _) = seed_user(&system, true).await;
    let (reader_id, _) = seed_user(&system, false).await;
    let (deals, entity_id) = provision_deals(&system).await;
    let mut ids = Vec::new();
    for _ in 0..9 {
        ids.push(
            insert_deal(
                &db,
                &deals,
                Some("open"),
                1.0,
                "2026-05-01T00:00:00Z",
                None,
                Some(true),
            )
            .await,
        );
    }
    let role_id = create_role(&db).await;
    grant_privileges(&db, role_id, &deals, &["read"]).await;
    assign_role_to_user(&db, reader_id, role_id).await;
    scope_role_for_entity(&db, &security, role_id, reader_id, entity_id, 0).await;
    for id in ids.iter().take(4) {
        sqlx::query(
            "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
             VALUES ($1, $2, 0, $3, 0)",
        )
        .bind(id)
        .bind(entity_id)
        .bind(reader_id)
        .execute(&db)
        .await
        .unwrap();
    }
    security.invalidate(reader_id).await;
    let count = definition(json!({ "source": deals, "measures": [{ "aggregation": "count" }] }));

    let reader = admin_ctx(&system, reader_id).await;
    let scoped = attome_search::run_structured_aggregate(
        system.state(),
        &reader,
        &count,
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    assert_eq!(scoped.buckets[0].values[0], Some(4.0));

    let admin = admin_ctx(&system, admin_id).await;
    let all = attome_search::run_structured_aggregate(
        system.state(),
        &admin,
        &count,
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    assert_eq!(all.buckets[0].values[0], Some(9.0));
}

// ── Lookup display names (Phase 4) ──────────────────────────────────────────

/// A group or series on a lookup field is labelled with the target record's
/// name for a caller who may read the target, and keeps the stored id for a
/// caller who may not; the key (and so the drill) is the id either way.
#[tokio::test]
async fn lookup_buckets_show_target_names_only_to_callers_who_can_read_them() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let (admin_id, _) = seed_user(&system, true).await;
    let (reader_id, _) = seed_user(&system, false).await;
    let (deals, deals_entity) = provision_deals(&system).await;

    let teams = format!("dash_data_team_{}", Uuid::now_v7().simple());
    let team_entity =
        attome_metadata::provision::ensure_entity(&db, &teams, "Team", Some("name"), false)
            .await
            .expect("provision team entity");
    attome_metadata::provision::ensure_attribute(
        &db,
        team_entity,
        "name",
        "Name",
        "text",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .expect("provision team name");
    attome_metadata::provision::ensure_attribute(
        &db,
        deals_entity,
        "team_ref",
        "Team",
        "lookup",
        false,
        false,
        true,
        true,
        Some(team_entity),
        None,
    )
    .await
    .expect("provision deal team lookup");
    sync_registry(&system).await;

    let mut team_ids = Vec::new();
    for name in ["North", "South"] {
        let id = Uuid::now_v7();
        sqlx::query(&format!(
            "INSERT INTO \"{teams}\" (id, name, is_active) VALUES ($1, $2, true)"
        ))
        .bind(id)
        .bind(name)
        .execute(&db)
        .await
        .expect("insert team");
        team_ids.push(id);
    }
    let mut deal_ids = Vec::new();
    for (i, status) in ["open", "open", "won", "won", "won"].iter().enumerate() {
        let id = insert_deal(
            &db,
            &deals,
            Some(status),
            1.0,
            "2026-05-01T00:00:00Z",
            None,
            Some(true),
        )
        .await;
        sqlx::query(&format!(
            "UPDATE \"{deals}\" SET team_ref = $1 WHERE id = $2"
        ))
        .bind(team_ids[i % 2])
        .bind(id)
        .execute(&db)
        .await
        .expect("set deal team");
        deal_ids.push(id);
    }

    let by_team = definition(json!({
        "source": deals, "measures": [{ "aggregation": "count" }], "group": { "field": "team_ref" }
    }));
    let admin = admin_ctx(&system, admin_id).await;
    let named = attome_search::run_structured_aggregate(
        system.state(),
        &admin,
        &by_team,
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    let north = value_bucket(&named, &team_ids[0].to_string());
    assert_eq!(north.label.as_deref(), Some("North"));
    assert_eq!(north.values[0], Some(3.0));
    assert_eq!(
        value_bucket(&named, &team_ids[1].to_string())
            .label
            .as_deref(),
        Some("South")
    );

    let by_status_and_team = definition(json!({
        "source": deals, "measures": [{ "aggregation": "count" }],
        "group": { "field": "status" }, "series": "team_ref"
    }));
    let series = attome_search::run_structured_aggregate(
        system.state(),
        &admin,
        &by_status_and_team,
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    let labels: std::collections::BTreeSet<_> = series
        .buckets
        .iter()
        .filter_map(|b| b.series_label.clone())
        .collect();
    assert_eq!(
        labels,
        ["North".to_string(), "South".to_string()]
            .into_iter()
            .collect()
    );

    // A reader who can see the deals (by share) but has no read on teams.
    let role_id = create_role(&db).await;
    grant_privileges(&db, role_id, &deals, &["read"]).await;
    assign_role_to_user(&db, reader_id, role_id).await;
    scope_role_for_entity(&db, &security, role_id, reader_id, deals_entity, 0).await;
    for id in &deal_ids {
        sqlx::query(
            "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
             VALUES ($1, $2, 0, $3, 0)",
        )
        .bind(id)
        .bind(deals_entity)
        .bind(reader_id)
        .execute(&db)
        .await
        .unwrap();
    }
    security.invalidate(reader_id).await;
    let reader = admin_ctx(&system, reader_id).await;
    let unnamed = attome_search::run_structured_aggregate(
        system.state(),
        &reader,
        &by_team,
        &[],
        chrono_tz::UTC,
    )
    .await
    .unwrap();
    let north = value_bucket(&unnamed, &team_ids[0].to_string());
    assert_eq!(north.values[0], Some(3.0));
    assert_eq!(
        north.label.as_deref(),
        Some(team_ids[0].to_string().as_str())
    );
    assert!(
        unnamed
            .buckets
            .iter()
            .all(|b| b.label.as_deref() != Some("North") && b.label.as_deref() != Some("South")),
        "a team name leaked to a caller without team read"
    );
}

/// The public route got the same live-row rule (a documented behavior change).
#[tokio::test]
async fn the_public_aggregate_route_no_longer_counts_inactive_rows() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let expected = seed_ground_truth(&db, &deals).await;
    let app = full_app(system);
    let res = app
        .oneshot(req(
            "POST",
            "/api/v1/search/aggregate",
            Some(&admin_cookie),
            Some(&json!({ "entity": deals, "metric_fn": "count" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(
        body["buckets"][0]["value"],
        expected.values().sum::<i64>() as f64
    );
}

// ── Dashboard data routes (Phase 2.3) ───────────────────────────────────────

struct DataDashboard {
    dashboard_id: Uuid,
    page_id: Uuid,
    widget_id: Uuid,
}

async fn insert_data_widget(
    db: &PgPool,
    section_id: Uuid,
    widget_type: &str,
    config: &Value,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget (id, section_id, widget_type, name, config) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(section_id)
    .bind(widget_type)
    .bind(format!("{widget_type} widget"))
    .bind(config.to_string())
    .execute(db)
    .await
    .expect("insert data widget");
    id
}

async fn build_data_dashboard(db: &PgPool, owner: Uuid, config: &Value) -> DataDashboard {
    let (dashboard_id, _) = insert_dashboard(db, owner, "Data dashboard").await;
    let page_id = insert_page(db, dashboard_id, "Numbers").await;
    let section_id = insert_section(db, page_id, "grid").await;
    let widget_id = insert_data_widget(db, section_id, "bar_chart", config).await;
    DataDashboard {
        dashboard_id,
        page_id,
        widget_id,
    }
}

async fn publish(app: &axum::Router, cookie: &str, dashboard_id: Uuid, db: &PgPool) {
    let mut row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(db)
            .await
            .unwrap();
    for step in ["submit-review", "approve", "publish"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/{step}"),
                Some(cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let body = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "{step}: {body}");
        row_version = body["row_version"].as_i64().unwrap();
    }
}

async fn start_revision(app: &axum::Router, cookie: &str, dashboard_id: Uuid, db: &PgPool) {
    let row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(db)
            .await
            .unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/start-revision"),
            Some(cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

async fn widget_data(
    app: &axum::Router,
    cookie: &str,
    dashboard: &DataDashboard,
    body: Value,
) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!(
                "/api/v1/attome-dashboard/{}/widgets/{}/data",
                dashboard.dashboard_id, dashboard.widget_id
            ),
            Some(cookie),
            Some(&body),
        ))
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 16 * 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn bucket_value(body: &Value, key: &str) -> f64 {
    body["structured"]["buckets"]
        .as_array()
        .unwrap_or_else(|| panic!("no buckets: {body}"))
        .iter()
        .find(|b| b["key"]["value"] == key)
        .unwrap_or_else(|| panic!("bucket {key} missing: {body}"))["values"][0]
        .as_f64()
        .unwrap()
}

/// The published number is the server count over every live row; a draft
/// edit changes the preview but never the published response.
#[tokio::test]
async fn a_published_structured_widget_returns_the_server_count_and_ignores_draft_edits() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let expected = seed_ground_truth(&db, &deals).await;
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "status" }
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (status, body) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data_class"], "structured");
    assert_eq!(body["drillability"], "exact");
    assert_eq!(body["render_kind"], "chart_bar");
    assert_eq!(body["definition_source"], "published");
    assert!(body["as_of"].is_string());
    for (status_value, count) in &expected {
        assert_eq!(bucket_value(&body, status_value), *count as f64);
    }
    let fingerprint = body["definition_fingerprint"].clone();
    let (_, again) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(
        again["definition_fingerprint"], fingerprint,
        "stable for identical inputs"
    );

    // Edit the draft: filter to `won` only.
    start_revision(&app, &admin_cookie, dashboard.dashboard_id, &db).await;
    let edited = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "status" },
        "filters": [{ "field": "status", "op": "eq", "value": "won" }]
    }});
    sqlx::query("UPDATE dashboard_widget SET config = $1 WHERE id = $2")
        .bind(edited.to_string())
        .bind(dashboard.widget_id)
        .execute(&db)
        .await
        .unwrap();

    let (_, published) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(
        published["structured"]["buckets"].as_array().unwrap().len(),
        3
    );
    assert_eq!(published["definition_fingerprint"], fingerprint);

    let (status, preview) =
        widget_data(&app, &admin_cookie, &dashboard, json!({ "preview": true })).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["definition_source"], "draft");
    assert_eq!(
        preview["structured"]["buckets"].as_array().unwrap().len(),
        1
    );
    assert_ne!(preview["definition_fingerprint"], fingerprint);
}

/// Parameters are validated against the declarations; a choice-field binding
/// refuses a value outside the field's choices; a valid value narrows the number.
#[tokio::test]
async fn parameters_are_validated_and_bound_server_side() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let expected = seed_ground_truth(&db, &deals).await;
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "bindings": [{ "source": "parameter", "name": "stage", "field": "status", "op": "eq" }]
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    sqlx::query(
        "INSERT INTO dashboard_parameter (id, dashboard_id, name, parameter_type) \
         VALUES ($1, $2, 'stage', 'choice')",
    )
    .bind(Uuid::now_v7())
    .bind(dashboard.dashboard_id)
    .execute(&db)
    .await
    .unwrap();
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (status, body) = widget_data(
        &app,
        &admin_cookie,
        &dashboard,
        json!({ "parameters": { "region": "x" } }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown parameter: {body}"
    );

    let (status, body) = widget_data(
        &app,
        &admin_cookie,
        &dashboard,
        json!({ "parameters": { "stage": "pending" } }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "outside the choice set: {body}"
    );

    let (status, body) = widget_data(
        &app,
        &admin_cookie,
        &dashboard,
        json!({ "parameters": { "stage": "won" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["structured"]["buckets"][0]["values"][0],
        expected["won"] as f64
    );
    assert_eq!(body["applied_filters"][0]["origin"]["kind"], "parameter");

    let (_, unset) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(
        unset["structured"]["buckets"][0]["values"][0],
        expected.values().sum::<i64>() as f64,
        "an unset parameter narrows nothing"
    );

    let (status, _) = widget_data(
        &app,
        &admin_cookie,
        &dashboard,
        json!({ "filters": [{ "field": "status", "op": "eq", "value": "won" }] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a viewer can never send a filter definition"
    );
}

/// `@current_user` resolves from the server's security context, so a
/// non-admin sees only rows they own even though their entity access is Global.
#[tokio::test]
async fn a_current_user_binding_yields_only_the_callers_rows() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let (viewer_id, viewer_cookie) = seed_user(&system, false).await;
    let (deals, deals_entity) = provision_deals(&system).await;
    for _ in 0..3 {
        insert_deal(
            &db,
            &deals,
            Some("open"),
            1.0,
            "2026-05-01T00:00:00Z",
            Some(viewer_id),
            Some(true),
        )
        .await;
    }
    for _ in 0..7 {
        insert_deal(
            &db,
            &deals,
            Some("open"),
            1.0,
            "2026-05-01T00:00:00Z",
            Some(admin_id),
            Some(true),
        )
        .await;
    }
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "bindings": [{ "source": "builtin", "name": "@current_user", "field": "owner_ref", "op": "eq" }]
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    let dashboard_entity = entity_id_for(&db, "attome_dashboard").await;
    let role_id = create_role(&db).await;
    grant_privileges(&db, role_id, "attome_dashboard", &["read"]).await;
    grant_privileges(&db, role_id, &deals, &["read"]).await;
    assign_role_to_user(&db, viewer_id, role_id).await;
    scope_role_for_entity(&db, &security, role_id, viewer_id, dashboard_entity, 0).await;
    scope_role_for_entity(&db, &security, role_id, viewer_id, deals_entity, 3).await;
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)",
    )
    .bind(dashboard.dashboard_id)
    .bind(dashboard_entity)
    .bind(viewer_id)
    .execute(&db)
    .await
    .unwrap();
    security.invalidate(viewer_id).await;
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (status, body) = widget_data(&app, &viewer_cookie, &dashboard, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["structured"]["buckets"][0]["values"][0], 3.0);
    let (_, admin_body) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(admin_body["structured"]["buckets"][0]["values"][0], 7.0);

    // A viewer with only a view share cannot preview the draft: 404, not 403.
    let (status, _) =
        widget_data(&app, &viewer_cookie, &dashboard, json!({ "preview": true })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A dashboard the caller cannot see is a 404, and one with nothing published
/// is a 404 for a viewer.
#[tokio::test]
async fn hidden_and_unpublished_dashboards_are_not_found() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let (outsider_id, outsider_cookie) = seed_user(&system, false).await;
    let (deals, _) = provision_deals(&system).await;
    let config = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    let role_id = create_role(&db).await;
    grant_privileges(&db, role_id, "attome_dashboard", &["read"]).await;
    assign_role_to_user(&db, outsider_id, role_id).await;
    let dashboard_entity = entity_id_for(&db, "attome_dashboard").await;
    scope_role_for_entity(&db, &security, role_id, outsider_id, dashboard_entity, 0).await;
    let app = full_app(system);

    let (status, _) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing published yet");

    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;
    let (status, _) = widget_data(&app, &outsider_cookie, &dashboard, json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no record access");
}

/// Page timezone wins over the user's, which wins over UTC.
#[tokio::test]
async fn timezone_precedence_is_page_then_user_then_utc() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let config = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    let app = full_app(system);

    let (_, body) = widget_data(&app, &admin_cookie, &dashboard, json!({ "preview": true })).await;
    assert_eq!(
        (body["timezone"].clone(), body["timezone_source"].clone()),
        (json!("UTC"), json!("utc"))
    );

    sqlx::query("UPDATE user_account SET timezone = 'Europe/London' WHERE id = $1")
        .bind(admin_id)
        .execute(&db)
        .await
        .unwrap();
    let (_, body) = widget_data(&app, &admin_cookie, &dashboard, json!({ "preview": true })).await;
    assert_eq!(
        (body["timezone"].clone(), body["timezone_source"].clone()),
        (json!("Europe/London"), json!("user"))
    );

    sqlx::query("UPDATE dashboard_page SET settings = $1 WHERE id = $2")
        .bind(json!({ "timezone": "Asia/Bahrain" }).to_string())
        .bind(dashboard.page_id)
        .execute(&db)
        .await
        .unwrap();
    let (_, body) = widget_data(&app, &admin_cookie, &dashboard, json!({ "preview": true })).await;
    assert_eq!(
        (body["timezone"].clone(), body["timezone_source"].clone()),
        (json!("Asia/Bahrain"), json!("page"))
    );
}

/// D-523: a licence with the dashboard module but not search still gets
/// widget data, while the public search aggregation stays hidden.
#[tokio::test]
async fn a_dashboard_only_licence_gets_widget_data_but_not_search_aggregate() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    insert_deal(
        &db,
        &deals,
        Some("open"),
        1.0,
        "2026-05-01T00:00:00Z",
        None,
        Some(true),
    )
    .await;
    let config = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    let license = system.state().modules.clone();
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let core = attome_modules::MODULE_CORE;
    let dash = attome_modules::MODULE_DASHBOARD;
    let mut bits = [0u64; 4];
    bits[core.word] |= core.mask;
    bits[dash.word] |= dash.mask;
    license.store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
        bits,
    )));

    let (status, body) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["structured"]["buckets"][0]["values"][0], 1.0);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/search/aggregate",
            Some(&admin_cookie),
            Some(&json!({ "entity": deals, "metric_fn": "count" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// The page route returns every widget in layout order and contains one
/// widget's failure to its own entry (read as a preview: the publish gate
/// refuses the broken widget).
#[tokio::test]
async fn the_page_route_executes_every_widget_and_contains_failures() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    insert_deal(
        &db,
        &deals,
        Some("open"),
        1.0,
        "2026-05-01T00:00:00Z",
        None,
        Some(true),
    )
    .await;
    let good = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &good).await;
    let section_id: Uuid =
        sqlx::query_scalar("SELECT id FROM dashboard_section WHERE page_id = $1")
            .bind(dashboard.page_id)
            .fetch_one(&db)
            .await
            .unwrap();
    let broken = json!({ "data": { "source": deals, "measures": [{ "aggregation": "sum", "field": "region" }] }});
    let broken_id = insert_data_widget(&db, section_id, "metric", &broken).await;
    let text_id =
        insert_data_widget(&db, section_id, "rich_text", &json!({ "content": "hi" })).await;
    // The health gate refuses to publish the broken widget, so the page is read
    // as the editor's preview, which executes the draft as it stands.
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!(
                "/api/v1/attome-dashboard/{}/pages/{}/data",
                dashboard.dashboard_id, dashboard.page_id
            ),
            Some(&admin_cookie),
            Some(&json!({ "preview": true })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let widgets = body["widgets"].as_array().unwrap();
    assert_eq!(widgets.len(), 3);
    let entry = |id: Uuid| {
        widgets
            .iter()
            .find(|w| w["widget_id"] == id.to_string())
            .unwrap()
    };
    assert_eq!(
        entry(dashboard.widget_id)["data"]["structured"]["buckets"][0]["values"][0],
        1.0
    );
    assert_eq!(entry(broken_id)["error"]["status"], 422);
    assert_eq!(entry(text_id)["data"]["data_class"], "none");
    assert_eq!(entry(text_id)["data"]["render_kind"], "text");
}

/// Write-time validation: an invalid `config.data` cannot be saved through the
/// generic entity API; a valid one can.
#[tokio::test]
async fn an_invalid_data_definition_cannot_be_saved() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let dashboard = build_data_dashboard(&db, admin_id, &json!({})).await;
    let section_id: Uuid =
        sqlx::query_scalar("SELECT id FROM dashboard_section WHERE page_id = $1")
            .bind(dashboard.page_id)
            .fetch_one(&db)
            .await
            .unwrap();
    let app = full_app(system);
    let post = |config: Value| {
        let app = app.clone();
        let cookie = admin_cookie.clone();
        async move {
            let res = app
                .oneshot(req(
                    "POST",
                    "/api/v1/dashboard_widget",
                    Some(&cookie),
                    Some(&json!({
                        "section_id": section_id,
                        "widget_type": "bar_chart",
                        "name": "validated",
                        "config": config.to_string(),
                    })),
                ))
                .await
                .unwrap();
            let status = res.status();
            (status, body_json(res).await)
        }
    };
    let (status, body) = post(json!({ "data": {
        "source": deals, "measures": [{ "aggregation": "sum", "field": "region" }]
    }}))
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    let (status, body) = post(json!({ "data": {
        "source": deals, "measures": [{ "aggregation": "sum", "field": "amount" }],
        "group": { "field": "closed_on", "bucket": "quarter" }
    }}))
    .await;
    assert!(status.is_success(), "{status}: {body}");
}

/// D-525: the palette lists only renderable types unless asked otherwise.
#[tokio::test]
async fn widget_types_hide_unsupported_types_by_default() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let list = |uri: &'static str| {
        let (app, cookie) = (app.clone(), admin_cookie.clone());
        async move {
            let res = app
                .oneshot(req("GET", uri, Some(&cookie), None))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            body_json(res).await
        }
    };
    let palette = list("/api/v1/attome-dashboard/widget-types").await;
    let palette = palette.as_array().unwrap();
    assert!(palette.iter().all(|d| d["render_kind"] != "unsupported"));
    assert!(palette.iter().any(|d| d["type_id"] == "bar_chart"));
    assert!(!palette.iter().any(|d| d["type_id"] == "sankey_diagram"));
    let everything = list("/api/v1/attome-dashboard/widget-types?include_unsupported=true").await;
    assert!(
        everything
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["type_id"] == "sankey_diagram")
    );
}

// ── Governed KPI widgets (Class B, E-02) ────────────────────────────────────

async fn insert_metric(db: &PgPool, formula: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
         (id, name, key, source_kind, formula, direction, period, is_active) \
         VALUES ($1, 'Win rate', $2, 'formula', $3, 'higher_is_better', 'month', true)",
    )
    .bind(id)
    .bind(format!("win_rate_{}", id.simple()))
    .bind(formula)
    .execute(db)
    .await
    .expect("insert metric definition");
    id
}

async fn insert_snapshot(db: &PgPool, metric_id: Uuid, period: &str, actual: f64) {
    sqlx::query(
        "INSERT INTO metric_snapshot (id, metric_ref, period_start, actual, source_version, status) \
         VALUES ($1, $2, $3::date, $4, 'formula', 'on_track')",
    )
    .bind(Uuid::now_v7())
    .bind(metric_id)
    .bind(period)
    .bind(actual)
    .execute(db)
    .await
    .expect("insert metric snapshot");
}

/// A published scorecard shows snapshots computed from the metric definition
/// captured at publish, says it is service-scoped, and reports
/// `definition_changed` once the metric is edited, instead of a number whose
/// meaning changed without a publish.
#[tokio::test]
async fn a_published_kpi_widget_is_held_to_its_captured_metric_definition() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let metric_id = insert_metric(&db, "a / b").await;
    insert_snapshot(&db, metric_id, "2026-04-01", 0.4).await;
    insert_snapshot(&db, metric_id, "2026-05-01", 0.5).await;
    let dashboard = build_data_dashboard(&db, admin_id, &json!({})).await;
    sqlx::query("UPDATE dashboard_widget SET widget_type = 'trendline', config = $1 WHERE id = $2")
        .bind(json!({ "metric_ref": metric_id }).to_string())
        .bind(dashboard.widget_id)
        .execute(&db)
        .await
        .unwrap();
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (status, body) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data_class"], "kpi");
    assert_eq!(body["drillability"], "explain_only");
    assert_eq!(body["kpi"]["service_scoped"], true);
    let metric = &body["kpi"]["metrics"][0];
    assert_eq!(metric["status"], "ok");
    assert_eq!(metric["current"]["actual"], 0.5);
    assert_eq!(metric["history"].as_array().unwrap().len(), 2);

    sqlx::query("UPDATE dashboard_metric_definition SET formula = 'a / (a + b)' WHERE id = $1")
        .bind(metric_id)
        .execute(&db)
        .await
        .unwrap();
    let (_, body) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    assert_eq!(body["kpi"]["metrics"][0]["status"], "definition_changed");
    assert!(body["kpi"]["metrics"][0]["current"].is_null());

    let (_, preview) =
        widget_data(&app, &admin_cookie, &dashboard, json!({ "preview": true })).await;
    assert_eq!(
        preview["kpi"]["metrics"][0]["status"], "ok",
        "the draft follows the live metric"
    );
}

// ── Phase 3.1: records behind a number (parity) ─────────────────────────────

async fn widget_route(
    app: &axum::Router,
    cookie: &str,
    dashboard: &DataDashboard,
    route: &str,
    body: Value,
) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!(
                "/api/v1/attome-dashboard/{}/widgets/{}/{route}",
                dashboard.dashboard_id, dashboard.widget_id
            ),
            Some(cookie),
            Some(&body),
        ))
        .await
        .unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 16 * 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Every record of a drill, following the keyset cursor to the end.
async fn all_records(
    app: &axum::Router,
    cookie: &str,
    dashboard: &DataDashboard,
    mut body: Value,
) -> (i64, Vec<Value>) {
    let mut rows = Vec::new();
    loop {
        let (status, page) = widget_route(app, cookie, dashboard, "records", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        rows.extend(page["records"]["rows"].as_array().unwrap().iter().cloned());
        match page["records"]["next_cursor"].as_str() {
            Some(cursor) => body["after_id"] = json!(cursor),
            None => return (page["records"]["total"].as_i64().unwrap(), rows),
        }
    }
}

/// Each bucket's records total equals its value, the buckets sum to the
/// ungrouped count, a sum equals the sum over its paged records, and the NULL
/// and Other buckets obey the same parity — for an admin and for a caller whose
/// record scope hides some rows.
#[tokio::test]
async fn records_match_their_numbers_for_every_bucket_and_caller() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let (reader_id, reader_cookie) = seed_user(&system, false).await;
    let (deals, deals_entity) = provision_deals(&system).await;
    let mut shared = Vec::new();
    for i in 0..60 {
        let status = [Some("open"), Some("won"), Some("lost"), None][i % 4];
        let id = insert_deal(
            &db,
            &deals,
            status,
            (i + 1) as f64,
            "2026-05-10T10:00:00Z",
            None,
            Some(true),
        )
        .await;
        if i % 3 == 0 {
            shared.push(id);
        }
    }
    for _ in 0..7 {
        insert_deal(
            &db,
            &deals,
            Some("open"),
            1000.0,
            "2026-05-10T10:00:00Z",
            None,
            Some(false),
        )
        .await;
    }
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }, { "aggregation": "sum", "field": "amount" }],
        "group": { "field": "status" },
        "presentation": { "limit": 2, "other_bucket": true, "sort": "key_asc" }
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;

    let dashboard_entity = entity_id_for(&db, "attome_dashboard").await;
    let role_id = create_role(&db).await;
    grant_privileges(&db, role_id, "attome_dashboard", &["read"]).await;
    grant_privileges(&db, role_id, &deals, &["read"]).await;
    assign_role_to_user(&db, reader_id, role_id).await;
    scope_role_for_entity(&db, &security, role_id, reader_id, dashboard_entity, 0).await;
    scope_role_for_entity(&db, &security, role_id, reader_id, deals_entity, 0).await;
    for record in std::iter::once(dashboard.dashboard_id).chain(shared.iter().copied()) {
        let entity = if record == dashboard.dashboard_id {
            dashboard_entity
        } else {
            deals_entity
        };
        sqlx::query(
            "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
             VALUES ($1, $2, 0, $3, 0)",
        )
        .bind(record)
        .bind(entity)
        .bind(reader_id)
        .execute(&db)
        .await
        .unwrap();
    }
    security.invalidate(reader_id).await;
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    for (cookie, expected_total) in [(&admin_cookie, 60), (&reader_cookie, shared.len() as i64)] {
        let (status, data) = widget_data(&app, cookie, &dashboard, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{data}");
        let structured = &data["structured"];
        let mut buckets: Vec<Value> = structured["buckets"].as_array().unwrap().clone();
        if !structured["other"].is_null() {
            buckets.push(structured["other"].clone());
        }
        let mut count_sum = 0.0;
        for bucket in &buckets {
            let (total, rows) = all_records(
                &app,
                cookie,
                &dashboard,
                json!({ "bucket_key": bucket["key"], "page_size": 7 }),
            )
            .await;
            let count = bucket["values"][0].as_f64().unwrap();
            assert_eq!(total as f64, count, "bucket {} total", bucket["key"]);
            assert_eq!(rows.len() as i64, total, "paged rows equal the total");
            let amount: f64 = rows
                .iter()
                .map(|r| r["amount"].as_f64().unwrap_or(0.0))
                .sum();
            assert_eq!(
                amount,
                bucket["values"][1].as_f64().unwrap_or(0.0),
                "bucket {} sum",
                bucket["key"]
            );
            count_sum += count;
        }
        assert_eq!(
            count_sum, expected_total as f64,
            "buckets sum to the ungrouped count"
        );
    }

    let null_bucket = json!({ "bucket_key": { "kind": "null" } });
    let (_, rows) = all_records(&app, &admin_cookie, &dashboard, null_bucket).await;
    assert!(rows.iter().all(|r| r["status"].is_null()));
}

/// A month bucket in a DST zone drills to exactly the rows it counted.
#[tokio::test]
async fn a_time_bucket_drills_to_its_half_open_local_range() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    for instant in [
        "2026-03-31T22:30:00Z",
        "2026-03-31T23:30:00Z",
        "2026-04-15T12:00:00Z",
        "2026-04-30T23:30:00Z",
    ] {
        insert_deal(&db, &deals, Some("open"), 1.0, instant, None, Some(true)).await;
    }
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "closed_on", "bucket": "month" }
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    sqlx::query("UPDATE dashboard_page SET settings = $1 WHERE id = $2")
        .bind(json!({ "timezone": "Europe/London" }).to_string())
        .bind(dashboard.page_id)
        .execute(&db)
        .await
        .unwrap();
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (_, data) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    for bucket in data["structured"]["buckets"].as_array().unwrap() {
        let (total, _) = all_records(
            &app,
            &admin_cookie,
            &dashboard,
            json!({ "bucket_key": bucket["key"] }),
        )
        .await;
        assert_eq!(
            total as f64,
            bucket["values"][0].as_f64().unwrap(),
            "{}",
            bucket["label"]
        );
    }
    // London: 22:30Z on 31 March is still March (BST starts 29 March, so
    // 23:30 BST); 23:30Z on 31 March is 00:30 BST on 1 April; 23:30Z on 30
    // April is 00:30 BST on 1 May.
    let labels: Vec<_> = data["structured"]["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["label"].as_str().unwrap().to_owned(),
                b["values"][0].as_f64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        labels,
        vec![
            ("2026-03".to_owned(), 1.0),
            ("2026-04".to_owned(), 2.0),
            ("2026-05".to_owned(), 1.0)
        ]
    );
}

/// A governed KPI or a stored-query widget refuses a records drill with a 422
/// naming its drillability.
#[tokio::test]
async fn only_exact_widgets_can_be_drilled() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let metric_id = insert_metric(&db, "a / b").await;
    insert_snapshot(&db, metric_id, "2026-05-01", 0.5).await;
    let dashboard = build_data_dashboard(&db, admin_id, &json!({})).await;
    sqlx::query("UPDATE dashboard_widget SET widget_type = 'scorecard', config = $1 WHERE id = $2")
        .bind(json!({ "metric_refs": [metric_id] }).to_string())
        .bind(dashboard.widget_id)
        .execute(&db)
        .await
        .unwrap();
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (status, body) = widget_route(&app, &admin_cookie, &dashboard, "records", json!({})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.to_string().contains("explain_only"), "{body}");

    let (status, explanation) =
        widget_route(&app, &admin_cookie, &dashboard, "explain", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{explanation}");
    assert_eq!(explanation["kpi"]["service_scoped"], true);
    assert_eq!(explanation["kpi"]["metrics"][0]["formula"], "a / b");
    assert!(explanation["structured"].is_null());
}

// ── Phase 3.2: explanation ───────────────────────────────────────────────────

/// The explanation is built from the same context as the records: identical
/// filters with their origins, the measure in words and formally, the
/// timezone, the live-row rule and the caller's scope; a built-in shows only
/// the caller's own name.
#[tokio::test]
async fn the_explanation_uses_the_same_context_as_the_records() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    insert_deal(
        &db,
        &deals,
        Some("won"),
        5.0,
        "2026-05-01T00:00:00Z",
        Some(admin_id),
        Some(true),
    )
    .await;
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "sum", "field": "amount" }],
        "filters": [{ "field": "amount", "op": "gt", "value": "0" }],
        "bindings": [
            { "source": "parameter", "name": "stage", "field": "status", "op": "eq" },
            { "source": "builtin", "name": "@current_user", "field": "owner_ref", "op": "eq" }
        ]
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    sqlx::query(
        "INSERT INTO dashboard_parameter (id, dashboard_id, name, parameter_type) VALUES ($1, $2, 'stage', 'choice')",
    )
    .bind(Uuid::now_v7())
    .bind(dashboard.dashboard_id)
    .execute(&db)
    .await
    .unwrap();
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let inputs = json!({ "parameters": { "stage": "won" } });
    let (status, explanation) =
        widget_route(&app, &admin_cookie, &dashboard, "explain", inputs.clone()).await;
    assert_eq!(status, StatusCode::OK, "{explanation}");
    let (status, records) =
        widget_route(&app, &admin_cookie, &dashboard, "records", inputs.clone()).await;
    assert_eq!(status, StatusCode::OK, "{records}");
    let (_, data) = widget_data(&app, &admin_cookie, &dashboard, inputs).await;

    let explained: Vec<_> = explanation["filters"].as_array().unwrap().iter()
        .map(|f| json!({ "field": f["field"], "op": f["op"], "value": f["value"], "origin": f["origin"] }))
        .collect();
    let applied: Vec<_> = records["applied_filters"].as_array().unwrap().iter()
        .map(|f| json!({ "field": f["filter"]["field"], "op": f["filter"]["op"], "value": f["filter"]["value"], "origin": f["origin"] }))
        .collect();
    assert_eq!(
        explained, applied,
        "explain and records share one filter list"
    );
    assert_eq!(
        records["definition_fingerprint"],
        data["definition_fingerprint"]
    );
    assert_eq!(
        explanation["definition_fingerprint"],
        data["definition_fingerprint"]
    );

    let structured = &explanation["structured"];
    assert_eq!(structured["measures"][0]["expression"], "SUM(amount)");
    assert_eq!(structured["live_rows_only"], true);
    assert_eq!(structured["access_level"], "global");
    assert_eq!(explanation["timezone"], "UTC");
    let builtin = explanation["filters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["origin"]["kind"] == "builtin")
        .unwrap();
    let own_name: String = sqlx::query_scalar("SELECT user_name FROM user_account WHERE id = $1")
        .bind(admin_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(builtin["value_display"], own_name.as_str());
    assert_eq!(data["structured"]["buckets"][0]["values"][0], 5.0);
    assert_eq!(records["records"]["total"], 1);
}

// ── Phase 3.3: metric lineage ────────────────────────────────────────────────

async fn insert_lineage_metric(
    db: &PgPool,
    key: &str,
    formula: Option<&str>,
    parent: Option<Uuid>,
    weight: Option<f64>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
         (id, name, key, source_kind, formula, direction, period, parent_ref, weight, is_active) \
         VALUES ($1, $2, $3, $4, $5, 'higher_is_better', 'month', $6, $7, true)",
    )
    .bind(id)
    .bind(format!("Metric {key}"))
    .bind(key)
    .bind(if formula.is_some() {
        "formula"
    } else {
        "manual"
    })
    .bind(formula)
    .bind(parent)
    .bind(weight)
    .execute(db)
    .await
    .expect("insert lineage metric");
    id
}

/// Children by `parent_ref` with weights, formula inputs by key with their
/// snapshots, a missing key, and a cycle that is marked, not followed.
#[tokio::test]
async fn metric_lineage_walks_children_formula_inputs_and_stops_at_cycles() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let suffix = Uuid::now_v7().simple().to_string();
    let k = |name: &str| format!("{name}_{suffix}");
    let (a, b) = (k("tickets"), k("sla"));
    let root = insert_lineage_metric(&db, &k("health"), None, None, None).await;
    let child = insert_lineage_metric(
        &db,
        &k("support"),
        Some(&format!("{a} / {b} + {}", k("ghost"))),
        Some(root),
        Some(0.6),
    )
    .await;
    let input_a = insert_lineage_metric(&db, &a, None, None, None).await;
    // A cycle: `sla` is a child of `support`, whose formula already uses `sla`.
    let input_b = insert_lineage_metric(&db, &b, Some(&k("support")), Some(child), Some(0.4)).await;
    insert_snapshot(&db, input_a, "2026-05-01", 12.0).await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/metrics/{root}/lineage?period_start=2026-05-01"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let root_node = &body["root"];
    assert_eq!(root_node["relation"], "root");
    let support = &root_node["children"][0];
    assert_eq!(support["metric_id"], child.to_string());
    assert_eq!(support["weight"], 0.6);
    let kids = support["children"].as_array().unwrap();
    let find = |key: &str| {
        kids.iter()
            .find(|n| n["key"] == key)
            .unwrap_or_else(|| panic!("{key} missing: {support}"))
    };
    assert_eq!(find(&k("ghost"))["missing"], true);
    assert_eq!(find(&a)["relation"], "formula_input");
    assert_eq!(find(&a)["snapshot"]["actual"], 12.0);
    let sla = kids
        .iter()
        .find(|n| n["metric_id"] == input_b.to_string())
        .unwrap();
    let sla_cycle = sla["children"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["metric_id"] == child.to_string())
        .unwrap();
    assert_eq!(
        sla_cycle["cycle"], true,
        "support is an ancestor of sla: {sla}"
    );
    assert!(sla_cycle["children"].as_array().unwrap().is_empty());
}

// ── Phase 3.4: drill-through export ─────────────────────────────────────────

/// An export built from a drill's filters matches the drawer's exact total,
/// including rows whose `is_active` is NULL.
#[tokio::test]
async fn a_drill_export_matches_the_records_total() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    for (status, active) in [
        ("won", Some(true)),
        ("won", None),
        ("won", Some(false)),
        ("open", Some(true)),
    ] {
        insert_deal(
            &db,
            &deals,
            Some(status),
            3.0,
            "2026-05-01T00:00:00Z",
            None,
            active,
        )
        .await;
    }
    let config = json!({ "data": {
        "source": deals,
        "measures": [{ "aggregation": "count" }],
        "group": { "field": "created_at", "bucket": "year" },
        "series": "status"
    }});
    let dashboard = build_data_dashboard(&db, admin_id, &config).await;
    let app = full_app(system);
    publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;

    let (_, data) = widget_data(&app, &admin_cookie, &dashboard, json!({})).await;
    let won = data["structured"]["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["series_key"]["value"] == "won")
        .unwrap()
        .clone();
    let (status, records) = widget_route(
        &app,
        &admin_cookie,
        &dashboard,
        "records",
        json!({ "bucket_key": won["key"], "series_key": won["series_key"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{records}");
    assert_eq!(records["records"]["total"], 2);
    let filters = records["records"]["drill_filters"].clone();
    assert!(
        filters.as_array().is_some_and(|f| !f.is_empty()),
        "{records}"
    );

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{deals}/export"),
            Some(&admin_cookie),
            Some(&json!({ "format": "csv", "columns": [], "filter": filters })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(res).await["matching_rows"], 2);
}

// ── Phase 3.5: health is a publish gate ──────────────────────────────────────

async fn try_publish(
    app: &axum::Router,
    cookie: &str,
    dashboard_id: Uuid,
    db: &PgPool,
) -> (StatusCode, Value) {
    let mut row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(db)
            .await
            .unwrap();
    for step in ["submit-review", "approve"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/{step}"),
                Some(cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        row_version = body_json(res).await["row_version"].as_i64().unwrap();
    }
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/publish"),
            Some(cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    let status = res.status();
    (status, body_json(res).await)
}

/// Each blocking rule refuses publish and names the widget; the health route
/// reports the same issues; a clean dashboard publishes.
#[tokio::test]
async fn publish_refuses_broken_content_and_names_the_widget() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let app = full_app(system);

    // Invalid config.data, written around the write-time validator.
    let bad = json!({ "data": { "source": deals, "measures": [{ "aggregation": "sum", "field": "region" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &bad).await;
    let (status, body) = try_publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let message = body.to_string();
    assert!(
        message.contains("invalid_data_definition")
            && message.contains(&dashboard.widget_id.to_string()),
        "{message}"
    );

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!(
                "/api/v1/attome-dashboard/{}/health-check",
                dashboard.dashboard_id
            ),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    let health = body_json(res).await;
    assert_eq!(health["publishable"], false);
    assert_eq!(
        health["blocking"][0]["widget_id"],
        dashboard.widget_id.to_string()
    );

    // A binding to a parameter the page does not declare.
    let unbound = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }],
        "bindings": [{ "source": "parameter", "name": "nowhere", "field": "status", "op": "eq" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &unbound).await;
    let (status, body) = try_publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body.to_string().contains("undeclared_parameter"), "{body}");

    // A page with no root section.
    let (empty_page_dashboard, _) = insert_dashboard(&db, admin_id, "No section").await;
    insert_page(&db, empty_page_dashboard, "Bare").await;
    let (status, body) = try_publish(&app, &admin_cookie, empty_page_dashboard, &db).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body.to_string().contains("page_without_root_section"),
        "{body}"
    );

    // Clean content publishes, and an unsupported type only warns.
    let good = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }] }});
    let dashboard = build_data_dashboard(&db, admin_id, &good).await;
    sqlx::query("UPDATE dashboard_widget SET widget_type = 'sankey_diagram' WHERE id = $1")
        .bind(dashboard.widget_id)
        .execute(&db)
        .await
        .unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!(
                "/api/v1/attome-dashboard/{}/health-check",
                dashboard.dashboard_id
            ),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    let health = body_json(res).await;
    assert_eq!(health["publishable"], true, "{health}");
    assert_eq!(health["warnings"][0]["code"], "unsupported_widget_type");
    let (status, body) = try_publish(&app, &admin_cookie, dashboard.dashboard_id, &db).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Four-eyes binds the resolved definition: a widget edit after the request
/// invalidates execution; an unchanged draft publishes.
#[tokio::test]
async fn an_approval_executes_only_the_content_that_was_reviewed() {
    let system = skip_if_no_db!(test_system(&["dashboard.publish"]).await);
    let (requester_id, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (deals, _) = provision_deals(&system).await;
    let config = json!({ "data": { "source": deals, "measures": [{ "aggregation": "count" }] }});
    let app = full_app(system);

    let decide = |request_id: String, row_version: i64| {
        let (app, cookie) = (app.clone(), approver_cookie.clone());
        async move {
            let res = app
                .oneshot(req(
                    "POST",
                    &format!("/api/v1/admin/approvals/{request_id}/decide"),
                    Some(&cookie),
                    Some(&json!({ "decision": "approve", "row_version": row_version })),
                ))
                .await
                .unwrap();
            let status = res.status();
            (status, body_json(res).await)
        }
    };

    let changed = build_data_dashboard(&db, requester_id, &config).await;
    let (status, body) = try_publish(&app, &requester_cookie, changed.dashboard_id, &db).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let request_id = body["approval_request_id"].as_str().unwrap().to_owned();
    let edited = json!({ "data": { "source": deals, "measures": [{ "aggregation": "sum", "field": "amount" }] }});
    sqlx::query("UPDATE dashboard_widget SET config = $1 WHERE id = $2")
        .bind(edited.to_string())
        .bind(changed.widget_id)
        .execute(&db)
        .await
        .unwrap();
    let (status, body) = decide(request_id.clone(), 0).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let request_status: String =
        sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1::uuid")
            .bind(&request_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(request_status, "invalidated");
    let versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_version WHERE dashboard_id = $1")
            .bind(changed.dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(versions, 0);

    let unchanged = build_data_dashboard(&db, requester_id, &config).await;
    let (_, body) = try_publish(&app, &requester_cookie, unchanged.dashboard_id, &db).await;
    let request_id = body["approval_request_id"].as_str().unwrap().to_owned();
    let (status, body) = decide(request_id, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["executed"]["dashboard_id"],
        unchanged.dashboard_id.to_string()
    );
}
