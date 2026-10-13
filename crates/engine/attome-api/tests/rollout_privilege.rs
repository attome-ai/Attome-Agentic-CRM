//! D-792 (`document/general/FLEET-CONSOLE-DESIGN.md` 5.3, lane FC-A): the
//! fleet console's rollout credential on a customer server.
//!
//! A user holding only the platform **Rollout operator** role
//! (`metadata.rollout`) reaches every route the console calls (changeset
//! plan/apply/ledger, the release-report reads and item decisions, the
//! rollout status, its own approval request) and is refused (403) on a sample
//! of every other admin and record surface. Administrators still pass every
//! changed route. An apply request the rollout user opens is readable only by
//! it (and admins) and can never be approved by it. Conflict values it reads
//! are audited under it. The status call never carries values or secrets.
//!
//! Harness copied from `changeset_routes.rs`; direct SQL only seeds users,
//! role assignments and release-report items in the throwaway test database
//! (coding-guidelines.md section 4's test exemption).
//!
//! Requires a live Postgres (`DATABASE_URL`, migrated through the release
//! report tables) and Redis:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test rollout_privilege -- --test-threads=1
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &url);
    // Conflict values are sealed under this ring (as an apply seals them),
    // and a changeset apply is approval-gated, as on a production server.
    config.metadata.recovery_archive_key_encryption_key = KeyRing::single("12".repeat(32));
    config.approval.required_actions =
        vec![attome_api::changeset::ACTION_CHANGESET_APPLY.to_owned()];
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
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));
    Some(system)
}

#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
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

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("rollout-test-admin-{user_id}"))
    .bind(format!("cs-{user_id}@test.local"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded");
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
    if_match: Option<i64>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(v) = if_match {
        builder = builder.header("if-match", format!("\"{v}\""));
    }
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    builder.body(body).expect("request")
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

// ── Rollout-specific fixtures ───────────────────────────────────────────────

fn unique(prefix: &str) -> String {
    let hex = Uuid::now_v7().simple().to_string();
    format!("{prefix}_{}", &hex[hex.len() - 10..])
}

/// A user holding only the platform **Rollout operator** role, as the
/// onboarding runbook creates `attome-rollout` (no password, no direct
/// privilege). Cookie-authenticated here; an S2S client bound to the same
/// user resolves to the same roles (`attome-s2s` middleware, D-766), which
/// `tests/s2s.rs` proves for the transport.
async fn seed_rollout(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("attome-rollout-{user_id}"))
    .bind(format!("rollout-{user_id}@test.local"))
    .execute(db)
    .await
    .expect("insert throwaway rollout user");
    let role_id: Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(attome_security::rollout::ROLLOUT_OPERATOR_ROLE)
            .fetch_one(db)
            .await
            .expect(
                "the Rollout operator platform role must be seeded \
                 (platform-bundles/attome-security.json)",
            );
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign the Rollout operator role");
    (user_id, session_cookie(user_id))
}

/// A release-report item of `kind` in a standalone report; returns its id.
async fn report_item(
    state: &EngineState,
    kind: attome_core::release_report::ItemKind,
    entity: &str,
    record_id: Option<Uuid>,
    values: Option<attome_core::release_report::ConflictValues>,
) -> Uuid {
    use attome_core::release_report as rr;
    let ring = attome_core::recovery_archive::ring(state.base.config.as_ref());
    let mut tx = attome_db::tx::begin(&state.base.db).await.expect("begin");
    let report = rr::insert_items(
        &mut tx,
        ring,
        vec![rr::NewItem {
            kind,
            entity: entity.to_owned(),
            field: Some("title".to_owned()),
            record_id,
            object_kind: None,
            object_ref: None,
            detail: json!({ "rollout_privilege": true }),
            values,
            op: None,
        }],
        "rollout privilege test",
    )
    .await
    .expect("insert the item")
    .expect("a report");
    attome_db::tx::commit(tx).await.expect("commit");
    sqlx::query_scalar("SELECT id FROM release_report_item WHERE report_ref = $1")
        .bind(report)
        .fetch_one(&state.base.db)
        .await
        .expect("item id")
}

fn conflict_values(theirs: &str, ours: &str) -> attome_core::release_report::ConflictValues {
    attome_core::release_report::ConflictValues {
        theirs: json!(theirs),
        ours: json!(ours),
        key: None,
    }
}

fn id_of(v: &Value) -> Uuid {
    v["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("response has no id: {v}"))
}

/// A throwaway entity with a plain `title` text field and one record, made
/// by the administrator through the admin and entity APIs; returns
/// `(entity logical name, record id, record row_version)`.
async fn entity_with_record(system: &TestSystem, admin: &str, title: &str) -> (String, Uuid, i64) {
    let entity = unique("rollout_e");
    let (status, created) = send(
        &system.app,
        request(
            "POST",
            "/api/v1/admin/entities",
            admin,
            None,
            Some(json!({ "logicalname": entity, "name": "Rollout privilege test" })),
        ),
    )
    .await;
    assert!(status.is_success(), "create entity: {status} {created}");
    let entity_id = id_of(&created);
    let (status, field) = send(
        &system.app,
        request(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin,
            None,
            Some(json!({ "logicalname": "title", "name": "Title", "field_type": "text" })),
        ),
    )
    .await;
    assert!(status.is_success(), "add field: {status} {field}");
    let registry = attome_core::build_registry(&system.state.base.db)
        .await
        .expect("build metadata registry");
    system.state.entities.swap(registry);
    let (status, record) = send(
        &system.app,
        request(
            "POST",
            &format!("/api/v1/{entity}"),
            admin,
            None,
            Some(json!({ "title": title })),
        ),
    )
    .await;
    assert!(status.is_success(), "create record: {status} {record}");
    let record_id = id_of(&record);
    let row_version: i64 = sqlx::query_scalar(&format!(
        "SELECT row_version FROM {} WHERE id = $1",
        attome_core::quote_ident(&entity)
    ))
    .bind(record_id)
    .fetch_one(&system.state.base.db)
    .await
    .expect("record row_version");
    (entity, record_id, row_version)
}

/// One probe: method, uri, JSON body, `If-Match` row_version.
type Probe = (&'static str, String, Option<Value>, Option<i64>);

/// Every route the console calls, with a request that passes authorization
/// and then answers from the handler (a 404 for an id that does not exist
/// is the handler talking, not the policy).
fn rollout_route_probes() -> Vec<Probe> {
    let missing = Uuid::now_v7();
    vec![
        (
            "GET",
            "/api/v1/admin/metadata/rollout/status".into(),
            None,
            None,
        ),
        (
            "GET",
            "/api/v1/admin/metadata/changesets/ledger".into(),
            None,
            None,
        ),
        (
            "GET",
            format!("/api/v1/admin/metadata/changesets/ledger/{missing}"),
            None,
            None,
        ),
        (
            "POST",
            "/api/v1/admin/metadata/changesets/apply".into(),
            Some(json!({ "apply_ids": [missing], "phase": "expand", "backup_ref": "snap-1" })),
            None,
        ),
        (
            "GET",
            "/api/v1/admin/metadata/release-reports".into(),
            None,
            None,
        ),
        (
            "GET",
            "/api/v1/admin/metadata/release-reports/summary".into(),
            None,
            None,
        ),
        (
            "GET",
            format!("/api/v1/admin/metadata/release-reports/{missing}"),
            None,
            None,
        ),
        (
            "GET",
            format!("/api/v1/admin/metadata/release-reports/{missing}/items"),
            None,
            None,
        ),
        (
            "POST",
            format!("/api/v1/admin/metadata/release-report-items/{missing}/accept"),
            None,
            Some(0),
        ),
        (
            "POST",
            format!("/api/v1/admin/metadata/release-report-items/{missing}/use-mine"),
            Some(json!({ "record_row_version": 0 })),
            Some(0),
        ),
        (
            "POST",
            format!("/api/v1/admin/metadata/release-report-items/{missing}/dismiss"),
            None,
            Some(0),
        ),
        (
            "POST",
            format!("/api/v1/admin/metadata/release-report-items/{missing}/restore"),
            None,
            None,
        ),
        (
            "GET",
            format!("/api/v1/admin/approvals/{missing}"),
            None,
            None,
        ),
    ]
}

fn sorted_keys(v: &Value) -> Vec<String> {
    let mut keys: Vec<String> = v
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {v}"))
        .keys()
        .cloned()
        .collect();
    keys.sort_unstable();
    keys
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn the_rollout_operator_role_holds_only_metadata_rollout() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT p.key FROM role r \
               JOIN role_mm_privilege rp ON rp.role_ref = r.id AND rp.is_deleted = false \
               JOIN privilege p ON p.id = rp.privilege_ref AND p.is_active = true \
              WHERE r.name = $1 AND r.is_deleted = false ORDER BY p.key",
        )
        .bind(attome_security::rollout::ROLLOUT_OPERATOR_ROLE)
        .fetch_all(&system.state.base.db)
        .await
        .expect("role privileges");
        assert_eq!(
            keys,
            vec![attome_security::METADATA_ROLLOUT_PRIVILEGE_KEY.to_owned()]
        );
        let layer: String = sqlx::query_scalar(
            "SELECT owner_layer FROM role WHERE name = $1 AND is_deleted = false",
        )
        .bind(attome_security::rollout::ROLLOUT_OPERATOR_ROLE)
        .fetch_one(&system.state.base.db)
        .await
        .expect("role owner layer");
        assert_eq!(layer, "platform");
    });
}

#[test]
fn the_rollout_user_reaches_every_rollout_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, rollout) = seed_rollout(&system.state.base.db).await;
        for (method, uri, body, if_match) in rollout_route_probes() {
            let (status, answer) = send(
                &system.app,
                request(method, &uri, &rollout, if_match, body.clone()),
            )
            .await;
            assert!(
                status != StatusCode::FORBIDDEN && status != StatusCode::UNAUTHORIZED,
                "{method} {uri}: the rollout credential must pass, got {status} {answer}"
            );
            assert!(
                status != StatusCode::INTERNAL_SERVER_ERROR,
                "{method} {uri}: {status} {answer}"
            );
        }

        // Plan: an empty document list is the handler's 422 ("at least one
        // document"), reached only past the policy.
        let (status, answer) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/metadata/changesets/plan",
                &rollout,
                None,
                Some(json!({ "changesets": [] })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "plan: {answer}");
    });
}

#[test]
fn admins_still_pass_every_changed_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system.state.base.db).await;
        for (method, uri, body, if_match) in rollout_route_probes() {
            let (status, answer) = send(
                &system.app,
                request(method, &uri, &admin, if_match, body.clone()),
            )
            .await;
            assert!(
                status != StatusCode::FORBIDDEN && status != StatusCode::UNAUTHORIZED,
                "{method} {uri}: an administrator must pass, got {status} {answer}"
            );
        }
    });
}

#[test]
fn the_rollout_user_is_refused_everywhere_else() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (rollout_id, rollout) = seed_rollout(&system.state.base.db).await;
        let some_id = Uuid::now_v7();
        let refused: Vec<(&str, String, Option<Value>)> = vec![
            ("GET", "/api/v1/admin/entities".into(), None),
            (
                "POST",
                "/api/v1/admin/entities".into(),
                Some(json!({ "logicalname": unique("nope"), "name": "Nope" })),
            ),
            ("GET", "/api/v1/admin/security/roles".into(), None),
            ("GET", "/api/v1/admin/security/users".into(), None),
            (
                "GET",
                "/api/v1/admin/security/users/lookup?email=rollout".into(),
                None,
            ),
            ("GET", "/api/v1/admin/s2s/clients".into(), None),
            ("GET", "/api/v1/admin/approvals".into(), None),
            (
                "POST",
                format!("/api/v1/admin/approvals/{some_id}/decide"),
                Some(json!({ "decision": "approve", "row_version": 0 })),
            ),
            (
                "POST",
                format!("/api/v1/admin/approvals/{some_id}/cancel"),
                Some(json!({ "row_version": 0 })),
            ),
            (
                "POST",
                "/api/v1/admin/metadata/changesets/adopt".into(),
                Some(json!({ "changesets": [] })),
            ),
            ("GET", "/api/v1/admin/changesets".into(), None),
            // Records: the role holds no entity privilege at all.
            ("GET", format!("/api/v1/user_account/{rollout_id}"), None),
            (
                "POST",
                "/api/v1/team".into(),
                Some(json!({ "name": unique("team") })),
            ),
        ];
        for (method, uri, body) in refused {
            let (status, answer) =
                send(&system.app, request(method, &uri, &rollout, None, body)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {uri}: the rollout credential must be refused: {answer}"
            );
        }
    });
}

#[test]
fn the_rollout_user_reads_and_decides_release_report_items_audited() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system.state.base.db).await;
        let (rollout_id, rollout) = seed_rollout(&system.state.base.db).await;
        let state = &system.state;

        // A real record conflict: the customer's value is live, ours sealed.
        let (entity, record_id, row_version) =
            entity_with_record(&system, &admin, "customer title").await;
        let item = report_item(
            state,
            attome_core::release_report::ItemKind::Conflict,
            &entity,
            Some(record_id),
            Some(conflict_values("customer title", "our title")),
        )
        .await;
        let report: Uuid =
            sqlx::query_scalar("SELECT report_ref FROM release_report_item WHERE id = $1")
                .bind(item)
                .fetch_one(&state.base.db)
                .await
                .expect("report of the item");

        // The read decrypts the conflict values for the rollout principal
        // and writes one Security/Export event attributed to it.
        let (status, items) = send(
            &system.app,
            request(
                "GET",
                &format!("/api/v1/admin/metadata/release-reports/{report}/items"),
                &rollout,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{items}");
        let view = &items["items"][0];
        assert_eq!(view["values"]["theirs"], "customer title", "{items}");
        assert_eq!(view["values"]["ours"], "our title", "{items}");
        assert_eq!(view["values_hidden"], false);
        let reads: i64 = sqlx::query_scalar(
            // audit.chainer_enabled defaults on (D-316): events land in the
            // ingest queue first.
            "SELECT COUNT(*) FROM audit_ingest \
              WHERE payload->>'category' = 'Security' AND payload->>'operation' = 'Export' \
                AND payload->'user_context'->>'user_id' = $1 \
                AND payload->>'entity_name' = 'release_report_item'",
        )
        .bind(rollout_id.to_string())
        .fetch_one(&state.base.db)
        .await
        .expect("count value-read events");
        assert_eq!(
            reads, 1,
            "one audited read of conflict values by the rollout user"
        );

        // Use mine: our value is written through the engine under the
        // rollout principal's own context, compare-first on row_version.
        let (status, decided) = send(
            &system.app,
            request(
                "POST",
                &format!("/api/v1/admin/metadata/release-report-items/{item}/use-mine"),
                &rollout,
                Some(0),
                Some(json!({ "record_row_version": row_version })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{decided}");
        assert_eq!(decided["status"], "used_mine");
        assert_eq!(decided["decided_by"], json!(rollout_id));
        let title: Option<String> = sqlx::query_scalar(&format!(
            "SELECT title FROM {} WHERE id = $1",
            attome_core::quote_ident(&entity)
        ))
        .bind(record_id)
        .fetch_one(&state.base.db)
        .await
        .expect("record title");
        assert_eq!(title.as_deref(), Some("our title"));

        // Accept and Dismiss on fresh items.
        let accept = report_item(
            state,
            attome_core::release_report::ItemKind::Conflict,
            &entity,
            Some(record_id),
            Some(conflict_values("theirs", "ours")),
        )
        .await;
        let (status, accepted) = send(
            &system.app,
            request(
                "POST",
                &format!("/api/v1/admin/metadata/release-report-items/{accept}/accept"),
                &rollout,
                Some(0),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
        assert_eq!(accepted["status"], "accepted");

        let dismiss = report_item(
            state,
            attome_core::release_report::ItemKind::BreakingApiChange,
            &entity,
            None,
            None,
        )
        .await;
        let (status, dismissed) = send(
            &system.app,
            request(
                "POST",
                &format!("/api/v1/admin/metadata/release-report-items/{dismiss}/dismiss"),
                &rollout,
                Some(0),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{dismissed}");
        assert_eq!(dismissed["status"], "dismissed");

        // Each decision wrote its own event under the rollout user, on the
        // item it decided (D-542).
        let decisions: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT payload->>'record_id') FROM audit_ingest \
              WHERE payload->'user_context'->>'user_id' = $1 \
                AND payload->>'entity_name' = 'release_report_item' \
                AND payload->>'record_id' = ANY($2)",
        )
        .bind(rollout_id.to_string())
        .bind(vec![
            item.to_string(),
            accept.to_string(),
            dismiss.to_string(),
        ])
        .fetch_one(&state.base.db)
        .await
        .expect("count decision events");
        assert_eq!(decisions, 3, "three audited decisions");
    });
}

#[test]
fn a_rollout_apply_request_is_readable_by_its_requester_only_and_never_self_approved() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system.state.base.db).await;
        let (rollout_id, rollout) = seed_rollout(&system.state.base.db).await;
        let (_, other_rollout) = seed_rollout(&system.state.base.db).await;

        // The request an approval-gated apply opens for its requester (the
        // apply route runs this same gate after its ledger checks).
        let request_row = attome_audit::approval::gate(
            &system.state,
            attome_api::changeset::ACTION_CHANGESET_APPLY,
            json!({ "apply_ids": [Uuid::now_v7()], "phase": "expand", "backup_ref": "snap-1" }),
            rollout_id,
        )
        .await
        .expect("gate")
        .expect("metadata.changeset_apply is approval-gated in this harness");
        let uri = format!("/api/v1/admin/approvals/{}", request_row.id);

        let (status, own) = send(&system.app, request("GET", &uri, &rollout, None, None)).await;
        assert_eq!(status, StatusCode::OK, "{own}");
        assert_eq!(own["requested_by"], json!(rollout_id));
        assert_eq!(own["status"], "pending");

        // Another rollout principal cannot see it (404, not 403).
        let (status, body) = send(
            &system.app,
            request("GET", &uri, &other_rollout, None, None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // The rollout user cannot decide it over HTTP (admin-only route) ...
        let (status, body) = send(
            &system.app,
            request(
                "POST",
                &format!("{uri}/decide"),
                &rollout,
                None,
                Some(json!({ "decision": "approve", "row_version": request_row.row_version })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        // ... and the approval primitive refuses the requester itself
        // (separation of duties).
        let refused = attome_approval::decide(
            &system.state.base.db,
            request_row.id,
            rollout_id,
            attome_approval::Decision::Approve,
            request_row.row_version,
        )
        .await;
        assert!(
            matches!(refused, Err(attome_types::AppError::Forbidden)),
            "self-approval must be refused: {refused:?}"
        );

        // The status call counts it as waiting for a human.
        let (status, live) = send(
            &system.app,
            request(
                "GET",
                "/api/v1/admin/metadata/rollout/status",
                &rollout,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{live}");
        assert!(
            live["pending_approvals"].as_i64().unwrap_or(0) >= 1,
            "{live}"
        );

        // An administrator sees it and closes it (reject: nothing to run).
        let (status, seen) = send(&system.app, request("GET", &uri, &admin, None, None)).await;
        assert_eq!(status, StatusCode::OK, "{seen}");
        let (status, body) = send(
            &system.app,
            request(
                "POST",
                &format!("{uri}/decide"),
                &admin,
                None,
                Some(json!({ "decision": "reject", "row_version": seen["row_version"] })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}

#[test]
fn the_rollout_status_carries_no_values_or_secrets() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, rollout) = seed_rollout(&system.state.base.db).await;
        // A sealed conflict exists, so a leak would have something to leak.
        report_item(
            &system.state,
            attome_core::release_report::ItemKind::Conflict,
            "rollout_status_probe",
            Some(Uuid::now_v7()),
            Some(conflict_values("secret-theirs-value", "secret-ours-value")),
        )
        .await;
        let (status, live) = send(
            &system.app,
            request(
                "GET",
                "/api/v1/admin/metadata/rollout/status",
                &rollout,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{live}");
        assert_eq!(
            sorted_keys(&live),
            [
                "application_version",
                "configuration_version",
                "ledger_head",
                "pending_approvals",
                "ready",
                "release_report",
                "schema_version",
            ]
        );
        assert_eq!(
            sorted_keys(&live["release_report"]),
            [
                "building",
                "by_kind",
                "last_release_at",
                "last_report_id",
                "open_items",
            ]
        );
        assert!(live["ready"].is_boolean());
        let heads = live["ledger_head"].as_array().expect("ledger_head");
        for head in heads {
            assert_eq!(
                sorted_keys(head),
                [
                    "changeset_id",
                    "last_applied_seq",
                    "layer",
                    "phase",
                    "ref",
                    "scope",
                    "seq",
                    "status",
                ]
            );
        }
        assert!(live["release_report"]["open_items"].as_i64().unwrap_or(0) >= 1);
        let text = live.to_string();
        for leak in [
            "secret-theirs-value",
            "secret-ours-value",
            "values_enc",
            "password",
            "secret_hash",
        ] {
            assert!(
                !text.contains(leak),
                "the status must not carry {leak}: {text}"
            );
        }
    });
}
