//! DB-backed proof test for M01 Core C-12 ("No pool queries inside an open
//! transaction"). Before this change, every write path here acquired a
//! SECOND pool connection while its own mutation transaction was still open
//! on the first: `field_changes_from_obj` (create/update/upsert/bulk),
//! `require_record_access` inside upsert's transaction (after its own
//! `FOR UPDATE` conflict precheck), and `load_survivorship_rules`/the
//! per-dependent access resolution inside merge. Under normal pool headroom
//! that second acquire is merely wasteful (extra round trips); under pool
//! *saturation* — every connection already checked out, each one waiting on
//! a second that some other request in the same fix-needing shape also
//! needs — it self-deadlocks.
//!
//! This suite builds a real `EngineState` whose `state.base.db` pool is pinned
//! to exactly ONE connection (`attome_testkit::single_connection_pool`, the
//! attome-testkit helper this item adds) and drives the create/update/upsert/
//! merge/bulk happy paths against it. With only one connection ever
//! available, any remaining "second connection while the first is held"
//! defect is not probabilistic — it is the very first thing that happens,
//! and the call hangs until `sqlx`'s acquire timeout gives up. A pass here
//! is proof every path below completes a full mutation transaction without
//! ever asking this pool for a connection it cannot have.
//!
//! Same harness shape as `tests/upsert.rs`/`tests/mutation_ring.rs` next door
//! (D-343: one throwaway database per test binary) — a real `EngineState`
//! against a real Postgres, not a mock.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-records --test pool_saturation -- --test-threads=1
//! ```

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{HashMap, HashSet};

use attome_auth::{SessionClaims, TokenType};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_records::entity_crud::{create_record_for, do_merge_core, update_record_for};
use attome_server::AppState;
use attome_server::authz::AuthorizedContext;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

/// Same shape `tests/mutation_ring.rs`/`tests/upsert.rs::test_config` use —
/// this suite needs the identical infra (Postgres + Redis + storage) a full
/// `EngineState` requires. `database.connection_number` is irrelevant here: the
/// actual pool this suite drives every mutation against comes from
/// `attome_testkit::single_connection_pool` in `test_state` below, not from
/// `attome_db::create_pool(&config)`.
fn test_config(direct_url: &str) -> AppConfig {
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
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 1, "timeout": 5.0,
                "direct_url": "{direct_url}"
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
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
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
        direct_url = direct_url,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

// SAFETY: see `attome-ai/tests/record_update_field.rs`'s identical `ENV_LOCK`
// doc comment — `attome_db::create_pool`/`attome_testkit::test_db_url` read
// `DATABASE_URL`/`APP_ENV` from the environment synchronously before their
// first `.await`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `attome_audit::seed` (every write audits itself), `attome_metadata::autovalue::seed`
/// (`create_one` reads auto value rules from `autovalue`), and
/// `attome_security::seed_for_tests` (the `system.admin` privilege row this
/// suite's bulk step grants to its test user — `bulk::process` resolves a
/// caller's `SecurityContext` straight from Postgres, unlike every other path
/// here, which is handed a synthetic admin `SecurityContext` directly).
async fn seed_platform(db: &attome_db::DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            attome_audit::seed(db)
                .await
                .expect("seed audit entity metadata");
            attome_metadata::autovalue::seed_for_tests(db)
                .await
                .expect("seed autovalue entity + table");
            attome_security::seed::seed_for_tests(db)
                .await
                .expect("seed attome-security platform bundle (privileges incl. system.admin)");
        })
        .await;
}

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url);
    // M01 Core C-12: this is the whole point of this suite — `state.base.db`
    // (and its readonly/migrator clones, same handle) has exactly one
    // connection, via the new `attome_testkit::single_connection_pool` helper,
    // not `attome_db::create_pool(&config)`. See that helper's doc comment.
    let db = attome_testkit::single_connection_pool()
        .await
        .expect("test_db_url already confirmed a database is configured");
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
    seed_platform(&db).await;
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
    Some(EngineState::new(base))
}

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("pool-saturation-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Grants `system.admin` directly, the same shape
/// `attome-server/tests/bulk_mutation.rs::seed_user(system, true)` uses — needed
/// only for this suite's bulk step, whose `bulk::process` re-resolves the
/// caller's `SecurityContext` from Postgres rather than accepting the
/// synthetic one every other step in this file uses.
async fn grant_admin(db: &attome_db::DbPool, user_id: Uuid) {
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect(
                "system.admin privilege must already be seeded by attome_security::seed_for_tests",
            );
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

/// Never gated by any privilege check below (`is_admin` short-circuits every
/// `require`/`rls_predicate`/`resolve_entity_access_level` call the direct-call
/// paths make) — this suite proves the mutation call graph's pool usage, not
/// its authorization matrix (already covered by `record_level_security.rs`
/// and friends).
fn admin_context(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: true,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

/// A throwaway entity with one plain text field — this suite only needs a
/// row to exist and a field to write, not any particular field type.
async fn provision_test_entity(state: &EngineState) -> String {
    let logicalname = format!("c12_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "M01 Core C-12 Pool Saturation Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "title",
        "Title",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision title attribute");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    logicalname
}

fn upsert_request(entity: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{entity}/upsert"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("serialize body"),
        ))
        .expect("build request")
}

/// Sends `req` through the real route, with the same `AuthorizedContext` /
/// `SessionClaims` extensions the production authn/authz middleware would
/// have attached — same substitute `tests/upsert.rs`'s module doc comment
/// explains.
async fn send(
    state: &EngineState,
    user_id: Uuid,
    mut req: Request<Body>,
) -> axum::response::Response {
    req.extensions_mut()
        .insert(AuthorizedContext::new(Arc::new(admin_context(user_id))));
    req.extensions_mut().insert(SessionClaims {
        sub: user_id,
        iat: 0,
        exp: i64::MAX,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: "attome-test".into(),
        aud: "attome-test".into(),
        typ: TokenType::Session,
    });
    attome_records::entity_crud::routes()
        .with_state(state.clone())
        .oneshot(req)
        .await
        .expect("router call")
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("parse response body as JSON")
}

/// M01 Core C-12 proof: create, update, upsert (both its insert AND its
/// `FOR UPDATE`-then-update branch), merge, and bulk-create each complete
/// against a pool that can never hand out a second connection while any of
/// them holds the first. Before this item's fix, every one of these hung
/// (blocking on `sqlx`'s pool-acquire timeout, then erroring) the moment it
/// reached its own mid-transaction pool query.
#[tokio::test]
async fn create_update_upsert_merge_bulk_succeed_under_a_single_connection_pool() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    grant_admin(&state.base.db, user_id).await;
    let ctx = admin_context(user_id);
    let entity = provision_test_entity(&state).await;

    // ── create (mutations.rs::create_record_for) ───────────────────────────
    // Before C-12: `field_changes_from_obj` ran against `state.base.db`
    // while `create_one`'s own transaction was still open.
    let (record_id, created) =
        create_record_for(&state, &ctx, user_id, &entity, json!({ "title": "create" }))
            .await
            .expect("create must not hang/fail under a 1-connection pool");
    let created_json = serde_json::to_value(&created).expect("serialize create response");
    let row_version = created_json["row_version"]
        .as_i64()
        .expect("create response must carry row_version");

    // ── update (mutations.rs::update_record_for) ────────────────────────────
    // Same `field_changes_from_obj` defect, this time diffing against
    // `mutation.old_row`.
    let updated = update_record_for(
        &state,
        &ctx,
        user_id,
        &entity,
        record_id,
        row_version,
        json!({ "title": "update" }),
    )
    .await
    .expect("update must not hang/fail under a 1-connection pool");
    let updated_json = serde_json::to_value(&updated).expect("serialize update response");
    assert_eq!(updated_json["data"]["title"].as_str(), Some("update"));

    // ── upsert: insert branch, then the FOR-UPDATE/update branch ────────────
    // (entity_crud/upsert.rs::upsert_record) — `upsert_record` has no direct-
    // call counterpart (see `tests/upsert.rs`'s own doc comment), so this
    // drives the real route. Before C-12: the insert branch's own
    // `field_changes_from_obj` call, and — on the second call below — both
    // `require_record_access` (right after the `FOR UPDATE` conflict
    // precheck) and `field_changes_from_obj` again, all ran against
    // `state.base.db` from inside the open upsert transaction.
    let upsert_key = format!("upsert-{}", Uuid::now_v7());
    let first_upsert = send(
        &state,
        user_id,
        upsert_request(&entity, json!({ "match": { "title": upsert_key } })),
    )
    .await;
    assert_eq!(
        first_upsert.status(),
        StatusCode::CREATED,
        "upsert-insert must not hang/fail under a 1-connection pool"
    );
    let first_upsert_body = body_json(first_upsert).await;
    let upsert_record_id: Uuid = first_upsert_body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("upsert-insert response must carry an id");
    let upsert_row_version = first_upsert_body["row_version"]
        .as_i64()
        .expect("upsert-insert response must carry row_version");

    let second_upsert = send(
        &state,
        user_id,
        upsert_request(
            &entity,
            json!({
                "match": { "title": upsert_key },
                "row_version": upsert_row_version
            }),
        ),
    )
    .await;
    let second_status = second_upsert.status();
    let second_body = body_json(second_upsert).await;
    assert_eq!(
        second_status,
        StatusCode::OK,
        "upsert's conflict/update branch must not hang/fail under a 1-connection pool: {second_body}"
    );
    let second_upsert_body = second_body;
    assert_eq!(
        second_upsert_body["id"]
            .as_str()
            .and_then(|s| s.parse::<Uuid>().ok()),
        Some(upsert_record_id),
        "the conflict branch must update the same row, not insert a duplicate"
    );

    // ── merge (entity_crud/merge.rs::do_merge_core) ─────────────────────────
    // Before C-12: `load_survivorship_rules` ran unconditionally against
    // `state.base.db` from inside the merge's own open transaction.
    let (canonical_id, _) = create_record_for(
        &state,
        &ctx,
        user_id,
        &entity,
        json!({ "title": "merge-canonical" }),
    )
    .await
    .expect("merge canonical create must not hang/fail under a 1-connection pool");
    let (duplicate_id, _) = create_record_for(
        &state,
        &ctx,
        user_id,
        &entity,
        json!({ "title": "merge-duplicate" }),
    )
    .await
    .expect("merge duplicate create must not hang/fail under a 1-connection pool");
    do_merge_core(
        &state,
        &ctx,
        &entity,
        canonical_id,
        duplicate_id,
        user_id,
        None,
    )
    .await
    .expect("merge must not hang/fail under a 1-connection pool");

    // ── bulk create (bulk.rs::process -> apply_one) ─────────────────────────
    // Before C-12: `field_changes_from_obj` ran against `state.base.db` from
    // inside `apply_one`'s own open transaction, exactly like create/update
    // above. `process` re-resolves its caller's `SecurityContext` straight
    // from Postgres (`grant_admin` above is what makes that resolve as
    // admin) rather than accepting the synthetic one every other step here
    // uses. The parent ledger row is inserted directly (guidelines §4's
    // "tests against a throwaway database" exemption) rather than through
    // the HTTP enqueue route, since `process` only needs that row to exist —
    // it manages its own item ledger idempotently.
    let bulk_op_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO automation_bulk_operation \
         (id, entity_logicalname, operation, status, total, created_by) \
         VALUES ($1, $2, 'create', 'pending', 1, $3)",
    )
    .bind(bulk_op_id)
    .bind(&entity)
    .bind(user_id)
    .execute(&state.base.db)
    .await
    .expect("insert throwaway bulk operation ledger row");

    attome_records::bulk::process(
        &state,
        bulk_op_id,
        &entity,
        "create",
        vec![json!({ "data": { "title": "bulk-create" } })],
        user_id,
    )
    .await
    .expect("bulk create must not hang/fail under a 1-connection pool");

    let bulk_status: String =
        sqlx::query_scalar("SELECT status FROM automation_bulk_operation WHERE id = $1")
            .bind(bulk_op_id)
            .fetch_one(&state.base.db)
            .await
            .expect("bulk operation row must exist");
    assert_eq!(
        bulk_status, "completed",
        "bulk create must reach 'completed', not stall partway through"
    );
    let (item_status, item_record_id): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, record_id FROM automation_bulk_operation_item \
         WHERE bulk_operation_id = $1 AND item_index = 0",
    )
    .bind(bulk_op_id)
    .fetch_one(&state.base.db)
    .await
    .expect("bulk operation item row must exist");
    assert_eq!(item_status, "succeeded");
    assert!(item_record_id.is_some());
}
