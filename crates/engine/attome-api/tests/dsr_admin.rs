//! P-data-protection-governance §4/§6 — live-database HTTP coverage for
//! `dsr_admin.rs`, closing D-266's own disclosed gap: "not attempted here:
//! building a full `test_system()`-shaped HTTP harness for this module...
//! only the lower-layer primitives (`record_is_held`, `destroy_key`/
//! `scrub_record`'s hold refusal) are covered." Drives the real HTTP surface
//! (`dsr_admin::routes()`, mounted in `system.rs` behind `strict_authz`, same
//! as `approval_erasure.rs`'s pattern for another `strict_authz`-gated admin
//! module) rather than calling module-private handler functions directly.
//!
//! Covers the plan's own §6 acceptance criteria verbatim:
//! - "a DSR access request produces a correctly-scoped cross-entity export"
//! - "a DSR erasure request against a held record is rejected with the hold
//!   as the reported reason"
//!
//! Plus one additional happy-path erasure test (no hold) for basic
//! regression coverage of the D-107 `destroy_key` call path, matching the
//! "money-path features get the same treatment" testing convention.
//!
//! Requires a live Postgres (`DATABASE_URL`, `APP_ENV=debug` so
//! `attome_db::create_pool` honors it), Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), and a reachable object store matching `test_config`'s
//! `storage` block (same RustFS/MinIO instance `retention.rs`'s
//! `partition_archive` tests already require) — see `db-and-migrations`/
//! `testing` skills. `DATABASE_URL`'s target schema must already have
//! migration 0088 applied (`legal_hold`/`dsr_request`).
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3D<migrated_schema>"
//! cargo test -p attome-api --test dsr_admin -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::{EngineState, build_registry};
use attome_metadata::provision::{ensure_attribute, ensure_entity};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `audit.chainer_enabled` is pinned false (D-316 made true the code
/// default): this suite asserts `audit_header` rows exist immediately
/// after the mutation that produced them, which is the synchronous path's
/// guarantee. On the cutover path those rows only appear once the separate
/// `audit_chainer` process drains `audit_ingest`, and nothing starts it
/// here.
fn test_config(required_actions: &[&str]) -> AppConfig {
    let required_actions_json = serde_json::to_string(required_actions).unwrap();
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
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
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}",
                "s3_secret_key": "{s3_secret_key}",
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
            "approval": {{ "required_actions": {required_actions_json} }},
            "audit": {{ "chainer_enabled": false }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        // See `retention.rs`'s note on the same two lines: `TEST_S3_*` is set
        // by nothing in this repo, so the `"test"` fallback silently signed
        // every real upload with a credential RustFS rejects (403
        // InvalidAccessKeyId). `S3_ACCESS_KEY`/`S3_SECRET_KEY` are what
        // `scripts/run-integration-tests.ps1` actually exports.
        s3_access_key = attome_testkit::s3_env("S3_ACCESS_KEY"),
        s3_secret_key = attome_testkit::s3_env("S3_SECRET_KEY"),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(required_actions: &[&str]) -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    attome_testkit::s3_or_skip()?;
    let mut config = test_config(required_actions);
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

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("dsr-admin-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

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

/// Provisions a throwaway entity with a single `email` TEXT attribute (the
/// `match_attribute` every scope in this file uses) and refreshes the
/// arc-swap registry synchronously — `state.entities.load()` otherwise only
/// knows about entities that existed when `EngineSystem::build()` ran, same
/// caveat `retention.rs::propose_approve_execute_purges_a_record_...`
/// documents at its own call site.
async fn provision_test_entity(state: &EngineState, prefix: &str) -> String {
    let db = &state.base.db;
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(db, &logicalname, "DSR Test Entity", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        db, entity_id, "email", "Email", "text", false, false, false, true, None, None,
    )
    .await
    .expect("ensure_attribute email");

    let fresh_registry = build_registry(db).await.expect("build_registry");
    state.entities.swap(fresh_registry);
    logicalname
}

async fn seed_record(db: &attome_db::DbPool, logicalname: &str, email: &str) -> Uuid {
    let record_id = Uuid::now_v7();
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (id, email, is_active, created_at, modified_at) \
         VALUES ($1, $2, true, NOW(), NOW())"
    ))
    .bind(record_id)
    .bind(email)
    .execute(db)
    .await
    .expect("seed a test record");
    record_id
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn create_dsr_request(
    admin_cookie: &str,
    subject_reference: &str,
    request_type: &str,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/admin/dsr/requests")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({
                "subject_reference": subject_reference,
                "request_type": request_type,
            })
            .to_string(),
        ))
        .unwrap()
}

fn fulfill_request(admin_cookie: &str, id: Uuid, kind: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/dsr/requests/{id}/fulfill-{kind}"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn decide_request(
    admin_cookie: &str,
    request_id: Uuid,
    decision: &str,
    row_version: i64,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/approvals/{request_id}/decide"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "decision": decision, "row_version": row_version }).to_string(),
        ))
        .unwrap()
}

/// The plan's own §6 acceptance criterion, closed: an access request scoped
/// to two entities finds only the subject's matching record in each (not the
/// non-matching sibling records seeded alongside them), writes one masked-
/// export-shaped NDJSON object per entity to the live object store, and
/// marks the request `fulfilled` with an `evidence_ref`.
#[tokio::test]
async fn fulfill_access_produces_a_correctly_scoped_cross_entity_export() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity_a = provision_test_entity(&state, "dsr_test_a").await;
    let entity_b = provision_test_entity(&state, "dsr_test_b").await;

    let subject_email = format!("subject-{}@example.com", Uuid::now_v7().simple());
    let matching_a = seed_record(&db, &entity_a, &subject_email).await;
    let _other_a = seed_record(&db, &entity_a, "someone-else@example.com").await;
    let matching_b = seed_record(&db, &entity_b, &subject_email).await;

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "access"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(created["status"], "pending");

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "access",
            serde_json::json!({
                "scopes": [
                    { "entity_logicalname": entity_a, "match_attribute": "email" },
                    { "entity_logicalname": entity_b, "match_attribute": "email" },
                ],
                "admin_override": false,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = body_json(resp).await;
    assert_eq!(result["status"], "fulfilled");
    let scopes = result["scopes"].as_array().expect("scopes array");
    // M24/D-428: an access export auto-includes the subject's audit_consent
    // history even when the caller didn't name it — see `do_fulfill_export`.
    // M35 v1 Track A: it also always carries the subject's memory scope.
    assert_eq!(
        scopes.len(),
        4,
        "the two explicit scopes plus the auto-injected audit_consent and \
         memory scopes"
    );
    let consent_scope = scopes
        .iter()
        .find(|s| s["entity_logicalname"] == "audit_consent")
        .expect("access export must auto-include the subject's consent history");
    assert_eq!(
        consent_scope["exported_rows"], 0,
        "no consent rows exist for this subject in this test"
    );
    let memory_scope = scopes
        .iter()
        .find(|s| s["entity_logicalname"] == "memory")
        .expect("access export must always report the subject's memory scope");
    assert_eq!(
        memory_scope["exported_rows"], 0,
        "this subject is not a platform user, so it owns no memory rows"
    );

    for scope in scopes {
        if scope["entity_logicalname"] == "audit_consent" || scope["entity_logicalname"] == "memory"
        {
            continue;
        }
        assert_eq!(scope["exported_rows"], 1, "scope: {scope}");
        assert_eq!(scope["withheld_for_legal_hold"], 0);
        let object_key = scope["object_key"].as_str().unwrap();
        let path = ObjectPath::parse(object_key).expect("valid object key");
        let object = state
            .base
            .storage
            .store()
            .get(&path)
            .await
            .expect("exported object must exist in the live object store");
        let bytes = object.bytes().await.expect("read exported object bytes");
        let text = std::str::from_utf8(&bytes).expect("export must be valid UTF-8 NDJSON");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "exactly the subject's one record, not siblings"
        );
        let row: Value = serde_json::from_str(lines[0]).expect("valid JSON per line");
        let row_id = row["id"].as_str().unwrap();
        let expected_id = if scope["entity_logicalname"] == entity_a {
            matching_a.to_string()
        } else {
            matching_b.to_string()
        };
        assert_eq!(
            row_id, expected_id,
            "exported row must be the subject's own record"
        );
        assert_eq!(row["email"].as_str(), Some(subject_email.as_str()));
    }

    let (status, evidence_ref): (String, Option<String>) =
        sqlx::query_as("SELECT status, evidence_ref FROM dsr_request WHERE id = $1")
            .bind(request_id)
            .fetch_one(&db)
            .await
            .expect("request row must still exist");
    assert_eq!(status, "fulfilled");
    assert!(evidence_ref.is_some());
}

async fn seed_memory(db: &attome_db::DbPool, owner: Uuid, summary: &str) -> Uuid {
    attome_search::store(
        db,
        attome_search::NewMemory {
            scope_kind: attome_search::MemoryScopeKind::User,
            scope_ref: &owner.to_string(),
            owner_principal: owner,
            parent_entity: None,
            parent_record_id: None,
            kind: "fact",
            summary,
            facts: &["a supporting fact".to_string()],
            source_refs: &[],
        },
    )
    .await
    .expect("seed a memory")
}

/// M35 v1 Track A: an access export carries the subject's own memory rows —
/// all of them and nobody else's — as a readable NDJSON object, even though
/// `memory` is an infra table no caller-supplied scope can name.
#[tokio::test]
async fn fulfill_access_exports_the_subjects_memories_and_no_one_elses() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_mexp").await;
    let subject_email = format!("mem-export-{}@example.com", Uuid::now_v7().simple());
    let _record_id = seed_record(&db, &entity, &subject_email).await;

    let subject_user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(subject_user_id)
    .bind(format!("mem-export-subject-{}", subject_user_id.simple()))
    .bind(&subject_email)
    .execute(&db)
    .await
    .expect("insert subject systemuser");
    let other_user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(other_user_id)
        .bind(format!("mem-export-other-{}", other_user_id.simple()))
        .execute(&db)
        .await
        .expect("insert other systemuser");

    let mine_1 = seed_memory(&db, subject_user_id, "prefers concise replies").await;
    let mine_2 = seed_memory(&db, subject_user_id, "reviews contracts on Thursdays").await;
    let not_mine = seed_memory(&db, other_user_id, "another user's private note").await;

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "access"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_id: Uuid = body_json(resp).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "access",
            serde_json::json!({
                "scopes": [ { "entity_logicalname": entity, "match_attribute": "email" } ],
                "admin_override": false,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = body_json(resp).await;
    assert_eq!(result["status"], "fulfilled");

    let memory_scope = result["scopes"]
        .as_array()
        .expect("scopes array")
        .iter()
        .find(|s| s["entity_logicalname"] == "memory")
        .expect("the export must report the subject's memory scope")
        .clone();
    assert_eq!(memory_scope["exported_rows"], 2, "scope: {memory_scope}");
    assert_eq!(memory_scope["withheld_for_legal_hold"], 0);

    let path =
        ObjectPath::parse(memory_scope["object_key"].as_str().unwrap()).expect("valid object key");
    let object = state
        .base
        .storage
        .store()
        .get(&path)
        .await
        .expect("the memory export object must exist in the live object store");
    let bytes = object.bytes().await.expect("read exported object bytes");
    let text = std::str::from_utf8(&bytes).expect("export must be valid UTF-8 NDJSON");
    let rows: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid JSON per line"))
        .collect();

    let mut exported_ids: Vec<String> = rows
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    exported_ids.sort();
    let mut expected_ids = vec![mine_1.to_string(), mine_2.to_string()];
    expected_ids.sort();
    assert_eq!(
        exported_ids, expected_ids,
        "exactly the subject's memories, never another user's ({not_mine})"
    );
    for row in &rows {
        assert!(
            row["summary"].is_string(),
            "content must be exported: {row}"
        );
        assert_eq!(row["facts"], serde_json::json!(["a supporting fact"]));
        assert!(
            row.get("embedding").is_none() && row.get("tsv").is_none(),
            "derived index columns are not exported: {row}"
        );
    }

    let _ = sqlx::query("DELETE FROM memory WHERE owner_principal = ANY($1)")
        .bind(vec![subject_user_id, other_user_id])
        .execute(&db)
        .await;
    let _ = sqlx::query("DELETE FROM user_account WHERE id = ANY($1)")
        .bind(vec![subject_user_id, other_user_id])
        .execute(&db)
        .await;
}

/// The plan's other named §6 acceptance criterion, closed: a pending erasure
/// request whose scope includes a record under an active legal hold is
/// refused wholesale — no key destroyed for any scope — and the request row
/// itself surfaces `status = "blocked"` with the hold's matter reference as
/// the reported `block_reason`, not a generic error.
#[tokio::test]
async fn fulfill_erasure_against_a_held_record_is_blocked_with_the_hold_as_reason() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_test_hold").await;
    let subject_email = format!("held-{}@example.com", Uuid::now_v7().simple());
    let record_id = seed_record(&db, &entity, &subject_email).await;

    sqlx::query(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ($1, $2, 'dsr-test-matter-42', $3)",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(Uuid::now_v7())
    .execute(&db)
    .await
    .expect("place legal hold");

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "erasure"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "erasure",
            serde_json::json!({
                "scopes": [
                    { "entity_logicalname": entity, "match_attribute": "email" },
                ],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = body_json(resp).await;
    assert_eq!(result["status"], "blocked");
    let block_reason = result["block_reason"]
        .as_str()
        .expect("block_reason must be present");
    assert!(block_reason.contains("legal hold"), "got: {block_reason}");
    assert!(
        block_reason.contains("dsr-test-matter-42"),
        "got: {block_reason}"
    );
    assert_eq!(result["erased"].as_array().unwrap().len(), 0);

    let (status, block_reason_db): (String, Option<String>) =
        sqlx::query_as("SELECT status, block_reason FROM dsr_request WHERE id = $1")
            .bind(request_id)
            .fetch_one(&db)
            .await
            .expect("request row must still exist");
    assert_eq!(status, "blocked");
    assert!(block_reason_db.is_some());
}

/// Happy-path erasure (no hold): the D-107 `destroy_key` call path actually
/// runs end to end through the HTTP surface and marks the request
/// `fulfilled` with an evidence_ref — the record has no pre-existing
/// `audit_erasure_key` row (never had protected audit history), which
/// `destroy_key` itself treats as a no-op rather than an error (see
/// `attome-audit/tests/erasure.rs`'s
/// `erasing_a_record_with_no_protected_history_is_a_no_op_not_an_error`), so
/// `key_destroyed` is expected `false` here — this test proves the request
/// still resolves to `fulfilled` with real audit evidence regardless.
#[tokio::test]
async fn fulfill_erasure_with_no_hold_erases_and_writes_audit_evidence() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_test_erase").await;
    let subject_email = format!("erase-{}@example.com", Uuid::now_v7().simple());
    let record_id = seed_record(&db, &entity, &subject_email).await;

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "erasure"))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "erasure",
            serde_json::json!({
                "scopes": [
                    { "entity_logicalname": entity, "match_attribute": "email" },
                ],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = body_json(resp).await;
    assert_eq!(result["status"], "fulfilled");
    let erased = result["erased"].as_array().expect("erased array");
    assert_eq!(erased.len(), 1);
    assert_eq!(
        erased[0]["record_id"].as_str().unwrap(),
        record_id.to_string()
    );

    let (status, evidence_ref): (String, Option<String>) =
        sqlx::query_as("SELECT status, evidence_ref FROM dsr_request WHERE id = $1")
            .bind(request_id)
            .fetch_one(&db)
            .await
            .expect("request row must still exist");
    assert_eq!(status, "fulfilled");
    assert!(evidence_ref.is_some());

    let audit_event_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_header \
          WHERE entity_name = $1 AND record_id = $2 AND operation = 21)",
    )
    .bind(&entity)
    .bind(record_id)
    .fetch_one(&db)
    .await
    .expect("query audit_header");
    assert!(
        audit_event_exists,
        "DSR erasure must write an Erasure audit event"
    );
}

/// M35/D-451 — the memory-erasure hook is unconditional, same shape as
/// consent withdrawal: it runs regardless of the caller-named `scopes`,
/// because `memory` is an infra table (not a provisioned entity)
/// and can never be named by a `DsrScope`. This is the test the module plan
/// asks for — DSR erasure deletes subject-related memories.
#[tokio::test]
async fn fulfill_erasure_also_deletes_the_subjects_memories() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_test_memory").await;
    let subject_email = format!("mem-erase-{}@example.com", Uuid::now_v7().simple());
    let _record_id = seed_record(&db, &entity, &subject_email).await;

    // The subject is ALSO a platform user (memory's owner_principal is a
    // real user_account, unlike the entity-record match above which
    // is keyed by an arbitrary attribute).
    let subject_user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(subject_user_id)
    .bind(format!("mem-subject-{}", subject_user_id.simple()))
    .bind(&subject_email)
    .execute(&db)
    .await
    .expect("insert subject systemuser");

    let memory_id = attome_search::store(
        &db,
        attome_search::NewMemory {
            scope_kind: attome_search::MemoryScopeKind::User,
            scope_ref: &subject_user_id.to_string(),
            owner_principal: subject_user_id,
            parent_entity: None,
            parent_record_id: None,
            kind: "fact",
            summary: "subject's memory that must be erased",
            facts: &[],
            source_refs: &[],
        },
    )
    .await
    .expect("seed a memory for the subject");

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "erasure"))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "erasure",
            serde_json::json!({
                "scopes": [
                    { "entity_logicalname": entity, "match_attribute": "email" },
                ],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = body_json(resp).await;
    assert_eq!(result["status"], "fulfilled");
    assert_eq!(
        result["memories_deleted"], 1,
        "the erasure response must report the deleted memory: {result:?}"
    );

    let still_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM memory WHERE id = $1)")
            .bind(memory_id)
            .fetch_one(&db)
            .await
            .expect("query memory");
    assert!(
        !still_exists,
        "the subject's memory must be deleted by DSR erasure"
    );

    let _ = sqlx::query("DELETE FROM user_account WHERE id = $1")
        .bind(subject_user_id)
        .execute(&db)
        .await;
}

// ── D-268: D-195 four-eyes gate on fulfill-erasure ──────────────────────────
// Same three-scenario shape `approval_erasure.rs` already established for
// `erasure_admin::erase_record`'s identical gate.

/// `approval.required_actions = ["dsr.fulfill_erasure"]`: the same
/// fulfill-erasure call now returns `202 approval_pending: true` and does
/// NOT destroy any key or touch the DSR request's own status.
#[tokio::test]
async fn gated_dsr_erasure_submits_and_does_not_execute() {
    let system = skip_if_no_db!(test_system(&["dsr.fulfill_erasure"]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_test_gate").await;
    let subject_email = format!("gated-{}@example.com", Uuid::now_v7().simple());
    let record_id = seed_record(&db, &entity, &subject_email).await;

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "erasure"))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "erasure",
            serde_json::json!({
                "scopes": [{ "entity_logicalname": entity, "match_attribute": "email" }],
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = body_json(resp).await;
    assert_eq!(body["approval_pending"], true);
    assert!(body["approval_request_id"].is_string());

    let (status, key_wrapped): (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT r.status, k.wrapped_dek FROM dsr_request r \
          LEFT JOIN audit_erasure_key k ON k.record_id = $2 \
          WHERE r.id = $1",
    )
    .bind(request_id)
    .bind(record_id)
    .fetch_one(&db)
    .await
    .expect("query request + key state");
    assert_eq!(
        status, "pending",
        "gated request must stay pending, not execute"
    );
    assert!(
        key_wrapped.is_none(),
        "no key row should exist — nothing was destroyed"
    );
}

/// Separation-of-duties: the admin who fulfilled (submitted) the request
/// cannot decide their own approval request.
#[tokio::test]
async fn requester_cannot_approve_own_dsr_erasure_request() {
    let system = skip_if_no_db!(test_system(&["dsr.fulfill_erasure"]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_gate_sod").await;
    let subject_email = format!("gated-sod-{}@example.com", Uuid::now_v7().simple());
    seed_record(&db, &entity, &subject_email).await;

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(&admin_cookie, &subject_email, "erasure"))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &admin_cookie,
            request_id,
            "erasure",
            serde_json::json!({
                "scopes": [{ "entity_logicalname": entity, "match_attribute": "email" }],
            }),
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let approval_request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(decide_request(
            &admin_cookie,
            approval_request_id,
            "approve",
            0,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A different `system.admin` approving actually erases the records and
/// marks the DSR request `fulfilled`, in the same call.
#[tokio::test]
async fn different_admin_approving_executes_dsr_erasure_and_marks_request_fulfilled() {
    let system = skip_if_no_db!(test_system(&["dsr.fulfill_erasure"]).await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, requester_cookie) = seed_admin(&db).await;
    let (_, approver_cookie) = seed_admin(&db).await;

    let entity = provision_test_entity(&state, "dsr_gate_appr").await;
    let subject_email = format!("gated-approve-{}@example.com", Uuid::now_v7().simple());
    let record_id = seed_record(&db, &entity, &subject_email).await;

    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(create_dsr_request(
            &requester_cookie,
            &subject_email,
            "erasure",
        ))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let request_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let resp = app
        .clone()
        .oneshot(fulfill_request(
            &requester_cookie,
            request_id,
            "erasure",
            serde_json::json!({
                "scopes": [{ "entity_logicalname": entity, "match_attribute": "email" }],
            }),
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let approval_request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(decide_request(
            &approver_cookie,
            approval_request_id,
            "approve",
            0,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let decide_body = body_json(resp).await;
    assert_eq!(decide_body["status"], "approved");
    assert_eq!(decide_body["executed"]["status"], "fulfilled");
    let erased = decide_body["executed"]["erased"]
        .as_array()
        .expect("erased array");
    assert_eq!(erased.len(), 1);
    assert_eq!(
        erased[0]["record_id"].as_str().unwrap(),
        record_id.to_string()
    );

    let dsr_status: String = sqlx::query_scalar("SELECT status FROM dsr_request WHERE id = $1")
        .bind(request_id)
        .fetch_one(&db)
        .await
        .expect("request row must still exist");
    assert_eq!(dsr_status, "fulfilled");
}
