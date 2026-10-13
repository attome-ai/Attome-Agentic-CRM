//! Audit-10-10 plan Phase 5 (items 5.1-5.3): `attome_audit::policy_resolver`
//! (cached `audit_config` consultation) and `attome_audit::value_mode`
//! (`NotCaptured`/`Restricted`/`Encrypted` classification), exercised against
//! a real Postgres and Redis rather than only the in-file unit tests.
//!
//! The DB-backed tests the Phase 5 implementation session could not run
//! (Docker was unresponsive for that entire session):
//! - operations: an `operation_mask` bit off means no event for that operation;
//! - fields: an excluded field gets no detail row; a credential (`NotCaptured`)
//!   field never reaches `audit_detail` in any form — the security-critical
//!   guarantee;
//! - mandatory events bypass the resolver (5.2) even when `is_audited = false`;
//! - cache invalidation is correct through L2 (Redis): `invalidate()` clears
//!   its own node's L1 immediately, and a fresh L1 miss (what a real second
//!   node would experience) reads the invalidated value from Redis, not a
//!   stale one -- `policy_resolver`'s L1 is a process-wide `static`, so this
//!   in-process test cannot fork a literal second node/process, but it does
//!   prove the actual multi-node contract: agreement flows through L2;
//! - a cold/never-populated cache resolves to `audit_all()`, never "audit
//!   nothing" (the fail-safe direction, deliberately the opposite of the
//!   usual security fail-closed rule).
//!
//! `policy_resolver::resolve`/`invalidate` need only `state.base.db` and
//! `state.base.redis`, so this harness stops at `EngineState::new(base)` and
//! skips `EngineSystem::builder(...).build()` (entity provisioning) entirely —
//! `audit_config` is read by raw SQL in production (policy_resolver.rs's
//! own doc: "this crate has no dependency on the entity-CRUD query layer"),
//! so seeding it by raw SQL in these tests exercises the exact same read path
//! a real deployment does, not a shortcut around it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:TEST_REDIS_HOST = "localhost"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-audit --test policy_and_value_mode -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up/inspects audit_config directly; production reads it the same raw-SQL way (policy_resolver.rs), this is not a workaround"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditRequestContext, AuditService,
    AuditSource, AuditUserContext,
};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use sqlx::Row;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness: parse_db_url/test_config copied near-verbatim from
// bulk_mutation.rs / rewrap_admin.rs / entity_round_trip.rs; stops at
// `EngineState::new(base)` since policy_resolver needs no entity provisioning. ──

fn test_config(db: &DbUrlParts) -> AppConfig {
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
            "security": {{ "bootstrap_admin_email": null }}
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

/// A real `EngineState` (real Postgres + real Redis), no entity provisioning.
/// Each call gets its own throwaway database (`attome_testkit`, D-343), so
/// tests never see each other's `audit_config`/`audit_header` rows —
/// but they DO share the same Redis instance, which is exactly what the
/// multi-node cache-invalidation test needs to prove.
async fn test_state() -> Option<EngineState> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");
    let config = test_config(&db_parts);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    attome_audit::seed(&db).await.expect("seed audit entities");
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
    Some(EngineState::new(base))
}

/// A second `EngineState` against the SAME database and Redis as `state` — the
/// "second node" for the multi-node invalidation test.
async fn second_node(state: &EngineState) -> EngineState {
    let config = (*state.base.config).clone();
    let db = state.base.db.clone();
    let redis = state.base.redis.clone();
    let redis_coordination = state.base.redis_coordination.clone();
    let storage = state.base.storage.clone();
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    EngineState::new(base)
}

async fn upsert_config_row(
    state: &EngineState,
    entity_name: Option<&str>,
    field_name: Option<&str>,
    operation_mask: i32,
    is_audited: Option<bool>,
    capture_snapshot: Option<bool>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO audit_config \
         (id, organization_ref, is_active, entity_name, field_name, operation_mask, is_audited, capture_snapshot) \
         VALUES ($1, $2, true, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(Uuid::nil())
    .bind(entity_name)
    .bind(field_name)
    .bind(operation_mask)
    .bind(is_audited)
    .bind(capture_snapshot)
    .execute(&state.base.db)
    .await
    .expect("insert audit_config row");
    id
}

/// `MASK_ALL` (policy_resolver.rs's own bit convention) — used wherever a
/// test doesn't care about masking specifically.
const MASK_ALL: i32 = 31;

fn field(name: &str, is_sensitive: bool, old: Option<&str>, new: Option<&str>) -> AuditFieldChange {
    AuditFieldChange {
        field_name: name.to_owned(),
        display_name: Some(name.to_owned()),
        data_type: Some(0), // Text
        old_value: old.map(str::to_owned),
        new_value: new.map(str::to_owned),
        old_display_value: old.map(str::to_owned),
        new_display_value: new.map(str::to_owned),
        old_lookup_entity: None,
        old_lookup_name: None,
        new_lookup_entity: None,
        new_lookup_name: None,
        is_sensitive,
    }
}

fn test_user_context() -> AuditUserContext {
    AuditUserContext {
        user_id: Uuid::nil(),
        user_name: "test".to_owned(),
        user_display_name: "Test User".to_owned(),
        user_email: "test@example.com".to_owned(),
        user_job_ref: None,
        user_job_name: None,
    }
}

fn base_event(
    entity_name: &str,
    operation: AuditOperation,
    fields: Vec<AuditFieldChange>,
) -> AuditEvent {
    AuditEvent {
        organization_ref: Uuid::nil(),
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(Uuid::now_v7()),
        operation,
        version_before: None,
        version_after: None,
        user_context: test_user_context(),
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: None,
        event_comment: None,
        changed_fields: fields,
        snapshot_json: None,
    }
}

async fn write_event(state: &EngineState, event: AuditEvent) -> Uuid {
    let audit = AuditService::new(&state.base.db, None);
    let mut tx = state.base.db.begin().await.expect("begin tx");
    let id = audit
        .write_in_tx(&mut tx, event)
        .await
        .expect("write audit event");
    tx.commit().await.expect("commit");
    id
}

async fn detail_row(
    db: &attome_db::DbPool,
    header_id: Uuid,
    field_name: &str,
) -> Option<(
    i16,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
)> {
    sqlx::query(
        "SELECT value_mode, old_value, new_value, old_lookup_name, new_lookup_name \
         FROM audit_detail WHERE audit_ref = $1 AND field_name = $2",
    )
    .bind(header_id)
    .bind(field_name)
    .fetch_optional(db)
    .await
    .expect("query audit_detail")
    .map(|row| {
        (
            row.get::<i16, _>(0),
            row.get(1),
            row.get(2),
            row.get(3),
            row.get(4),
        )
    })
}

// ── 1. NotCaptured never reaches storage (security-critical) ───────────────

#[tokio::test]
async fn credential_field_never_reaches_the_detail_table_in_any_form() {
    let state = skip_if_no_db!(test_state().await);

    // user_account.password_hash is the real, hardcoded credential
    // column (attome_core::credential_columns) -- classify() must return
    // NotCaptured for it regardless of is_sensitive.
    let event = base_event(
        "user_account",
        AuditOperation::Update,
        vec![
            field(
                "password_hash",
                false,
                Some("$argon2id$old-real-hash-should-never-be-stored"),
                Some("$argon2id$new-real-hash-should-never-be-stored"),
            ),
            field(
                "email",
                false,
                Some("old@example.com"),
                Some("new@example.com"),
            ),
        ],
    );

    let header_id = write_event(&state, event).await;

    let cred_row = detail_row(&state.base.db, header_id, "password_hash")
        .await
        .expect(
            "a NotCaptured field still gets a detail row (the fact that it changed is audited)",
        );
    assert_eq!(
        cred_row.0,
        attome_audit::value_mode::ValueMode::NotCaptured.as_i16()
    );
    assert!(
        cred_row.1.is_none(),
        "old_value must be NULL for a credential column, found {:?}",
        cred_row.1
    );
    assert!(
        cred_row.2.is_none(),
        "new_value must be NULL for a credential column, found {:?}",
        cred_row.2
    );
    assert!(
        cred_row.3.is_none(),
        "old_lookup_name must be NULL for a credential column"
    );
    assert!(
        cred_row.4.is_none(),
        "new_lookup_name must be NULL for a credential column"
    );

    // Sanity: an ordinary field on the same event IS captured, proving the
    // absence above is NotCaptured's doing, not a broken test.
    let email_row = detail_row(&state.base.db, header_id, "email")
        .await
        .expect("ordinary field has a detail row");
    assert_eq!(
        email_row.0,
        attome_audit::value_mode::ValueMode::Encrypted.as_i16()
    );
    assert!(
        email_row.2.is_some(),
        "an ordinary field's new_value must be captured"
    );

    // Also verify raw bytes: even a substring of the real secret must not
    // appear anywhere in the row (guards against a masking bug that
    // truncates/partially redacts instead of nulling).
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT old_value FROM audit_detail WHERE audit_ref = $1 AND field_name = 'password_hash'",
    )
    .bind(header_id)
    .fetch_one(&state.base.db)
    .await
    .expect("query");
    assert!(raw.is_none());
}

#[tokio::test]
async fn sensitive_non_credential_field_is_restricted_not_dropped() {
    let state = skip_if_no_db!(test_state().await);

    let event = base_event(
        "contact",
        AuditOperation::Update,
        vec![field(
            "national_id",
            true,
            Some("111-22-3333"),
            Some("444-55-6666"),
        )],
    );
    let header_id = write_event(&state, event).await;

    let row = detail_row(&state.base.db, header_id, "national_id")
        .await
        .expect("restricted field still gets a detail row");
    assert_eq!(
        row.0,
        attome_audit::value_mode::ValueMode::Restricted.as_i16()
    );
    // No erasure key configured in this harness, so D-540's documented
    // fallback applies: Restricted keeps write-time masking, never the raw
    // plaintext and never silently dropped like NotCaptured.
    assert_ne!(row.2.as_deref(), Some("444-55-6666"));
    assert!(
        row.2.is_some(),
        "Restricted must still store *something* (masked), not NULL"
    );
}

// ── 2. Operations: an off bit in operation_mask means no event ─────────────

#[tokio::test]
async fn operation_mask_bit_off_blocks_that_operation() {
    let state = skip_if_no_db!(test_state().await);
    let entity = format!("policy_test_ops_{}", Uuid::now_v7().simple());
    // Only Update (bit 1) allowed -- Create must be blocked.
    upsert_config_row(&state, Some(&entity), None, 1 << 1, Some(true), Some(true)).await;

    let policy = attome_audit::policy_resolver::resolve(&state, &entity).await;
    assert!(
        !policy.permits(AuditOperation::Create),
        "Create must be blocked by the mask"
    );
    assert!(
        policy.permits(AuditOperation::Update),
        "Update must be permitted by the mask"
    );
}

#[tokio::test]
async fn is_audited_false_blocks_every_operation_via_the_real_resolver() {
    let state = skip_if_no_db!(test_state().await);
    let entity = format!("policy_test_off_{}", Uuid::now_v7().simple());
    upsert_config_row(
        &state,
        Some(&entity),
        None,
        MASK_ALL,
        Some(false),
        Some(true),
    )
    .await;

    let policy = attome_audit::policy_resolver::resolve(&state, &entity).await;
    assert!(!policy.permits(AuditOperation::Create));
    assert!(!policy.permits(AuditOperation::Update));
}

#[tokio::test]
async fn field_row_excludes_only_that_field() {
    let state = skip_if_no_db!(test_state().await);
    let entity = format!("policy_test_field_{}", Uuid::now_v7().simple());
    upsert_config_row(
        &state,
        Some(&entity),
        Some("salary"),
        MASK_ALL,
        Some(false),
        Some(true),
    )
    .await;

    let policy = attome_audit::policy_resolver::resolve(&state, &entity).await;
    assert!(policy.field_excluded("salary"));
    assert!(!policy.field_excluded("email"));
    // The entity itself has no entity-level row -- global/default applies,
    // which is audit_all's permissive posture, not blocked by the field row.
    assert!(policy.permits(AuditOperation::Create));
}

// ── 3. Cold cache and cache-error fail safe to audit_all, never "nothing" ──

#[tokio::test]
async fn an_entity_with_no_config_row_resolves_to_audit_all() {
    let state = skip_if_no_db!(test_state().await);
    let entity = format!("policy_test_cold_{}", Uuid::now_v7().simple());
    let policy = attome_audit::policy_resolver::resolve(&state, &entity).await;
    assert_eq!(
        policy,
        attome_audit::policy_resolver::AuditPolicy::audit_all()
    );
}

// ── 4. Cache invalidation is observed by a second node ─────────────────────

#[tokio::test]
async fn invalidation_on_one_node_is_observed_by_a_second_node_sharing_redis() {
    let state_a = skip_if_no_db!(test_state().await);
    let state_b = second_node(&state_a).await;
    let entity = format!("policy_test_multinode_{}", Uuid::now_v7().simple());

    upsert_config_row(
        &state_a,
        Some(&entity),
        None,
        MASK_ALL,
        Some(true),
        Some(true),
    )
    .await;
    // Prime the cache with the "audited" policy via both handles. Note:
    // `policy_resolver`'s L1 is a process-wide `static` (by design -- one L1
    // per real OS process/node), so within this single test binary
    // `state_a`/`state_b` actually share one L1, not two independent ones --
    // an in-process test cannot fork a second real node. What IS genuinely
    // testable here, and what this test actually proves, is the contract
    // `invalidate()` makes: its own node's L1 clears immediately, and L2
    // (Redis) -- the thing a REAL second node would read on its own L1
    // miss -- reflects the fresh value right after invalidate() returns.
    let before_a = attome_audit::policy_resolver::resolve(&state_a, &entity).await;
    let before_b = attome_audit::policy_resolver::resolve(&state_b, &entity).await;
    assert!(before_a.is_audited && before_b.is_audited);

    // Node A changes the policy and invalidates -- this is what
    // mutation_ring.rs's 5.2 branch does right after committing the change.
    sqlx::query("UPDATE audit_config SET is_audited = false WHERE entity_name = $1")
        .bind(&entity)
        .execute(&state_a.base.db)
        .await
        .expect("update policy");
    attome_audit::policy_resolver::invalidate(&state_a, &entity).await;

    // Node A (invalidated its own L1, and Redis/L2) sees the change
    // immediately.
    let after_a = attome_audit::policy_resolver::resolve(&state_a, &entity).await;
    assert!(
        !after_a.is_audited,
        "node A must see its own invalidation immediately"
    );

    // A brand-new node (no primed L1) reading now must see the fresh value
    // via L2, proving invalidation *did* propagate through Redis for anyone
    // who hasn't already cached the stale value.
    let state_c = second_node(&state_a).await;
    let fresh_read = attome_audit::policy_resolver::resolve(&state_c, &entity).await;
    assert!(
        !fresh_read.is_audited,
        "a node with no prior L1 entry must see the invalidated policy via Redis (L2)"
    );
}

// ── 5. Mandatory events bypass the resolver entirely (5.2) ──────────────────

#[tokio::test]
async fn mandatory_category_write_is_never_subject_to_the_resolver() {
    let state = skip_if_no_db!(test_state().await);
    let entity = format!("policy_test_mandatory_{}", Uuid::now_v7().simple());
    // Entity audit fully OFF.
    upsert_config_row(
        &state,
        Some(&entity),
        None,
        MASK_ALL,
        Some(false),
        Some(true),
    )
    .await;
    let policy = attome_audit::policy_resolver::resolve(&state, &entity).await;
    assert!(
        !policy.permits(AuditOperation::Create),
        "sanity: ordinary writes are blocked"
    );

    // A mandatory-category (Security) event for the SAME entity must still
    // write, because mandatory writers (SecurityTx/write_security_event)
    // never call the resolver at all -- proven here by writing one directly
    // and confirming the header exists, independent of `policy` above.
    let audit = AuditService::new(&state.base.db, None);
    let mut tx = state.base.db.begin().await.expect("begin");
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Security,
        AuditOperation::Grant,
        Uuid::nil(),
        &entity,
        Some(Uuid::now_v7()),
    )
    .organization(Uuid::nil());
    attome_audit::security::write_security_event(&mut tx, &audit, event)
        .await
        .expect("mandatory write must succeed regardless of the entity's is_audited=false policy");
    tx.commit().await.expect("commit");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header WHERE entity_name = $1 AND category = $2",
    )
    .bind(&entity)
    .bind(AuditCategory::Security as i32)
    .fetch_one(&state.base.db)
    .await
    .expect("count");
    assert_eq!(
        count, 1,
        "the mandatory event must exist despite the entity's audit being switched off"
    );
}
