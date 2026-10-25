//! Integration test for M85 (Incident Management)'s `attome_service::timeline`
//! — the checklist's explicit requirement: "tests: hidden sources excluded."
//!
//! Builds a full `EngineState` (same harness shape `tests/clock.rs` already
//! established) and a hand-built, non-admin `SecurityContext` — no cached
//! resolver involved, so this test never needs the resolver's own
//! cache-invalidation dance (`record_level_security.rs`'s
//! `scope_role_for_entity` calls `security.invalidate(user_id)` for exactly
//! that reason; this file's `build_timeline` calls read straight from the DB
//! on every call, so there is nothing to invalidate). Role/entity-access/
//! record-share rows are seeded directly via SQL, same
//! grant-shape `attome-api/tests/record_level_security.rs` already
//! established for the identical (`AccessLevel::None` + explicit
//! `record_share`) scenario.
//!
//! `communication` and `record_relationship` are provisioned inline
//! (same "inlined for the test" reasoning `tests/clock.rs`'s
//! `ensure_note_entity` already documents for `note`) — this crate has no
//! production dependency on the crates that normally seed them
//! (`attome-api::communication_seed`/`relationship_seed`), and adding one
//! only for a test would be a heavier, backwards dependency for one small
//! entity.

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

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
            "host": "localhost", "port": 5555, "dbname": "unused",
            "user": "unused", "password": "unused", "schema": "attome_dev",
            "connection_number": 5, "timeout": 5.0
        }},
        "cache": {{
            "host": "{redis_host}", "port": {redis_port}, "password": "", "db": 0,
            "connection_pool_size": 4, "timeout": 2000,
            "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": false
        }},
        "storage": {{
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "test", "s3_use_path_style": true, "s3_verify_ssl": false
        }},
        "auth": {{
            "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
            "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
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
        "cors": {{ "allowed_origins": ["http://allowed.test"] }}
    }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// Same env-var-mutation serialization `tests/clock.rs` documents
/// (`attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` synchronously, and
/// `cargo test` runs this file's tests concurrently).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
    // reads these vars while this guard is held.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config();
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
    Some(EngineState::new(base))
}

/// Inlined — see this file's module doc for why `communication` isn't
/// provisioned through its owning crate here.
async fn ensure_communication_entity(db: &DbPool) {
    use attome_metadata::provision::{ensure_attribute, ensure_entity};
    let id = ensure_entity(db, "communication", "Communication", Some("subject"), true)
        .await
        .expect("ensure communication entity");
    for (ln, dn, ft, req) in [
        ("entity_name", "Entity Name", "text", true),
        ("record_id", "Record Id", "text", true),
        ("subject", "Subject", "text", false),
        ("body", "Body", "text", false),
        ("status", "Status", "text", false),
    ] {
        ensure_attribute(db, id, ln, dn, ft, req, false, false, false, None, None)
            .await
            .expect("ensure communication attribute");
    }
    let choice = |choices: &[&str]| serde_json::json!({ "choices": choices, "multi": false });
    ensure_attribute(
        db,
        id,
        "channel",
        "Channel",
        "choice",
        true,
        false,
        true,
        true,
        None,
        Some(choice(&["email", "portal", "call", "meeting", "other"])),
    )
    .await
    .expect("ensure communication.channel");
    ensure_attribute(
        db,
        id,
        "direction",
        "Direction",
        "choice",
        false,
        false,
        true,
        true,
        None,
        Some(choice(&["inbound", "outbound"])),
    )
    .await
    .expect("ensure communication.direction");
    ensure_attribute(
        db,
        id,
        "sent_at",
        "Sent At",
        "date_time",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .expect("ensure communication.sent_at");
}

/// Inlined — see this file's module doc.
async fn ensure_relationship_entity(db: &DbPool) {
    use attome_metadata::provision::{ensure_attribute, ensure_entity};
    let id = ensure_entity(db, "record_relationship", "Record Relationship", None, true)
        .await
        .expect("ensure record_relationship entity");
    for (ln, dn) in [
        ("from_entity_name", "From Entity"),
        ("from_record_id", "From Record Id"),
        ("to_entity_name", "To Entity"),
        ("to_record_id", "To Record Id"),
        ("relationship_type", "Relationship Type"),
    ] {
        ensure_attribute(db, id, ln, dn, "text", true, false, false, true, None, None)
            .await
            .expect("ensure record_relationship attribute");
    }
}

async fn ensure_seeded(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed");
    attome_service::seed::seed_for_tests(db)
        .await
        .expect("attome_service::seed::seed");
    attome_audit::seed::seed(db)
        .await
        .expect("attome_audit::seed::seed");
    ensure_communication_entity(db).await;
    ensure_relationship_entity(db).await;
    ensure_decision_entity(db).await;
    ensure_note_entity(db).await;
}

/// Inlined — see this file's module doc.
async fn ensure_decision_entity(db: &DbPool) {
    use attome_metadata::provision::{ensure_attribute, ensure_entity};
    let id = ensure_entity(db, "dashboard_decision", "Decision", Some("title"), false)
        .await
        .expect("ensure dashboard_decision entity");
    for f in ["title", "status"] {
        ensure_attribute(db, id, f, f, "text", false, false, false, true, None, None)
            .await
            .expect("ensure dashboard_decision attribute");
    }
}

/// Inlined — see this file's module doc.
async fn ensure_note_entity(db: &DbPool) {
    use attome_metadata::provision::{ensure_attribute, ensure_entity};
    let id = ensure_entity(db, "note", "Note", None, false)
        .await
        .expect("ensure note entity");
    for f in ["entity_name", "record_id", "title", "note_text"] {
        ensure_attribute(db, id, f, f, "text", false, false, false, true, None, None)
            .await
            .expect("ensure note attribute");
    }
}

async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build metadata registry");
    state.entities.swap(registry);
}

async fn entity_id_by_logicalname(db: &DbPool, logicalname: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info WHERE logicalname = $1 \
         AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("resolve entity id")
}

async fn insert_ticket(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_ticket (id, ticket_number, title, priority, status) \
         VALUES ($1, $2, 'Timeline Test Ticket', 'medium', 'open')",
    )
    .bind(id)
    .bind(format!("TKT-TL-{id}"))
    .execute(db)
    .await
    .expect("insert service_ticket");
    id
}

async fn insert_communication(db: &DbPool, ticket_id: Uuid, subject: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO communication (id, entity_name, record_id, subject, channel, is_active) \
         VALUES ($1, 'service_ticket', $2, $3, 'portal', true)",
    )
    .bind(id)
    .bind(ticket_id.to_string())
    .bind(subject)
    .execute(db)
    .await
    .expect("insert communication");
    id
}

async fn insert_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(id)
        .bind(format!("timeline-test-{id}"))
        .execute(db)
        .await
        .expect("insert user_account");
    id
}

/// A fresh `role` granting `"{logicalname}.read"` — same shape
/// `record_level_security.rs::create_role_with_privileges` establishes,
/// reimplemented here (that file lives in `attome-api`'s test tree, which
/// this crate cannot depend on — see this crate's own layering: `attome-service`
/// never depends on `attome-api`).
async fn create_read_role(db: &DbPool, logicalname: &str) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("timeline-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");

    let key = format!("{logicalname}.read");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
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

    role_id
}

async fn assign_role(db: &DbPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
}

/// `access_level`: 0=None, 1=Team, 2=BusinessUnit, 3=Global
/// (`attome_server::security::AccessLevel`).
async fn scope_role(db: &DbPool, role_id: Uuid, entity_id: Uuid, access_level: i16) {
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, $4, $4, $4, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(access_level)
    .execute(db)
    .await
    .expect("upsert role entity-access grant");
}

/// capability: 0=View, 1=Action (`attome_security::rls::Capability`).
async fn share_record(
    db: &DbPool,
    record_id: Uuid,
    entity_id: Uuid,
    user_id: Uuid,
    capability: i16,
) {
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, $4)",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .bind(capability)
    .execute(db)
    .await
    .expect("insert record share");
}

fn ctx_for(user_id: Uuid, privileges: &[&str]) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: privileges.iter().map(|s| s.to_string()).collect(),
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

/// The checklist's explicit requirement: "tests: hidden sources excluded."
/// A caller who can read the ticket (Global-tier `service_ticket` access) but is
/// scoped to `None`-tier on `communication`, with only ONE of two
/// communications on the ticket explicitly shared to them, must see that one
/// communication in the timeline and must NOT see the other.
#[tokio::test]
async fn timeline_excludes_a_communication_the_caller_cannot_see() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;

    let ticket_id = insert_ticket(db).await;
    let visible_comm = insert_communication(db, ticket_id, "Visible to caller").await;
    let hidden_comm = insert_communication(db, ticket_id, "Hidden from caller").await;

    let ticket_entity_id = entity_id_by_logicalname(db, "service_ticket").await;
    let comm_entity_id = entity_id_by_logicalname(db, "communication").await;

    let user_id = insert_user(db).await;
    let ticket_role = create_read_role(db, "service_ticket").await;
    assign_role(db, user_id, ticket_role).await;
    scope_role(db, ticket_role, ticket_entity_id, 3).await; // Global — ticket fully visible

    let comm_role = create_read_role(db, "communication").await;
    assign_role(db, user_id, comm_role).await;
    scope_role(db, comm_role, comm_entity_id, 0).await; // None — only explicit shares visible

    // Only the "visible" communication is explicitly shared (View capability).
    share_record(db, visible_comm, comm_entity_id, user_id, 0).await;

    let ctx = ctx_for(user_id, &["service_ticket.read", "communication.read"]);

    let timeline = attome_service::timeline::build_timeline(&state, &ctx, ticket_id)
        .await
        .expect("build_timeline");

    let comm_ids: Vec<Uuid> = timeline
        .items
        .iter()
        .filter(|e| e.source_entity == "communication")
        .map(|e| e.source_id)
        .collect();

    assert!(
        comm_ids.contains(&visible_comm),
        "the explicitly-shared communication must appear in the timeline"
    );
    assert!(
        !comm_ids.contains(&hidden_comm),
        "a communication the caller has no share/access on must NOT appear in the timeline, \
         even though it is attached to a ticket the caller can see"
    );
}

/// An admin sees every source unfiltered — the positive-path counterpart to
/// the exclusion test above, proving the merge/permission logic doesn't
/// accidentally drop rows for a caller who legitimately can see everything.
#[tokio::test]
async fn admin_sees_every_communication_on_the_ticket() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;

    let ticket_id = insert_ticket(db).await;
    let comm_a = insert_communication(db, ticket_id, "First").await;
    let comm_b = insert_communication(db, ticket_id, "Second").await;

    let admin_ctx = ctx_for(Uuid::now_v7(), &[]);
    let admin_ctx = SecurityContext {
        is_admin: true,
        ..admin_ctx
    };

    let timeline = attome_service::timeline::build_timeline(&state, &admin_ctx, ticket_id)
        .await
        .expect("build_timeline");

    let comm_ids: Vec<Uuid> = timeline
        .items
        .iter()
        .filter(|e| e.source_entity == "communication")
        .map(|e| e.source_id)
        .collect();
    assert!(comm_ids.contains(&comm_a));
    assert!(comm_ids.contains(&comm_b));
}

/// A caller who cannot see the ticket itself at all gets `NotFound` for the
/// whole timeline — no source is assembled or leaked piecemeal.
#[tokio::test]
async fn timeline_404s_when_the_caller_cannot_see_the_ticket_itself() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;

    let ticket_id = insert_ticket(db).await;
    let ticket_entity_id = entity_id_by_logicalname(db, "service_ticket").await;

    let user_id = insert_user(db).await;
    let role = create_read_role(db, "service_ticket").await;
    assign_role(db, user_id, role).await;
    scope_role(db, role, ticket_entity_id, 0).await; // None, no share granted at all

    let ctx = ctx_for(user_id, &["service_ticket.read"]);

    let result = attome_service::timeline::build_timeline(&state, &ctx, ticket_id).await;
    assert!(matches!(result, Err(attome_types::AppError::NotFound)));
}

/// The ticket's state model, as boot loads it from the attome-service bundle
/// (`state_field = "status"`).
fn register_ticket_state_model(state: &EngineState) {
    use attome_core::state_registry::{StateModelDef, StateModelEntry, StateModelRegistry};
    state
        .state_models
        .swap(StateModelRegistry::from_entries(vec![(
            "service_ticket".to_string(),
            StateModelEntry {
                model: Some(StateModelDef {
                    id: Uuid::now_v7(),
                    entity_logicalname: "service_ticket".into(),
                    name: "Ticket Lifecycle".into(),
                    state_field: "status".into(),
                    initial_state: "open".into(),
                    is_active: true,
                    row_version: 0,
                }),
                transitions: Vec::new(),
            },
        )]));
}

/// D-601: the ticket route is now a thin caller of the generic record
/// timeline. It must return exactly the entries the pre-D-601 implementation
/// did — the four legacy sources, computed here by that implementation's own
/// queries as the oracle — and nothing from the sources the generic route
/// added (a note on the ticket stays off this route).
#[tokio::test]
async fn ticket_timeline_returns_the_same_entries_as_the_legacy_merge() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;
    register_ticket_state_model(&state);

    let ticket_id = insert_ticket(db).await;
    let header: Uuid = sqlx::query_scalar(
        "INSERT INTO audit_header (entity_name, record_id, category, operation, event_hash, changed_on, user_display_name) VALUES ('service_ticket', $1, 1, 1, $2, NOW(), 'Tester') RETURNING id",
    )
    .bind(ticket_id)
    .bind(format!("test-{}", Uuid::now_v7()))
    .fetch_one(db)
    .await
    .expect("insert audit header");
    for (field, old, new) in [("status", "open", "in_progress"), ("title", "a", "b")] {
        sqlx::query(
            "INSERT INTO audit_detail (audit_ref, field_name, old_value, new_value, is_sensitive) VALUES ($1, $2, $3, $4, false)",
        )
        .bind(header)
        .bind(field)
        .bind(old)
        .bind(new)
        .execute(db)
        .await
        .expect("insert audit detail");
    }
    insert_communication(db, ticket_id, "First").await;
    insert_communication(db, ticket_id, "Second").await;
    let decision: Uuid = sqlx::query_scalar(
        "INSERT INTO dashboard_decision (title, status) VALUES ('Escalate', 'open') RETURNING id",
    )
    .fetch_one(db)
    .await
    .expect("insert decision");
    sqlx::query(
        "INSERT INTO record_relationship (from_entity_name, from_record_id, to_entity_name, to_record_id, relationship_type) VALUES ('dashboard_decision', $1, 'service_ticket', $2, 'related')",
    )
    .bind(decision.to_string())
    .bind(ticket_id.to_string())
    .execute(db)
    .await
    .expect("link decision");
    let note: Uuid = sqlx::query_scalar(
        "INSERT INTO note (entity_name, record_id, title) VALUES ('service_ticket', $1, 'not on this route') RETURNING id",
    )
    .bind(ticket_id.to_string())
    .fetch_one(db)
    .await
    .expect("insert note");

    // The legacy implementation's four source queries, verbatim in shape.
    let mut expected: HashSet<(String, Uuid)> = HashSet::new();
    let audit: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_header WHERE entity_name = 'service_ticket' AND record_id = $1",
    )
    .bind(ticket_id)
    .fetch_all(db)
    .await
    .expect("legacy audit query");
    expected.extend(audit.into_iter().map(|id| ("audit_header".to_string(), id)));
    let transitions: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM audit_detail d JOIN audit_header h ON h.id = d.audit_ref WHERE h.entity_name = 'service_ticket' AND h.record_id = $1 AND d.field_name = 'status'",
    )
    .bind(ticket_id)
    .fetch_all(db)
    .await
    .expect("legacy transition query");
    expected.extend(
        transitions
            .into_iter()
            .map(|id| ("audit_detail".to_string(), id)),
    );
    let comms: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM communication WHERE entity_name = 'service_ticket' AND record_id = $1 AND is_active IS NOT FALSE",
    )
    .bind(ticket_id.to_string())
    .fetch_all(db)
    .await
    .expect("legacy communication query");
    expected.extend(
        comms
            .into_iter()
            .map(|id| ("communication".to_string(), id)),
    );
    expected.insert(("dashboard_decision".to_string(), decision));
    assert_eq!(
        expected.len(),
        5,
        "fixture: 1 header, 1 transition, 2 communications, 1 decision"
    );

    let admin_ctx = SecurityContext {
        is_admin: true,
        ..ctx_for(Uuid::now_v7(), &[])
    };
    let timeline = attome_service::timeline::build_timeline(&state, &admin_ctx, ticket_id)
        .await
        .expect("build_timeline");
    let got: HashSet<(String, Uuid)> = timeline
        .items
        .iter()
        .map(|e| (e.source_entity.clone(), e.source_id))
        .collect();
    assert_eq!(got, expected);
    assert_eq!(timeline.items.len(), expected.len(), "no entry twice");
    assert!(
        !got.iter().any(|(_, id)| *id == note),
        "notes stay off the ticket route"
    );
    let transition = timeline
        .items
        .iter()
        .find(|e| e.source_entity == "audit_detail")
        .expect("a status transition");
    assert_eq!(transition.summary, "status: open -> in_progress");
    assert_eq!(timeline.page, 1);
    assert_eq!(timeline.total, 5);
}
