//! DB-backed tests for the entity-generic record timeline and record history
//! (basic-units plan U3/U6, D-601):
//! `attome_records::entity_crud::{timeline, history}`.
//!
//! - keyset paging across sources that share one timestamp returns every entry
//!   exactly once, in the documented order;
//! - per-source visibility: a note, communication or decision on a readable
//!   record that the caller cannot read individually never appears;
//! - a record the caller cannot read is `NotFound` for both routes;
//! - history drops a sensitive field the caller has no read grant for (and a
//!   change whose only field was that one) and masks a readable sensitive
//!   field;
//! - a malformed cursor is a 422 through the real route.
//!
//! Fixture rows (records, audit rows, roles, shares) are written with direct
//! SQL against this binary's own throwaway database — guidelines §4's
//! "tests against a throwaway database" exemption.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-records --test record_timeline -- --test-threads=1
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
use std::sync::Arc;

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_core::state_registry::{StateModelDef, StateModelEntry, StateModelRegistry};
use attome_db::DbPool;
use attome_records::entity_crud::history::{RecordHistoryQuery, record_history};
use attome_records::entity_crud::timeline::{
    TimelineEntryKind, TimelineOptions, TimelineQuery, record_timeline,
};
use attome_server::AppState;
use attome_server::authz::AuthorizedContext;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use tower::ServiceExt;
use uuid::Uuid;

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
                "connection_number": 5, "timeout": 5.0,
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

// `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` synchronously; this
// file's tests run concurrently by default.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The platform entities the timeline reads, provisioned once per binary.
async fn seed_platform(db: &DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            attome_security::seed::seed_for_tests(db)
                .await
                .expect("seed security entities");
            attome_audit::seed(db).await.expect("seed audit entities");
            ensure_child_entity(
                db,
                "note",
                "Note",
                &[("title", "text"), ("note_text", "text")],
            )
            .await;
            ensure_child_entity(
                db,
                "communication",
                "Communication",
                &[
                    ("subject", "text"),
                    ("channel", "text"),
                    ("sent_at", "date"),
                ],
            )
            .await;
            let rel = attome_metadata::provision::ensure_entity(
                db,
                "record_relationship",
                "Record Relationship",
                None,
                false,
            )
            .await
            .expect("ensure record_relationship");
            for f in [
                "from_entity_name",
                "from_record_id",
                "to_entity_name",
                "to_record_id",
                "relationship_type",
            ] {
                attome_metadata::provision::ensure_attribute(
                    db, rel, f, f, "text", false, false, false, true, None, None,
                )
                .await
                .expect("ensure relationship attribute");
            }
            let dec = attome_metadata::provision::ensure_entity(
                db,
                "dashboard_decision",
                "Decision",
                Some("title"),
                false,
            )
            .await
            .expect("ensure dashboard_decision");
            for f in ["title", "status"] {
                attome_metadata::provision::ensure_attribute(
                    db, dec, f, f, "text", false, false, false, true, None, None,
                )
                .await
                .expect("ensure decision attribute");
            }
        })
        .await;
}

async fn ensure_child_entity(db: &DbPool, name: &str, display: &str, extra: &[(&str, &str)]) {
    let id = attome_metadata::provision::ensure_entity(db, name, display, None, false)
        .await
        .unwrap_or_else(|e| panic!("ensure {name}: {e}"));
    for (f, t) in [("entity_name", "text"), ("record_id", "text")]
        .iter()
        .chain(extra.iter())
    {
        attome_metadata::provision::ensure_attribute(
            db, id, f, f, t, false, false, false, true, None, None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure {name}.{f}: {e}"));
    }
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

async fn sync_registry(state: &EngineState) {
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("build metadata registry"),
    );
}

/// A throwaway parent entity: `name`, a `status` state field, and two
/// sensitive fields (`secret_a`, `secret_b`). Registers a state model on
/// `status` in the in-memory registry, as boot does from the database.
async fn provision_parent(state: &EngineState) -> (String, Uuid) {
    let name = format!("tl_parent_{}", Uuid::now_v7().simple());
    let id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &name,
        "Timeline Parent",
        Some("name"),
        false,
    )
    .await
    .expect("provision parent entity");
    for (f, sensitive) in [
        ("name", false),
        ("status", false),
        ("secret_a", true),
        ("secret_b", true),
    ] {
        attome_metadata::provision::ensure_attribute(
            &state.base.db,
            id,
            f,
            f,
            "text",
            false,
            sensitive,
            false,
            false,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("provision {f}: {e}"));
    }
    sync_registry(state).await;
    state
        .state_models
        .swap(StateModelRegistry::from_entries(vec![(
            name.clone(),
            StateModelEntry {
                model: Some(StateModelDef {
                    id: Uuid::now_v7(),
                    entity_logicalname: name.clone(),
                    name: "Lifecycle".into(),
                    state_field: "status".into(),
                    initial_state: "open".into(),
                    is_active: true,
                    row_version: 0,
                }),
                transitions: Vec::new(),
            },
        )]));
    (name, id)
}

async fn insert_parent_record(db: &DbPool, entity: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(&format!(
        "INSERT INTO \"{entity}\" (id, name, status) VALUES ($1, 'rec', 'open')"
    ))
    .bind(id)
    .execute(db)
    .await
    .expect("insert parent record");
    id
}

async fn insert_header(
    db: &DbPool,
    entity: &str,
    record_id: Uuid,
    operation: i32,
    at: DateTime<Utc>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO audit_header \
            (entity_name, record_id, category, operation, event_hash, changed_on, user_display_name) \
         VALUES ($1, $2, 1, $3, $4, $5, 'Tester') RETURNING id",
    )
    .bind(entity)
    .bind(record_id)
    .bind(operation)
    .bind(format!("test-{}", Uuid::now_v7()))
    .bind(at)
    .fetch_one(db)
    .await
    .expect("insert audit header")
}

async fn insert_detail(
    db: &DbPool,
    header: Uuid,
    field: &str,
    old: Option<&str>,
    new: Option<&str>,
    sensitive: bool,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO audit_detail (audit_ref, field_name, old_value, new_value, is_sensitive) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(header)
    .bind(field)
    .bind(old)
    .bind(new)
    .bind(sensitive)
    .fetch_one(db)
    .await
    .expect("insert audit detail")
}

async fn insert_child(
    db: &DbPool,
    table: &str,
    entity: &str,
    record_id: Uuid,
    label_col: &str,
    label: &str,
    at: DateTime<Utc>,
) -> Uuid {
    sqlx::query_scalar(&format!(
        "INSERT INTO \"{table}\" (entity_name, record_id, \"{label_col}\", created_at) \
         VALUES ($1, $2, $3, $4) RETURNING id"
    ))
    .bind(entity)
    .bind(record_id.to_string())
    .bind(label)
    .bind(at)
    .fetch_one(db)
    .await
    .unwrap_or_else(|e| panic!("insert {table}: {e}"))
}

async fn insert_linked_decision(
    db: &DbPool,
    entity: &str,
    record_id: Uuid,
    title: &str,
    at: DateTime<Utc>,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO dashboard_decision (title, status, created_at) \
         VALUES ($1, 'open', $2) RETURNING id",
    )
    .bind(title)
    .bind(at)
    .fetch_one(db)
    .await
    .expect("insert decision");
    sqlx::query(
        "INSERT INTO record_relationship \
            (from_entity_name, from_record_id, to_entity_name, to_record_id, relationship_type) \
         VALUES ($1, $2, 'dashboard_decision', $3, 'related')",
    )
    .bind(entity)
    .bind(record_id.to_string())
    .bind(id.to_string())
    .execute(db)
    .await
    .expect("link decision");
    id
}

async fn entity_id(db: &DbPool, logicalname: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM entity_info WHERE logicalname = $1 \
         AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("resolve entity id")
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

/// A role granting `{entity}.read` at `level` (0 None, 1 Team, 2 BU, 3
/// Global), assigned to `user`.
async fn grant_read(db: &DbPool, user: Uuid, entity: &str, level: i16) {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("timeline-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert role");
    let key = format!("{entity}.read");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
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
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role");
    let ent = entity_id(db, entity).await;
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, $4, $4, $4, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(ent)
    .bind(level)
    .execute(db)
    .await
    .expect("scope role");
}

/// A View-capability share of one row to `user`.
async fn share(db: &DbPool, entity: &str, record_id: Uuid, user: Uuid) {
    let ent = entity_id(db, entity).await;
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)",
    )
    .bind(record_id)
    .bind(ent)
    .bind(user)
    .execute(db)
    .await
    .expect("insert record share");
}

fn ctx(
    user_id: Uuid,
    is_admin: bool,
    privileges: &[String],
    field_grants: &[String],
) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin,
        privileges: privileges.iter().cloned().collect(),
        field_grants: field_grants.iter().cloned().collect(),
        field_write_grants: HashSet::new(),
        // D-589: the pre-D-589 behaviour (every non-sensitive field on bulk surfaces).
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

fn admin() -> SecurityContext {
    ctx(Uuid::now_v7(), true, &[], &[])
}

fn opts(page_size: i64, cursor: Option<String>) -> TimelineOptions {
    TimelineOptions::from_query(&TimelineQuery {
        cursor,
        page_size: Some(page_size),
        kinds: None,
    })
    .expect("valid timeline query")
}

/// Every entry exactly once across pages of 2, 3 and 7, with most entries
/// sharing one timestamp across four sources and one source holding several
/// rows at that timestamp — the case a naive `(occurred_at, id)` keyset
/// merge gets wrong.
#[tokio::test]
async fn timeline_keyset_pages_every_entry_exactly_once_across_equal_timestamps() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (entity, _) = provision_parent(&state).await;
    let record = insert_parent_record(db, &entity).await;

    let t = Utc::now() - Duration::hours(1);
    let t = DateTime::<Utc>::from_timestamp_micros(t.timestamp_micros()).expect("micros");
    let earlier = t - Duration::seconds(5);

    let mut expected: HashSet<(String, Uuid)> = HashSet::new();
    for _ in 0..3 {
        let h = insert_header(db, &entity, record, 1, t).await;
        expected.insert(("audit_event".into(), h));
        let d = insert_detail(db, h, "status", Some("open"), Some("closed"), false).await;
        expected.insert(("state_transition".into(), d));
        // A non-state field change is not a transition.
        insert_detail(db, h, "name", Some("a"), Some("b"), false).await;
    }
    let h = insert_header(db, &entity, record, 0, earlier).await;
    expected.insert(("audit_event".into(), h));
    for i in 0..3 {
        let n = insert_child(db, "note", &entity, record, "title", &format!("n{i}"), t).await;
        expected.insert(("note".into(), n));
        let c = insert_child(
            db,
            "communication",
            &entity,
            record,
            "subject",
            &format!("c{i}"),
            t,
        )
        .await;
        expected.insert(("communication".into(), c));
    }
    let n = insert_child(db, "note", &entity, record, "title", "old", earlier).await;
    expected.insert(("note".into(), n));
    let d = insert_linked_decision(db, &entity, record, "Go", t).await;
    expected.insert(("decision".into(), d));
    // Noise on another record of the same entity must never appear.
    let other = insert_parent_record(db, &entity).await;
    insert_child(db, "note", &entity, other, "title", "other", t).await;
    insert_header(db, &entity, other, 1, t).await;

    let all = record_timeline(&state, &admin(), &entity, record, &opts(200, None))
        .await
        .expect("single page");
    assert!(all.next_cursor.is_none());
    let all_keys: Vec<(String, Uuid)> = all
        .items
        .iter()
        .map(|e| (e.kind.as_str().to_owned(), e.source_id))
        .collect();
    assert_eq!(
        all_keys.iter().cloned().collect::<HashSet<_>>(),
        expected,
        "the full timeline is exactly the fixture set"
    );
    assert_eq!(all_keys.len(), expected.len(), "no entry twice in one page");
    // Documented order: newest first, then kind name, then id newest first.
    for pair in all.items.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let ka = (
            std::cmp::Reverse(a.occurred_at),
            a.kind.as_str(),
            std::cmp::Reverse(a.source_id),
        );
        let kb = (
            std::cmp::Reverse(b.occurred_at),
            b.kind.as_str(),
            std::cmp::Reverse(b.source_id),
        );
        assert!(ka < kb, "entries out of order: {a:?} then {b:?}");
    }

    for page_size in [2, 3, 7] {
        let mut seen: Vec<(String, Uuid)> = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(pages < 50, "paging did not terminate");
            let page = record_timeline(&state, &admin(), &entity, record, &opts(page_size, cursor))
                .await
                .expect("page");
            assert!(page.items.len() as i64 <= page_size);
            seen.extend(
                page.items
                    .iter()
                    .map(|e| (e.kind.as_str().to_owned(), e.source_id)),
            );
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(
            seen, all_keys,
            "pages of {page_size} concatenate to exactly the single-page order"
        );
    }
}

/// The caller reads the record (Global) but holds `None` scope on notes,
/// communications and decisions, with one note and one communication shared
/// to them: only those two child rows appear; the decision does not.
#[tokio::test]
async fn timeline_hides_child_rows_the_caller_cannot_read_individually() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (entity, _) = provision_parent(&state).await;
    let record = insert_parent_record(db, &entity).await;
    let t = Utc::now();

    let visible_note = insert_child(db, "note", &entity, record, "title", "shared", t).await;
    let hidden_note = insert_child(db, "note", &entity, record, "title", "hidden", t).await;
    let visible_comm =
        insert_child(db, "communication", &entity, record, "subject", "shared", t).await;
    let hidden_comm =
        insert_child(db, "communication", &entity, record, "subject", "hidden", t).await;
    let hidden_decision = insert_linked_decision(db, &entity, record, "Secret", t).await;

    let user = insert_user(db).await;
    grant_read(db, user, &entity, 3).await;
    grant_read(db, user, "note", 0).await;
    grant_read(db, user, "communication", 0).await;
    grant_read(db, user, "dashboard_decision", 0).await;
    share(db, "note", visible_note, user).await;
    share(db, "communication", visible_comm, user).await;

    let privileges: Vec<String> = [
        entity.as_str(),
        "note",
        "communication",
        "dashboard_decision",
    ]
    .iter()
    .map(|e| format!("{e}.read"))
    .collect();
    let caller = ctx(user, false, &privileges, &[]);

    let page = record_timeline(&state, &caller, &entity, record, &opts(200, None))
        .await
        .expect("timeline");
    let ids: HashSet<Uuid> = page.items.iter().map(|e| e.source_id).collect();
    assert!(ids.contains(&visible_note), "a shared note appears");
    assert!(
        ids.contains(&visible_comm),
        "a shared communication appears"
    );
    assert!(
        !ids.contains(&hidden_note),
        "an unshared note must not appear"
    );
    assert!(
        !ids.contains(&hidden_comm),
        "an unshared communication must not appear"
    );
    assert!(
        !ids.contains(&hidden_decision),
        "an unreadable decision must not appear"
    );

    // Without the entity privilege at all, the source is skipped entirely.
    let no_notes = ctx(user, false, &privileges[..1], &[]);
    let page = record_timeline(&state, &no_notes, &entity, record, &opts(200, None))
        .await
        .expect("timeline without child privileges");
    assert!(
        page.items.iter().all(
            |e| e.kind != TimelineEntryKind::Note && e.kind != TimelineEntryKind::Communication
        ),
        "no child rows without the child entity's read privilege"
    );
}

/// A caller who cannot read the record gets `NotFound` from both routes, and
/// nothing about its children or audit trail.
#[tokio::test]
async fn timeline_and_history_are_not_found_for_a_record_the_caller_cannot_read() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (entity, _) = provision_parent(&state).await;
    let record = insert_parent_record(db, &entity).await;
    insert_child(db, "note", &entity, record, "title", "n", Utc::now()).await;
    insert_header(db, &entity, record, 1, Utc::now()).await;

    let user = insert_user(db).await;
    grant_read(db, user, &entity, 0).await; // None tier, no share
    grant_read(db, user, "note", 3).await;
    let caller = ctx(
        user,
        false,
        &[format!("{entity}.read"), "note.read".into()],
        &[],
    );

    let timeline = record_timeline(&state, &caller, &entity, record, &opts(50, None)).await;
    assert!(matches!(timeline, Err(AppError::NotFound)), "{timeline:?}");
    let history = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery::default(),
    )
    .await;
    assert!(matches!(history, Err(AppError::NotFound)), "{history:?}");

    // A record that does not exist is NotFound too, even for an admin.
    let missing = record_timeline(&state, &admin(), &entity, Uuid::now_v7(), &opts(50, None)).await;
    assert!(matches!(missing, Err(AppError::NotFound)), "{missing:?}");
}

/// B-R12: `secret_b` (sensitive, no read grant) is never named — its only
/// change is dropped whole — and `secret_a` (sensitive, granted) is shown as
/// changed with no values. A change with no field rows (a delete) is kept.
#[tokio::test]
async fn history_drops_ungranted_fields_and_masks_sensitive_ones() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (entity, _) = provision_parent(&state).await;
    let record = insert_parent_record(db, &entity).await;
    let t = Utc::now() - Duration::minutes(10);

    let update = insert_header(db, &entity, record, 1, t).await;
    insert_detail(db, update, "name", Some("old"), Some("new"), false).await;
    insert_detail(
        db,
        update,
        "secret_a",
        Some("********"),
        Some("********"),
        true,
    )
    .await;
    insert_detail(
        db,
        update,
        "secret_b",
        Some("********"),
        Some("********"),
        true,
    )
    .await;
    let hidden_only = insert_header(db, &entity, record, 1, t + Duration::minutes(1)).await;
    insert_detail(
        db,
        hidden_only,
        "secret_b",
        Some("********"),
        Some("********"),
        true,
    )
    .await;
    let deleted = insert_header(db, &entity, record, 2, t + Duration::minutes(2)).await;

    let user = insert_user(db).await;
    grant_read(db, user, &entity, 3).await;
    let caller = ctx(
        user,
        false,
        &[format!("{entity}.read")],
        &[format!("{entity}.secret_a")],
    );

    let page = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery::default(),
    )
    .await
    .expect("history");
    let ids: Vec<Uuid> = page.items.iter().map(|c| c.audit_id).collect();
    assert_eq!(
        ids,
        vec![deleted, update],
        "newest first; the hidden-only change is dropped"
    );
    assert_eq!(page.items[0].operation, "soft_deleted");
    assert!(page.items[0].fields.is_empty());

    let fields = &page.items[1].fields;
    let names: Vec<&str> = fields.iter().map(|f| f.field_name.as_str()).collect();
    assert_eq!(names, vec!["name", "secret_a"], "secret_b is never named");
    let name = &fields[0];
    assert!(!name.masked);
    assert_eq!(name.old_value.as_deref(), Some("old"));
    assert_eq!(name.new_value.as_deref(), Some("new"));
    assert_eq!(name.field_type.as_deref(), Some("text"));
    let secret = &fields[1];
    assert!(secret.masked);
    assert!(secret.old_value.is_none() && secret.new_value.is_none());

    // B2-T3: one field's history only, and none for a field the caller may
    // not read.
    let name_only = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery {
            field: Some("name".into()),
            ..Default::default()
        },
    )
    .await
    .expect("one field's history");
    let ids: Vec<Uuid> = name_only.items.iter().map(|c| c.audit_id).collect();
    assert_eq!(
        ids,
        vec![update],
        "the delete has no field rows; it is not name's history"
    );
    let names: Vec<&str> = name_only.items[0]
        .fields
        .iter()
        .map(|f| f.field_name.as_str())
        .collect();
    assert_eq!(names, vec!["name"]);
    let hidden = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery {
            field: Some("secret_b".into()),
            ..Default::default()
        },
    )
    .await
    .expect("a hidden field's history");
    assert!(
        hidden.items.is_empty(),
        "a field the caller cannot read has no history"
    );

    // The timeline's audit entries follow the same field filter.
    let timeline = record_timeline(&state, &caller, &entity, record, &opts(200, None))
        .await
        .expect("timeline");
    let update_entry = timeline
        .items
        .iter()
        .find(|e| e.source_id == update)
        .expect("the update is on the timeline");
    assert_eq!(
        update_entry.detail["changed_fields"],
        serde_json::json!(["name", "secret_a"])
    );

    // Paging: one change per page, via the cursor.
    let first = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery {
            cursor: None,
            page_size: Some(1),
            ..Default::default()
        },
    )
    .await
    .expect("first page");
    assert_eq!(first.items.len(), 1);
    let second = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery {
            cursor: first.next_cursor.clone(),
            page_size: Some(1),
            ..Default::default()
        },
    )
    .await
    .expect("second page");
    assert_eq!(second.items[0].audit_id, update);
    assert!(second.next_cursor.is_none());
}

async fn get(state: &EngineState, uri: &str) -> StatusCode {
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build request");
    req.extensions_mut()
        .insert(AuthorizedContext::new(Arc::new(admin())));
    attome_records::entity_crud::routes()
        .with_state(state.clone())
        .oneshot(req)
        .await
        .expect("router call")
        .status()
}

/// A malformed cursor is a 422 through the real routes; a cursor from the
/// other route is malformed too.
#[tokio::test]
async fn malformed_cursor_is_a_422() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (entity, _) = provision_parent(&state).await;
    let record = insert_parent_record(db, &entity).await;

    let base = format!("/api/v1/{entity}/{record}");
    assert_eq!(
        get(&state, &format!("{base}/timeline")).await,
        StatusCode::OK
    );
    assert_eq!(
        get(&state, &format!("{base}/history")).await,
        StatusCode::OK
    );
    assert_eq!(
        get(&state, &format!("{base}/timeline?cursor=not-a-cursor")).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&state, &format!("{base}/history?cursor=not-a-cursor")).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&state, &format!("{base}/timeline?kinds=note,bogus")).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Z14-T5: signed by the server, but the history route's tag: the
    // timeline route's own 422.
    let history_cursor = {
        use base64::Engine as _;
        attome_types::cursor::seal(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(format!("1:change:{}", Uuid::now_v7())),
        )
    };
    assert_eq!(
        get(&state, &format!("{base}/timeline?cursor={history_cursor}")).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

/// D-540: a value the audit writer withheld (`Restricted`, `NotCaptured`, or
/// `Encrypted` under an erasure key) is never handed out; until audited
/// decryption exists it reads as masked. `Encrypted` without an erasure key
/// is stored as written and shown (see `value_withheld`), so this test uses
/// `Restricted`. A field whose old and new values are both empty is omitted.
#[tokio::test]
async fn history_masks_encrypted_values_and_omits_empty_changes() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (entity, _) = provision_parent(&state).await;
    let record = insert_parent_record(db, &entity).await;
    let t = Utc::now() - Duration::minutes(5);

    let update = insert_header(db, &entity, record, 1, t).await;
    let encrypted = insert_detail(
        db,
        update,
        "name",
        Some("Q2lwaGVy"),
        Some("dGV4dA=="),
        false,
    )
    .await;
    sqlx::query("UPDATE audit_detail SET value_mode = 1 WHERE id = $1")
        .bind(encrypted)
        .execute(db)
        .await
        .expect("mark the detail withheld");
    let empty_only = insert_header(db, &entity, record, 1, t + Duration::minutes(1)).await;
    insert_detail(db, empty_only, "name", None, None, false).await;

    let user = insert_user(db).await;
    grant_read(db, user, &entity, 3).await;
    let caller = ctx(user, false, &[format!("{entity}.read")], &[]);
    let page = record_history(
        &state,
        &caller,
        &entity,
        record,
        &RecordHistoryQuery::default(),
    )
    .await
    .expect("history");

    let change = page
        .items
        .iter()
        .find(|c| c.audit_id == update)
        .expect("the encrypted change is listed");
    let name = &change.fields[0];
    assert!(
        name.masked,
        "an encrypted value is masked, not shown as ciphertext"
    );
    assert!(name.old_value.is_none() && name.new_value.is_none());
    assert!(
        page.items.iter().all(|c| c.audit_id != empty_only),
        "a change whose only field went from empty to empty has nothing to show"
    );
}
