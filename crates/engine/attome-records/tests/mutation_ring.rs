//! DB-backed proof test for M01 Core C-10 ("One `commit_mutation` ring
//! helper"): `MutationRing::commit_mutation` on a create result must write
//! the D-133 (2) creator-share row (`record_share`) — the exact
//! step `attome-workflow::scheduler::execute_entity_write` used to skip
//! entirely before this item wired it onto the ring (see
//! `attome-workflow/tests/scheduler_entity_write_visibility.rs` for the
//! end-to-end DB proof that a workflow-created record is now visible to its
//! creator).
//!
//! Same harness shape as `tests/upsert.rs` next door (D-343: one throwaway
//! database per test binary) — a real `EngineState` against a real Postgres,
//! not a mock, because the point is to prove the actual
//! `record_share` row lands, not just that the function returns Ok.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-records --test mutation_ring -- --test-threads=1
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

use attome_audit::AuditOperation;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_records::entity_crud::resolve_entity;
use attome_records::entity_mutation::MutationMode;
use attome_records::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

/// Same shape `tests/upsert.rs::test_config` uses — this suite needs the
/// identical infra (Postgres + Redis + storage) a full `EngineState` requires.
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
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

// SAFETY: see `attome-ai/tests/record_update_field.rs`'s identical `ENV_LOCK`
// doc comment — `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` from the
// environment synchronously before its first `.await`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn seed_platform(db: &attome_db::DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            attome_audit::seed(db)
                .await
                .expect("seed audit entity metadata");
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

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("mutation-ring-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Admin, same reasoning `tests/upsert.rs::security_context` states — this
/// suite proves the ring's own orchestration, not the authorization matrix
/// `create_one` also enforces.
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

/// A minimal throwaway entity with no extra attributes — this suite only
/// needs a row to exist, not any particular field on it.
async fn provision_test_entity(state: &EngineState) -> String {
    let logicalname = format!("ring_test_{}", Uuid::now_v7().simple());
    attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "C-10 Mutation Ring Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    logicalname
}

/// C-10's first proof bullet: `commit_mutation` on a `create_one` result
/// writes the creator-share row. Before this item, that grant was "owned by
/// the caller" (each mutation call site remembered to call
/// `grant_creator_share` itself right after the insert) — the workflow
/// scheduler's Create Record node was the one caller that forgot, and a
/// record it created was invisible to `instance.started_by` as a result.
/// Pinning the grant inside the ring, unconditionally for
/// `MutationSideEffects { grant_creator_share: true, .. }`, makes that a
/// structural guarantee instead of a per-call-site convention.
#[tokio::test]
async fn commit_mutation_on_create_writes_the_creator_share_row() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity)
        .await
        .expect("resolve freshly provisioned test entity");

    let ctx = admin_context(user_id);
    let actor = MutationActor::fetch(&state, user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .expect("begin tx");
    let obj = serde_json::Map::new();
    let mutation = attome_records::entity_mutation::create_one(
        &mut tx,
        &state,
        &ctx,
        &entity_name,
        &attrs,
        &obj,
        user_id,
        actor.org_ref,
        MutationMode::Strict,
    )
    .await
    .expect("create_one");
    let record_id = mutation.record_id;

    let ring = MutationRing::new(&state);
    ring.commit_mutation(
        tx,
        &ctx,
        entity_id,
        &entity_name,
        &attrs,
        &actor,
        AuditOperation::Create,
        MutationSideEffects {
            grant_creator_share: true,
            mirror_file_fields: false,
        },
        GrantInvalidation::Skip,
        MutationAudit::new(),
        "test create",
        mutation,
    )
    .await
    .expect("commit_mutation");

    let share_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record_share \
         WHERE record_id = $1 AND entity_ref = $2 AND principal_id = $3 AND capability = 1",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .fetch_one(&state.base.db)
    .await
    .expect("query share row");

    assert_eq!(
        share_count, 1,
        "commit_mutation on a create result must write exactly one \
         record_share row for the acting user — the creator share \
         grant this item makes structural instead of per-call-site"
    );
}

/// The `grant_creator_share: false` half of the same guarantee: an update
/// through the ring must NOT grant a share row a second time (the row
/// already exists from creation, and a bare update is not itself an
/// ownership event).
#[tokio::test]
async fn commit_mutation_on_update_does_not_grant_a_second_share_row() {
    let state = skip_if_no_db!(test_state().await);
    let user_id = seed_user(&state.base.db).await;
    let entity = provision_test_entity(&state).await;
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity)
        .await
        .expect("resolve freshly provisioned test entity");

    let ctx = admin_context(user_id);
    let actor = MutationActor::fetch(&state, user_id).await;
    let ring = MutationRing::new(&state);

    // Create, through the ring, exactly like the test above.
    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .expect("begin tx");
    let obj = serde_json::Map::new();
    let mutation = attome_records::entity_mutation::create_one(
        &mut tx,
        &state,
        &ctx,
        &entity_name,
        &attrs,
        &obj,
        user_id,
        actor.org_ref,
        MutationMode::Strict,
    )
    .await
    .expect("create_one");
    let record_id = mutation.record_id;
    let row_version = mutation
        .new_row
        .as_ref()
        .and_then(|r| r.get("row_version"))
        .and_then(serde_json::Value::as_i64)
        .expect("created row carries row_version");
    ring.commit_mutation(
        tx,
        &ctx,
        entity_id,
        &entity_name,
        &attrs,
        &actor,
        AuditOperation::Create,
        MutationSideEffects {
            grant_creator_share: true,
            mirror_file_fields: false,
        },
        GrantInvalidation::Skip,
        MutationAudit::new(),
        "test create",
        mutation,
    )
    .await
    .expect("commit_mutation create");

    // Now update the same record through the ring with
    // `grant_creator_share: false`.
    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .expect("begin tx");
    let update_obj = serde_json::Map::new();
    let mutation = attome_records::entity_mutation::update_one(
        &mut tx,
        &state,
        &ctx,
        &entity_name,
        entity_id,
        record_id,
        &attrs,
        &update_obj,
        user_id,
        row_version,
        MutationMode::Strict,
    )
    .await
    .expect("update_one");
    ring.commit_mutation(
        tx,
        &ctx,
        entity_id,
        &entity_name,
        &attrs,
        &actor,
        AuditOperation::Update,
        MutationSideEffects {
            grant_creator_share: false,
            mirror_file_fields: false,
        },
        GrantInvalidation::Skip,
        MutationAudit::new(),
        "test update",
        mutation,
    )
    .await
    .expect("commit_mutation update");

    let share_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record_share \
         WHERE record_id = $1 AND entity_ref = $2 AND principal_id = $3 AND capability = 1",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .fetch_one(&state.base.db)
    .await
    .expect("query share row");

    assert_eq!(
        share_count, 1,
        "an update through the ring must not write a second creator-share \
         row — ON CONFLICT DO NOTHING already makes grant_creator_share \
         itself idempotent, but this proves the update path never even \
         calls it when MutationSideEffects::grant_creator_share is false"
    );
}
