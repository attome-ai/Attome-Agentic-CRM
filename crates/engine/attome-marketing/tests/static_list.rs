//! E7-T5: static list operations against a real database — members added
//! and removed with their events, a segment list refused, an import undone
//! exactly, the undo window enforced, and an unreadable person left out.
//!
//! `marketing_list` and `contact` are provisioned here (the marketing and
//! crm packs provision them on a deployment); fixture rows are direct SQL
//! against this binary's throwaway database (guidelines §4's test
//! exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test static_list"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use std::collections::{HashMap, HashSet};

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_marketing::static_list;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::{point_config_at, skip_if_no_db};
use attome_types::AppError;
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
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 8, "timeout": 5.0
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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod", "jwt_issuer": "attome-test",
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
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_state() -> Option<EngineState> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config).await.expect("connect");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("redis");
    let coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("storage");
    for (name, fields) in [
        (
            "marketing_list",
            &[
                ("name", "text"),
                ("kind", "text"),
                ("target_entity", "text"),
                ("member_count", "number"),
            ][..],
        ),
        ("contact", &[("name", "text"), ("email", "text")][..]),
    ] {
        let id = attome_metadata::provision::ensure_entity(&db, name, name, None, false)
            .await
            .expect("provision entity");
        for (field, field_type) in fields {
            attome_metadata::provision::ensure_attribute(
                &db, id, field, field, field_type, false, false, false, true, None, None,
            )
            .await
            .expect("provision attribute");
        }
    }
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        coordination,
        storage,
    );
    let state = EngineState::new(base);
    state
        .entities
        .swap(attome_core::build_registry(&db).await.expect("registry"));
    Some(state)
}

fn ctx(user_id: Uuid, is_admin: bool) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin,
        privileges: [
            "marketing_list.update".to_owned(),
            "marketing_list.read".to_owned(),
        ]
        .into_iter()
        .collect(),
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

async fn list(state: &EngineState, kind: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_list (id, name, kind, target_entity) VALUES ($1, 'test list', $2, 'contact')",
    )
    .bind(id)
    .bind(kind)
    .execute(&state.base.db)
    .await
    .expect("insert list");
    id
}

async fn contact(state: &EngineState) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO contact (id, name, email) VALUES ($1, 'P', $2)")
        .bind(id)
        .bind(format!("{}@example.com", id.simple()))
        .execute(&state.base.db)
        .await
        .expect("insert contact");
    id
}

async fn members(state: &EngineState, list: Uuid) -> HashSet<Uuid> {
    sqlx::query_scalar("SELECT person_id FROM marketing_list_member WHERE list_id = $1")
        .bind(list)
        .fetch_all(&state.base.db)
        .await
        .unwrap()
        .into_iter()
        .collect()
}

#[tokio::test]
async fn add_and_remove_members_audited() {
    let state = skip_if_no_db!(test_state().await);
    let admin = ctx(Uuid::now_v7(), true);
    let list = list(&state, "static").await;
    let (a, b) = (contact(&state).await, contact(&state).await);
    let added = static_list::add_members(&state, &admin, list, &[a, b, a])
        .await
        .unwrap();
    assert_eq!(added.changed, 2);
    let removed = static_list::remove_members(&state, &admin, list, &[a])
        .await
        .unwrap();
    assert_eq!(removed.changed, 1);
    assert_eq!(members(&state, list).await, HashSet::from([b]));
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_list_membership_event WHERE list_id = $1",
    )
    .bind(list)
    .fetch_one(&state.base.db)
    .await
    .unwrap();
    assert_eq!(events, 3, "two entered, one left");
}

#[tokio::test]
async fn rejects_add_to_segment_kind() {
    let state = skip_if_no_db!(test_state().await);
    let admin = ctx(Uuid::now_v7(), true);
    let list = list(&state, "segment").await;
    let person = contact(&state).await;
    let refused = static_list::add_members(&state, &admin, list, &[person]).await;
    assert!(
        matches!(refused, Err(AppError::Validation(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn import_then_undo_removes_only_imported() {
    let state = skip_if_no_db!(test_state().await);
    let admin = ctx(Uuid::now_v7(), true);
    let list = list(&state, "static").await;
    let by_hand = contact(&state).await;
    let imported = contact(&state).await;
    static_list::add_members(&state, &admin, list, &[by_hand])
        .await
        .unwrap();
    // An import that finished an hour ago and added one person.
    let import = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_list_import (id, list_id, document_id, status, created_by, finished_at) \
         VALUES ($1, $2, $3, 'done', $4, now() - interval '1 hour')",
    )
    .bind(import)
    .bind(list)
    .bind(Uuid::now_v7())
    .bind(admin.user_id)
    .execute(&state.base.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO marketing_list_member (list_id, person_id, person_entity, source, import_job_id) \
         VALUES ($1, $2, 'contact', 'import', $3)",
    )
    .bind(list)
    .bind(imported)
    .bind(import)
    .execute(&state.base.db)
    .await
    .unwrap();
    let undone = static_list::undo_import(&state, &admin, list, import)
        .await
        .unwrap();
    assert_eq!(undone.changed, 1);
    assert_eq!(members(&state, list).await, HashSet::from([by_hand]));
}

#[tokio::test]
async fn undo_after_window_conflicts() {
    let state = skip_if_no_db!(test_state().await);
    let admin = ctx(Uuid::now_v7(), true);
    let list = list(&state, "static").await;
    let import = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_list_import (id, list_id, document_id, status, created_by, finished_at) \
         VALUES ($1, $2, $3, 'done', $4, now() - interval '8 days')",
    )
    .bind(import)
    .bind(list)
    .bind(Uuid::now_v7())
    .bind(admin.user_id)
    .execute(&state.base.db)
    .await
    .unwrap();
    let refused = static_list::undo_import(&state, &admin, list, import).await;
    assert!(
        matches!(refused, Err(AppError::Conflict("list.undo_window_passed"))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn unreadable_person_rejected() {
    let state = skip_if_no_db!(test_state().await);
    // Not an administrator and no read grant on contact: nobody is readable.
    let caller = ctx(Uuid::now_v7(), false);
    let list = list(&state, "static").await;
    let person = contact(&state).await;
    let change = static_list::add_members(&state, &caller, list, &[person])
        .await
        .unwrap();
    assert_eq!(change.changed, 0);
    assert_eq!(change.skipped, 1);
    assert!(members(&state, list).await.is_empty());
}
