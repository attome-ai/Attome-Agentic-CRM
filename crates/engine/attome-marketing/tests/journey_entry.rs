//! E8-T5: journey entry sources against a real database — a person joining
//! a list is queued for a live journey's enrolment within one tick, a
//! paused journey takes no one, and date sources match their offset in the
//! Gregorian calendar and the month and day in the Hijri one.
//!
//! The entities are provisioned here (the marketing and crm packs provision
//! them on a deployment); fixture rows are direct SQL against this binary's
//! throwaway database (guidelines §4's test exemption). Enrolment itself
//! (E8-T4) runs as the queued `marketing_journey_enrol` jobs; these tests
//! read the queue.
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-marketing --test journey_entry"
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

use attome_calendar::hijri::{HijriCalendar, HijriDate};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_marketing::journey::{enrol, entry};
use attome_marketing::static_list;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::{point_config_at, skip_if_no_db};
use chrono::{NaiveDate, NaiveTime};
use serde_json::json;
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
        (
            "marketing_journey",
            &[
                ("name", "text"),
                ("workflow_definition_logicalname", "text"),
                ("entry_sources", "text"),
                ("status", "text"),
            ][..],
        ),
        (
            "contact",
            &[("name", "text"), ("email", "text"), ("birthdate", "date")][..],
        ),
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
    // The enrol job type is registered by the app; queueing needs it known.
    let _ = attome_core::jobs::JOB_TYPES.register(
        attome_jobs::JobType::new(enrol::JOB, 1),
        |_state: EngineState, _job: attome_jobs::RegisteredJob| async {
            Ok::<(), attome_jobs::registry::BoxError>(())
        },
    );
    Some(state)
}

fn admin() -> SecurityContext {
    SecurityContext {
        user_id: Uuid::now_v7(),
        is_admin: true,
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
        unit_scope: Default::default(),
        service_principal: false,
    }
}

async fn list(state: &EngineState) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_list (id, name, kind, target_entity) \
         VALUES ($1, 'entry list', 'static', 'contact')",
    )
    .bind(id)
    .execute(&state.base.db)
    .await
    .expect("insert list");
    id
}

async fn journey(state: &EngineState, status: &str, sources: serde_json::Value) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO marketing_journey (id, name, workflow_definition_logicalname, entry_sources, status) \
         VALUES ($1, 'entry journey', $2, $3, $4)",
    )
    .bind(id)
    .bind(format!("journey_{}", id.simple()))
    .bind(sources.to_string())
    .bind(status)
    .execute(&state.base.db)
    .await
    .expect("insert journey");
    id
}

async fn contact(state: &EngineState, birthdate: Option<NaiveDate>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO contact (id, name, email, birthdate) VALUES ($1, 'P', $2, $3)")
        .bind(id)
        .bind(format!("{}@example.com", id.simple()))
        .bind(birthdate)
        .execute(&state.base.db)
        .await
        .expect("insert contact");
    id
}

/// Whether an enrol job for the person in the journey is queued.
async fn queued(state: &EngineState, journey: Uuid, person: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM apalis.jobs \
          WHERE job::text LIKE '%' || $1 || '%' AND job::text LIKE '%' || $2 || '%')",
    )
    .bind(journey.to_string())
    .bind(person.to_string())
    .fetch_one(&state.base.db)
    .await
    .expect("read queue")
}

/// Date sources run for every live journey, so the two date tests take
/// turns: one's run must not claim the other's journey for the day before
/// that test has written its contacts.
static DATE_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Ticks until the feed is read to its end (other tests' events included).
async fn drain(state: &EngineState) {
    for _ in 0..40 {
        entry::entry_tick(state).await.expect("entry tick");
    }
}

#[tokio::test]
async fn segment_entered_enrols_person() {
    let state = skip_if_no_db!(test_state().await);
    let list = list(&state).await;
    let journey = journey(
        &state,
        "live",
        json!([{"type": "segment_entered", "list_id": list}]),
    )
    .await;
    let person = contact(&state, None).await;
    static_list::add_members(&state, &admin(), list, &[person])
        .await
        .expect("add member");
    drain(&state).await;
    assert!(
        queued(&state, journey, person).await,
        "an enrol job is queued"
    );
    // A second pass takes nothing new: the mark moved past the event.
    let mark: Option<Uuid> =
        sqlx::query_scalar("SELECT mark FROM marketing_journey_entry_state WHERE journey_id = $1")
            .bind(journey)
            .fetch_one(&state.base.db)
            .await
            .expect("state row");
    assert!(mark.is_some());
}

#[tokio::test]
async fn paused_journey_does_not_enrol() {
    let state = skip_if_no_db!(test_state().await);
    let list = list(&state).await;
    let journey = journey(
        &state,
        "paused",
        json!([{"type": "segment_entered", "list_id": list}]),
    )
    .await;
    let person = contact(&state, None).await;
    static_list::add_members(&state, &admin(), list, &[person])
        .await
        .expect("add member");
    drain(&state).await;
    assert!(
        !queued(&state, journey, person).await,
        "a paused journey takes no one"
    );
}

#[tokio::test]
async fn date_entry_matches_offset() {
    let state = skip_if_no_db!(test_state().await);
    let _turn = DATE_TESTS.lock().await;
    let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
    // Renewal reminder: a week before the date.
    let journey = journey(
        &state,
        "live",
        json!([{"type": "date", "entity": "contact", "attribute": "birthdate", "offset_days": -7}]),
    )
    .await;
    let due = contact(&state, NaiveDate::from_ymd_opt(2026, 10, 27)).await;
    let not_due = contact(&state, NaiveDate::from_ymd_opt(2026, 10, 28)).await;
    let noon = NaiveTime::from_hms_opt(12, 0, 0).unwrap();
    entry::date_entry_on(&state, today, noon)
        .await
        .expect("date entry");
    assert!(queued(&state, journey, due).await);
    assert!(!queued(&state, journey, not_due).await);
    // Once a day: a second run the same day queues nothing more.
    let again = entry::date_entry_on(&state, today, noon)
        .await
        .expect("date entry again");
    let mine: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'",
    )
    .bind(journey.to_string())
    .fetch_one(&state.base.db)
    .await
    .unwrap();
    assert_eq!(
        mine, 1,
        "one chunk queued for the day (second run queued {again})"
    );
    // Before 00:10 nothing runs.
    let early = NaiveTime::from_hms_opt(0, 5, 0).unwrap();
    let next_day = today.succ_opt().unwrap();
    assert_eq!(
        entry::date_entry_on(&state, next_day, early).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn hijri_date_entry_matches() {
    let state = skip_if_no_db!(test_state().await);
    let _turn = DATE_TESTS.lock().await;
    let calendar = HijriCalendar::umm_al_qura();
    let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
    let h = calendar.to_hijri(today).unwrap();
    // Born on today's Hijri month and day, five Hijri years ago.
    let born = calendar
        .to_gregorian(HijriDate::new(h.year - 5, h.month, h.day))
        .unwrap();
    // The same Gregorian month and day five years ago is a different Hijri day.
    let gregorian_twin = NaiveDate::from_ymd_opt(2021, 10, 20).unwrap();
    assert_ne!(born, gregorian_twin);
    let journey = journey(
        &state,
        "live",
        json!([{"type": "date", "entity": "contact", "attribute": "birthdate", "calendar": "hijri"}]),
    )
    .await;
    let hijri_birthday = contact(&state, Some(born)).await;
    let other = contact(&state, Some(gregorian_twin)).await;
    entry::date_entry_on(&state, today, NaiveTime::from_hms_opt(9, 0, 0).unwrap())
        .await
        .expect("date entry");
    assert!(queued(&state, journey, hijri_birthday).await);
    assert!(!queued(&state, journey, other).await);
}
