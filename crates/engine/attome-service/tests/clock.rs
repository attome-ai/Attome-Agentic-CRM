//! Integration tests for `attome_service::clock` (M73/D-422) — pause/resume
//! elapsed-time accounting, the breach sweep's paused-clock exclusion, and
//! breach escalation. Requires a live, throwaway Postgres, same convention
//! `tests/convert.rs` and `attome-workflow/tests/execution.rs` already use;
//! skips loudly when no `DATABASE_URL`/test database is configured.

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
use attome_service::clock::PauseReason;
use attome_testkit::skip_if_no_db;
use chrono::{DateTime, Utc};
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
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Same env-var-mutation serialization `attome-workflow/tests/execution.rs`
/// documents (`attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV`
/// synchronously, and `cargo test` runs this file's tests concurrently).
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
    ensure_note_entity(db).await;
}

/// `sla::sweep_breaches` and `clock`'s auto-pause path both write a
/// system-authored `note`. That entity's provisioning lives in
/// `attome-api::note_seed` (a crate this test intentionally does not depend
/// on — `attome-api` already depends on `attome-service` in production, and a
/// dev-dependency the other way is unnecessary complexity for one small
/// entity), so this mirrors that seed's `ensure_entity`/`ensure_attribute`
/// calls directly — the same `attome-metadata::provision` primitives, just
/// inlined for the test.
async fn ensure_note_entity(db: &DbPool) {
    use attome_metadata::provision::{ensure_attribute, ensure_entity};
    let id = ensure_entity(db, "note", "Note", Some("title"), false)
        .await
        .expect("ensure note entity");
    for (ln, dn, ft, req) in [
        ("title", "Title", "text", true),
        ("note_text", "Note Text", "text", true),
        ("entity_name", "Entity Name", "text", true),
        ("record_id", "Record Id", "text", true),
    ] {
        ensure_attribute(db, id, ln, dn, ft, req, false, false, false, None, None)
            .await
            .expect("ensure note attribute");
    }
    ensure_attribute(
        db,
        id,
        "is_customer_visible",
        "Customer Visible",
        "bool",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .expect("ensure note.is_customer_visible");
}

async fn insert_systemuser(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(id)
        .bind(format!("clock-test-{id}"))
        .execute(db)
        .await
        .expect("insert user_account");
    id
}

async fn insert_policy(
    db: &DbPool,
    priority: &str,
    target_minutes: i64,
    start_minute: i32,
    end_minute: i32,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_sla_policy \
             (id, name, priority, resolution_target_minutes, \
              business_hours_start_minute, business_hours_end_minute, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6, true)",
    )
    .bind(id)
    .bind(format!("Clock Test Policy {id}"))
    .bind(priority)
    .bind(target_minutes)
    .bind(start_minute)
    .bind(end_minute)
    .execute(db)
    .await
    .expect("insert service_sla_policy");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_ticket(
    db: &DbPool,
    sla_policy_id: Option<Uuid>,
    resolution_due_at: Option<DateTime<Utc>>,
    status: &str,
    assignee_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_ticket \
             (id, ticket_number, title, priority, status, sla_policy_id, \
              resolution_due_at, assignee_id) \
         VALUES ($1, $2, 'Clock Test Ticket', 'medium', $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("TKT-CLOCK-{id}"))
    .bind(status)
    .bind(sla_policy_id)
    .bind(resolution_due_at)
    .bind(assignee_id)
    .execute(db)
    .await
    .expect("insert service_ticket");
    id
}

async fn insert_clock(
    db: &DbPool,
    ticket_id: Uuid,
    state: &str,
    paused_reason: Option<&str>,
    elapsed_business_seconds: i64,
    state_changed_at: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO service_sla_clock \
             (id, ticket_ref, state, paused_reason, elapsed_business_seconds, state_changed_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(ticket_id)
    .bind(state)
    .bind(paused_reason)
    .bind(elapsed_business_seconds)
    .bind(state_changed_at)
    .execute(db)
    .await
    .expect("insert service_sla_clock");
}

async fn read_escalation(db: &DbPool, ticket_id: Uuid) -> (Option<bool>, Option<f64>) {
    sqlx::query_as(
        "SELECT sla_breached, escalation_level::double precision \
         FROM service_ticket WHERE id = $1",
    )
    .bind(ticket_id)
    .fetch_one(db)
    .await
    .expect("read ticket escalation state")
}

/// The checklist's required proof: business time that elapses while the
/// clock is paused is never added to `elapsed_business_seconds` — resuming a
/// clock that has been sitting paused for hours must show exactly the
/// banked total from before the pause, and pausing again almost immediately
/// after resuming must add only a few seconds, not the paused duration.
#[tokio::test]
async fn paused_time_is_excluded_from_elapsed_business_seconds() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let ticket_id = insert_ticket(db, None, None, "open", None).await;
    // Simulate a clock that banked 100s of business time and has been
    // sitting paused for 10 (wall-clock) hours.
    let far_past = Utc::now() - chrono::Duration::hours(10);
    insert_clock(db, ticket_id, "paused", Some("on_hold"), 100, far_past).await;

    let resumed = attome_service::clock::resume_ticket(&state, ticket_id, Uuid::now_v7())
        .await
        .expect("resume_ticket");
    assert_eq!(resumed.state, "running");
    assert_eq!(
        resumed.elapsed_business_seconds, 100,
        "the 10 hours spent paused must not be added to elapsed_business_seconds"
    );

    let paused_again =
        attome_service::clock::pause_ticket(&state, ticket_id, PauseReason::OnHold, Uuid::now_v7())
            .await
            .expect("pause_ticket");
    let running_segment = paused_again.elapsed_business_seconds - 100;
    assert!(
        (0..30).contains(&running_segment),
        "the running segment between resume and this pause must be a few seconds \
         (got {running_segment}s) — nowhere near the 10 paused hours"
    );
}

/// Pausing an already-paused clock is idempotent: the reason may change, but
/// `elapsed_business_seconds`/the transition instant must not be re-stamped
/// (that would silently discard the banked running segment).
#[tokio::test]
async fn re_pausing_an_already_paused_clock_only_updates_the_reason() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let ticket_id = insert_ticket(db, None, None, "open", None).await;
    let changed_at = Utc::now() - chrono::Duration::hours(3);
    insert_clock(
        db,
        ticket_id,
        "paused",
        Some("waiting_customer"),
        42,
        changed_at,
    )
    .await;

    let view = attome_service::clock::pause_ticket(
        &state,
        ticket_id,
        PauseReason::OutOfScope,
        Uuid::now_v7(),
    )
    .await
    .expect("pause_ticket");

    assert_eq!(view.state, "paused");
    assert_eq!(view.paused_reason.as_deref(), Some("out_of_scope"));
    assert_eq!(
        view.elapsed_business_seconds, 42,
        "elapsed_business_seconds must not change on a re-pause"
    );
}

/// `sweep_breaches` must skip a ticket whose clock is currently paused (its
/// `resolution_due_at` is stale wall-clock time, not a live business-time
/// deadline while paused), and must escalate — setting `escalation_level` —
/// the ticket it does mark breached.
#[tokio::test]
async fn sweep_breaches_skips_paused_tickets_and_escalates_the_rest() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let assignee_id = insert_systemuser(db).await;
    let policy_id = insert_policy(db, "clock-sweep-test", 60, 0, 1440).await;
    let past_due = Utc::now() - chrono::Duration::minutes(5);

    let breaching_ticket = insert_ticket(
        db,
        Some(policy_id),
        Some(past_due),
        "open",
        Some(assignee_id),
    )
    .await;

    let paused_ticket = insert_ticket(
        db,
        Some(policy_id),
        Some(past_due),
        "open",
        Some(assignee_id),
    )
    .await;
    insert_clock(db, paused_ticket, "paused", Some("on_hold"), 0, Utc::now()).await;

    let breached = attome_service::sla::sweep_breaches(db, &state.base.config.notification)
        .await
        .expect("sweep_breaches");
    assert_eq!(
        breached, 1,
        "only the unpaused, overdue ticket should be newly marked breached"
    );

    let (is_breached, level) = read_escalation(db, breaching_ticket).await;
    assert_eq!(is_breached, Some(true));
    assert_eq!(
        level,
        Some(1.0),
        "the breach must escalate to tier 0 (the assignee) => escalation_level 1"
    );

    let (paused_is_breached, paused_level) = read_escalation(db, paused_ticket).await;
    assert_ne!(
        paused_is_breached,
        Some(true),
        "a paused ticket must never be marked breached"
    );
    assert!(
        paused_level.is_none_or(|l| l == 0.0),
        "a paused ticket must not be escalated either"
    );
}

/// `sweep_auto_pause` reconciles a ticket's clock from the entity change
/// feed: a `waiting_on_customer` status update pauses a running clock, and a
/// later update off that status auto-resumes a clock this consumer itself
/// paused.
#[tokio::test]
async fn auto_pause_sweep_pauses_on_waiting_and_resumes_after() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let ticket_id = insert_ticket(db, None, None, "open", None).await;

    // Simulate the generic entity engine's own change-feed emission for a
    // status update into waiting_on_customer.
    sqlx::query("UPDATE service_ticket SET status = 'waiting_on_customer' WHERE id = $1")
        .bind(ticket_id)
        .execute(db)
        .await
        .expect("update ticket status");
    let mut conn = db.acquire().await.expect("acquire connection");
    attome_core::change_feed::emit(
        &mut conn,
        "service_ticket",
        ticket_id,
        attome_core::change_feed::ChangeOperation::Update,
    )
    .await
    .expect("emit change event");
    drop(conn);

    let reconciled = attome_service::clock::sweep_auto_pause(db)
        .await
        .expect("sweep_auto_pause (pause pass)");
    assert_eq!(reconciled, 1);

    let (state_after_pause,): (String,) =
        sqlx::query_as("SELECT state FROM service_sla_clock WHERE ticket_ref = $1")
            .bind(ticket_id)
            .fetch_one(db)
            .await
            .expect("read clock state");
    assert_eq!(state_after_pause, "paused");

    // Now move the ticket off waiting_on_customer and prove the sweep
    // resumes the clock it auto-paused.
    sqlx::query("UPDATE service_ticket SET status = 'in_progress' WHERE id = $1")
        .bind(ticket_id)
        .execute(db)
        .await
        .expect("update ticket status");
    let mut conn = db.acquire().await.expect("acquire connection");
    attome_core::change_feed::emit(
        &mut conn,
        "service_ticket",
        ticket_id,
        attome_core::change_feed::ChangeOperation::Update,
    )
    .await
    .expect("emit change event");
    drop(conn);

    let reconciled_again = attome_service::clock::sweep_auto_pause(db)
        .await
        .expect("sweep_auto_pause (resume pass)");
    assert_eq!(reconciled_again, 1);

    let (state_after_resume,): (String,) =
        sqlx::query_as("SELECT state FROM service_sla_clock WHERE ticket_ref = $1")
            .bind(ticket_id)
            .fetch_one(db)
            .await
            .expect("read clock state");
    assert_eq!(state_after_resume, "running");
}

/// `sweep_auto_pause` also stamps `service_ticket.resolved_at` the first time
/// `status` crosses into `resolved`/`closed` (the timestamp `analytics_
/// seed`'s mean-time-to-resolve query reads), and clears it back to NULL if
/// the ticket is later reopened.
#[tokio::test]
async fn auto_pause_sweep_stamps_and_clears_resolved_at() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let ticket_id = insert_ticket(db, None, None, "open", None).await;

    async fn emit_ticket_update(db: &DbPool, ticket_id: Uuid) {
        let mut conn = db.acquire().await.expect("acquire connection");
        attome_core::change_feed::emit(
            &mut conn,
            "service_ticket",
            ticket_id,
            attome_core::change_feed::ChangeOperation::Update,
        )
        .await
        .expect("emit change event");
    }

    sqlx::query("UPDATE service_ticket SET status = 'resolved' WHERE id = $1")
        .bind(ticket_id)
        .execute(db)
        .await
        .expect("update ticket status to resolved");
    emit_ticket_update(db, ticket_id).await;
    attome_service::clock::sweep_auto_pause(db)
        .await
        .expect("sweep_auto_pause (resolve pass)");

    let (resolved_at,): (Option<DateTime<Utc>>,) =
        sqlx::query_as("SELECT resolved_at FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(db)
            .await
            .expect("read resolved_at");
    assert!(
        resolved_at.is_some(),
        "resolved_at must be stamped once status reads resolved"
    );

    sqlx::query("UPDATE service_ticket SET status = 'open' WHERE id = $1")
        .bind(ticket_id)
        .execute(db)
        .await
        .expect("reopen ticket");
    emit_ticket_update(db, ticket_id).await;
    attome_service::clock::sweep_auto_pause(db)
        .await
        .expect("sweep_auto_pause (reopen pass)");

    let (resolved_at_after_reopen,): (Option<DateTime<Utc>>,) =
        sqlx::query_as("SELECT resolved_at FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_one(db)
            .await
            .expect("read resolved_at after reopen");
    assert!(
        resolved_at_after_reopen.is_none(),
        "resolved_at must be cleared once the ticket is reopened"
    );
}

// ── D-517: unresolved SLAs and recalculation ─────────────────────────────

/// A policy whose `calendar_ref` names `calendar_id` (which may not exist),
/// under a priority unique to the calling test so `apply_policy` selects it.
async fn insert_calendar_policy(db: &DbPool, priority: &str, calendar_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_sla_policy \
             (id, name, priority, resolution_target_minutes, business_hours_start_minute, \
              business_hours_end_minute, calendar_ref, is_active) \
         VALUES ($1, $2, $3, 240, 540, 1020, $4, true)",
    )
    .bind(id)
    .bind(format!("Calendar Policy {id}"))
    .bind(priority)
    .bind(calendar_id.to_string())
    .execute(db)
    .await
    .expect("insert calendar-backed service_sla_policy");
    id
}

/// Repairs a dangling `calendar_ref` by creating the calendar it names: a
/// 24x7 UTC calendar, so expected business time equals wall-clock time.
async fn insert_24x7_calendar(db: &DbPool, id: Uuid) {
    let window = serde_json::json!([{ "start_minute": 0, "end_minute": 1440 }]);
    let days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let hours: serde_json::Map<String, serde_json::Value> = days
        .iter()
        .map(|d| (d.to_string(), window.clone()))
        .collect();
    sqlx::query(
        "INSERT INTO calendar (id, name, tz, working_days, hours, is_active, owner_layer) \
         VALUES ($1, $2, 'UTC', $3, $4, true, 'project')",
    )
    .bind(id)
    .bind(format!("clock-test-24x7-{id}"))
    .bind(days.iter().map(|d| d.to_string()).collect::<Vec<_>>())
    .bind(serde_json::Value::Object(hours))
    .execute(db)
    .await
    .expect("insert calendar");
}

async fn read_sla_state(
    db: &DbPool,
    ticket_id: Uuid,
) -> (Option<DateTime<Utc>>, Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT resolution_due_at, sla_calculation_status, sla_unresolved_reason \
         FROM service_ticket WHERE id = $1",
    )
    .bind(ticket_id)
    .fetch_one(db)
    .await
    .expect("read ticket SLA state")
}

async fn calculation_rows(
    db: &DbPool,
    ticket_id: Uuid,
) -> Vec<(String, String, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT calculation_type, outcome, calendar_content_hash, calendar_tzdb_version \
         FROM service_sla_calculation WHERE ticket_ref = $1 ORDER BY id",
    )
    .bind(ticket_id)
    .fetch_all(db)
    .await
    .expect("read service_sla_calculation rows")
}

/// The decision's core rule: a ticket whose SLA calendar cannot be resolved
/// is still assigned its policy, gets no deadline and an explicit reason, is
/// never breached, and gets a real deadline once the calendar exists and the
/// SLA is recalculated — with evidence rows for both calculations.
#[tokio::test]
async fn an_unresolvable_calendar_leaves_the_sla_unresolved_until_recalculated() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let calendar_id = Uuid::now_v7(); // not created yet
    let priority = format!("d517-apply-{calendar_id}");
    let policy_id = insert_calendar_policy(db, &priority, calendar_id).await;
    let ticket_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_ticket (id, ticket_number, title, priority, status) \
         VALUES ($1, $2, 'D-517 Ticket', $3, 'open')",
    )
    .bind(ticket_id)
    .bind(format!("TKT-D517-{ticket_id}"))
    .bind(&priority)
    .execute(db)
    .await
    .expect("insert ticket");

    let applied = attome_service::sla::apply_policy(db, ticket_id)
        .await
        .expect("apply_policy must not fail ticket handling")
        .expect("the policy is still assigned");
    assert_eq!(applied.sla_policy_id, policy_id);
    assert_eq!(applied.resolution_due_at, None);
    assert_eq!(
        applied.sla_calculation_status,
        attome_service::sla::SlaCalculationStatus::Unresolved
    );
    assert_eq!(
        applied.sla_unresolved_reason,
        Some(attome_service::sla::UnresolvedReason::CalendarUnresolved)
    );
    let (due, status, reason) = read_sla_state(db, ticket_id).await;
    assert_eq!(due, None, "no substitute deadline may be stored");
    assert_eq!(status.as_deref(), Some("unresolved"));
    assert_eq!(reason.as_deref(), Some("calendar_unresolved"));

    attome_service::sla::sweep_breaches(db, &state.base.config.notification)
        .await
        .expect("sweep_breaches");
    let (breached, _) = read_escalation(db, ticket_id).await;
    assert_ne!(breached, Some(true), "an unresolved SLA is never breached");

    insert_24x7_calendar(db, calendar_id).await;
    let recalculated = attome_service::clock::recalculate_ticket(db, ticket_id)
        .await
        .expect("recalculate_ticket");
    assert!(recalculated.recalculated);
    assert_eq!(
        recalculated.sla_calculation_status,
        Some(attome_service::sla::SlaCalculationStatus::Calculated)
    );
    let (due, status, reason) = read_sla_state(db, ticket_id).await;
    assert!(due.is_some(), "the repaired calendar yields a deadline");
    assert_eq!(status.as_deref(), Some("calculated"));
    assert_eq!(reason, None);

    let rows = calculation_rows(db, ticket_id).await;
    assert_eq!(rows.len(), 2, "one evidence row per calculation: {rows:?}");
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_str()),
        ("apply", "unresolved")
    );
    assert_eq!(
        (rows[1].0.as_str(), rows[1].1.as_str()),
        ("recalculate", "calculated")
    );
    assert_eq!(rows[1].2.as_ref().map(String::len), Some(64));
    // D-621: the version the answer depended on is recorded beside the hash —
    // absent while the calendar could not be resolved.
    assert_eq!(
        rows[0].3, None,
        "an unresolved calculation has no calendar, so no tz version"
    );
    let version = rows[1]
        .3
        .as_deref()
        .expect("the calculated row records the tz database version");
    assert_eq!(
        version,
        attome_calendar::TZDB_VERSION,
        "the evidence must name the version this crate compiled in"
    );
    assert_eq!(
        version.len(),
        5,
        "expected a YYYYx tz version, got {version}"
    );
    assert!(
        version.as_bytes()[..4].iter().all(u8::is_ascii_digit),
        "{version}"
    );
    assert!(version.as_bytes()[4].is_ascii_lowercase(), "{version}");

    // Recalculating an SLA that is no longer unresolved is a no-op.
    let again = attome_service::clock::recalculate_ticket(db, ticket_id)
        .await
        .expect("recalculate_ticket (second call)");
    assert!(!again.recalculated);
    assert_eq!(calculation_rows(db, ticket_id).await.len(), 2);
}

/// Business time that runs while the calendar is unresolvable is kept as an
/// unsettled segment on pause — not dropped, not approximated — and banked
/// exactly once recalculation can resolve it.
#[tokio::test]
async fn a_pause_with_an_unresolvable_calendar_keeps_its_segment_until_recalculated() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;

    let calendar_id = Uuid::now_v7();
    let policy_id =
        insert_calendar_policy(db, &format!("d517-pause-{calendar_id}"), calendar_id).await;
    let ticket_id = insert_ticket(
        db,
        Some(policy_id),
        Some(Utc::now() + chrono::Duration::hours(8)),
        "open",
        None,
    )
    .await;
    insert_clock(
        db,
        ticket_id,
        "running",
        None,
        0,
        Utc::now() - chrono::Duration::hours(2),
    )
    .await;

    let paused =
        attome_service::clock::pause_ticket(&state, ticket_id, PauseReason::OnHold, Uuid::now_v7())
            .await
            .expect("pause_ticket");
    assert_eq!(
        paused.elapsed_business_seconds, 0,
        "nothing may be banked from an unresolvable calendar"
    );
    let (unsettled,): (Option<String>,) =
        sqlx::query_as("SELECT unsettled_segments FROM service_sla_clock WHERE ticket_ref = $1")
            .bind(ticket_id)
            .fetch_one(db)
            .await
            .expect("read unsettled_segments");
    assert!(unsettled.is_some(), "the two-hour segment must be kept");
    let (due, status, _) = read_sla_state(db, ticket_id).await;
    assert_eq!(due, None);
    assert_eq!(status.as_deref(), Some("unresolved"));

    insert_24x7_calendar(db, calendar_id).await;
    let summary = attome_service::clock::recalculate_unresolved(&state, Uuid::now_v7(), None, 500)
        .await
        .expect("recalculate_unresolved");
    assert!(summary.calculated >= 1, "{summary:?}");

    let (elapsed, unsettled): (f64, Option<String>) = sqlx::query_as(
        "SELECT elapsed_business_seconds::double precision, unsettled_segments \
         FROM service_sla_clock WHERE ticket_ref = $1",
    )
    .bind(ticket_id)
    .fetch_one(db)
    .await
    .expect("read clock after recalculation");
    assert!(
        (7_190.0..=7_260.0).contains(&elapsed),
        "the two-hour segment must be banked at 24x7 business time, got {elapsed}s"
    );
    assert_eq!(unsettled, None);
    let (due, status, _) = read_sla_state(db, ticket_id).await;
    assert!(due.is_some());
    assert_eq!(status.as_deref(), Some("calculated"));
}
