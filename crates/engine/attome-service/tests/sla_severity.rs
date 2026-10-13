//! Integration test for M85 (Incident Management)'s severity-driven SLA
//! selection — `attome_service::sla::apply_policy` now tries a policy matching
//! an incident-type ticket's `severity` before falling back to the pre-M85
//! priority-based selection (`attome_service::sla::select_policy_for_ticket`).
//! Same harness shape `tests/convert.rs` already established (plain
//! `DbPool` + `minimal_config`, no full `AppState`/`EngineState` needed since
//! `apply_policy` only takes a pool).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
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
}

#[allow(clippy::too_many_arguments)]
async fn insert_policy(
    db: &DbPool,
    name: &str,
    priority: &str,
    severity: Option<&str>,
    target_minutes: i64,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_sla_policy \
             (id, name, priority, severity, resolution_target_minutes, \
              business_hours_start_minute, business_hours_end_minute, is_active) \
         VALUES ($1, $2, $3, $4, $5, 0, 1440, true)",
    )
    .bind(id)
    .bind(name)
    .bind(priority)
    .bind(severity)
    .bind(target_minutes)
    .execute(db)
    .await
    .expect("insert service_sla_policy");
    id
}

async fn insert_ticket(
    db: &DbPool,
    ticket_type: &str,
    priority: &str,
    severity: Option<&str>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_ticket \
             (id, ticket_number, title, ticket_type, priority, severity, status) \
         VALUES ($1, $2, 'M85 Severity SLA Test Ticket', $3, $4, $5, 'open')",
    )
    .bind(id)
    .bind(format!("TKT-SEV-{id}"))
    .bind(ticket_type)
    .bind(priority)
    .bind(severity)
    .execute(db)
    .await
    .expect("insert service_ticket");
    id
}

/// The checklist's severity-drives-SLA requirement: an incident-type ticket
/// with a `severity` set must be assigned the policy matching that severity,
/// even though a policy matching its `priority` also exists and would have
/// won under the pre-M85 selection.
#[tokio::test]
async fn incident_ticket_prefers_a_severity_matched_policy_over_a_priority_matched_one() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let priority_policy = insert_policy(&db, "Priority: high", "high", None, 480).await;
    let severity_policy =
        insert_policy(&db, "Severity: critical", "any", Some("critical"), 30).await;

    let ticket_id = insert_ticket(&db, "incident", "high", Some("critical")).await;

    let applied = attome_service::sla::apply_policy(&db, ticket_id)
        .await
        .expect("apply_policy")
        .expect("a policy must be assigned");

    assert_eq!(
        applied.sla_policy_id, severity_policy,
        "the severity-matched policy must win for an incident, not the priority-matched one"
    );
    assert_ne!(applied.sla_policy_id, priority_policy);
}

/// Severity must be consulted only for `ticket_type = 'incident'` — a
/// non-incident ticket keeps the pre-M85 priority-based selection unchanged,
/// even when it happens to carry a `severity` value that also matches a
/// severity-scoped policy.
#[tokio::test]
async fn non_incident_ticket_ignores_severity_and_uses_priority_selection() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let priority_policy = insert_policy(&db, "Priority: high 2", "high", None, 480).await;
    let _severity_policy =
        insert_policy(&db, "Severity: critical 2", "any", Some("critical"), 30).await;

    let ticket_id = insert_ticket(&db, "request", "high", Some("critical")).await;

    let applied = attome_service::sla::apply_policy(&db, ticket_id)
        .await
        .expect("apply_policy")
        .expect("a policy must be assigned");

    assert_eq!(
        applied.sla_policy_id, priority_policy,
        "a non-incident ticket must ignore severity entirely and use the \
         priority-based selection"
    );
}

/// An incident whose `severity` matches no active `service_sla_policy` row falls
/// back to the ordinary priority-based selection (then `priority = 'any'`),
/// exactly like the pre-M85 behavior — severity selection degrades
/// gracefully rather than leaving the ticket with no SLA policy at all.
#[tokio::test]
async fn incident_with_unmatched_severity_falls_back_to_priority_selection() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let priority_policy = insert_policy(&db, "Priority: medium 3", "medium", None, 480).await;
    // A severity policy exists, but for a different severity than the ticket carries.
    let _unrelated_severity_policy =
        insert_policy(&db, "Severity: critical 3", "any", Some("critical"), 30).await;

    let ticket_id = insert_ticket(&db, "incident", "medium", Some("low")).await;

    let applied = attome_service::sla::apply_policy(&db, ticket_id)
        .await
        .expect("apply_policy")
        .expect("a policy must be assigned via priority fallback");

    assert_eq!(applied.sla_policy_id, priority_policy);
}
