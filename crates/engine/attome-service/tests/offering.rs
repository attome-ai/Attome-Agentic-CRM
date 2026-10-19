//! Integration tests for `attome_service::offering::create_work_request_from_offering`
//! — exercised directly against a real database with the shipped bundles'
//! state models loaded (`support::test_state`), same harness as
//! `tests/convert.rs`.
//!
//! M70 Phase 1 acceptance (S1): the work request is created by the entity
//! engine — change-feed row, `Entity` audit event, the route's business
//! event, the creator share, lookup liveness.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod support;

use attome_testkit::skip_if_no_db;

use attome_audit::{AuditCategory, AuditOperation};
use attome_db::DbPool;
use attome_service::offering::{
    CreateWorkRequestFromOfferingRequest, create_work_request_from_offering,
};
use attome_service::token;
use attome_types::AppError;
use support::{admin_ctx, audit_events, change_events, ctx_for, insert_systemuser, test_state};
use uuid::Uuid;

/// The pepper ring portal tokens hash with (attome-auth hardening 1.4, D-500).
fn test_ring() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "attome-service-test-pepper-0123456789abcdef", &[])
}

async fn insert_sla_policy(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_sla_policy \
         (id, name, priority, resolution_target_minutes, business_hours_start_minute, business_hours_end_minute) \
         VALUES ($1, $2, 'high', 120, 540, 1020)",
    )
    .bind(id)
    .bind(format!("Offering Test SLA Policy {id}"))
    .execute(db)
    .await
    .expect("insert service_sla_policy");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_offering(
    db: &DbPool,
    name: &str,
    is_public: bool,
    is_active: bool,
    default_priority: &str,
    default_queue_ref: Option<Uuid>,
    default_sla_policy_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_offering \
         (id, name, category, default_priority, default_queue_ref, default_sla_policy_id, \
          fulfilment, is_public, is_active) \
         VALUES ($1, $2, 'it', $3, $4, $5, 'ticket', $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(default_priority)
    .bind(default_queue_ref)
    .bind(default_sla_policy_id)
    .bind(is_public)
    .bind(is_active)
    .execute(db)
    .await
    .expect("insert service_offering");
    id
}

fn request(title: &str, requester_id: Uuid) -> CreateWorkRequestFromOfferingRequest {
    CreateWorkRequestFromOfferingRequest {
        title: title.to_owned(),
        description: None,
        request_type: "it_request".to_owned(),
        requester_id,
        channel: None,
    }
}

#[tokio::test]
async fn creating_from_an_offering_inherits_its_defaults_and_issues_a_verifiable_token() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;

    let actor = insert_systemuser(db).await;
    let requester_id = insert_systemuser(db).await;
    let sla_policy_id = insert_sla_policy(db).await;
    // G3-T1: the offering's default queue is a work queue record.
    let queue_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_work_queue (id, name, distribution) VALUES ($1, 'Laptops', 'manual')",
    )
    .bind(queue_id)
    .execute(db)
    .await
    .expect("insert service_work_queue");
    let offering_id = insert_offering(
        db,
        "Laptop Request",
        true,
        true,
        "high",
        Some(queue_id),
        Some(sla_policy_id),
    )
    .await;

    let response = create_work_request_from_offering(
        &state,
        &admin_ctx(actor),
        offering_id,
        CreateWorkRequestFromOfferingRequest {
            title: "New laptop please".to_owned(),
            description: Some("Starting Monday".to_owned()),
            request_type: "it_request".to_owned(),
            requester_id,
            channel: None,
        },
        &test_ring(),
    )
    .await
    .expect("create_work_request_from_offering");

    assert_eq!(response.status, "new");

    #[derive(sqlx::FromRow)]
    struct StoredWorkRequest {
        status: String,
        priority: Option<String>,
        queue_ref: Option<String>,
        sla_policy_id: Option<Uuid>,
        offering_id: Option<Uuid>,
        portal_public_id: Option<String>,
        portal_secret_hash: Option<String>,
        created_by: Option<Uuid>,
    }
    let stored = sqlx::query_as::<_, StoredWorkRequest>(
        "SELECT status, priority, queue_ref, sla_policy_id, offering_id, portal_public_id, \
                portal_secret_hash, created_by \
         FROM service_work_request WHERE id = $1",
    )
    .bind(response.work_request_id)
    .fetch_one(db)
    .await
    .expect("read created work request");

    assert_eq!(stored.status, "new");
    assert_eq!(
        stored.priority.as_deref(),
        Some("high"),
        "inherited from the offering's default_priority"
    );
    assert_eq!(
        stored.queue_ref.as_deref(),
        Some(queue_id.to_string().as_str()),
        "inherited from the offering's default_queue_ref"
    );
    assert_eq!(stored.sla_policy_id, Some(sla_policy_id));
    assert_eq!(stored.offering_id, Some(offering_id));
    assert_eq!(stored.created_by, Some(actor), "stamped with the caller");
    assert!(
        stored
            .portal_secret_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with("hmac256")),
        "the portal token must be stored as peppered HMAC (D-500)"
    );

    // The returned bearer must verify against exactly the stored hash, and
    // its public_id half must match what got persisted.
    let (public_id, secret) = token::parse_bearer(&response.portal_token).expect("parse_bearer");
    assert_eq!(
        public_id.to_string(),
        stored.portal_public_id.expect("portal_public_id set")
    );
    assert!(
        token::verify(secret, stored.portal_secret_hash.as_deref(), &test_ring())
            .await
            .expect("verify")
    );

    // S1: the engine's evidence.
    let id = response.work_request_id;
    assert_eq!(
        change_events(db, "service_work_request", id, "create").await,
        1
    );
    assert_eq!(
        audit_events(db, id, AuditCategory::Entity, AuditOperation::Create).await,
        1
    );
    assert_eq!(
        audit_events(db, id, AuditCategory::BusinessEvent, AuditOperation::Create).await,
        1
    );
    let shares: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM record_share WHERE record_id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("count creator shares");
    assert_eq!(shares, 1, "the D-133 creator share");
}

/// The raw INSERT accepted any `requester_id`; the engine's lookup-liveness
/// check refuses one that names no user.
#[tokio::test]
async fn a_requester_that_does_not_exist_is_a_validation_error() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let offering_id = insert_offering(db, "Desk Move", true, true, "low", None, None).await;

    let err = create_work_request_from_offering(
        &state,
        &admin_ctx(actor),
        offering_id,
        request("Ghost requester", Uuid::now_v7()),
        &test_ring(),
    )
    .await
    .expect_err("a dangling requester_id must be refused");
    assert!(
        matches!(&err, AppError::Validation(m) if m == "requester_id: lookup target does not exist or is deleted"),
        "expected Validation, got {err:?}"
    );
}

#[tokio::test]
async fn creating_without_the_create_privilege_is_forbidden() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let user = insert_systemuser(db).await;
    let offering_id = insert_offering(db, "Badge", true, true, "low", None, None).await;

    let err = create_work_request_from_offering(
        &state,
        &ctx_for(user, &["service_offering.read"]),
        offering_id,
        request("No privilege", user),
        &test_ring(),
    )
    .await
    .expect_err("no service_work_request.create");
    assert!(matches!(err, AppError::Forbidden), "got {err:?}");
}

#[tokio::test]
async fn creating_from_a_nonexistent_offering_is_not_found() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let requester_id = insert_systemuser(db).await;

    let err = create_work_request_from_offering(
        &state,
        &admin_ctx(actor),
        Uuid::now_v7(),
        request("Doesn't matter", requester_id),
        &test_ring(),
    )
    .await
    .expect_err("a nonexistent offering must fail");
    assert!(matches!(err, AppError::NotFound));
}

#[tokio::test]
async fn creating_from_an_inactive_offering_is_not_found() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let requester_id = insert_systemuser(db).await;
    let offering_id = insert_offering(db, "Retired Offering", true, false, "low", None, None).await;

    let err = create_work_request_from_offering(
        &state,
        &admin_ctx(actor),
        offering_id,
        request("Doesn't matter", requester_id),
        &test_ring(),
    )
    .await
    .expect_err("an inactive offering must fail the same as a missing one");
    assert!(matches!(err, AppError::NotFound));
}
