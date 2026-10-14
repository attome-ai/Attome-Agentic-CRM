//! Integration tests for `attome_service::convert` — the transaction, lock,
//! status, authorization and entity-engine behaviour of every conversion,
//! exercised directly against a real database with the shipped bundles'
//! state models loaded (`support::register_bundle_state_models`), so the
//! work request's `→ converted` transition is checked exactly as it is in
//! production.
//!
//! M70 Phase 1 acceptance (S1): per route, the destination and the work
//! request each get a change-feed row and an `Entity` audit event, the
//! route's declared `Configuration` event is written. (The calculation-rule
//! check left with v1's `calculation` rules: v2 computes values with formula
//! fields and business-rule policies, D-789.)

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod support;

use attome_testkit::skip_if_no_db;

use attome_audit::{AuditCategory, AuditOperation};
use attome_db::DbPool;
use attome_service::convert::{
    convert_work_request_to_project, convert_work_request_to_task, convert_work_request_to_ticket,
};
use attome_types::AppError;
use support::{admin_ctx, audit_events, change_events, ctx_for, insert_systemuser, test_state};
use uuid::Uuid;

async fn insert_work_request(
    db: &DbPool,
    title: &str,
    status: &str,
    requester_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_work_request \
         (id, title, description, request_type, status, requester_id, channel) \
         VALUES ($1, $2, 'a test work request', 'it_request', $3, $4, 'portal')",
    )
    .bind(id)
    .bind(title)
    .bind(status)
    .bind(requester_id)
    .execute(db)
    .await
    .expect("insert service_work_request");
    id
}

async fn insert_organization(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("Convert Test Organization {id}"))
        .execute(db)
        .await
        .expect("insert organization");
    id
}

async fn insert_project(db: &DbPool, organization_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attome_project (id, name, project_code, organization_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(format!("Convert Test Project {id}"))
    .bind(format!("PRJ-TEST-{id}"))
    .bind(organization_id)
    .execute(db)
    .await
    .expect("insert attome_project");
    id
}

async fn work_request_state(db: &DbPool, id: Uuid) -> (String, Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT status, resolved_entity_name, resolved_record_id \
         FROM service_work_request WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("read work request")
}

/// The S1 evidence every successful conversion must leave behind.
async fn assert_engine_evidence(db: &DbPool, target: &str, record_id: Uuid, work_request_id: Uuid) {
    assert_eq!(
        change_events(db, target, record_id, "create").await,
        1,
        "the destination's create must emit exactly one change-feed row"
    );
    assert_eq!(
        change_events(db, "service_work_request", work_request_id, "update").await,
        1,
        "the work request's status update must emit exactly one change-feed row"
    );
    assert_eq!(
        audit_events(db, record_id, AuditCategory::Entity, AuditOperation::Create).await,
        1,
        "the destination's Entity/Create audit event"
    );
    assert_eq!(
        audit_events(
            db,
            work_request_id,
            AuditCategory::Entity,
            AuditOperation::Update
        )
        .await,
        1,
        "the work request's Entity/Update audit event"
    );
    assert_eq!(
        audit_events(
            db,
            record_id,
            AuditCategory::Configuration,
            AuditOperation::Create
        )
        .await,
        1,
        "the route's declared mandatory Configuration/Create event"
    );
    let shares: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM record_share WHERE record_id = $1")
            .bind(record_id)
            .fetch_one(db)
            .await
            .expect("count creator shares");
    assert_eq!(
        shares, 1,
        "the destination gets the D-133 creator share, as a generic create does"
    );
}

#[tokio::test]
async fn converting_a_new_work_request_creates_a_ticket_through_the_engine() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;

    let actor = insert_systemuser(db).await;
    let requester = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Convert Me", "new", Some(requester)).await;

    let response = convert_work_request_to_ticket(&state, &admin_ctx(actor), work_request_id)
        .await
        .expect("convert_work_request_to_ticket");

    let (title, status, channel, requester_id, created_by): (
        String,
        String,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT title, status, channel, requester_id, created_by \
         FROM service_ticket WHERE id = $1",
    )
    .bind(response.ticket_id)
    .fetch_one(db)
    .await
    .expect("read created ticket");
    assert_eq!(title, "Convert Me");
    assert_eq!(status, "new");
    assert_eq!(channel.as_deref(), Some("portal"), "channel carried over");
    assert_eq!(requester_id, Some(requester));
    assert_eq!(created_by, Some(actor), "stamped with the caller");
    assert!(response.ticket_number.starts_with("TKT-"));

    let (status, resolved_entity_name, resolved_record_id) =
        work_request_state(db, work_request_id).await;
    assert_eq!(status, "converted");
    assert_eq!(resolved_entity_name.as_deref(), Some("service_ticket"));
    assert_eq!(
        resolved_record_id.as_deref(),
        Some(response.ticket_id.to_string().as_str())
    );

    assert_engine_evidence(db, "service_ticket", response.ticket_id, work_request_id).await;
}

/// `triaged → converted` is the lifecycle's other entry into `converted`.
#[tokio::test]
async fn a_triaged_work_request_converts_too() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let requester = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Triaged", "triaged", Some(requester)).await;

    convert_work_request_to_ticket(&state, &admin_ctx(actor), work_request_id)
        .await
        .expect("a triaged request converts");
    assert_eq!(work_request_state(db, work_request_id).await.0, "converted");
}

/// The engine's state-model check is live in this harness: a status the
/// bundle's lifecycle has no edge into `converted` from is refused, and the
/// whole conversion rolls back.
#[tokio::test]
async fn the_bundle_lifecycle_is_enforced_on_the_status_update() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let registry = state.state_models.load();
    let entry = registry
        .get("service_work_request")
        .expect("the bundle's work request lifecycle is loaded");
    for from in ["new", "triaged"] {
        assert!(
            entry
                .transitions
                .iter()
                .any(|t| t.from_state == from && t.to_state == "converted"),
            "platform-bundles/attome-service.json must allow {from} -> converted"
        );
    }
    assert!(
        !entry
            .transitions
            .iter()
            .any(|t| t.from_state == "converted"),
        "converted stays terminal"
    );
    drop(registry);

    // A status outside the lifecycle entirely (seeded by hand) has no edge.
    let actor = insert_systemuser(db).await;
    let requester = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Odd State", "", Some(requester)).await;
    let err = convert_work_request_to_ticket(&state, &admin_ctx(actor), work_request_id)
        .await
        .expect_err("no transition from '' to converted");
    assert!(
        matches!(err, AppError::TransitionNotAllowed(_)),
        "expected TransitionNotAllowed, got {err:?}"
    );
    let tickets: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM service_ticket WHERE title = 'Odd State'")
            .fetch_one(db)
            .await
            .expect("count tickets");
    assert_eq!(tickets, 0, "the ticket create rolled back with the update");
}

/// The `→ converted` transitions carry `not is_null(resolved_record_id)`, so a
/// generic update cannot mark a request converted without the record a real
/// conversion links in the same write.
#[tokio::test]
async fn a_generic_update_cannot_mark_a_work_request_converted_without_a_record() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let requester = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Bare Convert", "new", Some(requester)).await;
    let row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM service_work_request WHERE id = $1")
            .bind(work_request_id)
            .fetch_one(db)
            .await
            .expect("row_version");

    let result = attome_records::entity_crud::update_record_for(
        &state,
        &admin_ctx(actor),
        actor,
        "service_work_request",
        work_request_id,
        row_version,
        serde_json::json!({ "status": "converted" }),
    )
    .await;
    let Err(err) = result else {
        panic!("a bare status update to converted must be refused");
    };
    assert!(
        !matches!(err, AppError::NotFound | AppError::Internal(_)),
        "expected a guard refusal, got {err:?}"
    );
    let (status, _, _) = work_request_state(db, work_request_id).await;
    assert_eq!(status, "new", "the refused update wrote nothing");
}

#[tokio::test]
async fn converting_an_already_converted_work_request_is_a_conflict_not_a_second_ticket() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Already Done", "converted", None).await;

    let err = convert_work_request_to_ticket(&state, &admin_ctx(actor), work_request_id)
        .await
        .expect_err("converting an already-converted request must fail");
    assert!(
        matches!(err, AppError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    let ticket_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM service_ticket WHERE title = 'Already Done'",
    )
    .fetch_one(db)
    .await
    .expect("count tickets");
    assert_eq!(ticket_count, 0, "no ticket should have been created");
}

#[tokio::test]
async fn converting_a_nonexistent_work_request_is_not_found() {
    let state = skip_if_no_db!(test_state().await);
    let actor = insert_systemuser(&state.base.db).await;
    let err = convert_work_request_to_ticket(&state, &admin_ctx(actor), Uuid::now_v7())
        .await
        .expect_err("converting a nonexistent request must fail");
    assert!(matches!(err, AppError::NotFound), "got {err:?}");
}

/// The ticket's `requester_id` is required; the raw INSERT used to write a
/// NULL there. The engine refuses it, and nothing is half-written.
#[tokio::test]
async fn converting_a_request_without_a_requester_is_a_validation_error() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "No Requester", "new", None).await;

    let err = convert_work_request_to_ticket(&state, &admin_ctx(actor), work_request_id)
        .await
        .expect_err("a ticket without a requester must be refused");
    assert!(
        matches!(&err, AppError::Validation(m) if m.starts_with("requester_id")),
        "expected Validation, got {err:?}"
    );
    assert_eq!(work_request_state(db, work_request_id).await.0, "new");
}

/// Security negative path (M70 §5): without create on the destination the
/// conversion is 403, before anything is read or written.
#[tokio::test]
async fn converting_without_create_on_the_target_is_forbidden() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let user = insert_systemuser(db).await;
    let requester = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "No Create", "new", Some(requester)).await;

    let ctx = ctx_for(user, &["service_work_request.update"]);
    let err = convert_work_request_to_ticket(&state, &ctx, work_request_id)
        .await
        .expect_err("no service_ticket.create");
    assert!(matches!(err, AppError::Forbidden), "got {err:?}");

    let ctx = ctx_for(user, &["service_ticket.create"]);
    let err = convert_work_request_to_ticket(&state, &ctx, work_request_id)
        .await
        .expect_err("no service_work_request.update");
    assert!(matches!(err, AppError::Forbidden), "got {err:?}");
    assert_eq!(work_request_state(db, work_request_id).await.0, "new");
}

/// Both privileges but no record-level access to this work request (no role
/// scope, no share): the conversion answers 404, the record-access gate's
/// not-found convention, and writes nothing.
#[tokio::test]
async fn converting_a_work_request_the_caller_cannot_update_is_not_found() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let user = insert_systemuser(db).await;
    let requester = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Not Yours", "new", Some(requester)).await;

    let ctx = ctx_for(
        user,
        &["service_work_request.update", "service_ticket.create"],
    );
    let err = convert_work_request_to_ticket(&state, &ctx, work_request_id)
        .await
        .expect_err("no record-level access");
    assert!(matches!(err, AppError::NotFound), "got {err:?}");
    assert_eq!(work_request_state(db, work_request_id).await.0, "new");
}

#[tokio::test]
async fn converting_to_task_creates_a_leaf_work_item_under_the_given_project() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let organization_id = insert_organization(db).await;
    let project_id = insert_project(db, organization_id).await;
    let work_request_id = insert_work_request(db, "Convert Me To A Task", "new", None).await;

    let response =
        convert_work_request_to_task(&state, &admin_ctx(actor), work_request_id, project_id)
            .await
            .expect("convert_work_request_to_task");

    let (name, item_project_id, item_type, status): (String, Uuid, String, String) =
        sqlx::query_as(
            "SELECT name, project_id, item_type, status FROM project_work_item WHERE id = $1",
        )
        .bind(response.work_item_id)
        .fetch_one(db)
        .await
        .expect("read created work item");
    assert_eq!(name, "Convert Me To A Task");
    assert_eq!(item_project_id, project_id);
    assert_eq!(item_type, "task");
    assert_eq!(status, "not_started");

    let (status, resolved_entity_name, resolved_record_id) =
        work_request_state(db, work_request_id).await;
    assert_eq!(status, "converted");
    assert_eq!(resolved_entity_name.as_deref(), Some("project_work_item"));
    assert_eq!(
        resolved_record_id.as_deref(),
        Some(response.work_item_id.to_string().as_str())
    );

    assert_engine_evidence(
        db,
        "project_work_item",
        response.work_item_id,
        work_request_id,
    )
    .await;
}

#[tokio::test]
async fn converting_to_task_with_a_nonexistent_project_is_a_validation_error() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Convert Me Badly", "new", None).await;

    let err =
        convert_work_request_to_task(&state, &admin_ctx(actor), work_request_id, Uuid::now_v7())
            .await
            .expect_err("converting into a nonexistent project must fail");
    assert!(
        matches!(&err, AppError::Validation(m) if m == "project_id: lookup target does not exist or is deleted"),
        "expected Validation, got {err:?}"
    );
    assert_eq!(
        work_request_state(db, work_request_id).await.0,
        "new",
        "a failed conversion must not mark the work request converted"
    );
}

#[tokio::test]
async fn converting_to_project_creates_a_project_under_the_given_organization() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let organization_id = insert_organization(db).await;
    let work_request_id = insert_work_request(db, "Convert Me To A Project", "new", None).await;

    let response = convert_work_request_to_project(
        &state,
        &admin_ctx(actor),
        work_request_id,
        organization_id,
    )
    .await
    .expect("convert_work_request_to_project");

    let (name, project_organization_id, status, project_code): (String, Uuid, String, String) =
        sqlx::query_as(
            "SELECT name, organization_id, status, project_code FROM attome_project WHERE id = $1",
        )
        .bind(response.project_id)
        .fetch_one(db)
        .await
        .expect("read created project");
    assert_eq!(name, "Convert Me To A Project");
    assert_eq!(project_organization_id, organization_id);
    assert_eq!(status, "planning");
    assert!(response.project_code.starts_with("PRJ-"));
    assert_eq!(project_code, response.project_code);

    let (wr_status, resolved_entity_name, _) = work_request_state(db, work_request_id).await;
    assert_eq!(wr_status, "converted");
    assert_eq!(resolved_entity_name.as_deref(), Some("attome_project"));

    assert_engine_evidence(db, "attome_project", response.project_id, work_request_id).await;
}

#[tokio::test]
async fn converting_to_project_with_a_nonexistent_organization_is_a_validation_error() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let actor = insert_systemuser(db).await;
    let work_request_id = insert_work_request(db, "Convert Me Badly Too", "new", None).await;

    let err =
        convert_work_request_to_project(&state, &admin_ctx(actor), work_request_id, Uuid::now_v7())
            .await
            .expect_err("converting into a nonexistent organization must fail");
    assert!(
        matches!(&err, AppError::Validation(m) if m == "organization_id: lookup target does not exist or is deleted"),
        "expected Validation, got {err:?}"
    );
}
