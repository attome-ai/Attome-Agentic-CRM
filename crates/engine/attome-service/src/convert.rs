//! `POST /api/v1/work-request/{id}/convert-to-{ticket,task,project}` — the
//! real piece of 🏰 Unified Work Inbox behavior this crate has: turning an
//! intake item into whichever record it becomes. Everything else on
//! `service_work_request`/`service_ticket` is generic entity CRUD (D-398).
//!
//! All three share one shape, [`convert`]: check the caller may create the
//! destination and update this particular work request, then in ONE
//! transaction lock the work request, status-check it, create the destination
//! through the entity engine (`entity_mutation::create_one_as`), and move the
//! work request to `converted` through the engine too (`update_one_as`), with
//! every audit event written in that same transaction.
//!
//! M70 Phase 1 (`document/xrm/module/M70-work-intake/master-plan.md` §4
//! item 1): until then both writes were raw `INSERT`/`UPDATE` statements, so
//! a conversion emitted no change-feed row, ran no field validation,
//! calculation/formula rule (D-604) or autovalue, granted no creator share,
//! and re-implemented lookup checks by hand. The engine now does all of that,
//! including the state-model check on `status` — which is why the
//! `service_work_request` lifecycle in `platform-bundles/attome-service.json`
//! carries `new → converted` and `triaged → converted`.
//!
//! →Task and →Project both take their destination's required parent lookup
//! (`project_id`, `organization_id`) as a request-body field, since
//! `service_work_request` has no way to derive either — deciding which
//! project or organization an intake item lands in is the caller's call, not
//! something to infer.
use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_records::entity_mutation::{
    CreateStamp, MutationMode, MutationResult, Principal, create_one_as, update_one_as,
};
use attome_records::mutation_ring::MutationActor;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::WorkRequestUpdate;
use crate::intake::{IntakeEntity, audit_entity_write, placeholder_number, put_opt, row_str};

const WORK_REQUEST: &str = "service_work_request";

#[derive(Debug, Serialize, ToSchema)]
pub struct ConvertToTicketResponse {
    pub ticket_id: Uuid,
    pub ticket_number: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConvertToTaskRequest {
    /// The project the new task (`project_work_item`) is created under —
    /// required because `project_id` is a required lookup on that entity and
    /// nothing on `service_work_request` names one.
    pub project_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConvertToTaskResponse {
    pub work_item_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConvertToProjectRequest {
    /// The organization the new project is created under — required because
    /// `organization_id` is a required lookup on `attome_project` and nothing on
    /// `service_work_request` names one.
    pub organization_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConvertToProjectResponse {
    pub project_id: Uuid,
    pub project_code: String,
}

/// The work request fields a conversion copies onto its destination, read
/// under the conversion's advisory lock.
struct WorkRequestSource {
    pub title: String,
    pub description: Option<String>,
    pub requester_id: Option<Uuid>,
    pub channel: Option<String>,
    row_version: i64,
}

/// `(title, description, requester_id, status, channel, row_version)` — named
/// so clippy's `type_complexity` lint doesn't flag the inline tuple.
type WorkRequestRawRow = (
    String,
    Option<String>,
    Option<Uuid>,
    String,
    Option<String>,
    i64,
);

/// Advisory-locks and loads the work request being converted, regardless of
/// destination — the lock key is keyed on the work request alone, so a
/// →Ticket and a →Task attempt racing on the same request still serialize
/// against each other rather than both passing the status check below. The
/// returned `row_version` is what the engine's optimistic-concurrency check
/// on the status update compares against.
async fn lock_and_load_work_request(
    tx: &mut Transaction<'_, Postgres>,
    work_request_id: Uuid,
) -> Result<WorkRequestSource, AppError> {
    // Advisory lock BEFORE reading — the same "lock, then act" order
    // attome-s2s::admin::create_client uses — so two concurrent conversions of
    // the same work request can't both pass the status check below.
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!(
                "attome-service/convert-work-request:{work_request_id}"
            ))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another request is already converting this work request",
        ));
    }

    let row: Option<WorkRequestRawRow> = sqlx::query_as(
        "SELECT title, description, requester_id, status, channel, row_version \
         FROM service_work_request \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(work_request_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (title, description, requester_id, status, channel, row_version) =
        row.ok_or(AppError::NotFound)?;

    if status == "converted" || status == "rejected" {
        return Err(AppError::Conflict(
            "this work request has already been converted or rejected",
        ));
    }

    Ok(WorkRequestSource {
        title,
        description,
        requester_id,
        channel,
        row_version,
    })
}

/// The one conversion pipeline every direction shares. `build_body` turns
/// the locked work request into the destination's create body; everything
/// else — authorization, the transaction, both engine writes, the creator
/// share, the audit events, the commit — is identical per direction.
///
/// # Authorization
///
/// The caller needs `{target}.create` (checked here, so a non-HTTP caller
/// cannot skip it) and update access to *this* work request: the
/// `service_work_request.update` privilege (the HTTP route's extractor)
/// plus record-level access (`require_record_access`, checked here) — a user
/// scoped to their own requests cannot convert somebody else's. Field-write
/// grants and state-model transition privileges are the engine's own checks.
async fn convert(
    state: &EngineState,
    ctx: &SecurityContext,
    work_request_id: Uuid,
    target_entity: &str,
    build_body: impl FnOnce(&WorkRequestSource) -> Map<String, Value>,
) -> Result<MutationResult, AppError> {
    ctx.require_key(&format!("{target_entity}.create"))?;
    ctx.require_key("service_work_request.update")?;

    let request = IntakeEntity::resolve(state, WORK_REQUEST).await?;
    let target = IntakeEntity::resolve(state, target_entity).await?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        request.id,
        &request.name,
        work_request_id,
        RecordAction::Update,
    )
    .await?;
    let actor = MutationActor::fetch(state, ctx.user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let source = lock_and_load_work_request(&mut tx, work_request_id).await?;
    let body = build_body(&source);

    let created = create_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        &target.name,
        &target.attrs,
        &body,
        CreateStamp::staff(ctx.user_id, actor.org_ref),
        MutationMode::Strict,
    )
    .await?;
    attome_records::entity_crud::grant_creator_share(
        &mut tx,
        target.id,
        created.record_id,
        ctx.user_id,
    )
    .await?;

    let mut patch = Map::new();
    patch.insert("status".into(), Value::String("converted".into()));
    patch.insert(
        "resolved_entity_name".into(),
        Value::String(target.name.clone()),
    );
    patch.insert(
        "resolved_record_id".into(),
        Value::String(created.record_id.to_string()),
    );
    let updated = update_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        &request.name,
        request.id,
        work_request_id,
        &request.attrs,
        &patch,
        Some(ctx.user_id),
        source.row_version,
        MutationMode::Strict,
    )
    .await?;

    audit_entity_write(
        &mut tx,
        state,
        &actor,
        &target,
        &created,
        AuditOperation::Create,
        &body,
        "work_request.convert",
    )
    .await?;
    audit_entity_write(
        &mut tx,
        state,
        &actor,
        &request,
        &updated,
        AuditOperation::Update,
        &patch,
        "work_request.convert",
    )
    .await?;
    // The route's declared mandatory event (D-542), now atomic with the
    // conversion itself rather than written after it committed.
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            &target.name,
            Some(created.record_id),
        )
        .organization(actor.org_ref)
        .named("work_request.convert"),
    )
    .await?;

    attome_db::tx::commit(tx).await?;
    attome_records::rw_pin::pin_write_with_current_lsn(state, ctx.user_id, "convert work request")
        .await;
    Ok(created)
}

/// Work Request → Ticket. Carries the request's `channel` (M53 Phase 1,
/// D-474 — `omnichannel_metrics.rs`'s CSAT-by-channel query needs it) and its
/// requester; a request with no requester fails the ticket's required
/// `requester_id` check with a 422 rather than creating an orphaned ticket.
///
/// `pub` so this crate's integration tests exercise the real transaction,
/// lock, status and authorization logic without an HTTP request; the thin
/// handler below owns only the route's compile-time privilege extractor and
/// the response shaping.
pub async fn convert_work_request_to_ticket(
    state: &EngineState,
    ctx: &SecurityContext,
    work_request_id: Uuid,
) -> Result<ConvertToTicketResponse, AppError> {
    let created = convert(state, ctx, work_request_id, "service_ticket", |source| {
        let mut body = Map::new();
        body.insert(
            "ticket_number".into(),
            Value::String(placeholder_number("TKT")),
        );
        body.insert("title".into(), Value::String(source.title.clone()));
        put_opt(&mut body, "description", source.description.clone());
        put_opt(
            &mut body,
            "requester_id",
            source.requester_id.map(|id| id.to_string()),
        );
        body.insert("priority".into(), Value::String("medium".into()));
        body.insert("status".into(), Value::String("new".into()));
        put_opt(&mut body, "channel", source.channel.clone());
        body
    })
    .await?;
    Ok(ConvertToTicketResponse {
        ticket_id: created.record_id,
        ticket_number: row_str(&created, "ticket_number").unwrap_or_default(),
    })
}

/// Work Request → Task: creates a leaf `project_work_item` under the
/// caller-supplied project. The engine's lookup-liveness check refuses a
/// missing or deleted project with a 422.
pub async fn convert_work_request_to_task(
    state: &EngineState,
    ctx: &SecurityContext,
    work_request_id: Uuid,
    project_id: Uuid,
) -> Result<ConvertToTaskResponse, AppError> {
    let created = convert(state, ctx, work_request_id, "project_work_item", |source| {
        let mut body = Map::new();
        body.insert("name".into(), Value::String(source.title.clone()));
        body.insert("project_id".into(), Value::String(project_id.to_string()));
        body.insert("item_type".into(), Value::String("task".into()));
        body.insert("status".into(), Value::String("not_started".into()));
        put_opt(&mut body, "description", source.description.clone());
        body
    })
    .await?;
    Ok(ConvertToTaskResponse {
        work_item_id: created.record_id,
    })
}

/// Work Request → Project: creates a new `attome_project` under the
/// caller-supplied organization.
pub async fn convert_work_request_to_project(
    state: &EngineState,
    ctx: &SecurityContext,
    work_request_id: Uuid,
    organization_id: Uuid,
) -> Result<ConvertToProjectResponse, AppError> {
    let created = convert(state, ctx, work_request_id, "attome_project", |source| {
        let mut body = Map::new();
        body.insert("name".into(), Value::String(source.title.clone()));
        body.insert(
            "project_code".into(),
            Value::String(placeholder_number("PRJ")),
        );
        body.insert(
            "organization_id".into(),
            Value::String(organization_id.to_string()),
        );
        body.insert("status".into(), Value::String("planning".into()));
        put_opt(&mut body, "description", source.description.clone());
        body
    })
    .await?;
    Ok(ConvertToProjectResponse {
        project_id: created.record_id,
        project_code: row_str(&created, "project_code").unwrap_or_default(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert-to-ticket",
    tag = "service",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
    responses(
        (status = 201, description = "Success", body = ConvertToTicketResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such work request", body = ErrorResponse),
        (status = 409, description = "Already converted or rejected", body = ErrorResponse),
        (status = 422, description = "The ticket failed validation (e.g. the request has no requester)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn convert_to_ticket(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkRequestUpdate>>,
    Path(work_request_id): Path<Uuid>,
) -> Result<(StatusCode, Json<ConvertToTicketResponse>), AppError> {
    // The extractor confirmed service_work_request.update; the target's
    // create privilege and record-level access are checked inside.
    let response = convert_work_request_to_ticket(&state, &ctx, work_request_id).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert-to-task",
    tag = "service",
    params(("id" = Uuid, Path)),
    request_body = ConvertToTaskRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
    responses(
        (status = 201, description = "Success", body = ConvertToTaskResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such work request", body = ErrorResponse),
        (status = 409, description = "Already converted or rejected", body = ErrorResponse),
        (status = 422, description = "project_id does not name a live project", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn convert_to_task(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkRequestUpdate>>,
    Path(work_request_id): Path<Uuid>,
    Json(body): Json<ConvertToTaskRequest>,
) -> Result<(StatusCode, Json<ConvertToTaskResponse>), AppError> {
    let response =
        convert_work_request_to_task(&state, &ctx, work_request_id, body.project_id).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert-to-project",
    tag = "service",
    params(("id" = Uuid, Path)),
    request_body = ConvertToProjectRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
    responses(
        (status = 201, description = "Success", body = ConvertToProjectResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such work request", body = ErrorResponse),
        (status = 409, description = "Already converted or rejected", body = ErrorResponse),
        (status = 422, description = "organization_id does not name a live organization", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn convert_to_project(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkRequestUpdate>>,
    Path(work_request_id): Path<Uuid>,
    Json(body): Json<ConvertToProjectRequest>,
) -> Result<(StatusCode, Json<ConvertToProjectResponse>), AppError> {
    let response =
        convert_work_request_to_project(&state, &ctx, work_request_id, body.organization_id)
            .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/work-request/{id}/convert-to-ticket",
            post(convert_to_ticket),
        )
        .route(
            "/api/v1/work-request/{id}/convert-to-task",
            post(convert_to_task),
        )
        .route(
            "/api/v1/work-request/{id}/convert-to-project",
            post(convert_to_project),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own model.
#[derive(utoipa::OpenApi)]
#[openapi(paths(convert_to_ticket, convert_to_task, convert_to_project))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
