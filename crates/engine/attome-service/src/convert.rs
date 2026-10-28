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

/// Convert a work request to a ticket
///
/// Creates a service ticket from the work request and marks the request converted, in one transaction.
/// Needs the right to create tickets and to update the request. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert-to-ticket",
    tag = "service",
    params(("id" = Uuid, Path, description = "The work request")),
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

/// Convert a work request to a task
///
/// Creates a task from the work request and marks the request converted, in one transaction. Needs the
/// right to create tasks and to update the request. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert-to-task",
    tag = "service",
    params(("id" = Uuid, Path, description = "The work request")),
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

/// Convert a work request to a project
///
/// Creates a project from the work request and marks the request converted, in one transaction. Needs
/// the right to create projects and to update the request. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert-to-project",
    tag = "service",
    params(("id" = Uuid, Path, description = "The work request")),
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

// ── G2-T3: conversion maps ──────────────────────────────────────────────────
//
// A `service_conversion_map` turns a work request into a record of any
// entity: `target_entity`, and `field_map`, the target's fields as JSON
// whose string values may name the request's fields as `{{field}}` (a value
// that is exactly one `{{field}}` copies it as it is; otherwise the names
// are filled in as text). A map tied to an offering with `direct_create`
// converts a request filed through that offering at once. Converting with
// several maps splits the request into several records, created together;
// the first is the request's `resolved_record_id`, and all of them are listed
// in `converted_records`.

/// The conversion map entity.
pub const MAP_ENTITY: &str = "service_conversion_map";
/// Most records one conversion splits a request into.
pub const MAX_SPLIT: usize = 10;

/// One conversion map.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConversionMap {
    pub id: Uuid,
    pub name: String,
    pub target_entity: String,
    pub field_map: Option<String>,
}

/// `POST /api/v1/work-request/{id}/convert`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConvertWithMapsRequest {
    /// The maps to convert with, in order; more than one splits the request.
    pub map_ids: Vec<Uuid>,
    /// Values for the target records that the request cannot supply (a
    /// required parent, say), applied over every map's result.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub values: Map<String, Value>,
}

/// A record a conversion created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ConvertedRecord {
    pub entity: String,
    pub id: Uuid,
}

/// What a conversion with maps created.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConvertWithMapsResponse {
    pub records: Vec<ConvertedRecord>,
}

/// A map's `field_map`: an object of target field to value. Pure.
pub fn parse_field_map(raw: Option<&str>) -> Result<Map<String, Value>, String> {
    let raw = raw.map(str::trim).filter(|r| !r.is_empty()).unwrap_or("{}");
    let map: Map<String, Value> =
        serde_json::from_str(raw).map_err(|e| format!("field_map is not a JSON object: {e}"))?;
    if let Some(bad) = map
        .keys()
        .find(|k| k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return Err(format!(
            "field_map names `{bad}`, which is not a field name"
        ));
    }
    Ok(map)
}

/// One map value with the request's fields filled in. Pure.
fn fill(spec: &str, source: &Map<String, Value>) -> Value {
    let trimmed = spec.trim();
    if let Some(name) = trimmed
        .strip_prefix("{{")
        .and_then(|r| r.strip_suffix("}}"))
        .map(str::trim)
        .filter(|n| !n.contains("{{") && !n.contains("}}"))
    {
        return source.get(name).cloned().unwrap_or(Value::Null);
    }
    let mut out = String::with_capacity(spec.len());
    let mut rest = spec;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return Value::String(out);
        };
        match source.get(after[..end].trim()) {
            Some(Value::String(s)) => out.push_str(s),
            Some(Value::Null) | None => {}
            Some(other) => out.push_str(&other.to_string()),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Value::String(out)
}

/// The target record's body: the map applied to the request, then the
/// caller's values over it. A field that comes out empty is left out, so the
/// engine's defaults and rules apply. Pure.
pub fn apply_map(
    field_map: &Map<String, Value>,
    source: &Map<String, Value>,
    overrides: &Map<String, Value>,
) -> Map<String, Value> {
    let mut body = Map::new();
    for (field, spec) in field_map {
        let value = match spec {
            Value::String(s) => fill(s, source),
            other => other.clone(),
        };
        let empty = value.is_null() || value.as_str().is_some_and(|s| s.trim().is_empty());
        if !empty {
            body.insert(field.clone(), value);
        }
    }
    for (field, value) in overrides {
        body.insert(field.clone(), value.clone());
    }
    body
}

/// The active maps `ids` name, in that order; 422 for one that is not.
pub async fn load_maps(
    db: &attome_db::DbPool,
    ids: &[Uuid],
) -> Result<Vec<ConversionMap>, AppError> {
    let rows: Vec<ConversionMap> = sqlx::query_as(
        "SELECT id, name, target_entity, field_map FROM service_conversion_map \
          WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)",
    )
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    ids.iter()
        .map(|id| {
            rows.iter().find(|m| m.id == *id).cloned().ok_or_else(|| {
                AppError::Validation(format!("{id} is not an active conversion map"))
            })
        })
        .collect()
}

/// The maps that convert a request filed through `offering_id` at once.
pub async fn maps_for_direct_creation(
    db: &attome_db::DbPool,
    offering_id: Uuid,
) -> Result<Vec<ConversionMap>, AppError> {
    sqlx::query_as(
        "SELECT id, name, target_entity, field_map FROM service_conversion_map \
          WHERE offering_ref = $1 AND direct_create = true \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY name, id LIMIT $2",
    )
    .bind(offering_id)
    .bind(i64::try_from(MAX_SPLIT).unwrap_or(10))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Converts a work request with `maps`, one record per map, in one
/// transaction, through the entity engine like the fixed conversions above:
/// the caller needs `{target}.create` for every map and update access to
/// the request. The request becomes `converted`.
pub async fn convert_with_maps(
    state: &EngineState,
    ctx: &SecurityContext,
    work_request_id: Uuid,
    maps: &[ConversionMap],
    overrides: &Map<String, Value>,
) -> Result<Vec<ConvertedRecord>, AppError> {
    if maps.is_empty() || maps.len() > MAX_SPLIT {
        return Err(AppError::Validation(format!(
            "a conversion uses 1 to {MAX_SPLIT} maps"
        )));
    }
    ctx.require_key("service_work_request.update")?;
    let mut targets = Vec::with_capacity(maps.len());
    for map in maps {
        ctx.require_key(&format!("{}.create", map.target_entity))?;
        let field_map = parse_field_map(map.field_map.as_deref())
            .map_err(|e| AppError::Validation(format!("conversion map {}: {e}", map.name)))?;
        targets.push((
            IntakeEntity::resolve(state, &map.target_entity).await?,
            field_map,
        ));
    }
    let request = IntakeEntity::resolve(state, WORK_REQUEST).await?;
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
    let loaded = lock_and_load_work_request(&mut tx, work_request_id).await?;
    let source: Map<String, Value> = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(w) - 'portal_secret_hash' - 'portal_public_id' \
           FROM service_work_request w WHERE w.id = $1",
    )
    .bind(work_request_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .as_object()
    .cloned()
    .unwrap_or_default();

    let mut records = Vec::with_capacity(targets.len());
    for (target, field_map) in &targets {
        let body = apply_map(field_map, &source, overrides);
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
        audit_entity_write(
            &mut tx,
            state,
            &actor,
            target,
            &created,
            AuditOperation::Create,
            &body,
            "work_request.convert",
        )
        .await?;
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
        records.push(ConvertedRecord {
            entity: target.name.clone(),
            id: created.record_id,
        });
    }

    let mut patch = Map::new();
    patch.insert("status".into(), Value::String("converted".into()));
    if let Some(first) = records.first() {
        patch.insert(
            "resolved_entity_name".into(),
            Value::String(first.entity.clone()),
        );
        patch.insert(
            "resolved_record_id".into(),
            Value::String(first.id.to_string()),
        );
    }
    patch.insert(
        "converted_records".into(),
        Value::String(serde_json::to_string(&records).map_err(AppError::internal)?),
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
        loaded.row_version,
        MutationMode::Strict,
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
    attome_db::tx::commit(tx).await?;
    attome_records::rw_pin::pin_write_with_current_lsn(state, ctx.user_id, "convert work request")
        .await;
    Ok(records)
}

#[utoipa::path(
    post,
    path = "/api/v1/work-request/{id}/convert",
    tag = "service",
    params(("id" = Uuid, Path, description = "The work request")),
    request_body = ConvertWithMapsRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
    responses(
        (status = 201, description = "The records the request became", body = ConvertWithMapsResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such work request", body = ErrorResponse),
        (status = 409, description = "Already converted or rejected", body = ErrorResponse),
        (status = 422, description = "A map is not active or not valid, or a target record failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Converts a work request with conversion maps (G2-T3).
///
/// Each map creates one record of its entity from the request's fields; more
/// than one map splits the request into several records, created together.
async fn convert_with_maps_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkRequestUpdate>>,
    Path(work_request_id): Path<Uuid>,
    Json(body): Json<ConvertWithMapsRequest>,
) -> Result<(StatusCode, Json<ConvertWithMapsResponse>), AppError> {
    let maps = load_maps(&state.base.db, &body.map_ids).await?;
    let records = convert_with_maps(&state, &ctx, work_request_id, &maps, &body.values).await?;
    Ok((
        StatusCode::CREATED,
        Json(ConvertWithMapsResponse { records }),
    ))
}

#[cfg(test)]
mod intake_convert {
    use super::*;
    use serde_json::json;

    fn source() -> Map<String, Value> {
        json!({
            "title": "New laptop",
            "description": "For the new hire",
            "requester_id": "01900000-0000-7000-8000-000000000001",
            "priority": "high",
            "reference": "REQ-2026-00042",
            "channel": null
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    #[test]
    fn intake_convert_copies_fields_and_fills_text() {
        let map = parse_field_map(Some(
            r#"{"name": "{{title}}", "owner_ref": "{{requester_id}}",
                "summary": "{{reference}}: {{title}} ({{channel}})", "kind": "asset_request",
                "quantity": 1, "via": "{{channel}}"}"#,
        ))
        .unwrap_or_default();
        let body = apply_map(&map, &source(), &Map::new());
        assert_eq!(body["name"], "New laptop");
        assert_eq!(body["owner_ref"], "01900000-0000-7000-8000-000000000001");
        assert_eq!(body["summary"], "REQ-2026-00042: New laptop ()");
        assert_eq!(body["kind"], "asset_request");
        assert_eq!(body["quantity"], 1);
        assert!(!body.contains_key("via"), "an empty value is left out");
    }

    #[test]
    fn intake_convert_lets_the_caller_supply_what_the_request_cannot() {
        let map = parse_field_map(Some(r#"{"name": "{{title}}"}"#)).unwrap_or_default();
        let mut overrides = Map::new();
        overrides.insert(
            "project_id".into(),
            json!("01900000-0000-7000-8000-000000000009"),
        );
        let body = apply_map(&map, &source(), &overrides);
        assert_eq!(body["project_id"], "01900000-0000-7000-8000-000000000009");
        assert_eq!(body["name"], "New laptop");
    }

    #[test]
    fn intake_convert_refuses_a_bad_map() {
        assert!(parse_field_map(Some("[1]")).is_err());
        assert!(parse_field_map(Some(r#"{"bad name": "x"}"#)).is_err());
        assert_eq!(parse_field_map(None).map(|m| m.len()), Ok(0));
        assert_eq!(MAX_SPLIT, 10);
    }
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
        .route(
            "/api/v1/work-request/{id}/convert",
            post(convert_with_maps_route),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own model.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    convert_to_ticket,
    convert_to_task,
    convert_to_project,
    convert_with_maps_route
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
