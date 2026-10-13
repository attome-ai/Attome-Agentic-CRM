//! Per-record state routes — `/api/v1/{entity}/{id}/transitions` (available
//! transitions for this record and this caller) and
//! `/api/v1/{entity}/{id}/transition` (a state change by name of the target
//! state).
//!
//! **One write path (M07 Phase A, §4.1).** `/transition` performs no write of
//! its own: `apply_transition_at` builds `{state_field: to_state}` and calls
//! `attome_records::entity_crud::update_record_for_with_comment`, the
//! same function the generic `PATCH /{entity}/{id}` handler calls, which runs
//! `entity_mutation::update_one`. So `check_transition`, `required_privilege`,
//! `guard_expression` (including `current_user`, P0 0.7), validation and
//! calculation rules, model record validators, the change feed, the audit
//! event and the rw-pin are identical on both routes, and a guarded
//! transition works here exactly when it works through PATCH (the old
//! "guarded transitions need PATCH" refusal is gone). `If-Match` is optional
//! (absent = the record's current version). The source-scan test
//! `tests/single_write_path.rs` fails on an `UPDATE` in this crate's record
//! routes.
//!
//! **Approval on a transition (M07 Phase F, D-770).** When the requested
//! transition carries an `approval_plan`, the same update path parks the
//! record in the transition's `pending_state` and opens a `attome-approval`
//! request in the same transaction; the response is still `200`, with
//! `to_state` = the pending state plus `approval_request_id` and
//! `requested_state` (additive fields, omitted otherwise — D-438).
//! `POST /{entity}/{id}/transition/cancel` withdraws or releases it (see
//! `crate::approval`).
//!
//! **C-01 — record-level gate.** `RecordScoped<A>` (see its own doc comment
//! in `attome_server::authz`) authorizes only the entity-level privilege
//! (`"{entity}.{action}"`); it deliberately does not and cannot check
//! whether `ctx` may see or act on THIS record — that needs the database.
//! Before either handler reads the record, it calls
//! `attome_records::entity_crud::require_record_access` — the exact same
//! record-level predicate `get_record`/`update_record` apply on the generic
//! `/{entity}/{id}` routes — so a Team/BusinessUnit-scoped caller who holds
//! the table-level privilege but has no team/share/ownership reach into this
//! particular record gets the identical `404 NotFound` the generic routes
//! would give them, not a 200 that leaks another team's record state.

use attome_core::{EngineState, quote_ident};
use attome_records::entity_crud::{
    optional_expected_row_version, require_record_access, update_record_for_outcome,
};
use attome_records::entity_mutation::MutationMode;
use attome_security::RecordAction;
use attome_security::record_action::{Read, Update};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};
use uuid::Uuid;

use crate::model::{
    AvailableTransition, CancelTransitionBody, TransitionRequestBody, TransitionResult,
};

/// `entity`'s own `entity_info.id`, or `None` when `entity` does not
/// name a live registered entity. Queries `entity_info` directly
/// rather than `state.entities` (`EntityMetaRegistry`) -- that snapshot is a
/// cache (`cache.metadata_registry_enabled = false` disables it outright,
/// the same config every DB-backed test in this workspace runs with,
/// matching `entity_crud::resolve::resolve_entity`'s own fallback for that
/// case) and even when enabled is refreshed asynchronously, so an entity
/// created immediately before this call is not guaranteed to be visible in
/// it yet.
///
/// Also the `entity_id` `require_record_access` needs (C-01) -- this query
/// already selected it, so both handlers get it for the price of the
/// existence check they already made, rather than a second round trip
/// through the heavier `entity_crud::resolve_entity` (which additionally
/// re-validates the entity's own module license -- correct for a generic
/// CRUD route, but a scope this record-level-access fix does not need to
/// take on).
async fn resolve_entity_id(state: &EngineState, entity: &str) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The record's live `state_field` value and `row_version`, or `None` when
/// the record does not exist (soft-deleted counts as not existing, same
/// predicate every other read in this codebase uses). A read only — every
/// write goes through the generic update path (M07 §4.1).
async fn fetch_current_state(
    state: &EngineState,
    entity: &str,
    state_field: &str,
    record_id: Uuid,
) -> Result<Option<(Option<String>, i64)>, AppError> {
    let table = quote_ident(entity);
    let field_ident = quote_ident(state_field);
    sqlx::query_as::<_, (Option<String>, i64)>(&format!(
        "SELECT {field_ident}, row_version FROM {table} WHERE id = $1 AND is_active = true"
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/transitions",
    tag = "state",
    params(
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AvailableTransition>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Record not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_available_transitions(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id)): Path<(String, Uuid)>,
) -> Result<Json<PaginatedResponse<AvailableTransition>>, AppError> {
    let entity_id = resolve_entity_id(&state, &entity)
        .await?
        .ok_or(AppError::NotFound)?;
    // C-01: `RecordScoped<Read>` above only proved `ctx` holds
    // `{entity}.read` table-wide -- it says nothing about THIS record. Same
    // gate, same action, same `NotFound`-on-miss convention as
    // `entity_crud::get_record` applies to the generic `GET /{entity}/{id}`.
    require_record_access(&state, &ctx, entity_id, &entity, id, RecordAction::Read).await?;
    let registry = state.state_models.load();
    let Some(entry) = registry.get(&entity) else {
        // No configured lifecycle for this entity -- nothing to list, not an
        // error (an ungoverned entity legitimately has zero transitions).
        return Ok(Json(PaginatedResponse::new(Vec::new(), 0, 1, 1)));
    };
    let Some(model) = &entry.model else {
        return Ok(Json(PaginatedResponse::new(Vec::new(), 0, 1, 1)));
    };
    let (current, _) = fetch_current_state(&state, &entity, &model.state_field, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let items: Vec<AvailableTransition> =
        attome_core::available_transitions(entry, &ctx, current.as_deref())
            .into_iter()
            .map(|t| AvailableTransition {
                to_state: t.to_state.clone(),
                name: t.name.clone(),
                display_order: t.display_order,
            })
            .collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// The reusable core behind `POST /api/v1/{entity}/{id}/transition`, for a
/// caller that already holds a `SecurityContext`.
///
/// M07 Phase A (§4.1): a thin caller of the generic update path
/// (`entity_crud::update_record_for_with_comment` ->
/// `entity_mutation::update_one`), writing `{state_field: to_state}`. So the
/// transition check, `required_privilege`, `guard_expression` (with
/// `current_user`), validation/calculation rules, model record validators,
/// the change-feed row, the audit event (with the `state_transition` marker
/// and `comment`), cache invalidation and the rw-pin are exactly what a
/// generic `PATCH` of the same field gets. There is no other write here.
///
/// `expected_row_version` is the caller's `If-Match`; `None` means the
/// record's current version, read here — a concurrent write between that
/// read and the update is then a `409 version_conflict`, never a silent
/// overwrite. A supplied version that is not the current one is a `409`
/// before anything is written.
///
/// Takes a bare `&SecurityContext` — the caller is responsible for the
/// entity-level `{entity}.update` check first (`transition_record` uses
/// `Authorized<RecordScoped<Update>>`). The record-level check
/// (`require_record_access`) runs here and again inside the update path —
/// C-01's rule that entity-level and record-level authorization are two
/// separate checks.
pub async fn apply_transition(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    to_state: &str,
    comment: Option<String>,
) -> Result<TransitionResult, AppError> {
    apply_transition_at(state, ctx, entity, id, to_state, comment, None).await
}

/// [`apply_transition`] with the caller's optional `If-Match`.
pub async fn apply_transition_at(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    to_state: &str,
    comment: Option<String>,
    expected_row_version: Option<i64>,
) -> Result<TransitionResult, AppError> {
    let to_state = to_state.trim();
    if to_state.is_empty() {
        return Err(AppError::Validation("to_state is required".into()));
    }
    let entity_id = resolve_entity_id(state, entity)
        .await?
        .ok_or(AppError::NotFound)?;
    // C-01: the caller's own entity-level check only proved `ctx` holds
    // `{entity}.update` table-wide -- it says nothing about THIS record, and
    // the current-version read below must not answer for a record the caller
    // cannot reach.
    require_record_access(state, ctx, entity_id, entity, id, RecordAction::Update).await?;

    // `/transition` exists to move a governed state field; on an entity with
    // no model it is a 422, not an ungoverned field write.
    let state_field = {
        let registry = state.state_models.load();
        registry
            .get(entity)
            .and_then(|entry| entry.model.as_ref())
            .map(|model| model.state_field.clone())
            .ok_or_else(|| {
                AppError::Validation(format!("{entity} has no configured state model"))
            })?
    };

    let (from_state, current_version) = fetch_current_state(state, entity, &state_field, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let expected = match expected_row_version {
        Some(v) if v != current_version => return Err(AppError::VersionConflict),
        Some(v) => v,
        None => current_version,
    };

    let mut body = serde_json::Map::new();
    body.insert(
        state_field.clone(),
        serde_json::Value::String(to_state.to_owned()),
    );
    let outcome = update_record_for_outcome(
        state,
        ctx,
        ctx.user_id,
        entity,
        id,
        expected,
        serde_json::Value::Object(body),
        comment,
        MutationMode::Strict,
    )
    .await?;
    let response = outcome.response;

    Ok(TransitionResult {
        record_id: id,
        from_state,
        to_state: response
            .data()
            .get(&state_field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or(to_state)
            .to_owned(),
        row_version: response.row_version(),
        // M07 Phase F: a plan-bearing transition parked the record in its
        // pending state (`to_state` above) and opened this request.
        approval_request_id: outcome.approval.as_ref().map(|a| a.request_id),
        requested_state: outcome.approval.map(|a| a.requested),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/transition",
    tag = "state",
    params(
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("If-Match" = Option<String>, Header, description = "Optional expected row_version; absent means the record's current version"),
    ),
    request_body = TransitionRequestBody,
    responses(
        (status = 200, description = "Success. For a transition that requires approval (M07 Phase F), the record is parked in the transition's pending state (`to_state`) and `approval_request_id`/`requested_state` are present", body = TransitionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or the transition's own required_privilege", body = ErrorResponse),
        (status = 404, description = "Record not found", body = ErrorResponse),
        (status = 409, description = "The record changed concurrently, or If-Match is not its current row_version", body = ErrorResponse),
        (status = 422, description = "No transition is configured for this state change, its guard condition refused it, or a rule rejected the write", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
async fn transition_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<TransitionRequestBody>,
) -> Result<Json<TransitionResult>, AppError> {
    let expected = optional_expected_row_version(&headers)?;
    let result = apply_transition_at(
        &state,
        &ctx,
        &entity,
        id,
        &body.to_state,
        body.comment,
        expected,
    )
    .await?;
    Ok(Json(result))
}

/// M07 Phase F (D-770) — withdraws the record's open transition approval and
/// returns the record to the state it came from. Only the request's own
/// requester may cancel an open request (`403` otherwise); when the request
/// already closed without executing (rejected, expired, invalidated) but the
/// record is still parked, the requester or an administrator may release it
/// here (a rejection goes to its `on_reject_state`, the rest to the origin).
/// See `crate::approval`.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/transition/cancel",
    tag = "state",
    params(
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
    ),
    request_body = CancelTransitionBody,
    responses(
        (status = 200, description = "The approval is cancelled (or was already closed) and the record has left its pending state", body = TransitionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks {entity}.update, or is not the requester (an administrator may only release an already-closed approval)", body = ErrorResponse),
        (status = 404, description = "Record not found", body = ErrorResponse),
        (status = 409, description = "The record is not waiting on an approval, or its approval was granted and is being carried out", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Cancelled),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn cancel_transition_approval(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity, id)): Path<(String, Uuid)>,
    Json(body): Json<CancelTransitionBody>,
) -> Result<Json<TransitionResult>, AppError> {
    let result =
        crate::approval::cancel_or_release(&state, &ctx, &entity, id, body.comment).await?;
    Ok(Json(result))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/{entity}/{id}/transitions",
            get(list_available_transitions),
        )
        .route(
            "/api/v1/{entity}/{id}/transition",
            axum::routing::post(transition_record),
        )
        .route(
            "/api/v1/{entity}/{id}/transition/cancel",
            axum::routing::post(cancel_transition_approval),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_available_transitions,
    transition_record,
    cancel_transition_approval
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
