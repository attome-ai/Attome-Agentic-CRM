//! M12 (data management) — `POST /api/v1/{entity}/bulk-transform`: an
//! in-place bulk field transform.
//!
//! The mapping model's `fields[].transform` column is a free-text M45
//! (attome-rules) expression, but M45 does not exist in this worktree
//! (D-408). This surface is deliberately narrower: a **fixed set** of
//! built-in operations (`trim` | `upper` | `lower` | `set_to_value`)
//! applied to exactly one field, over a caller-supplied, bounded set of
//! record ids. Arbitrary expression evaluation is explicit future work once
//! attome-rules lands, not silently approximated here.
//!
//! Every actual mutation goes through `entity_mutation::update_one` — the
//! same primitive interactive `PATCH`, `bulk::apply_one`, and staged import
//! all share — so field-write-security, hierarchy-cycle protection, row
//! versioning, and audit are byte-identical to an ordinary update
//! (guidelines §9: reuse established mutation primitives). This module only
//! adds the item ledger (crash/redelivery-safe, mirrors
//! `automation_bulk_operation_item`'s D-099 row-claiming discipline) and the
//! dry-run/approval-gating shell around it.
//!
//! `POST .../bulk-transform/dry-run` reports how many of the given record
//! ids are actually live and updatable under the caller's current row
//! security — the required "count first" step before the caller submits
//! the real run. `POST .../bulk-transform` itself gates through the same
//! D-195 four-eyes mechanism every other high-risk action in this codebase
//! uses ([`ACTION_DATA_BULK_TRANSFORM`], config opt-in via
//! `approval.required_actions`) once the candidate count crosses
//! [`APPROVAL_THRESHOLD_ROWS`].

use attome_audit::{
    Attribution, AuditCategory, AuditEvent, AuditOperation, AuditOutcome, AuditRequestContext,
    AuditService, AuditSource, write_bulk_accepted, write_bulk_completed_once,
};
use attome_auth::SessionClaims;
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_security::record_action::Update;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::capability::{Available, BatchJobs};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use utoipa::ToSchema;
use uuid::Uuid;

use attome_records::entity_crud;
use attome_records::entity_mutation::{self, MutationMode, sql_cast};

/// D-195 four-eyes gate — see this file's module doc. Registered in
/// `approval_admin::KNOWN_ACTION_TYPES`/`execute_approved`.
pub const ACTION_DATA_BULK_TRANSFORM: &str = "data.bulk_transform";

/// A run over more than this many candidate records requires the D-195
/// gate (when `data.bulk_transform` is in `approval.required_actions` —
/// opt-in like every other wired action, D-195). No measured
/// production-shaped cost exists for this operation yet (coding-guidelines
/// §14); chosen to match `bulk::MAX_BULK_RECORDS`'s own documented
/// provisional-until-measured posture.
pub const APPROVAL_THRESHOLD_ROWS: usize = 500;

/// Hard cap on one request's candidate set, independent of the approval
/// threshold above (a request can be gated *and* still bounded).
const MAX_TRANSFORM_RECORDS: usize = 5000;

const BUILTIN_TRANSFORMS: &[&str] = &["trim", "upper", "lower", "set_to_value"];

fn valid_transform(t: &str) -> bool {
    BUILTIN_TRANSFORMS.contains(&t)
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
struct BulkTransformRequestBody {
    field: String,
    /// `"trim"`, `"upper"`, `"lower"`, or `"set_to_value"`.
    transform: String,
    /// Required (and only meaningful) for `"set_to_value"`.
    #[serde(default)]
    value: Option<String>,
    record_ids: Vec<Uuid>,
}

fn validate_body_shape(
    attrs: &[AttrInfo],
    body: &BulkTransformRequestBody,
) -> Result<(), AppError> {
    if !valid_transform(&body.transform) {
        return Err(AppError::Validation(format!(
            "transform must be one of: {}",
            BUILTIN_TRANSFORMS.join(", ")
        )));
    }
    if body.transform == "set_to_value" && body.value.is_none() {
        return Err(AppError::Validation(
            "value is required when transform is set_to_value".into(),
        ));
    }
    let attr = attrs
        .iter()
        .find(|a| a.logicalname == body.field)
        .ok_or_else(|| AppError::Validation(format!("unknown field: {}", body.field)))?;
    // Deliberately narrow (see module doc): every built-in transform here
    // operates on a plain text value. `sql_cast` returning "" is this
    // crate's existing signal for "no special cast" (`entity_mutation.rs`),
    // which — excluding the multi-valued choice/file branches it also
    // covers — is exactly the plain-text case.
    if !sql_cast(attr).is_empty() {
        return Err(AppError::Validation(format!(
            "field {} is not a plain text field; bulk-transform's built-in operations only \
             support text fields",
            body.field
        )));
    }
    if body.record_ids.is_empty() {
        return Err(AppError::Validation("record_ids must not be empty".into()));
    }
    if body.record_ids.len() > MAX_TRANSFORM_RECORDS {
        return Err(AppError::Validation(format!(
            "at most {MAX_TRANSFORM_RECORDS} record_ids per request, got {}",
            body.record_ids.len()
        )));
    }
    Ok(())
}

/// Counts how many of `record_ids` are currently live and updatable under
/// `ctx`'s row security — shared by the dry-run endpoint and the real
/// enqueue path's own defense-in-depth check.
async fn count_updatable(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_ids: &[Uuid],
) -> Result<i64, AppError> {
    let table = quote_ident(entity_name);
    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity_name,
        RecordAction::Update,
    )
    .await?;
    let mut conds = vec![
        "t.id = ANY($1)".to_string(),
        "t.is_active = true".to_string(),
    ];
    let mut params: Vec<String> = Vec::new();
    if let Some(pred) = attome_security::rls_predicate(
        ctx,
        entity_id,
        "t",
        access_level,
        RecordAction::Update.share_capability(),
        2,
    ) {
        conds.push(pred.sql.trim_start_matches("AND ").to_owned());
        params.extend(pred.binds.to_text_params());
    }
    let sql = format!(
        "SELECT COUNT(*) FROM {table} t WHERE {}",
        conds.join(" AND ")
    );
    let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(record_ids);
    for p in &params {
        q = q.bind(p.clone());
    }
    q.fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

#[derive(Serialize, ToSchema)]
struct DryRunResponse {
    matching_count: i64,
    requested_count: i64,
    will_require_approval: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/bulk-transform/dry-run",
    tag = "entity",
    params(("entity" = String, Path)),
    request_body = BulkTransformRequestBody,
    responses(
        (status = 200, description = "Success", body = DryRunResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "counts matching records only, writes nothing")))),
)]
async fn dry_run(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path(entity_input): Path<String>,
    Json(body): Json<BulkTransformRequestBody>,
) -> Result<Json<DryRunResponse>, AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        entity_crud::resolve_entity(&state, &entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    validate_body_shape(&attrs, &body)?;
    let matching_count =
        count_updatable(&state, &ctx, entity_id, &entity_name, &body.record_ids).await?;
    Ok(Json(DryRunResponse {
        matching_count,
        requested_count: body.record_ids.len() as i64,
        will_require_approval: body.record_ids.len() > APPROVAL_THRESHOLD_ROWS,
    }))
}

#[derive(Serialize, ToSchema)]
pub(crate) struct BulkTransformEnqueueResponse {
    id: Uuid,
    status: String,
    total: i32,
}

#[derive(Serialize, ToSchema)]
struct BulkTransformApprovalPending {
    approval_pending: bool,
    approval_request_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/bulk-transform",
    tag = "entity",
    params(("entity" = String, Path)),
    request_body = BulkTransformRequestBody,
    responses(
        (status = 202, description = "Success", body = BulkTransformEnqueueResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("apply_transform_one"), "each transformed record writes its own Entity/Update event when the job runs")))),
)]
async fn enqueue_bulk_transform(
    State(state): State<EngineState>,
    _ctx: Authorized<RecordScoped<Update>>,
    _jobs: Available<BatchJobs>,
    Extension(claims): Extension<SessionClaims>,
    Path(entity_input): Path<String>,
    Json(body): Json<BulkTransformRequestBody>,
) -> Result<Response, AppError> {
    let (_entity_id, entity_name, attrs, is_append_only) =
        entity_crud::resolve_entity(&state, &entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    validate_body_shape(&attrs, &body)?;

    if body.record_ids.len() > APPROVAL_THRESHOLD_ROWS
        && let Some(request) = attome_audit::approval::gate(
            &state,
            ACTION_DATA_BULK_TRANSFORM,
            json!({
                "entity": entity_name,
                "field": body.field,
                "transform": body.transform,
                "value": body.value,
                "record_ids": body.record_ids,
                "user_id": claims.sub,
            }),
            claims.sub,
        )
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(BulkTransformApprovalPending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let response = do_bulk_transform(
        &state,
        &entity_name,
        &body.field,
        &body.transform,
        body.value.as_deref(),
        &body.record_ids,
        claims.sub,
    )
    .await?;
    Ok((StatusCode::ACCEPTED, Json(response)).into_response())
}

/// The real mutation-enqueue, factored out so the direct (ungated) path
/// above and `approval_admin::execute_approved`'s
/// `ACTION_DATA_BULK_TRANSFORM` arm call the exact same code — one
/// execution path per action, same convention `dsr_admin::do_fulfill_erasure`
/// established. Takes only what it actually writes to the ledger row — the
/// entity's id/attrs aren't needed until the worker's own per-item pass
/// (`apply_transform_one`), so they're deliberately not threaded through
/// here (also keeps this under clippy's `too_many_arguments` limit).
pub(crate) async fn do_bulk_transform(
    state: &EngineState,
    entity_name: &str,
    field: &str,
    transform: &str,
    value: Option<&str>,
    record_ids: &[Uuid],
    user_id: Uuid,
) -> Result<BulkTransformEnqueueResponse, AppError> {
    let operation_id = Uuid::now_v7();
    let total = record_ids.len() as i32;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO bulk_transform_operation \
            (id, entity_logicalname, field_logicalname, transform, transform_value, status, total, created_by) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)",
    )
    .bind(operation_id)
    .bind(entity_name)
    .bind(field)
    .bind(transform)
    .bind(value)
    .bind(total)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "INSERT INTO bulk_transform_operation_item (operation_id, item_index, record_id, status) \
         SELECT $1, (item.ordinality - 1)::integer, item.value, 'pending' \
         FROM unnest($2::uuid[]) WITH ORDINALITY AS item(value, ordinality)",
    )
    .bind(operation_id)
    .bind(record_ids)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::DataBulkTransform(attome_jobs::DataBulkTransformPayload {
            operation_id,
            entity_logicalname: entity_name.to_owned(),
            field_logicalname: field.to_owned(),
            transform: transform.to_owned(),
            value: value.map(str::to_owned),
            record_ids: record_ids.to_vec(),
            user_id,
        }),
    )
    .await
    .map_err(AppError::internal)?;

    // Plan item 3.10 / D-541 rule 5 — the `BulkAccepted` parent event, in the
    // same transaction as the job enqueue above: if this transaction rolls
    // back, no parent event and no operation exists. Category/entity match
    // the per-record `Update` events `apply_transform_one` writes.
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let accepted_event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: None,
        operation: AuditOperation::BulkAccepted,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(operation_id),
        event_name: None,
        event_comment: Some(format!("bulk-transform {transform} on {field} accepted")),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    write_bulk_accepted(
        &audit_service,
        &mut tx,
        accepted_event,
        Attribution::user(user_id),
        total,
    )
    .await?;

    attome_db::tx::commit(tx).await?;

    Ok(BulkTransformEnqueueResponse {
        id: operation_id,
        status: "pending".into(),
        total,
    })
}

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct BulkTransformStatus {
    id: Uuid,
    entity_logicalname: String,
    field_logicalname: String,
    transform: String,
    status: String,
    total: i32,
    succeeded: i32,
    failed: i32,
    errors: Value,
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/bulk-transform/{id}",
    tag = "entity",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = BulkTransformStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_transform_status(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, operation_id)): Path<(String, Uuid)>,
) -> Result<Json<BulkTransformStatus>, AppError> {
    let (_, entity_name, _, _) = entity_crud::resolve_entity(&state, &entity_input).await?;
    let row: Option<BulkTransformStatus> = sqlx::query_as(
        "SELECT id, entity_logicalname, field_logicalname, transform, status, total, succeeded, failed, errors \
           FROM bulk_transform_operation \
          WHERE id = $1 AND entity_logicalname = $2 AND is_deleted = false \
            AND (created_by = $3 OR $4)",
    )
    .bind(operation_id)
    .bind(&entity_name)
    .bind(claims.sub)
    .bind(ctx.is_admin)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(row.ok_or(AppError::NotFound)?))
}

async fn mark_operation_failed(
    state: &EngineState,
    operation_id: Uuid,
    entity_logicalname: &str,
    user_id: Uuid,
    message: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE bulk_transform_operation \
            SET status = 'failed', errors = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(operation_id)
    .bind(json!([{ "error": message }]))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // Plan item 3.10 rule 4 — the whole operation never started, so this is
    // the "all-or-nothing" shape: a `Failed`, affected-0 `BulkCompleted`
    // event, in its own transaction after this early-bail write.
    write_bulk_completed(state, operation_id, entity_logicalname, user_id, 0, 0).await
}

/// Plan item 3.10 / D-541 rule 5 — writes the `BulkCompleted` parent event
/// for `operation_id` in its own transaction. `succeeded` becomes
/// `affected_count` (I13); `failed` becomes `failed_count`. Idempotent via
/// `write_bulk_completed_once` — safe to call from a resumed/retried
/// terminal-state write.
async fn write_bulk_completed(
    state: &EngineState,
    operation_id: Uuid,
    entity_name: &str,
    user_id: Uuid,
    succeeded: i32,
    failed: i32,
) -> Result<(), AppError> {
    let outcome = if failed == 0 {
        if succeeded == 0 {
            AuditOutcome::Failed
        } else {
            AuditOutcome::Succeeded
        }
    } else if succeeded == 0 {
        AuditOutcome::Failed
    } else {
        AuditOutcome::PartiallyFailed
    };
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: None,
        operation: AuditOperation::BulkCompleted,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(operation_id),
        event_name: None,
        event_comment: Some("bulk-transform completed".to_owned()),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_bulk_completed_once(
        &audit_service,
        &mut tx,
        event,
        Attribution::user(user_id),
        outcome,
        succeeded,
        failed,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

async fn mark_item_failed(
    state: &EngineState,
    operation_id: Uuid,
    item_index: i32,
    error: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE bulk_transform_operation_item \
            SET status = 'failed', error = $3, attempts = attempts + 1, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE operation_id = $1 AND item_index = $2 AND status <> 'succeeded' AND is_deleted = false",
    )
    .bind(operation_id)
    .bind(item_index)
    .bind(error)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

fn apply_builtin(transform: &str, current: Option<&str>, value: Option<&str>) -> String {
    match transform {
        "trim" => current.unwrap_or_default().trim().to_string(),
        "upper" => current.unwrap_or_default().to_uppercase(),
        "lower" => current.unwrap_or_default().to_lowercase(),
        _ => value.unwrap_or_default().to_string(),
    }
}

/// `state`+`ctx` bundled the same way `bulk.rs::RequestContext` does — see
/// that type's doc comment for why (keeps `apply_transform_one` under
/// clippy's `too_many_arguments` limit).
struct RequestContext<'a> {
    state: &'a EngineState,
    ctx: &'a SecurityContext,
}

/// The resolved entity `apply_transform_one` mutates against — same
/// bundling reasoning as `bulk.rs::EntityMutationTarget`.
struct EntityTarget<'a> {
    entity_id: Uuid,
    entity_name: &'a str,
    attrs: &'a [AttrInfo],
}

/// The one field + built-in operation this run applies — bundled for the
/// same `too_many_arguments` reason as the two structs above.
struct TransformSpec<'a> {
    field: &'a str,
    transform: &'a str,
    value: Option<&'a str>,
}

/// Mirrors `bulk::apply_one`'s D-099 row-claiming discipline (claim under
/// `FOR UPDATE`, mutate, finalize, all in one transaction) so a
/// crash/redelivery resumes safely instead of double-applying an
/// already-succeeded item.
async fn apply_transform_one(
    rctx: RequestContext<'_>,
    target: &EntityTarget<'_>,
    spec: &TransformSpec<'_>,
    operation_id: Uuid,
    item_index: i32,
    record_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let RequestContext { state, ctx } = rctx;
    let EntityTarget {
        entity_id,
        entity_name,
        attrs,
    } = *target;
    let TransformSpec {
        field,
        transform,
        value,
    } = *spec;
    entity_crud::require_record_access(
        state,
        ctx,
        entity_id,
        entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let claimed: Option<String> = sqlx::query_scalar(
        "SELECT status FROM bulk_transform_operation_item \
          WHERE operation_id = $1 AND item_index = $2 AND is_deleted = false FOR UPDATE",
    )
    .bind(operation_id)
    .bind(item_index)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(status) = claimed else {
        return Err(AppError::Internal(
            "bulk transform item ledger row is missing".into(),
        ));
    };
    if matches!(status.as_str(), "succeeded" | "running") {
        return Ok(());
    }

    let attempts = sqlx::query(
        "UPDATE bulk_transform_operation_item \
            SET status = 'running', attempts = attempts + 1, error = NULL, \
                claimed_at = NOW(), updated_at = NOW(), row_version = row_version + 1 \
          WHERE operation_id = $1 AND item_index = $2 AND is_deleted = false",
    )
    .bind(operation_id)
    .bind(item_index)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if attempts.rows_affected() != 1 {
        return Err(AppError::Internal(
            "bulk transform item ledger row is missing".into(),
        ));
    }

    let table = quote_ident(entity_name);
    let col = quote_ident(field);
    let current: Option<(Option<String>, i64)> = sqlx::query_as(&format!(
        "SELECT {col}::text, row_version FROM {table} WHERE id = $1 AND is_active = true"
    ))
    .bind(record_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((current_value, row_version)) = current else {
        return Err(AppError::NotFound);
    };

    let new_value = apply_builtin(transform, current_value.as_deref(), value);
    let mut obj = serde_json::Map::new();
    obj.insert(field.to_string(), Value::String(new_value));

    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let mutation = entity_mutation::update_one(
        &mut tx,
        state,
        ctx,
        entity_name,
        entity_id,
        record_id,
        attrs,
        &obj,
        user_id,
        row_version,
        MutationMode::Strict,
    )
    .await?;

    let changed_fields =
        entity_crud::field_changes_from_obj(&mut tx, state, attrs, &obj, mutation.old_row.as_ref())
            .await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(mutation.record_id),
        operation: AuditOperation::Update,
        version_before: Some(row_version),
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(operation_id),
        event_name: None,
        event_comment: Some(format!("bulk-transform {transform} on {field}")),
        changed_fields,
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    audit_service.write_in_tx(&mut tx, event).await?;

    sqlx::query(
        "UPDATE bulk_transform_operation_item \
            SET status = 'succeeded', error = NULL, updated_at = NOW(), row_version = row_version + 1 \
          WHERE operation_id = $1 AND item_index = $2 AND is_deleted = false",
    )
    .bind(operation_id)
    .bind(item_index)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Worker-side processing for `EngineJob::DataBulkTransform`. Authorization
/// is re-resolved directly from Postgres before the loop (same discipline
/// `bulk::process` follows) — a revoked grant cannot remain usable because
/// an app node still has a warm security cache.
pub async fn process(
    state: &EngineState,
    payload: attome_jobs::DataBulkTransformPayload,
) -> Result<(), AppError> {
    let operation_id = payload.operation_id;
    let (entity_id, entity_name, attrs, is_append_only) =
        match entity_crud::resolve_entity(state, &payload.entity_logicalname).await {
            Ok(v) => v,
            Err(e) => {
                mark_operation_failed(
                    state,
                    operation_id,
                    &payload.entity_logicalname,
                    payload.user_id,
                    &format!("entity resolution failed: {e}"),
                )
                .await?;
                return Ok(());
            }
        };
    if is_append_only {
        mark_operation_failed(
            state,
            operation_id,
            &payload.entity_logicalname,
            payload.user_id,
            "entity is append-only; bulk-transform is not supported",
        )
        .await?;
        return Ok(());
    }

    let security = attome_security::resolve_uncached(&state.base.db, payload.user_id).await?;
    if security.require(&entity_name, "update").is_err() {
        mark_operation_failed(
            state,
            operation_id,
            &payload.entity_logicalname,
            payload.user_id,
            "bulk-transform authorization was revoked before processing",
        )
        .await?;
        return Ok(());
    }

    sqlx::query(
        "UPDATE bulk_transform_operation SET status = 'running', updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(operation_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let succeeded_indices: HashSet<i32> = sqlx::query_scalar(
        "SELECT item_index FROM bulk_transform_operation_item \
          WHERE operation_id = $1 AND status = 'succeeded' AND is_deleted = false",
    )
    .bind(operation_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();

    for (index, record_id) in payload.record_ids.iter().enumerate() {
        let item_index = index as i32;
        if succeeded_indices.contains(&item_index) {
            continue;
        }
        if let Err(error) = apply_transform_one(
            RequestContext {
                state,
                ctx: &security,
            },
            &EntityTarget {
                entity_id,
                entity_name: &entity_name,
                attrs: &attrs,
            },
            &TransformSpec {
                field: &payload.field_logicalname,
                transform: &payload.transform,
                value: payload.value.as_deref(),
            },
            operation_id,
            item_index,
            *record_id,
            payload.user_id,
        )
        .await
        {
            if matches!(&error, AppError::Internal(_)) {
                return Err(error);
            }
            mark_item_failed(state, operation_id, item_index, &error.to_string()).await?;
        }
    }

    let (succeeded, failed): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE status = 'succeeded'), COUNT(*) FILTER (WHERE status = 'failed') \
           FROM bulk_transform_operation_item WHERE operation_id = $1 AND is_deleted = false",
    )
    .bind(operation_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let errors: Vec<(i32, Option<String>)> = sqlx::query_as(
        "SELECT item_index, error FROM bulk_transform_operation_item \
          WHERE operation_id = $1 AND status = 'failed' AND is_deleted = false ORDER BY item_index",
    )
    .bind(operation_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let errors_json = Value::Array(
        errors
            .into_iter()
            .map(|(index, error)| json!({ "index": index, "error": error }))
            .collect(),
    );
    sqlx::query(
        "UPDATE bulk_transform_operation \
            SET status = 'completed', succeeded = $2, failed = $3, errors = $4, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(operation_id)
    .bind(succeeded as i32)
    .bind(failed as i32)
    .bind(errors_json)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    write_bulk_completed(
        state,
        operation_id,
        &entity_name,
        payload.user_id,
        succeeded as i32,
        failed as i32,
    )
    .await?;

    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/{entity}/bulk-transform",
            post(enqueue_bulk_transform),
        )
        .route("/api/v1/{entity}/bulk-transform/dry-run", post(dry_run))
        .route(
            "/api/v1/{entity}/bulk-transform/{id}",
            get(get_transform_status),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(dry_run, enqueue_bulk_transform, get_transform_status))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
