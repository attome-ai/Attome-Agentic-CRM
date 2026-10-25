//! `/api/v1/admin/business-rules` (D-789 §6.1; D-790 removed the old
//! `/api/v1/admin/rules*` family outright, with no legacy projection). CRUD
//! with `If-Match` on PATCH, `/validate` (no write), `/{id}/test` (no write)
//! and `/{id}/publish`. The store, validation, warnings and layer rules are
//! `rule_admin.rs`; this file is the thin transport over them.
//!
//! Every mutating route declares `x-audit` (D-542), writes its
//! Configuration security event in its own transaction, records its
//! changeset op when the write mode records (`rule_admin::write_mode`,
//! D-791 rule 2), commits, then invalidates the rule registry.

use attome_core::EngineState;
use attome_core::business_rules::{
    self as br, BUSINESS_KIND, BusinessRuleDef, ConditionOutcome, LockEffect, PolicyEffect,
    RuleAudience, RuleIssue, SetValueSource,
};
use attome_core::changeset::{Op, RecordingCtx};
use attome_records::query_admin::resolve_live_entity_id;
use attome_records::rule_engine;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::rule_admin::{
    self as store, BusinessRule, BusinessRuleBody, BusinessRulePatch, RuleEditorWarning,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/// `If-Match: "<row_version>"` → the expected `row_version`.
fn if_match(headers: &HeaderMap, required: bool) -> Result<Option<i64>, AppError> {
    let Some(raw) = headers.get(IF_MATCH) else {
        return if required {
            Err(AppError::Validation(
                "If-Match: \"<row_version>\" is required to update a business rule".into(),
            ))
        } else {
            Ok(None)
        };
    };
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map(Some).map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

fn configuration_event(
    operation: attome_audit::AuditOperation,
    actor: Uuid,
    id: Uuid,
    name: &'static str,
) -> attome_audit::security::SecurityEvent {
    attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Configuration,
        operation,
        actor,
        "rule",
        Some(id),
    )
    .named(name)
}

async fn read_or_404(state: &EngineState, id: Uuid) -> Result<BusinessRule, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    store::read_rule(&mut conn, id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Warnings for a stored business rule (a single read or a write answer).
async fn warnings_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    rule: &BusinessRule,
) -> Result<Vec<RuleEditorWarning>, AppError> {
    if rule.kind != BUSINESS_KIND {
        return Ok(Vec::new());
    }
    let Some(input) = store::input_of(rule) else {
        return Ok(Vec::new());
    };
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    Ok(
        store::check(&mut conn, state, Some(ctx), &input, Some(rule.id))
            .await?
            .warnings,
    )
}

// ── List / get ──────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct RuleFilter {
    /// One entity's rules.
    entity: Option<String>,
    /// `business` or a legacy kind.
    kind: Option<String>,
    /// Rules that apply to this staff role.
    role_id: Option<Uuid>,
    /// Rules that apply to this web-portal role.
    portal_role_id: Option<Uuid>,
    /// Only active (true) or inactive (false) ones.
    is_active: Option<bool>,
}

/// List business rules
///
/// List business rules. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/business-rules",
    tag = "admin",
    params(RuleFilter, OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<BusinessRule>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_rules(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(filter): Query<RuleFilter>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<BusinessRule>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let entity = filter.entity.as_deref().map(str::trim);
    let kind = filter.kind.as_deref().map(str::trim);
    const WHERE: &str = "WHERE r.is_deleted = false \
           AND ($1::text IS NULL OR r.entity_logicalname = $1) \
           AND ($2::text IS NULL OR r.kind = $2) \
           AND ($3::uuid IS NULL OR EXISTS (SELECT 1 FROM rule_role rr \
                 WHERE rr.rule_ref = r.id AND rr.role_ref = $3)) \
           AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM rule_role rr \
                 WHERE rr.rule_ref = r.id AND rr.portal_role_ref = $4)) \
           AND ($5::bool IS NULL OR r.is_active = $5)";
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let rows: Vec<store::RuleRow> = sqlx::query_as(&format!(
        "SELECT {} FROM rule r {WHERE} \
         ORDER BY r.entity_logicalname, r.display_order, r.name LIMIT $6 OFFSET $7",
        store::RULE_COLUMNS
    ))
    .bind(entity)
    .bind(kind)
    .bind(filter.role_id)
    .bind(filter.portal_role_id)
    .bind(filter.is_active)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM rule r {WHERE}"))
        .bind(entity)
        .bind(kind)
        .bind(filter.role_id)
        .bind(filter.portal_role_id)
        .bind(filter.is_active)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let items = store::assemble_rules(&mut conn, rows).await?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One business rule
///
/// One business rule. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/business-rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The business rule")),
    responses(
        (status = 200, description = "The rule with its editor warnings", body = BusinessRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<BusinessRule>, AppError> {
    let mut rule = read_or_404(&state, id).await?;
    rule.warnings = warnings_for(&state, &ctx, &rule).await?;
    Ok(Json(rule))
}

// ── Create / update / delete ────────────────────────────────────────────────

/// Create a business rule
///
/// Create a business rule. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules",
    tag = "admin",
    request_body = BusinessRuleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created, with editor warnings", body = BusinessRule),
        (status = 200, description = "A repeat of an identical create: the existing rule", body = BusinessRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "`rule_exists`: another rule of this (entity, name); or a changeset refusal", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<BusinessRuleBody>,
) -> Result<Response, AppError> {
    let input = store::input_from_body(body).map_err(|i| store::issues_error(&i))?;
    let checked = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        let existing = store::read_rule_by_key(&mut conn, &input.entity, &input.name).await?;
        if let Some(existing) = existing {
            // Idempotent by (entity, name) among live rows (design §6.3).
            return if store::input_of(&existing).is_some_and(|e| e.same_definition(&input)) {
                let mut existing = existing;
                existing.warnings = warnings_for(&state, &ctx, &existing).await?;
                Ok((StatusCode::OK, Json(existing)).into_response())
            } else {
                Err(AppError::Conflict(
                    "rule_exists: a rule with this name already exists on this entity; \
                     change it with PATCH or pick another name",
                ))
            };
        }
        store::check(&mut conn, &state, Some(&ctx), &input, None).await?
    };
    if !checked.issues.is_empty() {
        return Err(store::issues_error(&checked.issues));
    }
    resolve_live_entity_id(&state.base.db, &input.entity).await?;
    let mode = store::write_mode(&state, &recording).await?;

    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    store::insert_rule(&mut tx, id, &input, mode.layer, true).await?;
    let mut rule = store::read_rule(&mut tx, id)
        .await?
        .ok_or_else(|| AppError::internal("rule vanished inside its own create"))?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        configuration_event(
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            id,
            "rule.create",
        ),
    )
    .await?;
    if mode.record {
        recording
            .record(&mut tx, store::rule_op(Op::UpsertRule, &rule)?)
            .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    store::invalidate(&state).await;
    rule.warnings = checked.warnings;
    Ok((StatusCode::CREATED, Json(rule)).into_response())
}

/// Update a business rule
///
/// Update a business rule. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/business-rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The business rule"), ("If-Match" = String, Header, description = "`\"<row_version>\"` of the rule being changed (required)")),
    request_body = BusinessRulePatch,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Updated, with editor warnings", body = BusinessRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 409, description = "`version_conflict` (stale If-Match), `layer_mismatch`, or a changeset refusal", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or If-Match missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(patch): Json<BusinessRulePatch>,
) -> Result<Json<BusinessRule>, AppError> {
    let expected = if_match(&headers, true)?;
    let stored = read_or_404(&state, id).await?;
    let body = store::merge_patch(&stored, patch)?;
    let input = store::input_from_body(body).map_err(|i| store::issues_error(&i))?;
    let checked = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        store::check(&mut conn, &state, Some(&ctx), &input, Some(id)).await?
    };
    if !checked.issues.is_empty() {
        return Err(store::issues_error(&checked.issues));
    }
    let mode = store::write_mode(&state, &recording).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (owner, row_version) = store::lock_rule(&mut tx, id, false).await?;
    store::check_owner(&recording, mode, &owner)?;
    if expected.is_some_and(|v| v != row_version) {
        return Err(AppError::VersionConflict);
    }
    store::update_rule(&mut tx, id, &input, Some(true)).await?;
    let mut rule = store::read_rule(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        configuration_event(
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            id,
            "rule.update",
        ),
    )
    .await?;
    if mode.record {
        recording
            .record(&mut tx, store::rule_op(Op::UpsertRule, &rule)?)
            .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    store::invalidate(&state).await;
    rule.warnings = checked.warnings;
    Ok(Json(rule))
}

/// Delete a business rule
///
/// Delete a business rule. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/business-rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The business rule"), ("If-Match" = Option<String>, Header, description = "Optional `\"<row_version>\"`")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Retired (is_active = false)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active rule", body = ErrorResponse),
        (status = 409, description = "`version_conflict`, `layer_mismatch`, or a changeset refusal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let expected = if_match(&headers, false)?;
    let mode = store::write_mode(&state, &recording).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (owner, row_version) = store::lock_rule(&mut tx, id, true).await?;
    store::check_owner(&recording, mode, &owner)?;
    if expected.is_some_and(|v| v != row_version) {
        return Err(AppError::VersionConflict);
    }
    store::retire_in_tx(&mut tx, id).await?;
    let rule = store::read_rule(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        configuration_event(
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            id,
            "rule.delete",
        ),
    )
    .await?;
    if mode.record {
        recording
            .record(&mut tx, store::rule_op(Op::RetireRule, &rule)?)
            .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    store::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Validate ────────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct ValidateResponse {
    valid: bool,
    issues: Vec<RuleIssue>,
    warnings: Vec<RuleEditorWarning>,
}

/// Validate a business rule
///
/// Validate a business rule. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules/validate",
    tag = "admin",
    request_body = BusinessRuleBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "validates a rule body against the live schema, roles and limits; writes nothing")))),
    responses(
        (status = 200, description = "The issues and warnings; nothing is written", body = ValidateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn validate_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<BusinessRuleBody>,
) -> Result<Json<ValidateResponse>, AppError> {
    let input = match store::input_from_body(body) {
        Ok(input) => input,
        Err(issues) => {
            return Ok(Json(ValidateResponse {
                valid: false,
                issues,
                warnings: Vec::new(),
            }));
        }
    };
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let existing = store::read_rule_by_key(&mut conn, &input.entity, &input.name).await?;
    let checked = store::check(
        &mut conn,
        &state,
        Some(&ctx),
        &input,
        existing.map(|r| r.id),
    )
    .await?;
    Ok(Json(ValidateResponse {
        valid: checked.issues.is_empty(),
        issues: checked.issues,
        warnings: checked.warnings,
    }))
}

// ── Test ────────────────────────────────────────────────────────────────────

/// Who the rule is tested for. Absent: the rule is evaluated as if it
/// applied, every policy included.
#[derive(Deserialize, ToSchema, Default)]
pub(crate) struct TestAudience {
    /// Staff roles the writer holds.
    #[serde(default)]
    role_ids: Vec<Uuid>,
    /// A portal writer's role (wins over `role_ids`).
    #[serde(default)]
    portal_role_id: Option<Uuid>,
    /// A system context (workflow, bundle record sets): no locks, no
    /// role-scoped rules.
    #[serde(default)]
    system: bool,
    /// `false` for an API-key or S2S principal, which skips locks (D-791
    /// rule 3). Default `true`.
    #[serde(default)]
    interactive: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct RuleTestRequest {
    /// The record to evaluate against — no save, no side effects.
    #[serde(default)]
    pub(crate) record: Map<String, Value>,
    #[serde(default, rename = "as")]
    pub(crate) audience: Option<TestAudience>,
}

#[derive(Serialize, ToSchema)]
struct RuleTraceEntryWire {
    expr: String,
    value: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct TestError {
    field: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) severity: String,
}

#[derive(Serialize, ToSchema)]
struct TestLock {
    field: String,
    /// `hidden` or `disabled`.
    effect: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RuleTestResponse {
    /// Whether the rule applies to the tested audience (always `true` when
    /// no audience was given).
    applies: bool,
    /// `true`, `false`, `unknown` (null, non-boolean or a failed evaluation:
    /// locks and errors apply, `set_value` fails the write) or `transient`.
    condition: String,
    /// Ordinals of the policies that fire.
    policies_fired: Vec<i32>,
    /// Field → the value each firing `set_value` policy writes.
    set_values: Map<String, Value>,
    pub(crate) errors: Vec<TestError>,
    locks: Vec<TestLock>,
    trace: Vec<RuleTraceEntryWire>,
    /// Legacy kinds: the expression's raw value.
    result: Option<Value>,
    /// An evaluation failure (budget, divide by zero, a `set_value` that
    /// could not be computed).
    pub(crate) error: Option<String>,
}

fn outcome_label(o: &ConditionOutcome) -> &'static str {
    match o {
        ConditionOutcome::True => "true",
        ConditionOutcome::False => "false",
        ConditionOutcome::Unknown { .. } => "unknown",
        ConditionOutcome::Transient => "transient",
    }
}

/// Test a business rule
///
/// Test a business rule. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules/{id}/test",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The business rule")),
    request_body = RuleTestRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "evaluates the stored rule against a caller-supplied record in memory only; no save, no relation to any real record, no persistent effect")))),
    responses(
        (status = 200, description = "Success", body = RuleTestResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 422, description = "The stored rule no longer compiles against the live schema", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn test_rule(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(req): Json<RuleTestRequest>,
) -> Result<Json<RuleTestResponse>, AppError> {
    let rule = read_or_404(&state, id).await?;
    let attrs = store::attrs_for_entity(&state, &rule.entity_logicalname).ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{}'",
            rule.entity_logicalname
        ))
    })?;
    let now = Utc::now();
    if rule.kind != BUSINESS_KIND {
        return Ok(Json(test_legacy(&rule, &attrs, &req.record, now)?));
    }
    Ok(Json(test_business(&rule, &attrs, &req, now)?))
}

/// One rule's outcome on a stored record (A11-T5).
#[derive(Serialize, ToSchema)]
struct RuleExplanation {
    rule_id: Uuid,
    name: String,
    kind: String,
    #[serde(flatten)]
    outcome: RuleTestResponse,
}

/// `GET /api/v1/admin/business-rules/explain`.
#[derive(Serialize, ToSchema)]
struct RulesExplained {
    entity: String,
    record_id: Uuid,
    rules: Vec<RuleExplanation>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ExplainQuery {
    /// The entity's logical name.
    entity: String,
    /// The record.
    id: Uuid,
}

/// Explain a record's rules
///
/// A11-T5: why a record looks the way it does: every active rule on its
/// entity evaluated against the stored record, as `.../{id}/test` evaluates
/// one: whether it applies, its condition, the policies that fire, the
/// values it would set, its errors and locks, and the trace. Writes nothing.
#[utoipa::path(
    get,
    path = "/api/v1/admin/business-rules/explain",
    tag = "admin",
    params(ExplainQuery),
    responses(
        (status = 200, description = "Each active rule's outcome on the record", body = RulesExplained),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity or record", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn explain_rules(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Query(query): Query<ExplainQuery>,
) -> Result<Json<RulesExplained>, AppError> {
    let record =
        attome_records::entity_crud::read_record(&state, &ctx, &query.entity, query.id).await?;
    let data = record.data().as_object().cloned().unwrap_or_default();
    let attrs = store::attrs_for_entity(&state, &query.entity).ok_or(AppError::NotFound)?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM rule WHERE entity_logicalname = $1 AND is_deleted = false \
           AND is_active = true ORDER BY display_order, name",
    )
    .bind(&query.entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let request = RuleTestRequest {
        record: data,
        audience: None,
    };
    let mut rules = Vec::with_capacity(ids.len());
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    for id in ids {
        let Some(rule) = store::read_rule(&mut conn, id).await? else {
            continue;
        };
        let outcome = if rule.kind == BUSINESS_KIND {
            test_business(&rule, &attrs, &request, now)
        } else {
            test_legacy(&rule, &attrs, &request.record, now)
        };
        // A rule that no longer compiles is reported, not a failed explain.
        let outcome = outcome.unwrap_or_else(|error| RuleTestResponse {
            applies: false,
            condition: "unknown".into(),
            policies_fired: Vec::new(),
            set_values: Map::new(),
            errors: Vec::new(),
            locks: Vec::new(),
            trace: Vec::new(),
            result: None,
            error: Some(error.to_string()),
        });
        rules.push(RuleExplanation {
            rule_id: rule.id,
            name: rule.name.clone(),
            kind: rule.kind.clone(),
            outcome,
        });
    }
    Ok(Json(RulesExplained {
        entity: query.entity,
        record_id: query.id,
        rules,
    }))
}

/// A3-T5: one rule on one record, as `.../{id}/test` evaluates it.
pub(crate) fn evaluate(
    rule: &BusinessRule,
    attrs: &[attome_core::AttrInfo],
    req: &RuleTestRequest,
    now: chrono::DateTime<Utc>,
) -> Result<RuleTestResponse, AppError> {
    if rule.kind == BUSINESS_KIND {
        test_business(rule, attrs, req, now)
    } else {
        test_legacy(rule, attrs, &req.record, now)
    }
}

fn trace_wire(trace: &attome_rules::Trace) -> Vec<RuleTraceEntryWire> {
    trace
        .entries()
        .iter()
        .map(|e| RuleTraceEntryWire {
            expr: e.expr.clone(),
            value: e.value.to_string(),
        })
        .collect()
}

fn test_legacy(
    rule: &BusinessRule,
    attrs: &[attome_core::AttrInfo],
    record: &Map<String, Value>,
    now: chrono::DateTime<Utc>,
) -> Result<RuleTestResponse, AppError> {
    let expression = rule.expression.as_deref().unwrap_or_default();
    let schema = rule_engine::schema_for_entity(attrs);
    let compiled = attome_rules::compile(expression, &schema)
        .map_err(|e| AppError::Validation(format!("stored expression no longer compiles: {e}")))?;
    let ctx = rule_engine::context_for_record(now, attrs, record);
    let mut out = RuleTestResponse {
        applies: true,
        condition: "unknown".into(),
        policies_fired: Vec::new(),
        set_values: Map::new(),
        errors: Vec::new(),
        locks: Vec::new(),
        trace: Vec::new(),
        result: None,
        error: None,
    };
    match compiled.eval_traced(&ctx) {
        Ok((value, trace)) => {
            out.condition = outcome_label(&ConditionOutcome::from_result(Ok(value.clone()))).into();
            out.result = Some(rule_engine::json_from_rules_value(&value));
            out.trace = trace_wire(&trace);
        }
        Err(e) => out.error = Some(e.to_string()),
    }
    Ok(out)
}

fn test_business(
    rule: &BusinessRule,
    attrs: &[attome_core::AttrInfo],
    req: &RuleTestRequest,
    now: chrono::DateTime<Utc>,
) -> Result<RuleTestResponse, AppError> {
    let condition = rule.condition.as_ref().ok_or_else(|| {
        AppError::Validation(
            rule.load_error
                .clone()
                .unwrap_or_else(|| "the stored rule has no condition".into()),
        )
    })?;
    let compiled =
        br::compile_condition(condition, attrs).map_err(|issues| store::issues_error(&issues))?;
    let def = BusinessRuleDef {
        id: rule.id,
        entity_logicalname: rule.entity_logicalname.clone(),
        name: rule.name.clone(),
        display_name: rule.display_name.clone(),
        is_active: true,
        display_order: rule.display_order,
        version: rule.version,
        row_version: rule.row_version,
        applies_to: rule.applies_to,
        role_ids: rule
            .roles
            .iter()
            .filter(|r| !r.portal_role && r.live)
            .map(|r| r.id)
            .collect(),
        portal_role_ids: rule
            .roles
            .iter()
            .filter(|r| r.portal_role)
            .map(|r| r.id)
            .collect(),
        condition: condition.clone(),
        policies: rule.policies.clone(),
    };
    let (applies, subject_to_locks) = match &req.audience {
        None => (true, true),
        Some(a) => {
            let audience = if a.system {
                RuleAudience::System
            } else if let Some(role_id) = a.portal_role_id {
                RuleAudience::Portal { role_id }
            } else {
                RuleAudience::Staff {
                    role_ids: &a.role_ids,
                    interactive: a.interactive.unwrap_or(true),
                }
            };
            (
                def.applies_to_audience(&audience),
                audience.subject_to_locks(),
            )
        }
    };

    let ctx = compiled.context(attrs, &req.record, now);
    let (outcome, trace) = match compiled.compiled.eval_traced(&ctx) {
        Ok((value, trace)) => (ConditionOutcome::from_result(Ok(value)), trace_wire(&trace)),
        Err(e) => (ConditionOutcome::from_result(Err(e)), Vec::new()),
    };
    let mut out = RuleTestResponse {
        applies,
        condition: outcome_label(&outcome).into(),
        policies_fired: Vec::new(),
        set_values: Map::new(),
        errors: Vec::new(),
        locks: Vec::new(),
        trace,
        result: None,
        error: None,
    };
    if !applies {
        return Ok(out);
    }
    let expr_schema = br::condition_schema(attrs);
    let expr_ctx = br::condition_context(attrs, &req.record, now);
    for p in &def.policies {
        let Some(effect) = p.effect() else { continue };
        match effect {
            PolicyEffect::Lock { field, effect } => {
                if subject_to_locks && outcome.holds_fail_closed() {
                    out.policies_fired.push(p.ordinal);
                    out.locks.push(TestLock {
                        field: field.to_owned(),
                        effect: match effect {
                            LockEffect::Hidden => "hidden",
                            LockEffect::Disabled => "disabled",
                        }
                        .into(),
                    });
                }
            }
            PolicyEffect::Error {
                field,
                message,
                severity,
            } => {
                if outcome.holds_fail_closed() {
                    out.policies_fired.push(p.ordinal);
                    out.errors.push(TestError {
                        field: field.map(str::to_owned),
                        message: message.map(str::to_owned),
                        severity: severity.as_str().into(),
                    });
                }
            }
            PolicyEffect::Required { field, message } => {
                let empty = req.record.get(field).is_none_or(|v| {
                    v.is_null()
                        || v.as_str().is_some_and(|s| s.trim().is_empty())
                        || v.as_array().is_some_and(Vec::is_empty)
                });
                if outcome.holds_fail_closed() && empty {
                    out.policies_fired.push(p.ordinal);
                    out.errors.push(TestError {
                        field: Some(field.to_owned()),
                        message: Some(
                            message.map_or_else(|| format!("{field} is required"), str::to_owned),
                        ),
                        severity: "error".into(),
                    });
                }
            }
            PolicyEffect::AllowedValues {
                field,
                values,
                message,
            } => {
                if outcome.holds_fail_closed() && !br::value_allowed(req.record.get(field), values)
                {
                    out.policies_fired.push(p.ordinal);
                    out.errors.push(TestError {
                        field: Some(field.to_owned()),
                        message: Some(message.map_or_else(
                            || format!("{field} has a value this rule does not allow"),
                            str::to_owned,
                        )),
                        severity: "error".into(),
                    });
                }
            }
            PolicyEffect::Tag { .. } => {
                if outcome.holds_fail_closed() {
                    out.policies_fired.push(p.ordinal);
                }
            }
            PolicyEffect::SetValue { field, source, .. } => match &outcome {
                ConditionOutcome::True => {
                    out.policies_fired.push(p.ordinal);
                    let value = match source {
                        SetValueSource::Literal(v) => v.clone(),
                        SetValueSource::Expression(src) => {
                            match attome_rules::compile(src, &expr_schema)
                                .map_err(|e| e.to_string())
                                .and_then(|c| c.eval(&expr_ctx).map_err(|e| e.to_string()))
                            {
                                Ok(v) => rule_engine::json_from_rules_value(&v),
                                Err(e) => {
                                    out.error = Some(format!("set_value on '{field}': {e}"));
                                    Value::Null
                                }
                            }
                        }
                    };
                    out.set_values.insert(field.to_owned(), value);
                }
                ConditionOutcome::Unknown { .. } | ConditionOutcome::Transient => {
                    out.error = Some(format!(
                        "set_value on '{field}' cannot be computed: the condition is unknown"
                    ));
                }
                ConditionOutcome::False => {}
            },
        }
    }
    Ok(out)
}

// ── Publish ─────────────────────────────────────────────────────────────────

/// Publish a business rule
///
/// Publish a business rule. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules/{id}/publish",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The business rule")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Activated)])))),
    responses(
        (status = 200, description = "Published: `version` bumped and snapshotted", body = BusinessRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 409, description = "A concurrent publish, `layer_mismatch`, or a changeset refusal", body = ErrorResponse),
        (status = 422, description = "The stored rule no longer validates against the live schema", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<Json<BusinessRule>, AppError> {
    let stored = read_or_404(&state, id).await?;
    if let Some(e) = &stored.load_error {
        return Err(AppError::Validation(format!(
            "the stored rule cannot be published: {e}"
        )));
    }
    // Re-validates against the LIVE schema: a field may have changed since
    // the last save; publishing is the moment that must catch it.
    let input = store::input_of(&stored)
        .ok_or_else(|| AppError::Validation("the stored rule no longer validates".into()))?;
    let checked = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        store::check(&mut conn, &state, Some(&ctx), &input, Some(id)).await?
    };
    if !checked.issues.is_empty() {
        return Err(store::issues_error(&checked.issues));
    }
    let mode = store::write_mode(&state, &recording).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (owner, _) = store::lock_rule(&mut tx, id, false).await?;
    store::check_owner(&recording, mode, &owner)?;
    store::publish_in_tx(&mut tx, &stored, ctx.user_id).await?;
    let rule = store::read_rule(&mut tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        configuration_event(
            attome_audit::AuditOperation::Activated,
            ctx.user_id,
            id,
            "rule.publish",
        ),
    )
    .await?;
    if mode.record {
        recording
            .record(&mut tx, store::rule_op(Op::PublishRule, &rule)?)
            .await?;
    }
    // A3-T5: the stored records the published rule refuses go to its
    // clean-up queue, from a durable full scan, never this request.
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::ValidationCleanupScan { rule_id: id },
    )
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    store::invalidate(&state).await;
    Ok(Json(rule))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/business-rules",
            get(list_rules).post(create_rule),
        )
        .route("/api/v1/admin/business-rules/validate", post(validate_rule))
        .route("/api/v1/admin/business-rules/explain", get(explain_rules))
        .route(
            "/api/v1/admin/business-rules/{id}",
            get(get_rule).patch(update_rule).delete(delete_rule),
        )
        .route("/api/v1/admin/business-rules/{id}/test", post(test_rule))
        .route(
            "/api/v1/admin/business-rules/{id}/publish",
            post(publish_rule),
        )
        .route(
            "/api/v1/admin/business-rules/{id}/simulate",
            post(crate::validation_simulation::simulate_rule),
        )
        .route(
            "/api/v1/admin/business-rules/{id}/cleanup",
            get(crate::validation_simulation::cleanup_queue),
        )
        .route(
            "/api/v1/admin/validation/stats",
            get(crate::validation_stats::validation_stats),
        )
        // O9-T1: rule-change and flow-change scenarios.
        .route(
            "/api/v1/scenarios/{id}/simulations",
            post(crate::validation_simulation::run_scenario)
                .get(crate::validation_simulation::list_scenario),
        )
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_rules,
    get_rule,
    create_rule,
    update_rule,
    delete_rule,
    validate_rule,
    test_rule,
    publish_rule,
    explain_rules,
    crate::validation_simulation::simulate_rule,
    crate::validation_simulation::cleanup_queue,
    crate::validation_simulation::run_scenario,
    crate::validation_simulation::list_scenario,
    crate::validation_stats::validation_stats
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_match_is_required_on_patch_and_optional_on_delete() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            if_match(&headers, true),
            Err(AppError::Validation(_))
        ));
        assert_eq!(if_match(&headers, false).expect("absent"), None);
        headers.insert(IF_MATCH, "\"7\"".parse().expect("hv"));
        assert_eq!(if_match(&headers, true).expect("parsed"), Some(7));
        headers.insert(IF_MATCH, "\"x\"".parse().expect("hv"));
        assert!(if_match(&headers, false).is_err());
    }

    #[test]
    fn the_fragment_documents_every_route_with_x_audit_on_the_mutating_ones() {
        let value = serde_json::to_value(openapi_fragment()).expect("serializes");
        let paths = &value["paths"];
        for (path, method, key) in [
            ("/api/v1/admin/business-rules", "post", "x-audit"),
            ("/api/v1/admin/business-rules/{id}", "patch", "x-audit"),
            ("/api/v1/admin/business-rules/{id}", "delete", "x-audit"),
            (
                "/api/v1/admin/business-rules/{id}/publish",
                "post",
                "x-audit",
            ),
            (
                "/api/v1/admin/business-rules/validate",
                "post",
                "x-audit-exempt",
            ),
            (
                "/api/v1/admin/business-rules/{id}/test",
                "post",
                "x-audit-exempt",
            ),
        ] {
            assert!(
                paths[path][method][key].is_object() || paths[path][method][key].is_array(),
                "{method} {path} lacks {key}"
            );
        }
        assert!(paths["/api/v1/admin/business-rules"]["get"].is_object());
        assert!(paths["/api/v1/admin/business-rules/{id}"]["get"].is_object());
    }
}
