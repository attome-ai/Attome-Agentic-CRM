//! M9-T1: approval processes on top of `attome-approval`.
//!
//! A process (`approval_process`, migration 0210) names an entity, an
//! optional entry condition (V2 rule text over the record's fields, the
//! workflow condition evaluator's), the approval plan its requests follow,
//! and whether a submitted record is locked while pending
//! (`attome_records::approval_lock`, which leaves `editable_attributes`
//! writable). Administrators manage processes; a person who may update a
//! record submits it, and only the requester recalls it while no decision
//! has been made. Deciding goes through the ordinary approval routes, and the
//! lock ends with the request.
//!
//! Not a second approval framework (D-421): a submission is one
//! `approval_request` (action type `approval_process`, regarding the record,
//! `payload.process_id`), resolved, decided, escalated and timed out exactly
//! like every other.
//!
//! M9-T4: the request page reads `GET /api/v1/approvals/{id}`: what is
//! asked, by whom, why (the submitter's `reason`), the attribute changes a
//! held change carries (from, to), every decision so far, and whether the
//! caller may decide now. An administrator, the requester, anyone who
//! decided it, an eligible approver, and anyone who may read the record it
//! is about see it; anyone else gets 404. A record's history panel reads
//! `GET /api/v1/approvals/regarding/{entity}/{record_id}`, for whoever may
//! read the record.

use attome_approval::ApprovalPlan;
use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_records::approval_lock::APPROVAL_PROCESS_ACTION;
use attome_security::RecordAction;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// One approval process.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ApprovalProcess {
    pub id: Uuid,
    pub name: String,
    pub entity_logicalname: String,
    /// V2 rule text over the record's fields; `null` admits every record.
    pub entry_condition: Option<String>,
    #[schema(value_type = Object)]
    pub plan: Value,
    pub lock_record: bool,
    /// What may still change while a request is pending.
    pub editable_attributes: Vec<String>,
    /// M9-T2: `submit` (a person submits the record) or `change` (an
    /// update that changes a watched attribute is held for approval).
    pub starts_on: String,
    /// M9-T2: the attributes a `change` process holds.
    pub watched_attributes: Vec<String>,
    pub is_active: bool,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, name, entity_logicalname, entry_condition, plan, lock_record, \
                       editable_attributes, starts_on, watched_attributes, is_active, \
                       row_version, created_at, updated_at";

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApprovalProcessBody {
    pub name: String,
    pub entity_logicalname: String,
    #[serde(default)]
    pub entry_condition: Option<String>,
    pub plan: ApprovalPlan,
    #[serde(default = "default_true")]
    pub lock_record: bool,
    #[serde(default)]
    pub editable_attributes: Vec<String>,
    /// M9-T2: `submit` (the default) or `change`.
    #[serde(default = "default_starts_on")]
    pub starts_on: String,
    /// M9-T2: required for a `change` process, empty for `submit`.
    #[serde(default)]
    pub watched_attributes: Vec<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_starts_on() -> String {
    "submit".to_owned()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApprovalProcessUpdate {
    #[serde(flatten)]
    pub body: ApprovalProcessBody,
    pub row_version: i64,
}

fn default_true() -> bool {
    true
}

/// Checks a body: a name, a known entity, a parsing entry condition, a valid
/// plan whose approver tokens resolve, editable attributes of the entity.
fn check_body(state: &EngineState, body: &ApprovalProcessBody) -> Result<(), AppError> {
    if body.name.trim().is_empty() || body.name.len() > 200 {
        return Err(AppError::Validation(
            "name is required (at most 200 characters)".into(),
        ));
    }
    let registry = state.entities.load();
    let Some(meta) = registry.get(&body.entity_logicalname) else {
        return Err(AppError::Validation(format!(
            "unknown entity {:?}",
            body.entity_logicalname
        )));
    };
    if let Some(condition) = body
        .entry_condition
        .as_deref()
        .filter(|c| !c.trim().is_empty())
    {
        attome_workflow::condition::check_expression(condition).map_err(AppError::Validation)?;
    }
    body.plan.validate()?;
    attome_audit::approval::validate_plan_approvers(&body.plan)?;
    if let Some(unknown) = body
        .editable_attributes
        .iter()
        .find(|a| !meta.attrs.iter().any(|attr| &attr.logicalname == *a))
    {
        return Err(AppError::Validation(format!(
            "editable attribute {unknown:?} is not a field of {}",
            body.entity_logicalname
        )));
    }
    match body.starts_on.as_str() {
        "submit" if body.watched_attributes.is_empty() => {}
        "submit" => {
            return Err(AppError::Validation(
                "watched_attributes belong to a process that starts on change".into(),
            ));
        }
        "change" if body.watched_attributes.is_empty() => {
            return Err(AppError::Validation(
                "a process that starts on change needs at least one watched attribute".into(),
            ));
        }
        "change" => {}
        _ => {
            return Err(AppError::Validation(
                "starts_on is `submit` or `change`".into(),
            ));
        }
    }
    if let Some(unknown) = body
        .watched_attributes
        .iter()
        .find(|a| !meta.attrs.iter().any(|attr| &attr.logicalname == *a))
    {
        return Err(AppError::Validation(format!(
            "watched attribute {unknown:?} is not a field of {}",
            body.entity_logicalname
        )));
    }
    Ok(())
}

/// List approval processes
///
/// List approval processes. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/approval-processes",
    tag = "admin",
    operation_id = "list_approval_processes",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Every approval process, by name", body = PaginatedResponse<ApprovalProcess>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_processes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ApprovalProcess>>, AppError> {
    let w = page.window();
    let items: Vec<ApprovalProcess> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM approval_process WHERE NOT is_deleted \
          ORDER BY name, id LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_process WHERE NOT is_deleted")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

/// Create an approval process
///
/// Create an approval process. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/approval-processes",
    tag = "admin",
    operation_id = "create_approval_process",
    request_body = ApprovalProcessBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = ApprovalProcess),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_process(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<ApprovalProcessBody>,
) -> Result<(StatusCode, Json<ApprovalProcess>), AppError> {
    check_body(&state, &body)?;
    let id = Uuid::now_v7();
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "approval_process",
            Some(id),
        )
        .named("approval_process.create"),
    )
    .await?;
    let row: ApprovalProcess = sqlx::query_as(&format!(
        "INSERT INTO approval_process \
             (id, name, entity_logicalname, entry_condition, plan, lock_record, \
              editable_attributes, is_active, created_by, starts_on, watched_attributes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(body.name.trim())
    .bind(&body.entity_logicalname)
    .bind(
        body.entry_condition
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty()),
    )
    .bind(serde_json::to_value(&body.plan).map_err(AppError::internal)?)
    .bind(body.lock_record)
    .bind(&body.editable_attributes)
    .bind(body.is_active)
    .bind(ctx.user_id)
    .bind(&body.starts_on)
    .bind(&body.watched_attributes)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// One approval process
///
/// One approval process. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/approval-processes/{id}",
    tag = "admin",
    operation_id = "get_approval_process",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The process", body = ApprovalProcess),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_process(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalProcess>, AppError> {
    load(&state, id).await.map(Json)
}

async fn load(state: &EngineState, id: Uuid) -> Result<ApprovalProcess, AppError> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM approval_process WHERE id = $1 AND NOT is_deleted"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Update an approval process
///
/// Update an approval process. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/approval-processes/{id}",
    tag = "admin",
    operation_id = "update_approval_process",
    params(("id" = Uuid, Path)),
    request_body = ApprovalProcessUpdate,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Updated", body = ApprovalProcess),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "row_version conflict", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_process(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(update): Json<ApprovalProcessUpdate>,
) -> Result<Json<ApprovalProcess>, AppError> {
    let body = &update.body;
    check_body(&state, body)?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "approval_process",
            Some(id),
        )
        .named("approval_process.update"),
    )
    .await?;
    let row: Option<ApprovalProcess> = sqlx::query_as(&format!(
        "UPDATE approval_process \
            SET name = $3, entity_logicalname = $4, entry_condition = $5, plan = $6, \
                lock_record = $7, editable_attributes = $8, is_active = $9, \
                starts_on = $10, watched_attributes = $11, \
                row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND row_version = $2 AND NOT is_deleted \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(update.row_version)
    .bind(body.name.trim())
    .bind(&body.entity_logicalname)
    .bind(
        body.entry_condition
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty()),
    )
    .bind(serde_json::to_value(&body.plan).map_err(AppError::internal)?)
    .bind(body.lock_record)
    .bind(&body.editable_attributes)
    .bind(body.is_active)
    .bind(&body.starts_on)
    .bind(&body.watched_attributes)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return match load(&state, id).await {
            Ok(_) => Err(AppError::VersionConflict),
            Err(e) => Err(e),
        };
    };
    tx.commit().await?;
    Ok(Json(row))
}

/// Delete an approval process
///
/// Delete an approval process. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/approval-processes/{id}",
    tag = "admin",
    operation_id = "delete_approval_process",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Deleted; pending requests keep their plan and lock until decided"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_process(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "approval_process",
            Some(id),
        )
        .named("approval_process.delete"),
    )
    .await?;
    let rows = sqlx::query(
        "UPDATE approval_process SET is_deleted = true, is_active = false, \
                row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitBody {
    pub record_id: Uuid,
    /// M9-T4: why the record is submitted, shown to the approvers (at most
    /// 2000 characters).
    #[serde(default)]
    pub reason: Option<String>,
}

/// The longest submission reason, in characters.
const REASON_MAX: usize = 2000;

/// What a submission filed.
#[derive(Debug, Serialize, ToSchema)]
pub struct Submitted {
    pub request_id: Uuid,
    pub status: String,
    /// The request's row version, for a recall.
    pub row_version: i64,
    pub locked: bool,
}

/// Whether the record's fields meet the entry condition (none: every record).
pub fn admits(entry_condition: Option<&str>, record: &Value) -> bool {
    match entry_condition.filter(|c| !c.trim().is_empty()) {
        Some(condition) => attome_workflow::condition::expression_holds(condition, record),
        None => true,
    }
}

/// Submit a record for approval
///
/// Submit a record for approval. Any signed-in user. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/approval-processes/{id}/submit",
    tag = "approvals",
    operation_id = "submit_to_approval_process",
    description = "Submits a record to an approval process (M9-T1): the caller must be able to update the record, the record must meet the process's entry condition, and it may have no other pending request of this process. A locking process holds the record until the request is decided or recalled.",
    params(("id" = Uuid, Path)),
    request_body = SubmitBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Submitted)])))),
    responses(
        (status = 201, description = "Submitted", body = Submitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not update the record", body = ErrorResponse),
        (status = 404, description = "No active process, or no such record", body = ErrorResponse),
        (status = 409, description = "The record already has a pending request of this process", body = ErrorResponse),
        (status = 422, description = "The record does not meet the entry condition", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn submit(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<SubmitBody>,
) -> Result<(StatusCode, Json<Submitted>), AppError> {
    let process = load(&state, id).await?;
    if !process.is_active {
        return Err(AppError::NotFound);
    }
    if process.starts_on != "submit" {
        return Err(AppError::Validation(
            "this process starts on change: it holds changes to its watched attributes, and \
             records are not submitted to it"
                .into(),
        ));
    }
    let entity_id = state
        .entities
        .load()
        .get(&process.entity_logicalname)
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity_id,
        &process.entity_logicalname,
        body.record_id,
        RecordAction::Update,
    )
    .await?;
    let record = attome_records::entity_crud::read_record(
        &state,
        &ctx,
        &process.entity_logicalname,
        body.record_id,
    )
    .await?;
    let data = serde_json::to_value(record)
        .map_err(AppError::internal)?
        .get("data")
        .cloned()
        .unwrap_or(Value::Null);
    if !admits(process.entry_condition.as_deref(), &data) {
        return Err(AppError::Validation(
            "the record does not meet this approval process's entry condition".into(),
        ));
    }
    let plan: ApprovalPlan = serde_json::from_value(process.plan.clone())
        .map_err(|e| AppError::internal(format!("stored approval process plan: {e}")))?;
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    if reason.is_some_and(|r| r.chars().count() > REASON_MAX) {
        return Err(AppError::Validation(format!(
            "reason is at most {REASON_MAX} characters"
        )));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-api/approval-process-submit:{id}:{}",
            body.record_id
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this record is being submitted to this process already",
        ));
    }
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM approval_request \
                         WHERE regarding_entity = $1 AND regarding_id = $2 AND status = 'pending' \
                           AND action_type = $3 AND payload ->> 'process_id' = $4)",
    )
    .bind(&process.entity_logicalname)
    .bind(body.record_id)
    .bind(APPROVAL_PROCESS_ACTION)
    .bind(id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if pending {
        return Err(AppError::Conflict(
            "the record already waits for this approval process",
        ));
    }
    let payload = serde_json::json!({
        "process_id": id,
        "process_name": process.name,
        "entity": process.entity_logicalname,
        "record_id": body.record_id,
        "reason": reason,
    });
    let backstop_ttl = attome_audit::approval::plan_backstop_ttl(&plan);
    let request = attome_approval::submit_with_plan_regarding_in_tx(
        &mut tx,
        APPROVAL_PROCESS_ACTION,
        payload,
        ctx.user_id,
        plan,
        backstop_ttl,
        None,
        Some((process.entity_logicalname.as_str(), body.record_id)),
    )
    .await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Submitted,
            ctx.user_id,
            "approval_request",
            Some(request.id),
        )
        .named("approval_process.submit")
        .comment(format!(
            "{} {} submitted to approval process {}",
            process.entity_logicalname, body.record_id, process.name
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(Submitted {
            request_id: request.id,
            status: request.status.as_str().to_owned(),
            row_version: request.row_version,
            locked: process.lock_record,
        }),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecallBody {
    pub row_version: i64,
}

/// The recall's audit event, in the recall's own transaction.
struct RecallAudit<'a> {
    state: &'a EngineState,
    actor: Uuid,
}

impl attome_db::BeforeCommit<attome_approval::ApprovalRequest> for RecallAudit<'_> {
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut attome_db::Tx<'_>,
        request: &'a attome_approval::ApprovalRequest,
    ) -> attome_db::hook::HookFuture<'a> {
        Box::pin(async move {
            attome_audit::security::write_security_event(
                tx,
                &attome_audit::audit_service(self.state),
                SecurityEvent::new(
                    MandatoryCategory::Security,
                    AuditOperation::Cancelled,
                    self.actor,
                    "approval_request",
                    Some(request.id),
                )
                .named("approval_process.recall"),
            )
            .await
            .map(|_| ())
        })
    }
}

/// Recall an approval request
///
/// Recall an approval request. Any signed-in user. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/approval-processes/requests/{request_id}/recall",
    tag = "approvals",
    operation_id = "recall_approval_process_request",
    description = "The requester takes a pending approval-process request back (M9-T1); the record's lock ends with it.",
    params(("request_id" = Uuid, Path)),
    request_body = RecallBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Cancelled)])))),
    responses(
        (status = 200, description = "Recalled", body = Submitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Only the requester recalls", body = ErrorResponse),
        (status = 404, description = "No such approval-process request", body = ErrorResponse),
        (status = 409, description = "Already decided, or changed since read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn recall(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(request_id): Path<Uuid>,
    Json(body): Json<RecallBody>,
) -> Result<Json<Submitted>, AppError> {
    let current = attome_approval::get(&state.base.db, request_id).await?;
    if current.action_type != APPROVAL_PROCESS_ACTION {
        return Err(AppError::NotFound);
    }
    let hook = RecallAudit {
        state: &state,
        actor: ctx.user_id,
    };
    let recalled = attome_approval::recall_with(
        &state.base.db,
        request_id,
        ctx.user_id,
        body.row_version,
        &hook,
    )
    .await?;
    Ok(Json(Submitted {
        request_id: recalled.id,
        status: recalled.status.as_str().to_owned(),
        row_version: recalled.row_version,
        locked: false,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/approval-processes",
            get(list_processes).post(create_process),
        )
        .route(
            "/api/v1/admin/approval-processes/{id}",
            get(get_process)
                .patch(update_process)
                .delete(delete_process),
        )
        .route("/api/v1/approval-processes/{id}/submit", post(submit))
        .route(
            "/api/v1/approval-processes/requests/{request_id}/recall",
            post(recall),
        )
        .route("/api/v1/approvals/{id}", get(get_request))
        .route(
            "/api/v1/approvals/regarding/{entity}/{record_id}",
            get(list_regarding),
        )
}

/// M9-T4: one attribute a request would change.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangedAttribute {
    pub attribute: String,
    /// The value when the request was opened.
    pub from: Value,
    /// The value approval writes.
    pub to: Value,
}

/// M9-T4: one decision on a request.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct DecisionEntry {
    pub approver_id: Uuid,
    pub approver_name: Option<String>,
    /// Who acted, when a delegate decided for `approver_id`.
    pub decided_by: Option<Uuid>,
    pub step: i32,
    /// `approved` or `rejected`.
    pub decision: String,
    pub comment: Option<String>,
    pub decided_at: DateTime<Utc>,
}

/// M9-T4: what the request page shows.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApprovalDetail {
    pub id: Uuid,
    pub action_type: String,
    /// The approval process's name, when the request came from one.
    pub title: Option<String>,
    pub status: String,
    /// The current step (zero-based) of `step_count`.
    pub step: i32,
    pub step_count: i32,
    pub requested_by: Uuid,
    pub requested_by_name: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    pub row_version: i64,
    /// Why it was asked, in the requester's words.
    pub reason: Option<String>,
    pub regarding_entity: Option<String>,
    pub regarding_id: Option<Uuid>,
    /// The attribute changes a held change carries, by name.
    pub changes: Vec<ChangedAttribute>,
    #[schema(value_type = Object)]
    pub payload: Value,
    /// Whether the caller may approve or reject it now.
    pub can_decide: bool,
    pub decisions: Vec<DecisionEntry>,
}

/// M9-T4: one request in a record's approval history.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApprovalHistoryItem {
    pub id: Uuid,
    pub action_type: String,
    pub title: Option<String>,
    pub status: String,
    pub requested_by: Uuid,
    pub requested_by_name: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    /// The attributes a held change carries, by name.
    pub changed_attributes: Vec<String>,
}

/// The attribute changes of a held change's payload, by name.
pub(crate) fn changes_of(payload: &Value) -> Vec<ChangedAttribute> {
    let Some(changes) = payload.get("changes").and_then(Value::as_object) else {
        return Vec::new();
    };
    let previous = payload.get("previous").and_then(Value::as_object);
    let mut out: Vec<ChangedAttribute> = changes
        .iter()
        .map(|(attribute, to)| ChangedAttribute {
            attribute: attribute.clone(),
            from: previous
                .and_then(|p| p.get(attribute))
                .cloned()
                .unwrap_or(Value::Null),
            to: to.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.attribute.cmp(&b.attribute));
    out
}

fn text_of(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Display names of `ids`.
async fn user_names(
    state: &EngineState,
    ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, String>, AppError> {
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, user_name FROM user_account WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// Whether the caller may read the record `entity`/`record_id`.
async fn may_read_record(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    entity: &str,
    record_id: Uuid,
) -> bool {
    let Ok((entity_id, ..)) = attome_records::entity_crud::resolve_entity(state, entity).await
    else {
        return false;
    };
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity_id,
        entity,
        record_id,
        RecordAction::Read,
    )
    .await
    .is_ok()
}

/// One of my approval requests
///
/// One of my approval requests. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/approvals/{id}",
    tag = "approvals",
    operation_id = "get_approval_request_detail",
    description = "The approval request page (M9-T4): what is asked, by whom, why, the attribute changes it carries, every decision so far, and whether the caller may decide now. Visible to an administrator, the requester, anyone who decided it, an eligible approver, and anyone who may read the record it is about.",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The request", body = ApprovalDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such request, or the caller may not see it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_request(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalDetail>, AppError> {
    let request = attome_approval::get(&state.base.db, id).await?;
    let decisions: Vec<DecisionEntry> = sqlx::query_as(
        "SELECT g.approver_id, u.user_name AS approver_name, g.decided_by, g.step, \
                g.decision, g.comment, g.decided_at \
           FROM approval_grant g \
           LEFT JOIN user_account u ON u.id = g.approver_id \
          WHERE g.request_id = $1 \
          ORDER BY g.decided_at, g.id",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let can_decide = request.status == attome_approval::ApprovalStatus::Pending
        && crate::my_work_approvals::is_eligible(&state, &ctx, &request).await?;
    let decided = decisions
        .iter()
        .any(|d| d.approver_id == ctx.user_id || d.decided_by == Some(ctx.user_id));
    let visible = ctx.is_admin
        || request.requested_by == ctx.user_id
        || decided
        || can_decide
        || match (&request.regarding_entity, request.regarding_id) {
            (Some(entity), Some(record_id)) => {
                may_read_record(&state, &ctx, entity, record_id).await
            }
            _ => false,
        };
    if !visible {
        return Err(AppError::NotFound);
    }
    let names = user_names(&state, &[request.requested_by]).await?;
    let step_count = request
        .plan
        .as_ref()
        .map_or(1, |p| i32::try_from(p.steps.len()).unwrap_or(i32::MAX));
    Ok(Json(ApprovalDetail {
        id: request.id,
        title: text_of(&request.payload, "process_name"),
        reason: text_of(&request.payload, "reason"),
        changes: changes_of(&request.payload),
        action_type: request.action_type,
        status: request.status.to_string(),
        step: request.step,
        step_count,
        requested_by: request.requested_by,
        requested_by_name: names.get(&request.requested_by).cloned(),
        requested_at: request.requested_at,
        expires_at: request.expires_at,
        executed_at: request.executed_at,
        row_version: request.row_version,
        regarding_entity: request.regarding_entity,
        regarding_id: request.regarding_id,
        payload: request.payload,
        can_decide,
        decisions,
    }))
}

/// Approvals regarding a record
///
/// Approvals regarding a record. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/approvals/regarding/{entity}/{record_id}",
    tag = "approvals",
    operation_id = "list_approvals_regarding_record",
    description = "A record's approval history (M9-T4), newest first, for whoever may read the record.",
    params(("entity" = String, Path), ("record_id" = Uuid, Path), OnePageQuery),
    responses(
        (status = 200, description = "The record's approval requests", body = PaginatedResponse<ApprovalHistoryItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller may not read it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_regarding(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, record_id)): Path<(String, Uuid)>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ApprovalHistoryItem>>, AppError> {
    if !may_read_record(&state, &ctx, &entity, record_id).await {
        return Err(AppError::NotFound);
    }
    let w = page.window();
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        action_type: String,
        status: String,
        requested_by: Uuid,
        requested_at: DateTime<Utc>,
        executed_at: Option<DateTime<Utc>>,
        payload: Value,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, action_type, status, requested_by, requested_at, executed_at, payload \
           FROM approval_request \
          WHERE regarding_entity = $1 AND regarding_id = $2 \
          ORDER BY requested_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request WHERE regarding_entity = $1 AND regarding_id = $2",
    )
    .bind(&entity)
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut requesters: Vec<Uuid> = rows.iter().map(|r| r.requested_by).collect();
    requesters.sort_unstable();
    requesters.dedup();
    let names = user_names(&state, &requesters).await?;
    let items = rows
        .into_iter()
        .map(|r| ApprovalHistoryItem {
            title: text_of(&r.payload, "process_name"),
            changed_attributes: changes_of(&r.payload)
                .into_iter()
                .map(|c| c.attribute)
                .collect(),
            requested_by_name: names.get(&r.requested_by).cloned(),
            id: r.id,
            action_type: r.action_type,
            status: r.status,
            requested_by: r.requested_by,
            requested_at: r.requested_at,
            executed_at: r.executed_at,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_processes,
    create_process,
    get_process,
    update_process,
    delete_process,
    submit,
    recall,
    get_request,
    list_regarding
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_request_page_lists_changes_by_name_with_their_old_values() {
        let payload = serde_json::json!({
            "changes": { "discount": 25, "amount": 900 },
            "previous": { "discount": "15" },
        });
        let changes = changes_of(&payload);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].attribute, "amount");
        assert_eq!(changes[0].from, Value::Null);
        assert_eq!(changes[1].attribute, "discount");
        assert_eq!(changes[1].from, serde_json::json!("15"));
        assert_eq!(changes[1].to, serde_json::json!(25));
        assert!(changes_of(&serde_json::json!({ "process_id": "x" })).is_empty());
    }

    #[test]
    fn approval_process_entry_condition_admits_matching_records() {
        let record = serde_json::json!({ "amount": 25000, "stage": "draft" });
        assert!(admits(None, &record));
        assert!(admits(Some("  "), &record));
        assert!(admits(Some("amount > 10000"), &record));
        assert!(!admits(Some("amount > 50000"), &record));
        assert!(
            !admits(Some("missing_field == 1"), &record),
            "an unknown field never admits"
        );
    }
}
