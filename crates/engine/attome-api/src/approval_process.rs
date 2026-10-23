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
    pub is_active: bool,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, name, entity_logicalname, entry_condition, plan, lock_record, \
                       editable_attributes, is_active, row_version, created_at, updated_at";

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
    #[serde(default = "default_true")]
    pub is_active: bool,
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
    Ok(())
}

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
              editable_attributes, is_active, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING {COLUMNS}"
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
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

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
}

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
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_processes,
    create_process,
    get_process,
    update_process,
    delete_process,
    submit,
    recall
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

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
