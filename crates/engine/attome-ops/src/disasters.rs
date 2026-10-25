//! AB3-T7: a declared disaster, under two-person control.
//!
//! - `POST /api/v1/ops/disasters` declares one (`ops.dr.declare`): the
//!   scenario and a summary (`ops_disaster`, migration 0264).
//! - `POST /api/v1/ops/disasters/{id}/actions` asks to switch to the
//!   recovery site, replace live data or fail back. Nothing happens on one
//!   person's word: the request is an approval whose only step names the
//!   Operations role, and the approval engine never lets the requester
//!   decide their own request, so a second `ops.dr.declare` holder must.
//! - `GET /api/v1/ops/disasters/approvals/{approval_id}` answers that
//!   approval's status, for `drill recover --approval-id` to wait on.
//! - `POST /api/v1/ops/disasters/{id}/close` closes it (`If-Match`).
//! - `GET /api/v1/ops/disasters` and `GET /api/v1/ops/disasters/{id}/actions`
//!   (`ops.read`, AB3-T10) list the disasters, open ones first, and the
//!   actions asked for on one with their approval status.
//!
//! Every write commits with its Configuration event. AB11's incident
//! service is not built, so declaring opens no incident yet.

use attome_approval::{ApprovalPlan, ApprovalStep, OnTimeout, StepMode};
use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The approval action a disaster action waits on.
pub const ACTION_DISASTER: &str = "ops.disaster_action";

/// The role whose members (but never the requester) approve.
const APPROVER_ROLE: &str = "Operations";

/// The actions a declared disaster can ask for.
pub const ACTIONS: [&str; 3] = ["switch_site", "replace_live_data", "failback"];

/// `ops.dr.declare`: who declares disasters and asks for their actions.
#[derive(Debug)]
pub struct OpsDrDeclare;

impl PrivilegeKey for OpsDrDeclare {
    const KEY: &'static str = "ops.dr.declare";
}

const COLUMNS: &str = "id, declared_by, declared_at, scenario, summary, closed_at, sla_excluded, \
     exclusion_evidence, row_version";

/// A declared disaster.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Disaster {
    pub id: Uuid,
    pub declared_by: Uuid,
    pub declared_at: DateTime<Utc>,
    pub scenario: String,
    pub summary: String,
    pub closed_at: Option<DateTime<Utc>>,
    pub sla_excluded: bool,
    pub exclusion_evidence: Option<String>,
    pub row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclareDisaster {
    /// What happened, such as `site_loss` or `data_corruption`.
    pub scenario: String,
    pub summary: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DisasterActionBody {
    /// `switch_site`, `replace_live_data` or `failback`.
    pub action: String,
    #[serde(default)]
    pub detail: Option<String>,
}

/// The approval a disaster action waits on.
#[derive(Debug, Serialize, ToSchema)]
pub struct DisasterApproval {
    pub approval_id: Uuid,
    /// `pending`, `approved`, `rejected`, `expired`, ...
    pub status: String,
    pub action: Option<String>,
    pub disaster_id: Option<Uuid>,
}

/// Checks a declaration's text. Pure.
pub fn check_declaration(body: &DeclareDisaster) -> Result<(), AppError> {
    let scenario = body.scenario.trim();
    if scenario.is_empty() || scenario.len() > 100 {
        return Err(AppError::Validation(
            "scenario is 1 to 100 characters".into(),
        ));
    }
    let summary = body.summary.trim();
    if summary.is_empty() || summary.chars().count() > 4000 {
        return Err(AppError::Validation(
            "summary is 1 to 4000 characters".into(),
        ));
    }
    Ok(())
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    raw.parse::<i64>().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {raw}"
        ))
    })
}

fn event(
    operation: AuditOperation,
    actor: Uuid,
    id: Uuid,
    name: &str,
    comment: String,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "ops_disaster",
        Some(id),
    )
    .named(name.to_owned())
    .comment(comment)
}

/// Declare a disaster
///
/// AB3-T7: records the declaration. Needs `ops.dr.declare`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/disasters",
    tag = "ops",
    operation_id = "declare_ops_disaster",
    request_body = DeclareDisaster,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The declared disaster", body = Disaster),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.dr.declare", body = ErrorResponse),
        (status = 422, description = "An empty or too long scenario or summary", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn declare(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsDrDeclare>>,
    Json(body): Json<DeclareDisaster>,
) -> Result<(StatusCode, Json<Disaster>), AppError> {
    check_declaration(&body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let disaster: Disaster = sqlx::query_as(&format!(
        "INSERT INTO ops_disaster (id, declared_by, declared_at, scenario, summary) \
         VALUES (uuidv7(), $1, now(), $2, $3) RETURNING {COLUMNS}"
    ))
    .bind(ctx.user_id)
    .bind(body.scenario.trim())
    .bind(body.summary.trim())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            disaster.id,
            "ops.disaster_declared",
            format!("disaster declared: {}", disaster.scenario),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::warn!(disaster = %disaster.id, scenario = %disaster.scenario, "disaster declared");
    Ok((StatusCode::CREATED, Json(disaster)))
}

/// Ask for a disaster action
///
/// AB3-T7: switching to the recovery site, replacing live data or failing
/// back waits for a second `ops.dr.declare` holder: the answer is the
/// approval request, which the requester can never decide. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/disasters/{id}/actions",
    tag = "ops",
    operation_id = "request_ops_disaster_action",
    params(("id" = Uuid, Path, description = "The declared disaster")),
    request_body = DisasterActionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Submitted)])))),
    responses(
        (status = 202, description = "The approval the action waits on", body = DisasterApproval),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.dr.declare", body = ErrorResponse),
        (status = 404, description = "No such disaster", body = ErrorResponse),
        (status = 409, description = "The disaster is closed", body = ErrorResponse),
        (status = 422, description = "An unknown action, or no Operations role to approve it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn request_action(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsDrDeclare>>,
    Path(id): Path<Uuid>,
    Json(body): Json<DisasterActionBody>,
) -> Result<(StatusCode, Json<DisasterApproval>), AppError> {
    if !ACTIONS.contains(&body.action.as_str()) {
        return Err(AppError::Validation(format!(
            "action is one of {}",
            ACTIONS.join(", ")
        )));
    }
    let closed: Option<Option<DateTime<Utc>>> =
        sqlx::query_scalar("SELECT closed_at FROM ops_disaster WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if closed.ok_or(AppError::NotFound)?.is_some() {
        return Err(AppError::Conflict("this disaster is closed"));
    }
    let role: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(APPROVER_ROLE)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let role = role.ok_or_else(|| {
        AppError::Validation("no Operations role exists to approve a disaster action".into())
    })?;
    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec![format!("role:{role}")],
            sla_minutes: None,
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    };
    let detail = body.detail.as_deref().map(str::trim).unwrap_or_default();
    let request = attome_audit::approval::gate_with_plan_regarding(
        &state,
        ACTION_DISASTER,
        json!({ "disaster_id": id, "action": body.action, "detail": detail }),
        ctx.user_id,
        plan,
        None,
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(DisasterApproval {
            approval_id: request.id,
            status: request.status.to_string(),
            action: Some(body.action),
            disaster_id: Some(id),
        }),
    ))
}

/// A disaster action's approval
///
/// AB3-T7: whether the second person approved yet. Needs `ops.dr.declare`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/disasters/approvals/{approval_id}",
    tag = "ops",
    operation_id = "get_ops_disaster_approval",
    params(("approval_id" = Uuid, Path, description = "The approval request")),
    responses(
        (status = 200, description = "The approval's status", body = DisasterApproval),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.dr.declare", body = ErrorResponse),
        (status = 404, description = "No such disaster approval", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn approval_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsDrDeclare>>,
    Path(approval_id): Path<Uuid>,
) -> Result<Json<DisasterApproval>, AppError> {
    let request = attome_approval::get(&state.base.db, approval_id).await?;
    if request.action_type != ACTION_DISASTER {
        return Err(AppError::NotFound);
    }
    Ok(Json(DisasterApproval {
        approval_id,
        status: request.status.to_string(),
        action: request.payload["action"].as_str().map(str::to_owned),
        disaster_id: request.payload["disaster_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok()),
    }))
}

/// Close a disaster
///
/// AB3-T7: `If-Match` names the row version. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/disasters/{id}/close",
    tag = "ops",
    operation_id = "close_ops_disaster",
    params(
        ("id" = Uuid, Path, description = "The declared disaster"),
        ("If-Match" = String, Header, description = "The disaster's row_version, quoted"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Closed)])))),
    responses(
        (status = 200, description = "The closed disaster", body = Disaster),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.dr.declare", body = ErrorResponse),
        (status = 404, description = "No such disaster", body = ErrorResponse),
        (status = 409, description = "Already closed, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match is missing or not a row_version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn close(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsDrDeclare>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Disaster>, AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(Option<DateTime<Utc>>, i64)> =
        sqlx::query_as("SELECT closed_at, row_version FROM ops_disaster WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let (closed_at, version) = current.ok_or(AppError::NotFound)?;
    if closed_at.is_some() {
        return Err(AppError::Conflict("this disaster is already closed"));
    }
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    let disaster: Disaster = sqlx::query_as(&format!(
        "UPDATE ops_disaster SET closed_at = now(), row_version = row_version + 1 \
          WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Closed,
            ctx.user_id,
            id,
            "ops.disaster_closed",
            format!("disaster closed: {}", disaster.scenario),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(disaster))
}

/// List disasters
///
/// AB3-T10: every declared disaster, open ones first, newest first. Needs
/// `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/disasters",
    tag = "ops",
    operation_id = "list_ops_disasters",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of disasters", body = PaginatedResponse<Disaster>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_disasters(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<crate::upgrades::OpsRead>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<Disaster>>, AppError> {
    let w = page.window();
    let items: Vec<Disaster> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_disaster \
          ORDER BY closed_at IS NOT NULL, declared_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ops_disaster")
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

/// The most actions one disaster's list answers.
const MAX_ACTIONS: i64 = 100;

/// A disaster's actions
///
/// AB3-T10: the actions asked for on one disaster (newest first, at most
/// 100), each with its approval's status. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/disasters/{id}/actions",
    tag = "ops",
    operation_id = "list_ops_disaster_actions",
    params(("id" = Uuid, Path, description = "The declared disaster")),
    responses(
        (status = 200, description = "The actions", body = PaginatedResponse<DisasterApproval>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_actions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<crate::upgrades::OpsRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<DisasterApproval>>, AppError> {
    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, status::text, payload->>'action' FROM approval_request \
          WHERE action_type = $1 AND payload->>'disaster_id' = $2 \
          ORDER BY requested_at DESC, id DESC LIMIT $3",
    )
    .bind(ACTION_DISASTER)
    .bind(id.to_string())
    .bind(MAX_ACTIONS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<DisasterApproval> = rows
        .into_iter()
        .map(|(approval_id, status, action)| DisasterApproval {
            approval_id,
            status,
            action,
            disaster_id: Some(id),
        })
        .collect();
    let n = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, n, 1, MAX_ACTIONS)))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/disasters", get(list_disasters).post(declare))
        .route(
            "/api/v1/ops/disasters/{id}/actions",
            get(list_actions).post(request_action),
        )
        .route(
            "/api/v1/ops/disasters/approvals/{approval_id}",
            get(approval_status),
        )
        .route("/api/v1/ops/disasters/{id}/close", post(close))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        declare,
        request_action,
        approval_status,
        close,
        list_disasters,
        list_actions
    ),
    components(schemas(Disaster, DeclareDisaster, DisasterActionBody, DisasterApproval))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_needs_a_scenario_and_summary() {
        let body = |scenario: &str, summary: &str| DeclareDisaster {
            scenario: scenario.into(),
            summary: summary.into(),
        };
        assert!(check_declaration(&body("site_loss", "Riyadh site down")).is_ok());
        assert!(check_declaration(&body(" ", "x")).is_err());
        assert!(check_declaration(&body("x", "")).is_err());
    }

    #[test]
    fn close_requires_if_match() {
        assert!(if_match(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::IF_MATCH, "\"1\"".parse().unwrap());
        assert_eq!(if_match(&headers).unwrap(), 1);
        assert!(ACTIONS.contains(&"switch_site"));
    }
}
