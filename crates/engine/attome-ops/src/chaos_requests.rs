//! AB9-T7: production game days. A chaos run against a production
//! deployment is refused by `attome drill chaos run` unless three things
//! hold: `ops.chaos.production_game_days` is on, a second person approved
//! the run, and it stays within `ops.chaos.max_duration_secs`.
//!
//! - `POST /api/v1/ops/chaos/requests` (`ops.chaos.run`) asks for one run:
//!   the fault, how long, and why. Refused with 422 while game days are
//!   off or past the time limit. The answer is an approval whose only step
//!   names the Operations role; the approval engine never lets the
//!   requester decide their own request, so a second `ops.chaos.run`
//!   holder (Operations has it) must approve.
//! - `GET /api/v1/ops/chaos/requests/{id}` answers that request: its status,
//!   fault and duration, for the CLI to check before it injects anything.

use attome_approval::{ApprovalPlan, ApprovalStep, OnTimeout, StepMode};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The approval action a production chaos run waits on.
pub const ACTION_CHAOS: &str = "ops.chaos_run";

/// The role whose members (but never the requester) approve.
const APPROVER_ROLE: &str = "Operations";

/// `ops.chaos.run`: who asks for fault injection.
#[derive(Debug)]
pub struct OpsChaosRun;

impl PrivilegeKey for OpsChaosRun {
    const KEY: &'static str = "ops.chaos.run";
}

/// A production chaos run asked for.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChaosRequestBody {
    /// A fault of the chaos catalogue (`process-kill`, `redis-down`, ...).
    pub fault: String,
    /// How long the fault lasts, in seconds.
    pub duration_secs: u32,
    /// Why, for the approver.
    pub reason: String,
}

/// A production chaos run's approval.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChaosRequest {
    pub approval_id: Uuid,
    /// `pending`, `approved`, `rejected`, ...
    pub status: String,
    pub fault: String,
    pub duration_secs: u32,
    pub reason: String,
}

/// Whether a request may be made, given the settings: why not, if not.
/// Pure.
pub fn refusal(settings: &attome_config::ChaosSettings, body: &ChaosRequestBody) -> Option<String> {
    if !settings.production_game_days {
        return Some(
            "production game days are off (ops.chaos.production_game_days); chaos runs on a test rig"
                .into(),
        );
    }
    if body.duration_secs == 0 || body.duration_secs > settings.max_duration_secs {
        return Some(format!(
            "duration_secs is 1 to {} (ops.chaos.max_duration_secs)",
            settings.max_duration_secs
        ));
    }
    let fault_ok = !body.fault.is_empty()
        && body.fault.len() <= 64
        && body
            .fault
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !fault_ok {
        return Some("fault names a chaos catalogue fault".into());
    }
    if body.reason.trim().is_empty() || body.reason.len() > 2_000 {
        return Some("reason says why, in at most 2,000 characters".into());
    }
    None
}

/// Ask for a production chaos run
///
/// AB9-T7: refused while production game days are off. The answer is the
/// approval a second `ops.chaos.run` holder must give; the requester can
/// never decide it. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/chaos/requests",
    tag = "ops",
    operation_id = "request_ops_chaos_run",
    request_body = ChaosRequestBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Submitted)])))),
    responses(
        (status = 202, description = "The approval the run waits on", body = ChaosRequest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.chaos.run", body = ErrorResponse),
        (status = 422, description = "Game days are off, the duration is past the limit, or no Operations role exists", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn request_run(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsChaosRun>>,
    Json(body): Json<ChaosRequestBody>,
) -> Result<(StatusCode, Json<ChaosRequest>), AppError> {
    if let Some(reason) = refusal(&state.base.config.ops.chaos, &body) {
        return Err(AppError::Validation(reason));
    }
    let role: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(APPROVER_ROLE)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let role = role.ok_or_else(|| {
        AppError::Validation("no Operations role exists to approve a chaos run".into())
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
    let reason = body.reason.trim().to_owned();
    let request = attome_audit::approval::gate_with_plan_regarding(
        &state,
        ACTION_CHAOS,
        json!({
            "fault": body.fault,
            "duration_secs": body.duration_secs,
            "reason": reason,
        }),
        ctx.user_id,
        plan,
        None,
    )
    .await?;
    tracing::warn!(approval = %request.id, fault = %body.fault, duration = body.duration_secs,
        "production chaos run requested");
    Ok((
        StatusCode::ACCEPTED,
        Json(ChaosRequest {
            approval_id: request.id,
            status: request.status.to_string(),
            fault: body.fault,
            duration_secs: body.duration_secs,
            reason,
        }),
    ))
}

/// A production chaos run's request
///
/// AB9-T7: whether the second person approved it, with the fault and
/// duration approved. Needs `ops.chaos.run`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/chaos/requests/{id}",
    tag = "ops",
    operation_id = "get_ops_chaos_request",
    params(("id" = Uuid, Path, description = "The approval request")),
    responses(
        (status = 200, description = "The request", body = ChaosRequest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.chaos.run", body = ErrorResponse),
        (status = 404, description = "No such chaos request", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_request(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsChaosRun>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ChaosRequest>, AppError> {
    Ok(Json(read(&state.base.db, id).await?))
}

/// The chaos request `id`, or 404 for any other approval.
pub async fn read(db: &attome_db::DbPool, id: Uuid) -> Result<ChaosRequest, AppError> {
    let request = attome_approval::get(db, id).await?;
    if request.action_type != ACTION_CHAOS {
        return Err(AppError::NotFound);
    }
    Ok(view(id, &request))
}

/// For `attome drill chaos run --production --approval-id`: checks the
/// approved request against the run ([`run_refusal`]) and claims its
/// execution, so one approval allows one run. Why not, if not.
pub async fn claim_for_run(
    db: &attome_db::DbPool,
    settings: &attome_config::ChaosSettings,
    id: Uuid,
    fault: &str,
    duration_secs: u64,
) -> Result<(), String> {
    let request = attome_approval::get(db, id)
        .await
        .map_err(|e| format!("the chaos request {id} could not be read: {e}"))?;
    if request.action_type != ACTION_CHAOS {
        return Err(format!("{id} is not a chaos request"));
    }
    if let Some(reason) = run_refusal(settings, &view(id, &request), fault, duration_secs) {
        return Err(reason);
    }
    attome_approval::claim_execution(
        db,
        id,
        request.row_version,
        attome_approval::POLICY_ACTOR_ID,
    )
    .await
    .map_err(|e| format!("the chaos request {id} could not be claimed (already run?): {e}"))?;
    Ok(())
}

/// A chaos approval as the routes show it. Pure.
fn view(id: Uuid, request: &attome_approval::ApprovalRequest) -> ChaosRequest {
    ChaosRequest {
        approval_id: id,
        status: request.status.to_string(),
        fault: request.payload["fault"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        duration_secs: request.payload["duration_secs"]
            .as_u64()
            .and_then(|d| u32::try_from(d).ok())
            .unwrap_or(0),
        reason: request.payload["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    }
}

/// Why the CLI may not run `fault` for `duration_secs` on a production
/// deployment under `request`, if it may not. Pure.
pub fn run_refusal(
    settings: &attome_config::ChaosSettings,
    request: &ChaosRequest,
    fault: &str,
    duration_secs: u64,
) -> Option<String> {
    if !settings.production_game_days {
        return Some("production game days are off (ops.chaos.production_game_days)".into());
    }
    if request.status != "approved" {
        return Some(format!(
            "the chaos request is {}, not approved",
            request.status
        ));
    }
    if request.fault != fault {
        return Some(format!(
            "the approved fault is {}, not {fault}",
            request.fault
        ));
    }
    if duration_secs > u64::from(request.duration_secs)
        || duration_secs > u64::from(settings.max_duration_secs)
    {
        return Some(format!(
            "the run may last at most {} s (approved {} s, limit {} s)",
            request.duration_secs.min(settings.max_duration_secs),
            request.duration_secs,
            settings.max_duration_secs
        ));
    }
    None
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/chaos/requests", post(request_run))
        .route("/api/v1/ops/chaos/requests/{id}", get(get_request))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(request_run, get_request),
    components(schemas(ChaosRequestBody, ChaosRequest))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_config::ChaosSettings;

    fn body(duration_secs: u32) -> ChaosRequestBody {
        ChaosRequestBody {
            fault: "redis-down".into(),
            duration_secs,
            reason: "quarterly game day".into(),
        }
    }

    #[test]
    fn request_refused_when_game_days_off() {
        let off = ChaosSettings::default();
        assert!(
            refusal(&off, &body(60))
                .unwrap()
                .contains("game days are off")
        );
        let on = ChaosSettings {
            production_game_days: true,
            max_duration_secs: 300,
        };
        assert_eq!(refusal(&on, &body(60)), None);
        assert!(refusal(&on, &body(301)).is_some());
        assert!(refusal(&on, &body(0)).is_some());
        let mut bad = body(60);
        bad.fault = "rm -rf".into();
        assert!(refusal(&on, &bad).is_some());
    }

    #[test]
    fn run_needs_the_approved_request() {
        let on = ChaosSettings {
            production_game_days: true,
            max_duration_secs: 300,
        };
        let mut request = ChaosRequest {
            approval_id: Uuid::nil(),
            status: "pending".into(),
            fault: "redis-down".into(),
            duration_secs: 120,
            reason: "game day".into(),
        };
        assert!(
            run_refusal(&on, &request, "redis-down", 60)
                .unwrap()
                .contains("not approved")
        );
        request.status = "approved".into();
        assert_eq!(run_refusal(&on, &request, "redis-down", 60), None);
        assert!(run_refusal(&on, &request, "process-kill", 60).is_some());
        assert!(run_refusal(&on, &request, "redis-down", 121).is_some());
        assert!(run_refusal(&ChaosSettings::default(), &request, "redis-down", 60).is_some());
    }
}
