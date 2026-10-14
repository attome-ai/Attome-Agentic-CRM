//! The eval suite runner (roadmap N23-T1): runs every case of a suite
//! against its agent and grades the runs.
//!
//! `POST /api/v1/admin/ai/eval-suites/{suite}/runs` records a run
//! (`ai_eval_run`, migration 0017) and returns at once; the cases run in the
//! background, one after another, each as one turn of a fresh session
//! started from the suite's agent object (`agent::start_session_from_object`)
//! at the `reversible` ceiling, so a write is only ever proposed, a
//! consequential action is refused rather than sent for approval, and every
//! limit and policy that binds the agent in production binds it here. The
//! tools a turn called and its answer are graded by the suite's own graders
//! (`attome_model::kinds::eval_suite::grade_suite`). `GET
//! /api/v1/admin/ai/eval-runs/{id}` reads the result.
//!
//! Every case spends model tokens under the starting administrator's budget.
//! A run is bounded to [`MAX_RUN_CASES`] cases and [`CASE_STEP_BUDGET`] steps
//! a case.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The most cases one run executes.
pub const MAX_RUN_CASES: usize = 50;
/// The most tool steps one case's turn may take.
pub const CASE_STEP_BUDGET: usize = 10;

#[derive(Debug, Serialize, ToSchema)]
pub struct EvalRunStarted {
    pub run_id: Uuid,
    pub cases: usize,
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct EvalRun {
    pub id: Uuid,
    pub suite_ref: Uuid,
    pub suite_hash: String,
    pub agent_ref: Uuid,
    /// `running`, `passed`, `failed` or `error`.
    pub status: String,
    pub score: Option<f64>,
    /// The graded cases (`SuiteOutcome`).
    #[schema(value_type = Option<Object>)]
    pub outcome: Option<Value>,
    pub error: Option<String>,
    pub started_by: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The agent a suite tests, and its cases (bounded).
pub fn suite_plan(doc: &Value) -> Result<(Uuid, Vec<Value>), AppError> {
    let agent = doc["agent"]
        .as_str()
        .and_then(|a| Uuid::parse_str(a).ok())
        .ok_or_else(|| AppError::Validation("the suite names no agent".into()))?;
    let cases: Vec<Value> = doc["cases"].as_array().cloned().unwrap_or_default();
    if cases.is_empty() {
        return Err(AppError::Validation("the suite has no cases".into()));
    }
    if cases.len() > MAX_RUN_CASES {
        return Err(AppError::Validation(format!(
            "a run takes at most {MAX_RUN_CASES} cases; split the suite"
        )));
    }
    Ok((agent, cases))
}

/// One case run as one turn, as a transcript the graders read.
async fn run_case(
    state: &EngineState,
    security: &std::sync::Arc<SecurityContext>,
    agent: Uuid,
    input: &str,
) -> Result<attome_model::kinds::eval_suite::RunTranscript, AppError> {
    let session = crate::agent::start_session_from_object(
        state,
        security,
        agent,
        "eval",
        crate::agent::SessionConstraints {
            risk_ceiling: crate::descriptor::RiskTier::Reversible,
            allowed_action_ids: None,
        },
        false,
    )
    .await?;
    let finished = async {
        let conversation = crate::conversation::create(
            &state.base.db,
            crate::conversation::NewConversation {
                agent_session_id: session.id,
                owner_user_id: security.user_id,
                agent_definition_ref: None,
                surface: crate::conversation::Surface::Internal,
                title: Some("Eval case".to_owned()),
            },
        )
        .await?;
        crate::turn::run(
            state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &crate::turn::TurnInputs {
                session: &session,
                security: security.clone(),
                conversation_id: conversation.id,
                step_budget: Some(CASE_STEP_BUDGET),
            },
            input,
        )
        .await
    }
    .await;
    if let Err(error) = crate::session::revoke(
        &state.base.db,
        session.id,
        security.user_id,
        "eval case finished",
    )
    .await
    {
        tracing::warn!(%error, session = %session.id, "eval session not ended");
    }
    let outcome = finished?;
    Ok(attome_model::kinds::eval_suite::RunTranscript {
        tool_calls: outcome.steps.iter().map(|s| s.action_id.clone()).collect(),
        text: outcome.text,
    })
}

/// Runs every case and records the graded result on the run row.
async fn run_suite(
    state: EngineState,
    security: std::sync::Arc<SecurityContext>,
    run_id: Uuid,
    doc: Value,
    agent: Uuid,
    cases: Vec<Value>,
) {
    let mut runs = Vec::with_capacity(cases.len());
    let mut failure: Option<String> = None;
    for case in &cases {
        let input = case["input"].as_str().unwrap_or_default();
        match run_case(&state, &security, agent, input).await {
            Ok(transcript) => runs.push(transcript),
            Err(error) => {
                failure = Some(error.to_string());
                break;
            }
        }
    }
    let (status, score, outcome, error) = match failure {
        Some(error) => (
            "error",
            None,
            None,
            Some(error.chars().take(2000).collect::<String>()),
        ),
        None => {
            let graded = attome_model::kinds::eval_suite::grade_suite(&doc, &runs);
            let status = if graded.passed { "passed" } else { "failed" };
            (
                status,
                Some(graded.score),
                serde_json::to_value(&graded).ok(),
                None,
            )
        }
    };
    if let Err(error) = sqlx::query(
        "UPDATE ai_eval_run SET status = $2, score = $3, outcome = $4, error = $5, \
         finished_at = now() WHERE id = $1",
    )
    .bind(run_id)
    .bind(status)
    .bind(score)
    .bind(outcome)
    .bind(error)
    .execute(&state.base.db)
    .await
    {
        tracing::error!(%error, run = %run_id, "eval run result not recorded");
    }
}

/// `POST /api/v1/admin/ai/eval-suites/{suite}/runs`
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/eval-suites/{suite}/runs",
    operation_id = "start_eval_run",
    tag = "action",
    params(("suite" = Uuid, Path, description = "The eval suite object (its newest version runs)")),
    responses(
        (status = 202, description = "Running; read it with GET /api/v1/admin/ai/eval-runs/{id}", body = EvalRunStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such eval suite", body = ErrorResponse),
        (status = 422, description = "The suite names no agent, has no cases or too many", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, AuditOperation::Create)])))),
)]
async fn start_run(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(suite): Path<Uuid>,
) -> Result<(StatusCode, Json<EvalRunStarted>), AppError> {
    let planned = record_run(&state, suite, ctx.user_id).await?;
    let count = planned.cases.len();
    let run_id = planned.run_id;
    let security = ctx.into_inner();
    // Not awaited: an administrator follows the run with GET. A process that
    // dies mid-run leaves the row `running`; the next run supersedes it.
    drop(tokio::spawn(run_suite(
        state.clone(),
        security,
        planned.run_id,
        planned.doc,
        planned.agent,
        planned.cases,
    )));
    Ok((
        StatusCode::ACCEPTED,
        Json(EvalRunStarted {
            run_id,
            cases: count,
            status: "running".into(),
        }),
    ))
}

/// A run recorded and ready to execute.
struct PlannedRun {
    run_id: Uuid,
    doc: Value,
    agent: Uuid,
    cases: Vec<Value>,
}

/// Reads the suite, records the run row and its Ai security event.
async fn record_run(
    state: &EngineState,
    suite: Uuid,
    started_by: Uuid,
) -> Result<PlannedRun, AppError> {
    let version = attome_model::store::read(&state.base.db, suite, None).await?;
    if version.kind != attome_model::kinds::eval_suite::EVAL_SUITE.as_str() {
        return Err(AppError::NotFound);
    }
    let (agent, cases) = suite_plan(&version.doc)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let run_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_eval_run (suite_ref, suite_hash, agent_ref, status, started_by) \
         VALUES ($1, $2, $3, 'running', $4) RETURNING id",
    )
    .bind(suite)
    .bind(&version.content_hash)
    .bind(agent)
    .bind(started_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Ai,
            AuditOperation::Create,
            started_by,
            "ai_eval_run",
            Some(run_id),
        )
        .named("ai.eval_run.start")
        .comment(format!(
            "eval suite {suite} against agent {agent}: {} case(s)",
            cases.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(PlannedRun {
        run_id,
        doc: version.doc,
        agent,
        cases,
    })
}

/// Runs `suite` to the end as the administrator who last started it by hand
/// and returns its score (the pinned-model drift check, N25-T2). `None` when
/// nobody has run the suite yet, that person is no longer an active
/// administrator, or the run ended in an error rather than a grade.
pub(crate) async fn run_as_last_starter(
    state: &EngineState,
    suite: Uuid,
) -> Result<Option<f64>, AppError> {
    let starter: Option<Uuid> = sqlx::query_scalar(
        "SELECT started_by FROM ai_eval_run WHERE suite_ref = $1 \
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(suite)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(starter) = starter else {
        return Ok(None);
    };
    let security = match state.base.security.resolve_strict(starter).await {
        Ok(security) if security.is_admin => security,
        Ok(_) | Err(AppError::NotFound | AppError::Forbidden | AppError::Unauthorized) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let planned = record_run(state, suite, starter).await?;
    let run_id = planned.run_id;
    run_suite(
        state.clone(),
        security,
        run_id,
        planned.doc,
        planned.agent,
        planned.cases,
    )
    .await;
    let score: Option<f64> = sqlx::query_scalar(
        "SELECT score FROM ai_eval_run WHERE id = $1 AND status IN ('passed', 'failed')",
    )
    .bind(run_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    Ok(score)
}

/// `GET /api/v1/admin/ai/eval-runs/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/eval-runs/{id}",
    operation_id = "get_eval_run",
    tag = "action",
    params(("id" = Uuid, Path, description = "The eval run")),
    responses(
        (status = 200, description = "The run and, once finished, its graded cases", body = EvalRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such run", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_run(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<EvalRun>, AppError> {
    sqlx::query_as(
        "SELECT id, suite_ref, suite_hash, agent_ref, status, score, outcome, error, \
                started_by, started_at, finished_at \
         FROM ai_eval_run WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .map(Json)
    .ok_or(AppError::NotFound)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/ai/eval-suites/{suite}/runs", post(start_run))
        .route("/api/v1/admin/ai/eval-runs/{id}", get(get_run))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(start_run, get_run),
    components(schemas(EvalRunStarted, EvalRun))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_suite_names_its_agent_and_bounded_cases() {
        let agent = Uuid::now_v7();
        let (a, cases) = suite_plan(&json!({
            "agent": agent.to_string(),
            "cases": [{ "name": "x", "input": "hi", "expect": {} }]
        }))
        .unwrap();
        assert_eq!(a, agent);
        assert_eq!(cases.len(), 1);
        assert!(suite_plan(&json!({ "cases": [{}] })).is_err());
        assert!(suite_plan(&json!({ "agent": agent.to_string(), "cases": [] })).is_err());
        let many: Vec<Value> = (0..=MAX_RUN_CASES).map(|_| json!({})).collect();
        assert!(suite_plan(&json!({ "agent": agent.to_string(), "cases": many })).is_err());
    }
}
