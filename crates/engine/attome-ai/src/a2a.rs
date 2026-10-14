//! Agent-to-agent (roadmap N14-T1): trusted partners find this deployment's
//! agents and hand them tasks through each agent's typed contract.
//!
//! - `GET /api/v1/a2a/agents` — agent cards: every published agent object
//!   that declares a `handoff` contract, with its role and its input and
//!   output schemas. An agent without a contract takes no outside work.
//! - `POST /api/v1/a2a/agents/{agent}/tasks` — one task: the input is checked
//!   against the contract, the agent runs one bounded turn in a session of
//!   its own (`agent::start_session_from_object`, read-only ceiling, marked
//!   tainted: the input came from outside), and its answer comes back checked
//!   against the output contract. The task is the session's conversation, so
//!   its trace is the ordinary one.
//!
//! **Trust.** A partner authenticates like any caller (an S2S client or an
//! API key) and acts with that principal's own privileges; the agent's
//! policy, tools and daily limits apply on top. A partner never writes here:
//! the ceiling is `Read`, so a write the answer calls for is the partner's
//! to request through its own channel.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::orchestrate::{CHILD_STEP_BUDGET, child_task, handoff_of, parse_answer};

/// The most agent cards one listing returns.
const MAX_CARDS: i64 = 200;

/// One agent a partner can hand work to.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentCard {
    pub id: Uuid,
    pub name: String,
    pub role: Option<String>,
    #[schema(value_type = Object)]
    pub input_schema: Value,
    #[schema(value_type = Object)]
    pub output_schema: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct A2aTaskRequest {
    /// The task, matching the agent's input contract.
    #[schema(value_type = Object)]
    pub input: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct A2aTask {
    /// The task's id (its conversation).
    pub id: Uuid,
    /// `completed` (output matches the contract), `failed` (it did not, or
    /// the run ended early) or `rejected` (the input broke the contract).
    pub status: String,
    #[schema(value_type = Option<Object>)]
    pub output: Option<Value>,
    pub issues: Vec<String>,
}

/// `GET /api/v1/a2a/agents`
#[utoipa::path(
    get,
    path = "/api/v1/a2a/agents",
    tag = "action",
    responses(
        (status = 200, description = "Agents that take outside work, with their contracts", body = PaginatedResponse<AgentCard>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_agents(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
) -> Result<Json<PaginatedResponse<AgentCard>>, AppError> {
    let rows: Vec<(Uuid, String, Value)> = sqlx::query_as(
        "SELECT object_id, name, doc FROM ( \
             SELECT DISTINCT ON (o.id) o.id AS object_id, o.name, v.doc \
             FROM metadata_object o \
             JOIN metadata_object_version v ON v.object_id = o.id \
             WHERE o.kind = 'agent' AND o.is_active AND v.state = 'published' \
             ORDER BY o.id, v.version_no DESC \
             LIMIT $1 \
         ) newest \
         WHERE doc ? 'handoff' \
         ORDER BY name",
    )
    .bind(MAX_CARDS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<AgentCard> = rows
        .into_iter()
        .filter_map(|(id, name, doc)| {
            let handoff = handoff_of(&doc)?;
            Some(AgentCard {
                id,
                name,
                role: doc["role"].as_str().map(str::to_owned),
                input_schema: handoff.input,
                output_schema: handoff.output,
            })
        })
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_CARDS,
    }))
}

/// `POST /api/v1/a2a/agents/{agent}/tasks`
#[utoipa::path(
    post,
    path = "/api/v1/a2a/agents/{agent}/tasks",
    tag = "action",
    params(("agent" = Uuid, Path, description = "The agent object")),
    request_body = A2aTaskRequest,
    responses(
        (status = 200, description = "The task's result", body = A2aTask),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No published agent with this id", body = ErrorResponse),
        (status = 422, description = "The agent takes no outside work, or cannot start a session", body = ErrorResponse),
        (status = 429, description = "A budget or daily limit is used up", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create)])))),
)]
async fn create_task(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(agent): Path<Uuid>,
    Json(body): Json<A2aTaskRequest>,
) -> Result<Json<A2aTask>, AppError> {
    let published = attome_model::store::read_published(&state.base.db, agent).await?;
    if published.kind != attome_model::kinds::AGENT.as_str() {
        return Err(AppError::NotFound);
    }
    let handoff = handoff_of(&published.doc).ok_or_else(|| {
        AppError::Validation("this agent takes no outside work (no handoff contract)".into())
    })?;
    let issues = attome_model::contract::value_issues(&handoff.input, &body.input, "/input");
    if !issues.is_empty() {
        return Ok(Json(A2aTask {
            id: Uuid::nil(),
            status: "rejected".into(),
            output: None,
            issues,
        }));
    }
    let security = ctx.into_inner();
    let session = crate::agent::start_session_from_object(
        &state,
        &security,
        agent,
        "a2a",
        crate::agent::SessionConstraints {
            risk_ceiling: crate::descriptor::RiskTier::Read,
            allowed_action_ids: None,
        },
        true,
    )
    .await?;
    let ran = async {
        let conversation = crate::conversation::create(
            &state.base.db,
            crate::conversation::NewConversation {
                agent_session_id: session.id,
                owner_user_id: security.user_id,
                agent_definition_ref: None,
                surface: crate::conversation::Surface::Internal,
                title: Some(format!("A2A task for {}", published.name)),
            },
        )
        .await?;
        let task = child_task(
            published.doc["role"].as_str().unwrap_or("an agent"),
            published.doc["instructions"].as_str().unwrap_or_default(),
            &body.input,
            &handoff.output,
        );
        let outcome = crate::turn::run(
            &state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &crate::turn::TurnInputs {
                session: &session,
                security: security.clone(),
                conversation_id: conversation.id,
                step_budget: Some(CHILD_STEP_BUDGET),
            },
            &task,
        )
        .await?;
        Ok::<_, AppError>((conversation.id, outcome))
    }
    .await;
    if let Err(error) = crate::session::revoke(
        &state.base.db,
        session.id,
        security.user_id,
        "a2a task finished",
    )
    .await
    {
        tracing::warn!(%error, session = %session.id, "a2a session not ended");
    }
    let (task_id, outcome) = ran?;
    Ok(Json(match parse_answer(&outcome.text) {
        Some(output) => {
            let issues = attome_model::contract::value_issues(&handoff.output, &output, "/output");
            if issues.is_empty() {
                A2aTask {
                    id: task_id,
                    status: "completed".into(),
                    output: Some(output),
                    issues,
                }
            } else {
                A2aTask {
                    id: task_id,
                    status: "failed".into(),
                    output: None,
                    issues,
                }
            }
        }
        None => A2aTask {
            id: task_id,
            status: "failed".into(),
            output: None,
            issues: vec![format!(
                "the run ended ({}) without a JSON answer",
                outcome.terminal_state.as_str()
            )],
        },
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/a2a/agents", get(list_agents))
        .route("/api/v1/a2a/agents/{agent}/tasks", post(create_task))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_agents, create_task),
    components(schemas(AgentCard, A2aTaskRequest, A2aTask))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
