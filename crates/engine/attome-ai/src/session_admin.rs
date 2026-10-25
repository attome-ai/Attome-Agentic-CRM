//! Minimal supervisor dashboard surface (M33 Phase 1, D-460): a read-only
//! list of live and recent `agent_session` rows, so an operator can
//! see what `agent.pause`/`agent.resume`/`agent.kill`
//! (`crate::actions::agent_supervise`) would act on. This module owns only
//! the read; the three actions above are how a supervisor actually acts —
//! same split `attome_workflow::instance_admin` draws between listing instances
//! and the separate cancel endpoint.
//!
//! Gated on the same `ai_agent.supervise` privilege the three actions
//! require — see `crate::actions::agent_supervise::AgentSupervise`'s doc
//! comment for why reading and acting share one privilege here.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, PageBase, PageWindow, PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::actions::agent_supervise::AgentSupervise;
use crate::capability_pack::CapabilityPackRef;

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    owner_user_id: Uuid,
    risk_ceiling: i16,
    allowed_action_ids: Option<Vec<String>>,
    capability_pack_refs: Option<serde_json::Value>,
    surface: String,
    agent_definition_ref: Option<Uuid>,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: Option<chrono::DateTime<chrono::Utc>>,
    paused_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    tainted: bool,
    retrieval_mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Paused,
    Revoked,
    Ended,
}

fn status_of(row: &SessionRow) -> SessionStatus {
    // Order matters: a session can accumulate more than one terminal-ish
    // timestamp over its life (e.g. paused, then later revoked) — revoke is
    // the most permanent state (TODO-039), so it wins over an earlier pause.
    if row.revoked_at.is_some() {
        SessionStatus::Revoked
    } else if row.ended_at.is_some() {
        SessionStatus::Ended
    } else if row.paused_at.is_some() {
        SessionStatus::Paused
    } else {
        SessionStatus::Active
    }
}

/// The provenance column (0480) as wire types. Provenance only, so an
/// unreadable value reads as "none recorded" rather than failing the whole
/// dashboard read — it can never widen what a session may do.
fn pack_refs_of(value: Option<serde_json::Value>) -> Option<Vec<CapabilityPackRef>> {
    match value {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => serde_json::from_value(value).ok(),
    }
}

fn risk_ceiling_wire(v: i16) -> &'static str {
    match v {
        1 => "reversible",
        2 => "consequential",
        _ => "read",
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionSummary {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub risk_ceiling: String,
    /// The session's effective allow-list, exactly as snapshotted at start.
    /// `None` means "whatever the ceiling permits"; `[]` means nothing — a
    /// supervisor reading the dashboard must see the difference.
    pub allowed_action_ids: Option<Vec<String>>,
    /// D-556 §2 provenance: which capability packs (and which of their
    /// versions) produced the grants above. Never consulted for
    /// authorization; shown so an operator can say where a grant came from.
    pub capability_pack_refs: Option<Vec<CapabilityPackRef>>,
    pub surface: String,
    pub agent_definition_ref: Option<Uuid>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub status: SessionStatus,
    pub tainted: bool,
    /// D-561 §5: the knowledge retrieval mode this session **uses** —
    /// `tool_invoked` | `pre_retrieved`, resolved from its agent definition
    /// when it started and stored on the row. Nothing changes it afterwards.
    pub retrieval_mode: String,
    /// The mode the session's agent definition is configured with **now**, for
    /// comparison only: it reaches the next session started from that
    /// definition, never this one. `unrecognised` when the definition holds a
    /// value a new session would refuse to start with; `None` when the session
    /// has no definition or the definition row no longer exists.
    pub agent_retrieval_mode: Option<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct SessionListQuery {
    /// Filter to one status (`active` | `paused` | `revoked` | `ended`).
    /// Unfiltered by default — a dashboard wants to see all of them.
    status: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/agents/sessions` — the supervisor dashboard's one read.
#[utoipa::path(
    get,
    path = "/api/v1/admin/agents/sessions",
    tag = "action",
    params(SessionListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SessionSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ai_agent.supervise", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_sessions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<AgentSupervise>>,
    Query(q): Query<SessionListQuery>,
) -> Result<Json<PaginatedResponse<SessionSummary>>, AppError> {
    let window = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    // Status is filtered in Rust, not SQL: it is derived from three
    // timestamp columns (see `status_of`), and expressing that derivation
    // twice (once here, once in a WHERE clause) is exactly the kind of
    // "two copies that can drift" guidelines §0/§13 warn against for a
    // low-cardinality admin table that is never going to need it for scale.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_session")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT id, owner_user_id, risk_ceiling, allowed_action_ids, capability_pack_refs, \
                surface, agent_definition_ref, started_at, ended_at, paused_at, revoked_at, tainted, \
                retrieval_mode \
         FROM agent_session \
         ORDER BY started_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let definitions: Vec<Uuid> = rows.iter().filter_map(|r| r.agent_definition_ref).collect();
    let configured = configured_retrieval_modes(&state.base.db, &definitions).await?;

    let mut items: Vec<SessionSummary> = rows
        .into_iter()
        .map(|r| {
            let status = status_of(&r);
            let agent_retrieval_mode = r
                .agent_definition_ref
                .and_then(|id| configured.get(&id).cloned());
            SessionSummary {
                id: r.id,
                owner_user_id: r.owner_user_id,
                risk_ceiling: risk_ceiling_wire(r.risk_ceiling).to_owned(),
                allowed_action_ids: r.allowed_action_ids,
                capability_pack_refs: pack_refs_of(r.capability_pack_refs),
                surface: r.surface,
                agent_definition_ref: r.agent_definition_ref,
                started_at: r.started_at,
                status,
                tainted: r.tainted,
                retrieval_mode: r.retrieval_mode,
                agent_retrieval_mode,
            }
        })
        .collect();

    if let Some(wanted) = q.status.as_deref() {
        items.retain(|s| format!("{:?}", s.status).to_lowercase() == wanted.to_lowercase());
    }

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// The retrieval mode each listed agent definition is configured with now,
/// read the way `agent::start_session` would resolve it for a new session.
///
/// `to_jsonb(a) -> 'retrieval_mode'` rather than the column by name, so a
/// deployment whose agent entity predates the attribute reads as the default
/// instead of failing the whole dashboard; `ai_agent` itself is
/// runtime-provisioned, so its absence is an empty map too.
async fn configured_retrieval_modes(
    db: &sqlx::PgPool,
    definitions: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, String>, AppError> {
    if definitions.is_empty() {
        return Ok(Default::default());
    }
    let provisioned: bool = sqlx::query_scalar("SELECT to_regclass('ai_agent') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !provisioned {
        return Ok(Default::default());
    }
    let rows: Vec<(Uuid, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT a.id, to_jsonb(a) -> 'retrieval_mode' FROM ai_agent a WHERE a.id = ANY($1)",
    )
    .bind(definitions)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, value)| (id, configured_mode_wire(value).to_owned()))
        .collect())
}

/// One definition's stored value, resolved exactly as a new session would
/// resolve it (`agent::definition_retrieval_mode`).
fn configured_mode_wire(value: Option<serde_json::Value>) -> &'static str {
    let data = serde_json::json!({ "retrieval_mode": value });
    crate::agent::definition_retrieval_mode(&data).map_or("unrecognised", |m| m.as_str())
}

/// One step of a session's run, in order (N29-T2).
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct TraceStep {
    pub id: Uuid,
    pub action_id: String,
    /// `completed`, `executed`, `claimed`, `approval_requested`, a refusal...
    pub outcome: String,
    /// The tool call that asked for it, when an agent did.
    pub tool_call_id: Option<String>,
    pub acting_user_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Most steps one trace returns.
const MAX_TRACE_STEPS: i64 = 1_000;

/// `GET /api/v1/admin/agents/sessions/{id}/trace` — every action a session
/// invoked, oldest first (N29-T2): what it did, what came of it and who it
/// acted as. Results are not included: they may hold record data, which the
/// records' own routes govern.
#[utoipa::path(
    get,
    path = "/api/v1/admin/agents/sessions/{id}/trace",
    tag = "action",
    params(("id" = Uuid, Path, description = "The agent session")),
    responses(
        (status = 200, description = "The session's steps, oldest first (at most 1000)", body = PaginatedResponse<TraceStep>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ai_agent.supervise", body = ErrorResponse),
        (status = 404, description = "No such session", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn session_trace(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<AgentSupervise>>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<PaginatedResponse<TraceStep>>, AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agent_session WHERE id = $1)")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let items: Vec<TraceStep> = sqlx::query_as(
        "SELECT id, action_id, outcome, tool_call_id, acting_user_id, created_at \
         FROM action_invocation WHERE agent_session_id = $1 \
         ORDER BY created_at, id LIMIT $2",
    )
    .bind(id)
    .bind(MAX_TRACE_STEPS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_TRACE_STEPS,
        warnings: Vec::new(),
    }))
}

/// One session a supervisor delegated to (N8-T1's run tree).
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ChildSession {
    pub id: Uuid,
    /// The specialist agent object it ran as.
    pub agent_object_ref: Option<Uuid>,
    pub surface: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Most child sessions one listing returns.
const MAX_CHILDREN: i64 = 200;

/// `GET /api/v1/admin/agents/sessions/{id}/children` — the sessions this one
/// delegated to, oldest first (N8-T1): with each child's own trace, the
/// whole run tree.
#[utoipa::path(
    get,
    path = "/api/v1/admin/agents/sessions/{id}/children",
    tag = "action",
    params(("id" = Uuid, Path, description = "The supervising agent session")),
    responses(
        (status = 200, description = "The delegated sessions, oldest first (at most 200)", body = PaginatedResponse<ChildSession>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ai_agent.supervise", body = ErrorResponse),
        (status = 404, description = "No such session", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn session_children(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<AgentSupervise>>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<PaginatedResponse<ChildSession>>, AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agent_session WHERE id = $1)")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let items: Vec<ChildSession> = sqlx::query_as(
        "SELECT id, agent_object_ref, surface, started_at, revoked_at          FROM agent_session WHERE parent_session_ref = $1          ORDER BY started_at, id LIMIT $2",
    )
    .bind(id)
    .bind(MAX_CHILDREN)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_CHILDREN,
        warnings: Vec::new(),
    }))
}

/// One tool call inside a turn of a run (N29-T1).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunToolCall {
    pub tool_call_id: String,
    pub action_id: String,
    /// The tool call's own status (`proposed`, `executed`, `rejected`, ...).
    pub status: String,
    pub gate_decision: Option<String>,
    /// The invocation ledger's outcome for it, when it reached the ledger.
    pub invocation_outcome: Option<String>,
}

/// One turn of a run.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunTurn {
    pub turn_id: Uuid,
    pub conversation_id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub model_id: Option<String>,
    pub prompt_version: Option<String>,
    pub terminal_state: Option<String>,
    pub tool_calls: Vec<RunToolCall>,
}

/// A session's whole run as one tree (N29-T1).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunTree {
    pub session_id: Uuid,
    pub parent_session_ref: Option<Uuid>,
    pub child_session_ids: Vec<Uuid>,
    pub turns: Vec<RunTurn>,
}

/// Most turns one tree returns.
const MAX_RUN_TURNS: i64 = 500;

/// `GET /api/v1/admin/agents/sessions/{id}/run` — the session's run as one
/// tree (N29-T1): its parent and delegated children, every turn of its
/// conversations with the model, prompt version and end state, and each
/// turn's tool calls with the gate's decision and the ledger's outcome.
#[utoipa::path(
    get,
    path = "/api/v1/admin/agents/sessions/{id}/run",
    tag = "action",
    params(("id" = Uuid, Path, description = "The agent session")),
    responses(
        (status = 200, description = "The run tree", body = RunTree),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ai_agent.supervise", body = ErrorResponse),
        (status = 404, description = "No such session", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn session_run(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<AgentSupervise>>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<RunTree>, AppError> {
    let db = &state.base.db;
    let parent: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT parent_session_ref FROM agent_session WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let parent_session_ref = parent.ok_or(AppError::NotFound)?;
    let child_session_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM agent_session WHERE parent_session_ref = $1 ORDER BY started_at, id LIMIT 200",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    type TurnRow = (
        Uuid,
        Uuid,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let turn_rows: Vec<TurnRow> = sqlx::query_as(
        "SELECT m.turn_id, m.conversation_id, MIN(m.created_at), MAX(m.model_id), \
                MAX(m.prompt_version), MAX(m.terminal_state) \
         FROM ai_message m JOIN ai_conversation c ON c.id = m.conversation_id \
         WHERE c.agent_session_id = $1 \
         GROUP BY m.turn_id, m.conversation_id ORDER BY MIN(m.created_at) LIMIT $2",
    )
    .bind(id)
    .bind(MAX_RUN_TURNS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let calls: Vec<(Uuid, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT t.turn_id, t.tool_call_id, t.action_id, t.status, t.gate_decision \
         FROM ai_tool_call t JOIN ai_conversation c ON c.id = t.conversation_id \
         WHERE c.agent_session_id = $1 ORDER BY t.created_at, t.id LIMIT 5000",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let outcomes: std::collections::HashMap<String, String> =
        sqlx::query_as::<_, (String, String)>(
            "SELECT tool_call_id, outcome FROM action_invocation \
         WHERE agent_session_id = $1 AND tool_call_id IS NOT NULL LIMIT 5000",
        )
        .bind(id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .collect();
    let turns = turn_rows
        .into_iter()
        .map(
            |(turn_id, conversation_id, started_at, model_id, prompt_version, terminal_state)| {
                RunTurn {
                    turn_id,
                    conversation_id,
                    started_at,
                    model_id,
                    prompt_version,
                    terminal_state,
                    tool_calls: calls
                        .iter()
                        .filter(|c| c.0 == turn_id)
                        .map(
                            |(_, tool_call_id, action_id, status, gate_decision)| RunToolCall {
                                tool_call_id: tool_call_id.clone(),
                                action_id: action_id.clone(),
                                status: status.clone(),
                                gate_decision: gate_decision.clone(),
                                invocation_outcome: outcomes.get(tool_call_id).cloned(),
                            },
                        )
                        .collect(),
                }
            },
        )
        .collect();
    Ok(Json(RunTree {
        session_id: id,
        parent_session_ref,
        child_session_ids,
        turns,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/agents/sessions", get(list_sessions))
        .route(
            "/api/v1/admin/agents/sessions/{id}/trace",
            get(session_trace),
        )
        .route(
            "/api/v1/admin/agents/sessions/{id}/children",
            get(session_children),
        )
        .route("/api/v1/admin/agents/sessions/{id}/run", get(session_run))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_sessions, session_trace, session_children, session_run),
    components(schemas(TraceStep, ChildSession, RunTree, RunTurn, RunToolCall))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ended: bool, paused: bool, revoked: bool) -> SessionRow {
        let now = chrono::Utc::now();
        SessionRow {
            id: Uuid::now_v7(),
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: 0,
            allowed_action_ids: None,
            capability_pack_refs: None,
            surface: "test".into(),
            agent_definition_ref: None,
            started_at: now,
            ended_at: ended.then_some(now),
            paused_at: paused.then_some(now),
            revoked_at: revoked.then_some(now),
            tainted: false,
            retrieval_mode: "tool_invoked".into(),
        }
    }

    #[test]
    fn status_reads_active_when_no_terminal_or_pause_timestamp_is_set() {
        assert_eq!(status_of(&row(false, false, false)), SessionStatus::Active);
    }

    #[test]
    fn status_reads_paused_only_when_nothing_more_permanent_is_set() {
        assert_eq!(status_of(&row(false, true, false)), SessionStatus::Paused);
    }

    /// Revoke wins over a pause a session happened to also carry — kill is
    /// the most permanent state (TODO-039).
    #[test]
    fn revoked_wins_over_paused() {
        assert_eq!(status_of(&row(false, true, true)), SessionStatus::Revoked);
    }

    #[test]
    fn status_reads_ended_when_set_and_not_revoked() {
        assert_eq!(status_of(&row(true, false, false)), SessionStatus::Ended);
    }

    /// The configured mode reads the way a new session resolves it: absent,
    /// null or blank is the default, and a value a start would refuse is said
    /// to be unrecognised rather than shown as either mode.
    #[test]
    fn the_configured_mode_is_resolved_like_a_session_start() {
        use serde_json::json;
        assert_eq!(configured_mode_wire(None), "tool_invoked");
        assert_eq!(configured_mode_wire(Some(json!(null))), "tool_invoked");
        assert_eq!(configured_mode_wire(Some(json!(""))), "tool_invoked");
        assert_eq!(
            configured_mode_wire(Some(json!("pre_retrieved"))),
            "pre_retrieved"
        );
        assert_eq!(
            configured_mode_wire(Some(json!("tool_invoked"))),
            "tool_invoked"
        );
        assert_eq!(configured_mode_wire(Some(json!("none"))), "unrecognised");
        assert_eq!(configured_mode_wire(Some(json!(1))), "unrecognised");
    }

    #[test]
    fn risk_ceiling_wire_matches_session_rs_encoding() {
        assert_eq!(risk_ceiling_wire(0), "read");
        assert_eq!(risk_ceiling_wire(1), "reversible");
        assert_eq!(risk_ceiling_wire(2), "consequential");
        // An unrecognised stored value narrows, same as `session::tier_from_i16`.
        assert_eq!(risk_ceiling_wire(99), "read");
    }
}
