//! C4 — the chat HTTP API (`/api/v1/ai/conversations…`).
//!
//! Thin handlers: parse, authorize the conversation, call the engine
//! (`conversation`, `turn`, `confirm`, `tool_call`), shape the response.
//!
//! **Every route authorizes the conversation before returning anything
//! (I-20).** A conversation, message or tool-call id is an identifier, never a
//! capability: an unknown conversation and another user's conversation are the
//! same `404`, decided by `conversation::load_for(Access::Owner)` before any
//! other read. `/stream` is not here — it is C10's.
//!
//! **Starting a conversation** requires the same privilege and the same
//! explicit ceiling as `POST /agents/{id}/sessions`, and goes through the same
//! `agent::start_session`, so the agent policy still bounds the session. No
//! new grant exists for chat in C4.
//!
//! Audit (D-542): every mutating route declares its mandatory `Ai` event and
//! the engine writes it in the mutation's own transaction —
//! `session::start` (Create), `conversation::append_audited` (Create, the
//! human's message), `execute::run_executor` (Execute, an executed action),
//! `tool_call::reject` (Rejected), `conversation::end_and_revoke` (Closed).

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::agent::{AgentUpdate, StartSessionRequest};
use crate::chat_view::{CitationView, Grounding, RecordContext, ToolCallView, TurnGrounding};
use crate::confirm::{ConfirmOutcome, ConfirmRefusal, ConfirmRequest};
use crate::conversation::{self, Access, Conversation, EndOutcome, NewConversation, Surface};
use crate::descriptor::RiskTier;
use crate::feedback::Vote;
use crate::tool_call::{Rejection, Status};
use crate::turn::{Pending, TurnInputs, TurnOutcome};

/// The longest message a human may send in one turn.
const MAX_MESSAGE_CHARS: usize = 16_000;
/// Turns one user may start per minute, across all conversations.
const TURNS_PER_USER_PER_MINUTE: i32 = 30;
/// Turns one conversation may run per minute.
const TURNS_PER_CONVERSATION_PER_MINUTE: i32 = 12;
/// Confirmations one user may attempt per minute.
const CONFIRMS_PER_USER_PER_MINUTE: i32 = 60;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Body of `POST /api/v1/ai/conversations`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartConversationRequest {
    /// The `ai_agent` definition to converse with.
    pub agent_definition_id: Uuid,
    /// **Required.** `"read"` | `"reversible"` | `"consequential"` — the same
    /// explicit ceiling `POST /agents/{id}/sessions` takes. The agent policy
    /// still bounds it; it never grants anything the caller does not hold.
    pub risk_ceiling: String,
    /// Optional. Omitted or `null`: whatever the ceiling permits. `[]`: nothing.
    #[serde(default)]
    pub allowed_action_ids: Option<Vec<String>>,
    #[serde(default)]
    pub title: Option<String>,
    /// Optional (N1-T1): `"develop"` builds — the metadata tools and reads,
    /// so every change is a draft and no record is written; `"run"` acts —
    /// everything but the metadata edit tools. Omitted: no narrowing. It only
    /// narrows `allowed_action_ids`, never widens it.
    #[serde(default)]
    pub mode: Option<String>,
}

/// The actions a conversation mode allows (N1-T1), from every registered
/// `(id, is_write)`; `None` for no mode.
pub fn mode_actions(
    mode: Option<&str>,
    actions: impl Iterator<Item = (String, bool)>,
) -> Result<Option<Vec<String>>, AppError> {
    let is_model_edit = |id: &str| id.starts_with("model.") && id.ends_with(".edit");
    match mode.map(str::trim) {
        None | Some("") => Ok(None),
        Some("develop") => Ok(Some(
            actions
                .filter(|(id, write)| !write || id.starts_with("model."))
                .map(|(id, _)| id)
                .collect(),
        )),
        Some("run") => Ok(Some(
            actions
                .filter(|(id, _)| !is_model_edit(id))
                .map(|(id, _)| id)
                .collect(),
        )),
        Some(other) => Err(AppError::Validation(format!(
            "mode must be \"develop\" or \"run\", not {other:?}"
        ))),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConversationView {
    pub id: Uuid,
    pub agent_session_id: Uuid,
    pub agent_definition_ref: Option<Uuid>,
    pub surface: String,
    pub title: Option<String>,
    /// The ordinal of the last message; the history's `total`.
    pub last_ordinal: i64,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

impl From<Conversation> for ConversationView {
    fn from(c: Conversation) -> Self {
        Self {
            id: c.id,
            agent_session_id: c.agent_session_id,
            agent_definition_ref: c.agent_definition_ref,
            surface: c.surface,
            title: c.title,
            last_ordinal: c.last_ordinal,
            started_at: c.started_at,
            ended_at: c.ended_at,
            row_version: c.row_version,
        }
    }
}

/// The governance in effect for a conversation's session — snapshotted when
/// it started (D-505), shown whatever state the session is now in.
#[derive(Debug, Serialize, ToSchema)]
pub struct GovernanceView {
    /// `"live"` | `"paused"` | `"ended"` — ended covers revoked, ended and
    /// expired alike.
    pub state: String,
    /// `"read"` | `"reversible"` | `"consequential"`.
    pub risk_ceiling: String,
    pub allowed_action_ids: Option<Vec<String>>,
    /// Whether the session started downstream of tool-obtained content (I-10).
    pub tainted: bool,
    pub max_invocations_per_session: Option<i32>,
    pub max_writes_per_day: Option<i32>,
    pub max_tokens_per_session: Option<i64>,
    pub max_session_duration_minutes: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConversationDetail {
    pub conversation: ConversationView,
    pub governance: GovernanceView,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageView {
    pub id: Uuid,
    pub ordinal: i64,
    /// `"user"` | `"assistant"` | `"tool"`.
    pub role: String,
    pub content: String,
    pub turn_id: Uuid,
    /// Set on a turn's final assistant message: one of the twelve terminal
    /// states.
    pub terminal_state: Option<String>,
    /// Provenance: the model and prompt version that wrote an assistant
    /// message. `null` on user and tool messages.
    pub model_id: Option<String>,
    pub prompt_version: Option<String>,
    /// On a turn's final assistant message: the citations of the turn's
    /// executed knowledge actions, never anything parsed from `content`
    /// (row A-56). Empty on every other message.
    pub citations: Vec<CitationView>,
    /// On a turn's final assistant message only; `null` elsewhere.
    pub grounding: Option<Grounding>,
    /// C10-B: the caller's current vote on a turn's answer, `null` when there
    /// is none (and on every other message).
    pub feedback: Option<Vote>,
    pub created_at: DateTime<Utc>,
}

/// Body of `PUT …/messages/{message_id}/feedback`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackRequest {
    /// `"up"` | `"down"`.
    pub vote: Vote,
}

/// The caller's current vote on one answer.
#[derive(Debug, Serialize, ToSchema)]
pub struct FeedbackView {
    pub message_id: Uuid,
    pub vote: Vote,
    pub updated_at: DateTime<Utc>,
}

/// Body of `POST …/messages`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SendChatMessageRequest {
    pub text: String,
    /// Optional: the record the user is looking at — a navigation hint,
    /// **never authorization** (I-19, row A-66). Shape-checked only, never
    /// looked up, and stored as one fixed line in the user's message.
    #[serde(default)]
    pub context: Option<RecordContext>,
}

/// Why a turn stopped for a human.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingView {
    /// A proposal is persisted and awaits confirmation. Nothing executed.
    /// Confirm it by `tool_call_id` with this `arguments_hash`.
    Confirmation {
        tool_call_id: String,
        action_id: String,
        arguments_hash: String,
        reason: String,
    },
    /// A four-eyes approval was requested. Nothing executed.
    Approval {
        approval_request_id: Uuid,
        action_id: String,
    },
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TurnResponse {
    pub turn_id: Uuid,
    /// One of the twelve terminal states (D-565).
    pub terminal_state: String,
    pub text: String,
    pub pending: Option<PendingView>,
    /// The model that wrote `text`, when one did.
    pub model_id: Option<String>,
    /// The turn's executed knowledge actions' citations (row A-56).
    pub citations: Vec<CitationView>,
    pub grounding: Grounding,
}

/// Body of `POST …/tool-calls/{tid}/confirm`. **Only the hash the UI
/// displayed** — the arguments that run are the server's stored copy (I-13).
/// An `arguments` field, or any other, is rejected (row A-08).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmToolCallRequest {
    pub arguments_hash: String,
}

/// `200`: the proposal ran now.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfirmExecuted {
    /// Always `"executed"`.
    pub outcome: String,
    pub result: Value,
}

/// `202`: a `Consequential` action was submitted for four-eyes approval.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfirmApprovalRequested {
    /// Always `"approval_requested"`.
    pub outcome: String,
    pub approval_request_id: Uuid,
}

/// A confirm or reject that did not run anything: the standard error body
/// (`error` is always `"conflict"` or `"rate_limit_exceeded"`) plus the
/// outcome decided from the persisted state.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfirmConflict {
    pub error: String,
    pub message: String,
    /// `stale_hash` | `conflict` | `in_progress` | `already_executed` |
    /// `approval_pending` | `rejected` | `expired` | `invalidated` |
    /// `session_paused` | `write_limit_reached` | `action_failed` |
    /// `outcome_unrecorded` | `executing` | `executed` | `proposed`.
    pub outcome: String,
    /// `already_executed`: the recorded result of the execution that ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// `approval_pending`: the approval request it waits on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
}

fn conflict(status: StatusCode, outcome: &str, message: &str) -> ConfirmConflictResponse {
    ConfirmConflictResponse {
        status,
        body: ConfirmConflict {
            error: if status == StatusCode::TOO_MANY_REQUESTS {
                "rate_limit_exceeded".into()
            } else {
                "conflict".into()
            },
            message: message.into(),
            outcome: outcome.into(),
            result: None,
            approval_request_id: None,
        },
    }
}

struct ConfirmConflictResponse {
    status: StatusCode,
    body: ConfirmConflict,
}

impl IntoResponse for ConfirmConflictResponse {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

fn risk_ceiling_wire(tier: RiskTier) -> &'static str {
    match tier {
        RiskTier::Read => "read",
        RiskTier::Reversible => "reversible",
        RiskTier::Consequential => "consequential",
    }
}

// ---------------------------------------------------------------------------
// Shared steps
// ---------------------------------------------------------------------------

/// I-20: the caller's own conversation, or `404`.
async fn owned(state: &EngineState, id: Uuid, caller: Uuid) -> Result<Conversation, AppError> {
    conversation::load_for(&state.base.db, id, Access::Owner(caller))
        .await?
        .ok_or(AppError::NotFound)
}

async fn rate_limit(state: &EngineState, key: String, per_minute: i32) -> Result<(), AppError> {
    let outcome =
        attome_cache::rate_limit::check(&state.base.redis_coordination, &key, per_minute).await?;
    if outcome.allowed {
        Ok(())
    } else {
        Err(AppError::TooManyRequests {
            retry_after_secs: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/ai/conversations` — starts a conversation and its agent
/// session from an agent definition.
#[utoipa::path(
    post,
    path = "/api/v1/ai/conversations",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create)])))),
    request_body = StartConversationRequest,
    responses(
        (status = 200, description = "Started", body = ConversationDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ai_agent.update", body = ErrorResponse),
        (status = 404, description = "No such agent definition, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "risk_ceiling is missing or unknown, an unknown field was sent, or the definition cannot start a session (inactive, no live primary model, or no valid agent policy)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_conversation(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<AgentUpdate>>,
    Json(body): Json<StartConversationRequest>,
) -> Result<Json<ConversationDetail>, AppError> {
    // D-766: this work escapes the S2S entity ceiling (it re-resolves the
    // caller later, or reads across entities by role), so a capped caller
    // is refused until the ceiling is carried through.
    ctx.refuse_if_capped()?;
    let mode = mode_actions(
        body.mode.as_deref(),
        crate::engine::REGISTRY.all().map(|d| {
            (
                d.id.as_str().to_owned(),
                d.effect == crate::descriptor::Effect::Write,
            )
        }),
    )?;
    let mut constraints = crate::agent::admin_session_constraints(&StartSessionRequest {
        risk_ceiling: body.risk_ceiling,
        allowed_action_ids: body.allowed_action_ids,
        agent: None,
    })?;
    if let Some(mode) = mode {
        constraints.allowed_action_ids = Some(crate::agent::narrow_to_agent_tools(
            constraints.allowed_action_ids.take(),
            &mode,
        ));
    }
    // C11 B3: have the delta fan-out connected before the first answer.
    crate::delta_stream::warm(state.base.redis.clone(), state.base.config.clone());
    // A human directly starting a conversation is not "retrieved content".
    let session = crate::agent::start_session(
        &state,
        &ctx,
        body.agent_definition_id,
        "internal",
        constraints,
        false,
    )
    .await?;
    let created = conversation::create(
        &state.base.db,
        NewConversation {
            agent_session_id: session.id,
            owner_user_id: ctx.user_id,
            agent_definition_ref: Some(body.agent_definition_id),
            surface: Surface::Internal,
            title: body.title.filter(|t| !t.trim().is_empty()),
        },
    )
    .await;
    let created = match created {
        Ok(created) => created,
        Err(e) => {
            // Never leave a live, dispatchable session with no conversation.
            if let Err(revoke) = crate::session::revoke(
                &state.base.db,
                session.id,
                ctx.user_id,
                "conversation could not be created",
            )
            .await
            {
                tracing::error!(
                    agent_session_id = %session.id,
                    error = %revoke,
                    "could not revoke the session of a conversation that failed to start"
                );
            }
            return Err(e);
        }
    };
    Ok(Json(ConversationDetail {
        conversation: created.into(),
        governance: GovernanceView {
            state: "live".into(),
            risk_ceiling: risk_ceiling_wire(session.risk_ceiling).into(),
            allowed_action_ids: session.allowed_action_ids,
            tainted: session.tainted,
            max_invocations_per_session: session.policy.max_invocations_per_session,
            max_writes_per_day: session.policy.max_writes_per_day,
            max_tokens_per_session: session.policy.max_tokens_per_session,
            max_session_duration_minutes: session.policy.max_session_duration_minutes,
        },
    }))
}

/// `GET /api/v1/ai/conversations` — the caller's own conversations, newest
/// first.
#[utoipa::path(
    get,
    path = "/api/v1/ai/conversations",
    tag = "action",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ConversationView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_conversations(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ConversationView>>, AppError> {
    let window = q.window();
    let (rows, total) =
        conversation::list_for_owner(&state.base.db, ctx.user_id, window.page, window.page_size)
            .await?;
    let items = rows.into_iter().map(ConversationView::from).collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// `GET /api/v1/ai/conversations/{id}` — metadata and the governance in
/// effect.
#[utoipa::path(
    get,
    path = "/api/v1/ai/conversations/{id}",
    tag = "action",
    params(("id" = Uuid, Path, description = "The conversation")),
    responses(
        (status = 200, description = "Success", body = ConversationDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_conversation(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConversationDetail>, AppError> {
    let conv = owned(&state, id, ctx.user_id).await?;
    let governance = crate::session::load_governance(&state.base.db, conv.agent_session_id)
        .await?
        .ok_or_else(|| AppError::internal("a conversation's agent session row is missing"))?;
    let s = governance.session;
    Ok(Json(ConversationDetail {
        conversation: conv.into(),
        governance: GovernanceView {
            state: if governance.dead {
                "ended"
            } else if governance.paused {
                "paused"
            } else {
                "live"
            }
            .into(),
            risk_ceiling: risk_ceiling_wire(s.risk_ceiling).into(),
            allowed_action_ids: s.allowed_action_ids,
            tainted: s.tainted,
            max_invocations_per_session: s.policy.max_invocations_per_session,
            max_writes_per_day: s.policy.max_writes_per_day,
            max_tokens_per_session: s.policy.max_tokens_per_session,
            max_session_duration_minutes: s.policy.max_session_duration_minutes,
        },
    }))
}

/// `POST /api/v1/ai/conversations/{id}/messages` — sends a message and runs
/// one turn.
#[utoipa::path(
    post,
    path = "/api/v1/ai/conversations/{id}/messages",
    tag = "action",
    // Explicit: utoipa defaults the operation id to the fn name, and
    // `server::omnichannel` already has a `send_message`. Two operations with
    // one id make openapi-typescript emit a duplicate `operations` key, which
    // fails the Angular build.
    operation_id = "send_chat_message",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create)])))),
    params(("id" = Uuid, Path, description = "The conversation")),
    request_body = SendChatMessageRequest,
    responses(
        (status = 200, description = "The turn ran to one of its twelve terminal states", body = TurnResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
        (status = 409, description = "The conversation has ended", body = ErrorResponse),
        (status = 422, description = "The message is empty or too long, the record context is malformed, or an unknown field was sent", body = ErrorResponse),
        (status = 429, description = "Too many turns for this user or conversation", body = ErrorResponse),
        (status = 503, description = "No inference endpoint is configured", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn send_message(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<SendChatMessageRequest>,
) -> Result<Json<TurnResponse>, AppError> {
    let text = body.text.trim();
    if text.is_empty() {
        return Err(AppError::Validation("text must not be empty".into()));
    }
    if text.chars().count() > MAX_MESSAGE_CHARS {
        return Err(AppError::Validation(format!(
            "text must be at most {MAX_MESSAGE_CHARS} characters"
        )));
    }
    // Record context becomes part of the user's own message — shape-checked,
    // never looked up, never an authorization input (I-19).
    let text = crate::chat_view::fold_record_context(body.context.as_ref(), text)?;
    let conv = owned(&state, id, ctx.user_id).await?;
    if conv.ended_at.is_some() {
        return Err(AppError::Conflict("the conversation has ended"));
    }
    rate_limit(
        &state,
        format!("attome-ai:rl:chat-turn:user:{}", ctx.user_id),
        TURNS_PER_USER_PER_MINUTE,
    )
    .await?;
    rate_limit(
        &state,
        format!("attome-ai:rl:chat-turn:conversation:{}", conv.id),
        TURNS_PER_CONVERSATION_PER_MINUTE,
    )
    .await?;

    // The session whatever its state: `turn::run` re-reads it live on every
    // step and ends the turn with the terminal state that names why.
    let governance = crate::session::load_governance(&state.base.db, conv.agent_session_id)
        .await?
        .ok_or_else(|| AppError::internal("a conversation's agent session row is missing"))?;
    let security = ctx.into_inner();
    let conversation_id = conv.id;
    let turn_state = state.clone();
    let outcome = run_detached("chat turn", async move {
        crate::turn::run(
            &turn_state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &TurnInputs {
                session: &governance.session,
                security,
                conversation_id,
                step_budget: None,
            },
            &text,
        )
        .await
    })
    .await?;
    let grounding =
        crate::chat_view::grounding_for_turns(&state.base.db, conv.id, &[outcome.turn_id])
            .await?
            .remove(&outcome.turn_id)
            .unwrap_or_default();
    Ok(Json(turn_response(outcome, grounding)))
}

/// Body of `POST /api/v1/ai/conversations/{id}/runs` (N7-T1).
#[derive(Debug, serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartRunRequest {
    /// What the agent is to do.
    pub task: String,
    /// The most tool steps the run may take (capped by the platform's own
    /// bound); omitted: the platform's bound.
    #[serde(default)]
    pub max_steps: Option<usize>,
}

/// What a started run returns at once (N7-T1).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunStarted {
    pub conversation_id: Uuid,
    /// `running`: follow `GET /api/v1/ai/conversations/{id}/stream` for its
    /// steps and its end state.
    pub status: String,
}

/// `POST /api/v1/ai/conversations/{id}/runs` — gives the agent a task and
/// returns at once while it works through it in the background (N7-T1):
/// the same turn loop, gate and ledger as a chat message, bounded by
/// `max_steps`, ending in one of the turn's terminal states (completed,
/// awaiting confirmation or approval, a limit, a failure). Its steps and end
/// state are on the conversation's stream.
#[utoipa::path(
    post,
    path = "/api/v1/ai/conversations/{id}/runs",
    tag = "action",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("turn::run"),
        "the run is detached; its first write, the person's message and its mandatory \
         Ai event, happens in turn::run exactly as for POST .../messages, which the \
         emission test drives"
    )))),
    params(("id" = Uuid, Path, description = "The conversation")),
    request_body = StartRunRequest,
    responses(
        (status = 202, description = "Running; follow the conversation's stream", body = RunStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
        (status = 409, description = "The conversation has ended", body = ErrorResponse),
        (status = 422, description = "The task is empty or too long", body = ErrorResponse),
        (status = 429, description = "Too many turns for this user or conversation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_run(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<StartRunRequest>,
) -> Result<(axum::http::StatusCode, Json<RunStarted>), AppError> {
    let task = body.task.trim().to_owned();
    if task.is_empty() {
        return Err(AppError::Validation("task must not be empty".into()));
    }
    if task.chars().count() > MAX_MESSAGE_CHARS {
        return Err(AppError::Validation(format!(
            "task must be at most {MAX_MESSAGE_CHARS} characters"
        )));
    }
    let conv = owned(&state, id, ctx.user_id).await?;
    if conv.ended_at.is_some() {
        return Err(AppError::Conflict("the conversation has ended"));
    }
    rate_limit(
        &state,
        format!("attome-ai:rl:chat-turn:user:{}", ctx.user_id),
        TURNS_PER_USER_PER_MINUTE,
    )
    .await?;
    rate_limit(
        &state,
        format!("attome-ai:rl:chat-turn:conversation:{}", conv.id),
        TURNS_PER_CONVERSATION_PER_MINUTE,
    )
    .await?;
    let governance = crate::session::load_governance(&state.base.db, conv.agent_session_id)
        .await?
        .ok_or_else(|| AppError::internal("a conversation's agent session row is missing"))?;
    let security = ctx.into_inner();
    let conversation_id = conv.id;
    let run_state = state.clone();
    let max_steps = body.max_steps;
    // Not awaited: the caller follows the stream. A process that dies mid-run
    // is the case the lease sweep and the held claims already cover, as for a
    // chat turn whose client went away (`run_detached`).
    drop(tokio::spawn(async move {
        let outcome = crate::turn::run(
            &run_state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &TurnInputs {
                session: &governance.session,
                security,
                conversation_id,
                step_budget: max_steps,
            },
            &task,
        )
        .await;
        match outcome {
            Ok(outcome) => tracing::info!(
                conversation_id = %conversation_id,
                terminal_state = outcome.terminal_state.as_str(),
                "background agent run ended"
            ),
            Err(error) => tracing::warn!(
                conversation_id = %conversation_id,
                %error,
                "background agent run failed"
            ),
        }
    }));
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(RunStarted {
            conversation_id,
            status: "running".into(),
        }),
    ))
}

/// Runs a turn or a confirmation to completion whether or not its client is
/// still waiting.
///
/// Both mutate under a D-502 claim, and both persist their outcome after the
/// side effect. Run inside the request future, a client that goes away — a
/// closed tab, a dropped connection, the request timeout — dropped that future
/// between the two: the side effect had happened, the claim was held so it
/// would never run again, and the call stayed `executing` with no outcome (the
/// A-87 browser pass found it). Spawned, a disconnect only drops the wait; the
/// work finishes and the ledger, which `/stream` relays, records it.
///
/// A bare `tokio::spawn` is sanctioned here (coding-guidelines §10): the
/// handler awaits it, and a process that dies mid-way is the case the lease
/// sweep and the held claim already cover.
async fn run_detached<T: Send + 'static>(
    what: &'static str,
    work: impl std::future::Future<Output = Result<T, AppError>> + Send + 'static,
) -> Result<T, AppError> {
    tokio::spawn(work).await.map_err(|error| {
        tracing::error!(%error, what, "detached chat work panicked or was cancelled");
        AppError::internal(format!("{what} did not complete"))
    })?
}

fn turn_response(outcome: TurnOutcome, grounding: TurnGrounding) -> TurnResponse {
    TurnResponse {
        model_id: outcome.model_id,
        citations: grounding.citations,
        grounding: grounding.grounding,
        turn_id: outcome.turn_id,
        terminal_state: outcome.terminal_state.as_str().into(),
        text: outcome.text,
        pending: outcome.pending.map(|p| match p {
            Pending::Confirmation {
                tool_call_id,
                action_id,
                arguments_hash,
                reason,
            } => PendingView::Confirmation {
                tool_call_id,
                action_id,
                arguments_hash,
                reason,
            },
            Pending::Approval {
                approval_id,
                action_id,
            } => PendingView::Approval {
                approval_request_id: approval_id,
                action_id,
            },
        }),
    }
}

/// `GET /api/v1/ai/conversations/{id}/messages` — the transcript, oldest
/// first, paged by ordinal.
#[utoipa::path(
    get,
    path = "/api/v1/ai/conversations/{id}/messages",
    tag = "action",
    params(("id" = Uuid, Path, description = "The conversation"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MessageView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_messages(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<MessageView>>, AppError> {
    let conv = owned(&state, id, ctx.user_id).await?;
    let window = q.window();
    // Ordinals are gapless per conversation (D-552), so page N is exactly the
    // ordinals after (N - 1) * page_size, which is the window's offset.
    let rows =
        conversation::history(&state.base.db, conv.id, window.offset, window.page_size).await?;
    // Grounding belongs to a turn's final assistant message: the one that
    // carries its terminal state.
    let final_turns: Vec<Uuid> = rows
        .iter()
        .filter(|m| is_turn_final(m))
        .map(|m| m.turn_id)
        .collect();
    let mut grounding =
        crate::chat_view::grounding_for_turns(&state.base.db, conv.id, &final_turns).await?;
    let answer_ids: Vec<Uuid> = rows
        .iter()
        .filter(|m| is_turn_final(m))
        .map(|m| m.id)
        .collect();
    let votes =
        crate::feedback::votes_for(&state.base.db, conv.id, ctx.user_id, &answer_ids).await?;
    let items = rows
        .into_iter()
        .map(|m| {
            let (citations, grounding) = if is_turn_final(&m) {
                let g = grounding.remove(&m.turn_id).unwrap_or_default();
                (g.citations, Some(g.grounding))
            } else {
                (Vec::new(), None)
            };
            MessageView {
                id: m.id,
                ordinal: m.ordinal,
                role: m.role,
                content: m.content,
                turn_id: m.turn_id,
                terminal_state: m.terminal_state,
                model_id: m.model_id,
                prompt_version: m.prompt_version,
                citations,
                grounding,
                feedback: votes.get(&m.id).copied(),
                created_at: m.created_at,
            }
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        conv.last_ordinal,
        window.page,
        window.page_size,
    )))
}

/// `PUT /api/v1/ai/conversations/{id}/messages/{message_id}/feedback` — the
/// caller's thumbs up or down on a turn's answer. Changing a vote replaces
/// it; there is one current vote per user and message.
#[utoipa::path(
    put,
    path = "/api/v1/ai/conversations/{id}/messages/{message_id}/feedback",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Update)])))),
    params(
        ("id" = Uuid, Path, description = "The conversation"),
        ("message_id" = Uuid, Path, description = "The answer being rated"),
    ),
    request_body = FeedbackRequest,
    responses(
        (status = 200, description = "The vote is recorded", body = FeedbackView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller, or no such message in it", body = ErrorResponse),
        (status = 422, description = "The message is not a turn's answer, the vote is not up or down, or an unknown field was sent", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_feedback(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((id, message_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<FeedbackRequest>,
) -> Result<Json<FeedbackView>, AppError> {
    let conv = owned(&state, id, ctx.user_id).await?;
    let fb = crate::feedback::set_vote(&state, conv.id, message_id, ctx.user_id, body.vote).await?;
    Ok(Json(FeedbackView {
        message_id: fb.message_id,
        vote: fb.vote,
        updated_at: fb.updated_at,
    }))
}

/// What a Stop request found (C11 B4).
#[derive(Debug, Serialize, ToSchema)]
pub struct CancelTurnView {
    pub turn_id: Uuid,
    /// `requested` — recorded now, and the turn stops at its next boundary;
    /// `already_requested` — an earlier Stop stands; `already_ended` — the
    /// turn had already finished, and nothing was written.
    pub state: String,
}

/// `POST /api/v1/ai/conversations/{id}/turns/{turn_id}/cancel` — Stop.
///
/// The turn ends as `cancelled` at its next boundary: before another model
/// call, before another tool call is proposed, or at once while a model call
/// is streaming. A tool call already dispatched completes and is recorded; a
/// proposal waiting for confirmation or approval is untouched (row A-84).
/// Repeating the request is harmless.
#[utoipa::path(
    post,
    path = "/api/v1/ai/conversations/{id}/turns/{turn_id}/cancel",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Update)])))),
    params(
        ("id" = Uuid, Path, description = "The conversation"),
        ("turn_id" = Uuid, Path, description = "The turn to stop"),
    ),
    responses(
        (status = 200, description = "The Stop is recorded, was already recorded, or the turn had already ended", body = CancelTurnView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller, or no such turn in it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_turn(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((id, turn_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<CancelTurnView>, AppError> {
    let conv = owned(&state, id, ctx.user_id).await?;
    let outcome = crate::turn_cancel::request(&state, conv.id, turn_id, ctx.user_id).await?;
    Ok(Json(CancelTurnView {
        turn_id,
        state: outcome.as_str().to_owned(),
    }))
}

fn is_turn_final(m: &conversation::MessageRow) -> bool {
    m.role == "assistant" && m.terminal_state.is_some()
}

/// `GET /api/v1/ai/conversations/{id}/tool-calls` — the conversation's tool
/// calls, oldest first. A read projection for display: `arguments` is shown on
/// a confirmation card and never sent back (I-13); the stored outcome is not
/// exposed.
#[utoipa::path(
    get,
    path = "/api/v1/ai/conversations/{id}/tool-calls",
    tag = "action",
    params(("id" = Uuid, Path, description = "The conversation"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ToolCallView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_tool_calls(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ToolCallView>>, AppError> {
    let conv = owned(&state, id, ctx.user_id).await?;
    let window = q.window();
    let (items, total) =
        crate::chat_view::list_tool_calls(&state.base.db, conv.id, window.page, window.page_size)
            .await?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// `POST /api/v1/ai/conversations/{id}/tool-calls/{tid}/confirm` — executes a
/// **server-persisted** proposal as the agent action it is (I-13).
#[utoipa::path(
    post,
    path = "/api/v1/ai/conversations/{id}/tool-calls/{tid}/confirm",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Execute)])))),
    params(
        ("id" = Uuid, Path, description = "The conversation"),
        ("tid" = String, Path, description = "The proposal's tool_call_id"),
    ),
    request_body = ConfirmToolCallRequest,
    responses(
        (status = 200, description = "The proposal ran", body = ConfirmExecuted),
        (status = 202, description = "Submitted for four-eyes approval", body = ConfirmApprovalRequested),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation or proposal for this caller", body = ErrorResponse),
        (status = 409, description = "Nothing ran; `outcome` says why, from the persisted state", body = ConfirmConflict),
        (status = 422, description = "An unknown field (such as `arguments`) was sent", body = ErrorResponse),
        (status = 429, description = "Too many confirmations, or the session's daily write limit is spent", body = ConfirmConflict),
        (status = 503, description = "A transient failure; nothing ran and the proposal is confirmable again", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn confirm_tool_call(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((id, tid)): Path<(Uuid, String)>,
    Json(body): Json<ConfirmToolCallRequest>,
) -> Result<Response, AppError> {
    rate_limit(
        &state,
        format!("attome-ai:rl:chat-confirm:user:{}", ctx.user_id),
        CONFIRMS_PER_USER_PER_MINUTE,
    )
    .await?;
    let caller = ctx.user_id;
    let confirm_state = state.clone();
    let (call, hash) = (tid.clone(), body.arguments_hash);
    let outcome = run_detached("confirm", async move {
        crate::confirm::confirm_tool_call(
            &confirm_state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            ConfirmRequest {
                caller,
                conversation_id: id,
                tool_call_id: &call,
                displayed_hash: &hash,
            },
        )
        .await
    })
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(AppError::Internal(detail)) => {
            // The engine has already returned the proposal to `proposed`
            // (or left it to the lease sweep): nothing ran, and it is
            // confirmable again. Retryable, not a masked 500.
            tracing::warn!(error = %detail, conversation = %id, tool_call = %tid, "confirm: transient failure");
            return Err(AppError::Overloaded(
                "the confirmation could not complete; nothing ran — retry",
            ));
        }
        Err(e) => return Err(e),
    };
    Ok(match outcome {
        ConfirmOutcome::Executed { result } => (
            StatusCode::OK,
            Json(ConfirmExecuted {
                outcome: "executed".into(),
                result,
            }),
        )
            .into_response(),
        ConfirmOutcome::ApprovalRequested {
            approval_request_id,
        } => (
            StatusCode::ACCEPTED,
            Json(ConfirmApprovalRequested {
                outcome: "approval_requested".into(),
                approval_request_id,
            }),
        )
            .into_response(),
        ConfirmOutcome::Refused(refusal) => refusal_response(refusal)?,
    })
}

/// Maps a refusal to its response. `NotFound` is the standard `404`; a
/// transient action failure is the standard retryable `503`; everything else
/// is a [`ConfirmConflict`].
fn refusal_response(refusal: ConfirmRefusal) -> Result<Response, AppError> {
    let conflict_409 =
        |outcome: &str, message: &str| conflict(StatusCode::CONFLICT, outcome, message);
    let response = match refusal {
        ConfirmRefusal::NotFound => return Err(AppError::NotFound),
        ConfirmRefusal::ActionFailed { invalidated: false } => {
            return Err(AppError::Overloaded(
                "the action failed transiently; nothing ran — retry",
            ));
        }
        ConfirmRefusal::StaleHash => conflict_409(
            "stale_hash",
            "the proposal is not the one you were shown; reload it",
        ),
        ConfirmRefusal::Conflict => conflict_409(
            "conflict",
            "the proposal changed while you confirmed it; nothing ran — retry",
        ),
        ConfirmRefusal::InProgress => {
            conflict_409("in_progress", "this proposal is already being executed")
        }
        ConfirmRefusal::AlreadyExecuted { result } => {
            let mut c = conflict_409("already_executed", "this proposal was already executed");
            c.body.result = result;
            c
        }
        ConfirmRefusal::ApprovalPending {
            approval_request_id,
        } => {
            let mut c = conflict_409(
                "approval_pending",
                "this proposal is waiting on a four-eyes approval",
            );
            c.body.approval_request_id = approval_request_id;
            c
        }
        ConfirmRefusal::Terminal { status } => {
            conflict_409(status.as_str(), "this proposal can no longer be confirmed")
        }
        ConfirmRefusal::Invalidated { reason } => conflict_409("invalidated", reason),
        ConfirmRefusal::SessionPaused => conflict_409(
            "session_paused",
            "the agent session is paused; confirm again once it is resumed",
        ),
        ConfirmRefusal::WriteLimitReached => conflict(
            StatusCode::TOO_MANY_REQUESTS,
            "write_limit_reached",
            "the agent session's daily write limit is spent",
        ),
        ConfirmRefusal::ActionFailed { invalidated: true } => conflict_409(
            "action_failed",
            "the action refused these arguments; nothing ran and the proposal is closed",
        ),
        ConfirmRefusal::OutcomeUnrecorded => conflict_409(
            "outcome_unrecorded",
            "the action's outcome could not be recorded; it will not run again",
        ),
    };
    Ok(response.into_response())
}

/// `DELETE /api/v1/ai/conversations/{id}/tool-calls/{tid}` — rejects a
/// pending proposal.
#[utoipa::path(
    delete,
    path = "/api/v1/ai/conversations/{id}/tool-calls/{tid}",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Rejected)])))),
    params(
        ("id" = Uuid, Path, description = "The conversation"),
        ("tid" = String, Path, description = "The proposal's tool_call_id"),
    ),
    responses(
        (status = 204, description = "Rejected"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation or proposal for this caller", body = ErrorResponse),
        (status = 409, description = "The proposal is no longer pending; `outcome` is its status", body = ConfirmConflict),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn reject_tool_call(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((id, tid)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    let conv = owned(&state, id, ctx.user_id).await?;
    Ok(
        match crate::tool_call::reject(&state, conv.id, &tid, ctx.user_id).await? {
            Rejection::Rejected => StatusCode::NO_CONTENT.into_response(),
            Rejection::NotFound => return Err(AppError::NotFound),
            Rejection::NotProposed(status) => conflict(
                StatusCode::CONFLICT,
                status_outcome(status),
                "this proposal is no longer pending",
            )
            .into_response(),
        },
    )
}

fn status_outcome(status: Status) -> &'static str {
    status.as_str()
}

/// `DELETE /api/v1/ai/conversations/{id}` — ends the conversation and revokes
/// its session.
#[utoipa::path(
    delete,
    path = "/api/v1/ai/conversations/{id}",
    tag = "action",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Closed)])))),
    params(("id" = Uuid, Path, description = "The conversation")),
    responses(
        (status = 204, description = "Ended (or already ended)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn end_conversation(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    match conversation::end_and_revoke(&state, id, ctx.user_id).await? {
        EndOutcome::Ended | EndOutcome::AlreadyEnded => Ok(StatusCode::NO_CONTENT),
        EndOutcome::NotFound => Err(AppError::NotFound),
    }
}

// ---------------------------------------------------------------------------
// C10-A — the stream
// ---------------------------------------------------------------------------

/// How long an empty poll waits before reading the log again.
const STREAM_POLL: std::time::Duration = std::time::Duration::from_millis(500);
/// Events read per query.
const STREAM_BATCH: i64 = 200;
/// A stream's bounded lifetime. The client reconnects with its last ordinal
/// (`Last-Event-ID`), which the log makes lossless.
const STREAM_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10 * 60);
const STREAM_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StreamQuery {
    /// Replay events with an ordinal greater than this (exclusive). Absent:
    /// the `Last-Event-ID` header, else `0` — the whole log.
    pub after: Option<i64>,
}

/// One frame's `data`: a stored event, as the stream sends it. The frame's SSE
/// `id` is `ordinal` and its `event` is `type`.
#[derive(Debug, Serialize, ToSchema)]
pub struct StreamEventView {
    /// The stream cursor: gapless per conversation.
    pub ordinal: i64,
    pub turn_id: Option<Uuid>,
    /// One of the nine semantic event types.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The event's stored payload (references and labels, never content).
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    /// `message.completed` only: the message text, read from the message
    /// ledger when the frame is sent — the event row stores no copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// `GET /api/v1/ai/conversations/{id}/stream` — the conversation's semantic
/// events as Server-Sent Events: every stored event after the cursor, in
/// ordinal order, then new ones as they commit (C10-A, I-14, row A-12).
///
/// **Authorized before the first frame (I-20).** The conversation is resolved
/// for the caller before the response starts: an unknown conversation, or
/// someone else's, is an ordinary `404` with no stream.
///
/// **A projection of the log.** Every frame with an `id` is a committed event.
/// Replay and live-follow are one loop over `ordinal > cursor`, and a
/// conversation's events commit in ordinal order, so the handoff from replay
/// to live neither skips nor repeats one.
///
/// **Token deltas (C11 B3).** While following live, the stream also relays
/// `message.delta` frames — `{turn_id, text}`, **with no `id`**, so a delta
/// never moves the client's `Last-Event-ID` and a reconnect replays durable
/// events only (I-14, A-78). A delta for a turn whose `message.completed`
/// this stream has already sent is dropped: the answer supersedes it (A-79).
/// When Redis is unavailable there are no deltas and nothing else changes.
#[utoipa::path(
    get,
    path = "/api/v1/ai/conversations/{id}/stream",
    tag = "action",
    params(("id" = Uuid, Path, description = "The conversation"), StreamQuery),
    responses(
        (status = 200, description = "Server-Sent Events: each frame's `id` is the event ordinal, its `event` the event type, its `data` a StreamEventView", content_type = "text/event-stream", body = StreamEventView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversation for this caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn stream_conversation(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<StreamQuery>,
    headers: axum::http::HeaderMap,
) -> Result<
    axum::response::sse::Sse<
        impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    AppError,
> {
    // Before anything is sent: an unknown or foreign conversation is a 404.
    let conv = owned(&state, id, ctx.user_id).await?;
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok());
    let after = q.after.or(last_event_id).unwrap_or(0).max(0);
    // Subscribed only after the authorization above: a caller who may not see
    // the conversation never reaches the delta feed at all (I-20).
    let deltas = crate::delta_stream::subscribe(&state.base.redis, &state.base.config).await;

    let stream = futures_util::stream::unfold(
        StreamCursor {
            db: state.base.db.clone(),
            conversation_id: conv.id,
            cursor: after,
            pending: std::collections::VecDeque::new(),
            deadline: tokio::time::Instant::now() + STREAM_LIFETIME,
            deltas,
            completed_turns: std::collections::HashSet::new(),
            next_poll: tokio::time::Instant::now(),
        },
        |mut s| async move {
            loop {
                if let Some(event) = s.pending.pop_front() {
                    return Some((Ok(event), s));
                }
                let now = tokio::time::Instant::now();
                if now >= s.deadline {
                    return None;
                }
                if now >= s.next_poll {
                    // Deltas already queued were published before anything
                    // this poll can read was committed (the turn drains its
                    // publisher before writing its answer), so they go out
                    // first — otherwise a fast turn's whole answer would be
                    // read as superseded and dropped.
                    s.drain_deltas();
                    match next_frames(&s.db, s.conversation_id, s.cursor).await {
                        Ok(Some((frames, last, completed))) => {
                            s.cursor = last;
                            s.pending.extend(frames);
                            s.completed_turns.extend(completed);
                            continue;
                        }
                        // Caught up. An ended conversation has nothing more to say.
                        Ok(None) => match conversation_ended(&s.db, s.conversation_id).await {
                            Ok(false) => s.next_poll = now + STREAM_POLL,
                            Ok(true) => return None,
                            Err(error) => {
                                tracing::warn!(%error, "conversation stream: liveness check failed");
                                return None;
                            }
                        },
                        // Ends the stream; the client reconnects from its cursor.
                        Err(error) => {
                            tracing::warn!(%error, "conversation stream: event read failed");
                            return None;
                        }
                    }
                }
                // Wait for the next poll, relaying deltas meanwhile.
                let wake = s.next_poll.min(s.deadline);
                let received = match s.deltas.as_mut() {
                    Some(deltas) => tokio::select! {
                        delta = deltas.recv() => Some(delta),
                        _ = tokio::time::sleep_until(wake) => None,
                    },
                    None => {
                        tokio::time::sleep_until(wake).await;
                        None
                    }
                };
                match received {
                    Some(Ok(delta)) => s.relay(delta),
                    // A slow stream skipped some deltas; the answer is whole.
                    Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                    Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                        s.deltas = None;
                    }
                    None => {}
                }
            }
        },
    );
    Ok(axum::response::sse::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(STREAM_KEEPALIVE)
            .text("keep-alive"),
    ))
}

struct StreamCursor {
    db: sqlx::PgPool,
    conversation_id: Uuid,
    cursor: i64,
    pending: std::collections::VecDeque<axum::response::sse::Event>,
    deadline: tokio::time::Instant,
    /// This process's delta feed, when Redis is reachable (C11 B3).
    deltas: Option<tokio::sync::broadcast::Receiver<crate::delta_stream::Delta>>,
    /// Turns whose `message.completed` this stream has sent. Their deltas are
    /// superseded and dropped.
    completed_turns: std::collections::HashSet<Uuid>,
    next_poll: tokio::time::Instant,
}

impl StreamCursor {
    /// Queues a delta frame, unless it is another conversation's or its
    /// turn's answer has already been sent (A-79).
    fn relay(&mut self, delta: crate::delta_stream::Delta) {
        if delta.conversation_id != self.conversation_id
            || self.completed_turns.contains(&delta.turn_id)
        {
            return;
        }
        if let Ok(data) = serde_json::to_string(&MessageDeltaView {
            turn_id: delta.turn_id,
            text: delta.text,
        }) {
            self.pending.push_back(
                axum::response::sse::Event::default()
                    .event("message.delta")
                    .data(data),
            );
        }
    }

    /// Relays every delta already waiting, without blocking.
    fn drain_deltas(&mut self) {
        loop {
            let next = match self.deltas.as_mut() {
                Some(deltas) => deltas.try_recv(),
                None => return,
            };
            match next {
                Ok(delta) => self.relay(delta),
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => return,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    self.deltas = None;
                    return;
                }
            }
        }
    }
}

/// One `message.delta` frame's `data` (C11 B3). Transport only: the frame
/// carries no `id`, and the text is superseded by the turn's
/// `message.completed`.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessageDeltaView {
    pub turn_id: Uuid,
    /// Text the model produced since the previous delta.
    pub text: String,
}

/// The next batch of frames after `after`, the last ordinal in it, and the
/// turns it completes — or `None` when the log has nothing newer.
type FrameBatch = (Vec<axum::response::sse::Event>, i64, Vec<Uuid>);

async fn next_frames(
    db: &sqlx::PgPool,
    conversation_id: Uuid,
    after: i64,
) -> Result<Option<FrameBatch>, AppError> {
    let rows =
        crate::conversation_event::list_after(db, conversation_id, after, STREAM_BATCH).await?;
    let Some(last) = rows.last().map(|r| r.ordinal) else {
        return Ok(None);
    };
    let mut frames = Vec::with_capacity(rows.len());
    let mut completed = Vec::new();
    for row in rows {
        if row.event_type == "message.completed"
            && let Some(turn_id) = row.turn_id
        {
            completed.push(turn_id);
        }
        // The ledger is the only copy of a message's text.
        let content = if row.event_type == "message.completed" {
            let ordinal = row.payload.get("message_ordinal").and_then(Value::as_i64);
            match ordinal {
                Some(ordinal) => sqlx::query_scalar::<_, String>(
                    "SELECT content FROM ai_message \
                      WHERE conversation_id = $1 AND ordinal = $2",
                )
                .bind(conversation_id)
                .bind(ordinal)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?,
                None => None,
            }
        } else {
            None
        };
        let view = StreamEventView {
            ordinal: row.ordinal,
            turn_id: row.turn_id,
            event_type: row.event_type.clone(),
            payload: row.payload,
            created_at: row.created_at,
            content,
        };
        let data = serde_json::to_string(&view).map_err(AppError::internal)?;
        frames.push(
            axum::response::sse::Event::default()
                .id(row.ordinal.to_string())
                .event(row.event_type)
                .data(data),
        );
    }
    Ok(Some((frames, last, completed)))
}

async fn conversation_ended(db: &sqlx::PgPool, conversation_id: Uuid) -> Result<bool, AppError> {
    let ended: Option<Option<DateTime<Utc>>> =
        sqlx::query_scalar("SELECT ended_at FROM ai_conversation WHERE id = $1")
            .bind(conversation_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(!matches!(ended, Some(None)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ai/conversations",
            post(start_conversation).get(list_conversations),
        )
        .route(
            "/api/v1/ai/conversations/{id}",
            get(get_conversation).delete(end_conversation),
        )
        .route(
            "/api/v1/ai/conversations/{id}/messages",
            post(send_message).get(list_messages),
        )
        .route(
            "/api/v1/ai/conversations/{id}/messages/{message_id}/feedback",
            axum::routing::put(put_feedback),
        )
        .route(
            "/api/v1/ai/conversations/{id}/tool-calls",
            get(list_tool_calls),
        )
        .route(
            "/api/v1/ai/conversations/{id}/tool-calls/{tid}/confirm",
            post(confirm_tool_call),
        )
        .route(
            "/api/v1/ai/conversations/{id}/tool-calls/{tid}",
            axum::routing::delete(reject_tool_call),
        )
        .route(
            "/api/v1/ai/conversations/{id}/stream",
            get(stream_conversation),
        )
        .route("/api/v1/ai/conversations/{id}/runs", post(start_run))
        .route(
            "/api/v1/ai/conversations/{id}/turns/{turn_id}/cancel",
            post(cancel_turn),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        start_conversation,
        list_conversations,
        get_conversation,
        send_message,
        list_messages,
        put_feedback,
        list_tool_calls,
        confirm_tool_call,
        reject_tool_call,
        end_conversation,
        stream_conversation,
        cancel_turn,
        start_run,
    ),
    components(schemas(StartRunRequest, RunStarted))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    fn actions() -> impl Iterator<Item = (String, bool)> {
        [
            ("record.get", false),
            ("record.update", true),
            ("model.form.edit", true),
            ("model.form.describe", false),
        ]
        .into_iter()
        .map(|(id, write)| (id.to_owned(), write))
    }

    #[test]
    fn develop_builds_and_run_acts() {
        assert_eq!(
            mode_actions(Some("develop"), actions()).unwrap().unwrap(),
            ["record.get", "model.form.edit", "model.form.describe"]
        );
        assert_eq!(
            mode_actions(Some("run"), actions()).unwrap().unwrap(),
            ["record.get", "record.update", "model.form.describe"]
        );
        assert!(mode_actions(None, actions()).unwrap().is_none());
        assert!(mode_actions(Some("chaos"), actions()).is_err());
    }
}
