//! Agent sessions and invocation idempotency (TODO-039, TODO-043).
//!
//! **A session is the unit an admin can kill.** Without one, "stop the agent"
//! has no referent: nothing to revoke, no ceiling to lower, and no way to ask
//! "what did it do" as a single question. An agent that can only be stopped by
//! disabling AI for the whole deployment is one nobody will let near production.
//!
//! ## Revocation is checked on the invocation path, and fails closed
//!
//! [`load_live`] returns `None` for a session that is revoked, ended, or absent
//! — and a caller that cannot load a live session cannot dispatch. The check is
//! a read of the row, not a cached flag: revocation must take effect on the
//! **next** invocation, and a cache is exactly the thing that would let a
//! revoked agent finish its loop.
//!
//! A database error here is a refusal, not a pass. That is the one place in
//! this file where the failure direction is stated explicitly, because the
//! ergonomic instinct — "don't fail a user's request because a lookup blipped"
//! — is right nearly everywhere else in the platform and wrong here.
//!
//! ## Idempotency uses data the model does not choose
//!
//! An LLM tool loop retries. A retried `record.create` must not produce two
//! records, and the ordinary HTTP idempotency key does not help: the model is
//! the client, and a key the model chooses is a key the model can vary — by
//! accident, on a retry, which is precisely when it matters.
//!
//! So the key is `(agent_session_id, tool_call_id)`. `tool_call_id` is assigned
//! by the inference API per tool call and is stable across a retry of that call.
//! Neither half is model output.

use attome_types::AppError;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::capability_pack::CapabilityPackRef;
use crate::descriptor::{ActionId, RiskTier};

/// A live agent session.
#[derive(Debug, Clone)]
pub struct AgentSession {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub risk_ceiling: RiskTier,
    /// `None` means "whatever the ceiling permits". An empty `Vec` means
    /// **nothing** — a session an admin has deliberately narrowed to no actions
    /// at all. Collapsing the two would make that session indistinguishable
    /// from an unrestricted one, and the direction that fails is not the safe
    /// one.
    pub allowed_action_ids: Option<Vec<String>>,
    /// M33 Phase 1 (D-460): whether this session was started downstream of
    /// tool-obtained content — an `AgentStep` handoff whose upstream step was
    /// itself tainted, per I-10. One-way, same as
    /// `ActionContext::tainted()`: nothing in this crate ever clears it once
    /// set. See `ActionContext::for_session`, the one place this flows back
    /// into a per-invocation gate decision.
    pub tainted: bool,
    /// D-505 §4: the governance values fixed at start beyond the ceiling and
    /// allow-list above.
    pub policy: PolicySnapshot,
    /// **The session runs as a shared channel principal** (C9, D-558): it was
    /// started for an `integration_system` channel — the public web
    /// widget — whose one service principal owns every anonymous visitor's
    /// session. Derived from the row (`integration_system_id IS NOT NULL`),
    /// never from a request, so no caller can set or clear it.
    ///
    /// What it changes, and only this: `budget_guard` meters the visitor's own
    /// session instead of the shared principal (so one visitor cannot spend
    /// every other visitor's budget, and no visitor escapes a cap by sharing
    /// it), and `turn::run` never offers the channel-owned actions
    /// ([`crate::webchat::CHANNEL_OWNED_ACTIONS`]) to the model.
    pub anonymous_channel: bool,
    /// The surface that opened the session (`agent_session.surface`
    /// — `"mcp"`, `"webchat"`, …), read off the row, never from a request.
    ///
    /// Carried so [`crate::context::ActionContext::for_session`] can tell an
    /// external MCP agent apart from the in-product surfaces: MCP entity
    /// admission (`crate::mcp::admission`, plan item M3.4) applies to the
    /// former only, and must also hold when an approved MCP action runs later
    /// from `execute::dispatch_approved_agent_action_under`, which rebuilds
    /// the context from this row.
    pub surface: String,
}

/// D-505 §4: the governance values a session fixes for its whole life beyond
/// D-503's ceiling and allow-list: the policy it was started under (with that
/// record's `row_version` at the moment), its knowledge scope and its
/// execution limits.
///
/// **Computed once, enforced from here.** `agent::start_session` resolves the
/// definition's policy and combines it into these values (D-505 §4). The
/// enforcement points read only this copy (D-512):
/// - `max_session_duration_minutes`, by [`load_live`], [`load_live_owned`] and
///   [`load_for_execution`], which treat a session past it as gone;
/// - `max_invocations_per_session`, by [`consume_invocation`];
/// - `max_writes_per_day`, session-wide, by [`reserve_session_write`];
/// - `max_tokens_per_session`, by `budget_guard`;
/// - `knowledge_source_refs`, by retrieval;
/// - `retrieval_mode`, by `turn::run` — whether knowledge is retrieved before
///   the first model call or left to the model's tools (D-561 §5).
///
/// Every field is an `Option` only because a session not started from a
/// definition (MCP, webchat), and every session opened before migration 0466,
/// has no policy term. This struct does not decide which `None` combinations
/// are legal for a *new* definition-started session; `start_session` does.
///
/// `knowledge_source_refs` follows `allowed_action_ids`' rule: `None` means no
/// narrowing from this snapshot, `Some(vec![])` means no knowledge retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    /// The `ai_agent_policy` record the session was started under.
    /// Traceability only, with no foreign key (migration 0466): editing or
    /// deleting the policy must never reach this session.
    pub policy_ref: Option<Uuid>,
    /// That policy's `row_version` when the session started. Present exactly
    /// when `policy_ref` is (`agent_session_policy_pair`).
    pub policy_row_version: Option<i64>,
    pub knowledge_source_refs: Option<Vec<Uuid>>,
    /// D-556 §2: the capability packs that contributed to
    /// `AgentSession::allowed_action_ids`, each with the `row_version` it held
    /// when the session started. **Provenance only** — the resolved ids above
    /// are authoritative and nothing reads this for authorization. `None`
    /// means no pack contributed.
    pub capability_pack_refs: Option<Vec<CapabilityPackRef>>,
    pub max_invocations_per_session: Option<i32>,
    pub max_writes_per_day: Option<i32>,
    pub max_tokens_per_session: Option<i64>,
    pub max_session_duration_minutes: Option<i32>,
    /// D-561 §5: how this session retrieves knowledge, resolved from the agent
    /// definition when the session starts and fixed for its whole life. Not an
    /// `Option`: every session has a mode, and a session started without a
    /// definition (MCP, webchat), or before migration 0481, has D-561's
    /// default, [`KnowledgeRetrievalMode::ToolInvoked`].
    pub retrieval_mode: KnowledgeRetrievalMode,
    /// C11 B2 (P-2): the persona composed from the agent definition when the
    /// session started (`agent::compose_persona`), fixed for the session so
    /// editing the definition changes the next session only. `None` for a
    /// session started without a definition, or before migration 0490.
    ///
    /// **Style, never authority.** Nothing on the dispatch path reads it: it
    /// reaches the model only inside `prompt.rs`'s persona frame, after the
    /// code-owned instructions and behind the notice that it grants nothing
    /// (I-4, D-503 §6).
    pub persona: Option<String>,
}

/// D-561 §5 — how a session retrieves knowledge. Resolved once, at session
/// start, from the agent definition's `retrieval_mode`, and immutable for the
/// session. Nothing a user or a model sends can change it.
///
/// Distinct from `attome_search::RetrievalMode` (lexical / vector / fused), which
/// is *how* a retrieval ranks; this is *when* a session retrieves at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KnowledgeRetrievalMode {
    /// The default. `search.knowledge` and `knowledge.answer` are in the tool
    /// list and the model decides when to retrieve.
    #[default]
    ToolInvoked,
    /// Knowledge is retrieved before the first model call of each turn, and
    /// the retrieval tools are **not** also offered (D-561 §5).
    PreRetrieved,
}

impl KnowledgeRetrievalMode {
    /// The stored value (`agent_session.retrieval_mode`, the agent
    /// definition's `retrieval_mode` choice).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolInvoked => "tool_invoked",
            Self::PreRetrieved => "pre_retrieved",
        }
    }

    /// Parses a stored value. `None` for anything else — the caller decides
    /// whether that is a refusal (a definition) or a default (a row the
    /// column's CHECK already constrains).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tool_invoked" => Some(Self::ToolInvoked),
            "pre_retrieved" => Some(Self::PreRetrieved),
            _ => None,
        }
    }
}

impl PolicySnapshot {
    /// No policy term and no snapshot limits. Written out at each start site
    /// rather than defaulted, so "this session has no governance snapshot"
    /// is always a visible choice.
    pub const NONE: PolicySnapshot = PolicySnapshot {
        policy_ref: None,
        policy_row_version: None,
        knowledge_source_refs: None,
        capability_pack_refs: None,
        max_invocations_per_session: None,
        max_writes_per_day: None,
        max_tokens_per_session: None,
        max_session_duration_minutes: None,
        retrieval_mode: KnowledgeRetrievalMode::ToolInvoked,
        persona: None,
    };
}

impl AgentSession {
    /// Whether this session may invoke `action`, by id.
    ///
    /// The **ceiling** is checked by the gate, not here: this is the allow-list
    /// half only, and keeping the two separate means neither can be mistaken
    /// for the whole check. `gate::evaluate` is the one enforcement point.
    pub fn permits(&self, action: ActionId) -> bool {
        allow_list_permits(self.allowed_action_ids.as_deref(), action)
    }
}

/// The allow-list rule, shared by [`AgentSession::permits`] and
/// `ActionContext::session_permits` (which `gate::admissible` enforces) so the
/// two can never disagree. `None` permits; a list permits only exact ids.
pub(crate) fn allow_list_permits(allowed: Option<&[String]>, action: ActionId) -> bool {
    match allowed {
        None => true,
        Some(ids) => ids.iter().any(|id| id == action.0),
    }
}

fn tier_from_i16(v: i16) -> RiskTier {
    match v {
        1 => RiskTier::Reversible,
        2 => RiskTier::Consequential,
        // Anything unexpected reads as the narrowest tier. A corrupted or
        // future value must not widen what an agent may do.
        _ => RiskTier::Read,
    }
}

/// The columns every session loader selects, matching [`SessionRow`]. A macro
/// rather than a `const`, so each query stays a single `concat!`-built
/// `&'static str` and no part of a session SELECT is assembled at runtime.
macro_rules! session_columns {
    () => {
        "id, owner_user_id, risk_ceiling, allowed_action_ids, tainted, policy_ref, \
         policy_row_version, knowledge_source_refs, capability_pack_refs, \
         max_invocations_per_session, max_writes_per_day, max_tokens_per_session, \
         max_session_duration_minutes, retrieval_mode, persona_snapshot, \
         (integration_system_id IS NOT NULL) AS anonymous_channel, surface"
    };
}

/// SQL that is true when a session has outlived its policy's duration (D-512
/// §6): a session with `max_session_duration_minutes` is live only while
/// `now < started_at + duration`. A session with no duration limit never
/// expires this way. A macro for the same reason as `session_columns!`.
macro_rules! session_expired {
    () => {
        "(max_session_duration_minutes IS NOT NULL \
          AND NOW() >= started_at + make_interval(mins => max_session_duration_minutes))"
    };
}

/// The liveness predicate every loader and [`consume_invocation`] share, so
/// they cannot disagree about what "live" means: not ended, not revoked, not
/// paused, not past its duration.
macro_rules! session_live {
    () => {
        concat!(
            "ended_at IS NULL AND revoked_at IS NULL AND paused_at IS NULL AND NOT ",
            session_expired!()
        )
    };
}

/// One `agent_session` row as the loaders read it: a struct rather
/// than a tuple, now that the D-505 snapshot makes a tuple unreadable.
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    owner_user_id: Uuid,
    risk_ceiling: i16,
    allowed_action_ids: Option<Vec<String>>,
    tainted: bool,
    policy_ref: Option<Uuid>,
    policy_row_version: Option<i64>,
    knowledge_source_refs: Option<Vec<Uuid>>,
    capability_pack_refs: Option<Value>,
    max_invocations_per_session: Option<i32>,
    max_writes_per_day: Option<i32>,
    max_tokens_per_session: Option<i64>,
    max_session_duration_minutes: Option<i32>,
    retrieval_mode: String,
    persona_snapshot: Option<String>,
    anonymous_channel: bool,
    surface: String,
}

impl From<SessionRow> for AgentSession {
    fn from(row: SessionRow) -> Self {
        AgentSession {
            id: row.id,
            owner_user_id: row.owner_user_id,
            risk_ceiling: tier_from_i16(row.risk_ceiling),
            allowed_action_ids: row.allowed_action_ids,
            tainted: row.tainted,
            anonymous_channel: row.anonymous_channel,
            surface: row.surface,
            policy: PolicySnapshot {
                policy_ref: row.policy_ref,
                policy_row_version: row.policy_row_version,
                knowledge_source_refs: row.knowledge_source_refs,
                // Provenance only, so a malformed value degrades to "no
                // provenance recorded" rather than refusing to load a live
                // session — it can never widen what the session may do, and
                // the column's own CHECK already constrains it to an array.
                capability_pack_refs: match row.capability_pack_refs {
                    None | Some(Value::Null) => None,
                    Some(value) => match serde_json::from_value::<Vec<CapabilityPackRef>>(value) {
                        Ok(refs) => Some(refs),
                        Err(error) => {
                            tracing::error!(
                                %error,
                                "agent session capability_pack_refs is not a pack-ref array; \
                                 loading no provenance"
                            );
                            None
                        }
                    },
                },
                max_invocations_per_session: row.max_invocations_per_session,
                max_writes_per_day: row.max_writes_per_day,
                max_tokens_per_session: row.max_tokens_per_session,
                max_session_duration_minutes: row.max_session_duration_minutes,
                // The column is NOT NULL with a CHECK on these two values
                // (0481), so the fallback is unreachable in practice; it is
                // the default rather than a refusal because the mode is not
                // an authority and a live session must still load.
                retrieval_mode: KnowledgeRetrievalMode::parse(&row.retrieval_mode).unwrap_or_else(
                    || {
                        tracing::error!(
                            value = %row.retrieval_mode,
                            "agent session retrieval_mode is not a known mode; using tool_invoked"
                        );
                        KnowledgeRetrievalMode::ToolInvoked
                    },
                ),
                persona: row.persona_snapshot,
            },
        }
    }
}

/// Loads a session **only if it is live**.
///
/// `Ok(None)` for revoked, ended, PAUSED, expired (past its policy duration,
/// D-512 §6), or absent — states a caller has no reason to distinguish, and
/// distinguishing them at this boundary would invite a caller to treat one of
/// them as recoverable. Pause joins revoke here deliberately (M33 Phase 1,
/// D-460): a paused session must be exactly as inert as a killed one to
/// anything that dispatches on its behalf — the difference between them is
/// only that a paused session can be resumed, which is a fact about
/// `session::resume`, not about what `load_live` returns while it is paused.
///
/// An error is returned rather than swallowed so the caller refuses. See the
/// module doc.
pub async fn load_live(db: &PgPool, session_id: Uuid) -> Result<Option<AgentSession>, AppError> {
    let row: Option<SessionRow> = sqlx::query_as(concat!(
        "SELECT ",
        session_columns!(),
        " FROM agent_session WHERE id = $1 AND ",
        session_live!(),
    ))
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(AgentSession::from))
}

/// [`load_live`], restricted to a session **owned by `owner_user_id` and
/// opened on `surface`**.
///
/// For a surface where the caller names the session by id (MCP's
/// `Mcp-Session-Id` header). A session carries security state of its own —
/// its ceiling, its allow-list, and above all its taint flag — so a session id
/// is not a bearer token: presenting someone else's untainted session would
/// let a caller's agent writes skip the confirm-first step their own session
/// imposes. The surface binding closes the same hole for a caller's *own*
/// session opened elsewhere (a webchat conversation starts untainted, an MCP
/// session never does).
///
/// Another user's session, a different surface's session, and a session that
/// does not exist all return `Ok(None)` — distinguishing them would confirm to
/// a caller that a guessed id belongs to someone.
pub async fn load_live_owned(
    db: &PgPool,
    session_id: Uuid,
    owner_user_id: Uuid,
    surface: &str,
) -> Result<Option<AgentSession>, AppError> {
    let row: Option<SessionRow> = sqlx::query_as(concat!(
        "SELECT ",
        session_columns!(),
        " FROM agent_session \
          WHERE id = $1 AND owner_user_id = $2 AND surface = $3 AND ",
        session_live!(),
    ))
    .bind(session_id)
    .bind(owner_user_id)
    .bind(surface)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(AgentSession::from))
}

/// What executing an already-approved agent action finds when it looks up the
/// session that asked for it (D-502).
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "a short-lived return value, matched once and never stored or collected; boxing the live session would only add an allocation per approved execution"
)]
pub enum SessionForExecution {
    /// Runnable now.
    Live(AgentSession),
    /// Temporarily not runnable. A paused session can be resumed
    /// (`session::resume`), so work waiting on it must keep waiting — "not
    /// now", not "never".
    Paused,
    /// Revoked, ended, past its policy duration (D-512 §6), or absent. Never
    /// runnable again.
    Gone,
}

/// [`SessionRow`] plus the two stop states [`load_for_execution`] tells apart.
#[derive(sqlx::FromRow)]
struct ExecutionSessionRow {
    #[sqlx(flatten)]
    session: SessionRow,
    dead: bool,
    paused: bool,
}

/// A session's governance snapshot and its state, whatever that state is —
/// the read `GET /ai/conversations/{id}` shows. Unlike [`load_live`] and
/// [`load_for_execution`] it never collapses a paused or dead session into
/// "absent": an operator reading a conversation needs to see what governed
/// it even after it stopped.
#[derive(Debug, Clone)]
pub struct SessionGovernance {
    pub session: AgentSession,
    /// Ended, revoked, or past its policy duration. Never runnable again.
    pub dead: bool,
    pub paused: bool,
}

/// See [`SessionGovernance`]. Same columns and the same dead/paused
/// predicate as [`load_for_execution`].
pub async fn load_governance(
    db: &PgPool,
    session_id: Uuid,
) -> Result<Option<SessionGovernance>, AppError> {
    let row: Option<ExecutionSessionRow> = sqlx::query_as(concat!(
        "SELECT ",
        session_columns!(),
        ", (ended_at IS NOT NULL OR revoked_at IS NOT NULL OR ",
        session_expired!(),
        ") AS dead, paused_at IS NOT NULL AS paused \
           FROM agent_session \
          WHERE id = $1",
    ))
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|row| SessionGovernance {
        dead: row.dead,
        paused: row.paused,
        session: row.session.into(),
    }))
}

/// [`load_for_execution`], read **inside the caller's transaction** under
/// `FOR SHARE` — the confirm path's check transaction (row A-41).
///
/// The lock is what makes the check and the transition it causes atomic: a
/// revoke, pause or kill of this session being committed concurrently must
/// wait for the caller's transaction, so it is either seen here (committed
/// first) or takes effect after the caller commits (and applies to the next
/// admission). **Lock order (C4):** this session row first, then the
/// account row — no C4 path may take them in the opposite order.
pub async fn lock_for_confirmation(
    tx: &mut sqlx::PgConnection,
    session_id: Uuid,
) -> Result<SessionForExecution, AppError> {
    let row: Option<ExecutionSessionRow> = sqlx::query_as(concat!(
        "SELECT ",
        session_columns!(),
        ", (ended_at IS NOT NULL OR revoked_at IS NOT NULL OR ",
        session_expired!(),
        ") AS dead, paused_at IS NOT NULL AS paused \
           FROM agent_session \
          WHERE id = $1 \
          FOR SHARE",
    ))
    .bind(session_id)
    .fetch_optional(tx)
    .await
    .map_err(AppError::internal)?;
    Ok(match row {
        None => SessionForExecution::Gone,
        Some(ExecutionSessionRow { dead: true, .. }) => SessionForExecution::Gone,
        Some(ExecutionSessionRow { paused: true, .. }) => SessionForExecution::Paused,
        Some(row) => SessionForExecution::Live(row.session.into()),
    })
}

/// [`load_live`], but telling a **paused** session apart from a dead one.
///
/// `load_live` deliberately collapses the two (a paused session must be as
/// inert as a killed one to anything that dispatches on its behalf), and every
/// dispatching caller keeps using it. This exists for the one caller whose
/// *follow-up* differs: running an approved agent action. A killed session's
/// approvals must die with it, but a paused session's approvals must survive
/// the pause — invalidating them would turn a supervisor's one-minute pause
/// into a permanent loss of every pending approval (D-502).
pub async fn load_for_execution(
    db: &PgPool,
    session_id: Uuid,
) -> Result<SessionForExecution, AppError> {
    let row: Option<ExecutionSessionRow> = sqlx::query_as(concat!(
        "SELECT ",
        session_columns!(),
        ", (ended_at IS NOT NULL OR revoked_at IS NOT NULL OR ",
        session_expired!(),
        ") AS dead, paused_at IS NOT NULL AS paused \
           FROM agent_session \
          WHERE id = $1",
    ))
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(match row {
        None => SessionForExecution::Gone,
        // Dead wins over paused: a session paused and then killed is killed,
        // and a paused session whose duration ran out is gone (D-512 §6).
        Some(ExecutionSessionRow { dead: true, .. }) => SessionForExecution::Gone,
        Some(ExecutionSessionRow { paused: true, .. }) => SessionForExecution::Paused,
        Some(row) => SessionForExecution::Live(row.session.into()),
    })
}

/// Everything needed to open a new session (TODO-039/M32 Phase 1, D-450).
///
/// A plain struct, not positional arguments, for the same reason
/// [`InvocationRecord`] is one: several fields are `Option`/`&str` and a
/// transposed pair would compile.
pub struct SessionStart<'a> {
    pub owner_user_id: Uuid,
    pub risk_ceiling: RiskTier,
    pub allowed_action_ids: Option<Vec<String>>,
    /// What opened it, for the audit trail and for an operator triaging
    /// "which surface is doing this" — the same column `0120`'s header
    /// documents.
    pub surface: &'a str,
    /// The `ai_agent` definition this session was started from, or `None`
    /// for a session opened directly (the read-only chatbot's sessions, or
    /// any future surface that does not go through a definition). Purely
    /// traceability — see migration `0253`'s header for why it carries no
    /// foreign key.
    pub agent_definition_ref: Option<Uuid>,
    /// The `integration_system` (kind = channel) this conversation arrived
    /// through, or `None` for a session that is not a channel conversation.
    /// Traceability only, no foreign key — same reasoning as
    /// `agent_definition_ref` (migration `0456`).
    pub integration_system_id: Option<Uuid>,
    /// M33 Phase 1 (D-460): whether this session starts downstream of
    /// tool-obtained content. A required field, not a default — the same
    /// "cannot be forgotten" reasoning `risk_ceiling` above already uses:
    /// a caller that starts a session from a tainted handoff and never
    /// considers the question would otherwise silently get `false`, which is
    /// exactly the "structured re-packaging clears trust" failure I-10
    /// exists to prevent.
    pub tainted: bool,
    /// D-505 §4 governance snapshot. Required, for the same reason `tainted`
    /// is: a surface with no policy term writes [`PolicySnapshot::NONE`]
    /// explicitly rather than inheriting a silent default.
    pub policy: PolicySnapshot,
}

impl std::fmt::Debug for SessionStart<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStart").finish_non_exhaustive()
    }
}

fn risk_tier_to_i16(tier: RiskTier) -> i16 {
    match tier {
        RiskTier::Read => 0,
        RiskTier::Reversible => 1,
        RiskTier::Consequential => 2,
    }
}

/// Opens a new session with the given constraints, already resolved by the
/// caller.
///
/// **This is not itself the "start from a definition" endpoint.** It is the
/// one place that actually inserts a `agent_session` row — the
/// primitive `crate::agent::start_session` (M32 Phase 1's HTTP route) and
/// `attome_workflow`'s `AgentStep` node both call, after each resolves an
/// `ai_agent` definition into the three values below. Keeping the insert
/// here, rather than duplicated at each call site, is what keeps "a session
/// is the unit an admin can kill" a single implementation: every session,
/// however it was opened, ends up as one row in this table, checked by the
/// same [`load_live`]/[`revoke`] this module already has.
///
/// Opening a session grants an agent authority, so the insert and its
/// mandatory `Ai` + `Create` audit event commit together (D-541 rule 4, G3-2a;
/// D-062). `audit` is normally `attome_audit::audit_service(state)`.
pub async fn start(
    db: &PgPool,
    audit: &attome_audit::AuditService<'_>,
    start: SessionStart<'_>,
) -> Result<AgentSession, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    // The pack provenance is stored as the JSONB array migration 0480 added.
    // `None` binds SQL NULL ("no pack contributed") and `Some(vec![])` binds
    // `[]` — the two are never collapsed, matching the rule the rest of the
    // snapshot follows.
    let capability_pack_refs: Option<Value> = start
        .policy
        .capability_pack_refs
        .as_ref()
        .map(|refs| serde_json::to_value(refs).map_err(AppError::internal))
        .transpose()?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_session \
            (owner_user_id, risk_ceiling, allowed_action_ids, surface, agent_definition_ref, \
             integration_system_id, tainted, policy_ref, policy_row_version, \
             knowledge_source_refs, capability_pack_refs, max_invocations_per_session, \
             max_writes_per_day, max_tokens_per_session, max_session_duration_minutes, \
             retrieval_mode, persona_snapshot) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) \
         RETURNING id",
    )
    .bind(start.owner_user_id)
    .bind(risk_tier_to_i16(start.risk_ceiling))
    .bind(&start.allowed_action_ids)
    .bind(start.surface)
    .bind(start.agent_definition_ref)
    .bind(start.integration_system_id)
    .bind(start.tainted)
    .bind(start.policy.policy_ref)
    .bind(start.policy.policy_row_version)
    .bind(&start.policy.knowledge_source_refs)
    .bind(capability_pack_refs)
    .bind(start.policy.max_invocations_per_session)
    .bind(start.policy.max_writes_per_day)
    .bind(start.policy.max_tokens_per_session)
    .bind(start.policy.max_session_duration_minutes)
    .bind(start.policy.retrieval_mode.as_str())
    .bind(start.policy.persona.as_deref())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Create,
        start.owner_user_id,
        "agent_session",
        Some(id),
    )
    .named(format!("agent_session.start.{}", start.surface))
    .comment(format!(
        "ceiling {:?}, definition {}, tainted {}",
        start.risk_ceiling,
        start
            .agent_definition_ref
            .map_or_else(|| "none".to_string(), |d| d.to_string()),
        start.tainted
    ));
    attome_audit::security::write_security_event(&mut tx, audit, event).await?;
    attome_db::tx::commit(tx).await?;

    Ok(AgentSession {
        id,
        owner_user_id: start.owner_user_id,
        risk_ceiling: start.risk_ceiling,
        allowed_action_ids: start.allowed_action_ids,
        tainted: start.tainted,
        policy: start.policy,
        anonymous_channel: start.integration_system_id.is_some(),
        surface: start.surface.to_owned(),
    })
}

/// What raising a session's invocation counter decided (D-512 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationAdmission {
    /// Counted; the call proceeds to the gate.
    Admitted,
    /// The session is not live (absent, paused, revoked, ended or expired).
    /// Nothing was counted.
    NotLive,
    /// The session's `max_invocations_per_session` is used up. Nothing was
    /// counted and nothing may run.
    LimitReached,
}

/// Consumes one unit of a session's invocation budget, **before** the gate
/// evaluates the call (D-512 §4; the counter is migration 0467's).
///
/// One conditional `UPDATE`: Postgres checks liveness and the limit and raises
/// the counter in the same statement, under the row lock the update takes, so
/// concurrent calls cannot overshoot the limit. The counter is raised for a
/// session with no limit too (usage accounting); only a limit refuses.
///
/// This is not idempotency state. The D-502 invocation ledger is untouched,
/// and a repeated tool call consumes budget again even when D-502 replays its
/// recorded result.
pub async fn consume_invocation(
    db: &PgPool,
    session_id: Uuid,
) -> Result<InvocationAdmission, AppError> {
    let counted: Option<i64> = sqlx::query_scalar(concat!(
        "UPDATE agent_session SET invocations_used = invocations_used + 1 \
          WHERE id = $1 AND ",
        session_live!(),
        " AND (max_invocations_per_session IS NULL \
               OR invocations_used < max_invocations_per_session) \
          RETURNING invocations_used",
    ))
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if counted.is_some() {
        return Ok(InvocationAdmission::Admitted);
    }

    // Nothing was counted. Only the refusal's kind is left to tell apart, and
    // both kinds refuse, so a concurrent state change between the two
    // statements cannot let a call through.
    let still_live: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS (SELECT 1 FROM agent_session WHERE id = $1 AND ",
        session_live!(),
        ")",
    ))
    .bind(session_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(if still_live {
        InvocationAdmission::LimitReached
    } else {
        InvocationAdmission::NotLive
    })
}

/// What reserving a write against a session's daily write total decided
/// (D-512 §3).
#[derive(Debug)]
pub enum WriteReservation {
    /// The session has no `max_writes_per_day` (no policy term). Nothing was
    /// reserved; the caller takes its ordinary D-502 path.
    Unlimited,
    /// A ledger row was claimed for this write inside the limit. The caller
    /// completes or releases it exactly as it would a D-502 claim.
    Reserved(Uuid),
    /// This exact tool call was already claimed. Nothing was reserved and no
    /// budget is consumed; the caller replays it (D-502).
    Existing(PriorInvocation),
    /// The session-wide total is used up for today. Nothing was reserved.
    LimitReached,
}

/// Reserves one agent write against the session-wide `max_writes_per_day`
/// total (D-512 §3), **atomically**.
///
/// The total is the session's agent write invocations since UTC midnight in
/// the D-502 ledger: `completed` rows, plus `claimed` rows still in flight —
/// an in-flight write must hold its place, or two concurrent writes could both
/// see room for one. The check and the claim happen in one short transaction
/// holding the session row's lock (`FOR UPDATE`), so concurrent writes for one
/// session serialize here and cannot both take the last slot. A failed write
/// releases its claim (`release_invocation`), freeing the slot.
///
/// `tool_call_id` is the D-502 key when there is one. `None` claims an
/// unkeyed row, which the caller completes or releases by id like any claim.
///
/// The per-(session, action) daily and per-minute caps are unchanged and
/// still apply inside each executor.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub async fn reserve_session_write(
    db: &PgPool,
    session_id: Uuid,
    tool_call_id: Option<&str>,
    action_id: ActionId,
    acting_user_id: Uuid,
) -> Result<WriteReservation, AppError> {
    let midnight_utc = chrono::Utc::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("00:00:00 is always a valid time")
        .and_utc();

    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<ReservationLimits> = sqlx::query_as(
        "SELECT max_writes_per_day, agent_object_ref, daily_class_limits \
         FROM agent_session WHERE id = $1 FOR UPDATE",
    )
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(ReservationLimits {
        max_writes_per_day: limit,
        agent_object_ref: agent_object,
        daily_class_limits: daily,
    }) = row
    else {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(WriteReservation::Unlimited);
    };
    // V2-D487 / AH4: the agent's own per-class daily cap, counted across all
    // of its sessions.
    let class_limit = agent_object.zip(daily.as_ref()).and_then(|(agent, daily)| {
        class_cap(daily, action_id).map(|(class, cap)| (agent, class, cap))
    });
    if limit.is_none() && class_limit.is_none() {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(WriteReservation::Unlimited);
    }

    if let Some(key) = tool_call_id {
        let prior: Option<(String, Option<Value>)> = sqlx::query_as(
            "SELECT outcome, result FROM action_invocation \
              WHERE agent_session_id = $1 AND tool_call_id = $2",
        )
        .bind(session_id)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if let Some((outcome, result)) = prior {
            tx.rollback().await.map_err(AppError::internal)?;
            return Ok(WriteReservation::Existing(PriorInvocation {
                outcome,
                result,
            }));
        }
    }

    if let Some(limit) = limit {
        let used: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM action_invocation \
              WHERE agent_session_id = $1 AND initiator = 1 AND created_at >= $2 \
                AND outcome IN ($3, $4)",
        )
        .bind(session_id)
        .bind(midnight_utc)
        .bind(OUTCOME_COMPLETED)
        .bind(OUTCOME_CLAIMED)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if used >= i64::from(limit) {
            tx.rollback().await.map_err(AppError::internal)?;
            tracing::warn!(
                session_id = %session_id,
                action_id = %action_id,
                used,
                limit,
                "session-wide daily write limit reached for this agent session"
            );
            return Ok(WriteReservation::LimitReached);
        }
    }

    if let Some((agent, class, cap)) = class_limit {
        // Serialises this agent's reservations across its sessions, so two
        // sessions cannot both take the last unit of a cap.
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-ai/agent-daily:{agent}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            tx.rollback().await.map_err(AppError::internal)?;
            return Err(AppError::Conflict(
                "another step of this agent is being reserved; retry",
            ));
        }
        let ids = crate::engine::REGISTRY.ids_of_class(class);
        let used: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM action_invocation i \
             JOIN agent_session s ON s.id = i.agent_session_id \
             WHERE s.agent_object_ref = $1 AND i.action_id = ANY($2) \
               AND i.created_at >= $3 AND i.outcome IN ($4, $5)",
        )
        .bind(agent)
        .bind(&ids)
        .bind(midnight_utc)
        .bind(OUTCOME_COMPLETED)
        .bind(OUTCOME_CLAIMED)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if used >= cap {
            tx.rollback().await.map_err(AppError::internal)?;
            tracing::warn!(
                session_id = %session_id,
                agent = %agent,
                action_id = %action_id,
                ?class,
                used,
                cap,
                "the agent's daily limit for this kind of step is reached"
            );
            return Ok(WriteReservation::LimitReached);
        }
    }

    // The session row lock serializes every reservation for this session, so
    // the only possible conflict is an approval submission's claim for the
    // same key, which never takes this path.
    let claimed: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO action_invocation \
            (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome) \
         VALUES ($1, $2, $3, 1, $4, $5) \
         ON CONFLICT DO NOTHING \
         RETURNING id",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .bind(action_id.0)
    .bind(acting_user_id)
    .bind(OUTCOME_CLAIMED)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = claimed else {
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(AppError::Conflict(
            "this tool call is being retried concurrently; retry it again",
        ));
    };
    tx.commit().await.map_err(AppError::internal)?;
    Ok(WriteReservation::Reserved(id))
}

/// What a write reservation reads from its session row.
#[derive(sqlx::FromRow)]
struct ReservationLimits {
    max_writes_per_day: Option<i32>,
    agent_object_ref: Option<Uuid>,
    daily_class_limits: Option<Value>,
}

/// The agent definition's daily cap for `action_id`'s limit class, when it
/// sets one (V2-D487): `daily_class_limits` is the agent object's
/// `limits.daily`, snapshotted at start.
fn class_cap(daily: &Value, action_id: ActionId) -> Option<(crate::descriptor::LimitClass, i64)> {
    use crate::descriptor::LimitClass;
    let class = crate::engine::REGISTRY.resolve(action_id.0)?.limit_class();
    let key = match class {
        LimitClass::None => return None,
        LimitClass::RecordChange => "record_changes",
        LimitClass::Delete => "deletes",
        LimitClass::MessageSend => "messages",
        LimitClass::ExternalCall => "external_calls",
    };
    let cap = daily.get(key)?.as_u64()?;
    Some((class, i64::try_from(cap).unwrap_or(i64::MAX)))
}

/// Records the agent object a session runs under and snapshots its daily
/// limits (V2-D487), right after the session starts. A later edit of the
/// agent never reaches a running session.
pub async fn attach_agent_object(
    db: &PgPool,
    session_id: Uuid,
    agent: Uuid,
    daily: Option<Value>,
) -> Result<(), AppError> {
    let updated = sqlx::query(
        "UPDATE agent_session SET agent_object_ref = $2, daily_class_limits = $3 WHERE id = $1",
    )
    .bind(session_id)
    .bind(agent)
    .bind(daily)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(AppError::internal("the new agent session row is missing"))
    }
}

/// Revokes a session. Idempotent: the first revocation stands.
///
/// A timestamp rather than a boolean, because an auditor asking "was this
/// session live when that write happened" needs the moment and a boolean
/// discards it.
pub async fn revoke(
    db: &PgPool,
    session_id: Uuid,
    revoked_by: Uuid,
    reason: &str,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE agent_session \
            SET revoked_at = NOW(), revoked_by = $2, revoked_reason = $3 \
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(revoked_by)
    .bind(reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Pauses a live session (M33 Phase 1, D-460 — a supervisor's `agent.pause`).
///
/// Idempotent in the same sense `revoke` is: pausing an already-paused,
/// revoked, or ended session no-ops (`Ok(false)`) rather than erroring — a
/// supervisor clicking pause twice, or racing a session that just ended on
/// its own, is not a caller error. Refuses to pause a session that is already
/// revoked or ended (the `WHERE` clause excludes them): there is nothing to
/// freeze on a session that can never run again.
pub async fn pause(
    db: &PgPool,
    session_id: Uuid,
    paused_by: Uuid,
    reason: &str,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE agent_session \
            SET paused_at = NOW(), paused_by = $2, paused_reason = $3 \
          WHERE id = $1 AND paused_at IS NULL AND revoked_at IS NULL AND ended_at IS NULL",
    )
    .bind(session_id)
    .bind(paused_by)
    .bind(reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Resumes a paused session. Idempotent: resuming a session that is not
/// currently paused (never paused, or already resumed) no-ops. Cannot resume
/// a revoked session — killed is permanent, matching `session.rs`'s own "a
/// session is the unit an admin can kill" doc comment; pause and revoke are
/// deliberately asymmetric.
pub async fn resume(db: &PgPool, session_id: Uuid) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE agent_session \
            SET paused_at = NULL, paused_by = NULL, paused_reason = NULL \
          WHERE id = $1 AND paused_at IS NOT NULL AND revoked_at IS NULL AND ended_at IS NULL",
    )
    .bind(session_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Claims a conversation's one-shot "handed off to a human" slot.
///
/// `Ok(true)` means this caller won and must perform the handoff; `Ok(false)`
/// means another request already claimed it (or an earlier one already handed
/// off) and the caller treats the session as handed off without doing more.
/// One atomic conditional UPDATE rather than an advisory lock: the caller's
/// next step (`bot.handoff` dispatch) opens its own transaction, and a lock
/// held across that would be a guard across an unrelated operation for no
/// benefit `rows_affected` does not already give (guidelines §2).
pub async fn claim_handoff(db: &PgPool, session_id: Uuid) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE agent_session SET handed_off_at = NOW() \
          WHERE id = $1 AND handed_off_at IS NULL",
    )
    .bind(session_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Records the work request a handoff created, so later messages in the
/// conversation can anchor to it.
pub async fn set_work_request_ref(
    db: &PgPool,
    session_id: Uuid,
    work_request_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE agent_session SET work_request_ref = $1 WHERE id = $2")
        .bind(work_request_id)
        .bind(session_id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// What a previous invocation of the same tool call produced.
#[derive(Debug, Clone)]
pub struct PriorInvocation {
    pub outcome: String,
    pub result: Option<Value>,
}

/// Looks up a prior invocation of this exact tool call.
///
/// `Some` means **do not run the action** — return what it produced. That
/// includes a `requires_approval` outcome with no result: re-running would
/// create a second approval request for one intent, and an approver seeing two
/// identical requests cannot tell which is real.
pub async fn prior_invocation(
    db: &PgPool,
    session_id: Uuid,
    tool_call_id: &str,
) -> Result<Option<PriorInvocation>, AppError> {
    let row: Option<(String, Option<Value>)> = sqlx::query_as(
        "SELECT outcome, result FROM action_invocation \
          WHERE agent_session_id = $1 AND tool_call_id = $2",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(outcome, result)| PriorInvocation { outcome, result }))
}

/// Ledger `outcome` for a key whose side effect has been claimed and is
/// running (or crashed mid-run). Never a replayable result.
pub const OUTCOME_CLAIMED: &str = "claimed";
/// Ledger `outcome` for a completed invocation; `result` is its payload.
pub const OUTCOME_COMPLETED: &str = "completed";
/// Ledger `outcome` for an invocation that raised a four-eyes request;
/// `result` is `{"approval_id": ...}`.
pub const OUTCOME_REQUIRES_APPROVAL: &str = "requires_approval";

/// The identity of one agent tool call, for [`claim_invocation`].
pub struct InvocationKey<'a> {
    pub session_id: Uuid,
    pub tool_call_id: &'a str,
    pub action_id: ActionId,
    pub acting_user_id: Uuid,
}

impl std::fmt::Debug for InvocationKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvocationKey").finish_non_exhaustive()
    }
}

/// The result of trying to claim an invocation key.
#[derive(Debug)]
pub enum Claim {
    /// This caller owns the key and must perform the side effect, then
    /// [`complete_invocation`] (or [`release_invocation`] on failure).
    Acquired(Uuid),
    /// Someone already claimed it. The caller must NOT perform the side
    /// effect: replay a completed outcome, or report a still-claimed one as in
    /// progress.
    Existing(PriorInvocation),
}

/// **Claim-first idempotency** (D-502): occupies `(session, tool_call_id)`
/// *before* the side effect runs, so two concurrent retries of one tool call
/// cannot both become executors.
///
/// The partial unique index `uq_action_invocation_tool_call` (migration
/// `0120`) is the lock: exactly one `INSERT` wins; every other attempt sees
/// the winner's row. This replaces "look up a prior invocation, then run",
/// which has a window between the look-up and the write that a retrying tool
/// loop is exactly the thing to find.
///
/// Loops at most twice: a concurrent [`release_invocation`] can delete the
/// winner's row between this call's conflicting insert and its read, in which
/// case the key is free again and the second insert takes it.
pub async fn claim_invocation(db: &PgPool, key: InvocationKey<'_>) -> Result<Claim, AppError> {
    for _ in 0..2 {
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO action_invocation \
                (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome) \
             VALUES ($1, $2, $3, 1, $4, $5) \
             ON CONFLICT (agent_session_id, tool_call_id) WHERE tool_call_id IS NOT NULL \
             DO NOTHING \
             RETURNING id",
        )
        .bind(key.session_id)
        .bind(key.tool_call_id)
        .bind(key.action_id.0)
        .bind(key.acting_user_id)
        .bind(OUTCOME_CLAIMED)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if let Some(id) = inserted {
            return Ok(Claim::Acquired(id));
        }
        if let Some(prior) = prior_invocation(db, key.session_id, key.tool_call_id).await? {
            return Ok(Claim::Existing(prior));
        }
    }
    Err(AppError::Conflict(
        "this tool call is being retried concurrently; retry it again",
    ))
}

/// Records what a claimed invocation produced. `false` if the row is no longer
/// a live claim (it was already completed or released) — nothing is
/// overwritten in that case.
pub async fn complete_invocation(
    db: &PgPool,
    invocation_id: Uuid,
    outcome: &str,
    result: Option<&Value>,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE action_invocation SET outcome = $2, result = $3 \
          WHERE id = $1 AND outcome = $4",
    )
    .bind(invocation_id)
    .bind(outcome)
    .bind(result)
    .bind(OUTCOME_CLAIMED)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Frees a claim whose side effect failed, so the same tool call can be
/// retried (D-502's retryability). Only ever deletes a row still in the
/// `claimed` state — a completed invocation is never released.
pub async fn release_invocation(db: &PgPool, invocation_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM action_invocation WHERE id = $1 AND outcome = $2")
        .bind(invocation_id)
        .bind(OUTCOME_CLAIMED)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// One invocation to record.
///
/// A struct rather than eight positional arguments: four of them are
/// `Option`/`bool`, so a transposed pair would compile and silently attribute
/// an agent's write to a human.
pub struct InvocationRecord<'a> {
    pub session_id: Option<Uuid>,
    pub tool_call_id: Option<&'a str>,
    pub action_id: ActionId,
    pub is_agent: bool,
    pub acting_user_id: Uuid,
    pub outcome: &'a str,
    pub result: Option<&'a Value>,
}

impl std::fmt::Debug for InvocationRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvocationRecord").finish_non_exhaustive()
    }
}

/// Records an invocation.
///
/// Returns `false` when the unique index rejected it — i.e. a concurrent
/// duplicate of the same tool call won the race. **That is not an error**: the
/// caller reads the winner's row and returns it, which is the same answer the
/// loser would have produced. `ON CONFLICT DO NOTHING` rather than a
/// check-then-insert, because the check-then-insert has a window and a retrying
/// tool loop is precisely the thing that would find it.
/// How many of `action_ids` ran today (UTC) for agent object `agent`,
/// across all of its sessions (AH4-T2): a limit belongs to the agent, not to
/// one session. Only invocations that ran count, not refusals or approval
/// requests. Pair with [`crate::registry::ActionRegistry::ids_of_class`].
pub async fn used_today(db: &PgPool, agent: Uuid, action_ids: &[String]) -> Result<i64, AppError> {
    if action_ids.is_empty() {
        return Ok(0);
    }
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation i \
         JOIN agent_session s ON s.id = i.agent_session_id \
         WHERE s.agent_object_ref = $1 \
           AND i.action_id = ANY($2) \
           AND i.outcome IN ('completed', 'executed') \
           AND i.created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",
    )
    .bind(agent)
    .bind(action_ids)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

pub async fn record_invocation(db: &PgPool, rec: InvocationRecord<'_>) -> Result<bool, AppError> {
    let InvocationRecord {
        session_id,
        tool_call_id,
        action_id,
        is_agent,
        acting_user_id,
        outcome,
        result,
    } = rec;
    let affected = sqlx::query(
        "INSERT INTO action_invocation \
            (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome, result) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .bind(action_id.0)
    .bind(if is_agent { 1i16 } else { 0i16 })
    .bind(acting_user_id)
    .bind(outcome)
    .bind(result)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected > 0)
}

/// Same as [`record_invocation`], but returns the inserted row's id.
///
/// Added for `crate::decision::execute` (M28 Phase 1): a decision needs to
/// remember *which* invocation it ran (`dashboard_decision.action_invocation_ref`),
/// not just whether recording succeeded. `ON CONFLICT DO NOTHING RETURNING
/// id` yields no row on the same race `record_invocation` documents — a
/// concurrent duplicate of the same tool call — which cannot happen for a
/// decision's own invocation (`tool_call_id` is always `None` there, and the
/// partial unique index only applies `WHERE tool_call_id IS NOT NULL`), but
/// the caller still gets `None` rather than a wrong id if that ever changes.
pub async fn record_invocation_returning_id(
    db: &PgPool,
    rec: InvocationRecord<'_>,
) -> Result<Option<Uuid>, AppError> {
    let InvocationRecord {
        session_id,
        tool_call_id,
        action_id,
        is_agent,
        acting_user_id,
        outcome,
        result,
    } = rec;
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO action_invocation \
            (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome, result) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT DO NOTHING \
         RETURNING id",
    )
    .bind(session_id)
    .bind(tool_call_id)
    .bind(action_id.0)
    .bind(if is_agent { 1i16 } else { 0i16 })
    .bind(acting_user_id)
    .bind(outcome)
    .bind(result)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(allowed: Option<Vec<&str>>) -> AgentSession {
        AgentSession {
            id: Uuid::now_v7(),
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: RiskTier::Read,
            allowed_action_ids: allowed
                .map(|v| v.into_iter().map(str::to_owned).collect::<Vec<String>>()),
            tainted: false,
            policy: PolicySnapshot::NONE,
            anonymous_channel: false,
            surface: "test".to_owned(),
        }
    }

    /// `None` and an empty list are different states, and the empty one denies.
    ///
    /// Collapsing them would make a session an admin deliberately narrowed to
    /// nothing indistinguishable from an unrestricted one.
    #[test]
    fn an_empty_allow_list_denies_and_none_permits() {
        assert!(session(None).permits(ActionId("record.get")));
        assert!(!session(Some(vec![])).permits(ActionId("record.get")));
    }

    #[test]
    fn the_allow_list_is_exact() {
        let s = session(Some(vec!["record.get"]));
        assert!(s.permits(ActionId("record.get")));
        assert!(!s.permits(ActionId("record.create")));
        // Not a prefix match. `record.get` must not admit `record.getall`.
        assert!(!s.permits(ActionId("record.getall")));
    }

    /// An unrecognised stored ceiling reads as the **narrowest** tier.
    ///
    /// A corrupted value, or one written by a future version that added a tier,
    /// must not widen what an agent may do. The only safe direction for an
    /// unknown is down.
    #[test]
    fn an_unknown_stored_ceiling_narrows() {
        assert_eq!(tier_from_i16(0), RiskTier::Read);
        assert_eq!(tier_from_i16(1), RiskTier::Reversible);
        assert_eq!(tier_from_i16(2), RiskTier::Consequential);
        assert_eq!(tier_from_i16(99), RiskTier::Read);
        assert_eq!(tier_from_i16(-1), RiskTier::Read);
    }

    /// `risk_tier_to_i16` and `tier_from_i16` must agree in both directions —
    /// a `start()` caller and `load_live`'s reader must never disagree about
    /// what a stored ceiling means.
    #[test]
    fn risk_tier_encoding_round_trips() {
        for tier in [
            RiskTier::Read,
            RiskTier::Reversible,
            RiskTier::Consequential,
        ] {
            assert_eq!(tier_from_i16(risk_tier_to_i16(tier)), tier);
        }
    }
}
