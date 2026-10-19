//! M53 Phase 1 (Omnichannel, web chat only, D-474) — the public web chat
//! widget endpoint and its bot-first / handoff / routing / business-hours
//! orchestration.
//!
//! ## Why this lives in `crates/server`, not `attome-api`
//!
//! This feature genuinely needs three engine crates at once:
//! `attome-api::communication` (M52's writer), `attome-ai` (M54's
//! `bot.handoff`, D-447), and `attome-integration` (M59's `integration_system`
//! service-principal convention, D-425). But `attome-ai` and
//! `attome-integration` each already have a REAL (non-dev) dependency on
//! `attome-api` (`entity_crud::create_record_for`/`update_record_for` reuse —
//! see each crate's own Cargo.toml comment), so `attome-api` cannot depend
//! back on either without a cycle; both are `attome-api`'s dev-dependencies
//! only. `crates/server` is the one layer above all three
//! (`crates/server -> xrm/xrm-* -> base/base-*`, coding-guidelines.md §1), the
//! same reason this crate's own `auth/` directory holds real HTTP handlers
//! rather than composition-only code — see this crate's module layout in
//! `CLAUDE.md`.
//!
//! ## Security posture — mirrors `content_public.rs` exactly
//!
//! Both routes are `attome_server::middleware::bypass::EXACT_BYPASS_PATHS`
//! entries (no session/API-key/S2S auth), CSRF-exempt (no live session cookie
//! for a cross-site request to ride along with — same reasoning
//! `content/vote`'s exemption documents), and each does its own manual
//! license check (`MODULE_OMNICHANNEL`) returning a uniform `NotFound`
//! regardless of the reason, same D-367 discipline. `POST .../message` is
//! rate-limited per caller IP AND per resumed session
//! (`attome_cache::rate_limit`, mirroring `content_public.rs::vote_on_page`'s
//! per-(page, address) shape) — an anonymous write route without a rate limit
//! is an open-ended write, and this one now has two independent ceilings.
//!
//! ## Identity: no bypass/superuser context, ever
//!
//! An anonymous web-chat visitor has no `user_account` account. Rather
//! than invent a bypass identity (a hard constraint this repo forbids), every
//! write in this module runs as a real, admin-provisioned `user_account`
//! — the `service_principal_ref` of the one active `integration_system`
//! row with `kind = 'channel'`, resolved fresh via `state.base.security.resolve`
//! — the EXACT D-425 pattern `attome-integration::webhook::handle_webhook`
//! already established for "an unauthenticated-by-session external caller
//! writes through the generic entity API path, as a real, privileged
//! principal, never a bypass identity." If that principal was never granted
//! `communication.create` (or `service_work_request.create`, for the direct
//! routing path below), the write is correctly rejected — this endpoint is a
//! data source, never an implicit privilege-escalation path.
//!
//! ## Session-scoped anonymous identity, not a customer record
//!
//! A visitor is identified only by a bearer token
//! (`"{agent_session_token.id}.{secret}"`, the same `{public_id}.{secret}`
//! shape `attome_service::token` already established for the Work Intake
//! self-service portal, D-423 — reused verbatim rather than inventing a
//! second bearer scheme). Its secret is hashed the way that module hashes
//! portal tokens: peppered HMAC for new rows, with older Argon2 rows still
//! accepted (D-500). `agent_session_token` is a small infra
//! table (migration `0440`, renamed by `0456`) holding only the credential —
//! the conversation's own handoff state lives on `agent_session`,
//! owned by `attome_ai::session` — not a customer/contact entity; Phase 1 does not
//! require a real `customer` record to exist for a web-chat visitor (see the
//! module plan's own "session-scoped anonymous identifier is fine" guidance);
//! a deployment that later wants to link a visitor to a known contact can
//! extend this without changing the transport contract.
//!
//! ## Thread anchoring: agent session, then the handed-off work request
//!
//! `communication`'s `entity_name`/`record_id` are required (D-465's
//! polymorphic "regarding" pair — see `communication_seed.rs`), so every
//! message needs SOME record to point at, even before any handoff decision is
//! made. Before handoff, messages are anchored to the `agent_session`
//! this conversation's bot turn runs under (`AGENT_SESSION_ENTITY`) — a bot
//! session always exists from message 1, and nothing needs to look at that
//! thread through the generic Communications-panel UI while the bot is still
//! handling it. The moment a handoff creates (or, for the outside-business-
//! hours path, this module directly creates) an `service_work_request`, EVERY
//! subsequent message in the same conversation anchors to THAT record instead
//! (`WORK_REQUEST_ENTITY`) — which IS a normal, generically browsable,
//! privilege-checked entity with its own form and Communications panel, so a
//! human agent who picks up the routed work request sees the ongoing
//! conversation and can reply through the ordinary
//! `POST /api/v1/service_work_request/{id}/communications/{comm_id}/reply` route,
//! no special-casing needed. The bot's own pre-handoff exchange stays exactly
//! where it was written (still queryable by `agent_session_id` for an
//! auditor), and `bot.handoff`'s own `link_session_note` already leaves an
//! `note` on the new work request naming the originating session — no
//! second linking mechanism is added here.
//!
//! ## Bot-first, then handoff (M54, D-447) — what this Phase 1 slice can
//! honestly claim
//!
//! This section describes the **unassisted** session (`webchat.enabled =
//! false`, the default). The live tool loop is `attome_ai::turn::run` (the old
//! `attome-ai::chat` module is gone, CLEANUP-REVIEW 1.7); an unassisted session
//! never runs it — the C9 section below covers the assisted one. What an
//! unassisted session gets: two of the four
//! trigger conditions the module plan names, evaluated deterministically —
//! **explicit ask** (`looks_like_explicit_ask`, a phrase match) and a
//! **step-bound proxy** (`STEP_LIMIT_PROXY` inbound messages on one session
//! with no resolution — the honest stand-in for "the tool loop hit its step
//! limit" when there is no tool loop to hit a limit in). Both call the SAME,
//! real `bot.handoff` dispatch path
//! (`attome_ai::dispatch`/`ActionOutcome::Completed`) — no second handoff
//! mechanism. Short of those two triggers, a message gets a fixed
//! acknowledgment reply.
//!
//! ## C9: the assistant answers (D-558) — only when enabled
//!
//! The paragraph above is still exactly what a deployment gets with
//! `webchat.enabled = false`, the default, and what any session started while
//! it was false keeps getting: the session carries no agent definition.
//!
//! Enabled, a new visitor's session comes from `attome_ai::webchat::start_session`
//! — the configured agent definition's policy, clamped (explicit knowledge
//! scope, retrieval actions plus `bot.handoff`, `Reversible`) — and every
//! decision about a message is `attome_ai::webchat`'s, not this handler's:
//! `webchat::entry` (kill switch or no model → the offline message) and
//! `webchat::answer`, which runs the ordinary `turn::run` and maps its result
//! through `webchat::reply_for`: an answer, the offline message (every service
//! state, including an exhausted per-visitor budget — never a handoff), or a
//! handoff for the step limit, a refusal or an empty retrieval. An explicit
//! ask still hands off before any model call. The step-limit *proxy* (three
//! inbound messages) applies only to an unassisted session: an assisted one
//! has a real step limit. If the enabled widget cannot start its governed
//! session (a missing definition or knowledge scope, a principal that cannot
//! read the definition), the visitor gets the unassisted session and the
//! failure is logged — never a wider one.
//!
//! ## Routing (M70 -> M84) — the simple, hardcoded-but-configurable default
//!
//! M45 Phase 2 (conditional routing rules) does not exist —
//! `attome_service::routing::evaluate_routing`'s own doc comment documents the
//! identical gap for M70's offering-based intake. This module's routing
//! contribution is exactly the plan's own fallback: every new web-chat
//! handoff's work request gets `work_queue_ref` set to
//! `omnichannel.web_chat_default_queue_ref` (an `setting`, empty by
//! default — no queue assignment happens until an admin configures one).
//!
//! ## Channel policies
//!
//! **Business hours** (M83/D-404): if `omnichannel.web_chat_calendar_ref`
//! names a live `calendar`, an inbound message outside its working
//! hours skips the bot entirely, replies with the fixed
//! `omnichannel.web_chat_offline_message`, and routes a work request the same
//! way a handoff would (but NOT through `bot.handoff` — there is no
//! `HandoffReason` variant for "outside business hours", and adding one would
//! be an M54-owned taxonomy change this module has no mandate to make; this
//! path calls `entity_crud::create_record_for` directly, the same primitive
//! `bot.handoff` itself uses). Unset (the default): the widget behaves as
//! always-open, matching `service_sla_policy.calendar_ref`'s own opt-in posture.
//!
//! **Consent (M24/D-428) does NOT apply here.** `attome_notification::
//! consent_gate::has_active_consent` (and `bot_handoff.rs`'s own consent
//! check) both exist specifically for OUTBOUND MARKETING and for opting a
//! subject into raw-transcript retention — a web-chat reply is a purely
//! reactive response to a conversation the visitor themselves just initiated,
//! never an unsolicited outbound send. The module plan's own checklist item
//! is scoped to "consent requirement (M24) for outbound marketing", and web
//! chat's outbound is not that. No consent gate is wired for the reply path.

use std::net::SocketAddr;
use std::sync::Arc;

use attome_ai::actions::bot_handoff::{BOT_HANDOFF, HandoffReason};
use attome_ai::{ActionContext, ActionOutcome, ActionRegistry, Executors, GateInputs, RiskTier};
use attome_config::AiSurface;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_modules::MODULE_OMNICHANNEL;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

const CHANNEL: &str = "web_chat";
const AGENT_SESSION_ENTITY: &str = "agent_session";
const WORK_REQUEST_ENTITY: &str = "service_work_request";
const COMMUNICATION_SUBJECT: &str = "Web Chat";

/// How many inbound messages on one still-not-handed-off session trigger a
/// handoff on an unassisted session — the honest proxy for
/// `attome_ai::turn::MAX_TOOL_STEPS`'s "step-bound hit" trigger when no tool loop
/// runs (an assisted session has the real limit). See the module doc's
/// "bot-first, then handoff" section.
const STEP_LIMIT_PROXY: i64 = 3;

const MESSAGE_RATE_LIMIT_PER_MINUTE: i32 = 20;
const SESSION_RATE_LIMIT_PER_MINUTE: i32 = 30;

const HANDOFF_ACK: &str =
    "Thanks — I've passed this along to our team, and someone will follow up with you shortly.";

fn bot_ack_message() -> &'static str {
    "Thanks for reaching out! Tell me a bit more about what you need, or ask to speak with a \
     person at any time."
}

// ── Wire types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendMessageRequest {
    /// Omit on the very first message of a new conversation. Present on
    /// every subsequent one.
    #[serde(default)]
    pub session_token: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChatMessageOut {
    /// `inbound` (the visitor) or `outbound` (the bot, or a human agent).
    pub direction: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    /// C11 B6 (row A-86): on an assistant answer grounded in the widget's
    /// knowledge, the sources it drew on — title and section only. Omitted
    /// when there are none, so a widget that predates it receives exactly the
    /// response it always did. Not stored: a later poll returns the message
    /// without them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub citations: Vec<attome_ai::webchat::WidgetCitation>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SendMessageResponse {
    /// Present on every response — a brand-new value for a first message, the
    /// same value the caller supplied for a resumed one. The widget must
    /// persist this (e.g. `sessionStorage`) and send it back on every later
    /// call.
    pub session_token: String,
    /// Any new outbound message this call itself produced (a bot ack, a
    /// handoff/offline acknowledgment). Empty when this session was already
    /// handed off to a human — the widget should poll for a human's reply
    /// instead.
    pub replies: Vec<ChatMessageOut>,
    pub handed_off: bool,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct PollQuery {
    pub token: String,
    /// Only messages strictly after this instant. Omit to fetch the whole
    /// conversation so far — a short-poll GET is Phase 1's transport choice
    /// (see the module doc); the widget is expected to pass its last-seen
    /// `created_at` on every subsequent poll.
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(as = ChannelPollResponse)]
pub struct PollResponse {
    pub messages: Vec<ChatMessageOut>,
    pub handed_off: bool,
}

// ── Settings (D-412) ────────────────────────────────────────────────────

async fn setting_str(state: &EngineState, key: &str) -> String {
    let Some(descriptor) = attome_core::setting_descriptor::registry().get(key) else {
        // Cannot happen for a key this module itself registers in
        // `setting_catalog.rs`'s `omnichannel_settings()` — a mismatch here
        // would be a registration bug, not a runtime condition to recover
        // from silently, but this module still degrades to "unset" rather
        // than panic on a live request path.
        tracing::error!(key, "omnichannel: setting key not found in the registry");
        return String::new();
    };
    let (value, _source) = state.settings.load().resolve(descriptor, None, None);
    value.as_str().unwrap_or("").to_string()
}

// ── Channel system resolution (D-425 pattern) ───────────────────────────

async fn load_channel_system(
    db: &DbPool,
) -> Result<Option<attome_integration::system::IntegrationSystem>, AppError> {
    // `is_active`, not `is_deleted` — see `attome_integration::system::load`'s
    // doc comment for the column this table actually has.
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM integration_system \
         WHERE kind = 'channel' AND status = 'active' AND is_active IS NOT FALSE \
         ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match id {
        Some(id) => attome_integration::system::load(db, id).await,
        None => Ok(None),
    }
}

// ── `agent_session_token` (migration 0456) ──────────────────────────────

/// The credential row joined to the conversation state it points at — one
/// query, so a resumed visitor's handoff status arrives with the secret check.
#[derive(Debug, sqlx::FromRow)]
struct SessionTokenRow {
    secret_hash: String,
    agent_session_id: Uuid,
    handed_off_at: Option<DateTime<Utc>>,
    work_request_ref: Option<Uuid>,
    /// C9: the session was started from the configured agent definition, so
    /// the assistant answers it. Read from the row, never from the request.
    assisted: bool,
}

async fn load_session_token(db: &DbPool, id: Uuid) -> Result<Option<SessionTokenRow>, AppError> {
    sqlx::query_as(
        "SELECT t.secret_hash, t.agent_session_id, s.handed_off_at, s.work_request_ref, \
                (s.agent_definition_ref IS NOT NULL) AS assisted \
           FROM agent_session_token t \
           JOIN agent_session s ON s.id = t.agent_session_id \
          WHERE t.id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn insert_session_token(
    db: &DbPool,
    id: Uuid,
    secret_hash: &str,
    agent_session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO agent_session_token (id, secret_hash, agent_session_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(secret_hash)
    .bind(agent_session_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn touch_last_seen(db: &DbPool, id: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE agent_session_token SET last_seen_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// `(entity_name, record_id)` a message should be written against right now —
/// see the module doc's "thread anchoring" section.
fn thread_anchor(row: &SessionTokenRow) -> (&'static str, Uuid) {
    match row.work_request_ref {
        Some(work_request_id) => (WORK_REQUEST_ENTITY, work_request_id),
        None => (AGENT_SESSION_ENTITY, row.agent_session_id),
    }
}

async fn count_inbound_messages(db: &DbPool, agent_session_id: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM communication \
         WHERE entity_name = $1 AND record_id = $2 AND direction = 'inbound' \
           AND is_active IS NOT FALSE",
    )
    .bind(AGENT_SESSION_ENTITY)
    .bind(agent_session_id.to_string())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    direction: String,
    body: Option<String>,
    created_at: DateTime<Utc>,
}

async fn fetch_messages(
    db: &DbPool,
    entity_name: &str,
    record_id: Uuid,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<ChatMessageOut>, AppError> {
    let rows: Vec<MessageRow> = sqlx::query_as(
        "SELECT direction, body, created_at FROM communication \
         WHERE entity_name = $1 AND record_id = $2 AND is_active IS NOT FALSE \
           AND ($3::timestamptz IS NULL OR created_at > $3) \
         ORDER BY created_at ASC",
    )
    .bind(entity_name)
    .bind(record_id.to_string())
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|r| ChatMessageOut {
            direction: r.direction,
            body: r.body.unwrap_or_default(),
            created_at: r.created_at,
            citations: Vec::new(),
        })
        .collect())
}

// ── Business hours (M83, D-404) ──────────────────────────────────────────

/// `true` only when `omnichannel.web_chat_calendar_ref` names a usable
/// calendar AND the current instant falls outside its working hours. Every
/// other case (unset, malformed, deleted, invalid) fails OPEN: this gate only
/// chooses which auto-reply a visitor sees, so a broken calendar must never
/// make the widget wrongly claim to be offline. That is a different call from
/// an SLA deadline, which never substitutes an answer (D-517) — so the
/// failure is logged at `error`, not hidden.
async fn business_hours_closed(state: &EngineState) -> bool {
    let calendar_ref = setting_str(state, "omnichannel.web_chat_calendar_ref").await;
    let calendar_id = match attome_core::calendar::parse_calendar_ref(Some(&calendar_ref)) {
        Ok(Some(id)) => id,
        Ok(None) => return false,
        Err(unresolved) => {
            tracing::error!(reason = %unresolved, "omnichannel: web_chat_calendar_ref cannot be used; treating the widget as open");
            return false;
        }
    };
    match attome_core::calendar::load_calendar(&state.base.db, calendar_id).await {
        Ok(Ok(loaded)) => !loaded.calendar.is_working(Utc::now()),
        Ok(Err(unresolved)) => {
            tracing::error!(calendar_id = %calendar_id, reason = %unresolved, "omnichannel: web_chat_calendar_ref cannot be used; treating the widget as open");
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, "omnichannel: failed to load web_chat_calendar_ref; treating the widget as open");
            false
        }
    }
}

// ── Routing (M70 -> M84, the simple hardcoded-but-configurable default) ──

/// Stamps `channel = 'web_chat'` on a just-created work request and, if
/// `omnichannel.web_chat_default_queue_ref` is configured, its
/// `work_queue_ref` too — one `update_record_for` call either way.
///
/// `channel` MUST be set here for the `bot.handoff`-created path: that
/// action's own executor (`attome-ai::actions::bot_handoff`, deliberately
/// not modified by this module — see the module doc's "bot-first, then
/// handoff" section) has no `channel` argument at all and never sets it,
/// so without this backfill every web-chat handoff's work request would
/// carry `channel = NULL` — invisible to `omnichannel_metrics`'s
/// channel-scoped queries and to any future per-channel routing rule. The
/// outside-business-hours path (which creates its own work request directly
/// via `entity_crud::create_record_for`) already sets `channel` at creation
/// time; calling this again for that path is a harmless no-op update, not a
/// second source of truth.
async fn finalize_handoff_work_request(
    state: &EngineState,
    principal_ctx: &Arc<SecurityContext>,
    principal_id: Uuid,
    work_request_id: Uuid,
) -> Result<(), AppError> {
    let queue_ref = setting_str(state, "omnichannel.web_chat_default_queue_ref").await;
    let row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM service_work_request WHERE id = $1")
            .bind(work_request_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let mut body = serde_json::json!({ "channel": CHANNEL });
    if !queue_ref.trim().is_empty() {
        body["work_queue_ref"] = serde_json::Value::String(queue_ref.trim().to_string());
    }
    attome_records::entity_crud::update_record_for(
        state,
        principal_ctx,
        principal_id,
        WORK_REQUEST_ENTITY,
        work_request_id,
        row_version,
        body,
    )
    .await?;
    Ok(())
}

// ── Bot-first trigger conditions ────────────────────────────────────────

/// Deterministic "explicit ask" trigger — one of `bot.handoff`'s four
/// documented conditions (M54 §5), evaluated without any model call. Not
/// exhaustive by design: a false negative here just means the bot's fixed
/// acknowledgment is shown once more before the step-limit proxy trigger
/// eventually fires; a false positive costs nothing worse than an earlier
/// handoff than strictly necessary.
fn looks_like_explicit_ask(message: &str) -> bool {
    let lower = message.to_lowercase();
    const PHRASES: &[&str] = &[
        "human",
        "real person",
        "speak to someone",
        "speak with someone",
        "talk to someone",
        "talk to a person",
        "representative",
        "agent please",
        "customer service",
    ];
    PHRASES.iter().any(|p| lower.contains(p))
}

/// Calls the real `bot.handoff` action (M54, D-447) — the one and only
/// handoff mechanism this module reuses, never a second implementation.
async fn dispatch_bot_handoff(
    state: &EngineState,
    principal_ctx: &Arc<SecurityContext>,
    agent_session_id: Uuid,
    reason: HandoffReason,
    user_message: &str,
) -> Result<Uuid, AppError> {
    let action_ctx = ActionContext::agent(Arc::clone(principal_ctx), RiskTier::Reversible)
        .with_agent_session(agent_session_id)
        // TODO-043: this module's own `claim_handoff_slot` already guarantees
        // at most one caller ever reaches this dispatch for a given session,
        // so the key only needs to be stable per session, not per attempt.
        .with_idempotency_key(format!("webchat:{agent_session_id}:handoff"));
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let licensed = state
        .modules
        .load()
        .has(attome_ai::actions::bot_handoff::descriptor().module);
    let gate_inputs = GateInputs {
        licensed,
        ai: &state.base.config.inference.ai,
        surface: Some(AiSurface::Chat),
        external_effects_enabled: state.base.config.security.external_effects_enabled,
    };
    let args = serde_json::json!({
        "agent_session_id": agent_session_id,
        "reason": reason,
        "tool_calls": Vec::<String>::new(),
        "bots_last_message": Value::Null,
        "user_request_summary": user_message,
    });

    match attome_ai::dispatch(
        state,
        &registry,
        &executors,
        BOT_HANDOFF,
        &action_ctx,
        &gate_inputs,
        &args,
    )
    .await?
    {
        ActionOutcome::Completed { result, .. } => result
            .get("work_request_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AppError::internal("bot.handoff did not return a work_request_id")),
        // `bot.handoff` is `RiskTier::Reversible`; a session started clean
        // (never tainted — this module never taints one, since no tool loop
        // ever runs) always auto-executes for `Initiator::Agent` per the
        // gate's own matrix (`gate.rs`). Anything else here means the
        // licensing/kill-switch/ceiling checks refused it, which surfaces as
        // `Err` above via `?` — this arm is genuinely unreachable in that
        // case and a hard error is more honest than silently treating it as
        // "no handoff happened".
        other => Err(AppError::internal(format!(
            "bot.handoff returned an unexpected outcome for a clean agent context: {other:?}"
        ))),
    }
}

// ── Communication writing ───────────────────────────────────────────────

/// The thread root any prior message against `(entity_name, record_id)`
/// already established, if one exists — `None` only for the very first
/// message ever written against this anchor. Every write below passes this
/// through as `parent_thread_id` so a whole conversation under one anchor
/// shares one `communication.thread_id`, rather than each call
/// self-backfilling its own (see `write_communication`'s own thread-backfill
/// doc comment — that backfill is correct only for a genuinely fresh thread).
async fn existing_thread_id(
    db: &DbPool,
    entity_name: &str,
    record_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT thread_id FROM communication \
         WHERE entity_name = $1 AND record_id = $2 \
         ORDER BY created_at ASC LIMIT 1",
    )
    .bind(entity_name)
    .bind(record_id.to_string())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Writes one message into the conversation anchored at `(entity_name,
/// record_id)`. Both `direction = "inbound"` (the visitor's own text) and
/// `direction = "outbound"` (the bot's fixed acknowledgment, or later a human
/// agent's own reply through the ordinary reply route) go through
/// [`attome_notification::communication::write_communication`] — the full M52 writer,
/// with the real privilege check, audit trail, and creator-share grant.
///
/// **Every row is authored by the resolved service principal, even the
/// inbound ones the principal did not literally type** — the same D-425
/// precedent `attome-integration::webhook::handle_webhook` already established
/// for "an inbound write from an unauthenticated-by-session external party
/// still runs as the channel's own service principal, so rules/privilege/
/// audit apply exactly as they would to any other write." There is no
/// bypass path here: an admin who never granted the web-chat principal
/// `communication.create` correctly sees every message write refused,
/// visitor-authored or not.
///
/// `direction` is threaded through explicitly (not hardcoded) precisely so
/// the visitor's own messages are recorded as `inbound` — getting this
/// backwards would make every visitor message read as `outbound` (wrong for
/// the Communications panel, and it would silently break
/// `count_inbound_messages`'s step-bound proxy, since nothing would ever be
/// `direction = 'inbound'`).
#[allow(clippy::too_many_arguments)]
async fn write_message(
    state: &EngineState,
    principal_ctx: &Arc<SecurityContext>,
    principal_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    direction: &str,
    body: &str,
) -> Result<(), AppError> {
    let parent_thread_id = existing_thread_id(&state.base.db, entity_name, record_id).await?;
    principal_ctx.require("communication", "create")?;
    attome_notification::communication::write_communication(
        state,
        principal_ctx,
        principal_id,
        entity_name,
        record_id,
        CHANNEL,
        direction,
        &[],
        &[],
        COMMUNICATION_SUBJECT,
        body,
        None,
        parent_thread_id,
        None,
        None,
    )
    .await?;
    Ok(())
}

// ── HTTP handlers ────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/omnichannel/webchat/message",
    tag = "omnichannel",
    request_body = SendMessageRequest,
    responses(
        (status = 200, description = "Success", body = SendMessageResponse),
        (status = 404, description = "Not licensed, no web-chat channel configured, or an unrecognized session token — identical response for all three", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
        (status = 429, description = "Too many messages from this caller or this session", body = ErrorResponse),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
async fn send_message(
    State(state): State<EngineState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, AppError> {
    let active = state.modules.load();
    let licensed = active.require(MODULE_OMNICHANNEL).is_ok();
    drop(active);
    if !licensed {
        return Err(AppError::NotFound);
    }

    let text = body.message.trim();
    if text.is_empty() {
        return Err(AppError::Validation("message is required".into()));
    }

    // Per-IP rate limit — reused exactly as `content_public.rs::vote_on_page`
    // uses it, before any other work happens on this request.
    let ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer.ip(),
        &headers,
        &state.base.config,
    );
    let ip_key = format!("omnichannel:rl:webchat:{ip}");
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &ip_key,
        MESSAGE_RATE_LIMIT_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    let system = load_channel_system(&state.base.db)
        .await?
        .ok_or(AppError::NotFound)?;
    let principal_id = attome_integration::system::service_principal_id(&system)?;
    let principal_ctx = state.base.security.resolve(principal_id).await?;

    let ring = state.base.pepper_ring();
    let (agent_session_id, token_id, session_token, already_handed_off, assisted) = match &body
        .session_token
    {
        Some(token) => {
            let Some((existing_id, secret)) = attome_service::token::parse_bearer(token) else {
                attome_service::token::verify(token, None, &ring).await?;
                return Err(AppError::NotFound);
            };
            let Some(row) = load_session_token(&state.base.db, existing_id).await? else {
                attome_service::token::verify(secret, None, &ring).await?;
                return Err(AppError::NotFound);
            };
            if !attome_service::token::verify(secret, Some(&row.secret_hash), &ring).await? {
                return Err(AppError::NotFound);
            }

            let session_key = format!("omnichannel:rl:webchat:session:{existing_id}");
            let session_outcome = attome_cache::rate_limit::check(
                &state.base.redis_coordination,
                &session_key,
                SESSION_RATE_LIMIT_PER_MINUTE,
            )
            .await?;
            if !session_outcome.allowed {
                return Err(AppError::TooManyRequests {
                    retry_after_secs: None,
                });
            }

            touch_last_seen(&state.base.db, existing_id).await?;
            (
                row.agent_session_id,
                existing_id,
                token.clone(),
                row.handed_off_at.is_some(),
                row.assisted,
            )
        }
        None => {
            // C9: enabled, the visitor's session is the configured agent's,
            // clamped. A failure falls back to the unassisted session below —
            // never to anything wider — and is logged for the operator.
            let assisted_session = if state.base.config.webchat.enabled {
                match attome_ai::webchat::start_session(&state, &principal_ctx, system.id).await {
                    Ok(session) => Some(session),
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "web chat is enabled but its assistant session could not start; \
                             serving this visitor unassisted"
                        );
                        None
                    }
                }
            } else {
                None
            };
            let assisted = assisted_session.is_some();
            let session = match assisted_session {
                Some(session) => session,
                None => {
                    attome_ai::session::start(
                        &state.base.db,
                        &attome_audit::audit_service(&state),
                        attome_ai::session::SessionStart {
                            owner_user_id: principal_id,
                            risk_ceiling: RiskTier::Reversible,
                            allowed_action_ids: Some(vec![BOT_HANDOFF.to_string()]),
                            surface: "webchat",
                            agent_definition_ref: None,
                            integration_system_id: Some(system.id),
                            tainted: false,
                            // D-505 §1: a webchat conversation names no definition,
                            // so it has no policy term.
                            policy: attome_ai::session::PolicySnapshot::NONE,
                        },
                    )
                    .await?
                }
            };
            let issued = attome_service::token::issue(&ring).await?;
            insert_session_token(
                &state.base.db,
                issued.public_id,
                &issued.secret_hash,
                session.id,
            )
            .await?;
            (session.id, issued.public_id, issued.bearer, false, assisted)
        }
    };

    // The anchor to write THIS inbound message against — the agent session
    // pre-handoff, the routed work request once one exists (see the module
    // doc's "thread anchoring" section).
    let (anchor_entity, anchor_record_id) = if already_handed_off {
        // Re-load to get the current work_request_ref — cheap, and correctness
        // matters more than saving one query on an already-handed-off thread.
        let row = load_session_token(&state.base.db, token_id)
            .await?
            .ok_or_else(|| AppError::internal("session token disappeared mid-request"))?;
        thread_anchor(&row)
    } else {
        (AGENT_SESSION_ENTITY, agent_session_id)
    };
    write_message(
        &state,
        &principal_ctx,
        principal_id,
        anchor_entity,
        anchor_record_id,
        "inbound",
        text,
    )
    .await?;

    if already_handed_off {
        // A human is already handling this conversation — log the message
        // and stop. No bot reply, no second handoff attempt.
        return Ok(Json(SendMessageResponse {
            session_token,
            replies: Vec::new(),
            handed_off: true,
        }));
    }

    let mut replies = Vec::new();
    let mut handed_off = false;

    if business_hours_closed(&state).await {
        let offline_message = setting_str(&state, "omnichannel.web_chat_offline_message").await;
        write_message(
            &state,
            &principal_ctx,
            principal_id,
            AGENT_SESSION_ENTITY,
            agent_session_id,
            "outbound",
            &offline_message,
        )
        .await?;
        replies.push(ChatMessageOut {
            direction: "outbound".to_string(),
            body: offline_message,
            created_at: Utc::now(),
            citations: Vec::new(),
        });

        if attome_ai::session::claim_handoff(&state.base.db, agent_session_id).await? {
            principal_ctx.require(WORK_REQUEST_ENTITY, "create")?;
            let (work_request_id, _resp) = attome_records::entity_crud::create_record_for(
                &state,
                &principal_ctx,
                principal_id,
                WORK_REQUEST_ENTITY,
                serde_json::json!({
                    "title": format!("Web chat (outside business hours): {}", truncate(text, 60)),
                    "description": text,
                    "request_type": "custom",
                    "requester_id": principal_id,
                    "status": "new",
                    "channel": CHANNEL,
                }),
            )
            .await?;
            attome_ai::session::set_work_request_ref(
                &state.base.db,
                agent_session_id,
                work_request_id,
            )
            .await?;
            finalize_handoff_work_request(&state, &principal_ctx, principal_id, work_request_id)
                .await?;
        }
        handed_off = true;
    } else {
        let bot = if looks_like_explicit_ask(text) {
            // Before any model call, assisted or not: a visitor who asks for a
            // person gets one without spending a token.
            BotReply::Handoff(HandoffReason::UserRequested)
        } else if assisted {
            assisted_reply(&state, &principal_ctx, agent_session_id, text).await
        } else if count_inbound_messages(&state.base.db, agent_session_id).await?
            >= STEP_LIMIT_PROXY
        {
            BotReply::Handoff(HandoffReason::StepLimitReached)
        } else {
            BotReply::Say(bot_ack_message().to_owned(), Vec::new())
        };

        match bot {
            BotReply::Offline => {
                let offline_message =
                    setting_str(&state, "omnichannel.web_chat_offline_message").await;
                write_message(
                    &state,
                    &principal_ctx,
                    principal_id,
                    AGENT_SESSION_ENTITY,
                    agent_session_id,
                    "outbound",
                    &offline_message,
                )
                .await?;
                replies.push(ChatMessageOut {
                    direction: "outbound".to_string(),
                    body: offline_message,
                    created_at: Utc::now(),
                    citations: Vec::new(),
                });
            }
            BotReply::Handoff(reason) => {
                if attome_ai::session::claim_handoff(&state.base.db, agent_session_id).await? {
                    let work_request_id = dispatch_bot_handoff(
                        &state,
                        &principal_ctx,
                        agent_session_id,
                        reason,
                        text,
                    )
                    .await?;
                    attome_ai::session::set_work_request_ref(
                        &state.base.db,
                        agent_session_id,
                        work_request_id,
                    )
                    .await?;
                    finalize_handoff_work_request(
                        &state,
                        &principal_ctx,
                        principal_id,
                        work_request_id,
                    )
                    .await?;
                    write_message(
                        &state,
                        &principal_ctx,
                        principal_id,
                        WORK_REQUEST_ENTITY,
                        work_request_id,
                        "outbound",
                        HANDOFF_ACK,
                    )
                    .await?;
                }
                replies.push(ChatMessageOut {
                    direction: "outbound".to_string(),
                    body: HANDOFF_ACK.to_string(),
                    created_at: Utc::now(),
                    citations: Vec::new(),
                });
                handed_off = true;
            }
            BotReply::Say(body, citations) => {
                write_message(
                    &state,
                    &principal_ctx,
                    principal_id,
                    AGENT_SESSION_ENTITY,
                    agent_session_id,
                    "outbound",
                    &body,
                )
                .await?;
                replies.push(ChatMessageOut {
                    direction: "outbound".to_string(),
                    body,
                    created_at: Utc::now(),
                    citations,
                });
            }
        }
    }

    Ok(Json(SendMessageResponse {
        session_token,
        replies,
        handed_off,
    }))
}

/// What the bot does with one message that is not already handed off.
enum BotReply {
    /// Send this text: the model's answer, or the fixed acknowledgment —
    /// with the answer's citations, if it has any.
    Say(String, Vec<attome_ai::webchat::WidgetCitation>),
    /// Send the configured offline message; no handoff.
    Offline,
    /// Hand the conversation to a person.
    Handoff(HandoffReason),
}

/// An assisted session's reply — `attome_ai::webchat` decides; this only maps.
///
/// An error from the turn itself (a database or queue failure, not a model
/// outcome) is the offline message and is logged: the inbound message is
/// already stored, so failing the request would invite a duplicate resend,
/// and an infrastructure fault is never a reason to hand off.
async fn assisted_reply(
    state: &EngineState,
    principal_ctx: &Arc<SecurityContext>,
    agent_session_id: Uuid,
    text: &str,
) -> BotReply {
    let config = &state.base.config;
    let generation_configured = !config.inference.generation.base_url.trim().is_empty();
    // C11 B5 (row A-85): the runtime switch narrows the configuration — its
    // own `webchat` surface and the master switch mean the offline message,
    // and the chat surface is read as `config AND runtime`.
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    if config.webchat.enabled && !attome_core::ai_runtime_switch::allows_webchat() {
        return BotReply::Offline;
    }
    let ai = attome_core::ai_runtime_switch::effective(&config.inference.ai);
    match attome_ai::webchat::entry(&config.webchat, ai, generation_configured) {
        // Disabled since this session started: the unassisted acknowledgment.
        attome_ai::webchat::Entry::Legacy => {
            return BotReply::Say(bot_ack_message().to_owned(), Vec::new());
        }
        attome_ai::webchat::Entry::Offline => return BotReply::Offline,
        attome_ai::webchat::Entry::Answer => {}
    }
    match attome_ai::webchat::answer(state, Arc::clone(principal_ctx), agent_session_id, text).await
    {
        Ok(answered) => match answered.reply {
            attome_ai::webchat::Reply::Answer => BotReply::Say(answered.text, answered.citations),
            attome_ai::webchat::Reply::Offline => BotReply::Offline,
            attome_ai::webchat::Reply::Handoff(reason) => BotReply::Handoff(reason),
        },
        Err(error) => {
            tracing::error!(%error, %agent_session_id, "web chat turn failed; sending the offline message");
            BotReply::Offline
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/omnichannel/webchat/poll",
    tag = "omnichannel",
    params(PollQuery),
    responses(
        (status = 200, description = "Success", body = PollResponse),
        (status = 404, description = "Not licensed, or an unrecognized session token — identical response for both", body = ErrorResponse),
        (status = 429, description = "Too many polls from this session", body = ErrorResponse),
    ),
)]
// Named `poll_webchat_messages`, not the shorter `poll` — utoipa derives a
// route's default `operationId` from the handler's Rust function name when
// none is set explicitly, and `attome_notification::admin` already has its own
// unrelated handler named `poll`. Two operations sharing one operationId
// compiles fine in Rust (different modules) but collides into one duplicate
// TypeScript identifier in the generated `api-types.ts` — found live via
// `npm run generate:api` + `build:base` after this route was added.
async fn poll_webchat_messages(
    State(state): State<EngineState>,
    Query(q): Query<PollQuery>,
) -> Result<Json<PollResponse>, AppError> {
    let active = state.modules.load();
    let licensed = active.require(MODULE_OMNICHANNEL).is_ok();
    drop(active);
    if !licensed {
        return Err(AppError::NotFound);
    }

    let ring = state.base.pepper_ring();
    let Some((public_id, secret)) = attome_service::token::parse_bearer(&q.token) else {
        attome_service::token::verify(&q.token, None, &ring).await?;
        return Err(AppError::NotFound);
    };
    let Some(row) = load_session_token(&state.base.db, public_id).await? else {
        attome_service::token::verify(secret, None, &ring).await?;
        return Err(AppError::NotFound);
    };
    if !attome_service::token::verify(secret, Some(&row.secret_hash), &ring).await? {
        return Err(AppError::NotFound);
    }

    let session_key = format!("omnichannel:rl:webchat:poll:{public_id}");
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &session_key,
        SESSION_RATE_LIMIT_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    touch_last_seen(&state.base.db, public_id).await?;
    let (entity_name, record_id) = thread_anchor(&row);
    let messages = fetch_messages(&state.base.db, entity_name, record_id, q.since).await?;

    Ok(Json(PollResponse {
        messages,
        handed_off: row.handed_off_at.is_some(),
    }))
}

// ── J3-T1: live delivery ────────────────────────────────────────────────────

/// How often a live stream looks for new messages.
const STREAM_TICK: std::time::Duration = std::time::Duration::from_secs(2);
/// How long one stream stays open before the widget reconnects.
const STREAM_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// The stream's keep-alive comment interval.
const STREAM_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(20);

/// The widget's session behind a bearer, checked exactly as the poll checks
/// it (same timing on every miss), and counted against the same per-session
/// rate limit. `NotFound` for every failure, as the poll answers.
async fn authenticate_visitor(
    state: &EngineState,
    token: &str,
) -> Result<(Uuid, SessionTokenRow), AppError> {
    let active = state.modules.load();
    let licensed = active.require(MODULE_OMNICHANNEL).is_ok();
    drop(active);
    if !licensed {
        return Err(AppError::NotFound);
    }
    let ring = state.base.pepper_ring();
    let Some((public_id, secret)) = attome_service::token::parse_bearer(token) else {
        attome_service::token::verify(token, None, &ring).await?;
        return Err(AppError::NotFound);
    };
    let Some(row) = load_session_token(&state.base.db, public_id).await? else {
        attome_service::token::verify(secret, None, &ring).await?;
        return Err(AppError::NotFound);
    };
    if !attome_service::token::verify(secret, Some(&row.secret_hash), &ring).await? {
        return Err(AppError::NotFound);
    }
    let session_key = format!("omnichannel:rl:webchat:poll:{public_id}");
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &session_key,
        SESSION_RATE_LIMIT_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    Ok((public_id, row))
}

/// One stream's position.
struct ChatStream {
    state: EngineState,
    public_id: Uuid,
    since: Option<DateTime<Utc>>,
    handed_off: bool,
    deadline: tokio::time::Instant,
}

/// The newest time among `messages`, else `since`. Pure.
fn advance(since: Option<DateTime<Utc>>, messages: &[ChatMessageOut]) -> Option<DateTime<Utc>> {
    messages.iter().map(|m| m.created_at).max().max(since)
}

/// The web chat's messages as they arrive (J3-T1).
///
/// Server-Sent Events: a `messages` event (`{messages, handed_off}`, the
/// poll's shape) whenever messages newer than `since` arrive or the
/// conversation is handed to a person, checked every 2 seconds. The stream
/// ends after 10 minutes and the widget reconnects with the last
/// `created_at` it saw; a widget that cannot hold a stream keeps polling.
/// Opening it counts as one poll against the session's rate limit.
#[utoipa::path(
    get,
    path = "/api/v1/omnichannel/webchat/stream",
    tag = "omnichannel",
    params(PollQuery),
    responses(
        (status = 200, description = "Server-Sent Events: `messages` with `{messages, handed_off}`", content_type = "text/event-stream"),
        (status = 404, description = "Not licensed, or an unrecognized session token — identical response for both", body = ErrorResponse),
        (status = 429, description = "Too many polls or streams from this session", body = ErrorResponse),
    ),
)]
async fn webchat_stream(
    State(state): State<EngineState>,
    Query(q): Query<PollQuery>,
) -> Result<
    axum::response::sse::Sse<
        impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
    >,
    AppError,
> {
    let (public_id, row) = authenticate_visitor(&state, &q.token).await?;
    touch_last_seen(&state.base.db, public_id).await?;
    let start = ChatStream {
        state,
        public_id,
        since: q.since,
        handed_off: row.handed_off_at.is_some(),
        deadline: tokio::time::Instant::now() + STREAM_LIFETIME,
    };
    let first = true;
    let stream = futures_util::stream::unfold((start, first), |(mut live, first)| async move {
        loop {
            // The first look is at once; then every tick.
            if !first {
                let wake = (tokio::time::Instant::now() + STREAM_TICK).min(live.deadline);
                tokio::time::sleep_until(wake).await;
            }
            if tokio::time::Instant::now() >= live.deadline {
                return None;
            }
            // The anchor moves to the work request at hand-off: re-read it.
            let row = match load_session_token(&live.state.base.db, live.public_id).await {
                Ok(Some(row)) => row,
                Ok(None) => return None,
                Err(error) => {
                    tracing::warn!(%error, "web chat stream: session read failed");
                    return None;
                }
            };
            let (entity_name, record_id) = thread_anchor(&row);
            let messages =
                match fetch_messages(&live.state.base.db, entity_name, record_id, live.since).await
                {
                    Ok(messages) => messages,
                    Err(error) => {
                        tracing::warn!(%error, "web chat stream: message read failed");
                        return None;
                    }
                };
            let handed_off = row.handed_off_at.is_some();
            if messages.is_empty() && handed_off == live.handed_off {
                if first {
                    return Some((
                        Ok(axum::response::sse::Event::default()
                            .event("ready")
                            .data("{}")),
                        (live, false),
                    ));
                }
                continue;
            }
            live.since = advance(live.since, &messages);
            live.handed_off = handed_off;
            let event = axum::response::sse::Event::default()
                .event("messages")
                .json_data(PollResponse {
                    messages,
                    handed_off,
                })
                .unwrap_or_else(|_| axum::response::sse::Event::default().event("error"));
            let _ = touch_last_seen(&live.state.base.db, live.public_id).await;
            return Some((Ok(event), (live, false)));
        }
    });
    Ok(axum::response::sse::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(STREAM_KEEPALIVE)
            .text("keep-alive"),
    ))
}

#[cfg(test)]
mod webchat_stream_tests {
    use super::*;

    fn message(at: DateTime<Utc>) -> ChatMessageOut {
        ChatMessageOut {
            direction: "outbound".into(),
            body: "hello".into(),
            created_at: at,
            citations: Vec::new(),
        }
    }

    #[test]
    fn a_stream_moves_past_the_newest_message_it_sent() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(5);
        assert_eq!(advance(None, &[]), None);
        assert_eq!(advance(Some(t1), &[]), Some(t1));
        assert_eq!(advance(None, &[message(t2), message(t1)]), Some(t2));
        assert_eq!(advance(Some(t2), &[message(t1)]), Some(t2));
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/omnichannel/webchat/message", post(send_message))
        .route(
            "/api/v1/omnichannel/webchat/poll",
            get(poll_webchat_messages),
        )
        .route("/api/v1/omnichannel/webchat/stream", get(webchat_stream))
        // J9-T2: co-browse sessions ride the same bundle.
        .merge(crate::cobrowse::routes())
        // J4-T2: inbound texts ride the same bundle.
        .merge(crate::sms_inbound::routes())
        // J8-T1: Meta's webhooks and the social reply route.
        .merge(crate::social::routes())
        // J6-T1: calls and the voice providers' callbacks.
        .merge(crate::voice::routes())
        // D20-T2: public booking links ride the same public bundle; their
        // OpenAPI is tagged `sales` in `openapi.rs`.
        .merge(crate::booking::routes())
        // D9-T3: quote acceptance by guest link (tagged `sales` too).
        .merge(crate::quote_accept::routes())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(send_message, poll_webchat_messages, webchat_stream))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(crate::cobrowse::openapi());
    doc.merge(crate::sms_inbound::openapi());
    doc.merge(crate::social::openapi());
    doc.merge(crate::voice::openapi());
    doc
}
