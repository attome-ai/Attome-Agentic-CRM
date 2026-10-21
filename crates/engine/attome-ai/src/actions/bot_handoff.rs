//! `bot.handoff` — the bot's first write action (M54, D-447): escalate a
//! conversation to a human by creating an `service_work_request` (M70).
//!
//! ## Why this is the ONLY write the bot can do
//!
//! A bot session's tool set is read-only by policy — no write action is on
//! its allow-list, so an injected instruction has nothing to write with.
//! `bot.handoff` is the deliberate, narrow exception: it does not let the bot
//! act on the platform's data, only ask a human to. D-447 records why that
//! boundary (work intake only, nothing else) is the right first write rather
//! than a general-purpose "let the bot write records" capability.
//!
//! ## The structured summary
//!
//! The plan requires the created work request to carry a **structured**
//! summary of the conversation, never the raw transcript verbatim unless the
//! subject has M24 consent. The executor builds a [`TurnDigest`] from the
//! typed arguments only — the action ids consulted and the bot's last message
//! — and [`render_description`] renders that plus the caller's summary. Those
//! arguments are caller-authored (model or orchestrator), so they carry the
//! same trust as any other model-supplied argument; what this action
//! guarantees structurally is only that raw transcript text needs consent.
//!
//! ## The raw transcript is opt-in, per subject, and checked here
//!
//! A caller MAY attach `raw_transcript` to the action's arguments — an
//! orchestrator that has the full `Turn` available could always choose to.
//! Whether it is actually PERSISTED is decided by this executor, not by the
//! caller's judgement: [`has_bot_transcript_consent`] is checked against
//! [`RAW_TRANSCRIPT_CONSENT_PURPOSE`] before
//! [`render_description`] is told to include it. A caller that forgets to
//! check consent, or checks it wrong, still cannot get raw transcript text
//! into a work request for a subject who has not granted it — the gate is on
//! the write path, not on trusting the request.
//!
//! Queries `audit_consent`/`audit_consent_purpose` directly by table name rather
//! than adding an `attome-ai -> attome-notification -> attome-compliance`
//! dependency triangle to reach the consent check that already exists at
//! `attome_notification::consent_gate::has_active_consent` — that function is
//! private to its own crate for the same "small, narrow, easy to replace"
//! reason its own doc comment gives, and this is a second copy of the same
//! shape rather than a reason to make it `pub` and add a cross-engine
//! dependency for one SELECT.
//!
//! ## Linking the session to the work request
//!
//! The created work request records an `note` naming the
//! `agent_session_id` it came from — the same polymorphic
//! entity_name/record_id convention `note` already uses elsewhere in this
//! platform (e.g. `attome-service::clock`'s system-authored pause/resume notes),
//! rather than a new column on either table. `agent_session_id` must also
//! name a session that is still LIVE and OWNED by the caller
//! ([`crate::session::load_live`]) — the same revocation-respecting check
//! TODO-039 established, applied here so a revoked session cannot open a work
//! request either.
//!
//! ## Notification (M51), not queue routing (M84)
//!
//! M84 (work queues) is not built in this repo, so there is no queue to
//! route to. This dispatches an M51 in-app notification to every holder of
//! `service_work_request.update` — the people who can act on a work request
//! today — the same `create_dispatch`/`DispatchRequest` shape and the same
//! "resolve holders of a privilege, notify each" query shape
//! `attome-ai::quality_monitor`'s `admin_recipients` already established in
//! this crate (parameterised on a different privilege key here). Best-effort:
//! a notification failure is logged and never fails the handoff, the same
//! posture `attome-service::clock::notify_recipients` and `quality_monitor`
//! both take.

use std::future::Future;
use std::pin::Pin;

use attome_config::NotificationSection;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_notification::dispatch::{DispatchRequest, create_dispatch};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};
use crate::session;

/// The action id.
pub const BOT_HANDOFF: &str = "bot.handoff";

/// REVIEW-2026-09-02 finding #9: `bot.handoff` is `Reversible` +
/// `Effect::Write` (it opens a real work request) and previously carried
/// none of `record.update_field`'s blast-radius controls — same caps
/// `crate::write_guard` now offers any agent-auto-execute write action.
/// Distinct value from `record_update_field::DAILY_WRITE_CAP`: a handoff is
/// a much lower-frequency action in practice (one per conversation that
/// needs a human, not one per tool call), so a smaller cap catches a
/// runaway loop faster without ever being a real ceiling on legitimate use.
pub const DAILY_HANDOFF_CAP: i64 = 20;
const PER_MINUTE_HANDOFF_RATE_CAP: i32 = 5;
const AUTO_APPROVAL_ACTION_TYPE: &str = "attome-ai/policy-approved:bot.handoff";
const AUTO_APPROVAL_TTL_MINUTES: i64 = 5;

/// The entity a handoff creates. Fixed, not deployment configuration —
/// `service_work_request` is the platform's own M70 work-intake entity, always
/// present (unlike `draft_article.rs`'s `knowledge_article_entity`, which is
/// genuinely deployment-specific because the platform ships no built-in
/// knowledge-article entity).
const WORK_REQUEST_ENTITY: &str = "service_work_request";

/// M24/D-428 consent purpose key gating raw-transcript retention. A
/// deployment curates its own `audit_consent_purpose` catalog (see
/// `attome-compliance::consent_seed`'s doc comment — "mutable, admins curate
/// this"); until a purpose with this key exists and is granted, the query
/// below simply finds no matching row, which reads as "not consented" — the
/// same fail-closed default `has_active_consent` documents for itself.
pub const RAW_TRANSCRIPT_CONSENT_PURPOSE: &str = "bot.raw_transcript_retention";

/// Why a handoff was triggered (M54 §5 — the four trigger conditions).
///
/// A model-invoked tool call supplies this directly for the two conditions
/// that are its own call (`UserRequested`, and — once a ranking signal
/// exists — `LowConfidence`); an orchestrator supplies it for the two that
/// are properties of how the turn ended (`StepLimitReached`, `Refusal` — see
/// [`handoff_reason`], which wires those two structurally).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffReason {
    /// The user asked to speak to a person.
    UserRequested,
    /// `turn::MAX_TOOL_STEPS` was reached without an answer.
    StepLimitReached,
    /// A confidence/ranking score fell below threshold. Stretch goal per the
    /// module plan — the trigger *value* exists and this action honours it
    /// when supplied, but nothing in this crate yet computes one to supply
    /// it automatically (no ranking signal is wired up here — see the
    /// implementation report, not silently assumed).
    LowConfidence,
    /// The bot abstained rather than answer ([`LoopOutcome::Abstained`]).
    Refusal,
}

impl HandoffReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::StepLimitReached => "step_limit_reached",
            Self::LowConfidence => "low_confidence",
            Self::Refusal => "refusal",
        }
    }
}

/// How a finished bot turn ended, as far as the handoff triggers care.
///
/// Coarser than [`crate::conversation::TerminalState`]: a caller (`webchat::reply_for`)
/// folds a terminal state and its grounding into one of these, and
/// [`handoff_reason`] maps it to a trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopOutcome {
    /// The model answered.
    Answered,
    /// The model abstained. A **correct** outcome, but it still leaves the
    /// user without an answer.
    Abstained,
    /// `turn::MAX_TOOL_STEPS` was reached.
    ///
    /// **Reported, never folded into an answer.** An answer built from a
    /// curtailed investigation reads exactly like a complete one, and the user
    /// has no way to know the model stopped looking.
    StepLimitReached,
}

/// Maps a finished turn's outcome to the `bot.handoff` reason it corresponds
/// to, when the outcome by itself warrants a handoff (M54 §5).
///
/// This wires two of `bot.handoff`'s four trigger conditions structurally, so
/// the mapping is asserted once here rather than left for every caller to get
/// right independently. The other two are not properties of a finished turn —
/// an explicit user request is a caller decision made before one exists, and
/// `LowConfidence` needs a grounding signal — so callers supply
/// [`HandoffReason::UserRequested`] or `LowConfidence` themselves.
pub fn handoff_reason(outcome: LoopOutcome) -> Option<HandoffReason> {
    match outcome {
        // A completed answer never warrants a handoff — that would turn every
        // successful turn into an escalation.
        LoopOutcome::Answered => None,
        LoopOutcome::StepLimitReached => Some(HandoffReason::StepLimitReached),
        // Abstaining is correct but leaves the user without an answer, which
        // is exactly what a handoff exists to resolve.
        LoopOutcome::Abstained => Some(HandoffReason::Refusal),
    }
}

/// M101 slice 3 — the argument contract, mirroring ``HandoffArgs``.
/// See `descriptor::UNDECLARED_SCHEMA` for why every action carries one, and
/// `lib.rs`'s `schemas_are_wellformed_and_describe_an_object` for what keeps
/// it honest.
const BOT_HANDOFF_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "agent_session_id": {
      "type": "string",
      "format": "uuid",
      "description": "The bot session being escalated."
    },
    "reason": {
      "type": "string",
      "enum": ["user_requested", "step_limit_reached", "low_confidence", "refusal"],
      "description": "Which of the four trigger conditions fired."
    },
    "tool_calls": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Action ids already tried this turn, for the human picking it up."
    },
    "bots_last_message": { "type": "string" },
    "user_request_summary": { "type": "string" }
  },
  "required": ["agent_session_id", "reason"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        BOT_HANDOFF,
        "Escalate this conversation to a human by opening a work request. Use this when \
         the user explicitly asks for a person, when you must refuse to help, or when you \
         are not confident enough to continue — never to answer a question yourself.",
        RiskTier::Reversible,
        Effect::Write,
        // Not idempotent by nature: retrying must not open a SECOND work request for
        // one handoff. Same reasoning `draft_article.rs`'s ARTICLE_DRAFT documents for
        // itself, and the same mechanism (TODO-043) — an agent invocation without a key
        // is refused by the gate before this executor is ever reached.
        RetryClass::RequiresKey,
        attome_modules::MODULE_BOT,
        &[],
    )
    .input_schema(BOT_HANDOFF_SCHEMA)
}

// ── The structured summary ─────────────────────────────────────────────────

/// The structured fields a handoff's description is rendered from, built by
/// the executor from the typed arguments (see the module doc).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TurnDigest {
    /// Every tool `action_id` invoked during the turn, in order. Not
    /// deduplicated — a triager seeing `record.get` three times learns
    /// something a deduplicated list would hide.
    pub tool_calls: Vec<String>,
    /// The model's own last `Answer`, if it had produced one before handing
    /// off. `None` when the turn ended (e.g. the step limit) with no answer
    /// at all.
    pub bots_last_message: Option<String>,
}

// ── Description rendering (pure — unit-tested without a database) ─────────

/// Renders the work request's `description` field from already-safe inputs.
///
/// `include_raw_transcript` is decided by the caller (the executor, after a
/// consent check) — this function does not itself decide whether consent
/// exists, only what to render given that decision, which is what makes the
/// "omitted without consent" behaviour testable without a database.
fn render_description(
    reason: HandoffReason,
    digest: &TurnDigest,
    user_request_summary: Option<&str>,
    raw_transcript: Option<&str>,
    include_raw_transcript: bool,
) -> String {
    let mut out = format!("Handoff reason: {}\n", reason.as_str());

    if digest.tool_calls.is_empty() {
        out.push_str("Tools consulted: none\n");
    } else {
        out.push_str(&format!(
            "Tools consulted: {}\n",
            digest.tool_calls.join(", ")
        ));
    }

    if let Some(s) = user_request_summary
        && !s.trim().is_empty()
    {
        out.push_str(&format!("What the user needs: {s}\n"));
    }

    if let Some(msg) = &digest.bots_last_message
        && !msg.trim().is_empty()
    {
        out.push_str(&format!("Bot's last message to the user: {msg}\n"));
    }

    if include_raw_transcript
        && let Some(raw) = raw_transcript
        && !raw.trim().is_empty()
    {
        out.push_str(
            "\n--- Full conversation transcript (subject has consented to \
             retention, M24) ---\n",
        );
        out.push_str(raw);
        out.push('\n');
    }

    out
}

// ── Consent check (M24/D-428) ──────────────────────────────────────────────

/// True iff `user_id` currently holds a `granted` `audit_consent` row for
/// [`RAW_TRANSCRIPT_CONSENT_PURPOSE`]. Fails closed — an absent purpose, an
/// absent row, or the most recent row being `withdrawn`/`expired` all read as
/// "not consented", the same posture `has_active_consent`
/// (`attome_notification::consent_gate`) documents for itself. Consent is
/// append-only (D-428), so "most recent by `created_at`" is the only correct
/// read of current status.
async fn has_bot_transcript_consent(db: &DbPool, user_id: Uuid) -> Result<bool, AppError> {
    let status: Option<String> = sqlx::query_scalar(
        "SELECT c.status FROM audit_consent c \
         JOIN audit_consent_purpose p ON c.purpose_ref = p.id \
         WHERE p.key = $1 AND c.regarding_entity = $2 AND c.regarding_id = $3 \
         ORDER BY c.created_at DESC LIMIT 1",
    )
    .bind(RAW_TRANSCRIPT_CONSENT_PURPOSE)
    .bind("user_account")
    .bind(user_id.to_string())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(status.as_deref() == Some("granted"))
}

// ── Linking the session (an note, not a new column) ────────────────────

async fn link_session_note(
    db: &DbPool,
    work_request_id: Uuid,
    agent_session_id: Uuid,
    reason: HandoffReason,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO note (id, entity_name, record_id, note_text, is_customer_visible) \
         VALUES ($1, $2, $3, $4, false)",
    )
    .bind(Uuid::now_v7())
    .bind(WORK_REQUEST_ENTITY)
    .bind(work_request_id.to_string())
    .bind(format!(
        "Opened by bot session {agent_session_id} ({}).",
        reason.as_str()
    ))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Notification (M51) ──────────────────────────────────────────────────────

/// Every active user holding `privilege_key`, direct or role-mediated — the
/// same join shape `attome-ai::quality_monitor::admin_recipients` already
/// uses for `system.admin`, parameterised here on `service_work_request.update`.
async fn privilege_holders(db: &DbPool, privilege_key: &str) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT su.id \
         FROM user_account su \
         WHERE (su.is_active IS NULL OR su.is_active = true) \
           AND ( \
             EXISTS ( \
               SELECT 1 FROM user_account_mm_privilege up \
               JOIN privilege p ON p.id = up.privilege_ref \
               WHERE up.user_ref = su.id AND up.is_active = true AND p.is_active = true \
                 AND p.key = $1 \
             ) \
             OR EXISTS ( \
               SELECT 1 FROM user_account_mm_role ur \
               JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
               JOIN privilege p ON p.id = rp.privilege_ref \
               WHERE ur.user_ref = su.id AND ur.is_deleted = false AND rp.is_deleted = false \
                 AND p.is_active = true AND p.key = $1 \
             ) \
           )",
    )
    .bind(privilege_key)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Best-effort: one recipient's dispatch failure (or the whole recipient
/// resolution) is logged and never fails the handoff — the work request has
/// already been created and is correct either way, same "the record is the
/// fact, the alert is a convenience" posture `attome-service::clock` and
/// `quality_monitor` both take for their own notifications.
async fn notify_handoff(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    work_request_id: Uuid,
    reason: HandoffReason,
) {
    let recipients = match privilege_holders(db, "service_work_request.update").await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %e,
                "bot.handoff: failed to resolve work-request notification recipients"
            );
            return;
        }
    };

    let subject = format!("Bot handoff: new work request ({})", reason.as_str());
    let body = format!(
        "A conversational bot escalated a request to a human ({}). \
         Review work request {work_request_id}.",
        reason.as_str()
    );
    for user_id in recipients {
        let req = DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(format!("/work-requests/{work_request_id}")),
            variables: std::collections::HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(e) = create_dispatch(db, notification_cfg, req).await {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                work_request_id = %work_request_id,
                "bot.handoff: notification dispatch failed for one recipient"
            );
        }
    }
}

// ── Executor ────────────────────────────────────────────────────────────────

/// The arguments the model (or an orchestrator acting on its behalf, for the
/// step-limit/refusal triggers) supplies.
///
/// Deliberately narrow and typed, like `read.rs::RecordArgs`: there is no
/// field here for `status`, `request_type`, or `requester_id` — those are set
/// by this code, never by the caller (see [`BotHandoff::execute`]), so a
/// caller-supplied value for any of them is not even representable.
#[derive(Deserialize)]
struct HandoffArgs {
    /// The bot session this handoff is opened from. Must be live and owned by
    /// the caller — see the module doc.
    agent_session_id: Uuid,
    reason: HandoffReason,
    /// Tool `action_id`s consulted this turn, becoming `TurnDigest::tool_calls`.
    #[serde(default)]
    tool_calls: Vec<String>,
    /// The model's own last message, becoming `TurnDigest::bots_last_message`.
    #[serde(default)]
    bots_last_message: Option<String>,
    /// A short description of what the user needs — caller-authored (model or
    /// human), the same trust boundary `draft_article.rs`'s `title`/`body`
    /// already rely on the caller for. Not derived from tool output by this
    /// code either way.
    #[serde(default)]
    user_request_summary: Option<String>,
    /// The full transcript, offered by the caller. Persisted only when
    /// [`has_bot_transcript_consent`] says the subject has granted it — see
    /// the module doc. A caller may always SUPPLY this; whether it survives
    /// is this executor's decision, not the caller's.
    #[serde(default)]
    raw_transcript: Option<String>,
}

fn parse_args(args: &Value) -> Result<HandoffArgs, AppError> {
    serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid bot.handoff arguments: {e}")))
}

#[derive(Debug)]
pub struct BotHandoff;

impl Action for BotHandoff {
    fn id(&self) -> ActionId {
        ActionId(BOT_HANDOFF)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args = parse_args(args)?;
            let db = &state.base.db;

            // The session must be live and owned by the caller. Revocation
            // (TODO-039) must block a handoff exactly as it blocks any other
            // invocation — a revoked bot session opening a work request on
            // the human's behalf would be the same failure a revoked session
            // finishing its tool loop would be.
            let live_session = session::load_live(db, args.agent_session_id)
                .await?
                .ok_or_else(|| {
                    AppError::Validation("agent_session_id does not name a live session".into())
                })?;
            if live_session.owner_user_id != ctx.security.user_id {
                return Err(AppError::Forbidden);
            }

            // **The privilege check the HTTP extractor performs, performed
            // here.** `create_record_for` deliberately does not do it — see
            // its own doc comment, and `draft_article.rs`'s identical
            // reasoning. `require` is the shared implementation the extractor
            // mirrors, locked to it by `record_scoped_policy_matches_require`.
            ctx.security.require(WORK_REQUEST_ENTITY, "create")?;

            // REVIEW-2026-09-02 finding #9: blast-radius caps, agent
            // invocations only — same reasoning `record_update_field.rs`
            // states for its own identical gate.
            let approval = if ctx.is_agent() {
                let Some(session_id) = ctx.agent_session_id else {
                    return Err(AppError::Forbidden);
                };
                crate::write_guard::enforce_write_caps(
                    state,
                    session_id,
                    BOT_HANDOFF,
                    DAILY_HANDOFF_CAP,
                    PER_MINUTE_HANDOFF_RATE_CAP,
                )
                .await?;

                let payload = serde_json::json!({
                    "action_id": BOT_HANDOFF,
                    "agent_session_id": args.agent_session_id,
                    "reason": args.reason.as_str(),
                });
                Some(
                    crate::write_guard::submit_and_auto_approve(
                        state,
                        AUTO_APPROVAL_ACTION_TYPE,
                        ctx.security.user_id,
                        payload,
                        AUTO_APPROVAL_TTL_MINUTES,
                    )
                    .await?,
                )
            } else {
                None
            };

            let digest = TurnDigest {
                tool_calls: args.tool_calls.clone(),
                bots_last_message: args.bots_last_message.clone(),
            };

            // M24/D-428: raw transcript is opt-in per subject, decided here —
            // never by trusting that a caller already checked.
            let consented = if args.raw_transcript.is_some() {
                has_bot_transcript_consent(db, ctx.security.user_id).await?
            } else {
                false
            };

            let description = render_description(
                args.reason,
                &digest,
                args.user_request_summary.as_deref(),
                args.raw_transcript.as_deref(),
                consented,
            );

            // `status`, `request_type`, and `requester_id` are set here, never
            // taken from `args` — see `HandoffArgs`'s doc comment.
            let record = serde_json::json!({
                "title": format!("Bot handoff ({})", args.reason.as_str()),
                "description": description,
                "request_type": "custom",
                "requester_id": ctx.security.user_id,
                "status": "new",
            });

            let (work_request_id, _response) = attome_records::entity_crud::create_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                WORK_REQUEST_ENTITY,
                record,
            )
            .await?;

            link_session_note(db, work_request_id, args.agent_session_id, args.reason).await?;

            notify_handoff(
                db,
                &state.base.config.notification,
                work_request_id,
                args.reason,
            )
            .await;

            if let Some((approval_id, row_version)) = approval {
                crate::write_guard::close_auto_approval(state, approval_id, row_version).await;
            }

            Ok(ActionResult::plain(serde_json::json!({
                "work_request_id": work_request_id,
                // No distinct human-readable number exists on `service_work_request`
                // (unlike `service_ticket.ticket_number`) — the id is the reference.
                "reference": work_request_id.to_string(),
                // C10-B: the invocation ledger stores this result, and the
                // handoff analytics group by it. One of the four schema
                // values, never free text.
                "reason": args.reason.as_str(),
            })))
        })
    }
}

// ── handoff.to_person (AI7-T3) ─────────────────────────────────────────────

/// `handoff.to_person` — an agent hands a ticket to a person, a queue or
/// another agent, with a summary and its reasoning, through the service
/// engine's hand-off ledger (`attome_service::handoff`). `bot.handoff` stays
/// as it is for web chat.
pub const HANDOFF_TO_PERSON: &str = "handoff.to_person";
/// The outcome kind the hand-off records, under rule `ai.handoff`, which
/// AI8's hand-off rate counts.
const HANDOFF_OUTCOME_KIND: &str = "agent_task";

const HANDOFF_TO_PERSON_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "ticket_id": { "type": "string", "format": "uuid", "description": "The ticket to hand off." },
    "to_kind": { "type": "string", "enum": ["user", "queue", "agent"], "description": "Who receives it." },
    "to_ref": { "type": "string", "format": "uuid", "description": "The person, queue or agent." },
    "summary": { "type": "string", "maxLength": 4000, "description": "What the ticket needs, in a few lines." },
    "reasoning": { "type": "string", "maxLength": 4000, "description": "Why it goes to them now." },
    "tool_calls": { "type": "array", "items": { "type": "string" }, "maxItems": 50, "description": "Tools consulted before handing off." }
  },
  "required": ["ticket_id", "to_kind", "to_ref", "summary", "reasoning"],
  "additionalProperties": false
}"#;

pub fn to_person_descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        HANDOFF_TO_PERSON,
        "Hand a ticket to a person, a queue or another agent with a short summary and your \
         reasoning. Use it when the ticket needs a person's judgement or authority; the \
         person can hand it back to you with a note.",
        RiskTier::Reversible,
        Effect::Write,
        // A retry must not hand off twice; the ticket's one-waiting rule
        // would refuse it anyway, but the gate asks an agent for a key.
        RetryClass::RequiresKey,
        attome_modules::MODULE_AI,
        &[],
    )
    .input_schema(HANDOFF_TO_PERSON_SCHEMA)
    .outcome_kind(HANDOFF_OUTCOME_KIND)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToPersonArgs {
    #[serde(default)]
    ticket_id: Option<Uuid>,
    to_kind: String,
    to_ref: Uuid,
    summary: String,
    reasoning: String,
    #[serde(default)]
    tool_calls: Vec<String>,
}

/// The hand-off's summary and reasoning, structured like a work request's
/// description: what the ticket needs, then the tools consulted; the
/// reasoning alone. Empty reasoning is refused. Pure.
pub fn render_handoff(
    summary: &str,
    reasoning: &str,
    tool_calls: &[String],
) -> Result<(String, String), AppError> {
    let reasoning = reasoning.trim();
    if reasoning.is_empty() {
        return Err(AppError::Validation(
            "reasoning is required: say why the ticket goes to them".into(),
        ));
    }
    let summary = summary.trim();
    if summary.is_empty() {
        return Err(AppError::Validation("summary is required".into()));
    }
    let mut out = format!("What the ticket needs: {summary}\n");
    if tool_calls.is_empty() {
        out.push_str("Tools consulted: none\n");
    } else {
        out.push_str(&format!("Tools consulted: {}\n", tool_calls.join(", ")));
    }
    Ok((out, reasoning.to_owned()))
}

/// Refuses a target the caller cannot see: a person or queue the agent's
/// owner may not read.
async fn require_visible_target(
    state: &EngineState,
    ctx: &ActionContext,
    to_kind: attome_service::handoff::ToKind,
    to_ref: Uuid,
) -> Result<(), AppError> {
    use attome_service::handoff::ToKind;
    let entity = match to_kind {
        ToKind::User => "user_account",
        ToKind::Queue => "service_work_queue",
        ToKind::Agent => "ai_agent",
    };
    match attome_records::entity_crud::read_record_bulk(state, &ctx.security, entity, to_ref).await
    {
        Ok(_) => Ok(()),
        Err(AppError::NotFound | AppError::Forbidden) => Err(AppError::Validation(format!(
            "no {} you can see has that id",
            to_kind.as_str()
        ))),
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
pub struct HandoffToPerson;

impl Action for HandoffToPerson {
    fn id(&self) -> ActionId {
        ActionId(HANDOFF_TO_PERSON)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: ToPersonArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid handoff.to_person arguments: {e}"))
            })?;
            let (summary, reasoning) =
                render_handoff(&args.summary, &args.reasoning, &args.tool_calls)?;
            // A conversation with no ticket is bot.handoff's: it opens a work
            // request. A hand-off moves an existing ticket.
            let ticket_id = args.ticket_id.ok_or_else(|| {
                AppError::Validation(
                    "ticket_id is required; to escalate a conversation use bot.handoff".into(),
                )
            })?;
            let to_kind = attome_service::handoff::ToKind::parse(&args.to_kind)
                .ok_or_else(|| AppError::Validation("to_kind is user, queue or agent".into()))?;
            // The ticket and the target must both be the caller's to see.
            attome_records::entity_crud::read_record_bulk(
                state,
                &ctx.security,
                "service_ticket",
                ticket_id,
            )
            .await?;
            require_visible_target(state, ctx, to_kind, args.to_ref).await?;
            if let Some(session_id) = ctx.agent_session_id {
                crate::write_guard::enforce_write_caps(
                    state,
                    session_id,
                    HANDOFF_TO_PERSON,
                    DAILY_HANDOFF_CAP,
                    PER_MINUTE_HANDOFF_RATE_CAP,
                )
                .await?;
            }
            // From the agent of the session (its definition or object), else
            // the person invoking it.
            let agent: Option<Uuid> = match ctx.agent_session_id {
                Some(session_id) => sqlx::query_scalar(
                    "SELECT COALESCE(agent_definition_ref, agent_object_ref) FROM agent_session \
                      WHERE id = $1",
                )
                .bind(session_id)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .flatten(),
                None => None,
            };
            let (from_kind, from_ref) = match (ctx.is_agent(), agent) {
                (true, Some(agent)) => (attome_service::handoff::FromKind::Agent, agent),
                _ => (
                    attome_service::handoff::FromKind::User,
                    ctx.security.user_id,
                ),
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let handoff_id = attome_service::handoff::create_handoff(
                &mut tx,
                state,
                attome_service::handoff::NewHandoff {
                    ticket_id,
                    from_kind,
                    from_ref,
                    to_kind,
                    to_ref: args.to_ref,
                    summary,
                    reasoning,
                    agent_session_ref: ctx.agent_session_id,
                },
                ctx.security.user_id,
            )
            .await?;
            attome_db::tx::commit(tx).await?;

            let proposal = crate::outcome::OutcomeProposal {
                kind: HANDOFF_OUTCOME_KIND,
                entity_logicalname: Some("service_ticket"),
                regarding_entity: Some("service_handoff"),
                regarding_id: Some(handoff_id),
                model_id: None,
                prompt_version: None,
                rule_ref: Some("ai.handoff"),
                proposed_by: Some(ctx.security.user_id),
                organization_ref: None,
                expected_value: Some(serde_json::json!({ "to_kind": to_kind.as_str() })),
            };
            if let Err(error) = crate::outcome::record_proposed(
                &state.base.db,
                Uuid::now_v7(),
                HANDOFF_TO_PERSON,
                &proposal,
                ctx.agent_session_id,
            )
            .await
            {
                tracing::warn!(%handoff_id, %error, "hand-off outcome not recorded");
            }
            Ok(ActionResult::plain(serde_json::json!({
                "handoff_id": handoff_id,
                "ticket_id": ticket_id,
                "to_kind": to_kind.as_str(),
                "to_ref": args.to_ref,
                "status": "pending",
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(serde_json::json!({
            "action": HANDOFF_TO_PERSON,
            "ticket_id": args["ticket_id"],
            "to_kind": args["to_kind"],
            "to_ref": args["to_ref"],
            "summary": args["summary"],
            "reasoning": args["reasoning"],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_to_person_requires_reasoning() {
        assert!(render_handoff("Customer wants a refund", "  ", &[]).is_err());
        assert!(render_handoff("  ", "Needs approval", &[]).is_err());
        let (summary, reasoning) = render_handoff(
            "Customer wants a refund over the limit",
            " Refunds above 1,000 need a supervisor ",
            &["record.get".to_owned(), "search.knowledge".to_owned()],
        )
        .expect("rendered");
        assert_eq!(
            summary,
            "What the ticket needs: Customer wants a refund over the limit\nTools consulted: record.get, search.knowledge\n"
        );
        assert_eq!(reasoning, "Refunds above 1,000 need a supervisor");
        let d = to_person_descriptor();
        assert_eq!(d.risk, RiskTier::Reversible);
        assert_eq!(d.outcome_kind, Some("agent_task"));
    }

    // ── Trigger wiring (M54 §5) ─────────────────────────────────────────────

    /// The step-bound-hit and refusal triggers are mapped structurally; an
    /// answered turn never triggers a handoff.
    #[test]
    fn handoff_reason_wires_the_step_limit_and_refusal_triggers() {
        assert_eq!(handoff_reason(LoopOutcome::Answered), None);
        assert_eq!(
            handoff_reason(LoopOutcome::StepLimitReached),
            Some(HandoffReason::StepLimitReached)
        );
        assert_eq!(
            handoff_reason(LoopOutcome::Abstained),
            Some(HandoffReason::Refusal)
        );
    }

    // ── Description rendering ───────────────────────────────────────────────

    #[test]
    fn the_description_names_the_reason_and_tools_consulted() {
        let digest = TurnDigest {
            tool_calls: vec!["search.knowledge".into(), "record.get".into()],
            bots_last_message: Some("I could not find that policy.".into()),
        };
        let out = render_description(
            HandoffReason::Refusal,
            &digest,
            Some("wants a refund on order 123"),
            None,
            false,
        );
        assert!(out.contains("Handoff reason: refusal"));
        assert!(out.contains("search.knowledge, record.get"));
        assert!(out.contains("wants a refund on order 123"));
        assert!(out.contains("I could not find that policy."));
    }

    /// **M24: raw transcript is never included without an explicit
    /// consented=true from the caller**, whatever the caller supplied.
    #[test]
    fn raw_transcript_is_omitted_unless_explicitly_included() {
        let digest = TurnDigest::default();
        let secret = "the customer's card number is 4111 1111 1111 1111";

        let without_consent = render_description(
            HandoffReason::UserRequested,
            &digest,
            None,
            Some(secret),
            false,
        );
        assert!(
            !without_consent.contains(secret),
            "the raw transcript must not appear when consent is not established"
        );

        let with_consent = render_description(
            HandoffReason::UserRequested,
            &digest,
            None,
            Some(secret),
            true,
        );
        assert!(
            with_consent.contains(secret),
            "the raw transcript must appear once explicitly included"
        );
    }

    #[test]
    fn an_empty_digest_still_renders_a_readable_description() {
        let digest = TurnDigest::default();
        let out = render_description(HandoffReason::StepLimitReached, &digest, None, None, false);
        assert!(out.contains("Tools consulted: none"));
    }

    // ── Descriptor shape ─────────────────────────────────────────────────────

    #[test]
    fn it_is_a_reversible_write_requiring_an_idempotency_key() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Reversible);
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.retry, RetryClass::RequiresKey);
    }

    #[test]
    fn it_is_gated_on_the_bot_module() {
        let d = descriptor();
        assert_eq!(
            (d.module.word, d.module.mask),
            (
                attome_modules::MODULE_BOT.word,
                attome_modules::MODULE_BOT.mask
            )
        );
    }

    /// **The ordering that makes this safe**, same reasoning
    /// `draft_article.rs::the_privilege_check_precedes_the_create` documents:
    /// asserted structurally because the failure — a reorder during a later
    /// tidy-up — is silent otherwise.
    #[test]
    fn the_privilege_check_precedes_the_create() {
        let source = include_str!("bot_handoff.rs");
        let code = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("test marker");

        let check = code
            .find(r#"require(WORK_REQUEST_ENTITY, "create")"#)
            .expect("the executor must check the create privilege itself");
        let create = code
            .find("create_record_for(")
            .expect("the executor must call the create path");
        assert!(
            check < create,
            "the privilege check must come BEFORE the create, or an agent \
             restricted to Read actions reaches create_one unchecked"
        );
    }

    /// `status`/`request_type`/`requester_id` must never come from `args` —
    /// `HandoffArgs` simply has no such field, so this is enforced by the
    /// type system rather than by a runtime check, but the constant values
    /// this code writes are pinned here so a later edit that starts reading
    /// them from `args` is a visible diff against this test.
    #[test]
    fn status_and_request_type_are_fixed_constants_not_caller_supplied() {
        let source = include_str!("bot_handoff.rs");
        let code = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("test marker");
        assert!(code.contains(r#""status": "new""#));
        assert!(code.contains(r#""request_type": "custom""#));
        assert!(!code.contains(r#"args.get("status")"#));
        assert!(!code.contains(r#"args.get("requester_id")"#));
    }
}
