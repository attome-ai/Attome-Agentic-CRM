//! C10-B — bot analytics: `GET /api/v1/admin/ai/bot-analytics`.
//!
//! Implements the formulas fixed in `document/chatbot/01-architecture.md`,
//! "C10-B: analytics and feedback", and nothing else:
//!
//! - **turns** and **tool calls** from `ai_conversation_event`, by event
//!   time, so a closed window's figures never change;
//! - **handoffs** from completed agent `bot.handoff` invocations — the one
//!   record every handoff path writes, including the web-chat channel's,
//!   which never enters the conversation tool-call ledger;
//! - **deflection** over a `started_at` cohort, from turn outcomes and
//!   handoffs, never from assistant text;
//! - **feedback** from `ai_message_feedback`.
//!
//! Every figure is a read-time aggregate over append-only rows: no counter,
//! rollup or trigger sits on the event-writing path.
//!
//! **Aggregates only, administrators only.** The route is `Authorized<Admin>`,
//! like `/admin/ai/compliance-report`, because the figures are
//! deployment-wide. The response carries no conversation id, user id, message
//! text, tool arguments or query text.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::{IntoParams, ToSchema};

use crate::actions::bot_handoff::BOT_HANDOFF;
use crate::conversation::{Surface, TerminalState};

/// The default window, ending now.
const DEFAULT_WINDOW_DAYS: i64 = 7;
/// The longest window a report may cover.
const MAX_WINDOW_DAYS: i64 = 366;

/// The twelve terminal states, in the order D-565 lists them.
const TERMINAL_STATES: [TerminalState; 13] = [
    TerminalState::Completed,
    TerminalState::MaxSteps,
    TerminalState::BudgetExceeded,
    TerminalState::SessionRevoked,
    TerminalState::KillSwitch,
    TerminalState::PrivilegeRevoked,
    TerminalState::AwaitingConfirmation,
    TerminalState::AwaitingApproval,
    TerminalState::InvalidToolCall,
    TerminalState::ModelFailure,
    TerminalState::ToolFailure,
    TerminalState::ProtocolError,
    TerminalState::Cancelled,
];

/// The handoff reasons the report names; anything else is `unknown`.
const HANDOFF_REASONS: [&str; 4] = [
    "user_requested",
    "step_limit_reached",
    "low_confidence",
    "refusal",
];

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/// A report's scope: `[from, to)`, and optionally one surface.
#[derive(Debug, Clone)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub surface: Option<Surface>,
}

impl Window {
    /// Resolves the query's optional bounds against `now`: `to` defaults to
    /// `now`, `from` to seven days before `to`. `to` must be after `from`, and
    /// the window at most 366 days.
    pub fn resolve(
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        surface: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Self, AppError> {
        let to = to.unwrap_or(now);
        let from = from.unwrap_or(to - Duration::days(DEFAULT_WINDOW_DAYS));
        if to <= from {
            return Err(AppError::Validation("`to` must be after `from`".into()));
        }
        if to - from > Duration::days(MAX_WINDOW_DAYS) {
            return Err(AppError::Validation(format!(
                "the window may cover at most {MAX_WINDOW_DAYS} days"
            )));
        }
        let surface = surface
            .map(|s| {
                Surface::parse(s).ok_or_else(|| {
                    AppError::Validation(
                        "`surface` must be one of internal, webchat, mcp, workflow".into(),
                    )
                })
            })
            .transpose()?;
        Ok(Self { from, to, surface })
    }

    fn surface_str(&self) -> Option<&'static str> {
        self.surface.map(Surface::as_str)
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct BotAnalytics {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// The surface filter, or `null` for every surface.
    pub surface: Option<String>,
    pub turns: TurnStats,
    pub tool_calls: ToolCallStats,
    pub handoffs: HandoffStats,
    pub deflection: DeflectionStats,
    pub feedback: FeedbackStats,
}

/// Turns, by event time.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct TurnStats {
    /// `turn.started` events in the window.
    pub started: i64,
    /// `turn.completed` events in the window. Each turn ends exactly once.
    pub ended: i64,
    /// Ended with `completed`.
    pub completed: i64,
    /// Ended with `awaiting_confirmation` or `awaiting_approval`: stopped for
    /// a human, neither a success nor a failure.
    pub awaiting: i64,
    /// Ended with `cancelled`: the user pressed Stop (C11 B4). Neither a
    /// success nor a failure, so counted on its own.
    pub cancelled: i64,
    /// Ended with any of the other nine states.
    pub failed: i64,
    /// `completed / ended`; `null` when nothing ended.
    pub completion_rate: Option<f64>,
    /// Every terminal state, zero-filled.
    pub by_terminal_state: BTreeMap<String, i64>,
}

/// One action's tool-call events in the window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, ToSchema)]
pub struct ToolCallCounts {
    /// `tool.call.proposed` events, reopened proposals excluded.
    pub proposed: i64,
    /// `tool.call.completed` events.
    pub completed: i64,
    /// `tool.call.failed{rejected}` events.
    pub rejected: i64,
    /// `tool.call.failed{invalidated}` events.
    pub invalidated: i64,
    /// `tool.call.failed{expired}` events.
    pub expired: i64,
    /// `approval.required` events.
    pub approval_required: i64,
}

impl ToolCallCounts {
    fn add(&mut self, other: &Self) {
        self.proposed += other.proposed;
        self.completed += other.completed;
        self.rejected += other.rejected;
        self.invalidated += other.invalidated;
        self.expired += other.expired;
        self.approval_required += other.approval_required;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ActionToolCalls {
    pub action_id: String,
    #[serde(flatten)]
    pub counts: ToolCallCounts,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ToolCallStats {
    pub total: ToolCallCounts,
    /// One row per action id, sorted by it.
    pub by_action: Vec<ActionToolCalls>,
}

/// Completed agent `bot.handoff` invocations in the window.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct HandoffStats {
    pub total: i64,
    /// `user_requested`, `step_limit_reached`, `low_confidence`, `refusal`,
    /// `unknown` — every key present, zero-filled.
    pub by_reason: BTreeMap<String, i64>,
}

/// Conversations started in the window, as they stand when the report runs.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DeflectionStats {
    /// With at least one turn outcome. The denominator.
    pub engaged: i64,
    /// Not handed off, and the last turn ended `completed`.
    pub deflected: i64,
    /// With a completed `bot.handoff`.
    pub handed_off: i64,
    /// Neither: not handed off, and the last turn ended otherwise.
    pub unresolved: i64,
    pub deflection_rate: Option<f64>,
    pub handoff_rate: Option<f64>,
}

/// Votes on turn answers written in the window.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct FeedbackStats {
    /// Rateable messages: an assistant message with a terminal state.
    pub answers: i64,
    /// Answers with at least one vote.
    pub rated_answers: i64,
    pub up: i64,
    pub down: i64,
    /// `up / (up + down)`; `null` with no votes.
    pub up_rate: Option<f64>,
    /// `rated_answers / answers`; `null` with no answers.
    pub coverage: Option<f64>,
}

fn ratio(numerator: i64, denominator: i64) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

// ---------------------------------------------------------------------------
// The queries — one per formula family, each bound, none interpolated
// ---------------------------------------------------------------------------

/// Builds the report for `window`.
pub async fn report(db: &PgPool, window: &Window) -> Result<BotAnalytics, AppError> {
    Ok(BotAnalytics {
        from: window.from,
        to: window.to,
        surface: window.surface_str().map(str::to_owned),
        turns: turns(db, window).await?,
        tool_calls: tool_calls(db, window).await?,
        handoffs: handoffs(db, window).await?,
        deflection: deflection(db, window).await?,
        feedback: feedback(db, window).await?,
    })
}

async fn turns(db: &PgPool, w: &Window) -> Result<TurnStats, AppError> {
    let rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT e.event_type, e.payload->>'terminal_state', COUNT(*) \
           FROM ai_conversation_event e \
           JOIN ai_conversation c ON c.id = e.conversation_id \
          WHERE e.event_type IN ('turn.started', 'turn.completed') \
            AND e.created_at >= $1 AND e.created_at < $2 \
            AND ($3::text IS NULL OR c.surface = $3) \
          GROUP BY 1, 2",
    )
    .bind(w.from)
    .bind(w.to)
    .bind(w.surface_str())
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut by_terminal_state: BTreeMap<String, i64> = TERMINAL_STATES
        .iter()
        .map(|s| (s.as_str().to_owned(), 0))
        .collect();
    let mut started = 0;
    for (event_type, state, n) in rows {
        if event_type == "turn.started" {
            started += n;
        } else if let Some(state) = state {
            // An unknown state cannot be written (the ledger's CHECK), so a
            // miss here is a contract break worth failing on, not hiding.
            let slot = by_terminal_state.get_mut(&state).ok_or_else(|| {
                AppError::internal(format!("turn.completed with unknown state {state:?}"))
            })?;
            *slot += n;
        }
    }
    let count = |pred: fn(TerminalState) -> bool| -> i64 {
        TERMINAL_STATES
            .iter()
            .filter(|s| pred(**s))
            .map(|s| by_terminal_state[s.as_str()])
            .sum()
    };
    let completed = count(TerminalState::is_success);
    let awaiting = count(TerminalState::is_resumable);
    let cancelled = by_terminal_state[TerminalState::Cancelled.as_str()];
    let ended: i64 = by_terminal_state.values().sum();
    Ok(TurnStats {
        started,
        ended,
        completed,
        awaiting,
        cancelled,
        failed: ended - completed - awaiting - cancelled,
        completion_rate: ratio(completed, ended),
        by_terminal_state,
    })
}

async fn tool_calls(db: &PgPool, w: &Window) -> Result<ToolCallStats, AppError> {
    let rows: Vec<(Option<String>, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT e.payload->>'action_id', e.event_type, e.payload->>'status', COUNT(*) \
           FROM ai_conversation_event e \
           JOIN ai_conversation c ON c.id = e.conversation_id \
          WHERE e.event_type IN ('tool.call.proposed', 'tool.call.completed', \
                                 'tool.call.failed', 'approval.required') \
            AND NOT (e.event_type = 'tool.call.proposed' \
                     AND COALESCE((e.payload->>'reopened')::boolean, false)) \
            AND e.created_at >= $1 AND e.created_at < $2 \
            AND ($3::text IS NULL OR c.surface = $3) \
          GROUP BY 1, 2, 3",
    )
    .bind(w.from)
    .bind(w.to)
    .bind(w.surface_str())
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut by_action: BTreeMap<String, ToolCallCounts> = BTreeMap::new();
    for (action_id, event_type, status, n) in rows {
        let action_id = action_id.ok_or_else(|| {
            AppError::internal(format!("{event_type} event without an action_id"))
        })?;
        let counts = by_action.entry(action_id).or_default();
        let slot = match (event_type.as_str(), status.as_deref()) {
            ("tool.call.proposed", _) => &mut counts.proposed,
            ("tool.call.completed", _) => &mut counts.completed,
            ("approval.required", _) => &mut counts.approval_required,
            ("tool.call.failed", Some("rejected")) => &mut counts.rejected,
            ("tool.call.failed", Some("invalidated")) => &mut counts.invalidated,
            ("tool.call.failed", Some("expired")) => &mut counts.expired,
            (other, status) => {
                return Err(AppError::internal(format!(
                    "unexpected tool-call event {other} with status {status:?}"
                )));
            }
        };
        *slot += n;
    }
    let mut total = ToolCallCounts::default();
    for counts in by_action.values() {
        total.add(counts);
    }
    Ok(ToolCallStats {
        total,
        by_action: by_action
            .into_iter()
            .map(|(action_id, counts)| ActionToolCalls { action_id, counts })
            .collect(),
    })
}

async fn handoffs(db: &PgPool, w: &Window) -> Result<HandoffStats, AppError> {
    let rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT i.result->>'reason', COUNT(*) \
           FROM action_invocation i \
           JOIN agent_session s ON s.id = i.agent_session_id \
          WHERE i.action_id = $4 AND i.outcome = 'completed' AND i.initiator = 1 \
            AND i.created_at >= $1 AND i.created_at < $2 \
            AND ($3::text IS NULL OR s.surface = $3) \
          GROUP BY 1",
    )
    .bind(w.from)
    .bind(w.to)
    .bind(w.surface_str())
    .bind(BOT_HANDOFF)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut by_reason: BTreeMap<String, i64> = HANDOFF_REASONS
        .iter()
        .chain(std::iter::once(&"unknown"))
        .map(|r| ((*r).to_owned(), 0))
        .collect();
    let mut total = 0;
    for (reason, n) in rows {
        let key = reason
            .filter(|r| HANDOFF_REASONS.contains(&r.as_str()))
            .unwrap_or_else(|| "unknown".to_owned());
        *by_reason.entry(key).or_default() += n;
        total += n;
    }
    Ok(HandoffStats { total, by_reason })
}

async fn deflection(db: &PgPool, w: &Window) -> Result<DeflectionStats, AppError> {
    let (engaged, deflected, handed_off): (i64, i64, i64) = sqlx::query_as(
        "WITH cohort AS ( \
             SELECT c.id, c.agent_session_id \
               FROM ai_conversation c \
              WHERE c.started_at >= $1 AND c.started_at < $2 \
                AND ($3::text IS NULL OR c.surface = $3) \
         ), last_turn AS ( \
             SELECT DISTINCT ON (e.conversation_id) \
                    e.conversation_id, e.payload->>'terminal_state' AS state \
               FROM ai_conversation_event e \
               JOIN cohort ON cohort.id = e.conversation_id \
              WHERE e.event_type = 'turn.completed' \
              ORDER BY e.conversation_id, e.ordinal DESC \
         ), classified AS ( \
             SELECT lt.state, EXISTS ( \
                        SELECT 1 FROM action_invocation i \
                         WHERE i.agent_session_id = cohort.agent_session_id \
                           AND i.action_id = $4 AND i.outcome = 'completed' \
                           AND i.initiator = 1) AS handed_off \
               FROM cohort JOIN last_turn lt ON lt.conversation_id = cohort.id \
         ) \
         SELECT COUNT(*), \
                COUNT(*) FILTER (WHERE NOT handed_off AND state = 'completed'), \
                COUNT(*) FILTER (WHERE handed_off) \
           FROM classified",
    )
    .bind(w.from)
    .bind(w.to)
    .bind(w.surface_str())
    .bind(BOT_HANDOFF)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(DeflectionStats {
        engaged,
        deflected,
        handed_off,
        unresolved: engaged - deflected - handed_off,
        deflection_rate: ratio(deflected, engaged),
        handoff_rate: ratio(handed_off, engaged),
    })
}

async fn feedback(db: &PgPool, w: &Window) -> Result<FeedbackStats, AppError> {
    let (answers, rated_answers, up, down): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), \
                COUNT(*) FILTER (WHERE f.up + f.down > 0), \
                COALESCE(SUM(f.up), 0)::bigint, \
                COALESCE(SUM(f.down), 0)::bigint \
           FROM ai_message m \
           JOIN ai_conversation c ON c.id = m.conversation_id \
           CROSS JOIN LATERAL ( \
               SELECT COUNT(*) FILTER (WHERE fb.vote = 'up') AS up, \
                      COUNT(*) FILTER (WHERE fb.vote = 'down') AS down \
                 FROM ai_message_feedback fb WHERE fb.message_id = m.id) f \
          WHERE m.role = 'assistant' AND m.terminal_state IS NOT NULL \
            AND m.created_at >= $1 AND m.created_at < $2 \
            AND ($3::text IS NULL OR c.surface = $3)",
    )
    .bind(w.from)
    .bind(w.to)
    .bind(w.surface_str())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(FeedbackStats {
        answers,
        rated_answers,
        up,
        down,
        up_rate: ratio(up, up + down),
        coverage: ratio(rated_answers, answers),
    })
}

// ---------------------------------------------------------------------------
// The route
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AnalyticsQuery {
    /// Inclusive start, UTC. Defaults to seven days before `to`.
    pub from: Option<DateTime<Utc>>,
    /// Exclusive end, UTC. Defaults to now.
    pub to: Option<DateTime<Utc>>,
    /// `internal` | `webchat` | `mcp` | `workflow`; omitted for all.
    pub surface: Option<String>,
}

/// `GET /api/v1/admin/ai/bot-analytics` — deployment-wide chatbot figures for
/// one window: turns, tool calls by type, handoffs by reason, deflection and
/// thumbs. Aggregates only; the formulas are `01-architecture.md`'s C10-B.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/bot-analytics",
    tag = "action",
    params(AnalyticsQuery),
    responses(
        (status = 200, description = "Success", body = BotAnalytics),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 422, description = "The window is empty, longer than 366 days, or the surface is unknown", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_bot_analytics(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<AnalyticsQuery>,
) -> Result<Json<BotAnalytics>, AppError> {
    let window = Window::resolve(q.from, q.to, q.surface.as_deref(), Utc::now())?;
    Ok(Json(report(&state.base.db, &window).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/ai/bot-analytics", get(get_bot_analytics))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_bot_analytics))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn the_window_defaults_to_the_last_seven_days() {
        let now = at("2026-09-22T12:00:00Z");
        let w = Window::resolve(None, None, None, now).unwrap();
        assert_eq!((w.from, w.to), (at("2026-09-15T12:00:00Z"), now));
        assert!(w.surface.is_none());
    }

    #[test]
    fn a_bad_window_or_surface_is_refused() {
        let now = at("2026-09-22T12:00:00Z");
        let refused = |from, to, surface| {
            matches!(
                Window::resolve(from, to, surface, now),
                Err(AppError::Validation(_))
            )
        };
        assert!(refused(Some(now), Some(now), None), "empty window");
        assert!(
            refused(Some(now), Some(at("2026-09-21T00:00:00Z")), None),
            "reversed"
        );
        assert!(
            refused(Some(at("2025-01-01T00:00:00Z")), None, None),
            "over 366 days"
        );
        assert!(refused(None, None, Some("sms")), "unknown surface");
        assert!(Window::resolve(None, None, Some("webchat"), now).is_ok());
    }

    #[test]
    fn every_terminal_state_is_classified_exactly_once() {
        let success = TERMINAL_STATES.iter().filter(|s| s.is_success()).count();
        let awaiting = TERMINAL_STATES.iter().filter(|s| s.is_resumable()).count();
        assert_eq!((success, awaiting), (1, 2));
        assert!(
            !TERMINAL_STATES
                .iter()
                .any(|s| s.is_success() && s.is_resumable())
        );
        let names: std::collections::BTreeSet<_> =
            TERMINAL_STATES.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), 13);
        assert!(
            TERMINAL_STATES.contains(&TerminalState::Cancelled),
            "Stop's state is counted, on its own"
        );
    }

    #[test]
    fn handoff_reasons_match_the_action_schema() {
        use crate::actions::bot_handoff::HandoffReason::*;
        let declared: Vec<_> = [UserRequested, StepLimitReached, LowConfidence, Refusal]
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(declared, HANDOFF_REASONS);
    }

    #[test]
    fn a_rate_is_null_without_a_denominator() {
        assert_eq!(ratio(0, 0), None);
        assert_eq!(ratio(1, 4), Some(0.25));
    }
}
