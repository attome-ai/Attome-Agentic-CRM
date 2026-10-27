//! Agent autonomy levels (roadmap AH8, V2-D693): how much an agent may do on
//! its own, set by an administrator per agent definition and per action.
//!
//! | Level | The agent… |
//! |---|---|
//! | 0 `suggest` | proposes; the person does it |
//! | 1 `ask_first` | confirm (Reversible) or four-eyes approval (Consequential) |
//! | `act_on_review` | staged; the person applies or discards the session's staged actions together (V2-D702) |
//! | 2 `act_with_undo` | runs after an undo window, during which it can be cancelled |
//! | 3 `act_and_report` | runs now and tells the person it acts for |
//! | 4 `automatic` | runs now |
//!
//! The numbers are the stored codes; `act_on_review` is stored as 5 but
//! ranks between `ask_first` and `act_with_undo` (the enum's order is the
//! rank).
//!
//! **No row, no change.** An action with no row keeps the gate's built-in
//! matrix exactly as before this module existed: a Reversible write runs and
//! asks on a tainted context, a Consequential action needs approval. A row is
//! the only way above that, and only an administrator writes one.
//!
//! **Limits ask, they do not refuse.** An invocation over any limit of its
//! row (daily count, money cap, owned records only, hours) is lowered to
//! `ask_first` and the request names the limit. A row or a limit that cannot
//! be read is `ask_first` too (fails closed).
//!
//! **The fixed rail** lives in the gate, not here: untrusted text in the
//! context lowers the level by one, and no row can turn that off
//! (`gate::evaluate`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, Effect, RiskTier};

/// The undo window when a row does not set one, and its bounds.
pub const DEFAULT_UNDO_SECONDS: u32 = 300;
pub const MIN_UNDO_SECONDS: u32 = 30;
pub const MAX_UNDO_SECONDS: u32 = 86_400;

/// How much an agent may do on its own. Ordered: a higher level does more.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    // Declared in rank order: the derived `Ord` is the rank.
    Suggest,
    AskFirst,
    /// V2-D702: staged until the person applies the session's staged actions.
    ActOnReview,
    ActWithUndo,
    ActAndReport,
    Automatic,
}

impl AutonomyLevel {
    /// Every level, lowest first.
    pub const ALL: [Self; 6] = [
        Self::Suggest,
        Self::AskFirst,
        Self::ActOnReview,
        Self::ActWithUndo,
        Self::ActAndReport,
        Self::Automatic,
    ];

    /// One level lower, never below `suggest`.
    #[must_use]
    pub fn lowered(self) -> Self {
        match self {
            Self::Suggest | Self::AskFirst => Self::Suggest,
            Self::ActOnReview => Self::AskFirst,
            Self::ActWithUndo => Self::ActOnReview,
            Self::ActAndReport => Self::ActWithUndo,
            Self::Automatic => Self::ActAndReport,
        }
    }

    /// The stored code. Stable: a new level takes a new code.
    pub fn as_i16(self) -> i16 {
        match self {
            Self::Suggest => 0,
            Self::AskFirst => 1,
            Self::ActWithUndo => 2,
            Self::ActAndReport => 3,
            Self::Automatic => 4,
            Self::ActOnReview => 5,
        }
    }

    pub fn from_i16(v: i16) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_i16() == v)
    }
}

/// The level an action behaves at when it has no row, as shown on the admin
/// screen. The gate does not read this: without a row it runs its built-in
/// matrix, which these values describe for a clean context.
pub fn default_for(risk: RiskTier) -> AutonomyLevel {
    match risk {
        RiskTier::Read => AutonomyLevel::Automatic,
        RiskTier::Reversible => AutonomyLevel::Automatic,
        RiskTier::Consequential => AutonomyLevel::AskFirst,
    }
}

/// What the gate receives: the level a row grants for this invocation, after
/// its limits and any per-write approval policy, and the row's undo window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutonomyGrant {
    pub level: AutonomyLevel,
    pub undo_seconds: u32,
}

impl AutonomyGrant {
    fn ask_first() -> Self {
        Self {
            level: AutonomyLevel::AskFirst,
            undo_seconds: DEFAULT_UNDO_SECONDS,
        }
    }
}

/// One stored row.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AutonomyRow {
    pub id: Uuid,
    pub agent_definition_id: Uuid,
    pub action_id: String,
    #[schema(value_type = i16)]
    pub level: i16,
    pub undo_seconds: i32,
    pub daily_limit: Option<i32>,
    pub money_cap_minor: Option<i64>,
    pub currency: Option<String>,
    pub owned_records_only: bool,
    pub hours_start: Option<i16>,
    pub hours_end: Option<i16>,
    pub time_zone: Option<String>,
    pub updated_by: Uuid,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

const ROW_COLUMNS: &str = "id, agent_definition_id, action_id, level, undo_seconds, daily_limit, \
     money_cap_minor, currency, owned_records_only, hours_start, hours_end, time_zone, \
     updated_by, updated_at, row_version";

impl AutonomyRow {
    fn grant(&self) -> AutonomyGrant {
        AutonomyGrant {
            level: AutonomyLevel::from_i16(self.level).unwrap_or(AutonomyLevel::AskFirst),
            undo_seconds: u32::try_from(self.undo_seconds)
                .unwrap_or(DEFAULT_UNDO_SECONDS)
                .clamp(MIN_UNDO_SECONDS, MAX_UNDO_SECONDS),
        }
    }
}

/// The level resolved for one agent invocation, and the limit that lowered
/// it, when one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    pub grant: Option<AutonomyGrant>,
    pub limit_exceeded: Option<&'static str>,
}

impl Resolution {
    const NONE: Self = Self {
        grant: None,
        limit_exceeded: None,
    };
}

/// The level this agent invocation runs at. `grant: None` for a person, for
/// an agent session with no definition, and for an action with no row: the
/// gate's built-in matrix applies.
pub async fn resolve(
    state: &EngineState,
    ctx: &ActionContext,
    descriptor: &ActionDescriptor,
    args: &Value,
) -> Resolution {
    if !ctx.is_agent() || descriptor.risk == RiskTier::Read {
        return Resolution::NONE;
    }
    let Some(session_id) = ctx.agent_session_id else {
        return Resolution::NONE;
    };
    match resolve_inner(state, ctx, session_id, descriptor, args).await {
        Ok(resolution) => resolution,
        Err(e) => {
            tracing::warn!(
                action_id = %descriptor.id,
                agent_session_id = %session_id,
                error = %e,
                "autonomy level could not be read; the invocation asks first"
            );
            Resolution {
                grant: Some(AutonomyGrant::ask_first()),
                limit_exceeded: None,
            }
        }
    }
}

async fn resolve_inner(
    state: &EngineState,
    ctx: &ActionContext,
    session_id: Uuid,
    descriptor: &ActionDescriptor,
    args: &Value,
) -> Result<Resolution, AppError> {
    let definition: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT agent_definition_ref FROM agent_session WHERE id = $1")
            .bind(session_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(definition) = definition.flatten() else {
        return Ok(Resolution::NONE);
    };
    let row: Option<AutonomyRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM ai_autonomy_level \
         WHERE agent_definition_id = $1 AND action_id = $2"
    ))
    .bind(definition)
    .bind(descriptor.id.0)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(Resolution::NONE);
    };
    let mut grant = row.grant();
    let mut limit_exceeded = None;
    if grant.level > AutonomyLevel::AskFirst {
        limit_exceeded =
            first_limit_exceeded(state, ctx, &row, definition, descriptor, args).await?;
        // N30: an administrator's per-write approval policy still asks.
        if limit_exceeded.is_none()
            && descriptor.effect == Effect::Write
            && crate::write_policy::requires_approval(&state.base.db, descriptor.id.0, args).await?
        {
            limit_exceeded = Some("a per-write approval policy names this action");
        }
        if limit_exceeded.is_some() {
            grant.level = AutonomyLevel::AskFirst;
        }
    }
    Ok(Resolution {
        grant: Some(grant),
        limit_exceeded,
    })
}

/// The first of the row's limits this invocation is over, when it is over one.
async fn first_limit_exceeded(
    state: &EngineState,
    ctx: &ActionContext,
    row: &AutonomyRow,
    definition: Uuid,
    descriptor: &ActionDescriptor,
    args: &Value,
) -> Result<Option<&'static str>, AppError> {
    if !within_hours(row, Utc::now()) {
        return Ok(Some("outside the hours set for this action"));
    }
    if let Some(cap) = row.money_cap_minor
        && !within_money_cap(descriptor, args, cap)
    {
        return Ok(Some("over the money cap set for this action"));
    }
    if let Some(limit) = row.daily_limit {
        let used = used_today(state, definition, descriptor.id.0).await?;
        if used >= i64::from(limit) {
            return Ok(Some("the daily limit for this action is used up"));
        }
    }
    if row.owned_records_only && !targets_owned_record(state, ctx, args).await? {
        return Ok(Some(
            "the record is not owned by the person the agent acts for",
        ));
    }
    Ok(None)
}

/// Whether `now` falls in the row's hours, in its time zone (UTC when unset).
/// No hours set: always.
pub fn within_hours(row: &AutonomyRow, now: DateTime<Utc>) -> bool {
    let (Some(start), Some(end)) = (row.hours_start, row.hours_end) else {
        return true;
    };
    let hour = match row.time_zone.as_deref() {
        Some(tz) => match tz.parse::<chrono_tz::Tz>() {
            Ok(tz) => now.with_timezone(&tz).hour(),
            // An unknown zone cannot be checked: outside (fails closed).
            Err(_) => return false,
        },
        None => now.hour(),
    };
    let hour = i16::try_from(hour).unwrap_or(i16::MAX);
    hour >= start && hour < end
}

/// Whether the amount the action declares as its money argument is within
/// `cap` (minor units). An action that declares no money argument, or whose
/// argument is missing or not a whole number, is over the cap.
pub fn within_money_cap(descriptor: &ActionDescriptor, args: &Value, cap: i64) -> bool {
    let Some(arg) = descriptor.money_arg else {
        return false;
    };
    match args.get(arg).and_then(Value::as_i64) {
        Some(amount) => amount >= 0 && amount <= cap,
        None => false,
    }
}

/// Invocations of `action_id` by sessions of this agent definition since UTC
/// midnight: completed ones, plus ones waiting in their undo window.
async fn used_today(
    state: &EngineState,
    definition: Uuid,
    action_id: &str,
) -> Result<i64, AppError> {
    let midnight = Utc::now()
        .date_naive()
        .and_time(chrono::NaiveTime::MIN)
        .and_utc();
    sqlx::query_scalar(
        "SELECT \
           (SELECT COUNT(*) FROM action_invocation i \
              JOIN agent_session s ON s.id = i.agent_session_id \
             WHERE s.agent_definition_ref = $1 AND i.action_id = $2 \
               AND i.outcome = 'completed' AND i.created_at >= $3) \
         + (SELECT COUNT(*) FROM ai_deferred_action d \
              JOIN agent_session s ON s.id = d.agent_session_id \
             WHERE s.agent_definition_ref = $1 AND d.action_id = $2 \
               AND d.status IN ('staged', 'pending', 'running') AND d.created_at >= $3)",
    )
    .bind(definition)
    .bind(action_id)
    .bind(midnight)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Whether the record the arguments name is owned by the person the agent
/// acts for. No single record named: not owned.
async fn targets_owned_record(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<bool, AppError> {
    let Some((entity, record_id)) = crate::approval::target_of(args) else {
        return Ok(false);
    };
    if state.entities.load().get(&entity).is_none() {
        return Ok(false);
    }
    let table = attome_core::quote_ident(&entity);
    let live = attome_core::live_row_predicate("t", false)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(&format!(
        "SELECT t.owner_ref FROM {table} t WHERE t.id = $1 {live}"
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(owner.flatten() == Some(ctx.security.user_id))
}

// ── What agents ran on their own (AH8-T8) ───────────────────────────────────

/// The level the gate applied to this agent invocation: the granted level,
/// lowered by one on a tainted context. `None` when no level applied.
pub fn effective_level(
    ctx: &ActionContext,
    descriptor: &ActionDescriptor,
) -> Option<AutonomyLevel> {
    if !ctx.is_agent() || descriptor.autonomy_locked || descriptor.risk == RiskTier::Read {
        return None;
    }
    ctx.autonomy.map(|grant| {
        if ctx.contains_retrieved_content {
            grant.level.lowered()
        } else {
            grant.level
        }
    })
}

/// Records an action an agent just ran on its own (`act_and_report` or
/// `automatic`), for the daily summary. Best effort, after the action
/// committed: a lost row costs one summary line, never the action.
pub async fn record_autonomous_run(
    state: &EngineState,
    ctx: &ActionContext,
    descriptor: &ActionDescriptor,
) {
    let Some(level) = effective_level(ctx, descriptor) else {
        return;
    };
    let Some(session_id) = ctx.agent_session_id else {
        return;
    };
    if level < AutonomyLevel::ActAndReport {
        return;
    }
    if let Err(e) = sqlx::query(
        "INSERT INTO ai_autonomous_run (agent_session_id, acting_user_id, action_id, level) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(session_id)
    .bind(ctx.security.user_id)
    .bind(descriptor.id.0)
    .bind(level.as_i16())
    .execute(&state.base.db)
    .await
    {
        tracing::warn!(
            action_id = %descriptor.id,
            error = %e,
            "AH8: an autonomous run was not recorded for the daily summary"
        );
    }
}

/// How many rows the summary prunes after they were summarized, in days.
pub const SUMMARY_RETENTION_DAYS: i32 = 30;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SummaryStats {
    pub people: u64,
    pub actions: u64,
    pub pruned: u64,
}

/// One line of a person's summary.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SummaryLine {
    pub acting_user_id: Uuid,
    pub action_id: String,
    pub runs: i64,
}

/// The summary text for one person's lines. Pure.
pub fn summary_text(lines: &[SummaryLine]) -> (String, String) {
    let total: i64 = lines.iter().map(|l| l.runs).sum();
    let body = lines
        .iter()
        .map(|l| format!("{} × {}", l.runs, l.action_id))
        .collect::<Vec<_>>()
        .join(", ");
    (
        format!("Your agents ran {total} action(s) on their own"),
        format!(
            "Since the last summary: {body}. Each one is in the record history and the audit trail."
        ),
    )
}

/// The daily summary (`EngineJob::AiAutonomySummary`): one in-app note per
/// person whose agents ran `automatic` actions since their last summary,
/// counted by action; then marks those rows summarized and prunes old ones.
/// `act_and_report` runs are not repeated here: each was reported when it ran.
pub async fn daily_summary(state: &EngineState) -> Result<SummaryStats, AppError> {
    let mut stats = SummaryStats::default();
    let cutoff = Utc::now();
    let lines: Vec<SummaryLine> = sqlx::query_as(
        "SELECT acting_user_id, action_id, COUNT(*)::bigint AS runs FROM ai_autonomous_run \
         WHERE summarized_at IS NULL AND level = $1 AND created_at < $2 \
         GROUP BY acting_user_id, action_id ORDER BY acting_user_id, runs DESC, action_id",
    )
    .bind(AutonomyLevel::Automatic.as_i16())
    .bind(cutoff)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut people: Vec<Uuid> = lines.iter().map(|l| l.acting_user_id).collect();
    people.dedup();
    for person in people {
        let mine: Vec<SummaryLine> = lines
            .iter()
            .filter(|l| l.acting_user_id == person)
            .cloned()
            .collect();
        let (subject, body) = summary_text(&mine);
        crate::deferred::notify(state, person, subject, body).await;
        let marked = sqlx::query(
            "UPDATE ai_autonomous_run SET summarized_at = now() \
             WHERE acting_user_id = $1 AND summarized_at IS NULL AND created_at < $2",
        )
        .bind(person)
        .bind(cutoff)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        stats.people += 1;
        stats.actions += marked.rows_affected();
    }
    // act_and_report rows were reported when they ran: close them too.
    sqlx::query(
        "UPDATE ai_autonomous_run SET summarized_at = now() \
         WHERE summarized_at IS NULL AND level <> $1 AND created_at < $2",
    )
    .bind(AutonomyLevel::Automatic.as_i16())
    .bind(cutoff)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let pruned = sqlx::query(
        "DELETE FROM ai_autonomous_run \
         WHERE summarized_at IS NOT NULL AND summarized_at < now() - make_interval(days => $1)",
    )
    .bind(SUMMARY_RETENTION_DAYS)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    stats.pruned = pruned.rows_affected();
    Ok(stats)
}

// ── Earned autonomy (AH8-T9) ────────────────────────────────────────────────

/// Agreement a raise needs, over at least [`RAISE_MIN_CASES`] decisions with
/// an outcome, within [`RAISE_WINDOW_DAYS`].
pub const RAISE_MIN_AGREEMENT: f64 = 0.98;
pub const RAISE_MIN_CASES: i64 = 200;
pub const RAISE_WINDOW_DAYS: i64 = 28;
/// An open proposal expires after this many days.
pub const PROPOSAL_DAYS: i32 = 14;

/// The level one rank above `current` that may be proposed for an action of
/// `risk`, if any. A consequential action is never proposed above
/// `act_on_review`: past that a person no longer sees each action, and only
/// an administrator's own choice goes there. Pure.
pub fn next_proposable(risk: RiskTier, current: AutonomyLevel) -> Option<AutonomyLevel> {
    let next = AutonomyLevel::ALL.into_iter().find(|l| *l > current)?;
    if risk == RiskTier::Consequential && next > AutonomyLevel::ActOnReview {
        return None;
    }
    Some(next)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProposalStats {
    pub proposed: u64,
    pub expired: u64,
}

/// Proposes raises from the trial figures of the last [`RAISE_WINDOW_DAYS`],
/// and expires stale proposals. Run by the hourly trial job after it
/// compares; at most one open proposal per agent and action.
pub async fn propose_raises(state: &EngineState) -> Result<ProposalStats, AppError> {
    let mut stats = ProposalStats::default();
    let expired = sqlx::query(
        "UPDATE ai_autonomy_proposal SET status = 'expired', decided_at = now() \
         WHERE status = 'open' AND expires_at < now()",
    )
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    stats.expired = expired.rows_affected();

    let since = Utc::now() - chrono::Duration::days(RAISE_WINDOW_DAYS);
    let agents: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT agent_ref FROM ai_trial_decision \
         WHERE agent_ref IS NOT NULL AND created_at >= $1",
    )
    .bind(since)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for agent in agents {
        for figures in crate::trial::counts(&state.base.db, agent, Some(since)).await? {
            let cases = figures.same + figures.different;
            let Some(agreement) = figures.agreement() else {
                continue;
            };
            if cases < RAISE_MIN_CASES || agreement < RAISE_MIN_AGREEMENT {
                continue;
            }
            let Some(descriptor) = crate::engine::REGISTRY.resolve(&figures.action_id) else {
                continue;
            };
            if descriptor.risk == RiskTier::Read || descriptor.autonomy_locked {
                continue;
            }
            let stored: Option<i16> = sqlx::query_scalar(
                "SELECT level FROM ai_autonomy_level WHERE agent_definition_id = $1 AND action_id = $2",
            )
            .bind(agent)
            .bind(&figures.action_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let current = stored
                .and_then(AutonomyLevel::from_i16)
                .unwrap_or_else(|| builtin_level(descriptor));
            let Some(to) = next_proposable(descriptor.risk, current) else {
                continue;
            };
            let made = sqlx::query(
                "INSERT INTO ai_autonomy_proposal \
                   (agent_definition_id, action_id, from_level, to_level, agreement, cases, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7)) \
                 ON CONFLICT (agent_definition_id, action_id) WHERE status = 'open' DO NOTHING",
            )
            .bind(agent)
            .bind(&figures.action_id)
            .bind(stored)
            .bind(to.as_i16())
            .bind(agreement)
            .bind(i32::try_from(cases).unwrap_or(i32::MAX))
            .bind(PROPOSAL_DAYS)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            stats.proposed += made.rows_affected();
        }
    }
    Ok(stats)
}

/// The level an action with no row behaves at for an agent, as a proposal's
/// starting point: `agent_must_confirm` writes and every consequential
/// action ask first; other writes already run (taint aside).
fn builtin_level(descriptor: &ActionDescriptor) -> AutonomyLevel {
    if descriptor.agent_must_confirm || descriptor.risk == RiskTier::Consequential {
        AutonomyLevel::AskFirst
    } else {
        AutonomyLevel::Automatic
    }
}

/// An open proposal, as the admin screen shows it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AutonomyProposal {
    pub id: Uuid,
    pub agent_definition_id: Uuid,
    pub action_id: String,
    /// Stored level code it starts from; `null` is the built-in rule.
    pub from_level: Option<i16>,
    pub to_level: i16,
    /// Trial agreement with people, 0 to 1.
    pub agreement: f64,
    pub cases: i32,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

const PROPOSAL_COLUMNS: &str = "id, agent_definition_id, action_id, from_level, to_level, \
     agreement, cases, status, expires_at, created_at";

/// `GET /api/v1/admin/ai/agents/{id}/autonomy/proposals` — open proposals.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/autonomy/proposals",
    operation_id = "list_autonomy_proposals",
    tag = "action",
    params(("id" = Uuid, Path, description = "The agent, as its sessions name it")),
    responses(
        (status = 200, description = "Open proposals to raise a level", body = PaginatedResponse<AutonomyProposal>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_proposals(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<AutonomyProposal>>, AppError> {
    let items: Vec<AutonomyProposal> = sqlx::query_as(&format!(
        "SELECT {PROPOSAL_COLUMNS} FROM ai_autonomy_proposal \
         WHERE agent_definition_id = $1 AND status = 'open' ORDER BY created_at DESC LIMIT $2"
    ))
    .bind(agent_id)
    .bind(MAX_ENTRIES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_ENTRIES,
        warnings: Vec::new(),
    }))
}

/// Accepts or rejects an open proposal. Accepting sets the level, keeping
/// the row's limits, and is refused with 409 when the level changed since the
/// proposal was made.
pub async fn decide_proposal(
    state: &EngineState,
    user_id: Uuid,
    proposal_id: Uuid,
    accept: bool,
) -> Result<AutonomyProposal, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let proposal: Option<AutonomyProposal> = sqlx::query_as(&format!(
        "SELECT {PROPOSAL_COLUMNS} FROM ai_autonomy_proposal WHERE id = $1 AND status = 'open' \
         FOR UPDATE"
    ))
    .bind(proposal_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(proposal) = proposal else {
        return Err(AppError::NotFound);
    };
    if accept {
        let current: Option<i16> = sqlx::query_scalar(
            "SELECT level FROM ai_autonomy_level \
             WHERE agent_definition_id = $1 AND action_id = $2 FOR UPDATE",
        )
        .bind(proposal.agent_definition_id)
        .bind(&proposal.action_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if current != proposal.from_level {
            return Err(AppError::Conflict(
                "the level changed since this was proposed; it no longer applies",
            ));
        }
        sqlx::query(
            "INSERT INTO ai_autonomy_level \
               (agent_definition_id, action_id, level, created_by, updated_by) \
             VALUES ($1, $2, $3, $4, $4) \
             ON CONFLICT (agent_definition_id, action_id) DO UPDATE SET \
               level = EXCLUDED.level, updated_by = EXCLUDED.updated_by, updated_at = now(), \
               row_version = ai_autonomy_level.row_version + 1",
        )
        .bind(proposal.agent_definition_id)
        .bind(&proposal.action_id)
        .bind(proposal.to_level)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    let decided: AutonomyProposal = sqlx::query_as(&format!(
        "UPDATE ai_autonomy_proposal SET status = $2, decided_by = $3, decided_at = now() \
         WHERE id = $1 RETURNING {PROPOSAL_COLUMNS}"
    ))
    .bind(proposal_id)
    .bind(if accept { "accepted" } else { "rejected" })
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            user_id,
            "ai_autonomy_proposal",
            Some(proposal_id),
        )
        .named(if accept {
            "ai.autonomy.proposal.accept"
        } else {
            "ai.autonomy.proposal.reject"
        })
        .comment(format!(
            "agent {}: raise {} to level code {} at {:.1}% trial agreement over {} cases {}",
            proposal.agent_definition_id,
            proposal.action_id,
            proposal.to_level,
            proposal.agreement * 100.0,
            proposal.cases,
            if accept { "accepted" } else { "rejected" }
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(decided)
}

/// `POST /api/v1/admin/ai/autonomy/proposals/{id}/accept`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/autonomy/proposals/{id}/accept",
    operation_id = "accept_autonomy_proposal",
    tag = "action",
    params(("id" = Uuid, Path, description = "The proposal")),
    responses(
        (status = 200, description = "Accepted; the level is raised", body = AutonomyProposal),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No open proposal with this id", body = ErrorResponse),
        (status = 409, description = "The level changed since the proposal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn accept_proposal(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AutonomyProposal>, AppError> {
    Ok(Json(decide_proposal(&state, ctx.user_id, id, true).await?))
}

/// `POST /api/v1/admin/ai/autonomy/proposals/{id}/reject`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/autonomy/proposals/{id}/reject",
    operation_id = "reject_autonomy_proposal",
    tag = "action",
    params(("id" = Uuid, Path, description = "The proposal")),
    responses(
        (status = 200, description = "Rejected", body = AutonomyProposal),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No open proposal with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn reject_proposal(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AutonomyProposal>, AppError> {
    Ok(Json(decide_proposal(&state, ctx.user_id, id, false).await?))
}

// ── Admin routes ────────────────────────────────────────────────────────────

/// One action an agent may call, with the level it runs at.
#[derive(Debug, Serialize, ToSchema)]
pub struct AutonomyEntry {
    pub action_id: String,
    pub risk: RiskTier,
    pub effect: Effect,
    /// The level the action behaves at with no row (clean context).
    pub default_level: AutonomyLevel,
    /// The level a row sets, when there is one.
    pub level: Option<AutonomyLevel>,
    /// `true` when no level applies to this action: it keeps its built-in
    /// rule for every agent (`autonomy_locked`).
    pub locked: bool,
    pub row: Option<AutonomyRow>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetAutonomy {
    pub level: AutonomyLevel,
    /// Seconds an `act_with_undo` action waits before it runs (30 to 86400).
    #[serde(default)]
    pub undo_seconds: Option<i32>,
    #[serde(default)]
    pub daily_limit: Option<i32>,
    /// Minor units of `currency`; requires the action to declare a money
    /// argument, or every invocation asks first.
    #[serde(default)]
    pub money_cap_minor: Option<i64>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub owned_records_only: bool,
    /// Start hour, inclusive (0 to 23).
    #[serde(default)]
    pub hours_start: Option<i16>,
    /// End hour, exclusive (1 to 24).
    #[serde(default)]
    pub hours_end: Option<i16>,
    /// IANA zone for the hours, such as `Asia/Riyadh`; UTC when unset.
    #[serde(default)]
    pub time_zone: Option<String>,
    /// The row's current `row_version` when replacing a row; a stale one is
    /// refused with 409.
    #[serde(default)]
    pub row_version: Option<i64>,
}

const MAX_ENTRIES: i64 = 500;

/// Validates a request against the action it names. Pure.
pub fn validate(descriptor: &ActionDescriptor, body: &SetAutonomy) -> Result<(), AppError> {
    if descriptor.risk == RiskTier::Read {
        return Err(AppError::Validation(format!(
            "{} only reads; it has no autonomy level",
            descriptor.id
        )));
    }
    if descriptor.autonomy_locked {
        return Err(AppError::Validation(format!(
            "{} keeps its built-in rule; no autonomy level applies to it",
            descriptor.id
        )));
    }
    if let Some(s) = body.undo_seconds {
        let ok = u32::try_from(s).is_ok_and(|s| (MIN_UNDO_SECONDS..=MAX_UNDO_SECONDS).contains(&s));
        if !ok {
            return Err(AppError::Validation(
                "undo_seconds must be between 30 and 86400".into(),
            ));
        }
    }
    if body.daily_limit.is_some_and(|d| d <= 0) {
        return Err(AppError::Validation("daily_limit must be above 0".into()));
    }
    match (&body.money_cap_minor, &body.currency) {
        (None, None) => {}
        (Some(cap), Some(cur))
            if *cap >= 0 && cur.len() == 3 && cur.chars().all(|c| c.is_ascii_uppercase()) => {}
        _ => {
            return Err(AppError::Validation(
                "money_cap_minor (0 or more) and currency (three capital letters) go together"
                    .into(),
            ));
        }
    }
    match (body.hours_start, body.hours_end) {
        (None, None) => {}
        (Some(s), Some(e)) if (0..=23).contains(&s) && (1..=24).contains(&e) && s < e => {}
        _ => {
            return Err(AppError::Validation(
                "hours_start (0 to 23) and hours_end (1 to 24, after the start) go together".into(),
            ));
        }
    }
    if let Some(tz) = &body.time_zone
        && tz.parse::<chrono_tz::Tz>().is_err()
    {
        return Err(AppError::Validation(format!("unknown time_zone {tz}")));
    }
    Ok(())
}

/// `GET /api/v1/admin/ai/agents/{id}/autonomy` — every non-read action with
/// the level it runs at for this agent.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/autonomy",
    operation_id = "list_agent_autonomy",
    tag = "action",
    params(("id" = Uuid, Path, description = "The agent: an `ai_agent` record or a published agent object, as its sessions name it")),
    responses(
        (status = 200, description = "Each action with its level", body = PaginatedResponse<AutonomyEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_levels(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<AutonomyEntry>>, AppError> {
    let rows: Vec<AutonomyRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLUMNS} FROM ai_autonomy_level WHERE agent_definition_id = $1 LIMIT $2"
    ))
    .bind(agent_id)
    .bind(MAX_ENTRIES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut items: Vec<AutonomyEntry> = crate::engine::REGISTRY
        .all()
        .filter(|d| d.risk != RiskTier::Read)
        .map(|d| {
            let row = rows.iter().find(|r| r.action_id == d.id.0).cloned();
            AutonomyEntry {
                action_id: d.id.0.to_owned(),
                risk: d.risk,
                effect: d.effect,
                default_level: default_for(d.risk),
                level: row.as_ref().and_then(|r| AutonomyLevel::from_i16(r.level)),
                locked: d.autonomy_locked,
                row,
            }
        })
        .collect();
    items.sort_by(|a, b| a.action_id.cmp(&b.action_id));
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_ENTRIES,
        warnings: Vec::new(),
    }))
}

/// `PUT /api/v1/admin/ai/agents/{id}/autonomy/{action_id}` — sets the level.
#[utoipa::path(
    put,
    path = "/api/v1/admin/ai/agents/{id}/autonomy/{action_id}",
    operation_id = "set_agent_autonomy",
    tag = "action",
    params(
        ("id" = Uuid, Path, description = "The agent, as its sessions name it"),
        ("action_id" = String, Path, description = "The action, e.g. email.send"),
    ),
    request_body = SetAutonomy,
    responses(
        (status = 200, description = "The stored level", body = AutonomyRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such action", body = ErrorResponse),
        (status = 409, description = "The row changed since row_version", body = ErrorResponse),
        (status = 422, description = "Invalid level or limits", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn set_level(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path((agent_id, action_id)): Path<(Uuid, String)>,
    Json(body): Json<SetAutonomy>,
) -> Result<Json<AutonomyRow>, AppError> {
    let descriptor = crate::engine::REGISTRY
        .resolve(&action_id)
        .ok_or(AppError::NotFound)?;
    validate(descriptor, &body)?;
    let undo = body.undo_seconds.unwrap_or(DEFAULT_UNDO_SECONDS as i32);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(i64, i16)> = sqlx::query_as(
        "SELECT row_version, level FROM ai_autonomy_level \
         WHERE agent_definition_id = $1 AND action_id = $2 FOR UPDATE",
    )
    .bind(agent_id)
    .bind(descriptor.id.0)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let (Some((version, _)), Some(expected)) = (current, body.row_version)
        && version != expected
    {
        return Err(AppError::Conflict(
            "the autonomy level changed since it was read",
        ));
    }
    let row: AutonomyRow = sqlx::query_as(&format!(
        "INSERT INTO ai_autonomy_level \
           (agent_definition_id, action_id, level, undo_seconds, daily_limit, money_cap_minor, \
            currency, owned_records_only, hours_start, hours_end, time_zone, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12) \
         ON CONFLICT (agent_definition_id, action_id) DO UPDATE SET \
           level = EXCLUDED.level, undo_seconds = EXCLUDED.undo_seconds, \
           daily_limit = EXCLUDED.daily_limit, money_cap_minor = EXCLUDED.money_cap_minor, \
           currency = EXCLUDED.currency, owned_records_only = EXCLUDED.owned_records_only, \
           hours_start = EXCLUDED.hours_start, hours_end = EXCLUDED.hours_end, \
           time_zone = EXCLUDED.time_zone, updated_by = EXCLUDED.updated_by, \
           updated_at = now(), row_version = ai_autonomy_level.row_version + 1 \
         RETURNING {ROW_COLUMNS}"
    ))
    .bind(agent_id)
    .bind(descriptor.id.0)
    .bind(body.level.as_i16())
    .bind(undo)
    .bind(body.daily_limit)
    .bind(body.money_cap_minor)
    .bind(&body.currency)
    .bind(body.owned_records_only)
    .bind(body.hours_start)
    .bind(body.hours_end)
    .bind(&body.time_zone)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let raises_consequential =
        descriptor.risk == RiskTier::Consequential && body.level > AutonomyLevel::AskFirst;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "ai_autonomy_level",
            Some(row.id),
        )
        .named("ai.autonomy.set")
        .comment(format!(
            "agent {agent_id}: {} set to {:?} (was {}){}",
            descriptor.id,
            body.level,
            current
                .and_then(|(_, l)| AutonomyLevel::from_i16(l))
                .map_or_else(|| "the built-in rule".to_owned(), |l| format!("{l:?}")),
            if raises_consequential {
                "; a consequential action may now run without per-action approval"
            } else {
                ""
            }
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(row))
}

/// `DELETE /api/v1/admin/ai/agents/{id}/autonomy/{action_id}` — back to the
/// built-in rule.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/ai/agents/{id}/autonomy/{action_id}",
    operation_id = "clear_agent_autonomy",
    tag = "action",
    params(
        ("id" = Uuid, Path, description = "The agent, as its sessions name it"),
        ("action_id" = String, Path, description = "The action"),
    ),
    responses(
        (status = 204, description = "Cleared"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No level is set for this action", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::HardDelete)])))),
)]
async fn clear_level(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path((agent_id, action_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM ai_autonomy_level WHERE agent_definition_id = $1 AND action_id = $2 \
         RETURNING id",
    )
    .bind(agent_id)
    .bind(&action_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = id else {
        return Err(AppError::NotFound);
    };
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            ctx.user_id,
            "ai_autonomy_level",
            Some(id),
        )
        .named("ai.autonomy.clear")
        .comment(format!(
            "agent {agent_id}: {action_id} back to the built-in rule"
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/ai/agents/{id}/autonomy/proposals",
            get(list_proposals),
        )
        .route(
            "/api/v1/admin/ai/autonomy/proposals/{id}/accept",
            axum::routing::post(accept_proposal),
        )
        .route(
            "/api/v1/admin/ai/autonomy/proposals/{id}/reject",
            axum::routing::post(reject_proposal),
        )
        .route("/api/v1/admin/ai/agents/{id}/autonomy", get(list_levels))
        .route(
            "/api/v1/admin/ai/agents/{id}/autonomy/{action_id}",
            axum::routing::put(set_level).delete(clear_level),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_levels,
        set_level,
        clear_level,
        list_proposals,
        accept_proposal,
        reject_proposal
    ),
    components(schemas(
        AutonomyEntry,
        AutonomyRow,
        SetAutonomy,
        AutonomyLevel,
        AutonomyProposal
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::RetryClass;
    use attome_modules::MODULE_AI;
    use chrono::TimeZone;

    fn row() -> AutonomyRow {
        AutonomyRow {
            id: Uuid::nil(),
            agent_definition_id: Uuid::nil(),
            action_id: "email.send".into(),
            level: 4,
            undo_seconds: 300,
            daily_limit: None,
            money_cap_minor: None,
            currency: None,
            owned_records_only: false,
            hours_start: None,
            hours_end: None,
            time_zone: None,
            updated_by: Uuid::nil(),
            updated_at: Utc::now(),
            row_version: 1,
        }
    }

    fn set(level: AutonomyLevel) -> SetAutonomy {
        SetAutonomy {
            level,
            undo_seconds: None,
            daily_limit: None,
            money_cap_minor: None,
            currency: None,
            owned_records_only: false,
            hours_start: None,
            hours_end: None,
            time_zone: None,
            row_version: None,
        }
    }

    #[test]
    fn lowering_steps_down_one_and_stops_at_suggest() {
        assert_eq!(
            AutonomyLevel::Automatic.lowered(),
            AutonomyLevel::ActAndReport
        );
        assert_eq!(
            AutonomyLevel::ActAndReport.lowered(),
            AutonomyLevel::ActWithUndo
        );
        assert_eq!(
            AutonomyLevel::ActWithUndo.lowered(),
            AutonomyLevel::ActOnReview
        );
        assert_eq!(
            AutonomyLevel::ActOnReview.lowered(),
            AutonomyLevel::AskFirst
        );
        assert_eq!(AutonomyLevel::AskFirst.lowered(), AutonomyLevel::Suggest);
        assert_eq!(AutonomyLevel::Suggest.lowered(), AutonomyLevel::Suggest);
    }

    #[test]
    fn levels_round_trip_through_their_stored_number() {
        for level in AutonomyLevel::ALL {
            assert_eq!(AutonomyLevel::from_i16(level.as_i16()), Some(level));
        }
        assert_eq!(AutonomyLevel::from_i16(6), None);
        assert_eq!(
            AutonomyLevel::ActOnReview.as_i16(),
            5,
            "stored codes never move"
        );
        for pair in AutonomyLevel::ALL.windows(2) {
            assert!(pair[0] < pair[1], "ALL is in rank order");
            assert_eq!(pair[1].lowered(), pair[0], "lowering is one rank down");
        }
    }

    #[test]
    fn an_unreadable_stored_level_grants_ask_first() {
        let mut r = row();
        r.level = 9;
        assert_eq!(r.grant().level, AutonomyLevel::AskFirst);
    }

    #[test]
    fn the_summary_counts_each_action() {
        let person = Uuid::nil();
        let (subject, body) = summary_text(&[
            SummaryLine {
                acting_user_id: person,
                action_id: "email.send".into(),
                runs: 12,
            },
            SummaryLine {
                acting_user_id: person,
                action_id: "record.update".into(),
                runs: 3,
            },
        ]);
        assert_eq!(subject, "Your agents ran 15 action(s) on their own");
        assert!(body.contains("12 × email.send, 3 × record.update"));
    }

    #[test]
    fn proposals_step_up_one_and_stop_consequential_at_review() {
        use AutonomyLevel as L;
        assert_eq!(
            next_proposable(RiskTier::Reversible, L::AskFirst),
            Some(L::ActOnReview)
        );
        assert_eq!(
            next_proposable(RiskTier::Reversible, L::ActAndReport),
            Some(L::Automatic)
        );
        assert_eq!(next_proposable(RiskTier::Reversible, L::Automatic), None);
        assert_eq!(
            next_proposable(RiskTier::Consequential, L::AskFirst),
            Some(L::ActOnReview)
        );
        assert_eq!(
            next_proposable(RiskTier::Consequential, L::ActOnReview),
            None,
            "past act_on_review only an administrator chooses"
        );
    }

    #[test]
    fn default_per_tier() {
        assert_eq!(
            default_for(RiskTier::Consequential),
            AutonomyLevel::AskFirst
        );
        assert_eq!(default_for(RiskTier::Reversible), AutonomyLevel::Automatic);
    }

    #[test]
    fn hours_are_checked_in_the_rows_time_zone() {
        let mut r = row();
        r.hours_start = Some(8);
        r.hours_end = Some(17);
        r.time_zone = Some("Asia/Riyadh".into());
        // 06:00 UTC is 09:00 in Riyadh.
        let morning = Utc
            .with_ymd_and_hms(2026, 10, 20, 6, 0, 0)
            .single()
            .unwrap_or_default();
        assert!(within_hours(&r, morning));
        // 15:00 UTC is 18:00 in Riyadh.
        let evening = Utc
            .with_ymd_and_hms(2026, 10, 20, 15, 0, 0)
            .single()
            .unwrap_or_default();
        assert!(!within_hours(&r, evening));
        r.time_zone = Some("Not/AZone".into());
        assert!(
            !within_hours(&r, morning),
            "an unknown zone is outside (fails closed)"
        );
        r.hours_start = None;
        r.hours_end = None;
        assert!(within_hours(&r, evening), "no hours set is always");
    }

    #[test]
    fn money_cap_needs_a_declared_whole_amount() {
        let plain = ActionDescriptor::new(
            "test.pay",
            "test",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        );
        let args = serde_json::json!({"amount_minor": 500});
        assert!(
            !within_money_cap(&plain, &args, 1000),
            "no declared money argument is over the cap"
        );
        let mut declared = plain.clone();
        declared.money_arg = Some("amount_minor");
        assert!(within_money_cap(&declared, &args, 1000));
        assert!(!within_money_cap(&declared, &args, 499));
        assert!(!within_money_cap(&declared, &serde_json::json!({}), 1000));
        assert!(!within_money_cap(
            &declared,
            &serde_json::json!({"amount_minor": -1}),
            1000
        ));
    }

    #[test]
    fn validation_refuses_bad_limits() {
        let d = ActionDescriptor::new(
            "test.write",
            "test",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        );
        assert!(validate(&d, &set(AutonomyLevel::Automatic)).is_ok());
        let mut b = set(AutonomyLevel::ActWithUndo);
        b.undo_seconds = Some(5);
        assert!(validate(&d, &b).is_err());
        let mut b = set(AutonomyLevel::Automatic);
        b.money_cap_minor = Some(100);
        assert!(validate(&d, &b).is_err(), "a money cap needs its currency");
        b.currency = Some("SAR".into());
        assert!(validate(&d, &b).is_ok());
        let mut b = set(AutonomyLevel::Automatic);
        b.hours_start = Some(17);
        b.hours_end = Some(8);
        assert!(validate(&d, &b).is_err());
        let mut b = set(AutonomyLevel::Automatic);
        b.time_zone = Some("Mars/Base".into());
        assert!(validate(&d, &b).is_err());
        let read = ActionDescriptor::new(
            "test.read",
            "test",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        );
        assert!(validate(&read, &set(AutonomyLevel::Automatic)).is_err());
    }
}
