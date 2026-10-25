//! AI8-T4: agent performance for administrators, read from the nightly
//! rollup (`ai_agent_daily_stat`, [`crate::agent_stats`]):
//!
//! - `GET /api/v1/admin/ai/agents/performance?from&to` — one row per agent:
//!   the range's sums and the rates derived from them at read time
//!   ([`rates`]: resolution = resolved ÷ done, accuracy = effectiveness ÷
//!   measured, hand-off rate = hand-offs ÷ done, cost per task = cost ÷
//!   done);
//! - `GET /api/v1/admin/ai/agents/{id}/performance/daily?from&to` — the
//!   daily series for charts;
//! - `GET /api/v1/admin/ai/agents/{id}/runs?day&metric&cursor` — what is
//!   behind one number: the outcome rows (`tasks`, `handoffs`) or the
//!   sessions with their tokens (`cost`), keyset-paged.
//!
//! Only ids, times, sources, action ids, tokens and cost leave here: no
//! message text and no record values.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, CursorPage, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The longest range one summary or series covers.
pub const MAX_RANGE_DAYS: i64 = 400;
/// Most runs one page holds.
pub const RUNS_PAGE: i64 = 100;
/// The most agents one summary lists.
pub const MAX_AGENTS: i64 = 500;

/// A date range.
#[derive(Debug, Clone, Copy, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct PerformanceRange {
    /// From this time (inclusive).
    pub from: NaiveDate,
    /// Up to this time (exclusive).
    pub to: NaiveDate,
}

impl PerformanceRange {
    /// Refuses a reversed or over-long range. Pure.
    pub fn check(&self) -> Result<(), AppError> {
        if self.to < self.from {
            return Err(AppError::Validation("to must not be before from".into()));
        }
        if (self.to - self.from).num_days() + 1 > MAX_RANGE_DAYS {
            return Err(AppError::Validation(format!(
                "a range covers at most {MAX_RANGE_DAYS} days"
            )));
        }
        Ok(())
    }
}

/// An agent's sums over a range, and the rates read from them.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AgentPerformance {
    pub agent_id: Uuid,
    pub name: Option<String>,
    pub tasks_done: i64,
    pub tasks_resolved: i64,
    pub tasks_measured: i64,
    pub effectiveness_sum: f64,
    pub handoffs: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    /// Millionths of the price list's currency.
    pub cost_micros: i64,
    /// `price_list`, or null when some tokens had no price.
    pub cost_unit: Option<String>,
    /// An estimate: tasks times a per-source figure.
    pub time_saved_seconds: i64,
    pub resolution_rate: Option<f64>,
    pub accuracy: Option<f64>,
    pub handoff_rate: Option<f64>,
    pub cost_per_task_micros: Option<f64>,
}

/// One day of an agent.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AgentPerformanceDay {
    pub day: NaiveDate,
    pub tasks_done: i64,
    pub tasks_resolved: i64,
    pub tasks_measured: i64,
    pub effectiveness_sum: f64,
    pub handoffs: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_micros: i64,
    pub cost_unit: Option<String>,
    pub time_saved_seconds: i64,
}

/// The rates of a set of sums, divided at read time; `None` where the
/// divisor is zero. Pure.
pub fn rates(
    done: i64,
    resolved: i64,
    measured: i64,
    effectiveness_sum: f64,
    handoffs: i64,
    cost_micros: i64,
) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    let over = |n: f64, d: i64| (d > 0).then(|| n / d as f64);
    (
        over(resolved as f64, done),
        over(effectiveness_sum, measured),
        over(handoffs as f64, done),
        over(cost_micros as f64, done),
    )
}

type SumRow = (
    Uuid,
    Option<String>,
    i64,
    i64,
    i64,
    f64,
    i64,
    i64,
    i64,
    i64,
    bool,
    i64,
);

/// Every agent's sums over the range, most tasks first.
pub async fn performance(
    db: &attome_db::DbPool,
    range: &PerformanceRange,
    agent: Option<Uuid>,
) -> Result<Vec<AgentPerformance>, AppError> {
    range.check()?;
    let rows: Vec<SumRow> = sqlx::query_as(
        "SELECT s.agent_definition_ref, a.name, \
                SUM(s.tasks_done)::bigint, SUM(s.tasks_resolved)::bigint, \
                SUM(s.tasks_measured)::bigint, SUM(s.effectiveness_sum)::float8, \
                SUM(s.handoffs)::bigint, SUM(s.input_tokens)::bigint, \
                SUM(s.output_tokens)::bigint, SUM(s.cost_micros)::bigint, \
                bool_and(s.cost_unit IS NOT NULL), SUM(s.time_saved_seconds)::bigint \
           FROM ai_agent_daily_stat s LEFT JOIN ai_agent a ON a.id = s.agent_definition_ref \
          WHERE s.day BETWEEN $1 AND $2 AND ($3::uuid IS NULL OR s.agent_definition_ref = $3) \
          GROUP BY s.agent_definition_ref, a.name \
          ORDER BY SUM(s.tasks_done) DESC, s.agent_definition_ref LIMIT $4",
    )
    .bind(range.from)
    .bind(range.to)
    .bind(agent)
    .bind(MAX_AGENTS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                name,
                done,
                resolved,
                measured,
                eff,
                handoffs,
                input,
                output,
                cost,
                priced,
                saved,
            )| {
                let (resolution_rate, accuracy, handoff_rate, cost_per_task_micros) =
                    rates(done, resolved, measured, eff, handoffs, cost);
                AgentPerformance {
                    agent_id: id,
                    name,
                    tasks_done: done,
                    tasks_resolved: resolved,
                    tasks_measured: measured,
                    effectiveness_sum: eff,
                    handoffs,
                    input_tokens: input,
                    output_tokens: output,
                    cost_micros: cost,
                    cost_unit: priced.then(|| crate::agent_stats::COST_UNIT.to_owned()),
                    time_saved_seconds: saved,
                    resolution_rate,
                    accuracy,
                    handoff_rate,
                    cost_per_task_micros: if priced { cost_per_task_micros } else { None },
                }
            },
        )
        .collect())
}

type DayRow = (
    NaiveDate,
    i32,
    i32,
    i32,
    f64,
    i32,
    i64,
    i64,
    i64,
    Option<String>,
    i64,
);

/// One agent's days in the range, oldest first.
pub async fn daily(
    db: &attome_db::DbPool,
    agent: Uuid,
    range: &PerformanceRange,
) -> Result<Vec<AgentPerformanceDay>, AppError> {
    range.check()?;
    let rows: Vec<DayRow> = sqlx::query_as(
        "SELECT day, tasks_done, tasks_resolved, tasks_measured, effectiveness_sum, handoffs, \
                input_tokens, output_tokens, cost_micros, cost_unit, time_saved_seconds \
           FROM ai_agent_daily_stat \
          WHERE agent_definition_ref = $1 AND day BETWEEN $2 AND $3 ORDER BY day",
    )
    .bind(agent)
    .bind(range.from)
    .bind(range.to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(day, done, resolved, measured, eff, handoffs, input, output, cost, unit, saved)| {
                AgentPerformanceDay {
                    day,
                    tasks_done: i64::from(done),
                    tasks_resolved: i64::from(resolved),
                    tasks_measured: i64::from(measured),
                    effectiveness_sum: eff,
                    handoffs: i64::from(handoffs),
                    input_tokens: input,
                    output_tokens: output,
                    cost_micros: cost,
                    cost_unit: unit,
                    time_saved_seconds: saved,
                }
            },
        )
        .collect())
}

/// Which number's runs to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunsMetric {
    Tasks,
    Handoffs,
    Cost,
}

/// The runs query.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunsQuery {
    /// The day, as YYYY-MM-DD.
    pub day: NaiveDate,
    /// `tasks`, `handoffs` or `cost`.
    #[param(value_type = String)]
    pub metric: RunsMetric,
    /// The previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One run behind a number: an outcome row (`tasks`, `handoffs`) or a
/// session with its tokens that day (`cost`).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AgentRun {
    /// `outcome` or `session`.
    pub kind: String,
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub session_id: Option<Uuid>,
    /// The outcome's source (`followup`, `collections`, `meeting`, `handoff`).
    pub source: Option<String>,
    pub regarding_entity: Option<String>,
    pub regarding_id: Option<Uuid>,
    pub measured_at: Option<DateTime<Utc>>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
}

/// `{micros}:{uuid}` of the last row of a page. Pure.
pub fn encode_cursor(at: DateTime<Utc>, id: Uuid) -> String {
    format!("{}:{id}", at.timestamp_micros())
}

/// The position a cursor names. Pure.
pub fn decode_cursor(cursor: &str) -> Result<(DateTime<Utc>, Uuid), AppError> {
    let bad = || AppError::Validation("cursor is not one this route issued".into());
    let (micros, id) = cursor.split_once(':').ok_or_else(bad)?;
    let at = micros
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_micros)
        .ok_or_else(bad)?;
    Ok((at, Uuid::parse_str(id).map_err(|_| bad())?))
}

type OutcomeRunRow = (
    Uuid,
    DateTime<Utc>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
);
type SessionRunRow = (Uuid, DateTime<Utc>, i64, i64);

/// The runs behind one of an agent's numbers on `day`.
pub async fn runs(
    db: &attome_db::DbPool,
    agent: Uuid,
    query: &RunsQuery,
) -> Result<CursorPage<AgentRun>, AppError> {
    let from = query
        .day
        .and_hms_opt(0, 0, 0)
        .map(|t| t.and_utc())
        .ok_or_else(|| AppError::Validation("day out of range".into()))?;
    let to = from + chrono::Duration::days(1);
    let (after_at, after_id) = match query.cursor.as_deref() {
        Some(c) => decode_cursor(c)?,
        None => (from - chrono::Duration::microseconds(1), Uuid::nil()),
    };
    let mut items: Vec<AgentRun> = match query.metric {
        RunsMetric::Tasks | RunsMetric::Handoffs => {
            let rows: Vec<OutcomeRunRow> = sqlx::query_as(
                "SELECT o.id, o.proposed_at, o.agent_session_ref, o.rule_ref, \
                        o.regarding_entity, o.regarding_id, o.measured_at \
                   FROM outcome o JOIN agent_session s ON s.id = o.agent_session_ref \
                  WHERE o.kind = 'agent_task' AND o.proposed_at >= $1 AND o.proposed_at < $2 \
                    AND COALESCE(s.agent_definition_ref, s.agent_object_ref) = $3 \
                    AND ($4 = false OR o.rule_ref = 'ai.handoff') \
                    AND (o.proposed_at, o.id) > ($5, $6) \
                  ORDER BY o.proposed_at, o.id LIMIT $7",
            )
            .bind(from)
            .bind(to)
            .bind(agent)
            .bind(query.metric == RunsMetric::Handoffs)
            .bind(after_at)
            .bind(after_id)
            .bind(RUNS_PAGE + 1)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            rows.into_iter()
                .map(
                    |(id, at, session, rule_ref, entity, regarding, measured)| AgentRun {
                        kind: "outcome".into(),
                        id,
                        at,
                        session_id: session,
                        source: Some(
                            crate::agent_stats::source_of(rule_ref.as_deref(), entity.as_deref())
                                .to_owned(),
                        ),
                        regarding_entity: entity,
                        regarding_id: regarding,
                        measured_at: measured,
                        input_tokens: None,
                        output_tokens: None,
                    },
                )
                .collect()
        }
        RunsMetric::Cost => {
            let rows: Vec<SessionRunRow> = sqlx::query_as(
                "SELECT s.id, s.started_at, \
                        COALESCE(SUM(m.input_tokens), 0)::bigint, \
                        COALESCE(SUM(m.output_tokens), 0)::bigint \
                   FROM agent_session s \
                   JOIN ai_conversation c ON c.agent_session_id = s.id \
                   JOIN ai_message m ON m.conversation_id = c.id \
                  WHERE COALESCE(s.agent_definition_ref, s.agent_object_ref) = $1 \
                    AND m.created_at >= $2 AND m.created_at < $3 \
                    AND (s.started_at, s.id) > ($4, $5) \
                  GROUP BY s.id, s.started_at \
                  ORDER BY s.started_at, s.id LIMIT $6",
            )
            .bind(agent)
            .bind(from)
            .bind(to)
            .bind(after_at)
            .bind(after_id)
            .bind(RUNS_PAGE + 1)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            rows.into_iter()
                .map(|(id, at, input, output)| AgentRun {
                    kind: "session".into(),
                    id,
                    at,
                    session_id: Some(id),
                    source: None,
                    regarding_entity: None,
                    regarding_id: None,
                    measured_at: None,
                    input_tokens: Some(input),
                    output_tokens: Some(output),
                })
                .collect()
        }
    };
    let next = if items.len() as i64 > RUNS_PAGE {
        items.truncate(RUNS_PAGE as usize);
        items.last().map(|r| encode_cursor(r.at, r.id))
    } else {
        None
    };
    Ok(CursorPage::new(items, next))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/performance",
    tag = "ai",
    params(PerformanceRange),
    responses(
        (status = 200, description = "Each agent's sums and rates over the range", body = PaginatedResponse<AgentPerformance>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "A reversed or over-long range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_performance(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(range): Query<PerformanceRange>,
) -> Result<Json<PaginatedResponse<AgentPerformance>>, AppError> {
    let items = performance(&state.base.db, &range, None).await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, MAX_AGENTS)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/performance/daily",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent"), PerformanceRange),
    responses(
        (status = 200, description = "The agent's days in the range", body = PaginatedResponse<AgentPerformanceDay>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "A reversed or over-long range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_performance_daily(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(agent): Path<Uuid>,
    Query(range): Query<PerformanceRange>,
) -> Result<Json<PaginatedResponse<AgentPerformanceDay>>, AppError> {
    let items = daily(&state.base.db, agent, &range).await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_RANGE_DAYS,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/runs",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent"), RunsQuery),
    responses(
        (status = 200, description = "The runs behind one number", body = CursorPage<AgentRun>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "An unknown metric or cursor", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_runs(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(agent): Path<Uuid>,
    Query(query): Query<RunsQuery>,
) -> Result<Json<CursorPage<AgentRun>>, AppError> {
    Ok(Json(runs(&state.base.db, agent, &query).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/ai/agents/performance", get(get_performance))
        .route(
            "/api/v1/admin/ai/agents/{id}/performance/daily",
            get(get_performance_daily),
        )
        .route("/api/v1/admin/ai/agents/{id}/runs", get(get_runs))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_performance, get_performance_daily, get_runs),
    components(schemas(AgentPerformance, AgentPerformanceDay, AgentRun, RunsMetric))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_divide_sums_and_skip_empty_divisors() {
        let (resolution, accuracy, handoff, cost) = rates(10, 7, 4, 3.0, 2, 5_000);
        assert_eq!(resolution, Some(0.7));
        assert_eq!(accuracy, Some(0.75));
        assert_eq!(handoff, Some(0.2));
        assert_eq!(cost, Some(500.0));
        assert_eq!(rates(0, 0, 0, 0.0, 0, 0), (None, None, None, None));
    }

    #[test]
    fn a_cursor_round_trips_and_a_bad_one_is_refused() {
        let at = DateTime::from_timestamp_micros(1_800_000_000_123_456).expect("a time");
        let id = Uuid::from_u128(42);
        assert_eq!(
            decode_cursor(&encode_cursor(at, id)).expect("decodes"),
            (at, id)
        );
        assert!(decode_cursor("nonsense").is_err());
        assert!(decode_cursor("12:not-a-uuid").is_err());
    }

    #[test]
    fn a_range_is_bounded() {
        let d = |y, m, day| NaiveDate::from_ymd_opt(y, m, day).expect("a date");
        assert!(
            PerformanceRange {
                from: d(2027, 1, 1),
                to: d(2027, 1, 31)
            }
            .check()
            .is_ok()
        );
        assert!(
            PerformanceRange {
                from: d(2027, 2, 1),
                to: d(2027, 1, 1)
            }
            .check()
            .is_err()
        );
        assert!(
            PerformanceRange {
                from: d(2026, 1, 1),
                to: d(2027, 6, 1)
            }
            .check()
            .is_err()
        );
    }
}
