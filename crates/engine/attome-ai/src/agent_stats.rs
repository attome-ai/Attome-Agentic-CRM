//! AI8-T2/T3: the per-agent daily rollup (`ai_agent_daily_stat`, migration
//! `0052`), derived from three ledgers and rebuildable at any time:
//!
//! - **tasks** — the outcome ledger's `agent_task` rows proposed that day
//!   (UTC), per agent of the session in `agent_session_ref`: done, resolved
//!   (the measured `actual_value` says it succeeded), measured, the summed
//!   effectiveness, and hand-offs (rule `ai.handoff`);
//! - **tokens** — `ai_message.input_tokens`/`output_tokens` of the agent's
//!   sessions' conversations, by the message's day;
//! - **cost** — those tokens priced per model: `inference.spend.prices` when
//!   it names the model, else the approved `ai_model` catalogue entry
//!   (`budget_guard::price_from_catalogue`). A day with any unpriced tokens
//!   keeps its tokens, adds no cost for them and has no `cost_unit`.
//!
//! The agent is the session's `agent_definition_ref`, else its
//! `agent_object_ref`. Sums and counts are stored, never averages: a reader
//! divides. `time_saved_seconds` is an **estimate**, tasks done times the
//! per-source figure in [`TIME_SAVED`], stated as such wherever it is shown.
//!
//! [`rollup_day`] replaces the day in one transaction (delete, then insert),
//! so a rerun gives the same rows and an agent with nothing that day keeps
//! no stale row. The nightly run computes yesterday once the UTC day has
//! reached 02:00; `POST /api/v1/admin/ai/agents/performance/backfill`
//! queues a range of up to [`MAX_BACKFILL_DAYS`].

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_config::ModelPrice;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// An approved model's id, cost unit, input and output cost.
type ModelPriceRow = (String, Option<String>, Option<f64>, Option<f64>);

/// The backfill job's name.
pub const BACKFILL_JOB: &str = "ai_agent_stats_backfill";
/// The nightly job's name.
pub const NIGHTLY_JOB: &str = "ai_agent_stats_rollup";
/// Most days one backfill computes.
pub const MAX_BACKFILL_DAYS: i64 = 400;
/// The UTC hour from which yesterday is rolled up.
pub const NIGHTLY_HOUR: u32 = 2;
/// The `cost_unit` of a fully priced row: the price list's own currency.
pub const COST_UNIT: &str = "price_list";

/// Estimated seconds a person would spend on one task of each source.
pub const TIME_SAVED: &[(&str, i64)] = &[
    ("followup", 120),
    ("collections", 180),
    ("meeting", 900),
    ("handoff", 300),
];

/// The source of an outcome row: its `rule_ref` when it names one
/// (`ai.collections`, `ai.meeting`, `ai.handoff`), else `followup` for a
/// follow-up ledger item, else `other`. Pure.
pub fn source_of(rule_ref: Option<&str>, regarding_entity: Option<&str>) -> &'static str {
    match rule_ref {
        Some("ai.collections") => "collections",
        Some("ai.meeting") => "meeting",
        Some("ai.handoff") => "handoff",
        _ if regarding_entity == Some("ai_followup_item") => "followup",
        _ => "other",
    }
}

/// Seconds saved by `tasks` tasks of `source`; a source with no figure
/// saves none. Pure.
pub fn time_saved(source: &str, tasks: i64) -> i64 {
    TIME_SAVED
        .iter()
        .find(|(s, _)| *s == source)
        .map_or(0, |(_, seconds)| seconds * tasks)
}

/// Whether a measured outcome's `actual_value` says the task succeeded:
/// `true`, or an object with `success`/`resolved` true or an `outcome` of
/// `accepted`, `resolved`, `success` or `completed`. Pure.
pub fn resolved(actual: Option<&Value>) -> bool {
    match actual {
        Some(Value::Bool(b)) => *b,
        Some(Value::Object(map)) => {
            map.get("success").and_then(Value::as_bool) == Some(true)
                || map.get("resolved").and_then(Value::as_bool) == Some(true)
                || map
                    .get("outcome")
                    .and_then(Value::as_str)
                    .is_some_and(|o| matches!(o, "accepted" | "resolved" | "success" | "completed"))
        }
        _ => false,
    }
}

/// One model's tokens for an agent and day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelUsage {
    pub model_id: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// The cost of `usage` in micros of the price list's currency, and the
/// row's unit: [`COST_UNIT`] when every token was priced (or there were
/// none), `None` when some were not — their tokens add no cost. Pure.
pub fn price_usage(
    usage: &[ModelUsage],
    prices: &HashMap<String, ModelPrice>,
) -> (i64, Option<&'static str>) {
    let mut micros: u64 = 0;
    let mut all_priced = true;
    for u in usage {
        if u.input_tokens == 0 && u.output_tokens == 0 {
            continue;
        }
        match u.model_id.as_ref().and_then(|m| prices.get(m)) {
            // The budget guard's own pricing: tokens × price per million.
            Some(price) => {
                micros = micros.saturating_add(crate::budget_guard::cost_micros(
                    price,
                    u.input_tokens.max(0).unsigned_abs(),
                    u.output_tokens.max(0).unsigned_abs(),
                ));
            }
            None => all_priced = false,
        }
    }
    (
        i64::try_from(micros).unwrap_or(i64::MAX),
        all_priced.then_some(COST_UNIT),
    )
}

/// One agent's day.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DayStat {
    pub tasks_done: i32,
    pub tasks_resolved: i32,
    pub tasks_measured: i32,
    pub effectiveness_sum: f64,
    pub handoffs: i32,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_micros: i64,
    pub cost_unit: Option<&'static str>,
    pub time_saved_seconds: i64,
}

/// `(agent, rule_ref, regarding_entity, actual_value, measured, effectiveness)`.
type OutcomeRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<Value>,
    bool,
    Option<f64>,
);

/// The prices of `models`: the configuration's first, then the approved
/// catalogue's.
async fn prices_for(
    state: &EngineState,
    models: &[String],
) -> Result<HashMap<String, ModelPrice>, AppError> {
    let mut prices = HashMap::new();
    let configured = &state.base.config.inference.spend.prices;
    let mut rest = Vec::new();
    for model in models {
        match configured.get(model) {
            Some(price) => {
                prices.insert(model.clone(), *price);
            }
            None => rest.push(model.clone()),
        }
    }
    if rest.is_empty() {
        return Ok(prices);
    }
    let rows: Vec<ModelPriceRow> = sqlx::query_as(
        "SELECT provider_model_id, cost_unit::text, input_cost::float8, output_cost::float8 \
           FROM ai_model \
          WHERE provider_model_id = ANY($1) AND approval_status = 'approved' \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY provider_model_id, id",
    )
    .bind(&rest)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (model, unit, input, output) in rows {
        if prices.contains_key(&model) {
            continue;
        }
        if let (Some(unit), Some(input), Some(output)) = (unit, input, output)
            && let Some(price) = crate::budget_guard::price_from_catalogue(&unit, input, output)
        {
            prices.insert(model, price);
        }
    }
    Ok(prices)
}

/// Computes `day` (UTC) for every agent and replaces its rows; how many
/// rows were written.
pub async fn rollup_day(state: &EngineState, day: NaiveDate) -> Result<u64, AppError> {
    let db = &state.base.db;
    let from = day
        .and_hms_opt(0, 0, 0)
        .map(|t| t.and_utc())
        .ok_or_else(|| AppError::internal("day out of range"))?;
    let to = from + chrono::Duration::days(1);

    let outcomes: Vec<OutcomeRow> = sqlx::query_as(
        "SELECT COALESCE(s.agent_definition_ref, s.agent_object_ref), o.rule_ref, \
                o.regarding_entity, o.actual_value, o.measured_at IS NOT NULL, o.effectiveness \
           FROM outcome o JOIN agent_session s ON s.id = o.agent_session_ref \
          WHERE o.kind = 'agent_task' AND o.proposed_at >= $1 AND o.proposed_at < $2 \
            AND COALESCE(s.agent_definition_ref, s.agent_object_ref) IS NOT NULL",
    )
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let tokens: Vec<(Uuid, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT COALESCE(s.agent_definition_ref, s.agent_object_ref), m.model_id, \
                COALESCE(SUM(m.input_tokens), 0)::bigint, COALESCE(SUM(m.output_tokens), 0)::bigint \
           FROM ai_message m \
           JOIN ai_conversation c ON c.id = m.conversation_id \
           JOIN agent_session s ON s.id = c.agent_session_id \
          WHERE m.created_at >= $1 AND m.created_at < $2 \
            AND COALESCE(s.agent_definition_ref, s.agent_object_ref) IS NOT NULL \
          GROUP BY 1, 2",
    )
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut stats: BTreeMap<Uuid, DayStat> = BTreeMap::new();
    for (agent, rule_ref, regarding, actual, measured, effectiveness) in outcomes {
        let stat = stats.entry(agent).or_default();
        let source = source_of(rule_ref.as_deref(), regarding.as_deref());
        stat.tasks_done += 1;
        if source == "handoff" {
            stat.handoffs += 1;
        }
        if measured {
            stat.tasks_measured += 1;
            stat.effectiveness_sum += effectiveness.unwrap_or(0.0);
            if resolved(actual.as_ref()) {
                stat.tasks_resolved += 1;
            }
        }
        stat.time_saved_seconds += time_saved(source, 1);
    }
    let models: Vec<String> = {
        let mut m: Vec<String> = tokens.iter().filter_map(|t| t.1.clone()).collect();
        m.sort();
        m.dedup();
        m
    };
    let prices = prices_for(state, &models).await?;
    let mut usage: BTreeMap<Uuid, Vec<ModelUsage>> = BTreeMap::new();
    for (agent, model_id, input, output) in tokens {
        usage.entry(agent).or_default().push(ModelUsage {
            model_id,
            input_tokens: input,
            output_tokens: output,
        });
    }
    for (agent, rows) in &usage {
        let stat = stats.entry(*agent).or_default();
        stat.input_tokens = rows.iter().map(|r| r.input_tokens).sum();
        stat.output_tokens = rows.iter().map(|r| r.output_tokens).sum();
        let (micros, unit) = price_usage(rows, &prices);
        stat.cost_micros = micros;
        stat.cost_unit = unit;
    }
    for stat in stats.values_mut() {
        if stat.input_tokens == 0 && stat.output_tokens == 0 && stat.cost_unit.is_none() {
            stat.cost_unit = Some(COST_UNIT);
        }
    }

    let agents: Vec<Uuid> = stats.keys().copied().collect();
    let col = |f: fn(&DayStat) -> i64| stats.values().map(f).collect::<Vec<i64>>();
    let tasks_done = col(|s| i64::from(s.tasks_done));
    let tasks_resolved = col(|s| i64::from(s.tasks_resolved));
    let tasks_measured = col(|s| i64::from(s.tasks_measured));
    let handoffs = col(|s| i64::from(s.handoffs));
    let input_tokens = col(|s| s.input_tokens);
    let output_tokens = col(|s| s.output_tokens);
    let cost_micros = col(|s| s.cost_micros);
    let time_saved_seconds = col(|s| s.time_saved_seconds);
    let effectiveness: Vec<f64> = stats.values().map(|s| s.effectiveness_sum).collect();
    let units: Vec<Option<String>> = stats
        .values()
        .map(|s| s.cost_unit.map(str::to_owned))
        .collect();

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM ai_agent_daily_stat WHERE day = $1")
        .bind(day)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let written = if agents.is_empty() {
        0
    } else {
        sqlx::query(
            "INSERT INTO ai_agent_daily_stat \
               (agent_definition_ref, day, tasks_done, tasks_resolved, tasks_measured, \
                effectiveness_sum, handoffs, input_tokens, output_tokens, cost_micros, cost_unit, \
                time_saved_seconds, computed_at) \
             SELECT r.agent, $2::date, r.done::int, r.resolved::int, r.measured::int, r.eff, \
                    r.handoffs::int, r.input, r.output, r.cost, r.unit, r.saved, now() \
               FROM unnest($1::uuid[], $3::bigint[], $4::bigint[], $5::bigint[], \
                           $6::float8[], $7::bigint[], $8::bigint[], $9::bigint[], \
                           $10::bigint[], $11::text[], $12::bigint[]) \
                    AS r(agent, done, resolved, measured, eff, handoffs, input, output, cost, \
                         unit, saved) \
             ON CONFLICT (agent_definition_ref, day) DO UPDATE SET \
               tasks_done = EXCLUDED.tasks_done, tasks_resolved = EXCLUDED.tasks_resolved, \
               tasks_measured = EXCLUDED.tasks_measured, \
               effectiveness_sum = EXCLUDED.effectiveness_sum, handoffs = EXCLUDED.handoffs, \
               input_tokens = EXCLUDED.input_tokens, output_tokens = EXCLUDED.output_tokens, \
               cost_micros = EXCLUDED.cost_micros, cost_unit = EXCLUDED.cost_unit, \
               time_saved_seconds = EXCLUDED.time_saved_seconds, computed_at = now()",
        )
        .bind(&agents)
        .bind(day)
        .bind(&tasks_done)
        .bind(&tasks_resolved)
        .bind(&tasks_measured)
        .bind(&effectiveness)
        .bind(&handoffs)
        .bind(&input_tokens)
        .bind(&output_tokens)
        .bind(&cost_micros)
        .bind(&units)
        .bind(&time_saved_seconds)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
    };
    attome_db::tx::commit(tx).await?;
    Ok(written)
}

/// The day the nightly run rolls up at `now`: yesterday (UTC), once today
/// has reached [`NIGHTLY_HOUR`]. Pure.
pub fn nightly_day(now: DateTime<Utc>) -> Option<NaiveDate> {
    use chrono::Timelike;
    (now.hour() >= NIGHTLY_HOUR).then(|| now.date_naive() - chrono::Duration::days(1))
}

fn done_key(day: NaiveDate) -> String {
    format!("attome-ai:agent_stats:done:{day}")
}

/// The nightly run (job [`NIGHTLY_JOB`], hourly): yesterday, once a day.
/// `attome-ai:agent_stats:done:{day}` (kept three days) marks a day done; a
/// lost marker only recomputes the same rows.
pub async fn nightly(state: &EngineState, now: DateTime<Utc>) -> Result<Option<u64>, AppError> {
    let Some(day) = nightly_day(now) else {
        return Ok(None);
    };
    let key = done_key(day);
    match state.base.redis.get(&key).await {
        Ok(Some(_)) => return Ok(None),
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "agent stats: marker unavailable; computing"),
    }
    let written = rollup_day(state, day).await?;
    if let Err(error) = state
        .base
        .redis
        .set(
            &key,
            "1".to_owned(),
            Some(Duration::from_secs(3 * 24 * 3600)),
        )
        .await
    {
        tracing::warn!(%error, "agent stats: marker not stored");
    }
    Ok(Some(written))
}

/// The days of a backfill, oldest first. Pure.
pub fn backfill_days(from: NaiveDate, to: NaiveDate) -> Result<Vec<NaiveDate>, AppError> {
    if to < from {
        return Err(AppError::Validation("to must not be before from".into()));
    }
    let days = (to - from).num_days() + 1;
    if days > MAX_BACKFILL_DAYS {
        return Err(AppError::Validation(format!(
            "a backfill covers at most {MAX_BACKFILL_DAYS} days"
        )));
    }
    Ok((0..days)
        .map(|i| from + chrono::Duration::days(i))
        .collect())
}

/// A backfill, as queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AgentStatsBackfill {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

/// Runs a queued backfill, day by day; rows written.
pub async fn run_backfill(state: &EngineState, job: &AgentStatsBackfill) -> Result<u64, AppError> {
    let mut written = 0;
    for day in backfill_days(job.from, job.to)? {
        written += rollup_day(state, day).await?;
    }
    Ok(written)
}

/// Rebuild agent performance for past days
///
/// Queues a job that rebuilds the per-agent daily rollup for the days from `from` to `to` from the
/// outcome, message and price ledgers. AI administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/agents/performance/backfill",
    tag = "ai",
    request_body = AgentStatsBackfill,
    responses(
        (status = 202, description = "The backfill is queued", body = AgentStatsBackfill),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "to before from, or more than 400 days", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Execute)])))),
)]
async fn post_backfill(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Json(body): Json<AgentStatsBackfill>,
) -> Result<(StatusCode, Json<AgentStatsBackfill>), AppError> {
    backfill_days(body.from, body.to)?;
    // Built here rather than through the registry, which a process that
    // runs no jobs never fills; the worker's handler (version 1) reads it.
    let job = attome_jobs::RegisteredJob {
        name: BACKFILL_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(body).map_err(AppError::internal)?,
        next: None,
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Execute,
            ctx.user_id,
            "ai_agent_daily_stat",
            None,
        )
        .comment(format!(
            "agent performance backfill {} to {}",
            body.from, body.to
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::ACCEPTED, Json(body)))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/ai/agents/performance/backfill",
        post(post_backfill),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_backfill), components(schemas(AgentStatsBackfill)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price(input: f64, output: f64) -> ModelPrice {
        ModelPrice {
            prompt_per_million: input,
            completion_per_million: output,
        }
    }

    #[test]
    fn cost_without_price_is_null_unit() {
        let prices: HashMap<String, ModelPrice> = [("gpt-small".to_owned(), price(2.0, 8.0))]
            .into_iter()
            .collect();
        let priced = vec![ModelUsage {
            model_id: Some("gpt-small".into()),
            input_tokens: 1_000,
            output_tokens: 500,
        }];
        // 1,000 × 2 + 500 × 8 = 6,000 micros (0.006 of the currency).
        assert_eq!(price_usage(&priced, &prices), (6_000, Some(COST_UNIT)));
        let mixed = vec![
            priced[0].clone(),
            ModelUsage {
                model_id: Some("local-unpriced".into()),
                input_tokens: 9_000,
                output_tokens: 9_000,
            },
        ];
        assert_eq!(
            price_usage(&mixed, &prices),
            (6_000, None),
            "tokens count, no cost, no unit"
        );
        assert_eq!(price_usage(&[], &prices), (0, Some(COST_UNIT)));
    }

    #[test]
    fn time_saved_uses_source_table() {
        assert_eq!(time_saved("followup", 3), 360);
        assert_eq!(time_saved("collections", 2), 360);
        assert_eq!(time_saved("meeting", 1), 900);
        assert_eq!(time_saved("handoff", 1), 300);
        assert_eq!(time_saved("other", 5), 0);
        assert_eq!(source_of(Some("ai.meeting"), None), "meeting");
        assert_eq!(
            source_of(Some("ai.collections"), Some("ai_followup_item")),
            "collections"
        );
        assert_eq!(
            source_of(Some("0190-uuid"), Some("ai_followup_item")),
            "followup"
        );
        assert_eq!(source_of(None, Some("activity")), "other");
    }

    #[test]
    fn a_measured_success_is_resolved() {
        assert!(resolved(Some(
            &serde_json::json!({ "outcome": "accepted" })
        )));
        assert!(resolved(Some(&serde_json::json!({ "success": true }))));
        assert!(resolved(Some(&serde_json::json!(true))));
        assert!(!resolved(Some(
            &serde_json::json!({ "outcome": "rejected" })
        )));
        assert!(!resolved(None));
    }

    #[test]
    fn the_nightly_run_waits_for_two_and_takes_yesterday() {
        use chrono::TimeZone;
        let early = Utc.with_ymd_and_hms(2027, 3, 10, 1, 59, 0).unwrap();
        assert_eq!(nightly_day(early), None);
        let two = Utc.with_ymd_and_hms(2027, 3, 10, 2, 0, 0).unwrap();
        assert_eq!(nightly_day(two), NaiveDate::from_ymd_opt(2027, 3, 9));
    }

    #[test]
    fn a_backfill_is_bounded_and_in_order() {
        let d = |m, day| NaiveDate::from_ymd_opt(2027, m, day).unwrap();
        assert_eq!(
            backfill_days(d(3, 1), d(3, 3)).unwrap(),
            vec![d(3, 1), d(3, 2), d(3, 3)]
        );
        assert!(backfill_days(d(3, 3), d(3, 1)).is_err());
        assert!(backfill_days(d(1, 1), NaiveDate::from_ymd_opt(2028, 6, 1).unwrap()).is_err());
    }
}
