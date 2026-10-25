//! A3-T5: what a new or tightened check does to the records already stored.
//!
//! `POST /api/v1/admin/business-rules/{id}/simulate` runs the rule over the
//! entity's live records in batches of [`BATCH`], exactly as
//! `.../{id}/test` evaluates one record, and answers how many it checked, how
//! many would be refused and the first [`FIRST_FAILING`] of those, before the
//! rule is published. A preview stops at [`PREVIEW_LIMIT`] records and says
//! so (`truncated`).
//!
//! Publishing enqueues `EngineJob::ValidationCleanupScan`, which scans every
//! live record and rewrites the rule's rows in `validation_cleanup`
//! (migration 0182): each failing record with its message and its owner, so
//! owners see their own records to fix
//! (`GET /api/v1/admin/business-rules/{id}/cleanup`). The scan is a durable
//! job, never the publish request: a full scan of a large table does not
//! belong on the request thread.
//!
//! O9-T1: a scenario can hold rule-change and flow-change runs.
//! `POST /api/v1/scenarios/{id}/simulations` runs this preview for a rule
//! (`rule_change`: the records it would refuse) or the M4 replay of a flow
//! version (`flow_change`: the past runs that would go differently) and
//! stores the result against the scenario (`scenario_simulation`, migration
//! 0240); `GET` on the same path lists them, newest first, to compare.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::business_rule_admin::{RuleTestRequest, RuleTestResponse};
use crate::rule_admin::{self as store, BusinessRule};

/// Records read per batch.
pub const BATCH: i64 = 500;
/// Most records a preview checks.
pub const PREVIEW_LIMIT: u64 = 10_000;
/// How many failing record ids a preview lists.
pub const FIRST_FAILING: usize = 50;

/// What a check would do to the stored records.
#[derive(Debug, Default, Clone, PartialEq, Serialize, ToSchema)]
pub struct Simulation {
    pub rule_id: Uuid,
    /// Live records checked.
    pub checked: u64,
    /// Records the check would refuse.
    pub failing: u64,
    /// Records whose condition could not be decided (an evaluation error).
    pub unknown: u64,
    /// The first failing records, in id order.
    pub failing_ids: Vec<Uuid>,
    /// The preview stopped at its limit before the end of the table.
    pub truncated: bool,
}

/// One record's verdict: refused (with the first refusing message), passing,
/// or undecided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Fails(String),
    Passes,
    Unknown,
}

/// The verdict a rule test outcome gives: any `error`-severity error
/// refuses; a warning does not.
pub(crate) fn verdict(outcome: &RuleTestResponse) -> Verdict {
    if let Some(error) = outcome.errors.iter().find(|e| e.severity == "error") {
        return Verdict::Fails(error.message.clone().unwrap_or_default());
    }
    if outcome.error.is_some() {
        return Verdict::Unknown;
    }
    Verdict::Passes
}

impl Simulation {
    /// Counts one record.
    pub(crate) fn record(&mut self, id: Uuid, verdict: &Verdict) {
        self.checked += 1;
        match verdict {
            Verdict::Fails(_) => {
                self.failing += 1;
                if self.failing_ids.len() < FIRST_FAILING {
                    self.failing_ids.push(id);
                }
            }
            Verdict::Unknown => self.unknown += 1,
            Verdict::Passes => {}
        }
    }
}

/// One live record as the scan reads it.
pub(crate) struct Stored {
    pub(crate) id: Uuid,
    owner: Option<Uuid>,
    pub(crate) data: Map<String, Value>,
}

/// The next batch of the entity's live records after `after`, by id.
pub(crate) async fn batch(
    state: &EngineState,
    entity: &str,
    after: Uuid,
) -> Result<Vec<Stored>, AppError> {
    let sql = format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id > $1 AND is_active IS NOT FALSE \
         ORDER BY id LIMIT $2",
        attome_core::quote_ident(entity)
    );
    let rows: Vec<Value> = sqlx::query_scalar(&sql)
        .bind(after)
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let data = row.as_object()?.clone();
            let id = data
                .get("id")?
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())?;
            let owner = data
                .get("owner_ref")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok());
            Some(Stored { id, owner, data })
        })
        .collect())
}

/// Runs `rule` over the stored records, calling `on_fail` for each refused
/// one, up to `limit` records (`None`: all).
async fn scan(
    state: &EngineState,
    rule: &BusinessRule,
    limit: Option<u64>,
    mut on_fail: impl FnMut(&Stored, &str),
) -> Result<Simulation, AppError> {
    let attrs = store::attrs_for_entity(state, &rule.entity_logicalname).ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{}'",
            rule.entity_logicalname
        ))
    })?;
    let now = Utc::now();
    let mut sim = Simulation {
        rule_id: rule.id,
        ..Simulation::default()
    };
    let mut after = Uuid::nil();
    loop {
        let records = batch(state, &rule.entity_logicalname, after).await?;
        let Some(last) = records.last() else {
            break;
        };
        after = last.id;
        let full = i64::try_from(records.len()).unwrap_or(i64::MAX) == BATCH;
        for stored in &records {
            if limit.is_some_and(|l| sim.checked >= l) {
                sim.truncated = true;
                return Ok(sim);
            }
            let request = RuleTestRequest {
                record: stored.data.clone(),
                audience: None,
            };
            let verdict = match crate::business_rule_admin::evaluate(rule, &attrs, &request, now) {
                Ok(outcome) => verdict(&outcome),
                Err(_) => Verdict::Unknown,
            };
            if let Verdict::Fails(message) = &verdict {
                on_fail(stored, message);
            }
            sim.record(stored.id, &verdict);
        }
        if !full {
            break;
        }
    }
    Ok(sim)
}

async fn read_rule(state: &EngineState, id: Uuid) -> Result<BusinessRule, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    store::read_rule(&mut conn, id)
        .await?
        .ok_or(AppError::NotFound)
}

/// The preview: the rule over at most [`PREVIEW_LIMIT`] stored records.
pub async fn simulate(state: &EngineState, rule_id: Uuid) -> Result<Simulation, AppError> {
    let rule = read_rule(state, rule_id).await?;
    scan(state, &rule, Some(PREVIEW_LIMIT), |_, _| {}).await
}

/// `EngineJob::ValidationCleanupScan`'s handler: scans every live record and
/// replaces the rule's clean-up rows with the records it refuses. A rule
/// deleted or deactivated since publish clears its rows. Safe to retry: each
/// run rewrites the whole set.
pub async fn run_cleanup_scan(state: &EngineState, rule_id: Uuid) -> Result<Simulation, AppError> {
    let rule = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        store::read_rule(&mut conn, rule_id).await?
    };
    let Some(rule) = rule.filter(|r| r.is_active) else {
        sqlx::query("DELETE FROM validation_cleanup WHERE rule_ref = $1")
            .bind(rule_id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        return Ok(Simulation {
            rule_id,
            ..Simulation::default()
        });
    };
    let mut failing: Vec<(Uuid, Option<Uuid>, String)> = Vec::new();
    let sim = scan(state, &rule, None, |stored, message| {
        failing.push((stored.id, stored.owner, message.to_owned()));
    })
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM validation_cleanup WHERE rule_ref = $1")
        .bind(rule_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for chunk in failing.chunks(usize::try_from(BATCH).unwrap_or(500)) {
        let ids: Vec<Uuid> = chunk.iter().map(|f| f.0).collect();
        let owners: Vec<Option<Uuid>> = chunk.iter().map(|f| f.1).collect();
        let messages: Vec<String> = chunk.iter().map(|f| f.2.clone()).collect();
        sqlx::query(
            "INSERT INTO validation_cleanup (rule_ref, entity, record_id, owner_ref, message) \
             SELECT $1, $2, r.id, r.owner, r.message \
             FROM UNNEST($3::uuid[], $4::uuid[], $5::text[]) AS r(id, owner, message) \
             ON CONFLICT (rule_ref, record_id) DO NOTHING",
        )
        .bind(rule_id)
        .bind(&rule.entity_logicalname)
        .bind(&ids)
        .bind(&owners)
        .bind(&messages)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        rule_id = %rule_id,
        checked = sim.checked,
        failing = sim.failing,
        "validation clean-up queue rewritten"
    );
    Ok(sim)
}

/// One record in a rule's clean-up queue.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct CleanupItem {
    pub record_id: Uuid,
    pub entity: String,
    pub message: String,
    /// The record's owner, who is asked to fix it.
    pub owner_ref: Option<Uuid>,
    pub found_at: DateTime<Utc>,
}

/// Simulate a business rule
///
/// Simulate a business rule. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules/{id}/simulate",
    description = "Runs the rule over the entity's stored records (at most 10,000) and returns how many it would refuse and the first 50 of them, without saving anything (A3-T5).",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "evaluates the stored rule over stored records in memory only; writes nothing")))),
    responses(
        (status = 200, description = "What the rule would do to the stored records", body = Simulation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 422, description = "The rule's entity is not registered", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn simulate_rule(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Simulation>, AppError> {
    simulate(&state, id).await.map(Json)
}

/// Business rule clean-up
///
/// Business rule clean-up. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/business-rules/{id}/cleanup",
    description = "The stored records the published rule refuses, as its last scan found them, newest first (A3-T5).",
    tag = "admin",
    params(("id" = Uuid, Path), OnePageQuery),
    responses(
        (status = 200, description = "The rule's clean-up queue", body = PaginatedResponse<CleanupItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn cleanup_queue(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<CleanupItem>>, AppError> {
    let window = page.window();
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validation_cleanup WHERE rule_ref = $1")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<CleanupItem> = sqlx::query_as(
        "SELECT record_id, entity, message, owner_ref, found_at FROM validation_cleanup \
         WHERE rule_ref = $1 ORDER BY found_at DESC, record_id LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    }))
}

// ── O9-T1: rule-change and flow-change scenarios ─────────────────────────

/// What a scenario simulation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioKind {
    RuleChange,
    FlowChange,
}

impl ScenarioKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rule_change" => Some(Self::RuleChange),
            "flow_change" => Some(Self::FlowChange),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuleChange => "rule_change",
            Self::FlowChange => "flow_change",
        }
    }
}

/// A rule-change or flow-change run for a scenario.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ScenarioSimulationBody {
    /// `rule_change` or `flow_change`.
    pub kind: String,
    /// The business rule (`rule_change`) or the flow definition
    /// (`flow_change`).
    pub subject_id: Uuid,
    /// `flow_change`: the version to replay.
    pub version_id: Option<Uuid>,
    /// `flow_change`: how many of the flow's latest finished runs, 1 to 50
    /// (default 10).
    pub last: Option<i64>,
}

/// One stored scenario simulation.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ScenarioSimulation {
    pub id: Uuid,
    pub scenario_id: Uuid,
    /// `rule_change` or `flow_change`.
    pub kind: String,
    pub subject_id: Uuid,
    pub subject_version_id: Option<Uuid>,
    /// Records the rule would refuse, or past runs that would go
    /// differently.
    pub affected: i64,
    /// The first affected records (rule) or the differing runs (flow).
    pub affected_ids: Vec<Uuid>,
    /// The full simulation result.
    #[schema(value_type = Object)]
    pub result: Value,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

/// What a rule simulation affects: the refused records. Pure.
pub fn rule_affected(simulation: &Simulation) -> (i64, Vec<Uuid>) {
    (
        i64::try_from(simulation.failing).unwrap_or(i64::MAX),
        simulation.failing_ids.clone(),
    )
}

/// What a flow replay affects: the runs that would go differently. Pure.
pub fn flow_affected(report: &attome_workflow::simulate::ReplayReport) -> (i64, Vec<Uuid>) {
    let ids: Vec<Uuid> = report
        .runs
        .iter()
        .filter(|r| !r.differences.is_empty())
        .map(|r| r.instance_id)
        .collect();
    (report.differing, ids)
}

async fn require_scenario(state: &EngineState, id: Uuid) -> Result<(), AppError> {
    if state.entities.load().get("dashboard_scenario").is_none() {
        return Err(AppError::NotFound);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM dashboard_scenario WHERE id = $1 AND is_active)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Runs a rule-change or flow-change simulation and stores it against the
/// scenario.
pub async fn run_scenario_simulation(
    state: &EngineState,
    actor: Uuid,
    scenario: Uuid,
    body: &ScenarioSimulationBody,
) -> Result<ScenarioSimulation, AppError> {
    let kind = ScenarioKind::parse(body.kind.trim())
        .ok_or_else(|| AppError::Validation("kind is rule_change or flow_change".into()))?;
    require_scenario(state, scenario).await?;
    let (affected, affected_ids, result, version) = match kind {
        ScenarioKind::RuleChange => {
            let simulation = simulate(state, body.subject_id).await?;
            let (affected, ids) = rule_affected(&simulation);
            let result = serde_json::to_value(&simulation).map_err(AppError::internal)?;
            (affected, ids, result, None)
        }
        ScenarioKind::FlowChange => {
            let version = body.version_id.ok_or_else(|| {
                AppError::Validation("a flow_change names the version_id to replay".into())
            })?;
            let report =
                attome_workflow::simulate::replay(state, body.subject_id, version, body.last)
                    .await?;
            let (affected, ids) = flow_affected(&report);
            let result = serde_json::to_value(&report).map_err(AppError::internal)?;
            (affected, ids, result, Some(version))
        }
    };
    sqlx::query_as(
        "INSERT INTO scenario_simulation \
             (scenario_id, kind, subject_id, subject_version_id, affected, affected_ids, \
              result, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING id, scenario_id, kind, subject_id, subject_version_id, affected, \
                   affected_ids, result, created_by, created_at",
    )
    .bind(scenario)
    .bind(kind.as_str())
    .bind(body.subject_id)
    .bind(version)
    .bind(affected)
    .bind(&affected_ids)
    .bind(&result)
    .bind(actor)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Run a scenario simulation
///
/// Run a scenario simulation. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/scenarios/{id}/simulations",
    operation_id = "scenario_simulation_run",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The scenario")),
    request_body = ScenarioSimulationBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The simulation, stored against the scenario", body = ScenarioSimulation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such scenario, rule, flow or version", body = ErrorResponse),
        (status = 422, description = "Unknown kind, a flow change without its version, or last out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Runs a rule-change or flow-change simulation for a scenario.
///
/// `rule_change` previews a business rule over the stored records (the
/// records it would refuse); `flow_change` replays a flow version over the
/// flow's latest finished runs (the runs that would go differently). The
/// result is stored against the scenario; nothing else is written.
pub(crate) async fn run_scenario(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<ScenarioSimulationBody>,
) -> Result<(StatusCode, Json<ScenarioSimulation>), AppError> {
    let stored = run_scenario_simulation(&state, ctx.user_id, id, &body).await?;
    Ok((StatusCode::CREATED, Json(stored)))
}

/// A scenario's simulations
///
/// A scenario's simulations. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/scenarios/{id}/simulations",
    operation_id = "scenario_simulation_list",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The scenario"), OnePageQuery),
    responses(
        (status = 200, description = "The scenario's simulations, newest first", body = PaginatedResponse<ScenarioSimulation>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Lists a scenario's rule-change and flow-change simulations.
///
/// Newest first, each with how many records or runs it affects, so runs of
/// the same rule or flow can be compared.
pub(crate) async fn list_scenario(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ScenarioSimulation>>, AppError> {
    let window = page.window();
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM scenario_simulation WHERE scenario_id = $1")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<ScenarioSimulation> = sqlx::query_as(
        "SELECT id, scenario_id, kind, subject_id, subject_version_id, affected, affected_ids, \
                result, created_by, created_at \
           FROM scenario_simulation WHERE scenario_id = $1 \
          ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_rule_change_affects_the_refused_records() {
        let simulation = Simulation {
            rule_id: Uuid::nil(),
            checked: 10,
            failing: 2,
            unknown: 0,
            failing_ids: vec![Uuid::from_u128(1), Uuid::from_u128(2)],
            truncated: false,
        };
        assert_eq!(
            rule_affected(&simulation),
            (2, vec![Uuid::from_u128(1), Uuid::from_u128(2)])
        );
        assert_eq!(
            ScenarioKind::parse("rule_change"),
            Some(ScenarioKind::RuleChange)
        );
        assert_eq!(
            ScenarioKind::parse("flow_change").map(ScenarioKind::as_str),
            Some("flow_change")
        );
        assert_eq!(ScenarioKind::parse("price_change"), None);
    }

    #[test]
    fn validation_simulation_counts_three_failing_of_a_hundred() {
        let mut sim = Simulation::default();
        let ids: Vec<Uuid> = (0..100u128).map(Uuid::from_u128).collect();
        for (i, id) in ids.iter().enumerate() {
            let v = if [7, 42, 99].contains(&i) {
                Verdict::Fails("amount must not be negative".into())
            } else {
                Verdict::Passes
            };
            sim.record(*id, &v);
        }
        assert_eq!(sim.checked, 100);
        assert_eq!(sim.failing, 3);
        assert_eq!(sim.failing_ids, vec![ids[7], ids[42], ids[99]]);
        assert_eq!(sim.unknown, 0);
    }

    #[test]
    fn validation_simulation_lists_at_most_fifty_failing_ids() {
        let mut sim = Simulation::default();
        for i in 0..120u128 {
            sim.record(Uuid::from_u128(i), &Verdict::Fails(String::new()));
        }
        assert_eq!(sim.failing, 120);
        assert_eq!(sim.failing_ids.len(), FIRST_FAILING);
        sim.record(Uuid::from_u128(500), &Verdict::Unknown);
        assert_eq!(sim.unknown, 1);
    }
}
