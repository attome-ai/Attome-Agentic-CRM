//! M48 Phase 1 (Scenario & Simulation, scoped-down slice —
//! `document/xrm/module/M48-scenario-simulation/master-plan.md`) — scenario
//! records, comparison, and branching (clone). Phase 2 (`base-simulate`
//! discrete-event engine, `xrm-simulate`, `MODULE_SIMULATE`) is explicitly
//! out of scope — nothing in this file references it.
//!
//! **Formula-backed metrics are the real what-if now — everything else is
//! still `baseline_only`/`pending`, read on.**
//! `attome_metric::metric::evaluate_formula_metric` (D-480 moved M27's
//! `metric.rs` to its own crate; REVIEW-2026-09-02's M27 formula fix) is the
//! mechanism the plan's Phase 1 vision asked for: `evaluate_one_metric`
//! below fetches this scenario's
//! `dashboard_scenario_assumption` rows once per `evaluate` call
//! ([`fetch_assumption_overrides`]), resolves each into a `key -> f64`
//! override, and calls `evaluate_formula_metric` twice — once with no
//! overrides (the baseline) and once with this scenario's overrides (the
//! scenario value) — so `delta` is a real difference, not a placeholder.
//!
//! `evaluate` below therefore does NOT fake plausible-looking numbers. Per
//! metric it does exactly one of:
//! - **formula-backed metric**: `ok` with a real `baseline_value`/
//!   `scenario_value`/`delta` when the formula and every metric it
//!   references resolve; `not_computable` with the underlying error in
//!   `note` when a reference is missing/undefined for this period — see
//!   this module's own doc comment on `evaluate_formula_metric`.
//! - **query/manual-backed metric with a successful snapshot**: the plan
//!   itself already documents this boundary ("query-backed metrics are not
//!   overridable in v1 — they read live data — the UI says so"), so even
//!   here nothing is actually *varied* by the scenario's assumptions; this
//!   writes a `baseline_only` result — `scenario_value` echoes the latest
//!   computed `metric_snapshot` value unchanged, `delta` is exactly
//!   `0.0`, and `note` says so explicitly, so a caller can never mistake
//!   this for a real what-if.
//! - **query/manual-backed metric with no successful snapshot yet**: writes
//!   a `pending` result and says what to do about it
//!   (`POST /api/v1/metrics/{id}/compute` first).
//!
//! See `document/decisions/runtime/D-453.md` for the recorded ruling this
//! module implements, and `scenario_seed.rs`'s module doc for why
//! `dashboard_scenario.status` is a plain Choice field rather than a boot-seeded
//! M07 state model.
use attome_core::EngineState;
use attome_db::DbPool;
use attome_records::entity_crud::create_record_for;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::access::require_entity_access;
use crate::auth::{ScenarioRead, ScenarioUpdate};
use attome_metric::metric::{
    METRIC_DEFINITION_COLUMNS, MetricDefinitionRow, SnapshotStatus, evaluate_formula_metric,
    latest_snapshot, period_start_for,
};

/// R-12 step 3's cap on how many additional scenarios `compare`'s `with=`
/// list may name — bounds both the record-level access-check loop and the
/// id list this module's own batched `ANY($1)` reads bind against.
const MAX_COMPARE_SCENARIOS: usize = 10;

// ── Data access ──────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ScenarioRow {
    id: Uuid,
    name: String,
}

async fn fetch_scenario(db: &DbPool, scenario_id: Uuid) -> Result<ScenarioRow, AppError> {
    sqlx::query_as::<_, ScenarioRow>(
        "SELECT id, name FROM dashboard_scenario \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(scenario_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// `metrics[]` for one scenario, in declared order.
async fn fetch_scenario_metric_refs(db: &DbPool, scenario_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT metric_ref FROM dashboard_scenario_metric \
         WHERE scenario_ref = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY display_order NULLS LAST, created_at",
    )
    .bind(scenario_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Resolves this scenario's `dashboard_scenario_assumption` rows into a
/// `key -> f64` override map for [`evaluate_formula_metric`].
/// `kind = "value"` parses `expression_or_value` as a plain number.
/// `kind = "expression"` evaluates it via `attome_rules` under an empty
/// `Schema`/`Context` — literals and pure functions only (`round(1.1 * 100)`
/// is fine; a bare field ref is rejected by the type checker, since an
/// assumption's own expression has no metric of its own to resolve a
/// related-metric reference against). A malformed assumption is a
/// `Validation` error surfaced to the caller, not silently skipped — a typo
/// in an assumption must not silently evaluate as "no override".
async fn fetch_assumption_overrides(
    db: &DbPool,
    scenario_id: Uuid,
) -> Result<std::collections::HashMap<String, f64>, AppError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT key, kind, expression_or_value FROM dashboard_scenario_assumption \
         WHERE scenario_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(scenario_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut overrides = std::collections::HashMap::with_capacity(rows.len());
    for (key, kind, raw) in rows {
        let value = match kind.as_str() {
            "value" => raw.trim().parse::<f64>().map_err(|_| {
                AppError::Validation(format!(
                    "scenario assumption '{key}' has kind=value but '{raw}' is not a number"
                ))
            })?,
            "expression" => {
                let schema = attome_rules::Schema::new();
                let compiled = attome_rules::compile(&raw, &schema).map_err(|e| {
                    AppError::Validation(format!(
                        "scenario assumption '{key}': invalid expression: {e}"
                    ))
                })?;
                let ctx = attome_rules::Context::new(Utc::now());
                match compiled.eval(&ctx).map_err(|e| {
                    AppError::Validation(format!(
                        "scenario assumption '{key}': expression evaluation failed: {e}"
                    ))
                })? {
                    attome_rules::Value::Number(n) => n,
                    other => {
                        return Err(AppError::Validation(format!(
                            "scenario assumption '{key}' must evaluate to a number, not {:?}",
                            other.ty()
                        )));
                    }
                }
            }
            other => {
                return Err(AppError::internal(format!(
                    "unknown scenario assumption kind: {other}"
                )));
            }
        };
        overrides.insert(key, value);
    }
    Ok(overrides)
}

/// `pub` (fields too) — same reason `attome_metric::metric::SnapshotRow` is: `do_evaluate`
/// below returns these directly, and this crate's own `tests/scenario.rs`
/// reads their fields straight off the result of a direct call, the same
/// "call the `pub` `do_*` function, skip the HTTP layer" convention every
/// other suite in this crate already uses.
#[derive(Debug, sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub struct ScenarioResultRow {
    pub id: Uuid,
    pub scenario_ref: Uuid,
    pub metric_ref: Uuid,
    pub baseline_value: Option<f64>,
    pub scenario_value: Option<f64>,
    pub delta: Option<f64>,
    pub status: String,
    pub note: Option<String>,
}

const RESULT_COLUMNS: &str =
    "id, scenario_ref, metric_ref, baseline_value, scenario_value, delta, status, note";

/// Generic over `sqlx::PgExecutor` (same convention
/// `attome-notification::consent_gate::has_active_consent` already uses) so
/// `evaluate` below can run every `INSERT` this makes inside its one
/// `db.begin()` transaction — `&mut *tx`, not the bare pool — making the N
/// result rows for one `evaluate` call atomic (R-12 step 4).
#[allow(clippy::too_many_arguments)]
async fn insert_result<'e, E>(
    executor: E,
    scenario_id: Uuid,
    metric_id: Uuid,
    baseline_value: Option<f64>,
    scenario_value: Option<f64>,
    delta: Option<f64>,
    status: &str,
    note: &str,
    evaluated_by: Uuid,
) -> Result<ScenarioResultRow, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let id = Uuid::now_v7();
    sqlx::query_as::<_, ScenarioResultRow>(&format!(
        "INSERT INTO dashboard_scenario_result \
         (id, scenario_ref, metric_ref, baseline_value, scenario_value, delta, status, note, \
          evaluated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {RESULT_COLUMNS}"
    ))
    .bind(id)
    .bind(scenario_id)
    .bind(metric_id)
    .bind(baseline_value)
    .bind(scenario_value)
    .bind(delta)
    .bind(status)
    .bind(note)
    .bind(evaluated_by)
    .fetch_one(executor)
    .await
    .map_err(AppError::internal)
}

/// The one function that decides, per metric, what `evaluate` can honestly
/// say — see this module's own doc comment for the three outcomes. `db`
/// serves every read (metric lookups, snapshot reads, formula evaluation);
/// `tx` is the caller's open `evaluate` transaction, used only for this
/// metric's one `insert_result` write, so the N writes across the whole
/// `evaluate` call commit or roll back together (R-12 step 4).
async fn evaluate_one_metric(
    db: &DbPool,
    tx: &mut Transaction<'_, Postgres>,
    scenario_id: Uuid,
    metric: &MetricDefinitionRow,
    overrides: &std::collections::HashMap<String, f64>,
    evaluated_by: Uuid,
) -> Result<ScenarioResultRow, AppError> {
    if metric.source_kind == "formula" {
        let Some(formula) = metric.formula.clone() else {
            return insert_result(
                &mut **tx,
                scenario_id,
                metric.id,
                None,
                None,
                None,
                "not_computable",
                "this metric is source_kind=formula but has no formula set",
                evaluated_by,
            )
            .await;
        };
        let period_start = period_start_for(&metric.period, Utc::now())?;
        let baseline = evaluate_formula_metric(db, &formula, period_start, None)
            .await
            .map_err(|e| e.to_string());
        let scenario_value = evaluate_formula_metric(db, &formula, period_start, Some(overrides))
            .await
            .map_err(|e| e.to_string());
        return match (baseline, scenario_value) {
            (Ok(baseline), Ok(scenario_value)) => {
                insert_result(
                    &mut **tx,
                    scenario_id,
                    metric.id,
                    Some(baseline),
                    Some(scenario_value),
                    Some(scenario_value - baseline),
                    "ok",
                    "formula re-evaluated against this scenario's assumptions",
                    evaluated_by,
                )
                .await
            }
            (Err(e), _) | (_, Err(e)) => {
                insert_result(
                    &mut **tx,
                    scenario_id,
                    metric.id,
                    None,
                    None,
                    None,
                    "not_computable",
                    &e,
                    evaluated_by,
                )
                .await
            }
        };
    }

    // query | manual — the plan itself documents this boundary: query-backed
    // metrics read live data and are not overridable in v1. There is
    // nothing for a scenario's assumptions to vary here either; the best
    // this can honestly report is "here is the metric's current value,
    // unchanged by this scenario".
    let period_start = period_start_for(&metric.period, Utc::now())?;
    let snapshot = latest_snapshot(db, metric.id, period_start).await?;
    match snapshot {
        Some(s) if s.status != SnapshotStatus::Failed.as_str() && s.actual.is_some() => {
            let baseline = s.actual;
            insert_result(
                &mut **tx,
                scenario_id,
                metric.id,
                baseline,
                baseline,
                Some(0.0),
                "baseline_only",
                "query/manual metric — this scaffolding has no mechanism to vary it by scenario \
                 assumptions yet (query-backed metrics are not overridable in v1, per the plan). \
                 scenario_value echoes the latest computed snapshot for the metric's current \
                 period unchanged; delta is 0 by construction, not a real what-if result.",
                evaluated_by,
            )
            .await
        }
        _ => {
            insert_result(
                &mut **tx,
                scenario_id,
                metric.id,
                None,
                None,
                None,
                "pending",
                "no successful snapshot exists yet for this metric's current period — call \
                 POST /api/v1/metrics/{id}/compute, then re-run evaluate.",
                evaluated_by,
            )
            .await
        }
    }
}

/// R-12 step 4: every metric this scenario references, in one `ANY($1)`
/// query instead of one `fetch_metric` per metric id. Returns a map so
/// `evaluate` can walk `metric_ids` in its own declared order while still
/// failing the whole call with `NotFound` if any referenced metric doesn't
/// resolve — the same "a missing definition fails the request" contract
/// `fetch_metric` gave per id before this change.
async fn fetch_metrics_by_ids(
    db: &DbPool,
    metric_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, MetricDefinitionRow>, AppError> {
    if metric_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let rows: Vec<MetricDefinitionRow> = sqlx::query_as(&format!(
        "SELECT {METRIC_DEFINITION_COLUMNS} FROM dashboard_metric_definition \
         WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(metric_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|m| (m.id, m)).collect())
}

/// R-12 step 4: the same "lock BEFORE reading" advisory-lock shape
/// `lifecycle.rs::lock_dashboard` uses, scoped to this scenario's own
/// `evaluate` — two concurrent `evaluate` calls for the same scenario must
/// not both write a result set (a second's writes could otherwise interleave
/// with the first's within the shared `dashboard_scenario_result` table). Namespace
/// 15 is `attome-dashboard`'s own (`crate::ADVISORY_LOCK_NAMESPACE`, pinned in
/// `crates/server/tests/advisory_lock_namespaces.rs`).
async fn lock_scenario_evaluate(
    tx: &mut Transaction<'_, Postgres>,
    scenario_id: Uuid,
) -> Result<(), AppError> {
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-dashboard/scenario-evaluate:{scenario_id}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another evaluate is already running for this scenario",
        ));
    }
    Ok(())
}

// ── HTTP surface ─────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
struct EvaluateResponse {
    scenario_id: Uuid,
    results: Vec<ScenarioResultRow>,
}

/// `pub` (not `pub(crate)`) — same reasoning as `lifecycle.rs::do_clone`/
/// `scenario.rs::do_clone` above: this crate's own `tests/scenario.rs`
/// exercises the real transaction/lock/insert logic directly against a live
/// database, skipping the HTTP layer. `evaluate` below owns only the
/// record-level access check (R-04); this function performs no privilege
/// check of its own.
///
/// R-12 step 4: batches the metric fetch (one `ANY($1)` instead of one
/// `fetch_metric` per referenced id) and wraps the whole per-metric write
/// loop in one `db.begin()` transaction, guarded by
/// [`lock_scenario_evaluate`] taken BEFORE any write — the same "lock, then
/// act" order `lifecycle.rs::lock_dashboard` uses — so two concurrent
/// `evaluate` calls for the same scenario can't interleave their
/// `dashboard_scenario_result` writes, and the N inserts for one call commit or
/// roll back together.
pub async fn do_evaluate(
    state: &EngineState,
    scenario_id: Uuid,
    evaluated_by: Uuid,
) -> Result<Vec<ScenarioResultRow>, AppError> {
    let db = &state.base.db;
    fetch_scenario(db, scenario_id).await?;
    let metric_ids = fetch_scenario_metric_refs(db, scenario_id).await?;
    let overrides = fetch_assumption_overrides(db, scenario_id).await?;
    let mut metrics_by_id = fetch_metrics_by_ids(db, &metric_ids).await?;

    let mut tx = attome_db::tx::begin(db).await?;
    lock_scenario_evaluate(&mut tx, scenario_id).await?;

    let mut results = Vec::with_capacity(metric_ids.len());
    for metric_id in &metric_ids {
        let metric = metrics_by_id.remove(metric_id).ok_or(AppError::NotFound)?;
        let result =
            evaluate_one_metric(db, &mut tx, scenario_id, &metric, &overrides, evaluated_by)
                .await?;
        results.push(result);
    }

    tx.commit().await.map_err(AppError::internal)?;
    Ok(results)
}

/// `POST /api/v1/scenarios/{id}/evaluate` — see this module's doc comment
/// for exactly what this does and does not compute. `dashboard_scenario.update`:
/// reuses the entity's own generic update privilege for this bespoke
/// business action (it writes new `dashboard_scenario_result` rows), same
/// convention `MetricUpdate`/`DecisionUpdate` already use in this crate.
#[utoipa::path(
    post,
    path = "/api/v1/scenarios/{id}/evaluate",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success — see each result's `status`/`note`. `ok` appears \
            for a formula-backed metric that resolves against this scenario's assumptions \
            (D-480/M27); `baseline_only`, `not_computable`, or `pending` cover every \
            query/manual-backed metric per this module's own doc comment",
            body = EvaluateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such scenario, or one it references a metric that no \
            longer resolves", body = ErrorResponse),
        (status = 409, description = "Another evaluate is already running for this scenario", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
)]
async fn evaluate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScenarioUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<EvaluateResponse>, AppError> {
    require_entity_access(&state, &ctx, "dashboard_scenario", id, RecordAction::Update).await?;
    let results = do_evaluate(&state, id, ctx.user_id).await?;
    attome_audit::write_business_event(
        &state,
        "dashboard_scenario",
        id,
        attome_audit::AuditOperation::Execute,
        "scenario.evaluate",
        ctx.user_id,
        None,
        None,
        format!("evaluated, {} result(s)", results.len()),
    )
    .await;
    Ok(Json(EvaluateResponse {
        scenario_id: id,
        results,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
struct CompareQuery {
    /// Comma-separated additional scenario ids to compare against `{id}`.
    #[serde(default)]
    with: Option<String>,
}

/// `pub` (this struct and the three below, fields too) — `do_compare`
/// returns this directly and this crate's own `tests/scenario.rs` inspects
/// it, same reasoning as `ScenarioResultRow` above.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CompareMetricColumn {
    pub metric_ref: Uuid,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CompareCell {
    pub metric_ref: Uuid,
    pub baseline_value: Option<f64>,
    pub scenario_value: Option<f64>,
    pub delta: Option<f64>,
    pub status: String,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CompareScenarioRow {
    pub scenario_id: Uuid,
    pub name: String,
    /// Aligned by index with the response's `metrics` array — a `null`-shaped
    /// entry (`status = "not_evaluated"`) stands in for a metric this
    /// scenario references but has never run `evaluate` for.
    pub cells: Vec<CompareCell>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CompareResponse {
    pub metrics: Vec<CompareMetricColumn>,
    pub scenarios: Vec<CompareScenarioRow>,
}

/// R-12 step 3: every `(scenario, metric)` pair's most recently inserted
/// `dashboard_scenario_result` row, for the whole compare grid in one statement
/// instead of one `latest_result` call per cell (was `O(scenarios *
/// metrics)`). `DISTINCT ON (scenario_ref, metric_ref)` + the matching
/// leading `ORDER BY` columns picks exactly one — the newest by `created_at`
/// (this crate's own `dashboard_scenario_result` is an ordinary provisioned entity,
/// so it carries no bespoke `evaluated_at` column — see `scenario_seed.rs`'s
/// module doc comment) — per pair, tie-broken by `id` the same way the
/// single-pair version this replaces was.
async fn latest_results_batch(
    db: &DbPool,
    scenario_ids: &[Uuid],
    metric_ids: &[Uuid],
) -> Result<std::collections::HashMap<(Uuid, Uuid), ScenarioResultRow>, AppError> {
    if scenario_ids.is_empty() || metric_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let rows: Vec<ScenarioResultRow> = sqlx::query_as(&format!(
        "SELECT DISTINCT ON (scenario_ref, metric_ref) {RESULT_COLUMNS} \
         FROM dashboard_scenario_result \
         WHERE scenario_ref = ANY($1) AND metric_ref = ANY($2) \
         ORDER BY scenario_ref, metric_ref, created_at DESC, id DESC"
    ))
    .bind(scenario_ids)
    .bind(metric_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|r| ((r.scenario_ref, r.metric_ref), r))
        .collect())
}

/// R-12 step 3: every scenario being compared, in one `ANY($1)` query
/// instead of one `fetch_scenario` per id.
async fn fetch_scenarios_by_ids(
    db: &DbPool,
    scenario_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, ScenarioRow>, AppError> {
    if scenario_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let rows: Vec<ScenarioRow> = sqlx::query_as(
        "SELECT id, name FROM dashboard_scenario \
         WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)",
    )
    .bind(scenario_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|r| (r.id, r)).collect())
}

/// `pub` — same reasoning as `do_evaluate` above: this crate's own
/// `tests/scenario.rs` calls this directly, skipping the HTTP layer. Unlike
/// `do_evaluate`/`do_clone`, this one *does* perform its own R-04
/// record-level access check (rather than leaving it to the HTTP handler)
/// because the set of records to check — every scenario named by `with` —
/// isn't known until after this function has parsed and validated `with`
/// itself; `compare` below is therefore a pure pass-through.
///
/// R-12 step 3: batches the scenario fetch (one `ANY($1)` instead of one
/// `fetch_scenario` per id) and the whole compare grid's result lookup (one
/// `DISTINCT ON` read instead of one `latest_result` call per `(scenario,
/// metric)` cell — was `O(scenarios * metrics)`), and caps `with` at
/// [`MAX_COMPARE_SCENARIOS`] before either batched read runs.
pub async fn do_compare(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    with: Option<&str>,
) -> Result<CompareResponse, AppError> {
    let mut with_ids: Vec<Uuid> = Vec::new();
    if let Some(with) = with {
        for part in with.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let parsed: Uuid = part
                .parse()
                .map_err(|_| AppError::Validation("`with` must be comma-separated UUIDs".into()))?;
            with_ids.push(parsed);
        }
    }
    // R-12 step 3: cap `with` before it drives any batched `ANY($1)` read
    // below — an unbounded id list is exactly the unbounded read this whole
    // item removes.
    if with_ids.len() > MAX_COMPARE_SCENARIOS {
        return Err(AppError::Validation(format!(
            "`with` may name at most {MAX_COMPARE_SCENARIOS} additional scenarios"
        )));
    }

    let mut scenario_ids = vec![id];
    for parsed in with_ids {
        if !scenario_ids.contains(&parsed) {
            scenario_ids.push(parsed);
        }
    }

    // R-04: every scenario being compared — the path `{id}` and everything
    // named in `?with=` — must individually pass a record-level Read check,
    // not just the entity-level `dashboard_scenario.read` the route's compile-time
    // policy already verified.
    for scenario_id in &scenario_ids {
        require_entity_access(
            state,
            ctx,
            "dashboard_scenario",
            *scenario_id,
            RecordAction::Read,
        )
        .await?;
    }

    // R-12 step 3: one batched scenario fetch instead of one per id.
    let mut scenarios_by_id = fetch_scenarios_by_ids(&state.base.db, &scenario_ids).await?;

    let mut metric_ids: Vec<Uuid> = Vec::new();
    for scenario_id in &scenario_ids {
        if !scenarios_by_id.contains_key(scenario_id) {
            return Err(AppError::NotFound);
        }
        let refs = fetch_scenario_metric_refs(&state.base.db, *scenario_id).await?;
        for m in &refs {
            if !metric_ids.contains(m) {
                metric_ids.push(*m);
            }
        }
    }

    // R-12 step 3: one batched `DISTINCT ON` read for the whole grid instead
    // of one `latest_result` call per (scenario, metric) cell.
    let results_by_pair = latest_results_batch(&state.base.db, &scenario_ids, &metric_ids).await?;

    let mut scenario_rows = Vec::with_capacity(scenario_ids.len());
    for scenario_id in &scenario_ids {
        let name = scenarios_by_id
            .remove(scenario_id)
            .map(|r| r.name)
            .ok_or(AppError::NotFound)?;
        let mut cells = Vec::with_capacity(metric_ids.len());
        for metric_id in &metric_ids {
            let cell = match results_by_pair.get(&(*scenario_id, *metric_id)) {
                Some(r) => CompareCell {
                    metric_ref: *metric_id,
                    baseline_value: r.baseline_value,
                    scenario_value: r.scenario_value,
                    delta: r.delta,
                    status: r.status.clone(),
                    note: r.note.clone(),
                },
                None => CompareCell {
                    metric_ref: *metric_id,
                    baseline_value: None,
                    scenario_value: None,
                    delta: None,
                    status: "not_evaluated".to_string(),
                    note: Some(format!(
                        "POST /api/v1/scenarios/{scenario_id}/evaluate has not been run yet"
                    )),
                },
            };
            cells.push(cell);
        }
        scenario_rows.push(CompareScenarioRow {
            scenario_id: *scenario_id,
            name,
            cells,
        });
    }

    Ok(CompareResponse {
        metrics: metric_ids
            .into_iter()
            .map(|metric_ref| CompareMetricColumn { metric_ref })
            .collect(),
        scenarios: scenario_rows,
    })
}

/// `GET /api/v1/scenarios/{id}/compare?with=uuid1,uuid2` — N scenarios x
/// metrics comparison matrix (plan §3.1). A straightforward read over the
/// entities `scenario_seed.rs` provisions: the metric column set is the
/// union of every `dashboard_scenario_metric` row referenced by any scenario being
/// compared; each cell is that scenario's most recent `evaluate` result for
/// that metric, or an explicit `not_evaluated` placeholder when it never ran
/// one. `dashboard_scenario.read`.
#[utoipa::path(
    get,
    path = "/api/v1/scenarios/{id}/compare",
    tag = "dashboard",
    params(("id" = Uuid, Path), CompareQuery),
    responses(
        (status = 200, description = "Success", body = CompareResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such scenario (the anchor `{id}`, or one named in `with`)", body = ErrorResponse),
        (status = 422, description = "`with` names more than 10 additional scenarios", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn compare(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScenarioRead>>,
    Path(id): Path<Uuid>,
    Query(q): Query<CompareQuery>,
) -> Result<Json<CompareResponse>, AppError> {
    let response = do_compare(&state, &ctx, id, q.with.as_deref()).await?;
    Ok(Json(response))
}

// ── Clone (branching) ────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ScenarioFieldsRow {
    name: String,
    description: Option<String>,
}

/// `pub` (not `pub(crate)`) — same reasoning as `lifecycle.rs::do_clone`:
/// this crate's own tests exercise it directly against a live database.
/// Copies the source scenario's assumptions and metric refs into the new
/// row, then sets `base_kind = "scenario_ref"` / `base_scenario_ref` = the
/// source — the branching mechanism the plan's `base` field describes.
///
/// R-07 Tier 1: every write is now an
/// `attome_records::entity_crud::create_record_for` call — the scenario
/// row, then one per copied assumption, then one per copied metric ref —
/// bounded by the source's own row count, same invariants (validation,
/// `row_version`, change-event outbox row, audit) a `POST` through the
/// generic engine gets. Deliberately not wrapped in one transaction (unlike
/// the old three-`INSERT` version): each engine write is already atomic on
/// its own, so a failure partway through this loop leaves a real, visible,
/// recoverable partial clone rather than today's silent one — see R-07's
/// spec for why that trade is preferred here over `entity_mutation::
/// create_one` under a shared `tx`.
///
/// Caller-authorization contract: same as `create_record_for` itself — `ctx`
/// must already hold `dashboard_scenario.create` (the HTTP handler's
/// `ctx.require_key` does this); this function performs no privilege check
/// of its own.
pub async fn do_clone(
    state: &EngineState,
    ctx: &SecurityContext,
    scenario_id: Uuid,
    cloned_by: Uuid,
) -> Result<Uuid, AppError> {
    let db = &state.base.db;
    let row: Option<ScenarioFieldsRow> = sqlx::query_as(
        "SELECT name, description FROM dashboard_scenario \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(scenario_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let fields = row.ok_or(AppError::NotFound)?;

    let (new_id, _) = create_record_for(
        state,
        ctx,
        cloned_by,
        "dashboard_scenario",
        serde_json::json!({
            "name": format!("{} (Copy)", fields.name),
            "description": fields.description,
            "base_kind": "scenario_ref",
            "base_scenario_ref": scenario_id.to_string(),
            "status": "draft",
            "owner_ref": cloned_by.to_string(),
        }),
    )
    .await?;

    let assumptions: Vec<(String, String, String, Option<f64>)> = sqlx::query_as(
        "SELECT key, kind, expression_or_value, display_order::double precision \
         FROM dashboard_scenario_assumption \
         WHERE scenario_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(scenario_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (key, kind, expression_or_value, display_order) in assumptions {
        create_record_for(
            state,
            ctx,
            cloned_by,
            "dashboard_scenario_assumption",
            serde_json::json!({
                "scenario_ref": new_id.to_string(),
                "key": key,
                "kind": kind,
                "expression_or_value": expression_or_value,
                "display_order": display_order,
            }),
        )
        .await?;
    }

    let metrics: Vec<(Uuid, Option<f64>)> = sqlx::query_as(
        "SELECT metric_ref, display_order::double precision FROM dashboard_scenario_metric \
         WHERE scenario_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(scenario_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (metric_ref, display_order) in metrics {
        create_record_for(
            state,
            ctx,
            cloned_by,
            "dashboard_scenario_metric",
            serde_json::json!({
                "scenario_ref": new_id.to_string(),
                "metric_ref": metric_ref.to_string(),
                "display_order": display_order,
            }),
        )
        .await?;
    }

    Ok(new_id)
}

#[derive(Serialize, utoipa::ToSchema)]
struct CloneResponse {
    id: Uuid,
}

/// `POST /api/v1/scenarios/{id}/clone` — branch a new scenario off this one
/// (plan §3.1's "branching" + "versioning ... + a clone operation";
/// `attome-api` has no generic clone primitive to reuse — confirmed by
/// inspection — so this follows the one established bespoke-clone pattern in
/// this crate, `lifecycle.rs::do_clone`/`clone_dashboard`).
#[utoipa::path(
    post,
    path = "/api/v1/scenarios/{id}/clone",
    operation_id = "clone_scenario",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    responses(
        (status = 201, description = "Success", body = CloneResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such scenario", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
async fn clone_scenario(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScenarioUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<CloneResponse>), AppError> {
    // Same two-privilege shape `lifecycle.rs::clone_dashboard` documents:
    // the route's compile-time policy covers `dashboard_scenario.update` on the
    // source; creating the copy needs `dashboard_scenario.create` too, checked by
    // hand since `Authorized<P>` only composes one policy.
    ctx.require_key("dashboard_scenario.create")?;
    require_entity_access(&state, &ctx, "dashboard_scenario", id, RecordAction::Update).await?;
    let new_id = do_clone(&state, &ctx, id, ctx.user_id).await?;
    attome_audit::write_business_event(
        &state,
        "dashboard_scenario",
        new_id,
        attome_audit::AuditOperation::Create,
        "scenario.clone",
        ctx.user_id,
        None,
        None,
        format!("cloned from scenario {id}"),
    )
    .await;
    Ok((StatusCode::CREATED, Json(CloneResponse { id: new_id })))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/scenarios/{id}/evaluate", post(evaluate))
        .route("/api/v1/scenarios/{id}/compare", get(compare))
        .route("/api/v1/scenarios/{id}/clone", post(clone_scenario))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(evaluate, compare, clone_scenario))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_status_string_is_pinned() {
        // `evaluate_one_metric`'s not_computable/pending branches don't key
        // off `SnapshotStatus::Failed` directly, but `attome_metric::metric`'s
        // own query-backed branch does (a failed snapshot is excluded from
        // "successful" before this module ever sees it) — pin the string so
        // a future edit to `SnapshotStatus` can't silently change it.
        // Formula-backed metrics are exercised against a live database in
        // `crates/engine/attome-metric/tests/metric.rs`.
        assert_eq!(
            SnapshotStatus::Failed.as_str(),
            "failed",
            "evaluate_one_metric's pending-vs-baseline_only branch keys off this exact string"
        );
    }
}
