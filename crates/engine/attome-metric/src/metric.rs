//! M27 Phase 1 — KPI & Metrics (`document/module-master-plans/
//! M27-kpi-metrics.md`): query-backed and manual metric definitions,
//! targets, and append-only snapshots. Phase 2's `formula` source (via
//! `attome-rules`/M45) is implemented — see [`evaluate_formula_metric`] below.
//! Expression thresholds and `metric.threshold_crossed` alerts, and Phase 3
//! (dimensions, benchmarking) remain out of scope — see that plan's
//! checklist.
//!
//! Split out of `attome-dashboard` into this crate by D-480 (M26 R-14) — see
//! that decision for why M27 is the dependency root that earned its own
//! crate while M28 (Decision Intelligence) and M48 (Scenario & Simulation)
//! stay in `attome-dashboard`.
//!
//! **`formula` metrics (REVIEW-2026-09-02 finding — the M27 formula gap).**
//! A formula expression is ordinary `attome-rules` syntax whose field refs are
//! other metrics' `key`s (bare refs only — no `.` hop; a metric has no
//! "related" record to hop to). `evaluate_formula_metric` parses the
//! expression once just to collect which keys it references (via the
//! crate's `parse()` entry point, before any `Schema` can be built), resolves
//! each referenced metric's latest snapshot for the *same* `period_start`
//! (so `q3_margin = revenue - cost` always compares like periods), builds a
//! `Context`/`Schema` from exactly those keys, then compiles and evaluates.
//! An `overrides` map (`HashMap<String, f64>` keyed by metric `key`) lets a
//! caller substitute one or more referenced values before evaluating without
//! this crate or `attome-rules` needing a dedicated "scenario" concept —
//! `Context::with_field` already lets a caller build whatever `Context` it
//! wants (M45's own module doc: "rules are pure... the caller resolves
//! everything"), so `attome_dashboard::scenario` (M48) can call this directly
//! with its assumption map as `overrides` and get a what-if answer with zero
//! changes to `attome-rules` itself.
//!
//! **Entities.** `dashboard_metric_definition` and `dashboard_metric_target` are
//! built-in metadata (D-366) declared in `platform-bundles/attome-metric.json`
//! and applied at boot by `attome-api/src/system.rs` via `bundle::
//! apply_platform_bundle` (D-478 seeds-to-bundles, second pass — the old
//! `metric_seed.rs` only ever used its `systemuser_id` parameter as
//! `owner_ref`'s lookup target, i.e. `lookup_entity` by logicalname). This
//! crate sits below `attome-api`, so its own tests use [`seed_for_tests`].
//! `attome-api/tests/entity_module_gate.rs`'s static scan reads bundles too.
//!
//! **`metric_snapshot` is NOT a provisioned entity.** It is an
//! infrastructure table (`crates/server/migrations/0160_metric_snapshot.sql`),
//! partitioned by month on `computed_at`, high-volume and append-only — same
//! shape as the audit ledger (`migrations/0026_audit_partitioning.sql`). It
//! carries no `entity_info` row, so it gets no generic CRUD; every
//! access goes through this module's own routes, the same "infra table,
//! bespoke routes" posture `audit_header` and `notification_recipient`
//! already use.
//!
//! **Why a snapshot, never a live query result (D-407).** Plan §5: "what was
//! churn in March cannot change when data is corrected in April without a
//! visible restatement." A snapshot row, once written, is never UPDATEd — a
//! recompute is a new INSERT whose `superseded_ref` points at the row it
//! replaces. "Current" for a `(metric, period)` pair is simply the most
//! recently computed row (`ORDER BY computed_at DESC, id DESC`);
//! `superseded_ref` is lineage for a restatement's audit trail, not the
//! lookup mechanism.
//!
//! **Query-backed metrics run through `query_exec` under the metric service
//! principal (D-786, implementing D-522's Class B).** A snapshot reads the
//! query's *current published version* (`sql_query_version`, "current
//! = MAX(id) for this query_id") and executes exactly that version, pinned,
//! through `attome_records::query_exec::execute_stored_query` — the same
//! function `POST /api/v1/query/execute` and scheduled reports (D-440) use —
//! under the `SecurityContext` of the metric service principal
//! ([`crate::principal`]), resolved fresh from PostgreSQL. The per-query
//! privilege gate, relation reads, record-level scope, the SELECT-only
//! readonly pool, the statement timeout (`is_report` → 5s, else 500ms) and the
//! plan-cost ceiling are therefore that one implementation, not a second copy
//! here. The scope is the principal's, never the viewer's or the caller's
//! (plan §5: "metric values are visible to anyone who may read the
//! definition; the underlying query privileges apply at compute time under
//! the service principal" — the one documented place a stored number may
//! summarize rows the viewer cannot list). The first result row must carry a
//! column named `value` (case-insensitive): a documented contract for a KPI
//! aggregate query, deliberately narrower than the general multi-column
//! report shape `query/execute` supports. Formula and manual metrics run no
//! SQL of their own and are unchanged.
use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use attome_records::query_exec::{ExecuteQueryRequest, execute_stored_query};
use attome_server::authz::{Authorized, Privilege};

use crate::auth::{MetricRead, MetricUpdate};

/// Test-fixture equivalent of applying `platform-bundles/attome-metric.json`
/// against a bare `DbPool` — `user_account` (the `owner_ref` lookup
/// target) must already be live, i.e. call `attome_security::seed::
/// seed_for_tests` first. `seed_bundle_for_tests` walks entities and queries
/// only, so the bundle's `roles` (D-786's metric service role) are reconciled
/// here through `attome_security::reconcile::reconcile_role`, the function the
/// real platform-bundle apply calls for a role step.
pub async fn seed_for_tests(db: &attome_db::DbPool) -> Result<(), attome_types::AppError> {
    let bundle_json = include_str!("../../../../platform-bundles/attome-metric.json");
    attome_metadata::provision::seed_bundle_for_tests(db, "attome-metric", bundle_json).await?;

    let bundle: serde_json::Value = serde_json::from_str(bundle_json)
        .map_err(|e| AppError::internal(format!("platform-bundles/attome-metric.json: {e}")))?;
    for role in bundle["roles"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let desc = attome_security::reconcile::RoleDesc {
            name: role["name"].as_str().unwrap_or_default().to_owned(),
            description: role["description"].as_str().map(str::to_owned),
            access_level: role["access_level"]
                .as_i64()
                .and_then(|v| i16::try_from(v).ok())
                .unwrap_or(3),
            position_hierarchy_enabled: false,
            privileges: role["privileges"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .filter_map(|g| g["privilege"].as_str())
                .map(|key| attome_security::reconcile::RoleGrantDesc {
                    privilege: key.to_owned(),
                    conditions: Vec::new(),
                })
                .collect(),
            entity_access: Vec::new(),
            field_security_profiles: Vec::new(),
        };
        attome_security::reconcile::reconcile_role(
            db,
            &desc,
            attome_security::reconcile::ReconcilePolicy::Seed,
            None,
        )
        .await?;
    }
    Ok(())
}

// ── Snapshot status ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotStatus {
    Ok,
    Warn,
    Crit,
    /// Not in the plan's `ok|warn|crit` list — added deliberately (plan §8):
    /// "a metric query that becomes slow: compute under `statement_timeout`,
    /// mark snapshot `failed`... never block the scheduler." A failed
    /// snapshot is still a real, visible row (never silently dropped), and
    /// the scheduler retries it on the next sweep (see
    /// `run_scheduled_snapshot_sweep`'s idempotency check, which treats
    /// `failed` as "not yet successfully computed for this period").
    Failed,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Crit => "crit",
            Self::Failed => "failed",
        }
    }
}

struct TargetRow {
    target_value: f64,
    threshold_warn: Option<f64>,
    threshold_crit: Option<f64>,
}

/// Pure — unit-tested directly. No target for this period means nothing to
/// compare against, so the snapshot is recorded `ok` (a value with no
/// judgment attached, not a fabricated warning).
fn evaluate_status(actual: f64, direction: &str, target: Option<&TargetRow>) -> SnapshotStatus {
    let Some(t) = target else {
        return SnapshotStatus::Ok;
    };
    match direction {
        "lower" => {
            if let Some(crit) = t.threshold_crit
                && actual >= crit
            {
                return SnapshotStatus::Crit;
            }
            if let Some(warn) = t.threshold_warn
                && actual >= warn
            {
                return SnapshotStatus::Warn;
            }
            SnapshotStatus::Ok
        }
        "target_band" => {
            let deviation = (actual - t.target_value).abs();
            if let Some(crit) = t.threshold_crit
                && deviation >= crit
            {
                return SnapshotStatus::Crit;
            }
            if let Some(warn) = t.threshold_warn
                && deviation >= warn
            {
                return SnapshotStatus::Warn;
            }
            SnapshotStatus::Ok
        }
        // "higher_is_better" and any other/unrecognized value — the seeded
        // choice list only allows the three above, so this arm is really
        // just "higher_is_better", named generically for defense in depth.
        _ => {
            if let Some(crit) = t.threshold_crit
                && actual <= crit
            {
                return SnapshotStatus::Crit;
            }
            if let Some(warn) = t.threshold_warn
                && actual <= warn
            {
                return SnapshotStatus::Warn;
            }
            SnapshotStatus::Ok
        }
    }
}

/// Which calendar a metric's periods follow (roadmap P9-T4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CalendarKind {
    #[default]
    Gregorian,
    /// Umm al-Qura months and years.
    Hijri,
}

/// How periods are cut: the calendar, the first day of a week and the
/// month a fiscal year starts in (1 is a calendar year).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodCalendar {
    pub kind: CalendarKind,
    pub week_start: chrono::Weekday,
    pub fiscal_start_month: u32,
}

impl Default for PeriodCalendar {
    fn default() -> Self {
        Self {
            kind: CalendarKind::Gregorian,
            week_start: chrono::Weekday::Mon,
            fiscal_start_month: 1,
        }
    }
}

impl PeriodCalendar {
    /// Reads a week start code: `sat`, `sun` or `mon`.
    pub fn week_start_from(code: &str) -> Result<chrono::Weekday, AppError> {
        match code.trim().to_ascii_lowercase().as_str() {
            "sat" | "saturday" => Ok(chrono::Weekday::Sat),
            "sun" | "sunday" => Ok(chrono::Weekday::Sun),
            "mon" | "monday" => Ok(chrono::Weekday::Mon),
            other => Err(AppError::Validation(format!(
                "unknown week start: {other} (use sat, sun or mon)"
            ))),
        }
    }
}

fn ymd(year: i32, month: u32, day: u32) -> Result<NaiveDate, AppError> {
    NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| AppError::Validation(format!("{year}-{month}-{day} is not a date")))
}

fn add_months(date: NaiveDate, months: u32) -> Result<NaiveDate, AppError> {
    date.checked_add_months(chrono::Months::new(months))
        .ok_or_else(|| AppError::Validation("the period ends outside the supported range".into()))
}

/// The period containing `now`: its first day and the day after its last
/// (roadmap P9-T4). Every boundary is UTC calendar time (no per-deployment
/// time zone exists yet, as `attome_dashboard::context` documents).
///
/// - `week` starts on `calendar.week_start` (Saturday, Sunday or Monday).
/// - `quarter` and `year` follow the fiscal year starting in
///   `calendar.fiscal_start_month`: with April, Q1 is April to June and the
///   year runs April to March.
/// - On the Hijri calendar, `month` and `year` are Umm al-Qura months and
///   years; `day`, `week` and `quarter` have no Hijri meaning and are a
///   validation error.
pub fn period_bounds(
    period: &str,
    calendar: PeriodCalendar,
    now: DateTime<Utc>,
) -> Result<(NaiveDate, NaiveDate), AppError> {
    let today = now.date_naive();
    if calendar.kind == CalendarKind::Hijri {
        let table = attome_calendar::hijri::HijriCalendar::umm_al_qura();
        let hijri = table
            .to_hijri(today)
            .map_err(|e| AppError::Validation(format!("no Hijri date for {today}: {e}")))?;
        let bounds = match period {
            "month" => table.month_bounds(hijri.year, hijri.month),
            "year" => table.year_bounds(hijri.year),
            "day" | "week" | "quarter" => {
                return Err(AppError::Validation(format!(
                    "a Hijri metric period is month or year, not {period}"
                )));
            }
            other => {
                return Err(AppError::Validation(format!(
                    "unknown metric period: {other}"
                )));
            }
        };
        return bounds.map_err(|e| AppError::Validation(format!("Hijri period: {e}")));
    }
    let fiscal = calendar.fiscal_start_month;
    if !(1..=12).contains(&fiscal) {
        return Err(AppError::Validation(format!(
            "the fiscal year start month must be 1 to 12, not {fiscal}"
        )));
    }
    // Months since the fiscal year started, 0 to 11.
    let into_year = (today.month() + 12 - fiscal) % 12;
    let year_start = |months_back: u32| -> Result<NaiveDate, AppError> {
        let first = ymd(today.year(), today.month(), 1)?;
        first
            .checked_sub_months(chrono::Months::new(months_back))
            .ok_or_else(|| {
                AppError::Validation("the period starts outside the supported range".into())
            })
    };
    let bounds = match period {
        "day" => (today, today + chrono::Duration::days(1)),
        "week" => {
            let back = (today.weekday().num_days_from_monday() + 7
                - calendar.week_start.num_days_from_monday())
                % 7;
            let start = today - chrono::Duration::days(i64::from(back));
            (start, start + chrono::Duration::days(7))
        }
        "month" => {
            let start = ymd(today.year(), today.month(), 1)?;
            (start, add_months(start, 1)?)
        }
        "quarter" => {
            let start = year_start(into_year % 3)?;
            (start, add_months(start, 3)?)
        }
        "year" => {
            let start = year_start(into_year)?;
            (start, add_months(start, 12)?)
        }
        other => {
            // R-13 item 4: `period` is client-authored metadata (the
            // metric's own `period` field), not an internal invariant — an
            // unrecognized value is the caller's data mistake to see and
            // fix, not an operator page.
            return Err(AppError::Validation(format!(
                "unknown metric period: {other}"
            )));
        }
    };
    Ok(bounds)
}

/// The first day of the period containing `now` on the default calendar:
/// Gregorian, weeks from Monday (ISO 8601), calendar quarters and years.
// `pub` (D-480) — `attome_dashboard::scenario::evaluate` reuses this to resolve
// "the current period" for a query/manual metric the same way this module's
// own scheduled sweep does.
pub fn period_start_for(period: &str, now: DateTime<Utc>) -> Result<NaiveDate, AppError> {
    period_bounds(period, PeriodCalendar::default(), now).map(|(start, _)| start)
}

// ── Data access ──────────────────────────────────────────────────────────

// `pub` (struct, fields, and `fetch_metric` below; D-480) —
// `attome_dashboard::scenario` reuses this shape rather than duplicating the
// SQL, same reuse-across-the-dependency-edge posture the rest of this
// module's `pub` items document.
#[derive(sqlx::FromRow)]
pub struct MetricDefinitionRow {
    pub id: Uuid,
    pub source_kind: String,
    pub query_ref: Option<String>,
    pub formula: Option<String>,
    pub direction: String,
    pub period: String,
}

impl std::fmt::Debug for MetricDefinitionRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricDefinitionRow")
            .finish_non_exhaustive()
    }
}

// Single source of truth for `MetricDefinitionRow`'s column list — every
// query that hydrates it (here and in `run_scheduled_snapshot_sweep`) must
// select exactly these columns in this order. `#[sqlx::FromRow]` only
// defaults a missing column when the field carries `#[sqlx(default)]`; this
// struct doesn't, so a query that omits a column here fails closed with
// `ColumnNotFound` rather than silently defaulting — keep the two in sync by
// construction instead.
pub const METRIC_DEFINITION_COLUMNS: &str =
    "id, source_kind, query_ref, formula, direction, period";

pub async fn fetch_metric(db: &DbPool, metric_id: Uuid) -> Result<MetricDefinitionRow, AppError> {
    sqlx::query_as::<_, MetricDefinitionRow>(&format!(
        "SELECT {METRIC_DEFINITION_COLUMNS} FROM dashboard_metric_definition \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn fetch_target(
    db: &DbPool,
    metric_id: Uuid,
    period_start: NaiveDate,
) -> Result<Option<TargetRow>, AppError> {
    let row: Option<(f64, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT target_value::double precision, threshold_warn::double precision, \
                threshold_crit::double precision \
         FROM dashboard_metric_target \
         WHERE metric_ref = $1 AND period_start = $2 AND (is_active IS NULL OR is_active = true) \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(metric_id)
    .bind(period_start)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(
        row.map(|(target_value, threshold_warn, threshold_crit)| TargetRow {
            target_value,
            threshold_warn,
            threshold_crit,
        }),
    )
}

#[derive(Debug, sqlx::FromRow, Serialize, ToSchema)]
pub struct SnapshotRow {
    pub id: Uuid,
    pub metric_ref: Uuid,
    pub period_start: NaiveDate,
    pub actual: Option<f64>,
    pub computed_at: DateTime<Utc>,
    pub source_version: Option<String>,
    pub status: String,
    pub superseded_ref: Option<Uuid>,
    pub evaluated_by: Option<Uuid>,
    pub error_message: Option<String>,
}

const SNAPSHOT_COLUMNS: &str = "id, metric_ref, period_start, actual, computed_at, \
     source_version, status, superseded_ref, evaluated_by, error_message";

// `pub` (D-480) — `attome_dashboard::scenario::evaluate` reads the same
// "current = most recent snapshot" value this module's own routes read,
// rather than duplicating the query.
pub async fn latest_snapshot(
    db: &DbPool,
    metric_id: Uuid,
    period_start: NaiveDate,
) -> Result<Option<SnapshotRow>, AppError> {
    sqlx::query_as::<_, SnapshotRow>(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM metric_snapshot \
         WHERE metric_ref = $1 AND period_start = $2 \
         ORDER BY computed_at DESC, id DESC LIMIT 1"
    ))
    .bind(metric_id)
    .bind(period_start)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// The only writer of `metric_snapshot` — a pure INSERT, never an
/// UPDATE (D-407). Advisory-locked per `(metric, period)` (guidelines §2) so
/// two concurrent computes (a scheduler tick racing an on-demand `/compute`
/// call) can't both read the same "previous" row and both link
/// `superseded_ref` to it, which would silently fork the history instead of
/// forming a single chain.
#[allow(clippy::too_many_arguments)]
async fn insert_snapshot(
    db: &DbPool,
    metric_id: Uuid,
    period_start: NaiveDate,
    actual: Option<f64>,
    source_version: Option<&str>,
    status: SnapshotStatus,
    evaluated_by: Option<Uuid>,
    error_message: Option<&str>,
) -> Result<SnapshotRow, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-metric/metric-snapshot:{metric_id}:{period_start}"
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a snapshot for this metric and period is already being computed",
        ));
    }

    let previous_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM metric_snapshot WHERE metric_ref = $1 AND period_start = $2 \
         ORDER BY computed_at DESC, id DESC LIMIT 1",
    )
    .bind(metric_id)
    .bind(period_start)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let id = Uuid::now_v7();
    let row: SnapshotRow = sqlx::query_as(&format!(
        "INSERT INTO metric_snapshot \
         (id, metric_ref, period_start, actual, source_version, status, superseded_ref, \
          evaluated_by, error_message) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {SNAPSHOT_COLUMNS}"
    ))
    .bind(id)
    .bind(metric_id)
    .bind(period_start)
    .bind(actual)
    .bind(source_version)
    .bind(status.as_str())
    .bind(previous_id)
    .bind(evaluated_by)
    .bind(error_message)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(row)
}

/// Masked, operator-actionable text persisted as a snapshot's
/// `error_message` when `query_exec` refuses the principal (D-786).
const PRINCIPAL_FORBIDDEN_MESSAGE: &str = "the metric service principal may not run this query: \
     set its required_privilege to `attome_metric.snapshot` (or grant its key) and grant read on \
     each entity it reads to the 'Metric Service' role";

/// Runs a query-backed metric (D-786): resolves the query's current published
/// version, then executes exactly that version, pinned, through
/// `query_exec::execute_stored_query` under the metric service principal's
/// freshly resolved `SecurityContext` (see this module's doc comment). Returns
/// the numeric `value` column of the first row and the version id (recorded as
/// `source_version`, D-407's reproducibility requirement — pinning makes it the
/// exact SQL that produced the number).
///
/// Every error this returns is safe to persist: `Validation` carries
/// client-authored-metadata mistakes, and `Internal` carries only a curated,
/// masked message — a raw driver error from `query_exec` is logged here with
/// the query id and replaced (guidelines §6).
async fn run_query_metric(
    state: &EngineState,
    query_ref: &str,
    trigger: crate::principal::Trigger,
) -> Result<(f64, String), AppError> {
    let db = &state.base.db;
    let query_id: Uuid = query_ref
        .parse()
        .map_err(|_| AppError::Validation("metric query_ref is not a valid UUID".into()))?;

    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM sql_query WHERE id = $1")
            .bind(query_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if is_active != Some(true) {
        return Err(AppError::Validation(
            "metric query_ref does not reference an active stored query".into(),
        ));
    }

    let version_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sql_query_version \
         WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(query_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let version_id = version_id.ok_or_else(|| {
        AppError::Validation("metric's stored query has no published version yet".into())
    })?;

    // Fail closed: no principal, no query (D-786).
    let principal = match crate::principal::resolve(state, trigger).await {
        Ok(ctx) => ctx,
        Err(e) => {
            if let crate::principal::PrincipalError::Internal(detail) = &e {
                tracing::warn!(query_id = %query_id, error = ?detail, "metric service principal resolution failed");
            } else {
                tracing::warn!(query_id = %query_id, reason = %e, "metric service principal unavailable");
            }
            return Err(AppError::Internal(e.to_string()));
        }
    };

    // One row, one page, no cursor: `include_total` selects query_exec's
    // OFFSET branch, which needs no `id` column (an aggregate has none) and
    // adds no ORDER BY — the same "first row of the result" the pre-D-786
    // `LIMIT 1` wrapper read.
    let request: ExecuteQueryRequest = serde_json::from_value(serde_json::json!({
        "query_id": query_id,
        "query_version_id": version_id,
        "page": 1,
        "page_size": 1,
        "include_total": true,
    }))
    .map_err(AppError::internal)?;

    let response = match execute_stored_query(state, &principal, request).await {
        Ok(r) => r,
        Err(AppError::Forbidden) => {
            tracing::warn!(query_id = %query_id, principal = %principal.user_id, "metric query refused for the metric service principal");
            return Err(AppError::Internal(PRINCIPAL_FORBIDDEN_MESSAGE.to_string()));
        }
        Err(AppError::NotFound) => {
            return Err(AppError::Validation(
                "metric query_ref does not reference an active stored query".into(),
            ));
        }
        // query_exec's own 422s (plan-cost ceiling, a malformed version) are
        // written for API clients and carry no driver detail.
        Err(AppError::Validation(message)) => return Err(AppError::Validation(message)),
        Err(e) => {
            // A timeout, a readonly-role permission denial, a syntax error:
            // `query_exec`'s masked `Internal` detail still quotes the
            // driver, so it is logged here and never persisted.
            tracing::warn!(query_id = %query_id, error = ?e, "metric query failed");
            return Err(AppError::internal(
                "metric query failed or exceeded its timeout; see server logs",
            ));
        }
    };

    // `ExecResponse`'s fields are private to `query_exec`; read the wire shape,
    // exactly as `attome-report/src/run.rs` does.
    let response = serde_json::to_value(&response).map_err(AppError::internal)?;
    let obj = response
        .pointer("/data/records/0")
        .and_then(|v| v.as_object().cloned())
        .ok_or_else(|| AppError::Validation("metric query returned no rows".into()))?;
    let value = obj
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("value"))
        .and_then(|(_, v)| v.as_f64())
        .ok_or_else(|| {
            AppError::Validation(
                "metric query result must contain a numeric column named `value`".into(),
            )
        })?;
    Ok((value, version_id.to_string()))
}

/// See this module's doc comment. `overrides` (metric `key` -> value)
/// substitutes a referenced metric's resolved value before evaluating —
/// `attome_dashboard::scenario`'s what-if seam; pass `None` for a normal
/// (non-scenario) compute.
///
/// Errors are all `AppError::Validation` (never `internal`) except a genuine
/// DB failure — an unknown/self/undefined-yet reference is a metric-authoring
/// mistake the caller should see and fix, not an operator page.
pub async fn evaluate_formula_metric(
    db: &DbPool,
    formula: &str,
    period_start: NaiveDate,
    overrides: Option<&std::collections::HashMap<String, f64>>,
) -> Result<f64, AppError> {
    let expr = attome_rules::parse(formula)
        .map_err(|e| AppError::Validation(format!("invalid formula: {e}")))?;
    let mut keys = Vec::new();
    collect_field_refs(&expr, &mut keys)?;
    keys.sort();
    keys.dedup();

    let mut schema = attome_rules::Schema::new();
    let mut ctx = attome_rules::Context::new(Utc::now());
    for key in &keys {
        let value = match overrides.and_then(|o| o.get(key)) {
            Some(&v) => v,
            None => {
                let metric_id: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM dashboard_metric_definition \
                     WHERE key = $1 AND (is_active IS NULL OR is_active = true)",
                )
                .bind(key)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?;
                let metric_id = metric_id.ok_or_else(|| {
                    AppError::Validation(format!("formula references unknown metric key: {key}"))
                })?;
                let snapshot = latest_snapshot(db, metric_id, period_start).await?;
                snapshot.and_then(|s| s.actual).ok_or_else(|| {
                    AppError::Validation(format!(
                        "formula references metric '{key}', which has no snapshot for \
                         period {period_start} yet"
                    ))
                })?
            }
        };
        schema = schema.with_field(key.clone(), attome_rules::Type::Number);
        ctx = ctx.with_field(key.clone(), attome_rules::Value::Number(value));
    }

    let compiled = attome_rules::compile(formula, &schema)
        .map_err(|e| AppError::Validation(format!("invalid formula: {e}")))?;
    match compiled
        .eval(&ctx)
        .map_err(|e| AppError::Validation(format!("formula evaluation failed: {e}")))?
    {
        attome_rules::Value::Number(n) => Ok(n),
        other => Err(AppError::Validation(format!(
            "formula must evaluate to a number, not {:?}",
            other.ty()
        ))),
    }
}

/// Walks a parsed formula collecting every bare field ref's name (each one a
/// referenced metric's `key`) — used before a `Schema` exists yet, per
/// `attome_rules::parse`'s own documented purpose. Rejects a `lookup_field.
/// target_field` hop outright: a metric has no related record to hop to, so
/// a hop here is always an authoring mistake, not a valid reference.
/// The metric keys a formula references, sorted and de-duplicated — the
/// dependency list `evaluate_formula_metric` resolves, exposed for lineage
/// (dashboard 10/10 Phase 3.3).
pub fn formula_metric_keys(formula: &str) -> Result<Vec<String>, AppError> {
    let expr = attome_rules::parse(formula)
        .map_err(|e| AppError::Validation(format!("invalid formula: {e}")))?;
    let mut keys = Vec::new();
    collect_field_refs(&expr, &mut keys)?;
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn collect_field_refs(expr: &attome_rules::Expr, out: &mut Vec<String>) -> Result<(), AppError> {
    use attome_rules::Expr;
    match expr {
        Expr::FieldRef(field_ref) => {
            if field_ref.hop.is_some() {
                return Err(AppError::Validation(format!(
                    "formula metric references may not use a lookup hop ('{field_ref}') — \
                     only a bare metric key"
                )));
            }
            out.push(field_ref.base.clone());
        }
        Expr::ListLit(items) => {
            for item in items {
                collect_field_refs(item, out)?;
            }
        }
        Expr::Unary { expr, .. } => collect_field_refs(expr, out)?,
        Expr::Binary { lhs, rhs, .. } => {
            collect_field_refs(lhs, out)?;
            collect_field_refs(rhs, out)?;
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_field_refs(arg, out)?;
            }
        }
        // Z11-T7: nor paths.
        Expr::Path(segments) => {
            return Err(AppError::Validation(format!(
                "formula metric references may not use a lookup path ('{}')",
                segments.join(".")
            )));
        }
        // Z11-T3: a formula metric combines metric keys; it has no lists.
        Expr::Lambda { .. } => {
            return Err(AppError::Validation(
                "formula metrics take no lambda (`x => ...`)".into(),
            ));
        }
        Expr::NullLit | Expr::BoolLit(_) | Expr::NumberLit(_) | Expr::StringLit(_) => {}
    }
    Ok(())
}

pub struct ComputeOutcome {
    pub snapshot: SnapshotRow,
    /// `true` when an existing, non-failed snapshot for this `(metric,
    /// period)` was returned as-is (idempotent skip) rather than a new row
    /// being written.
    pub skipped: bool,
}

impl std::fmt::Debug for ComputeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeOutcome").finish_non_exhaustive()
    }
}

/// The one function both the scheduled sweep and the on-demand `/compute`
/// route call. Idempotent per `(metric, period)` unless `force` is set —
/// `force` is D-407's restatement path: it always writes a new row, chained
/// via `superseded_ref` to whatever was there before (which is never
/// modified). `state.base.db` does the snapshot INSERT and every metadata
/// read; a `source_kind = "query"` metric's SQL runs through `query_exec` under
/// the metric service principal ([`run_query_metric`], D-786) — never under
/// the caller's context and never on the full-privilege pool.
///
/// `evaluated_by` is who triggered this compute: the on-demand route passes
/// the caller, the scheduled sweep passes
/// [`crate::principal::METRIC_PRINCIPAL_ID`]. It never widens or narrows the
/// query's scope, which is always the principal's.
///
/// `period_start` is `Option` (R-12): `None` resolves to the metric's own
/// current period (`period_start_for(&metric.period, Utc::now())`) using the
/// single `fetch_metric` call already made here — the on-demand `/compute`
/// route used to make that same resolution itself with a second, redundant
/// `fetch_metric` before ever calling this function.
pub async fn compute_and_record(
    state: &EngineState,
    metric_id: Uuid,
    period_start: Option<NaiveDate>,
    manual_actual: Option<f64>,
    force: bool,
    evaluated_by: Option<Uuid>,
) -> Result<ComputeOutcome, AppError> {
    let db = &state.base.db;
    let metric = fetch_metric(db, metric_id).await?;
    let period_start = match period_start {
        Some(p) => p,
        None => period_start_for(&metric.period, Utc::now())?,
    };

    if !force
        && let Some(existing) = latest_snapshot(db, metric_id, period_start).await?
        && existing.status != SnapshotStatus::Failed.as_str()
    {
        return Ok(ComputeOutcome {
            snapshot: existing,
            skipped: true,
        });
    }

    let (actual, source_version, status, error_message): (
        Option<f64>,
        Option<String>,
        SnapshotStatus,
        Option<String>,
    ) = match metric.source_kind.as_str() {
        "manual" => {
            let Some(actual) = manual_actual else {
                return Err(AppError::Validation(
                    "this metric is source_kind=manual — POST an `actual` value to record it"
                        .into(),
                ));
            };
            let target = fetch_target(db, metric_id, period_start).await?;
            let status = evaluate_status(actual, &metric.direction, target.as_ref());
            (Some(actual), Some("manual".to_string()), status, None)
        }
        "query" => {
            let Some(query_ref) = metric.query_ref.clone() else {
                return Err(AppError::Validation(
                    "this metric is source_kind=query but has no query_ref set".into(),
                ));
            };
            let trigger = crate::principal::Trigger::from_evaluated_by(evaluated_by);
            match run_query_metric(state, &query_ref, trigger).await {
                Ok((actual, version)) => {
                    let target = fetch_target(db, metric_id, period_start).await?;
                    let status = evaluate_status(actual, &metric.direction, target.as_ref());
                    (Some(actual), Some(version), status, None)
                }
                Err(e) => {
                    tracing::warn!(
                        metric_id = %metric_id,
                        period_start = %period_start,
                        error = %e,
                        "metric snapshot: query-backed compute failed"
                    );
                    // `AppError::Internal`'s `Display` (thiserror's
                    // `#[error("internal error")]`) is a fixed string by
                    // design — it never interpolates the wrapped detail, so
                    // `e.to_string()` would always store the literal
                    // "internal error" here, discarding the specific,
                    // already-masked message `run_query_metric` crafted
                    // (guidelines §6: never expose raw DB errors, but this
                    // curated message is exactly what's meant to reach
                    // `error_message`). Match the variant to recover it;
                    // any other variant (e.g. a future non-Internal error
                    // from this path) still falls back to `Display`, which
                    // is safe for every other variant's shape.
                    let message = match &e {
                        AppError::Internal(detail) => detail.clone(),
                        other => other.to_string(),
                    };
                    (None, None, SnapshotStatus::Failed, Some(message))
                }
            }
        }
        "formula" => {
            let Some(formula) = metric.formula.clone() else {
                return Err(AppError::Validation(
                    "this metric is source_kind=formula but has no formula set".into(),
                ));
            };
            match evaluate_formula_metric(db, &formula, period_start, None).await {
                Ok(actual) => {
                    let target = fetch_target(db, metric_id, period_start).await?;
                    let status = evaluate_status(actual, &metric.direction, target.as_ref());
                    (Some(actual), Some("formula".to_string()), status, None)
                }
                Err(e) => {
                    tracing::warn!(
                        metric_id = %metric_id,
                        period_start = %period_start,
                        error = %e,
                        "metric snapshot: formula-backed compute failed"
                    );
                    (None, None, SnapshotStatus::Failed, Some(e.to_string()))
                }
            }
        }
        other => {
            // R-13 item 4: `source_kind` is client-authored metric metadata,
            // not an internal invariant — same reasoning as
            // `period_start_for`'s bad-`period` arm above.
            return Err(AppError::Validation(format!(
                "unknown metric source_kind: {other}"
            )));
        }
    };

    let row = insert_snapshot(
        db,
        metric_id,
        period_start,
        actual,
        source_version.as_deref(),
        status,
        evaluated_by,
        error_message.as_deref(),
    )
    .await?;
    // P11-T1: a worse status than the last one notifies the owner, once.
    if status != SnapshotStatus::Failed {
        crate::alerts::after_snapshot(state, metric_id).await;
    }
    Ok(ComputeOutcome {
        snapshot: row,
        skipped: false,
    })
}

/// The scheduled snapshot job's entry point (`crates/server/src/jobs.rs`
/// dispatches `EngineJob::ComputeMetricSnapshots` here). Takes the
/// `EngineState` because query metrics run through `query_exec` (D-786).
/// Every snapshot it writes records the metric service principal
/// ([`crate::principal::METRIC_PRINCIPAL_ID`], a real `user_account`
/// row since D-786; it was the nil UUID before) as `evaluated_by` — plan §5:
/// "metrics are deployment-level facts, not per-viewer — record the
/// evaluation principal." Only `source_kind = "query"` metrics are swept
/// automatically; a `manual` metric has no value to derive on a timer, so it
/// is only ever written via an explicit `/compute` call. Failure isolation
/// (guidelines §10/plan §8): one metric's failure (a timeout, a bad query, a
/// missing grant, a disabled principal) is recorded as that metric's `failed`
/// snapshot and never stops the rest of the sweep.
pub async fn run_scheduled_snapshot_sweep(state: &EngineState) -> Result<u32, AppError> {
    let db = &state.base.db;
    let metrics: Vec<MetricDefinitionRow> = sqlx::query_as(&format!(
        "SELECT {METRIC_DEFINITION_COLUMNS} FROM dashboard_metric_definition \
         WHERE source_kind = 'query' AND (is_active IS NULL OR is_active = true)"
    ))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let now = Utc::now();
    let mut computed = 0u32;
    for metric in metrics {
        let period_start = match period_start_for(&metric.period, now) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(metric_id = %metric.id, error = %e, "metric snapshot sweep: bad period, skipping");
                continue;
            }
        };
        match compute_and_record(
            state,
            metric.id,
            Some(period_start),
            None,
            false,
            Some(crate::principal::METRIC_PRINCIPAL_ID),
        )
        .await
        {
            Ok(outcome) if !outcome.skipped => computed += 1,
            Ok(_) => {}
            // Another compute (a concurrent sweep tick, or an admin's
            // on-demand call) is already handling this exact metric/period —
            // not a failure, nothing to retry within this tick.
            Err(AppError::Conflict(_)) => {}
            Err(e) => {
                tracing::warn!(
                    metric_id = %metric.id,
                    error = %e,
                    "metric snapshot sweep: compute failed for one metric — continuing with the rest"
                );
            }
        }
    }
    Ok(computed)
}

// ── Lineage (plan §4: "Metric lineage — expose query→entity mapping on the
// definition") ──────────────────────────────────────────────────────────

/// R-12: one batched call per `list_metrics` page instead of one lookup per
/// row. Reuses `sql_query_entity_mapping` (D-146, keyed off each
/// query's *current* published version) for the multi-entity containment
/// case, and falls back to `sql_query.entity_logical_name` (set for
/// the simple single-entity case) for whichever `query_id`s the mapping
/// query didn't cover. Best-effort, same as the per-row version it replaces:
/// a lookup failure degrades to an empty lineage list for the affected
/// `query_id`s rather than failing the whole metric listing.
async fn lineage_for_query(
    db: &DbPool,
    query_refs: &[Option<String>],
) -> std::collections::HashMap<Uuid, Vec<String>> {
    let query_ids: Vec<Uuid> = query_refs
        .iter()
        .filter_map(|r| r.as_deref())
        .filter_map(|r| r.parse::<Uuid>().ok())
        .collect();
    if query_ids.is_empty() {
        return std::collections::HashMap::new();
    }

    let mapped: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT DISTINCT v.query_id, e.logicalname \
         FROM sql_query_entity_mapping m \
         JOIN sql_query_version v ON v.id = m.query_version_id \
         JOIN entity_info e ON e.id = m.entity_ref \
         WHERE v.query_id = ANY($1) \
           AND v.id = (SELECT MAX(id) FROM sql_query_version \
                       WHERE query_id = v.query_id)",
    )
    .bind(&query_ids)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut lineage: std::collections::HashMap<Uuid, Vec<String>> =
        std::collections::HashMap::new();
    for (query_id, name) in mapped {
        lineage.entry(query_id).or_default().push(name);
    }

    // Fallback lookup only for the `query_id`s the mapping query found
    // nothing for — mirrors the per-row version's "prefer mapping, else
    // single entity_logical_name" precedence.
    let missing: Vec<Uuid> = query_ids
        .into_iter()
        .filter(|id| !lineage.contains_key(id))
        .collect();
    if !missing.is_empty() {
        let single: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT q.id, e.logicalname FROM sql_query q \
             JOIN entity_info e ON e.id = q.entity_logical_name \
             WHERE q.id = ANY($1)",
        )
        .bind(&missing)
        .fetch_all(db)
        .await
        .unwrap_or_default();
        for (query_id, name) in single {
            lineage.entry(query_id).or_default().push(name);
        }
    }

    lineage
}

// ── HTTP surface ─────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct MetricDefinitionSummary {
    id: Uuid,
    name: String,
    key: String,
    source_kind: String,
    direction: String,
    period: String,
    unit: Option<String>,
    weight: Option<f64>,
    /// Entities this metric's query touches, when `source_kind = "query"` —
    /// empty for manual/formula metrics or a query with no declared mapping.
    lineage_entities: Vec<String>,
}

/// `GET /api/v1/metrics` — every active metric definition, enriched with
/// query lineage. `dashboard_metric_definition.read` (plan §5: metric values are
/// visible to anyone who may read the definition).
#[utoipa::path(
    get,
    path = "/api/v1/metrics",
    tag = "dashboard",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MetricDefinitionSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_metrics(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetricRead>>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<MetricDefinitionSummary>>, AppError> {
    let window = q.window();

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_metric_definition WHERE (is_active IS NULL OR is_active = true)",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<f64>,
    )> = sqlx::query_as(
        "SELECT id, name, key, source_kind, query_ref, direction, period, unit, \
                weight::double precision \
         FROM dashboard_metric_definition WHERE (is_active IS NULL OR is_active = true) \
         ORDER BY name LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // R-12: one batched lineage query for the whole page instead of one per
    // row.
    let query_refs: Vec<Option<String>> = rows.iter().map(|r| r.4.clone()).collect();
    let lineage_by_query = lineage_for_query(&state.base.db, &query_refs).await;

    let mut items = Vec::with_capacity(rows.len());
    for (id, name, key, source_kind, query_ref, direction, period, unit, weight) in rows {
        let lineage_entities = query_ref
            .as_deref()
            .and_then(|r| r.parse::<Uuid>().ok())
            .and_then(|qid| lineage_by_query.get(&qid).cloned())
            .unwrap_or_default();
        items.push(MetricDefinitionSummary {
            id,
            name,
            key,
            source_kind,
            direction,
            period,
            unit,
            weight,
            lineage_entities,
        });
    }

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// `GET /api/v1/metrics/{id}/snapshots` — the trend: every snapshot ever
/// recorded for this metric, newest period first, superseded rows included
/// (a restatement's whole history is visible, not just the current value).
#[utoipa::path(
    get,
    path = "/api/v1/metrics/{id}/snapshots",
    tag = "dashboard",
    params(
        ("id" = Uuid, Path),
        OnePageQuery,
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SnapshotRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_snapshots(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetricRead>>,
    Path(metric_id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SnapshotRow>>, AppError> {
    fetch_metric(&state.base.db, metric_id).await?;

    let window = q.window();

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metric_snapshot WHERE metric_ref = $1")
            .bind(metric_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items: Vec<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM metric_snapshot WHERE metric_ref = $1 \
         ORDER BY period_start DESC, computed_at DESC LIMIT $2 OFFSET $3"
    ))
    .bind(metric_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Deserialize, ToSchema, Default)]
struct ComputeMetricBody {
    /// Defaults to the metric's current period (today's day/week/month/
    /// quarter/year boundary, UTC).
    period_start: Option<NaiveDate>,
    /// Required when the metric is `source_kind = "manual"`; ignored for
    /// `"query"`.
    actual: Option<f64>,
    /// When `true`, always writes a new snapshot — D-407's restatement path
    /// — chained via `superseded_ref` to whatever was there before, which is
    /// left untouched.
    #[serde(default)]
    force: bool,
}

#[derive(Serialize, ToSchema)]
struct ComputeMetricResponse {
    snapshot: SnapshotRow,
    /// `true` when an existing snapshot was returned unchanged (idempotent
    /// skip) rather than a new one being computed.
    skipped: bool,
}

/// `POST /api/v1/metrics/{id}/compute` — admin on-demand trigger.
/// `dashboard_metric_definition.update`: triggering a computation is a business
/// action on the metric, same "reuse the CRUD update privilege for a
/// bespoke action" convention `attome_dashboard`'s own lifecycle transitions
/// use (`DashboardUpdate`).
#[utoipa::path(
    post,
    path = "/api/v1/metrics/{id}/compute",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = ComputeMetricBody,
    responses(
        (status = 200, description = "Success", body = ComputeMetricResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
        (status = 409, description = "A compute for this metric/period is already in flight", body = ErrorResponse),
        (status = 422, description = "Missing actual for a manual metric, formula source, or bad query_ref", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    // D-786: the first query-metric compute may provision the metric service
    // principal's role membership (Access/Grant, `principal::ensure`).
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute), (attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant)])))),
)]
async fn compute_metric(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricUpdate>>,
    Path(metric_id): Path<Uuid>,
    Json(body): Json<ComputeMetricBody>,
) -> Result<Json<ComputeMetricResponse>, AppError> {
    // R-12: no leading `fetch_metric` here anymore — `compute_and_record`
    // fetches the metric itself and resolves `period_start` from it when
    // `None`, so this handler no longer makes a second, redundant lookup of
    // the same row just to resolve the period.

    // D-786: the caller's privilege only decides whether a compute may be
    // triggered; the query itself runs under the metric service principal's
    // scope, never the caller's (D-522 Class B).
    let outcome = compute_and_record(
        &state,
        metric_id,
        body.period_start,
        body.actual,
        body.force,
        Some(ctx.user_id),
    )
    .await?;

    if !outcome.skipped {
        attome_audit::write_business_event(
            &state,
            "metric_definition",
            metric_id,
            attome_audit::AuditOperation::Execute,
            "metric.compute",
            ctx.user_id,
            None,
            None,
            "metric computed and recorded".to_string(),
        )
        .await;
    }

    Ok(Json(ComputeMetricResponse {
        snapshot: outcome.snapshot,
        skipped: outcome.skipped,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/metrics", get(list_metrics))
        .route("/api/v1/metrics/{id}/snapshots", get(list_snapshots))
        .route("/api/v1/metrics/{id}/compute", post(compute_metric))
        .route(
            "/api/v1/metrics/{id}/lineage",
            get(crate::lineage::metric_lineage),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_metrics,
    list_snapshots,
    compute_metric,
    crate::lineage::metric_lineage
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_start_boundaries_are_utc_calendar() {
        // Wednesday 2026-08-26 (this session's "today").
        let now = DateTime::parse_from_rfc3339("2026-08-26T15:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            period_start_for("day", now).unwrap(),
            NaiveDate::from_ymd_opt(2026, 8, 26).unwrap()
        );
        assert_eq!(
            period_start_for("week", now).unwrap(),
            NaiveDate::from_ymd_opt(2026, 8, 24).unwrap(),
            "week starts Monday"
        );
        assert_eq!(
            period_start_for("month", now).unwrap(),
            NaiveDate::from_ymd_opt(2026, 8, 1).unwrap()
        );
        assert_eq!(
            period_start_for("quarter", now).unwrap(),
            NaiveDate::from_ymd_opt(2026, 7, 1).unwrap(),
            "Aug is in Q3, which starts in July"
        );
        assert_eq!(
            period_start_for("year", now).unwrap(),
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()
        );
        // R-13 item 4: an unrecognized period is client data (this metric's
        // own `period` field), not an internal invariant — must surface as
        // `Validation` (422), not `Internal` (500).
        assert!(matches!(
            period_start_for("fortnight", now),
            Err(AppError::Validation(_))
        ));
    }

    fn at(day: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("{day}T12:00:00Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn fiscal_year_starting_april_bounds() {
        let cal = PeriodCalendar {
            fiscal_start_month: 4,
            ..PeriodCalendar::default()
        };
        let now = at("2026-02-10");
        assert_eq!(
            period_bounds("year", cal, now).unwrap(),
            (d(2025, 4, 1), d(2026, 4, 1))
        );
        assert_eq!(
            period_bounds("quarter", cal, now).unwrap(),
            (d(2026, 1, 1), d(2026, 4, 1)),
            "February is in the fiscal Q4, January to March"
        );
        let now = at("2026-05-20");
        assert_eq!(
            period_bounds("quarter", cal, now).unwrap(),
            (d(2026, 4, 1), d(2026, 7, 1))
        );
        assert_eq!(
            period_bounds("year", cal, now).unwrap(),
            (d(2026, 4, 1), d(2027, 4, 1))
        );
        let bad = PeriodCalendar {
            fiscal_start_month: 13,
            ..PeriodCalendar::default()
        };
        assert!(matches!(
            period_bounds("year", bad, now),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn week_starting_sunday_bounds() {
        // Friday 16 October 2026.
        let now = at("2026-10-16");
        let sunday = PeriodCalendar {
            week_start: PeriodCalendar::week_start_from("sun").unwrap(),
            ..PeriodCalendar::default()
        };
        assert_eq!(
            period_bounds("week", sunday, now).unwrap(),
            (d(2026, 10, 11), d(2026, 10, 18))
        );
        let saturday = PeriodCalendar {
            week_start: chrono::Weekday::Sat,
            ..PeriodCalendar::default()
        };
        assert_eq!(
            period_bounds("week", saturday, now).unwrap(),
            (d(2026, 10, 10), d(2026, 10, 17))
        );
        assert_eq!(
            period_bounds("week", saturday, at("2026-10-17")).unwrap().0,
            d(2026, 10, 17),
            "a Saturday starts its own week"
        );
        assert!(PeriodCalendar::week_start_from("wed").is_err());
    }

    #[test]
    fn hijri_month_bounds_ramadan_1447() {
        let cal = PeriodCalendar {
            kind: CalendarKind::Hijri,
            ..PeriodCalendar::default()
        };
        // 1 March 2026 is in Ramadan 1447, which began on 18 February 2026.
        let (start, end) = period_bounds("month", cal, at("2026-03-01")).unwrap();
        assert_eq!(start, d(2026, 2, 18));
        assert!((29..=30).contains(&(end - start).num_days()));
        assert!(matches!(
            period_bounds("week", cal, at("2026-03-01")),
            Err(AppError::Validation(_))
        ));
        let (year_start, year_end) = period_bounds("year", cal, at("2026-03-01")).unwrap();
        assert!(year_start <= start && end <= year_end);
    }

    #[test]
    fn higher_is_better_thresholds() {
        let target = TargetRow {
            target_value: 100.0,
            threshold_warn: Some(80.0),
            threshold_crit: Some(60.0),
        };
        assert_eq!(
            evaluate_status(90.0, "higher_is_better", Some(&target)),
            SnapshotStatus::Ok
        );
        assert_eq!(
            evaluate_status(75.0, "higher_is_better", Some(&target)),
            SnapshotStatus::Warn
        );
        assert_eq!(
            evaluate_status(50.0, "higher_is_better", Some(&target)),
            SnapshotStatus::Crit
        );
    }

    #[test]
    fn lower_is_better_thresholds() {
        let target = TargetRow {
            target_value: 5.0,
            threshold_warn: Some(10.0),
            threshold_crit: Some(20.0),
        };
        assert_eq!(
            evaluate_status(3.0, "lower", Some(&target)),
            SnapshotStatus::Ok
        );
        assert_eq!(
            evaluate_status(12.0, "lower", Some(&target)),
            SnapshotStatus::Warn
        );
        assert_eq!(
            evaluate_status(25.0, "lower", Some(&target)),
            SnapshotStatus::Crit
        );
    }

    #[test]
    fn target_band_thresholds_use_absolute_deviation() {
        let target = TargetRow {
            target_value: 100.0,
            threshold_warn: Some(5.0),
            threshold_crit: Some(15.0),
        };
        assert_eq!(
            evaluate_status(103.0, "target_band", Some(&target)),
            SnapshotStatus::Ok
        );
        assert_eq!(
            evaluate_status(93.0, "target_band", Some(&target)),
            SnapshotStatus::Warn,
            "7 below target is within crit but past warn"
        );
        assert_eq!(
            evaluate_status(120.0, "target_band", Some(&target)),
            SnapshotStatus::Crit,
            "20 above target exceeds the critical band"
        );
    }

    #[test]
    fn no_target_means_ok_not_a_fabricated_status() {
        assert_eq!(
            evaluate_status(0.0, "higher_is_better", None),
            SnapshotStatus::Ok
        );
    }
}
