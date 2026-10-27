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
use sha2::{Digest, Sha256};
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

/// A snapshot's band (roadmap P9-T6): on track, at risk or off track
/// against its target, or failed. Rows written before P9-T6 say `ok`,
/// `warn` and `crit`; those still read as on track, at risk and off track
/// ([`SnapshotStatus::parse`]) and are never rewritten (snapshots are
/// append-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    #[serde(alias = "ok")]
    OnTrack,
    #[serde(alias = "warn")]
    AtRisk,
    #[serde(alias = "crit")]
    OffTrack,
    /// Not a band (plan §8): "a metric query that becomes slow: compute
    /// under `statement_timeout`, mark snapshot `failed`... never block the
    /// scheduler." A failed snapshot is still a real, visible row (never
    /// silently dropped), and the scheduler retries it on the next sweep
    /// (see `run_scheduled_snapshot_sweep`'s idempotency check, which treats
    /// `failed` as "not yet successfully computed for this period").
    Failed,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnTrack => "on_track",
            Self::AtRisk => "at_risk",
            Self::OffTrack => "off_track",
            Self::Failed => "failed",
        }
    }

    /// A stored status, the pre-P9-T6 values included. Pure.
    pub fn parse(stored: &str) -> Option<Self> {
        match stored {
            "on_track" | "ok" => Some(Self::OnTrack),
            "at_risk" | "warn" => Some(Self::AtRisk),
            "off_track" | "crit" => Some(Self::OffTrack),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// How bad a band is (`None` for failed).
    pub fn rank(self) -> Option<u8> {
        match self {
            Self::OnTrack => Some(0),
            Self::AtRisk => Some(1),
            Self::OffTrack => Some(2),
            Self::Failed => None,
        }
    }

    fn worst(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// A target: the total's (`dimension_value` empty) or one member's.
#[derive(Debug, Clone, PartialEq)]
struct TargetRow {
    target_value: f64,
    threshold_warn: Option<f64>,
    threshold_crit: Option<f64>,
    /// Percent of the target a value may miss by and be at risk rather
    /// than off track.
    at_risk_tolerance: Option<f64>,
    dimension_value: Option<String>,
}

/// The target for the total (`member` `None`) or for one member: the
/// member's own target when it has one, else the total's. Pure.
fn pick_target<'a>(targets: &'a [TargetRow], member: Option<&str>) -> Option<&'a TargetRow> {
    let total = || {
        targets
            .iter()
            .find(|t| t.dimension_value.as_deref().is_none_or(str::is_empty))
    };
    match member {
        Some(value) => targets
            .iter()
            .find(|t| t.dimension_value.as_deref() == Some(value))
            .or_else(total),
        None => total(),
    }
}

/// The band from the explicit thresholds (`threshold_warn` at risk,
/// `threshold_crit` off track).
fn threshold_band(actual: f64, direction: &str, t: &TargetRow) -> SnapshotStatus {
    let (hit, measure): (fn(f64, f64) -> bool, f64) = match direction {
        "lower" => (|a, limit| a >= limit, actual),
        "target_band" => (|a, limit| a >= limit, (actual - t.target_value).abs()),
        _ => (|a, limit| a <= limit, actual),
    };
    if t.threshold_crit.is_some_and(|c| hit(measure, c)) {
        return SnapshotStatus::OffTrack;
    }
    if t.threshold_warn.is_some_and(|w| hit(measure, w)) {
        return SnapshotStatus::AtRisk;
    }
    SnapshotStatus::OnTrack
}

/// The band from the tolerance: meeting the target is on track, missing it
/// by up to `at_risk_tolerance` percent of the target is at risk, and
/// missing it by more is off track. For `target_band` the target itself is
/// the band's centre: within the tolerance is on track, within twice the
/// tolerance at risk.
fn tolerance_band(actual: f64, direction: &str, t: &TargetRow) -> SnapshotStatus {
    let Some(tolerance) = t.at_risk_tolerance.filter(|p| *p >= 0.0) else {
        return SnapshotStatus::OnTrack;
    };
    let slack = t.target_value.abs() * tolerance / 100.0;
    let miss = match direction {
        "lower" => actual - t.target_value,
        "target_band" => (actual - t.target_value).abs() - slack,
        _ => t.target_value - actual,
    };
    if miss <= 0.0 {
        SnapshotStatus::OnTrack
    } else if miss <= slack {
        SnapshotStatus::AtRisk
    } else {
        SnapshotStatus::OffTrack
    }
}

/// Pure — unit-tested directly. No target means nothing to compare
/// against, so the snapshot is on track (a value with no judgment attached,
/// not a fabricated warning). With a target, the worse of its thresholds'
/// band and its tolerance's band.
fn evaluate_status(actual: f64, direction: &str, target: Option<&TargetRow>) -> SnapshotStatus {
    let Some(t) = target else {
        return SnapshotStatus::OnTrack;
    };
    threshold_band(actual, direction, t).worst(tolerance_band(actual, direction, t))
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

/// The most targets one metric period reads (the total's and its members').
const MAX_TARGETS: i64 = 2_000;

/// The period's targets, newest first, read without assuming the governance
/// columns (`at_risk_tolerance`, `dimension_value`, P9-T4) exist.
async fn fetch_targets(
    db: &DbPool,
    metric_id: Uuid,
    period_start: NaiveDate,
) -> Result<Vec<TargetRow>, AppError> {
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(t) FROM dashboard_metric_target t \
         WHERE metric_ref = $1 AND period_start = $2 AND (is_active IS NULL OR is_active = true) \
         ORDER BY created_at DESC LIMIT $3",
    )
    .bind(metric_id)
    .bind(period_start)
    .bind(MAX_TARGETS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let num = |row: &serde_json::Value, key: &str| -> Option<f64> {
        match row.get(key)? {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    };
    Ok(rows
        .iter()
        .filter_map(|row| {
            Some(TargetRow {
                target_value: num(row, "target_value")?,
                threshold_warn: num(row, "threshold_warn"),
                threshold_crit: num(row, "threshold_crit"),
                at_risk_tolerance: num(row, "at_risk_tolerance"),
                dimension_value: row
                    .get("dimension_value")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect())
}

/// One member's stored value: its dimension values, comma-separated.
fn member_value(member: &MemberValue) -> String {
    member
        .dimensions
        .iter()
        .map(|d| d.as_deref().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(",")
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
    /// P9-T5: `None` on the total row; on a member row, the dimension
    /// attribute(s), comma-separated.
    pub dimension_attribute: Option<String>,
    /// The member's value (several dimensions' values comma-separated).
    pub dimension_value: Option<String>,
    /// P9-T9: the definition version the value was computed under.
    pub definition_version: i32,
    /// P9-T9: [`definition_fingerprint`] of the definition fields at compute
    /// time; `None` on rows written before P9-T9.
    pub definition_fingerprint: Option<String>,
}

const SNAPSHOT_COLUMNS: &str = "id, metric_ref, period_start, actual, computed_at, \
     source_version, status, superseded_ref, evaluated_by, error_message, \
     dimension_attribute, dimension_value, definition_version, definition_fingerprint";

/// P9-T5: the most members a dimensioned metric stores per period.
pub const MAX_MEMBERS: usize = 1_000;

/// One member of a dimensioned metric: its dimension values and its value.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberValue {
    pub dimensions: Vec<Option<String>>,
    pub value: f64,
}

/// A metric's dimensions, aggregate, declared definition version and
/// definition fingerprint.
struct DefinitionShape {
    dimensions: Vec<String>,
    aggregate: Option<String>,
    declared_version: Option<i32>,
    fingerprint: String,
}

/// Read without assuming the governance columns exist (P9-T4 adds them as
/// attributes).
async fn metric_dimensions(db: &DbPool, metric_id: Uuid) -> Result<DefinitionShape, AppError> {
    let row: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(d) FROM dashboard_metric_definition d WHERE id = $1")
            .bind(metric_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let row = row.unwrap_or_default();
    let dimensions = parse_dimensions(row.get("dimension_attributes").and_then(|v| v.as_str()));
    let aggregate = row
        .get("aggregate")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let declared_version = row
        .get("definition_version")
        .and_then(serde_json::Value::as_f64)
        .map(|v| v as i32);
    Ok(DefinitionShape {
        dimensions,
        aggregate,
        declared_version,
        fingerprint: definition_fingerprint(&row),
    })
}

/// P9-T9: the definition fields a metric's value depends on. A change to any
/// of them starts a new definition version.
pub const DEFINITION_FIELDS: &[&str] = &[
    "source_kind",
    "query_ref",
    "formula",
    "period",
    "entity_logicalname",
    "aggregate",
    "measure_attribute",
    "date_attribute",
    "filter_expression",
    "dimension_attributes",
    "calendar_kind",
    "week_start",
];

/// P9-T9: hex SHA-256 over [`DEFINITION_FIELDS`] of a definition row (its
/// `to_jsonb` form). An absent field, a null and a blank string are the same
/// value, so adding an attribute to the entity does not change any metric's
/// fingerprint. Pure.
pub fn definition_fingerprint(row: &serde_json::Value) -> String {
    let mut canonical = String::new();
    for field in DEFINITION_FIELDS {
        let value = match row.get(*field) {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(s)) if s.trim().is_empty() => String::new(),
            Some(serde_json::Value::String(s)) => s.trim().to_owned(),
            Some(other) => other.to_string(),
        };
        canonical.push_str(field);
        canonical.push('=');
        canonical.push_str(&serde_json::Value::String(value).to_string());
        canonical.push('\n');
    }
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// P9-T9: the version a new snapshot records. The metric's last snapshot
/// (any period) carries the version and fingerprint it was computed with; a
/// different fingerprint now means the definition changed, so the version
/// moves up by one. A last snapshot without a fingerprint (written before
/// P9-T9) keeps its version. The definition's own `definition_version`
/// attribute is a floor an administrator can raise by hand. Pure.
pub fn next_definition_version(
    declared: Option<i32>,
    last: Option<(i32, Option<&str>)>,
    fingerprint: &str,
) -> i32 {
    let floor = declared.unwrap_or(1).max(1);
    match last {
        None => floor,
        Some((version, Some(previous))) if previous != fingerprint => {
            version.saturating_add(1).max(floor)
        }
        Some((version, _)) => version.max(floor),
    }
}

/// P9-T9: the version and fingerprint of the metric's newest total snapshot.
async fn last_definition_version(
    db: &DbPool,
    metric_id: Uuid,
) -> Result<Option<(i32, Option<String>)>, AppError> {
    sqlx::query_as(
        "SELECT definition_version, definition_fingerprint FROM metric_snapshot \
         WHERE metric_ref = $1 AND dimension_attribute IS NULL \
         ORDER BY computed_at DESC, id DESC LIMIT 1",
    )
    .bind(metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// A metric's dimension attributes: a JSON list or a comma-separated list.
/// Pure.
pub fn parse_dimensions(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Vec::new();
    };
    let list: Vec<String> = serde_json::from_str::<Vec<String>>(raw)
        .unwrap_or_else(|_| raw.split(',').map(str::to_owned).collect());
    list.into_iter()
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .collect()
}

/// The total of a dimensioned result: its total row (every dimension
/// empty) when the query returned one, else the members' sum for a count or
/// sum metric. Any other aggregate needs the total row. Pure.
pub fn dimension_total(
    rows: &[MemberValue],
    aggregate: Option<&str>,
) -> Result<(f64, Vec<MemberValue>), AppError> {
    let (totals, members): (Vec<&MemberValue>, Vec<&MemberValue>) = rows
        .iter()
        .partition(|r| r.dimensions.iter().all(Option::is_none));
    if members.len() > MAX_MEMBERS {
        return Err(AppError::Validation(format!(
            "the metric has more than {MAX_MEMBERS} members; use fewer dimensions"
        )));
    }
    let members: Vec<MemberValue> = members.into_iter().cloned().collect();
    if let Some(total) = totals.first() {
        return Ok((total.value, members));
    }
    match aggregate {
        // Counts and sums add up; a stored query with no aggregate set is
        // read as one.
        None | Some("count") | Some("sum") => Ok((members.iter().map(|m| m.value).sum(), members)),
        Some(other) => Err(AppError::Validation(format!(
            "a {other} metric with dimensions needs its query to return the total row too \
             (every dimension empty, for example with GROUPING SETS)"
        ))),
    }
}

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
         WHERE metric_ref = $1 AND period_start = $2 AND dimension_attribute IS NULL \
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
    members: &[MemberValue],
    member_statuses: &[SnapshotStatus],
    dimension_attribute: Option<&str>,
    definition_version: i32,
    definition_fingerprint: &str,
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
           AND dimension_attribute IS NULL \
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
          evaluated_by, error_message, definition_version, definition_fingerprint) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
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
    .bind(definition_version)
    .bind(definition_fingerprint)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // P9-T5: one row per member, each chained to that member's last row.
    if let Some(attribute) = dimension_attribute {
        for (n, member) in members.iter().enumerate() {
            let value = member_value(member);
            let member_status = member_statuses
                .get(n)
                .copied()
                .unwrap_or(SnapshotStatus::OnTrack);
            sqlx::query(
                "INSERT INTO metric_snapshot \
                 (id, metric_ref, period_start, actual, source_version, status, superseded_ref, \
                  evaluated_by, dimension_attribute, dimension_value, definition_version, \
                  definition_fingerprint) \
                 SELECT $1, $2, $3, $4, $5, $6, \
                        (SELECT p.id FROM metric_snapshot p \
                          WHERE p.metric_ref = $2 AND p.period_start = $3 \
                            AND p.dimension_attribute = $8 AND p.dimension_value = $9 \
                          ORDER BY p.computed_at DESC, p.id DESC LIMIT 1), \
                        $7, $8, $9, $10, $11",
            )
            .bind(Uuid::now_v7())
            .bind(metric_id)
            .bind(period_start)
            .bind(member.value)
            .bind(source_version)
            .bind(member_status.as_str())
            .bind(evaluated_by)
            .bind(attribute)
            .bind(&value)
            .bind(definition_version)
            .bind(definition_fingerprint)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }

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
    let (response, version) = execute_metric_query(state, query_ref, trigger, 1).await?;
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
    Ok((value, version))
}

/// P9-T5: a dimensioned query metric's rows, each with its dimension
/// columns and `value`, run once (never once per member), and the version
/// that produced them. The query groups by the dimensions itself.
async fn run_query_metric_members(
    state: &EngineState,
    query_ref: &str,
    trigger: crate::principal::Trigger,
    dimensions: &[String],
) -> Result<(Vec<MemberValue>, String), AppError> {
    let page = i64::try_from(MAX_MEMBERS + 2).unwrap_or(i64::MAX);
    let (response, version) = execute_metric_query(state, query_ref, trigger, page).await?;
    let records = response
        .pointer("/data/records")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut rows = Vec::with_capacity(records.len());
    for record in records {
        let Some(obj) = record.as_object() else {
            continue;
        };
        let field = |name: &str| {
            obj.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        };
        let value = field("value").and_then(|v| v.as_f64()).ok_or_else(|| {
            AppError::Validation(
                "metric query result must contain a numeric column named `value`".into(),
            )
        })?;
        let dims = dimensions
            .iter()
            .map(|d| match field(d) {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(other) => Some(other.to_string()),
            })
            .collect();
        rows.push(MemberValue {
            dimensions: dims,
            value,
        });
    }
    Ok((rows, version))
}

/// Runs the metric's stored query (its newest version, pinned) under the
/// metric service principal and answers the response's wire shape and the
/// version id. See [`run_query_metric`].
async fn execute_metric_query(
    state: &EngineState,
    query_ref: &str,
    trigger: crate::principal::Trigger,
    page_size: i64,
) -> Result<(serde_json::Value, String), AppError> {
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
        "page_size": page_size,
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
    Ok((response, version_id.to_string()))
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

    let DefinitionShape {
        dimensions,
        aggregate,
        declared_version,
        fingerprint,
    } = metric_dimensions(db, metric_id).await?;
    let last = last_definition_version(db, metric_id).await?;
    let definition_version = next_definition_version(
        declared_version,
        last.as_ref().map(|(v, fp)| (*v, fp.as_deref())),
        &fingerprint,
    );
    let mut members: Vec<MemberValue> = Vec::new();
    let mut member_statuses: Vec<SnapshotStatus> = Vec::new();
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
            let targets = fetch_targets(db, metric_id, period_start).await?;
            let status = evaluate_status(actual, &metric.direction, pick_target(&targets, None));
            (Some(actual), Some("manual".to_string()), status, None)
        }
        "query" => {
            let Some(query_ref) = metric.query_ref.clone() else {
                return Err(AppError::Validation(
                    "this metric is source_kind=query but has no query_ref set".into(),
                ));
            };
            let trigger = crate::principal::Trigger::from_evaluated_by(evaluated_by);
            let ran = if dimensions.is_empty() {
                run_query_metric(state, &query_ref, trigger).await
            } else {
                run_query_metric_members(state, &query_ref, trigger, &dimensions)
                    .await
                    .and_then(|(rows, version)| {
                        let (total, found) = dimension_total(&rows, aggregate.as_deref())?;
                        members = found;
                        Ok((total, version))
                    })
            };
            match ran {
                Ok((actual, version)) => {
                    let targets = fetch_targets(db, metric_id, period_start).await?;
                    let status =
                        evaluate_status(actual, &metric.direction, pick_target(&targets, None));
                    member_statuses = members
                        .iter()
                        .map(|m| {
                            let value = member_value(m);
                            evaluate_status(
                                m.value,
                                &metric.direction,
                                pick_target(&targets, Some(&value)),
                            )
                        })
                        .collect();
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
                    let targets = fetch_targets(db, metric_id, period_start).await?;
                    let status =
                        evaluate_status(actual, &metric.direction, pick_target(&targets, None));
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
        &members,
        &member_statuses,
        (!members.is_empty())
            .then(|| dimensions.join(","))
            .as_deref(),
        definition_version,
        &fingerprint,
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
/// evaluation principal." `query` and `formula` metrics are swept, in
/// dependency order (P9-T8: children and formula inputs first, so a formula
/// reads this run's snapshots); a `manual` metric has no value to derive on
/// a timer, so it
/// is only ever written via an explicit `/compute` call. Failure isolation
/// (guidelines §10/plan §8): one metric's failure (a timeout, a bad query, a
/// missing grant, a disabled principal) is recorded as that metric's `failed`
/// snapshot and never stops the rest of the sweep.
pub async fn run_scheduled_snapshot_sweep(state: &EngineState) -> Result<u32, AppError> {
    let db = &state.base.db;
    let metrics: Vec<MetricDefinitionRow> = sqlx::query_as(&format!(
        "SELECT {METRIC_DEFINITION_COLUMNS} FROM dashboard_metric_definition \
         WHERE source_kind IN ('query', 'formula') AND (is_active IS NULL OR is_active = true)"
    ))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    // P9-T8: children and formula inputs before their parents, so a formula
    // reads this run's snapshots. With a cycle, only query metrics run.
    let metrics = match crate::order::load_nodes(db)
        .await
        .and_then(|nodes| crate::order::evaluation_order(&nodes))
    {
        Ok(order) => {
            let rank: std::collections::HashMap<Uuid, usize> = order
                .into_iter()
                .enumerate()
                .map(|(i, id)| (id, i))
                .collect();
            let mut metrics = metrics;
            metrics.sort_by_key(|m| rank.get(&m.id).copied().unwrap_or(usize::MAX));
            metrics
        }
        Err(error) => {
            tracing::warn!(%error, "metric snapshot sweep: no evaluation order, formula metrics skipped");
            metrics
                .into_iter()
                .filter(|m| m.source_kind == "query")
                .collect()
        }
    };

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

/// The snapshot list's page and dimension filters (P9-T5).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SnapshotListQuery {
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    #[param(minimum = 1)]
    pub page_size: Option<i64>,
    /// A dimension attribute (comma-separated for several): its members'
    /// rows instead of the totals.
    pub dimension_attribute: Option<String>,
    /// One member's value, with `dimension_attribute`.
    pub dimension_value: Option<String>,
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
        SnapshotListQuery,
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
    Query(q): Query<SnapshotListQuery>,
) -> Result<Json<PaginatedResponse<SnapshotRow>>, AppError> {
    fetch_metric(&state.base.db, metric_id).await?;

    let window = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    // Totals by default; members of one dimension (and one value) on request.
    let filter = "metric_ref = $1 \
         AND (($2::text IS NULL AND dimension_attribute IS NULL) OR dimension_attribute = $2) \
         AND ($3::text IS NULL OR dimension_value = $3)";

    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM metric_snapshot WHERE {filter}"
    ))
    .bind(metric_id)
    .bind(&q.dimension_attribute)
    .bind(&q.dimension_value)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items: Vec<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM metric_snapshot WHERE {filter} \
         ORDER BY period_start DESC, computed_at DESC LIMIT $4 OFFSET $5"
    ))
    .bind(metric_id)
    .bind(&q.dimension_attribute)
    .bind(&q.dimension_value)
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

/// One metric of a tree computation.
#[derive(Debug, Serialize, ToSchema)]
pub struct TreeComputed {
    pub metric_id: Uuid,
    /// `computed`, `skipped` (a snapshot for the period existed) or `failed`.
    pub outcome: String,
    pub error: Option<String>,
}

/// A tree computation, in the order it ran.
#[derive(Debug, Serialize, ToSchema)]
pub struct ComputeTreeResponse {
    pub metrics: Vec<TreeComputed>,
}

/// Compute a metric and everything under it
///
/// P9-T8: computes every query and formula metric the metric is built from
/// (its children and its formula's inputs, transitively), children before
/// parents, then the metric itself, for each one's current period. One
/// metric's failure is reported and the rest go on; a cycle is refused.
#[utoipa::path(
    post,
    path = "/api/v1/metrics/{id}/compute-tree",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The root metric")),
    responses(
        (status = 200, description = "What each metric of the tree did", body = ComputeTreeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
        (status = 422, description = "The tree has a cycle", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    // As `/compute`: a query metric's first compute may provision the metric
    // service principal's role membership (D-786).
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute), (attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant)])))),
)]
async fn compute_tree(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricUpdate>>,
    Path(metric_id): Path<Uuid>,
) -> Result<Json<ComputeTreeResponse>, AppError> {
    let db = &state.base.db;
    fetch_metric(db, metric_id).await?;
    let nodes = crate::order::load_nodes(db).await?;
    let tree = crate::order::tree_under(&nodes, metric_id);
    let order = crate::order::evaluation_order(&tree)?;
    let kinds: std::collections::HashMap<Uuid, String> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, source_kind FROM dashboard_metric_definition WHERE id = ANY($1)",
    )
    .bind(&order)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let mut metrics = Vec::with_capacity(order.len());
    for id in order {
        // A manual metric has no value to derive; it is entered by hand.
        if !matches!(
            kinds.get(&id).map(String::as_str),
            Some("query" | "formula")
        ) {
            continue;
        }
        let (outcome, error) =
            match compute_and_record(&state, id, None, None, false, Some(ctx.user_id)).await {
                Ok(o) if o.skipped => ("skipped", None),
                Ok(o) if o.snapshot.status == "failed" => ("failed", o.snapshot.error_message),
                Ok(_) => ("computed", None),
                Err(e) => ("failed", Some(e.to_string())),
            };
        metrics.push(TreeComputed {
            metric_id: id,
            outcome: outcome.to_owned(),
            error,
        });
    }
    attome_audit::write_business_event(
        &state,
        "metric_definition",
        metric_id,
        attome_audit::AuditOperation::Execute,
        "metric.compute_tree",
        ctx.user_id,
        None,
        None,
        format!("{} metrics computed in dependency order", metrics.len()),
    )
    .await;
    Ok(Json(ComputeTreeResponse { metrics }))
}

/// The metric's builder query.
#[derive(Debug, Serialize, ToSchema)]
pub struct BuilderQueryResponse {
    pub metric_id: Uuid,
    /// The stored query the metric now reads.
    pub query_id: Uuid,
}

/// Build a metric from its parts
///
/// P9-T3: describes the metric as an entity, an aggregate over one of its
/// attributes, the date that places a record in the metric's period, filters
/// and dimensions; creates (or republishes) the metric's stored query from it
/// and points the metric at that query. Needs the metric's update privilege.
#[utoipa::path(
    post,
    path = "/api/v1/metrics/{id}/builder",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The metric")),
    request_body = crate::builder::MetricSpec,
    responses(
        (status = 200, description = "The metric reads the built query", body = BuilderQueryResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
        (status = 409, description = "The metric changed while it was being built", body = ErrorResponse),
        (status = 422, description = "An unknown or sensitive attribute, a non-numeric measure, a bad filter, or a period without a calendar", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    // The stored query is Configuration: created the first time, republished after.
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create), (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
async fn build_metric(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricUpdate>>,
    Path(metric_id): Path<Uuid>,
    Json(spec): Json<crate::builder::MetricSpec>,
) -> Result<Json<BuilderQueryResponse>, AppError> {
    let query_id = crate::builder::upsert_builder_query(&state, &ctx, metric_id, &spec).await?;
    Ok(Json(BuilderQueryResponse {
        metric_id,
        query_id,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/metrics", get(list_metrics))
        .route("/api/v1/metrics/{id}/builder", post(build_metric))
        .route(
            "/api/v1/metrics/{id}/targets/spread",
            post(crate::targets::post_spread),
        )
        .route("/api/v1/metrics/{id}/snapshots", get(list_snapshots))
        .route("/api/v1/metrics/{id}/compute", post(compute_metric))
        .route("/api/v1/metrics/{id}/compute-tree", post(compute_tree))
        .route(
            "/api/v1/metrics/{id}/lineage",
            get(crate::lineage::metric_lineage),
        )
        .route(
            "/api/v1/metrics/{id}/impact",
            get(crate::lineage_graph::metric_impact),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_metrics,
    list_snapshots,
    compute_metric,
    compute_tree,
    build_metric,
    crate::targets::post_spread,
    crate::lineage::metric_lineage,
    crate::lineage_graph::metric_impact
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_blank_and_unknown_fields_but_not_a_filter() {
        let base =
            serde_json::json!({ "source_kind": "query", "query_ref": "q1", "period": "month" });
        let same = serde_json::json!({
            "source_kind": "query", "query_ref": "q1", "period": "month",
            "filter_expression": "  ", "formula": null, "name": "Renamed"
        });
        let filtered = serde_json::json!({
            "source_kind": "query", "query_ref": "q1", "period": "month",
            "filter_expression": "status == 'won'"
        });
        assert_eq!(definition_fingerprint(&base), definition_fingerprint(&same));
        assert_ne!(
            definition_fingerprint(&base),
            definition_fingerprint(&filtered)
        );
        assert_eq!(definition_fingerprint(&base).len(), 64);
    }

    #[test]
    fn version_moves_only_when_the_fingerprint_changes() {
        assert_eq!(next_definition_version(None, None, "a"), 1);
        assert_eq!(next_definition_version(Some(3), None, "a"), 3);
        assert_eq!(next_definition_version(None, Some((1, Some("a"))), "a"), 1);
        assert_eq!(next_definition_version(None, Some((1, Some("a"))), "b"), 2);
        // A pre-P9-T9 row has no fingerprint: record one, keep the version.
        assert_eq!(next_definition_version(None, Some((4, None)), "b"), 4);
        // The declared attribute is a floor.
        assert_eq!(
            next_definition_version(Some(7), Some((2, Some("a"))), "b"),
            7
        );
        assert_eq!(next_definition_version(Some(0), None, "a"), 1);
    }

    fn member(dim: Option<&str>, value: f64) -> MemberValue {
        MemberValue {
            dimensions: vec![dim.map(str::to_owned)],
            value,
        }
    }

    #[test]
    fn dimensions_parse_from_a_list_or_commas() {
        assert_eq!(
            parse_dimensions(Some(r#"["region", " owner "]"#)),
            vec!["region", "owner"]
        );
        assert_eq!(
            parse_dimensions(Some("region, owner")),
            vec!["region", "owner"]
        );
        assert!(parse_dimensions(Some("  ")).is_empty());
        assert!(parse_dimensions(None).is_empty());
    }

    #[test]
    fn a_count_total_is_its_members_sum_unless_the_query_gives_it() {
        let rows = vec![member(Some("east"), 2.0), member(Some("west"), 1.0)];
        let (total, members) = dimension_total(&rows, Some("count")).unwrap();
        assert_eq!((total, members.len()), (3.0, 2));
        let mut with_total = rows.clone();
        with_total.push(member(None, 10.0));
        assert_eq!(dimension_total(&with_total, Some("avg")).unwrap().0, 10.0);
        assert!(dimension_total(&rows, Some("avg")).is_err());
        let many: Vec<MemberValue> = (0..=MAX_MEMBERS)
            .map(|i| member(Some(&i.to_string()), 1.0))
            .collect();
        assert!(dimension_total(&many, Some("count")).is_err());
    }

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
            ..target(100.0)
        };
        assert_eq!(
            evaluate_status(90.0, "higher_is_better", Some(&target)),
            SnapshotStatus::OnTrack
        );
        assert_eq!(
            evaluate_status(75.0, "higher_is_better", Some(&target)),
            SnapshotStatus::AtRisk
        );
        assert_eq!(
            evaluate_status(50.0, "higher_is_better", Some(&target)),
            SnapshotStatus::OffTrack
        );
    }

    #[test]
    fn lower_is_better_thresholds() {
        let target = TargetRow {
            target_value: 5.0,
            threshold_warn: Some(10.0),
            threshold_crit: Some(20.0),
            ..target(5.0)
        };
        assert_eq!(
            evaluate_status(3.0, "lower", Some(&target)),
            SnapshotStatus::OnTrack
        );
        assert_eq!(
            evaluate_status(12.0, "lower", Some(&target)),
            SnapshotStatus::AtRisk
        );
        assert_eq!(
            evaluate_status(25.0, "lower", Some(&target)),
            SnapshotStatus::OffTrack
        );
    }

    #[test]
    fn target_band_thresholds_use_absolute_deviation() {
        let target = TargetRow {
            target_value: 100.0,
            threshold_warn: Some(5.0),
            threshold_crit: Some(15.0),
            ..target(100.0)
        };
        assert_eq!(
            evaluate_status(103.0, "target_band", Some(&target)),
            SnapshotStatus::OnTrack
        );
        assert_eq!(
            evaluate_status(93.0, "target_band", Some(&target)),
            SnapshotStatus::AtRisk,
            "7 below target is within crit but past warn"
        );
        assert_eq!(
            evaluate_status(120.0, "target_band", Some(&target)),
            SnapshotStatus::OffTrack,
            "20 above target exceeds the critical band"
        );
    }

    #[test]
    fn no_target_means_on_track_not_a_fabricated_status() {
        assert_eq!(
            evaluate_status(0.0, "higher_is_better", None),
            SnapshotStatus::OnTrack
        );
    }

    fn target(value: f64) -> TargetRow {
        TargetRow {
            target_value: value,
            threshold_warn: None,
            threshold_crit: None,
            at_risk_tolerance: None,
            dimension_value: None,
        }
    }

    #[test]
    fn higher_is_better_within_tolerance_is_at_risk() {
        let t = TargetRow {
            at_risk_tolerance: Some(10.0),
            ..target(100.0)
        };
        let band = |actual| evaluate_status(actual, "higher_is_better", Some(&t));
        assert_eq!(band(100.0), SnapshotStatus::OnTrack);
        assert_eq!(band(120.0), SnapshotStatus::OnTrack);
        assert_eq!(band(95.0), SnapshotStatus::AtRisk);
        assert_eq!(band(90.0), SnapshotStatus::AtRisk);
        assert_eq!(band(85.0), SnapshotStatus::OffTrack);
        // A crossed threshold is never softened by the tolerance.
        let strict = TargetRow {
            threshold_crit: Some(98.0),
            ..t.clone()
        };
        assert_eq!(
            evaluate_status(95.0, "higher_is_better", Some(&strict)),
            SnapshotStatus::OffTrack
        );
    }

    #[test]
    fn lower_is_better_over_crit_is_off_track() {
        let t = TargetRow {
            threshold_crit: Some(20.0),
            at_risk_tolerance: Some(50.0),
            ..target(10.0)
        };
        let band = |actual| evaluate_status(actual, "lower", Some(&t));
        assert_eq!(band(8.0), SnapshotStatus::OnTrack);
        assert_eq!(band(14.0), SnapshotStatus::AtRisk);
        assert_eq!(band(17.0), SnapshotStatus::OffTrack);
        assert_eq!(band(25.0), SnapshotStatus::OffTrack);
    }

    #[test]
    fn target_band_tolerance_is_both_sides() {
        let t = TargetRow {
            at_risk_tolerance: Some(5.0),
            ..target(100.0)
        };
        let band = |actual| evaluate_status(actual, "target_band", Some(&t));
        assert_eq!(band(104.0), SnapshotStatus::OnTrack);
        assert_eq!(band(92.0), SnapshotStatus::AtRisk);
        assert_eq!(band(111.0), SnapshotStatus::OffTrack);
    }

    #[test]
    fn old_status_values_still_parse() {
        assert_eq!(SnapshotStatus::parse("ok"), Some(SnapshotStatus::OnTrack));
        assert_eq!(SnapshotStatus::parse("warn"), Some(SnapshotStatus::AtRisk));
        assert_eq!(
            SnapshotStatus::parse("crit"),
            Some(SnapshotStatus::OffTrack)
        );
        assert_eq!(
            SnapshotStatus::parse("at_risk"),
            Some(SnapshotStatus::AtRisk)
        );
        assert_eq!(
            SnapshotStatus::parse("failed"),
            Some(SnapshotStatus::Failed)
        );
        assert_eq!(SnapshotStatus::parse("nonsense"), None);
        let old: SnapshotStatus = serde_json::from_str("\"warn\"").unwrap();
        assert_eq!(old, SnapshotStatus::AtRisk);
        let new: SnapshotStatus = serde_json::from_str("\"off_track\"").unwrap();
        assert_eq!(new, SnapshotStatus::OffTrack);
        assert_eq!(
            serde_json::to_string(&SnapshotStatus::OnTrack).unwrap(),
            "\"on_track\""
        );
    }

    #[test]
    fn a_member_uses_its_own_target_else_the_total() {
        let targets = vec![
            TargetRow {
                dimension_value: Some("Riyadh".into()),
                ..target(50.0)
            },
            target(100.0),
        ];
        assert_eq!(
            pick_target(&targets, None).map(|t| t.target_value),
            Some(100.0)
        );
        assert_eq!(
            pick_target(&targets, Some("Riyadh")).map(|t| t.target_value),
            Some(50.0)
        );
        assert_eq!(
            pick_target(&targets, Some("Jeddah")).map(|t| t.target_value),
            Some(100.0)
        );
    }
}
