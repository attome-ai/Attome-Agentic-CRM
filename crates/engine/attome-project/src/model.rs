//! Wire DTOs for this crate's read-only aggregation endpoints — everything
//! else (CRUD on every entity `seed.rs` registers) goes through the generic
//! entity API, so this crate carries no other response types.
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// `GET /api/v1/project/{id}/summary` — the "Project Control Center" tiles.
/// Every count/percentage here is computed at read time from the current
/// state of the project's own fields plus its child work items/issues/change
/// requests — nothing is a stored/cached rollup (see `work_plan.rs`'s doc
/// comment for why).
#[derive(Serialize, ToSchema)]
pub struct ProjectSummaryResponse {
    pub project_id: Uuid,
    /// PM-maintained (`attome_project.health`), not auto-scored — see the
    /// implementation plan's "Deferred" section.
    pub health: Option<String>,
    /// `points_completed / points_total * 100`, over the project's leaf work
    /// items only (a phase/parent item never carries its own points — see
    /// `work_plan.rs`). `0.0` when there are no leaf items yet.
    pub weighted_progress_pct: f64,
    pub points_completed: i64,
    pub points_total: i64,
    /// Points belonging to leaf items whose status is `blocked` — a delivery
    /// exposure metric, deliberately not netted out of `points_total` or
    /// counted toward `points_completed`.
    pub points_blocked: i64,
    /// Leaf work items only ("actionable" — a phase/parent container is
    /// never itself actionable).
    pub work_items_done: i64,
    pub work_items_actionable: i64,
    pub budget_amount: Option<f64>,
    /// PM-maintained for this phase — see the implementation plan's
    /// "Deferred" section (time-entry-driven automation is a follow-up).
    pub budget_consumed: Option<f64>,
    pub budget_consumed_pct: Option<f64>,
    /// `SUM(time_entry.hours * resource_rate.internal_cost_rate)` across
    /// this project's leaf work items, using each user's most recent rate as
    /// of the entry (falls back to `None`-contributes-nothing when no rate
    /// row exists for that user). Distinct from `budget_consumed` above,
    /// which stays a PM-maintained input — this is computed at read time
    /// from `project_time_entry`/`project_resource_rate`, the same
    /// D-368 rule every other number on this response follows.
    ///
    /// `None` (not `0.0`) when the caller lacks read access to
    /// `project_resource_rate` — `internal_cost_rate` is `is_sensitive`,
    /// and this field is derived from it, so it is gated the same way: a
    /// plain `ProjectRead` caller does not automatically see it.
    pub actual_cost: Option<f64>,
    pub open_risks_total: i64,
    pub open_risks_critical: i64,
    pub pending_change_requests_total: i64,
    pub pending_change_requests_customer_facing: i64,
    /// `MAX(due_date)` among leaf work items not yet `done` — `None` when
    /// every leaf item is done or the project has no leaf items yet.
    pub forecast_date: Option<DateTime<Utc>>,
    /// `target_end_date - forecast_date`, in days. Positive means the
    /// forecast lands before the target (buffer); negative means it lands
    /// after (overrun). `None` unless both dates are present.
    pub forecast_buffer_days: Option<i64>,
    /// The most recently captured baseline this project's variance fields
    /// are computed against — `None` when no baseline has ever been
    /// captured (`POST /project/{id}/baseline`). See `variance.rs`'s module
    /// doc for exactly what each field below does and does not measure.
    pub baseline_id: Option<Uuid>,
    pub baseline_label: Option<String>,
    pub baseline_captured_at: Option<DateTime<Utc>>,
    /// Active work items now minus active work items captured in the
    /// baseline — positive means scope has grown since the baseline,
    /// negative means it has shrunk (items deactivated/deleted).
    pub scope_item_count_variance: Option<i64>,
    /// The baseline's own planned finish (`MAX(planned_due)` across its
    /// captured items) minus the live `forecast_date` above, in days.
    /// Positive means the live forecast is ahead of the baseline's plan;
    /// negative means it has slipped behind it. `None` when either date is
    /// missing (no baseline, no baseline item carries a `planned_due`, or
    /// every leaf item is currently `done` so there is no live forecast).
    pub schedule_variance_days: Option<i64>,
    /// Budget at Completion — `budget_amount`, unchanged; repeated here so
    /// every EVM figure below reads from one self-contained group.
    pub budget_at_completion: Option<f64>,
    /// Planned Value — `BAC × (baseline points whose planned_due has
    /// already passed) / (baseline points total)`. A simplified,
    /// points-as-progress-measure PV: this crate has no per-task budget to
    /// time-phase (`project_work_item` carries no cost field — see
    /// `baseline.rs`'s own doc comment on why `planned_budget` is always
    /// `NULL`), so points stand in for value the same way `weighted_progress_pct`
    /// already does for EV below. `None` without a baseline or a `None` BAC.
    pub planned_value: Option<f64>,
    /// Earned Value — `BAC × weighted_progress_pct / 100`, the standard
    /// "budgeted cost of work performed" formula using this project's own
    /// live progress fraction. `None` without a `None` BAC.
    pub earned_value: Option<f64>,
    /// Cost Performance Index — `EV / AC` (`AC` is `actual_cost` above,
    /// already gated on `project_resource_rate` read access — this
    /// inherits that gate: `None` whenever `actual_cost` is `None`, same as
    /// every other cost-derived field on this response). `> 1` means
    /// under budget for work performed so far, `< 1` means over.
    pub cost_performance_index: Option<f64>,
    /// Schedule Performance Index — `EV / PV`. `> 1` means ahead of the
    /// baseline's planned pace, `< 1` means behind.
    pub schedule_performance_index: Option<f64>,
    /// Estimate at Completion — `BAC / CPI`, the standard "current cost
    /// performance continues for the rest of the project" projection.
    pub estimate_at_completion: Option<f64>,
    /// Estimate to Complete — `EAC - AC`.
    pub estimate_to_complete: Option<f64>,
    /// Variance at Completion — `BAC - EAC`. Positive means the project is
    /// trending to finish under budget.
    pub variance_at_completion: Option<f64>,
}

impl std::fmt::Debug for ProjectSummaryResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectSummaryResponse")
            .finish_non_exhaustive()
    }
}

/// One row of `GET /api/v1/project/{id}/work-items/rollup` — a work item's
/// own stored fields plus its point rollup. The client builds the WBS tree
/// from `parent_work_item_id`, the same flat-list-plus-parent-pointer shape
/// `entity/document-folder/document-folder-browser.component.ts` already
/// renders recursively.
#[derive(Serialize, ToSchema)]
pub struct WorkItemRollupRow {
    pub id: Uuid,
    pub name: String,
    pub parent_work_item_id: Option<Uuid>,
    pub item_type: String,
    pub status: String,
    pub owner_id: Option<Uuid>,
    pub start_date: Option<DateTime<Utc>>,
    pub due_date: Option<DateTime<Utc>>,
    pub sequence: Option<f64>,
    /// This node's own `points` value — meaningful only when it is itself a
    /// leaf (`points_total == points_own` in that case); 0 for a
    /// phase/parent row regardless of what its `points` column happens to
    /// hold, per the "parent tasks and phases do not carry their own
    /// progress" rule.
    pub points_own: f64,
    /// Sum of `points` over every leaf *descendant* of this node (itself,
    /// if this node is a leaf).
    pub points_completed: i64,
    pub points_total: i64,
    pub points_blocked: i64,
    /// `points_completed / points_total * 100`; `0.0` when `points_total`
    /// is `0` (no leaf descendants yet, e.g. an empty phase).
    pub progress_pct: f64,
    /// Critical Path Method result — see `critical_path.rs` for the
    /// algorithm and its documented scope (`finish_to_start` dependencies
    /// only). `false`/`None` (not an error) when the project's dependency
    /// graph has a cycle, or when this item isn't part of the dependency
    /// network at all (an isolated item's float is trivially `0`, so it IS
    /// still marked critical — only a genuine cycle degrades to `None`).
    pub is_critical_path: bool,
    pub total_float_days: Option<i64>,
}

impl std::fmt::Debug for WorkItemRollupRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkItemRollupRow").finish_non_exhaustive()
    }
}

/// `GET /api/v1/program/{id}/summary` — same D-368 read-time-rollup rule as
/// `ProjectSummaryResponse`, one level up: every number here is computed
/// fresh from the program's own child projects, never a stored aggregate.
#[derive(Serialize, ToSchema)]
pub struct ProgramSummaryResponse {
    pub program_id: Uuid,
    pub project_count: i64,
    /// `points_completed / points_total * 100` across every leaf work item
    /// of every project under this program; `0.0` when there are none yet.
    pub weighted_progress_pct: f64,
    pub points_completed: i64,
    pub points_total: i64,
    pub health_green: i64,
    pub health_amber: i64,
    pub health_red: i64,
    pub budget_amount_total: Option<f64>,
    pub budget_consumed_total: Option<f64>,
    /// Same `is_sensitive`-derived security gate as
    /// `ProjectSummaryResponse::actual_cost` — `None` unless the caller
    /// holds read access to `project_resource_rate`.
    pub actual_cost_total: Option<f64>,
}

impl std::fmt::Debug for ProgramSummaryResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramSummaryResponse")
            .finish_non_exhaustive()
    }
}

/// `GET /api/v1/portfolio/{id}/summary` — same rule, rolled up one level
/// further: every program under the portfolio, and every project under each
/// of those programs.
#[derive(Serialize, ToSchema)]
pub struct PortfolioSummaryResponse {
    pub portfolio_id: Uuid,
    pub program_count: i64,
    pub project_count: i64,
    pub weighted_progress_pct: f64,
    pub points_completed: i64,
    pub points_total: i64,
    pub health_green: i64,
    pub health_amber: i64,
    pub health_red: i64,
    pub budget_amount_total: Option<f64>,
    pub budget_consumed_total: Option<f64>,
    pub actual_cost_total: Option<f64>,
}

impl std::fmt::Debug for PortfolioSummaryResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortfolioSummaryResponse")
            .finish_non_exhaustive()
    }
}

/// One row of `GET /api/v1/resources/capacity` — a single resource's
/// capacity/demand picture over the requested `[from, to]` period (M72).
/// See `capacity.rs`'s module doc for the exact arithmetic behind each
/// field — in short: `capacity_hours` is the platform's default business
/// calendar over the period, net of approved leave; `allocated_hours` is
/// `resource_allocation.allocation_percent` prorated by date overlap;
/// `actual_hours` is `project_time_entry.hours`, unrelated to either.
#[derive(Serialize, ToSchema)]
pub struct CapacityRow {
    pub resource_id: Uuid,
    /// `user_account.user_name` — `None` for a legacy row with no
    /// username set, same optionality the column itself carries.
    pub resource_name: Option<String>,
    /// Business-calendar working hours over `[from, to]`, net of any
    /// `resource_availability` leave overlapping the period.
    pub capacity_hours: f64,
    /// `SUM(allocation_percent / 100 * capacity_hours * overlap_days /
    /// period_days)` across every `resource_allocation` row overlapping
    /// the period — prorated against the period's nominal (pre-leave)
    /// capacity, not the leave-adjusted figure above; see `capacity.rs`.
    pub allocated_hours: f64,
    /// `SUM(hours)` from `project_time_entry` for this resource, entries
    /// dated within `[from, to]` — what was actually logged, independent of
    /// what was planned.
    pub actual_hours: f64,
    /// `allocated_hours / capacity_hours * 100`; `0.0` when `capacity_hours`
    /// is `0` (e.g. a period with no working days at all, or a resource on
    /// leave for the whole period) rather than a division-by-zero `NaN`.
    pub utilization_pct: f64,
    /// `allocated_hours > capacity_hours` — the resource is committed past
    /// what the period's business calendar (net of leave) can deliver.
    pub over_allocated: bool,
}

impl std::fmt::Debug for CapacityRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapacityRow").finish_non_exhaustive()
    }
}
