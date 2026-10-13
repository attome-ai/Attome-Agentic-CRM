//! Baseline variance and Earned Value Management (EVM) for
//! `GET /api/v1/project/{id}/summary` (M69 master-plan §4: "Baseline
//! variance on the rollup + summary routes" / "EVM ... on the summary
//! route").
//!
//! **Compared against the most recently captured baseline** (`POST
//! /project/{id}/baseline`, `baseline.rs`) — `None` throughout when no
//! baseline has ever been captured for this project.
//!
//! **Points stand in for budget as the progress measure, because there is
//! nothing else to use.** `project_work_item` carries no per-item cost
//! field (`baseline.rs`'s own doc comment explains why
//! `project_baseline_item.planned_budget` is always `NULL`), so a
//! textbook EVM implementation — summing each *task's own* planned value —
//! is not possible with this schema. What this module computes instead is
//! the standard fallback every EVM guide gives when tasks aren't individually
//! budgeted: treat the project's total `budget_amount` as the Budget at
//! Completion (BAC), and use the *fraction of scope* (here, baseline
//! points, the same unit `work_plan.rs`'s own progress already uses) that
//! is planned-complete or actually-complete to convert a completion
//! fraction into a dollar figure. Earned Value in particular is exactly the
//! standard "EV = BAC × % complete" formula — nothing project-specific
//! about that one. Planned Value's "% planned complete as of today" is
//! genuinely a simplification (it should come from a time-phased plan, not
//! a single planned_due-per-item snapshot), documented as such on
//! [`ProjectSummaryResponse::planned_value`].
//!
//! **Security posture inherits `actual_cost`'s existing gate.** Every field
//! here that is a function of Actual Cost (`cost_performance_index`,
//! `estimate_at_completion`, `estimate_to_complete`, `variance_at_completion`)
//! is `None` whenever `actual_cost` itself is `None` — i.e. whenever the
//! caller cannot read `project_resource_rate` — the same rule
//! `summary.rs::actual_cost`'s own doc comment states. `planned_value`/
//! `earned_value`/`schedule_performance_index` do not depend on actual cost
//! and are visible to any caller who can see the summary at all.
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub(crate) struct LatestBaseline {
    pub id: Uuid,
    pub label: String,
    pub captured_at: DateTime<Utc>,
}

pub(crate) async fn latest_baseline(
    db: &DbPool,
    project_id: Uuid,
) -> Result<Option<LatestBaseline>, AppError> {
    sqlx::query_as::<_, LatestBaseline>(
        "SELECT id, label, captured_at FROM project_baseline \
         WHERE project_id = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY captured_at DESC LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[derive(sqlx::FromRow)]
pub(crate) struct BaselineAggregate {
    pub item_count: i64,
    pub planned_finish: Option<DateTime<Utc>>,
    /// Fraction (0..1) of baseline points whose `planned_due` has already
    /// passed — `None` when the baseline captured no points at all (every
    /// item's `points` was `NULL`/0, or the baseline has no items).
    pub planned_value_fraction: Option<f64>,
}

pub(crate) async fn baseline_aggregate(
    db: &DbPool,
    baseline_id: Uuid,
) -> Result<BaselineAggregate, AppError> {
    #[derive(sqlx::FromRow)]
    struct Raw {
        item_count: i64,
        planned_finish: Option<DateTime<Utc>>,
        planned_points_due: f64,
        planned_points_total: f64,
    }
    let raw = sqlx::query_as::<_, Raw>(
        "SELECT COUNT(*)::bigint AS item_count, \
                MAX(planned_due) AS planned_finish, \
                COALESCE(SUM(planned_points) FILTER (WHERE planned_due <= NOW()), 0)::double precision AS planned_points_due, \
                COALESCE(SUM(planned_points), 0)::double precision AS planned_points_total \
         FROM project_baseline_item \
         WHERE baseline_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(baseline_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    let planned_value_fraction = if raw.planned_points_total > 0.0 {
        Some(raw.planned_points_due / raw.planned_points_total)
    } else {
        None
    };
    Ok(BaselineAggregate {
        item_count: raw.item_count,
        planned_finish: raw.planned_finish,
        planned_value_fraction,
    })
}

/// Every active `project_work_item` (not leaf-only — matches
/// `baseline.rs::active_work_items`'s own "every active item" scope, so
/// this count is directly comparable to a captured baseline's
/// `item_count`).
pub(crate) async fn active_work_item_count(db: &DbPool, project_id: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM project_work_item \
         WHERE project_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(project_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct EvmResult {
    pub planned_value: Option<f64>,
    pub earned_value: Option<f64>,
    pub cost_performance_index: Option<f64>,
    pub schedule_performance_index: Option<f64>,
    pub estimate_at_completion: Option<f64>,
    pub estimate_to_complete: Option<f64>,
    pub variance_at_completion: Option<f64>,
}

/// Pure arithmetic, no I/O — see this module's doc comment for the formulas
/// and what each `None` case means.
pub(crate) fn compute_evm(
    budget_amount: Option<f64>,
    weighted_progress_pct: f64,
    actual_cost: Option<f64>,
    planned_value_fraction: Option<f64>,
) -> EvmResult {
    let bac = budget_amount;
    let ev = bac.map(|b| b * weighted_progress_pct / 100.0);
    let pv = match (bac, planned_value_fraction) {
        (Some(b), Some(f)) => Some(b * f),
        _ => None,
    };
    let cpi = match (ev, actual_cost) {
        (Some(e), Some(ac)) if ac > 0.0 => Some(e / ac),
        _ => None,
    };
    let spi = match (ev, pv) {
        (Some(e), Some(p)) if p > 0.0 => Some(e / p),
        _ => None,
    };
    let eac = match (bac, cpi) {
        (Some(b), Some(c)) if c > 0.0 => Some(b / c),
        _ => None,
    };
    let etc = match (eac, actual_cost) {
        (Some(e), Some(ac)) => Some(e - ac),
        _ => None,
    };
    let vac = match (bac, eac) {
        (Some(b), Some(e)) => Some(b - e),
        _ => None,
    };
    EvmResult {
        planned_value: pv,
        earned_value: ev,
        cost_performance_index: cpi,
        schedule_performance_index: spi,
        estimate_at_completion: eac,
        estimate_to_complete: etc,
        variance_at_completion: vac,
    }
}

pub(crate) fn schedule_variance_days(
    baseline_planned_finish: Option<DateTime<Utc>>,
    forecast_date: Option<DateTime<Utc>>,
) -> Option<i64> {
    match (baseline_planned_finish, forecast_date) {
        (Some(planned), Some(forecast)) => Some((planned - forecast).num_days()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_budget_means_everything_evm_is_none() {
        let r = compute_evm(None, 50.0, Some(100.0), Some(0.5));
        assert_eq!(r, EvmResult::default());
    }

    #[test]
    fn textbook_case_matches_hand_computed_values() {
        // BAC=1000, 40% complete -> EV=400. Planned 50% by now -> PV=500.
        // AC=320 -> CPI = 400/320 = 1.25, SPI = 400/500 = 0.8.
        // EAC = 1000/1.25 = 800, ETC = 800-320 = 480, VAC = 1000-800 = 200.
        let r = compute_evm(Some(1000.0), 40.0, Some(320.0), Some(0.5));
        assert_eq!(r.earned_value, Some(400.0));
        assert_eq!(r.planned_value, Some(500.0));
        assert_eq!(r.cost_performance_index, Some(1.25));
        assert_eq!(r.schedule_performance_index, Some(0.8));
        assert_eq!(r.estimate_at_completion, Some(800.0));
        assert_eq!(r.estimate_to_complete, Some(480.0));
        assert_eq!(r.variance_at_completion, Some(200.0));
    }

    #[test]
    fn no_actual_cost_access_hides_every_cost_derived_field_but_not_schedule() {
        let r = compute_evm(Some(1000.0), 40.0, None, Some(0.5));
        assert_eq!(r.earned_value, Some(400.0));
        assert_eq!(r.planned_value, Some(500.0));
        assert_eq!(r.schedule_performance_index, Some(0.8));
        assert_eq!(r.cost_performance_index, None);
        assert_eq!(r.estimate_at_completion, None);
        assert_eq!(r.estimate_to_complete, None);
        assert_eq!(r.variance_at_completion, None);
    }

    #[test]
    fn zero_actual_cost_is_not_a_division_by_zero() {
        let r = compute_evm(Some(1000.0), 10.0, Some(0.0), Some(0.1));
        assert_eq!(r.cost_performance_index, None);
        assert_eq!(r.estimate_at_completion, None);
    }

    #[test]
    fn zero_planned_value_is_not_a_division_by_zero() {
        let r = compute_evm(Some(1000.0), 10.0, Some(50.0), Some(0.0));
        assert_eq!(r.planned_value, Some(0.0));
        assert_eq!(r.schedule_performance_index, None);
    }

    #[test]
    fn schedule_variance_positive_means_ahead_of_baseline() {
        let planned = Utc::now();
        let forecast = planned - chrono::Duration::days(5);
        assert_eq!(
            schedule_variance_days(Some(planned), Some(forecast)),
            Some(5)
        );
    }

    #[test]
    fn schedule_variance_none_without_both_dates() {
        assert_eq!(schedule_variance_days(None, Some(Utc::now())), None);
        assert_eq!(schedule_variance_days(Some(Utc::now()), None), None);
    }
}
