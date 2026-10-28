//! `GET /api/v1/admin/ai/spend` (roadmap N24-T2): what generation has cost
//! this rolling month against each money cap, and where the month is heading.
//!
//! Reads the same counters the budget guard reserves against
//! (`budget_guard::spend_windows`, `attome-ai:spend:{scope}:{id}`), so the
//! report and the enforcement cannot disagree. Lines: the deployment, each
//! capped feature, and each agent that ran a session inside the window.
//! Amounts are in the unit the prices are written in. The forecast is the
//! month's spend so far scaled to the whole window from the age of the
//! oldest counted bucket (at least one day, so a fresh window does not
//! project a few minutes' spend into a month).

use std::time::Duration;

use attome_cache::token_window;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::budget_guard::{SPEND_WINDOW, SpendWindow, spend_windows};

/// The most agent lines one report carries.
const MAX_AGENT_LINES: i64 = 200;

/// One money window's month so far.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SpendLine {
    /// `spend_deployment`, `spend_feature` or `spend_agent`.
    pub scope: String,
    /// The feature id or agent id; empty for the deployment.
    pub key: String,
    /// Spent inside the window, in the price unit.
    pub spent: f64,
    /// The cap, in the price unit.
    pub cap: f64,
    /// `spent` as a percentage of `cap` (100 or more: refusing).
    pub percent: f64,
    /// Where the window's spend is heading over a whole month.
    pub forecast: f64,
}

/// The whole report.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SpendReport {
    /// The generation model the prices apply to.
    pub model: String,
    /// Whether that model has a price; without one nothing is counted.
    pub priced: bool,
    /// Percent of a cap at which generations are shortened.
    pub degrade_at_percent: u8,
    /// The window, in days.
    pub window_days: u64,
    pub lines: Vec<SpendLine>,
}

/// One report line from a window's counter.
pub fn line(window: &SpendWindow, consumed_micros: u64, elapsed: Duration) -> SpendLine {
    let spent = consumed_micros as f64 / 1_000_000.0;
    let cap = window.limit as f64 / 1_000_000.0;
    let percent = if cap > 0.0 {
        spent / cap * 100.0
    } else if spent > 0.0 {
        100.0
    } else {
        0.0
    };
    let day = Duration::from_secs(24 * 60 * 60);
    let elapsed = elapsed.max(day).min(SPEND_WINDOW);
    let forecast = spent * SPEND_WINDOW.as_secs_f64() / elapsed.as_secs_f64();
    let key = window
        .key
        .rsplit_once(':')
        .map(|(_, id)| id)
        .filter(|_| window.scope != "spend_deployment")
        .unwrap_or_default()
        .to_owned();
    SpendLine {
        scope: window.scope.to_owned(),
        key,
        spent: round2(spent),
        cap: round2(cap),
        percent: round2(percent),
        forecast: round2(forecast),
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// Read AI spend
///
/// What generation has cost this rolling month against each money cap (the deployment, each capped
/// feature, each agent that ran), from the counters the budget guard enforces, and where the month is
/// heading. AI administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/spend",
    tag = "action",
    responses(
        (status = 200, description = "This month's AI spend against each cap", body = SpendReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn spend_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<SpendReport>, AppError> {
    let spend = &state.base.config.inference.spend;
    let model = state.base.config.inference.generation.model.clone();
    let priced = crate::budget_guard::model_price(&state).await?.is_some();
    let mut windows: Vec<SpendWindow> = Vec::new();
    // The deployment's own window is the one every generation shares.
    windows.extend(
        spend_windows(spend, None, None, "")
            .into_iter()
            .filter(|w| w.scope == "spend_deployment"),
    );
    for feature in spend.feature_monthly.keys() {
        windows.extend(
            spend_windows(spend, None, None, feature)
                .into_iter()
                .filter(|w| w.scope == "spend_feature"),
        );
    }
    if spend.agent_monthly.is_some() {
        let window_days = i64::try_from(SPEND_WINDOW.as_secs() / 86_400).unwrap_or(30);
        let agents: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT agent_object_ref FROM agent_session \
             WHERE agent_object_ref IS NOT NULL \
               AND started_at > now() - make_interval(days => $1::int) \
             LIMIT $2",
        )
        .bind(window_days)
        .bind(MAX_AGENT_LINES)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for agent in agents {
            windows.extend(
                spend_windows(spend, None, Some(agent), "")
                    .into_iter()
                    .filter(|w| w.scope == "spend_agent"),
            );
        }
    }
    let mut lines = Vec::with_capacity(windows.len());
    for window in &windows {
        let held =
            token_window::read(&state.base.redis_coordination, &window.key, SPEND_WINDOW).await?;
        lines.push(line(window, held.consumed, held.elapsed));
    }
    Ok(Json(SpendReport {
        model,
        priced,
        degrade_at_percent: spend.degrade_at_percent,
        window_days: SPEND_WINDOW.as_secs() / 86_400,
        lines,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/ai/spend", get(spend_report))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(spend_report), components(schemas(SpendReport, SpendLine)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(scope: &'static str, key: &str, cap_micros: u64) -> SpendWindow {
        SpendWindow {
            key: key.to_owned(),
            limit: cap_micros,
            scope,
        }
    }

    #[test]
    fn a_line_shows_spend_percent_and_forecast() {
        let deployment = window(
            "spend_deployment",
            "attome-ai:spend:deployment",
            100_000_000,
        );
        // 30 spent in 10 days: on course for 90 over the month.
        let ten_days = Duration::from_secs(10 * 86_400);
        let l = line(&deployment, 30_000_000, ten_days);
        assert_eq!(l.spent, 30.0);
        assert_eq!(l.cap, 100.0);
        assert_eq!(l.percent, 30.0);
        assert_eq!(l.forecast, 90.0);
        assert_eq!(l.key, "", "the deployment line has no key");
    }

    #[test]
    fn a_fresh_window_forecasts_from_at_least_a_day() {
        let feature = window(
            "spend_feature",
            "attome-ai:spend:feature:record.summarize",
            10_000_000,
        );
        let l = line(&feature, 1_000_000, Duration::from_secs(60));
        assert_eq!(l.key, "record.summarize");
        assert_eq!(l.forecast, 30.0, "one day's spend times thirty");
        let zero_cap = window("spend_feature", "attome-ai:spend:feature:x", 0);
        assert_eq!(line(&zero_cap, 1, Duration::ZERO).percent, 100.0);
        assert_eq!(line(&zero_cap, 0, Duration::ZERO).percent, 0.0);
    }
}
