//! E14-T12: a tracked site's visits over the last days, for the tracking
//! screen: how many, how many by a known contact or lead, and the top
//! sources, landing pages and campaigns.
//!
//! Read from `marketing_web_session` (bots left out), so the window reaches
//! back as far as the site keeps sessions (its `retention_days`, E14-T11);
//! older days live only in `marketing_web_daily`. Stored queries cannot
//! read those infrastructure tables, so this is a route rather than saved
//! queries.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::alerts::TrackedSiteRead;

/// The longest window, in days.
pub const MAX_DAYS: i32 = 365;
/// The window when none is asked for.
pub const DEFAULT_DAYS: i32 = 30;
/// Rows per list.
const TOP: i64 = 10;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReportQuery {
    /// The site's key.
    pub site: String,
    /// Days back from now, 1 to 365 (30 by default).
    #[param(minimum = 1, maximum = 365)]
    pub days: Option<i32>,
}

/// One row of a top list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ReportRow {
    pub label: String,
    pub visits: i64,
}

/// A site's visits over the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TrackingReport {
    pub site: String,
    pub days: i32,
    /// Sessions in the window.
    pub visits: i64,
    /// Sessions by a known contact or lead.
    pub identified: i64,
    /// By UTM source, else the referrer's host, else `direct`.
    pub sources: Vec<ReportRow>,
    /// By landing page, without its query or fragment.
    pub landing_pages: Vec<ReportRow>,
    /// By UTM campaign; sessions without one are left out.
    pub campaigns: Vec<ReportRow>,
}

/// The window asked for, clamped. Pure.
pub fn window_days(days: Option<i32>) -> i32 {
    days.unwrap_or(DEFAULT_DAYS).clamp(1, MAX_DAYS)
}

/// A top-ten query over the window's sessions, grouped by `$label`.
macro_rules! top_sql {
    ($label:literal) => {
        concat!(
            "SELECT label, count(*) FROM (SELECT ",
            $label,
            " AS label FROM marketing_web_session \
               WHERE site_key = $1 AND NOT is_bot \
                 AND started_at >= now() - make_interval(days => $2)) v \
              WHERE label IS NOT NULL AND label <> '' \
              GROUP BY label ORDER BY count(*) DESC, label LIMIT $3"
        )
    };
}

/// By UTM source, else the referrer's host, else `direct`.
const SOURCES: &str = top_sql!(
    "COALESCE(NULLIF(btrim(utm_source), ''), \
     substring(referrer from '^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]+)'), 'direct')"
);
/// By landing page, without its query or fragment.
const LANDING_PAGES: &str = top_sql!("split_part(split_part(landing_url, '#', 1), '?', 1)");
/// By UTM campaign.
const CAMPAIGNS: &str = top_sql!("btrim(utm_campaign)");

async fn top(
    state: &EngineState,
    sql: &'static str,
    site: &str,
    days: i32,
) -> Result<Vec<ReportRow>, AppError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(sql)
        .bind(site)
        .bind(days)
        .bind(TOP)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(label, visits)| ReportRow { label, visits })
        .collect())
}

/// The report for `site` over `days`.
pub async fn report(
    state: &EngineState,
    site: &str,
    days: i32,
) -> Result<TrackingReport, AppError> {
    let (visits, identified): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE contact_ref IS NOT NULL OR lead_ref IS NOT NULL) \
           FROM marketing_web_session \
          WHERE site_key = $1 AND NOT is_bot \
            AND started_at >= now() - make_interval(days => $2)",
    )
    .bind(site)
    .bind(days)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(TrackingReport {
        site: site.to_owned(),
        days,
        visits,
        identified,
        sources: top(state, SOURCES, site, days).await?,
        landing_pages: top(state, LANDING_PAGES, site, days).await?,
        campaigns: top(state, CAMPAIGNS, site, days).await?,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/tracking/report",
    operation_id = "get_tracking_report",
    tag = "marketing",
    params(ReportQuery),
    responses(
        (status = 200, description = "The site's visits over the window", body = TrackingReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_tracked_site.read", body = ErrorResponse),
        (status = 422, description = "No site key", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// A site's visits report.
///
/// Visits over the last `days` (30 by default, at most 365), how many were
/// by a known contact or lead, and the top ten sources, landing pages and
/// campaigns. Bots are left out.
pub async fn get_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrackedSiteRead>>,
    Query(q): Query<ReportQuery>,
) -> Result<Json<TrackingReport>, AppError> {
    let site = q.site.trim();
    if site.is_empty() {
        return Err(AppError::Validation("site: required".into()));
    }
    Ok(Json(report(&state, site, window_days(q.days)).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/marketing/tracking/report", get(get_report))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_report), components(schemas(TrackingReport, ReportRow)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_clamped() {
        assert_eq!(window_days(None), DEFAULT_DAYS);
        assert_eq!(window_days(Some(0)), 1);
        assert_eq!(window_days(Some(7)), 7);
        assert_eq!(window_days(Some(5000)), MAX_DAYS);
    }
}
