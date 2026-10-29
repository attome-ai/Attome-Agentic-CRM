//! P9-T12: the scorecard and comment reads.
//!
//! - `GET /api/v1/metrics/scorecards/{id}`: a scorecard (read as the caller,
//!   through the record API's own checks) with each of its metrics the caller
//!   may see (`governance`): the newest total snapshot, its status, the
//!   period's target and its freshness. Stored snapshots only: nothing is
//!   computed on read. A snapshot is stale when it is older than twice its
//!   metric's period ([`is_stale`]) and failed when it carries an error.
//! - `GET /api/v1/metrics/{id}/comments`: the metric's comments the caller
//!   may read, newest first, optionally for one period.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::auth::MetricRead;

/// Comments read per metric before the page is cut.
const MAX_COMMENTS: i64 = 1_000;

/// A period's nominal length in days, for staleness. Pure.
pub fn period_days(period: &str) -> i64 {
    match period {
        "day" => 1,
        "week" => 7,
        "month" => 31,
        "quarter" => 92,
        "year" => 366,
        _ => 31,
    }
}

/// Whether a snapshot computed at `computed_at` is stale at `now`: older
/// than twice its metric's period. Pure.
pub fn is_stale(period: &str, computed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now - computed_at > chrono::Duration::days(2 * period_days(period))
}

/// How fresh a metric's newest value is.
#[derive(Debug, Serialize, ToSchema)]
pub struct Freshness {
    pub computed_at: Option<DateTime<Utc>>,
    /// No value, or the newest is older than twice the period.
    pub is_stale: bool,
    /// The newest value failed to compute.
    pub failed: bool,
}

/// One metric on a scorecard.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScorecardItem {
    pub metric_id: Uuid,
    pub name: String,
    pub key: String,
    pub period: String,
    pub unit: Option<String>,
    pub sort_order: Option<f64>,
    /// The newest total value: its period, value and status.
    pub period_start: Option<NaiveDate>,
    pub actual: Option<f64>,
    pub status: Option<String>,
    /// That period's total target.
    pub target: Option<f64>,
    pub freshness: Freshness,
}

/// A scorecard and its metrics.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScorecardRead {
    pub id: Uuid,
    pub name: Option<String>,
    pub description: Option<String>,
    pub items: Vec<ScorecardItem>,
}

type ItemRow = (
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Option<f64>,
    Option<NaiveDate>,
    Option<f64>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<f64>,
);

/// Read a scorecard
///
/// The scorecard with each metric's newest total value, status, target and freshness, from stored
/// values only. Metrics the caller may not see are left out. Anyone who may read the scorecard and
/// metric definitions.
#[utoipa::path(
    get,
    path = "/api/v1/metrics/scorecards/{id}",
    operation_id = "read_metric_scorecard",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The scorecard")),
    responses(
        (status = 200, description = "Success", body = ScorecardRead),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such scorecard", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_scorecard(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricRead>>,
    Path(scorecard_id): Path<Uuid>,
) -> Result<Json<ScorecardRead>, AppError> {
    let scorecard =
        attome_records::entity_crud::read_record(&state, &ctx, "metric_scorecard", scorecard_id)
            .await?;
    let field = |name: &str| {
        scorecard
            .data()
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };
    let roles = crate::governance::role_names(&state.base.db, ctx.user_id).await?;
    let rows: Vec<ItemRow> = sqlx::query_as(&format!(
        "SELECT d.id, d.name, d.key, d.period, d.unit, i.sort_order::double precision, \
                s.period_start, s.actual, s.status, s.computed_at, s.error_message, \
                (SELECT t.target_value::double precision FROM dashboard_metric_target t \
                  WHERE t.metric_ref = d.id AND t.period_start = s.period_start \
                    AND (t.is_active IS NULL OR t.is_active = true) \
                    AND COALESCE(to_jsonb(t)->>'dimension_value', '') = '' \
                  ORDER BY t.created_at DESC LIMIT 1) \
           FROM metric_scorecard_item i \
           JOIN dashboard_metric_definition d ON d.id = i.metric_ref \
           LEFT JOIN LATERAL ( \
                SELECT period_start, actual, status, computed_at, error_message \
                  FROM metric_snapshot \
                 WHERE metric_ref = d.id AND dimension_attribute IS NULL \
                 ORDER BY period_start DESC, computed_at DESC, id DESC LIMIT 1) s ON true \
          WHERE i.scorecard_ref = $1 \
            AND (i.is_active IS NULL OR i.is_active = true) \
            AND (d.is_active IS NULL OR d.is_active = true) \
            AND {} \
          ORDER BY i.sort_order NULLS LAST, d.name",
        crate::governance::visible_clause(2, 3)
    ))
    .bind(scorecard_id)
    .bind(ctx.is_admin)
    .bind(&roles)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let items = rows
        .into_iter()
        .map(
            |(
                metric_id,
                name,
                key,
                period,
                unit,
                sort_order,
                period_start,
                actual,
                status,
                computed_at,
                error_message,
                target,
            )| {
                let freshness = Freshness {
                    computed_at,
                    is_stale: computed_at.is_none_or(|at| is_stale(&period, at, now)),
                    failed: error_message.is_some(),
                };
                ScorecardItem {
                    metric_id,
                    name,
                    key,
                    period,
                    unit,
                    sort_order,
                    period_start,
                    actual,
                    status,
                    target,
                    freshness,
                }
            },
        )
        .collect();
    Ok(Json(ScorecardRead {
        id: scorecard_id,
        name: field("name"),
        description: field("description"),
        items,
    }))
}

/// A comment list's page and period.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CommentListQuery {
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    #[param(minimum = 1)]
    pub page_size: Option<i64>,
    /// Only the comments on this period.
    pub period_start: Option<NaiveDate>,
}

/// One comment on a metric.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricComment {
    pub id: Uuid,
    pub body: Option<String>,
    pub period_start: Option<DateTime<Utc>>,
    pub dimension_value: Option<String>,
    pub author_ref: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

type CommentRow = (
    Uuid,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<Uuid>,
    DateTime<Utc>,
);

/// List a metric's comments
///
/// The comments on the metric the caller may read, newest first, optionally for one period.
/// Anyone who may read metric definitions and the comments.
#[utoipa::path(
    get,
    path = "/api/v1/metrics/{id}/comments",
    operation_id = "list_metric_comments",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The metric"), CommentListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MetricComment>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_comments(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricRead>>,
    Path(metric_id): Path<Uuid>,
    Query(q): Query<CommentListQuery>,
) -> Result<Json<PaginatedResponse<MetricComment>>, AppError> {
    crate::metric::fetch_metric(&state.base.db, metric_id).await?;
    crate::governance::require_visible(&state.base.db, &ctx, metric_id).await?;
    let window = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    let rows: Vec<CommentRow> = sqlx::query_as(
        "SELECT c.id, c.body, c.period_start, c.dimension_value, c.author_ref, c.created_at \
           FROM metric_comment c \
          WHERE c.metric_ref = $1 AND (c.is_active IS NULL OR c.is_active = true) \
            AND ($2::date IS NULL OR c.period_start::date = $2) \
          ORDER BY c.created_at DESC, c.id DESC LIMIT $3",
    )
    .bind(metric_id)
    .bind(q.period_start)
    .bind(MAX_COMMENTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // The caller's record access to each comment, in one batch.
    let entity_id = state
        .entities
        .load()
        .get("metric_comment")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let readable =
        attome_records::changes::readable_ids(&state, &ctx, entity_id, "metric_comment", &ids)
            .await?;
    let visible: Vec<MetricComment> = rows
        .into_iter()
        .filter(|r| readable.contains(&r.0))
        .map(
            |(id, body, period_start, dimension_value, author_ref, created_at)| MetricComment {
                id,
                body,
                period_start,
                dimension_value,
                author_ref,
                created_at,
            },
        )
        .collect();
    let total = i64::try_from(visible.len()).unwrap_or(i64::MAX);
    let page: Vec<MetricComment> = visible
        .into_iter()
        .skip(usize::try_from(window.offset).unwrap_or(0))
        .take(usize::try_from(window.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(
        page,
        total,
        window.page,
        window.page_size,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scorecard_staleness_is_twice_the_period() {
        let now = Utc::now();
        assert!(!is_stale("month", now - chrono::Duration::days(40), now));
        assert!(is_stale("month", now - chrono::Duration::days(63), now));
        assert!(is_stale("day", now - chrono::Duration::days(3), now));
        assert!(!is_stale("year", now - chrono::Duration::days(400), now));
        assert_eq!(period_days("quarter"), 92);
    }
}
