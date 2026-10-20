//! Landing page conversions (roadmap E11-T1): for a page path, the unique
//! visitors the website tracking saw on it (E14, `marketing_web_event`
//! page views, by visitor id) and the form submissions sent from it (E10,
//! `marketing_form_submission.page_url`), over a period. A conversion is a
//! submission from the page; the rate is conversions over unique visitors.
//!
//! Paths compare without scheme, host, query, fragment or a trailing slash,
//! so `https://www.example.com/offer/?utm_source=x` counts for `/offer`.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// `marketing_form.read` — who may read a form's results.
#[derive(Debug)]
pub struct FormRead;

impl PrivilegeKey for FormRead {
    const KEY: &'static str = "marketing_form.read";
}

/// The path part of a page URL or path, without query, fragment or a
/// trailing slash; `/` for the root. `None` for an empty value. Pure.
pub fn page_path(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let rest = match url.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("/", |i| &rest[i..]),
        None => url,
    };
    let path = rest.split(['?', '#']).next().unwrap_or("/");
    let path = path.trim_end_matches('/');
    Some(if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    })
}

/// Conversions over unique visitors, as a fraction; `None` with no
/// visitors. Pure.
pub fn conversion_rate(visitors: i64, conversions: i64) -> Option<f64> {
    (visitors > 0).then(|| conversions as f64 / visitors as f64)
}

/// One landing page's results over a period.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct LandingStats {
    pub path: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub unique_visitors: i64,
    pub conversions: i64,
    /// Conversions over unique visitors; absent with no visitors.
    pub conversion_rate: Option<f64>,
}

/// The page's unique visitors and conversions in [`from`, `to`).
pub async fn page_stats(
    state: &EngineState,
    path: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<LandingStats, AppError> {
    let path = page_path(path).ok_or_else(|| AppError::Validation("path is required".into()))?;
    let db = &state.base.db_readonly;
    // The stored URLs are full; the path is compared after the host, with
    // the query, fragment and a trailing slash removed, the way `page_path`
    // does.
    let visitors: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT visitor_id) FROM marketing_web_event \
          WHERE kind = 'page_view' AND occurred_at >= $2 AND occurred_at < $3 \
            AND COALESCE(NULLIF(rtrim(split_part(split_part( \
                    regexp_replace(url, '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*', ''), '?', 1), '#', 1), '/'), ''), '/') = $1",
    )
    .bind(&path)
    .bind(from)
    .bind(to)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let conversions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_form_submission \
          WHERE created_at >= $2 AND created_at < $3 AND is_active IS NOT FALSE \
            AND COALESCE(NULLIF(rtrim(split_part(split_part( \
                    regexp_replace(page_url, '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*', ''), '?', 1), '#', 1), '/'), ''), '/') = $1",
    )
    .bind(&path)
    .bind(from)
    .bind(to)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(LandingStats {
        conversion_rate: conversion_rate(visitors, conversions),
        path,
        from,
        to,
        unique_visitors: visitors,
        conversions,
    })
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    /// The landing page's path (or full URL).
    pub path: String,
    /// The start, inclusive; 30 days before `to` by default.
    pub from: Option<DateTime<Utc>>,
    /// The end, exclusive; now by default.
    pub to: Option<DateTime<Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/landing/stats",
    operation_id = "get_marketing_landing_stats",
    tag = "marketing",
    params(StatsQuery),
    responses(
        (status = 200, description = "The page's unique visitors and conversions", body = LandingStats),
        (status = 403, description = "The caller may not read marketing forms", body = ErrorResponse),
        (status = 422, description = "No path, or the period ends before it starts or spans over a year", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Landing page results.
///
/// Unique visitors (website tracking page views) and conversions (form
/// submissions from the page) for one page path over a period of at most a
/// year, 30 days by default.
async fn get_stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<FormRead>>,
    Query(q): Query<StatsQuery>,
) -> Result<Json<LandingStats>, AppError> {
    let to = q.to.unwrap_or_else(Utc::now);
    let from = q.from.unwrap_or(to - Duration::days(30));
    if from >= to || to - from > Duration::days(366) {
        return Err(AppError::Validation(
            "the period must start before it ends and span at most a year".into(),
        ));
    }
    Ok(Json(page_stats(&state, &q.path, from, to).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/marketing/landing/stats", get(get_stats))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_stats), components(schemas(LandingStats)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landing_conversion_paths_match_without_host_query_or_slash() {
        assert_eq!(
            page_path("https://www.example.com/offer/?utm_source=x#form").as_deref(),
            Some("/offer")
        );
        assert_eq!(page_path("http://example.com").as_deref(), Some("/"));
        assert_eq!(page_path("/offer/").as_deref(), Some("/offer"));
        assert_eq!(page_path("offer").as_deref(), Some("/offer"));
        assert_eq!(page_path("/").as_deref(), Some("/"));
        assert_eq!(page_path("  "), None);
    }

    #[test]
    fn landing_conversion_rate_is_conversions_over_unique_visitors() {
        assert_eq!(conversion_rate(200, 30), Some(0.15));
        assert_eq!(conversion_rate(0, 3), None);
        assert_eq!(conversion_rate(10, 0), Some(0.0));
    }
}
