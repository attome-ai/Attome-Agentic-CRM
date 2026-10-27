//! Search quality metrics (roadmap A25-T8), from the impression log
//! (`search_impression`, TODO-021) over a window of days:
//!
//! - **zero-result rate**: the share of searches that answered nothing;
//! - **refinement rate**: the share of searches the same person followed
//!   with another search within [`REFINEMENT_SECONDS`], the usual sign the
//!   first answer did not help.
//!
//! Per entity, the refinement rate of the searches whose results showed that
//! entity. Searches with no caller (none today) are counted but never
//! refined. The log keeps query fingerprints only, never query text.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// A search followed by another from the same person within this many
/// seconds was refined.
pub const REFINEMENT_SECONDS: i64 = 30;
/// The window when the request names none.
pub const DEFAULT_DAYS: i64 = 30;
/// The longest window.
pub const MAX_DAYS: i64 = 365;
/// Most entities listed.
const MAX_ENTITIES: i64 = 100;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct QualityQuery {
    /// Days back from now, 1 to 365; 30 when absent.
    pub days: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct EntitySearchQuality {
    pub entity: String,
    /// Searches whose results showed this entity.
    pub searches: i64,
    pub refinement_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SearchQuality {
    pub days: i64,
    pub searches: i64,
    pub zero_result_rate: f64,
    pub refinement_rate: f64,
    pub by_entity: Vec<EntitySearchQuality>,
}

/// `part / whole`, 0 for an empty whole. Pure.
pub fn rate(part: i64, whole: i64) -> f64 {
    if whole <= 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// The metrics over the last `days`.
pub async fn quality(state: &EngineState, days: i64) -> Result<SearchQuality, AppError> {
    let days = days.clamp(1, MAX_DAYS);
    let db = &state.base.db;
    // One pass marks each search refined or not; the totals and the
    // per-entity rates read the same marks.
    let marked = "WITH searches AS ( \
           SELECT i.id, i.result_count, \
                  COALESCE(LEAD(i.created_at) OVER (PARTITION BY i.caller_ref ORDER BY i.created_at) \
                           <= i.created_at + make_interval(secs => $2), false) \
                    AND i.caller_ref IS NOT NULL AS refined \
             FROM search_impression i \
            WHERE i.created_at >= now() - make_interval(days => $1) \
         )";
    let (searches, zero, refined): (i64, i64, i64) = sqlx::query_as(&format!(
        "{marked} SELECT COUNT(*), COUNT(*) FILTER (WHERE result_count = 0), \
                COUNT(*) FILTER (WHERE refined) FROM searches"
    ))
    .bind(i32::try_from(days).map_err(AppError::internal)?)
    .bind(REFINEMENT_SECONDS as f64)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(&format!(
        "{marked} SELECT r.entity_logicalname, COUNT(DISTINCT s.id), \
                COUNT(DISTINCT s.id) FILTER (WHERE s.refined) \
           FROM searches s JOIN search_impression_row r ON r.impression_ref = s.id \
          GROUP BY r.entity_logicalname ORDER BY 2 DESC, 1 LIMIT $3"
    ))
    .bind(i32::try_from(days).map_err(AppError::internal)?)
    .bind(REFINEMENT_SECONDS as f64)
    .bind(MAX_ENTITIES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(SearchQuality {
        days,
        searches,
        zero_result_rate: rate(zero, searches),
        refinement_rate: rate(refined, searches),
        by_entity: rows
            .into_iter()
            .map(|(entity, n, refined)| EntitySearchQuality {
                entity,
                searches: n,
                refinement_rate: rate(refined, n),
            })
            .collect(),
    })
}

/// Search quality
///
/// A25-T8: the zero-result and refinement rates of searches over the last
/// `days` (30 by default), overall and per entity shown in results, from the
/// impression log. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/search/quality",
    tag = "search",
    params(QualityQuery),
    responses(
        (status = 200, description = "The rates", body = SearchQuality),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_quality(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(query): Query<QualityQuery>,
) -> Result<Json<SearchQuality>, AppError> {
    Ok(Json(
        quality(&state, query.days.unwrap_or(DEFAULT_DAYS)).await?,
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/search/quality", get(get_quality))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_quality),
    components(schemas(SearchQuality, EntitySearchQuality))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_are_shares_and_empty_is_zero() {
        assert_eq!(rate(1, 4), 0.25);
        assert_eq!(rate(0, 0), 0.0);
        assert_eq!(rate(3, 3), 1.0);
    }
}
