//! `GET /api/v1/admin/approvals/metrics` (roadmap N30-T8, T9): how approvals
//! are going, and who may be approving without looking.
//!
//! Computed when asked from `approval_request` and `approval_grant` over the
//! last `days` (default 30, at most 365), so there is no nightly job to keep
//! in step: per approver, decisions, the share approved and the median time
//! from request to decision; per action type, the backlog and its oldest
//! pending request; and the rejection comments' most common words.
//!
//! **Rubber-stamp warning.** An approver with at least
//! [`STAMP_MIN_DECISIONS`] decisions who approved at least
//! [`STAMP_APPROVE_SHARE`] of them with a median under
//! [`STAMP_MEDIAN_SECONDS`] seconds is flagged: either the requests are
//! routine enough for a write policy to drop, or nobody is reading them. A
//! warning is a prompt to look, never an automatic change.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

pub const STAMP_MIN_DECISIONS: i64 = 10;
pub const STAMP_APPROVE_SHARE: f64 = 0.95;
pub const STAMP_MEDIAN_SECONDS: f64 = 30.0;

#[derive(Debug, Deserialize, IntoParams)]
pub struct MetricsQuery {
    /// Days back from now, 1 to 365; default 30.
    #[serde(default)]
    pub days: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ApproverFigures {
    pub approver_id: Uuid,
    pub decisions: i64,
    pub approved: i64,
    /// Median seconds from request to this approver's decision.
    pub median_seconds: Option<f64>,
    /// The rubber-stamp warning (see the module doc).
    #[sqlx(skip)]
    pub warning: bool,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct Backlog {
    pub action_type: String,
    pub pending: i64,
    pub oldest: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct RejectionWord {
    pub word: String,
    pub count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApprovalMetrics {
    pub days: i32,
    pub approvers: Vec<ApproverFigures>,
    pub backlog: Vec<Backlog>,
    pub rejection_words: Vec<RejectionWord>,
}

/// The rubber-stamp rule.
pub fn rubber_stamp(decisions: i64, approved: i64, median_seconds: Option<f64>) -> bool {
    if decisions < STAMP_MIN_DECISIONS {
        return false;
    }
    #[allow(clippy::cast_precision_loss, reason = "decision counts are small")]
    let share = approved as f64 / decisions as f64;
    share >= STAMP_APPROVE_SHARE && median_seconds.is_some_and(|m| m < STAMP_MEDIAN_SECONDS)
}

/// `GET /api/v1/admin/approvals/metrics`
#[utoipa::path(
    get,
    path = "/api/v1/admin/approvals/metrics",
    tag = "admin",
    params(MetricsQuery),
    responses(
        (status = 200, description = "Approval figures and rubber-stamp warnings", body = ApprovalMetrics),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn approval_metrics(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<MetricsQuery>,
) -> Result<Json<ApprovalMetrics>, AppError> {
    let days = query.days.unwrap_or(30).clamp(1, 365);
    let db = &state.base.db;
    let mut approvers: Vec<ApproverFigures> = sqlx::query_as(
        "SELECT g.approver_id, \
                COUNT(*) AS decisions, \
                COUNT(*) FILTER (WHERE g.decision = 'approved') AS approved, \
                percentile_cont(0.5) WITHIN GROUP \
                    (ORDER BY EXTRACT(EPOCH FROM (g.decided_at - r.requested_at))) AS median_seconds \
         FROM approval_grant g JOIN approval_request r ON r.id = g.request_id \
         WHERE g.decided_at > now() - make_interval(days => $1) \
         GROUP BY g.approver_id ORDER BY decisions DESC LIMIT 200",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for a in &mut approvers {
        a.warning = rubber_stamp(a.decisions, a.approved, a.median_seconds);
    }
    let backlog: Vec<Backlog> = sqlx::query_as(
        "SELECT action_type, COUNT(*) AS pending, MIN(requested_at) AS oldest \
         FROM approval_request WHERE status = 'pending' \
         GROUP BY action_type ORDER BY pending DESC LIMIT 100",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rejection_words: Vec<RejectionWord> = sqlx::query_as(
        "SELECT word, COUNT(*) AS count FROM ( \
             SELECT lower(w) AS word \
             FROM approval_grant g, regexp_split_to_table(coalesce(g.comment, ''), '\\s+') AS w \
             WHERE g.decision = 'rejected' AND g.decided_at > now() - make_interval(days => $1) \
         ) words \
         WHERE char_length(word) >= 4 \
         GROUP BY word ORDER BY count DESC, word LIMIT 20",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(ApprovalMetrics {
        days,
        approvers,
        backlog,
        rejection_words,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/approvals/metrics", get(approval_metrics))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(approval_metrics),
    components(schemas(ApprovalMetrics, ApproverFigures, Backlog, RejectionWord))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_near_total_approver_is_flagged() {
        assert!(rubber_stamp(20, 20, Some(12.0)));
        assert!(
            !rubber_stamp(20, 20, Some(300.0)),
            "slow decisions are read"
        );
        assert!(
            !rubber_stamp(20, 15, Some(5.0)),
            "rejecting some is looking"
        );
        assert!(!rubber_stamp(5, 5, Some(5.0)), "too few to say");
        assert!(!rubber_stamp(20, 20, None));
    }
}
