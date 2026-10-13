//! M53 Phase 1 (Omnichannel, web chat only, D-474) — per-channel metrics
//! (M27): a couple of query-backed numbers scoped to `channel = 'web_chat'`,
//! the same "no generic metrics-registration framework exists, each module
//! exposes its own scoped queries behind a small admin route" pattern
//! `attome-content::analytics`/`attome-service::queue_analytics_seed` already
//! establish — not a new framework.
//!
//! Lives here (`attome-api`), not `crates/server`'s `omnichannel.rs`: unlike
//! the public widget endpoint, this route touches no `attome-ai`/
//! `attome-integration` API at all — it is a plain, protected, authenticated
//! admin read over `communication`/`service_work_request`/`service_ticket`, so it
//! carries none of that module's cross-crate dependency constraint.

use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct WebChatMetrics {
    /// Distinct conversations started (`communication` rows with
    /// `channel = 'web_chat', direction = 'inbound', in_reply_to IS NULL`)
    /// in the last 30 days.
    pub conversations_last_30_days: i64,
    /// Average time, in seconds, between a conversation's first inbound
    /// message and its first outbound reply (bot ack, offline message, or
    /// handoff ack) — `NULL` until at least one conversation has both.
    pub avg_first_response_seconds: Option<f64>,
    /// Average `service_ticket.csat_score` across every ticket whose `channel`
    /// is `web_chat` (M76's existing CSAT-on-close convention — reused
    /// verbatim, no new scoring mechanism). `NULL` until an agent has both
    /// converted a web-chat work request into a ticket (M70) and closed it
    /// with a score.
    pub avg_csat: Option<f64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/omnichannel/metrics",
    tag = "omnichannel",
    responses(
        (status = 200, description = "Success", body = WebChatMetrics),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn web_chat_metrics(
    State(state): State<EngineState>,
) -> Result<Json<WebChatMetrics>, AppError> {
    let conversations_last_30_days: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM communication \
         WHERE channel = 'web_chat' AND direction = 'inbound' AND in_reply_to IS NULL \
           AND is_active IS NOT FALSE AND created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // First response per thread: the earliest outbound row's created_at minus
    // the thread root's own created_at, averaged across every thread that has
    // both — a thread the bot never answered (should not happen, but a
    // defensive case) simply contributes nothing rather than skewing the
    // average with a NULL-as-zero.
    let avg_first_response_seconds: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(EXTRACT(EPOCH FROM (first_outbound.created_at - root.created_at))) \
         FROM communication root \
         JOIN LATERAL ( \
             SELECT created_at FROM communication reply \
             WHERE reply.thread_id = root.thread_id AND reply.direction = 'outbound' \
               AND reply.is_active IS NOT FALSE \
             ORDER BY reply.created_at ASC LIMIT 1 \
         ) first_outbound ON true \
         WHERE root.channel = 'web_chat' AND root.direction = 'inbound' \
           AND root.in_reply_to IS NULL AND root.is_active IS NOT FALSE",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let avg_csat: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(csat_score) FROM service_ticket \
         WHERE channel = 'web_chat' AND csat_score IS NOT NULL AND is_active IS NOT FALSE",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(WebChatMetrics {
        conversations_last_30_days,
        avg_first_response_seconds,
        avg_csat,
    }))
}

/// License-gated by the caller that mounts this router (`system.rs`'s
/// `license_gate(..., MODULE_OMNICHANNEL, "omnichannel")` wrapper), not here —
/// this file stays a plain, testable `Router`, same shape as
/// `quality_admin`/`changes_admin`.
pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/omnichannel/metrics", get(web_chat_metrics))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(web_chat_metrics))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
