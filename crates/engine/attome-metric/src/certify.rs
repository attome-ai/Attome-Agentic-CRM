//! P9-T11: certifying a metric.
//!
//! `POST /api/v1/metrics/{id}/certify` with `{certified}` is the only writer
//! of `certified` and `certified_at` (engine-managed fields: the generic
//! record API refuses them, and a new metric is born uncertified). It needs
//! the metric update privilege and `attome_metric.certify`, and is audited.
//! A snapshot under a new definition version clears the certification
//! (`governance::uncertify_if_new_version`).

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::MetricUpdate;

/// Whether the metric is certified.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CertifyMetricBody {
    pub certified: bool,
}

/// The metric's certification now.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricCertification {
    pub metric_id: Uuid,
    pub certified: bool,
    pub certified_at: Option<DateTime<Utc>>,
}

/// Certify a metric
///
/// Certifies the metric, or withdraws its certification. Needs `attome_metric.certify` as well as
/// update rights on metric definitions. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/metrics/{id}/certify",
    operation_id = "certify_metric",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The metric")),
    request_body = CertifyMetricBody,
    responses(
        (status = 200, description = "Success", body = MetricCertification),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the update or the certify privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_certify(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricUpdate>>,
    Path(metric_id): Path<Uuid>,
    Json(body): Json<CertifyMetricBody>,
) -> Result<Json<MetricCertification>, AppError> {
    ctx.require_key(crate::governance::CERTIFY)?;
    crate::governance::require_visible(&state.base.db, &ctx, metric_id).await?;
    let row: Option<(bool, Option<DateTime<Utc>>)> = sqlx::query_as(
        "UPDATE dashboard_metric_definition \
            SET certified = $2, \
                certified_at = CASE WHEN $2 THEN now() ELSE NULL END, \
                row_version = row_version + 1, modified_at = now() \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
          RETURNING certified, certified_at",
    )
    .bind(metric_id)
    .bind(body.certified)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((certified, certified_at)) = row else {
        return Err(AppError::NotFound);
    };
    attome_audit::write_business_event(
        &state,
        "metric_definition",
        metric_id,
        attome_audit::AuditOperation::Update,
        if certified {
            "metric.certify"
        } else {
            "metric.uncertify"
        },
        ctx.user_id,
        None,
        None,
        if certified {
            "metric certified".to_string()
        } else {
            "metric certification withdrawn".to_string()
        },
    )
    .await;
    Ok(Json(MetricCertification {
        metric_id,
        certified,
        certified_at,
    }))
}
