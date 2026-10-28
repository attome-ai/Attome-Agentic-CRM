//! Recalculation with preview (roadmap F10-T9).
//!
//! When a plan is published or a credit lands in an open period, a
//! [`preview_period`] job reruns the rules for that period in memory and
//! stores, per participant, what they are paid now (the latest finished
//! run's payout) and what they would be paid (`comp_recalc_preview`,
//! status `pending`). Statement lines and payouts are untouched. Sales ops
//! apply it with `POST .../recalc/apply`, which starts an ordinary
//! calculation run per plan version and marks the previews applied. A
//! closed (approved or locked) period is never previewed or recalculated.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::rules::evaluate;
use crate::run::CompRunCreate;

type PeriodRow = (NaiveDate, NaiveDate, Option<String>);

async fn period(state: &EngineState, period: Uuid) -> Result<Option<PeriodRow>, AppError> {
    sqlx::query_as(
        "SELECT starts_on::date, ends_on::date, status FROM comp_period \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(period)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The plan versions a period's finished runs calculated.
async fn versions_of(state: &EngineState, period: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT plan_version_ref FROM comp_run \
         WHERE period_ref = $1 AND status = 'done' AND (is_active IS NULL OR is_active = true)",
    )
    .bind(period)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Stores a pending preview per participant of every plan version the
/// period was calculated with; previews written.
pub async fn preview_period(state: &EngineState, period_id: Uuid) -> Result<u64, AppError> {
    let Some((starts, ends, status)) = period(state, period_id).await? else {
        return Ok(0);
    };
    if crate::close::is_closed(status.as_deref()) {
        return Ok(0);
    }
    let db = &state.base.db;
    let mut written = 0;
    for version in versions_of(state, period_id).await? {
        let components = match crate::run::components(state, version).await {
            Ok(c) => c,
            Err(reason) => {
                tracing::warn!(%period_id, %version, reason, "recalc preview: the plan does not compile");
                continue;
            }
        };
        let windows = crate::run::windows(db, version).await?;
        let participants: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
            "SELECT p.id, p.user_ref, \
                    (SELECT COALESCE(po.earned, po.amount)::text FROM comp_payout po \
                     JOIN comp_run r ON r.id = po.run_ref \
                     WHERE po.participant_ref = p.id AND r.period_ref = $2 \
                       AND r.plan_version_ref = $1 AND r.status = 'done' \
                     ORDER BY r.finished_at DESC NULLS LAST LIMIT 1) \
             FROM plan_participant p \
             WHERE p.plan_version_ref = $1 AND (p.is_active IS NULL OR p.is_active = true) \
             ORDER BY p.id",
        )
        .bind(version)
        .bind(period_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (participant, user, old) in participants {
            let (credits, quota) =
                crate::run::inputs(db, participant, user, period_id, starts, ends).await?;
            let dates = if windows.is_empty() {
                std::collections::HashMap::new()
            } else {
                crate::run::credit_dates(db, participant, period_id).await?
            };
            let new: Decimal = components
                .iter()
                .flat_map(|c| {
                    evaluate(
                        c,
                        &crate::run::eligible(c.id, &windows, &credits, &dates),
                        quota,
                    )
                })
                .map(|l| l.payout)
                .sum();
            let old: Decimal = old
                .as_deref()
                .and_then(|o| o.parse().ok())
                .unwrap_or(Decimal::ZERO);
            let mut tx = attome_db::tx::begin(db).await?;
            sqlx::query(
                "DELETE FROM comp_recalc_preview \
                 WHERE period_ref = $1 AND participant_ref = $2 AND status = 'pending'",
            )
            .bind(period_id)
            .bind(participant)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "INSERT INTO comp_recalc_preview \
                   (name, period_ref, participant_ref, old_amount, new_amount, status, owner_ref) \
                 VALUES ($1, $2, $3, $4::numeric, $5::numeric, 'pending', $6)",
            )
            .bind(format!("{old} -> {new}"))
            .bind(period_id)
            .bind(participant)
            .bind(old.to_string())
            .bind(new.to_string())
            .bind(user)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
            written += 1;
        }
    }
    Ok(written)
}

/// Queues a preview of every open period (after a plan is published).
pub async fn enqueue_open_periods(state: &EngineState) -> Result<u64, AppError> {
    let open: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM comp_period WHERE (status IS NULL OR status IN ('open', 'in_review')) \
           AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for period_id in &open {
        attome_jobs::enqueue_on_pool(
            &state.base.db,
            attome_core::jobs::EngineJob::CommissionRecalcPreview {
                period_id: *period_id,
            },
        )
        .await
        .map_err(AppError::internal)?;
    }
    Ok(open.len() as u64)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommissionRecalcApplied {
    pub period_id: Uuid,
    /// One calculation run per plan version.
    pub run_ids: Vec<Uuid>,
    pub previews_applied: u64,
}

/// Apply a commission recalculation
///
/// Applies the pending recalculation preview of an open period, so participants are paid what the
/// rules now give. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/commission/periods/{id}/recalc/apply",
    tag = "commission",
    params(("id" = Uuid, Path, description = "The commission period")),
    responses(
        (status = 202, description = "Calculation runs are queued and the previews marked applied", body = CommissionRecalcApplied),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_run.create", body = ErrorResponse),
        (status = 404, description = "No such period", body = ErrorResponse),
        (status = 409, description = "The period is approved or locked, or has no pending preview", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn commission_post_recalc_apply(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CompRunCreate>>,
    Path(period_id): Path<Uuid>,
) -> Result<(StatusCode, Json<CommissionRecalcApplied>), AppError> {
    let Some((_, _, status)) = period(&state, period_id).await? else {
        return Err(AppError::NotFound);
    };
    if crate::close::is_closed(status.as_deref()) {
        return Err(AppError::Conflict("the period is approved or locked"));
    }
    let versions = versions_of(&state, period_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let applied = sqlx::query(
        "UPDATE comp_recalc_preview SET status = 'applied', modified_at = now(), \
             row_version = row_version + 1 WHERE period_ref = $1 AND status = 'pending'",
    )
    .bind(period_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if applied == 0 {
        return Err(AppError::Conflict(
            "the period has no pending preview to apply",
        ));
    }
    let mut run_ids = Vec::with_capacity(versions.len());
    for version in versions {
        let run_id: Uuid = sqlx::query_scalar(
            "INSERT INTO comp_run (period_ref, plan_version_ref, status, owner_ref) \
             VALUES ($1, $2, 'queued', $3) RETURNING id",
        )
        .bind(period_id)
        .bind(version)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::CommissionRun { run_id },
        )
        .await
        .map_err(AppError::internal)?;
        run_ids.push(run_id);
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "comp_period",
            period_id,
            AuditOperation::Update,
            "commission.recalc_applied",
            ctx.user_id,
        )
        .comment(format!(
            "{applied} previews applied, {} runs",
            run_ids.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CommissionRecalcApplied {
            period_id,
            run_ids,
            previews_applied: applied,
        }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(commission_post_recalc_apply),
    components(schemas(CommissionRecalcApplied))
)]
pub(crate) struct ApiDocFragment;
