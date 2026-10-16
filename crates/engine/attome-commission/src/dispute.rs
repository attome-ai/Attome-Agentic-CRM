//! Disputes on statement lines and manual adjustments (roadmap F10-T8).
//!
//! A seller disputes one of their own statement lines with a reason. A
//! reviewer (sales ops, or a manager for their team) accepts, rejects, or
//! settles it with an adjustment. Adjustments, from a dispute or entered
//! directly by sales ops, need a reason; one whose size is above the
//! `commission.adjustment_approval_amount` setting (in the deployment's base
//! currency, default 1000) goes to approval and is only written when the
//! approval executes ([`ACTION_ADJUSTMENT_APPLY`]), never before.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The approval action that writes an adjustment above the threshold.
pub const ACTION_ADJUSTMENT_APPLY: &str = "commission.adjustment_apply";

/// The setting holding the approval threshold.
pub const APPROVAL_AMOUNT_SETTING: &str = "commission.adjustment_approval_amount";

const DEFAULT_APPROVAL_AMOUNT: i64 = 1000;

/// `comp_dispute.create`: may dispute a statement line.
#[derive(Debug)]
pub struct DisputeCreate;

impl PrivilegeKey for DisputeCreate {
    const KEY: &'static str = "comp_dispute.create";
}

/// `comp_dispute.update`: may decide a dispute.
#[derive(Debug)]
pub struct DisputeDecide;

impl PrivilegeKey for DisputeDecide {
    const KEY: &'static str = "comp_dispute.update";
}

/// `comp_adjustment.create`: may enter a manual adjustment.
#[derive(Debug)]
pub struct AdjustmentCreate;

impl PrivilegeKey for AdjustmentCreate {
    const KEY: &'static str = "comp_adjustment.create";
}

/// The approval threshold: the setting, else 1000.
pub fn approval_amount(state: &EngineState) -> Decimal {
    let Some(descriptor) = attome_core::setting_registry().get(APPROVAL_AMOUNT_SETTING) else {
        return Decimal::from(DEFAULT_APPROVAL_AMOUNT);
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    match value {
        serde_json::Value::Number(n) => n.to_string().parse().ok(),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|d: &Decimal| *d >= Decimal::ZERO)
    .unwrap_or(Decimal::from(DEFAULT_APPROVAL_AMOUNT))
}

/// Whether an adjustment of `amount` needs approval under `threshold`.
pub fn needs_approval(amount: Decimal, threshold: Decimal) -> bool {
    amount.abs() > threshold
}

fn required_reason(reason: &str) -> Result<String, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("reason is required".into()));
    }
    if reason.chars().count() > 2000 {
        return Err(AppError::Validation(
            "reason: at most 2000 characters".into(),
        ));
    }
    Ok(reason.to_owned())
}

/// An adjustment to write, as stored in its approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjustmentPayload {
    pub participant_id: Uuid,
    pub period_id: Uuid,
    /// Decimal text.
    pub amount: String,
    pub reason: String,
    /// The dispute this settles, marked `adjusted` when it is written.
    #[serde(default)]
    pub dispute_id: Option<Uuid>,
    /// Who asked for it.
    pub requested_by: Uuid,
}

/// The adjustment written, or the approval it waits on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommissionAdjustmentOutcome {
    /// The new `comp_adjustment`, when written.
    pub adjustment_id: Option<Uuid>,
    /// The approval request, when the amount is above the threshold.
    pub approval_request_id: Option<Uuid>,
}

async fn period_open(state: &EngineState, period: Uuid) -> Result<(), AppError> {
    let status: Option<Option<String>> = sqlx::query_scalar(
        "SELECT status FROM comp_period WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(period)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match status {
        None => Err(AppError::NotFound),
        Some(Some(s)) if s == "approved" || s == "locked" => {
            Err(AppError::Conflict("the period is approved or locked"))
        }
        Some(_) => Ok(()),
    }
}

/// Writes the adjustment (and settles its dispute) in one transaction.
/// Called directly under the threshold, and by the approval executor above
/// it with the request's id.
pub async fn do_apply_adjustment(
    state: &EngineState,
    payload: &AdjustmentPayload,
    actor: Uuid,
    approval_request: Option<Uuid>,
) -> Result<CommissionAdjustmentOutcome, AppError> {
    let amount: Decimal = payload
        .amount
        .parse()
        .map_err(|_| AppError::Validation("amount is not a number".into()))?;
    period_open(state, payload.period_id).await?;
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT user_ref FROM plan_participant \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(payload.participant_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(owner) = owner else {
        return Err(AppError::NotFound);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_adjustment \
           (participant_ref, period_ref, amount, reason, approval_request_id, owner_ref) \
         VALUES ($1, $2, $3::numeric, $4, $5, $6) RETURNING id",
    )
    .bind(payload.participant_id)
    .bind(payload.period_id)
    .bind(amount.to_string())
    .bind(&payload.reason)
    .bind(approval_request.map(|r| r.to_string()))
    .bind(owner)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(dispute) = payload.dispute_id {
        sqlx::query(
            "UPDATE comp_dispute SET status = 'adjusted', modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1",
        )
        .bind(dispute)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "comp_adjustment",
            id,
            AuditOperation::Create,
            "commission.adjustment_applied",
            actor,
        )
        .comment(format!("adjustment of {amount}: {}", payload.reason)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(CommissionAdjustmentOutcome {
        adjustment_id: Some(id),
        approval_request_id: None,
    })
}

/// Applies an adjustment now, or opens its approval when it is above the
/// threshold.
async fn adjust(
    state: &EngineState,
    payload: AdjustmentPayload,
) -> Result<(StatusCode, CommissionAdjustmentOutcome), AppError> {
    let amount: Decimal = payload
        .amount
        .parse()
        .map_err(|_| AppError::Validation("amount is not a number".into()))?;
    if amount.is_zero() {
        return Err(AppError::Validation("amount must not be zero".into()));
    }
    period_open(state, payload.period_id).await?;
    let required = needs_approval(amount, approval_amount(state));
    let value = serde_json::to_value(&payload).map_err(AppError::internal)?;
    if let Some(request) = attome_audit::approval::gate_required(
        state,
        ACTION_ADJUSTMENT_APPLY,
        value,
        payload.requested_by,
        required,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            CommissionAdjustmentOutcome {
                adjustment_id: None,
                approval_request_id: Some(request.id),
            },
        ));
    }
    let actor = payload.requested_by;
    Ok((
        StatusCode::CREATED,
        do_apply_adjustment(state, &payload, actor, None).await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommissionDisputeBody {
    pub statement_line_id: Uuid,
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CommissionDisputeCreated {
    pub dispute_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/disputes",
    tag = "commission",
    request_body = CommissionDisputeBody,
    responses(
        (status = 201, description = "The dispute is open", body = CommissionDisputeCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_dispute.create, or the line is not theirs", body = ErrorResponse),
        (status = 404, description = "No such statement line", body = ErrorResponse),
        (status = 422, description = "No reason given", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn commission_post_dispute(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DisputeCreate>>,
    Json(body): Json<CommissionDisputeBody>,
) -> Result<(StatusCode, Json<CommissionDisputeCreated>), AppError> {
    let reason = required_reason(&body.reason)?;
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT owner_ref FROM comp_statement_line \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(body.statement_line_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(owner) = owner else {
        return Err(AppError::NotFound);
    };
    if owner != Some(ctx.user_id) {
        return Err(AppError::Forbidden);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_dispute (statement_line_ref, reason, status, owner_ref) \
         VALUES ($1, $2, 'open', $3) RETURNING id",
    )
    .bind(body.statement_line_id)
    .bind(&reason)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "comp_dispute",
            id,
            AuditOperation::Create,
            "commission.dispute_opened",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(CommissionDisputeCreated { dispute_id: id }),
    ))
}

/// A reviewer's decision on a dispute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommissionDisputeDecision {
    Accept,
    Reject,
    Adjust,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommissionDisputeDecisionBody {
    pub decision: CommissionDisputeDecision,
    /// Required for `adjust`: the adjustment, as decimal text.
    pub amount: Option<String>,
    pub comment: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/disputes/{id}/decision",
    tag = "commission",
    params(("id" = Uuid, Path, description = "The dispute")),
    request_body = CommissionDisputeDecisionBody,
    responses(
        (status = 200, description = "Decided; an adjustment is written when it is within the approval amount", body = CommissionAdjustmentOutcome),
        (status = 202, description = "The adjustment waits on approval; the dispute stays open until it is written", body = CommissionAdjustmentOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_dispute.update, or comp_adjustment.create to adjust", body = ErrorResponse),
        (status = 404, description = "No such dispute", body = ErrorResponse),
        (status = 409, description = "The dispute is already decided, or its period is approved or locked", body = ErrorResponse),
        (status = 422, description = "No comment, or an adjust without an amount", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn commission_post_decision(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DisputeDecide>>,
    Path(dispute): Path<Uuid>,
    Json(body): Json<CommissionDisputeDecisionBody>,
) -> Result<(StatusCode, Json<CommissionAdjustmentOutcome>), AppError> {
    let comment = required_reason(&body.comment)?;
    let row: Option<(Option<String>, Uuid, Uuid)> = sqlx::query_as(
        "SELECT d.status, l.participant_ref, r.period_ref FROM comp_dispute d \
         JOIN comp_statement_line l ON l.id = d.statement_line_ref \
         JOIN comp_run r ON r.id = l.run_ref \
         WHERE d.id = $1 AND (d.is_active IS NULL OR d.is_active = true)",
    )
    .bind(dispute)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, participant, period)) = row else {
        return Err(AppError::NotFound);
    };
    if status.as_deref().is_some_and(|s| s != "open") {
        return Err(AppError::Conflict("the dispute is already decided"));
    }
    match body.decision {
        CommissionDisputeDecision::Adjust => {
            ctx.require("comp_adjustment", "create")?;
            let amount = body
                .amount
                .as_deref()
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .ok_or_else(|| AppError::Validation("amount is required to adjust".into()))?;
            sqlx::query(
                "UPDATE comp_dispute SET reviewer_comment = $2, modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
            )
            .bind(dispute)
            .bind(&comment)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let (status, outcome) = adjust(
                &state,
                AdjustmentPayload {
                    participant_id: participant,
                    period_id: period,
                    amount: amount.to_owned(),
                    reason: comment,
                    dispute_id: Some(dispute),
                    requested_by: ctx.user_id,
                },
            )
            .await?;
            let status = if status == StatusCode::CREATED {
                StatusCode::OK
            } else {
                status
            };
            Ok((status, Json(outcome)))
        }
        decision => {
            let new_status = if decision == CommissionDisputeDecision::Accept {
                "accepted"
            } else {
                "rejected"
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let updated = sqlx::query(
                "UPDATE comp_dispute SET status = $2, reviewer_comment = $3, modified_at = now(), \
                     row_version = row_version + 1 \
                 WHERE id = $1 AND (status IS NULL OR status = 'open')",
            )
            .bind(dispute)
            .bind(new_status)
            .bind(&comment)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if updated.rows_affected() == 0 {
                return Err(AppError::Conflict("the dispute is already decided"));
            }
            attome_audit::write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(&state),
                attome_audit::BusinessEvent::new(
                    "comp_dispute",
                    dispute,
                    AuditOperation::Update,
                    "commission.dispute_decided",
                    ctx.user_id,
                )
                .comment(format!("{new_status}: {comment}")),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok((
                StatusCode::OK,
                Json(CommissionAdjustmentOutcome {
                    adjustment_id: None,
                    approval_request_id: None,
                }),
            ))
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommissionAdjustmentBody {
    pub participant_id: Uuid,
    pub period_id: Uuid,
    /// Decimal text; negative takes pay away.
    pub amount: String,
    pub reason: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/adjustments",
    tag = "commission",
    request_body = CommissionAdjustmentBody,
    responses(
        (status = 201, description = "The adjustment is written", body = CommissionAdjustmentOutcome),
        (status = 202, description = "Above the approval amount: an approval request is open and nothing is written yet", body = CommissionAdjustmentOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_adjustment.create", body = ErrorResponse),
        (status = 404, description = "No such period or participant", body = ErrorResponse),
        (status = 409, description = "The period is approved or locked", body = ErrorResponse),
        (status = 422, description = "No reason, or the amount is not a non-zero number", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn commission_post_adjustment(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<AdjustmentCreate>>,
    Json(body): Json<CommissionAdjustmentBody>,
) -> Result<(StatusCode, Json<CommissionAdjustmentOutcome>), AppError> {
    let reason = required_reason(&body.reason)?;
    let (status, outcome) = adjust(
        &state,
        AdjustmentPayload {
            participant_id: body.participant_id,
            period_id: body.period_id,
            amount: body.amount.trim().to_owned(),
            reason,
            dispute_id: None,
            requested_by: ctx.user_id,
        },
    )
    .await?;
    Ok((status, Json(outcome)))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        commission_post_dispute,
        commission_post_decision,
        commission_post_adjustment
    ),
    components(schemas(
        CommissionDisputeBody,
        CommissionDisputeCreated,
        CommissionDisputeDecision,
        CommissionDisputeDecisionBody,
        CommissionAdjustmentBody,
        CommissionAdjustmentOutcome
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_amounts_above_the_threshold_need_approval() {
        let threshold = Decimal::from(1000);
        assert!(!needs_approval(Decimal::from(1000), threshold));
        assert!(needs_approval(Decimal::new(100001, 2), threshold));
        assert!(needs_approval(Decimal::from(-1500), threshold));
        assert!(!needs_approval(Decimal::from(-200), threshold));
    }

    #[test]
    fn a_reason_is_required() {
        assert!(matches!(
            required_reason("   "),
            Err(AppError::Validation(_))
        ));
        assert_eq!(
            required_reason(" late deal ").ok().as_deref(),
            Some("late deal")
        );
    }

    #[test]
    fn the_payload_round_trips_through_the_approval_request() {
        let payload = AdjustmentPayload {
            participant_id: Uuid::from_u128(1),
            period_id: Uuid::from_u128(2),
            amount: "1500.00".into(),
            reason: "missed split".into(),
            dispute_id: Some(Uuid::from_u128(3)),
            requested_by: Uuid::from_u128(4),
        };
        let value = serde_json::to_value(&payload).unwrap_or_default();
        let back: Option<AdjustmentPayload> = serde_json::from_value(value).ok();
        assert_eq!(back, Some(payload));
    }
}
