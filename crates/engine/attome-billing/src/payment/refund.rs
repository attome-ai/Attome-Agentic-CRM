//! Refunds (roadmap F5-T10).
//!
//! - [`request_refund`] (`POST /api/v1/billing/payments/{id}/refunds`,
//!   `payment.refund`) refunds part or all of a paid payment, never more than
//!   is left after earlier refunds (requested, waiting or done), under the
//!   payment's refund lock so two requests cannot both take the same
//!   amount. Above `billing.refund.approval_threshold` (0 = never) it waits
//!   for a `billing.refund` approval; otherwise it is `pending` and the
//!   `BillingExecuteRefund` job is enqueued in the same transaction.
//! - An approved refund ([`do_refund_approved`], from the approval
//!   dispatch) becomes `pending` and enqueues the job.
//! - The job ([`execute_refund`]) refunds through the payment's gateway with
//!   the key `refund:{refund_id}`, outside any transaction (a gateway outage
//!   leaves it pending for the job's retry), or, for a payment received by
//!   transfer, records that a person returns the money. Then, in one
//!   transaction, the refund is `succeeded` or `failed` and the payment
//!   `refunded` or `partially_refunded`. A refunded payment that paid
//!   invoices asks F4 for a draft credit note on each, in proportion.

use std::str::FromStr;

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::recurring::AdapterSource;
use crate::gateway::{GatewayError, GatewayStatus};

/// The approval action a refund above the threshold opens.
pub const ACTION_REFUND: &str = "billing.refund";

/// Refunds larger than this wait for an approval (0 = never).
pub const REFUND_THRESHOLD_SETTING: &str = "billing.refund.approval_threshold";

/// Statuses that hold part of a payment's amount.
const HOLDING: [&str; 4] = ["requested", "pending_approval", "pending", "succeeded"];

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RefundRequest {
    #[schema(value_type = f64)]
    pub amount: serde_json::Number,
    pub reason: String,
}

/// What a refund request did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RefundOutcome {
    pub refund_id: Uuid,
    pub payment_id: Uuid,
    /// `pending` (the job refunds it) or `pending_approval`.
    pub status: String,
    pub approval_id: Option<Uuid>,
}

/// The approval payload of a refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundPayload {
    pub refund_id: Uuid,
}

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

fn threshold(state: &EngineState) -> Decimal {
    attome_core::setting_registry()
        .get(REFUND_THRESHOLD_SETTING)
        .and_then(|descriptor| {
            let (value, _) = state.settings.load().resolve(descriptor, None, None);
            match value {
                serde_json::Value::Number(n) => n.to_string().parse().ok(),
                serde_json::Value::String(s) => s.trim().parse().ok(),
                _ => None,
            }
        })
        .filter(|d: &Decimal| *d >= Decimal::ZERO)
        .unwrap_or(Decimal::ZERO)
}

/// Takes the payment's refund lock in `tx`; `409` when another refund of
/// it holds it.
async fn lock_payment(tx: &mut attome_db::Tx<'_>, payment: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-billing/payment-refund:{payment}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "another refund of this payment is being recorded; try again",
        ))
    }
}

/// What is left to refund of a payment: its amount less every refund that
/// holds part of it.
async fn refundable(
    tx: &mut attome_db::Tx<'_>,
    payment: Uuid,
) -> Result<(Decimal, Option<String>), AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT amount::text, status FROM customer_payment \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(payment)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (amount, status) = row.ok_or(AppError::NotFound)?;
    let held: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payment_refund \
         WHERE payment_ref = $1 AND status = ANY($2) \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(payment)
    .bind(HOLDING.map(str::to_owned).to_vec())
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok((
        decimal(amount.as_deref()) - decimal(held.as_deref()),
        status,
    ))
}

/// Asks for a refund of `amount` of a payment, as `ctx`.
pub async fn request_refund(
    state: &EngineState,
    ctx: &SecurityContext,
    payment: Uuid,
    amount: Decimal,
    reason: &str,
) -> Result<RefundOutcome, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("a refund needs a reason".into()));
    }
    if amount <= Decimal::ZERO {
        return Err(AppError::Validation("refund an amount above zero".into()));
    }
    let limit = threshold(state);
    let needs_approval = limit > Decimal::ZERO && amount > limit;
    let refund = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_payment(&mut tx, payment).await?;
    let (left, status) = refundable(&mut tx, payment).await?;
    if !matches!(status.as_deref(), Some("succeeded" | "partially_refunded")) {
        return Err(AppError::Conflict("only a paid payment is refunded"));
    }
    if amount > left {
        return Err(AppError::Validation(format!(
            "{amount} is more than the {left} left to refund"
        )));
    }
    sqlx::query(
        "INSERT INTO payment_refund (id, payment_ref, amount, reason, status, created_by, \
             owner_ref, owner_type, is_active, row_version) \
         VALUES ($1, $2, $3::numeric, $4, $5, $6, $6, 0, true, 0)",
    )
    .bind(refund)
    .bind(payment)
    .bind(amount.to_string())
    .bind(reason)
    .bind(if needs_approval {
        "requested"
    } else {
        "pending"
    })
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        &mut tx,
        "payment_refund",
        refund,
        ChangeOperation::Create,
        "billing.refund.requested",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "payment_refund",
            refund,
            attome_audit::AuditOperation::Create,
            "billing.refund_requested",
            ctx.user_id,
        )
        .comment(reason.to_owned()),
    )
    .await?;
    if !needs_approval {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::BillingExecuteRefund { refund_id: refund },
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    if !needs_approval {
        return Ok(RefundOutcome {
            refund_id: refund,
            payment_id: payment,
            status: "pending".into(),
            approval_id: None,
        });
    }
    let opened = attome_audit::approval::gate_regarding_required(
        state,
        ACTION_REFUND,
        serde_json::to_value(RefundPayload { refund_id: refund }).map_err(AppError::internal)?,
        ctx.user_id,
        Some(("customer_payment", payment)),
    )
    .await;
    let next = if opened.is_ok() {
        "pending_approval"
    } else {
        "failed"
    };
    sqlx::query(
        "UPDATE payment_refund SET status = $2, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(refund)
    .bind(next)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let request = opened?;
    Ok(RefundOutcome {
        refund_id: refund,
        payment_id: payment,
        status: "pending_approval".into(),
        approval_id: Some(request.id),
    })
}

/// The approved refund: it becomes `pending` and the job refunds it.
pub async fn do_refund_approved(
    state: &EngineState,
    payload: &RefundPayload,
    approver: Uuid,
) -> Result<RefundOutcome, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let payment: Option<Uuid> = sqlx::query_scalar(
        "UPDATE payment_refund SET status = 'pending', modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND status IN ('requested', 'pending_approval') \
         RETURNING payment_ref",
    )
    .bind(payload.refund_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let payment = payment.ok_or(AppError::Conflict(
        "the refund is not waiting for an approval",
    ))?;
    emit_named(
        &mut tx,
        "payment_refund",
        payload.refund_id,
        ChangeOperation::Update,
        "billing.refund.approved",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "payment_refund",
            payload.refund_id,
            attome_audit::AuditOperation::Execute,
            "billing.refund_approved",
            approver,
        ),
    )
    .await?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::BillingExecuteRefund {
            refund_id: payload.refund_id,
        },
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(RefundOutcome {
        refund_id: payload.refund_id,
        payment_id: payment,
        status: "pending".into(),
        approval_id: None,
    })
}

type RefundRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

/// Refunds a pending refund (the `BillingExecuteRefund` job). A gateway
/// that cannot be reached, or a refund still processing, is an error so the
/// job retries; anything else settles it.
pub async fn execute_refund(
    state: &EngineState,
    refund: Uuid,
    adapters: &dyn AdapterSource,
) -> Result<(), AppError> {
    let row: Option<RefundRow> = sqlx::query_as(
        "SELECT r.status, r.amount::text, r.reason, r.payment_ref, r.created_by, \
                p.gateway_system_ref, p.gateway_reference \
         FROM payment_refund r JOIN customer_payment p ON p.id = r.payment_ref \
         WHERE r.id = $1",
    )
    .bind(refund)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, amount, reason, payment, requester, system_ref, reference)) = row else {
        return Err(AppError::NotFound);
    };
    if status.as_deref() != Some("pending") {
        return Ok(());
    }
    let amount = decimal(amount.as_deref());
    let system = system_ref
        .as_deref()
        .and_then(|s| Uuid::parse_str(s.trim()).ok());
    let (succeeded, failure) = match (system, reference) {
        (Some(system_id), Some(reference)) => {
            let system = crate::gateway::system(state, system_id).await?;
            let gateway = adapters.adapter(&system)?;
            let credential = crate::gateway::credential(state, &system).await?;
            match gateway
                .refund(&credential, &reference, amount, &format!("refund:{refund}"))
                .await
            {
                Ok(GatewayStatus::Refunded { .. } | GatewayStatus::Succeeded { .. }) => {
                    (true, None)
                }
                Ok(GatewayStatus::Pending) => {
                    return Err(AppError::CapabilityUnavailable(
                        "the gateway is still processing the refund",
                    ));
                }
                Ok(GatewayStatus::Failed { reason }) => (false, Some(reason)),
                Err(GatewayError::Refused(reason)) => (false, Some(reason)),
                Err(e @ (GatewayError::Unavailable(_) | GatewayError::BadSignature)) => {
                    return Err(e.into());
                }
            }
        }
        // Received by transfer, cheque or cash: a person returns it.
        _ => (true, None),
    };
    let actor = requester.unwrap_or_else(Uuid::nil);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_payment(&mut tx, payment).await?;
    let moved = sqlx::query(
        "UPDATE payment_refund SET status = $2, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1 AND status = 'pending'",
    )
    .bind(refund)
    .bind(if succeeded { "succeeded" } else { "failed" })
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if moved == 0 {
        return Ok(());
    }
    emit_named(
        &mut tx,
        "payment_refund",
        refund,
        ChangeOperation::Update,
        if succeeded {
            "billing.refund.succeeded"
        } else {
            "billing.refund.failed"
        },
    )
    .await?;
    if succeeded {
        let totals: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT p.amount::text, \
                    (SELECT COALESCE(SUM(r.amount), 0)::text FROM payment_refund r \
                     WHERE r.payment_ref = p.id AND r.status = 'succeeded' \
                       AND (r.is_active IS NULL OR r.is_active = true)) \
             FROM customer_payment p WHERE p.id = $1 FOR UPDATE",
        )
        .bind(payment)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let paid = decimal(totals.0.as_deref());
        let refunded = decimal(totals.1.as_deref());
        sqlx::query(
            "UPDATE customer_payment SET status = $2, modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1",
        )
        .bind(payment)
        .bind(if refunded >= paid {
            "refunded"
        } else {
            "partially_refunded"
        })
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        emit_named(
            &mut tx,
            "customer_payment",
            payment,
            ChangeOperation::Update,
            "billing.payment.refunded",
        )
        .await?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "payment_refund",
            refund,
            attome_audit::AuditOperation::Execute,
            if succeeded {
                "billing.refund_succeeded"
            } else {
                "billing.refund_failed"
            },
            actor,
        )
        .comment(failure.clone().unwrap_or_default()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    if succeeded {
        credit_paid_invoices(
            state,
            refund,
            payment,
            amount,
            reason.as_deref().unwrap_or(""),
            actor,
        )
        .await;
    } else {
        tracing::warn!(%refund, reason = failure.as_deref().unwrap_or(""), "billing: the gateway refused a refund");
    }
    Ok(())
}

type AllocationRow = (Uuid, Option<String>, Option<String>);

/// Asks F4 for a draft credit note on each invoice the payment paid, in
/// proportion to the refund (oldest allocation first); records the first on
/// the refund. A note that cannot be made is logged for a person to make.
async fn credit_paid_invoices(
    state: &EngineState,
    refund: Uuid,
    payment: Uuid,
    amount: Decimal,
    reason: &str,
    actor: Uuid,
) {
    let result: Result<(), AppError> = async {
        let allocations: Vec<AllocationRow> = sqlx::query_as(
            "SELECT a.invoice_ref, a.amount::text, i.grand_total::text \
             FROM payment_allocation a JOIN invoice i ON i.id = a.invoice_ref \
             WHERE a.payment_ref = $1 AND COALESCE(a.reversed, false) = false \
               AND (a.is_active IS NULL OR a.is_active = true) \
             ORDER BY a.allocated_on, a.id",
        )
        .bind(payment)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if allocations.is_empty() {
            return Ok(());
        }
        let ctx = state.base.security.resolve(actor).await?;
        let mut left = amount;
        let mut first: Option<Uuid> = None;
        for (invoice, allocated, total) in allocations {
            if left <= Decimal::ZERO {
                break;
            }
            let portion = decimal(allocated.as_deref()).min(left);
            let total = decimal(total.as_deref());
            if portion <= Decimal::ZERO || total <= Decimal::ZERO {
                continue;
            }
            left -= portion;
            let share = (portion / total).min(Decimal::ONE);
            let lines: Vec<(Uuid, Option<String>)> = sqlx::query_as(
                "SELECT id, quantity::text FROM invoice_line \
                 WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
            )
            .bind(invoice)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let plan: Vec<(Uuid, Decimal)> = lines
                .into_iter()
                .map(|(line, quantity)| {
                    let quantity = decimal(quantity.as_deref()) * share;
                    // Rounded down, so a note never credits more than was paid.
                    (
                        line,
                        quantity.round_dp_with_strategy(4, rust_decimal::RoundingStrategy::ToZero),
                    )
                })
                .filter(|(_, q)| *q > Decimal::ZERO)
                .collect();
            if plan.is_empty() {
                continue;
            }
            let note = crate::notes::create_credit_note(
                state,
                &ctx,
                invoice,
                &plan,
                &format!("Refund: {reason}"),
            )
            .await?;
            first.get_or_insert(note.note_id);
        }
        if let Some(note) = first {
            sqlx::query(
                "UPDATE payment_refund SET credit_note_ref = $2, modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
            )
            .bind(refund)
            .bind(note)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::warn!(%refund, error = %e, "billing: a refund's credit note was not drafted; a person drafts it");
    }
}

/// `payment.refund`: may refund payments.
#[derive(Debug)]
pub struct PaymentRefund;

impl attome_server::authz::PrivilegeKey for PaymentRefund {
    const KEY: &'static str = "payment.refund";
}

/// Refund a payment
///
/// Refunds part or all of a paid payment, never more than earlier refunds left, under the payment's
/// refund lock. Holders of `payment.refund`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/billing/payments/{id}/refunds",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The payment")),
    request_body = RefundRequest,
    responses(
        (status = 200, description = "The refund, pending or waiting for an approval", body = RefundOutcome),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not refund payments", body = attome_types::ErrorResponse),
        (status = 404, description = "No such payment", body = attome_types::ErrorResponse),
        (status = 409, description = "Not a paid payment, or another refund of it is being recorded", body = attome_types::ErrorResponse),
        (status = 422, description = "No reason, or more than is left to refund", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_refund(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<PaymentRefund>>,
    axum::extract::Path(payment): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<RefundRequest>,
) -> Result<axum::Json<RefundOutcome>, AppError> {
    let amount = Decimal::from_str(&body.amount.to_string())
        .or_else(|_| Decimal::from_scientific(&body.amount.to_string()))
        .map_err(|_| AppError::Validation(format!("{} is not a decimal amount", body.amount)))?;
    Ok(axum::Json(
        request_refund(&state, &ctx, payment, amount, &body.reason).await?,
    ))
}

/// This module's routes, for the OpenAPI document.
#[derive(Debug, utoipa::OpenApi)]
#[openapi(paths(post_refund), components(schemas(RefundRequest, RefundOutcome)))]
pub struct ApiDocFragment;
