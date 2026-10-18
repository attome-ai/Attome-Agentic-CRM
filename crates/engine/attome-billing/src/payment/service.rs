//! The payment service (roadmap F5-T3): manual payments, their allocation to
//! invoices, reversal, and applying a customer's credit.
//!
//! - Every operation on an account's money takes
//!   `pg_try_advisory_xact_lock(35, hashtext('attome-billing/account-balance:{account}'))`
//!   in its one transaction, so two payments for one account never allocate
//!   the same open amount; a busy account answers `409` to retry.
//! - [`record_payment`] writes the `customer_payment`, allocates it
//!   ([`super::allocate::allocate`]: oldest due first, or as the payer says)
//!   over the account's open invoices read and locked in the same
//!   transaction, writes the `payment_allocation` rows, refreshes each
//!   invoice's paid and open totals and payment status
//!   ([`crate::status::refresh_in_tx`]), and keeps what is left over as the
//!   payment's `unallocated` credit.
//! - [`reverse_payment`] never deletes: it marks the payment `reversed` with
//!   the reason and its allocations `reversed`, and the invoices reopen.
//! - [`apply_credit`] allocates an account's unallocated credit to its open
//!   invoices, oldest payment first.
//!
//! Payments and allocations are engine-owned: `customer_payment` and
//! `payment_allocation` are append-only for every other writer, so a payment
//! is never edited or deleted through the generic record path. Each write
//! emits its change-feed events (`billing.payment.recorded`,
//! `billing.payment.reversed`) and a business audit event in the same
//! transaction.

use std::str::FromStr;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::allocate::{AllocError, OpenInvoice, allocate};

/// The payment methods `customer_payment.method` offers.
pub const METHODS: [&str; 11] = [
    "card",
    "mada",
    "apple_pay",
    "stc_pay",
    "tabby",
    "tamara",
    "bank_transfer",
    "cheque",
    "cash",
    "sadad",
    "credit",
];

/// One allocation the payer asked for.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AllocationRequest {
    pub invoice_id: Uuid,
    #[schema(value_type = f64)]
    pub amount: serde_json::Number,
}

/// A payment received outside a gateway (transfer, cheque, cash).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewPayment {
    pub payer_account_id: Uuid,
    #[schema(value_type = f64)]
    pub amount: serde_json::Number,
    /// ISO 4217.
    pub currency: String,
    /// One of the payment methods; `bank_transfer` by default.
    pub method: Option<String>,
    /// The day it was received (default today).
    pub received_on: Option<NaiveDate>,
    /// The bank or cheque reference.
    pub reference: Option<String>,
    /// How the payer said to split it; oldest due first when absent.
    pub allocations: Option<Vec<AllocationRequest>>,
}

/// One allocation written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AllocationLine {
    pub invoice_id: Uuid,
    /// Decimal, as text.
    pub amount: String,
}

/// What recording (or applying credit) did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PaymentRecorded {
    pub payment_id: Uuid,
    pub allocations: Vec<AllocationLine>,
    /// Left over as the customer's credit, decimal text.
    pub unallocated: String,
}

fn decimal(n: &serde_json::Number) -> Result<Decimal, AppError> {
    Decimal::from_str(&n.to_string())
        .or_else(|_| Decimal::from_scientific(&n.to_string()))
        .map_err(|_| AppError::Validation(format!("{n} is not a decimal amount")))
}

fn text(t: Option<&str>) -> Decimal {
    t.and_then(|v| Decimal::from_str(v.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

fn alloc_error(e: AllocError) -> AppError {
    AppError::Validation(e.to_string())
}

/// Takes the account's balance lock in `tx`; `409` when another payment
/// for the account holds it.
async fn lock_account(tx: &mut attome_db::Tx<'_>, account: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-billing/account-balance:{account}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "another payment for this account is being recorded; try again",
        ))
    }
}

type OpenRow = (
    Uuid,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
);

/// The account's open invoices, locked, with what each still owes.
async fn open_invoices(
    tx: &mut attome_db::Tx<'_>,
    account: Uuid,
) -> Result<Vec<OpenInvoice>, AppError> {
    let rows: Vec<OpenRow> = sqlx::query_as(
        "SELECT id, due_date::date, issued_date::date, open_total::text, currency \
         FROM invoice \
         WHERE account_ref = $1 AND (is_active IS NULL OR is_active = true) \
           AND COALESCE(status, 'draft') NOT IN ('draft', 'void') \
           AND COALESCE(kind, 'invoice') IN ('invoice', 'debit_note', 'deposit') \
           AND COALESCE(payment_status, 'open') <> 'written_off' \
           AND open_total > 0 \
         ORDER BY id FOR UPDATE",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let today = Utc::now().date_naive();
    Ok(rows
        .into_iter()
        .map(|(id, due, issued, open, currency)| OpenInvoice {
            id,
            due_date: due.or(issued).unwrap_or(today),
            issued: issued.unwrap_or(today),
            open: text(open.as_deref()),
            currency: currency.unwrap_or_else(|| "SAR".into()),
        })
        .collect())
}

/// Writes the allocations of `payment` and refreshes their invoices.
async fn write_allocations(
    tx: &mut attome_db::Tx<'_>,
    payment: Uuid,
    lines: &[(Uuid, Decimal)],
    on: NaiveDate,
    actor: Uuid,
) -> Result<Vec<AllocationLine>, AppError> {
    let mut out = Vec::with_capacity(lines.len());
    for (invoice, amount) in lines {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO payment_allocation (id, payment_ref, invoice_ref, amount, allocated_on, \
                 reversed, created_by, owner_ref, owner_type, is_active, row_version) \
             VALUES ($1, $2, $3, $4::numeric, $5, false, $6, $6, 0, true, 0)",
        )
        .bind(id)
        .bind(payment)
        .bind(invoice)
        .bind(amount.to_string())
        .bind(on)
        .bind(actor)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        emit_named(
            tx,
            "payment_allocation",
            id,
            ChangeOperation::Create,
            "billing.payment.allocated",
        )
        .await?;
        crate::status::refresh_in_tx(tx, *invoice).await?;
        out.push(AllocationLine {
            invoice_id: *invoice,
            amount: amount.to_string(),
        });
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn business_event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    entity: &str,
    id: Uuid,
    operation: AuditOperation,
    name: &str,
    actor: Uuid,
    comment: Option<String>,
) -> Result<(), AppError> {
    let mut event = attome_audit::BusinessEvent::new(entity, id, operation, name, actor);
    if let Some(comment) = comment {
        event = event.comment(comment);
    }
    attome_audit::write_business_event_in_tx(tx, &attome_audit::audit_service(state), event)
        .await
        .map(|_| ())
}

/// Records a payment and allocates it.
pub async fn record_payment(
    state: &EngineState,
    ctx: &SecurityContext,
    input: &NewPayment,
) -> Result<PaymentRecorded, AppError> {
    ctx.require("customer_payment", "create")?;
    ctx.require("payment_allocation", "create")?;
    let amount = decimal(&input.amount)?;
    if amount <= Decimal::ZERO {
        return Err(alloc_error(AllocError::NotPositive));
    }
    let currency = input.currency.trim().to_ascii_uppercase();
    if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(AppError::Validation(
            "currency is a three-letter ISO code".into(),
        ));
    }
    let method = input.method.as_deref().unwrap_or("bank_transfer");
    if !METHODS.contains(&method) {
        return Err(AppError::Validation(format!(
            "method is one of {}",
            METHODS.join(", ")
        )));
    }
    let explicit = input
        .allocations
        .as_ref()
        .map(|list| {
            list.iter()
                .map(|a| Ok((a.invoice_id, decimal(&a.amount)?)))
                .collect::<Result<Vec<_>, AppError>>()
        })
        .transpose()?;
    let received = input.received_on.unwrap_or_else(|| Utc::now().date_naive());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_account(&mut tx, input.payer_account_id).await?;
    let account: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account WHERE id = $1 \
           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(input.payer_account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !account {
        return Err(AppError::Validation(
            "payer_account_id names no account".into(),
        ));
    }
    let mut open = open_invoices(&mut tx, input.payer_account_id).await?;
    if explicit.is_none() {
        // Oldest first only within the payment's currency.
        open.retain(|i| i.currency == currency);
    }
    let allocation =
        allocate(amount, &currency, &open, explicit.as_deref()).map_err(alloc_error)?;
    let payment = Uuid::now_v7();
    let name = input
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map_or_else(|| format!("PAY-{}", payment.simple()), str::to_owned);
    sqlx::query(
        "INSERT INTO customer_payment (id, name, payer_account_ref, amount, currency, method, \
             status, received_on, reference, unallocated, created_by, owner_ref, owner_type, \
             is_active, row_version) \
         VALUES ($1, $2, $3, $4::numeric, $5, $6, 'succeeded', $7, $8, $9::numeric, $10, $10, 0, \
             true, 0)",
    )
    .bind(payment)
    .bind(&name)
    .bind(input.payer_account_id)
    .bind(amount.to_string())
    .bind(&currency)
    .bind(method)
    .bind(received)
    .bind(input.reference.as_deref())
    .bind(allocation.credit.to_string())
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        &mut tx,
        "customer_payment",
        payment,
        ChangeOperation::Create,
        "billing.payment.recorded",
    )
    .await?;
    let lines =
        write_allocations(&mut tx, payment, &allocation.lines, received, ctx.user_id).await?;
    business_event(
        &mut tx,
        state,
        "customer_payment",
        payment,
        AuditOperation::Create,
        "billing.payment_recorded",
        ctx.user_id,
        None,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(PaymentRecorded {
        payment_id: payment,
        allocations: lines,
        unallocated: allocation.credit.to_string(),
    })
}

type PaymentRow = (Option<Uuid>, Option<String>);

/// Reverses a payment with a reason: its allocations stop counting and its
/// invoices reopen. Nothing is deleted.
pub async fn reverse_payment(
    state: &EngineState,
    ctx: &SecurityContext,
    payment: Uuid,
    reason: &str,
) -> Result<Vec<Uuid>, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("a reversal needs a reason".into()));
    }
    let account: Option<PaymentRow> = sqlx::query_as(
        "SELECT payer_account_ref, status FROM customer_payment \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(payment)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(account), _)) = account else {
        return Err(AppError::NotFound);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_account(&mut tx, account).await?;
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM customer_payment WHERE id = $1 FOR UPDATE")
            .bind(payment)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if status.as_deref() != Some("succeeded") {
        return Err(AppError::Conflict("only a received payment is reversed"));
    }
    let invoices: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE payment_allocation SET reversed = true, modified_at = now(), modified_by = $2, \
             row_version = row_version + 1 \
         WHERE payment_ref = $1 AND COALESCE(reversed, false) = false \
         RETURNING invoice_ref",
    )
    .bind(payment)
    .bind(ctx.user_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE customer_payment SET status = 'reversed', reversal_reason = $2, \
             unallocated = 0, modified_at = now(), modified_by = $3, \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(payment)
    .bind(reason)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        &mut tx,
        "customer_payment",
        payment,
        ChangeOperation::Update,
        "billing.payment.reversed",
    )
    .await?;
    let mut reopened = Vec::new();
    for invoice in invoices {
        if !reopened.contains(&invoice) {
            crate::status::refresh_in_tx(&mut tx, invoice).await?;
            reopened.push(invoice);
        }
    }
    business_event(
        &mut tx,
        state,
        "customer_payment",
        payment,
        AuditOperation::Execute,
        "billing.payment_reversed",
        ctx.user_id,
        Some(reason.to_owned()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(reopened)
}

type CreditRow = (Uuid, Option<String>, Option<String>, Option<NaiveDate>);

/// Allocates the account's unallocated credit to its open invoices, oldest
/// payment first; returns what each payment applied.
pub async fn apply_credit(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
) -> Result<Vec<PaymentRecorded>, AppError> {
    ctx.require("payment_allocation", "create")?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_account(&mut tx, account).await?;
    let credits: Vec<CreditRow> = sqlx::query_as(
        "SELECT id, unallocated::text, currency, received_on::date FROM customer_payment \
         WHERE payer_account_ref = $1 AND status = 'succeeded' AND unallocated > 0 \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY received_on, id FOR UPDATE",
    )
    .bind(account)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut applied = Vec::new();
    let today = Utc::now().date_naive();
    for (payment, unallocated, currency, _) in credits {
        let currency = currency.unwrap_or_else(|| "SAR".into());
        let open: Vec<OpenInvoice> = open_invoices(&mut tx, account)
            .await?
            .into_iter()
            .filter(|i| i.currency == currency)
            .collect();
        if open.is_empty() {
            continue;
        }
        let allocation =
            allocate(text(unallocated.as_deref()), &currency, &open, None).map_err(alloc_error)?;
        if allocation.lines.is_empty() {
            continue;
        }
        let lines =
            write_allocations(&mut tx, payment, &allocation.lines, today, ctx.user_id).await?;
        sqlx::query(
            "UPDATE customer_payment SET unallocated = $2::numeric, modified_at = now(), \
                 modified_by = $3, row_version = row_version + 1 WHERE id = $1",
        )
        .bind(payment)
        .bind(allocation.credit.to_string())
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        emit_named(
            &mut tx,
            "customer_payment",
            payment,
            ChangeOperation::Update,
            "billing.payment.credit_applied",
        )
        .await?;
        applied.push(PaymentRecorded {
            payment_id: payment,
            allocations: lines,
            unallocated: allocation.credit.to_string(),
        });
    }
    if !applied.is_empty() {
        business_event(
            &mut tx,
            state,
            "account",
            account,
            AuditOperation::Execute,
            "billing.credit_applied",
            ctx.user_id,
            None,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(applied)
}

/// F5-T7: applies a gateway's report on a payment, in the caller's
/// transaction (the webhook event's). The payment is the one with this
/// gateway system and reference; a report that changes nothing (already
/// applied, or still pending) returns `false`.
///
/// - Succeeded: a pending or failed payment becomes `succeeded` with the
///   gateway's fee, and is allocated oldest due first within its currency,
///   the rest kept as the payer's credit. An amount that differs from the
///   payment's is refused, never allocated.
/// - Failed: a pending payment becomes `failed`.
/// - Refunded: a succeeded payment becomes `refunded`, or
///   `partially_refunded` for less than its amount (reopening its invoices
///   is the refund flow's, F5-T10).
pub async fn apply_gateway_status_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    system_id: Uuid,
    gateway_reference: &str,
    status: &crate::gateway::GatewayStatus,
    actor: Uuid,
) -> Result<bool, AppError> {
    use crate::gateway::GatewayStatus;
    if matches!(status, GatewayStatus::Pending) {
        return Ok(false);
    }
    let found: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, payer_account_ref FROM customer_payment \
         WHERE gateway_system_ref = $1 AND gateway_reference = $2 \
         AND (is_active IS NULL OR is_active = true) \
         ORDER BY id LIMIT 1",
    )
    .bind(system_id.to_string())
    .bind(gateway_reference)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (payment, account) = found.ok_or_else(|| {
        AppError::Validation(format!(
            "no payment has the gateway reference {gateway_reference}"
        ))
    })?;
    // The account's money moves under its balance lock, as every payment's.
    if let Some(account) = account {
        lock_account(tx, account).await?;
    }
    let (amount, currency, current, link): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT amount::text, currency, status, payment_link_ref FROM customer_payment \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(payment)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let amount = text(amount.as_deref());
    let currency = currency
        .unwrap_or_else(|| "SAR".into())
        .to_ascii_uppercase();
    let current = current.unwrap_or_else(|| "pending".into());
    let (next, feed, comment) = match status {
        GatewayStatus::Pending => return Ok(false),
        GatewayStatus::Succeeded { amount: paid, fee } => {
            if !matches!(current.as_str(), "pending" | "failed") {
                return Ok(false);
            }
            if *paid != amount {
                return Err(AppError::Validation(format!(
                    "the gateway reports {paid} {currency}; the payment is {amount}"
                )));
            }
            let received = Utc::now().date_naive();
            // A payment through a link for an invoice pays that invoice
            // first; any other is allocated oldest due first.
            let link_invoice: Option<Uuid> = match link {
                Some(link) => sqlx::query_scalar::<_, Option<Uuid>>(
                    "SELECT invoice_ref FROM payment_link WHERE id = $1",
                )
                .bind(link)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::internal)?
                .flatten(),
                None => None,
            };
            let credit = match account {
                Some(account) => {
                    let mut open = open_invoices(tx, account).await?;
                    open.retain(|i| i.currency == currency);
                    let explicit: Option<Vec<(Uuid, Decimal)>> = link_invoice.map(|invoice| {
                        open.iter()
                            .find(|i| i.id == invoice)
                            .map(|i| vec![(invoice, i.open.min(amount))])
                            .unwrap_or_default()
                    });
                    let allocation = allocate(amount, &currency, &open, explicit.as_deref())
                        .map_err(alloc_error)?;
                    write_allocations(tx, payment, &allocation.lines, received, actor).await?;
                    allocation.credit
                }
                None => amount,
            };
            // The link has done its work.
            if let Some(link) = link {
                let used = sqlx::query(
                    "UPDATE payment_link SET status = 'used', used_at = now(), modified_at = now(), \
                         row_version = row_version + 1 \
                     WHERE id = $1 AND COALESCE(status, 'open') = 'open'",
                )
                .bind(link)
                .execute(&mut **tx)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
                if used > 0 {
                    emit_named(
                        tx,
                        "payment_link",
                        link,
                        ChangeOperation::Update,
                        "billing.payment_link.used",
                    )
                    .await?;
                }
            }
            sqlx::query(
                "UPDATE customer_payment SET status = 'succeeded', fee = $2::numeric, \
                 unallocated = $3::numeric, received_on = $4, modified_at = now(), \
                 row_version = row_version + 1 \
                 WHERE id = $1",
            )
            .bind(payment)
            .bind(fee.map(|f| f.to_string()))
            .bind(credit.to_string())
            .bind(received)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            ("succeeded", "billing.payment.succeeded", None)
        }
        GatewayStatus::Failed { reason } => {
            if current != "pending" {
                return Ok(false);
            }
            sqlx::query(
                "UPDATE customer_payment SET status = 'failed', modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1",
            )
            .bind(payment)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            ("failed", "billing.payment.failed", Some(reason.clone()))
        }
        GatewayStatus::Refunded { amount: refunded } => {
            let next = if *refunded >= amount {
                "refunded"
            } else {
                "partially_refunded"
            };
            if !matches!(current.as_str(), "succeeded" | "partially_refunded") || current == next {
                return Ok(false);
            }
            sqlx::query(
                "UPDATE customer_payment SET status = $2, modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1",
            )
            .bind(payment)
            .bind(next)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (
                next,
                "billing.payment.refunded",
                Some(format!("{refunded} {currency} refunded")),
            )
        }
    };
    emit_named(
        tx,
        "customer_payment",
        payment,
        ChangeOperation::Update,
        feed,
    )
    .await?;
    business_event(
        tx,
        state,
        "customer_payment",
        payment,
        AuditOperation::Update,
        &format!("billing.payment_{next}"),
        actor,
        comment,
    )
    .await?;
    Ok(true)
}

/// `customer_payment.create`: may record payments.
#[derive(Debug)]
pub struct PaymentCreate;

impl attome_server::authz::PrivilegeKey for PaymentCreate {
    const KEY: &'static str = "customer_payment.create";
}

/// `billing.payment_reverse`: may reverse a recorded payment.
#[derive(Debug)]
pub struct PaymentReverse;

impl attome_server::authz::PrivilegeKey for PaymentReverse {
    const KEY: &'static str = "billing.payment_reverse";
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/payments",
    tag = "billing",
    request_body = NewPayment,
    responses(
        (status = 200, description = "The payment and how it was allocated", body = PaymentRecorded),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not record payments", body = attome_types::ErrorResponse),
        (status = 409, description = "Another payment for the account is being recorded", body = attome_types::ErrorResponse),
        (status = 422, description = "A bad amount, currency, method or allocation", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_payment(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<PaymentCreate>>,
    axum::Json(body): axum::Json<NewPayment>,
) -> Result<axum::Json<PaymentRecorded>, AppError> {
    Ok(axum::Json(record_payment(&state, &ctx, &body).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReverseRequest {
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentReversed {
    pub payment_id: Uuid,
    /// The invoices that reopened.
    pub invoices: Vec<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/payments/{id}/reverse",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The payment")),
    request_body = ReverseRequest,
    responses(
        (status = 200, description = "Reversed; its invoices reopened", body = PaymentReversed),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not reverse payments", body = attome_types::ErrorResponse),
        (status = 404, description = "No such payment", body = attome_types::ErrorResponse),
        (status = 409, description = "Already reversed, or the account is busy", body = attome_types::ErrorResponse),
        (status = 422, description = "No reason", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
)]
pub(crate) async fn post_reverse(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<PaymentReverse>>,
    axum::extract::Path(payment): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ReverseRequest>,
) -> Result<axum::Json<PaymentReversed>, AppError> {
    let invoices = reverse_payment(&state, &ctx, payment, &body.reason).await?;
    Ok(axum::Json(PaymentReversed {
        payment_id: payment,
        invoices,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/accounts/{id}/apply-credit",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The account")),
    responses(
        (status = 200, description = "What each payment's credit paid", body = Vec<PaymentRecorded>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not record payments", body = attome_types::ErrorResponse),
        (status = 409, description = "Another payment for the account is being recorded", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
)]
pub(crate) async fn post_apply_credit(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<PaymentCreate>>,
    axum::extract::Path(account): axum::extract::Path<Uuid>,
) -> Result<axum::Json<Vec<PaymentRecorded>>, AppError> {
    Ok(axum::Json(apply_credit(&state, &ctx, account).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_payment, post_reverse, post_apply_credit),
    components(schemas(
        AllocationRequest,
        NewPayment,
        AllocationLine,
        PaymentRecorded,
        ReverseRequest,
        PaymentReversed
    ))
)]
pub(crate) struct ApiDocFragment;
