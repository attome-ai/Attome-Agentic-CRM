//! Saved methods and recurring charges (roadmap F5-T9).
//!
//! [`charge_due`] charges each due invoice with an open amount to its
//! account's default saved payment method, through the method's gateway:
//!
//! - One attempt is one `customer_payment` with `charge_attempt` n and
//!   `charged_invoice_ref`, saved `pending` with its gateway reference in its
//!   own transaction before the gateway is called (outside any transaction)
//!   with the idempotency key `invoice:{id}:attempt:{n}`. An attempt whose
//!   answer was lost stays `pending`, and the next run asks again with the
//!   same key, so the gateway charges it once.
//! - A failed attempt gets `next_retry_on` from the `billing.retry.days`
//!   setting (1, 3 and 7 days by default), and the invoice's contact is
//!   emailed a fresh payment link. After the last attempt there is no retry
//!   date; the change feed gets `billing.invoice.collections_handoff` for
//!   collections (AI5) instead.
//! - A succeeded attempt is applied through the payment service, which pays
//!   the charged invoice first.
//!
//! The daily `BillingChargeDue` job runs it only when the
//! `billing.saved_methods.enabled` setting is on. Card-updater events
//! ([`apply_card_update_in_tx`]) keep a saved method's brand, last four
//! digits and expiry current.

use std::str::FromStr;

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_types::AppError;
use chrono::{Duration, NaiveDate};
use rust_decimal::Decimal;
use serde::Serialize;
use uuid::Uuid;

use crate::gateway::{
    CardUpdate, GatewayError, GatewayHttp, GatewayStatus, GatewaySystem, PaymentGateway,
};

/// The setting holding the retry delays in days, after each failure.
pub const RETRY_DAYS_SETTING: &str = "billing.retry.days";

/// The setting that turns recurring charges on.
pub const ENABLED_SETTING: &str = "billing.saved_methods.enabled";

/// Invoices one run looks at.
const BATCH: i64 = 500;

/// How a run finds the adapter for a gateway system (tests pass a fake).
pub trait AdapterSource: Send + Sync {
    fn adapter(&self, system: &GatewaySystem) -> Result<Box<dyn PaymentGateway>, AppError>;
}

/// The gateways' real adapters.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveAdapters;

impl AdapterSource for LiveAdapters {
    fn adapter(&self, system: &GatewaySystem) -> Result<Box<dyn PaymentGateway>, AppError> {
        crate::gateway::gateway_for(&system.adapter, GatewayHttp::new(&system.base_url)?)
            .ok_or_else(|| AppError::Validation(format!("no adapter for {}", system.adapter)))
    }
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChargeRun {
    pub succeeded: usize,
    pub failed: usize,
    pub pending: usize,
    pub handed_off: usize,
}

/// Whether recurring charges are on.
pub fn enabled(state: &EngineState) -> bool {
    attome_core::setting_registry()
        .get(ENABLED_SETTING)
        .is_some_and(|d| {
            let (value, _) = state.settings.load().resolve(d, None, None);
            value.as_bool() == Some(true)
        })
}

/// The retry delays (days after each failure), from the setting.
pub fn retry_days(state: &EngineState) -> Vec<i64> {
    let configured = attome_core::setting_registry()
        .get(RETRY_DAYS_SETTING)
        .and_then(|d| {
            let (value, _) = state.settings.load().resolve(d, None, None);
            serde_json::from_value::<Vec<i64>>(value).ok()
        });
    match configured {
        Some(days) if days.iter().all(|d| (1..=90).contains(d)) => days,
        _ => vec![1, 3, 7],
    }
}

/// The day the attempt after failed attempt `attempt` (1-based) is due, or
/// none after the last one.
pub fn next_retry(today: NaiveDate, attempt: i32, days: &[i64]) -> Option<NaiveDate> {
    let index = usize::try_from(attempt).ok()?.checked_sub(1)?;
    days.get(index).map(|d| today + Duration::days(*d))
}

/// The idempotency key of an invoice's attempt n.
pub fn attempt_key(invoice: Uuid, attempt: i32) -> String {
    format!("invoice:{invoice}:attempt:{attempt}")
}

type DueRow = (
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

type AttemptRow = (
    Uuid,
    Option<i32>,
    Option<String>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
);

/// Charges the invoices due on `today` to their saved methods.
pub async fn charge_due(
    state: &EngineState,
    today: NaiveDate,
    adapters: &dyn AdapterSource,
) -> Result<ChargeRun, AppError> {
    let days = retry_days(state);
    let due: Vec<DueRow> = sqlx::query_as(
        "SELECT i.id, i.account_ref, i.open_total::text, i.currency, m.gateway_system_ref, m.token \
         FROM invoice i \
         JOIN LATERAL ( \
             SELECT gateway_system_ref, token FROM saved_payment_method m \
             WHERE m.account_ref = i.account_ref AND m.is_default = true \
               AND m.token IS NOT NULL AND (m.is_active IS NULL OR m.is_active = true) \
             ORDER BY m.id LIMIT 1) m ON true \
         WHERE COALESCE(i.status, 'draft') IN ('issued', 'sent', 'overdue') \
           AND COALESCE(i.kind, 'invoice') IN ('invoice', 'debit_note') \
           AND COALESCE(i.payment_status, 'open') NOT IN ('paid', 'written_off') \
           AND i.open_total > 0 AND i.due_date::date <= $1 \
           AND (i.is_active IS NULL OR i.is_active = true) \
         ORDER BY i.due_date, i.id LIMIT $2",
    )
    .bind(today)
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut run = ChargeRun::default();
    for (invoice, account, open, currency, system_ref, token) in due {
        let (Some(account), Some(system_ref), Some(token)) = (account, system_ref, token) else {
            continue;
        };
        let Ok(system_id) = Uuid::parse_str(system_ref.trim()) else {
            tracing::warn!(%invoice, "billing: a saved method names no gateway system");
            continue;
        };
        let open = open
            .as_deref()
            .and_then(|o| Decimal::from_str(o.trim()).ok())
            .unwrap_or_default();
        let currency = currency.unwrap_or_else(|| "SAR".into());
        let outcome = charge_invoice(
            state,
            today,
            &days,
            adapters,
            Due {
                invoice,
                account,
                open,
                currency: &currency,
                system_id,
                token: &token,
            },
        )
        .await;
        match outcome {
            Ok(Some(Outcome::Succeeded)) => run.succeeded += 1,
            Ok(Some(Outcome::Failed { handed_off })) => {
                run.failed += 1;
                run.handed_off += usize::from(handed_off);
            }
            Ok(Some(Outcome::Pending)) => run.pending += 1,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%invoice, error = %e, "billing: a recurring charge did not run");
            }
        }
    }
    Ok(run)
}

struct Due<'a> {
    invoice: Uuid,
    account: Uuid,
    open: Decimal,
    currency: &'a str,
    system_id: Uuid,
    token: &'a str,
}

enum Outcome {
    Succeeded,
    Failed { handed_off: bool },
    Pending,
}

/// One invoice: a new attempt, a pending one asked again, or nothing.
async fn charge_invoice(
    state: &EngineState,
    today: NaiveDate,
    days: &[i64],
    adapters: &dyn AdapterSource,
    due: Due<'_>,
) -> Result<Option<Outcome>, AppError> {
    let last: Option<AttemptRow> = sqlx::query_as(
        "SELECT id, charge_attempt::int, status, next_retry_on::date, gateway_reference, \
             amount::text \
         FROM customer_payment \
         WHERE charged_invoice_ref = $1 AND charge_attempt IS NOT NULL \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY charge_attempt DESC, id DESC LIMIT 1",
    )
    .bind(due.invoice)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let system = crate::gateway::system(state, due.system_id).await?;
    let gateway = adapters.adapter(&system)?;
    let (payment, attempt, reference, amount) = match last {
        None => new_attempt(state, &system, gateway.as_ref(), &due, 1).await?,
        Some((payment, attempt, status, retry_on, reference, amount)) => {
            let attempt = attempt.unwrap_or(1);
            match status.as_deref() {
                // No answer yet: ask again with the same key and amount.
                Some("pending") => (
                    payment,
                    attempt,
                    reference.unwrap_or_else(|| {
                        gateway.token_charge_reference(&attempt_key(due.invoice, attempt))
                    }),
                    amount
                        .as_deref()
                        .and_then(|a| Decimal::from_str(a.trim()).ok())
                        .unwrap_or(due.open),
                ),
                Some("failed") => match retry_on {
                    Some(day) if day <= today => {
                        new_attempt(state, &system, gateway.as_ref(), &due, attempt + 1).await?
                    }
                    // Waiting for its retry day, or handed to collections.
                    _ => return Ok(None),
                },
                // Paid (or refunded) already.
                _ => return Ok(None),
            }
        }
    };
    let credential = crate::gateway::credential(state, &system).await?;
    let key = attempt_key(due.invoice, attempt);
    let answer = gateway
        .charge_token(&credential, due.token, amount, due.currency, &key)
        .await;
    let status = match answer {
        Ok(status) => status,
        Err(GatewayError::Unavailable(reason)) => {
            tracing::warn!(invoice = %due.invoice, attempt, %reason, "billing: the gateway did not answer a recurring charge; it is asked again next run");
            return Ok(Some(Outcome::Pending));
        }
        Err(GatewayError::Refused(reason)) => GatewayStatus::Failed { reason },
        Err(GatewayError::BadSignature) => GatewayStatus::Failed {
            reason: "the gateway refused the call".into(),
        },
    };
    let actor = system.service_principal.unwrap_or_else(Uuid::nil);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::payment::service::apply_gateway_status_in_tx(
        &mut tx, state, system.id, &reference, &status, actor,
    )
    .await?;
    let outcome = match status {
        GatewayStatus::Succeeded { .. } | GatewayStatus::Refunded { .. } => Outcome::Succeeded,
        GatewayStatus::Pending => Outcome::Pending,
        GatewayStatus::Failed { reason } => {
            let retry_on = next_retry(today, attempt, days);
            sqlx::query(
                "UPDATE customer_payment SET next_retry_on = $2, modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
            )
            .bind(payment)
            .bind(
                retry_on
                    .and_then(|d| d.and_hms_opt(0, 0, 0))
                    .map(|d| d.and_utc()),
            )
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            notify_failure(&mut tx, state, &due, attempt, &reason, actor).await?;
            if retry_on.is_none() {
                emit_named(
                    &mut tx,
                    "invoice",
                    due.invoice,
                    ChangeOperation::Update,
                    "billing.invoice.collections_handoff",
                )
                .await?;
            }
            Outcome::Failed {
                handed_off: retry_on.is_none(),
            }
        }
    };
    attome_db::tx::commit(tx).await?;
    Ok(Some(outcome))
}

/// Saves attempt n as a pending payment carrying its gateway reference.
async fn new_attempt(
    state: &EngineState,
    system: &GatewaySystem,
    gateway: &dyn PaymentGateway,
    due: &Due<'_>,
    attempt: i32,
) -> Result<(Uuid, i32, String, Decimal), AppError> {
    let payment = Uuid::now_v7();
    let reference = gateway.token_charge_reference(&attempt_key(due.invoice, attempt));
    let actor = system.service_principal.unwrap_or_else(Uuid::nil);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO customer_payment (id, name, payer_account_ref, amount, currency, method, \
             status, gateway_system_ref, gateway_reference, charge_attempt, charged_invoice_ref, \
             unallocated, created_by, owner_ref, owner_type, is_active, row_version) \
         VALUES ($1, $2, $3, $4::numeric, $5, 'card', 'pending', $6, $7, $8, $9, 0, $10, $10, 0, \
             true, 0)",
    )
    .bind(payment)
    .bind(format!("PAY-{}", payment.simple()))
    .bind(due.account)
    .bind(due.open.to_string())
    .bind(due.currency)
    .bind(system.id.to_string())
    .bind(&reference)
    .bind(attempt)
    .bind(due.invoice)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        &mut tx,
        "customer_payment",
        payment,
        ChangeOperation::Create,
        "billing.payment.pending",
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((payment, attempt, reference, due.open))
}

type ContactRow = (Option<String>, Option<String>, Option<bool>);

/// Emails the invoice's contact a fresh payment link after a failed charge.
async fn notify_failure(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    due: &Due<'_>,
    attempt: i32,
    reason: &str,
    actor: Uuid,
) -> Result<(), AppError> {
    let link = super::link::insert_link_in_tx(
        tx,
        state,
        super::link::NewLink {
            invoice_id: Some(due.invoice),
            order_id: None,
            account_id: due.account,
            amount: due.open,
            currency: due.currency.to_owned(),
            hours: super::link::DEFAULT_EXPIRY_HOURS,
        },
        actor,
    )
    .await?;
    let contact: Option<ContactRow> = sqlx::query_as(
        "SELECT i.invoice_number, c.email, c.do_not_email \
         FROM invoice i LEFT JOIN contact c ON c.id = i.contact_ref WHERE i.id = $1",
    )
    .bind(due.invoice)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((number, Some(email), do_not_email)) = contact else {
        tracing::info!(invoice = %due.invoice, attempt, "billing: a recurring charge failed; the invoice has no contact email");
        return Ok(());
    };
    if do_not_email == Some(true) || !email.contains('@') {
        return Ok(());
    }
    let number = number.unwrap_or_default();
    let reason: String = reason.chars().take(200).collect();
    let message = attome_email::EmailMessage {
        to: email,
        subject: format!("Payment for invoice {number} failed | تعذّر تحصيل الفاتورة {number}"),
        text_body: format!(
            "We could not charge your saved card for invoice {number} ({reason}).\n\
             Pay {amount} {currency} here: {url}\n\n\
             تعذّر تحصيل الفاتورة {number} من بطاقتك المحفوظة.\n\
             ادفع {amount} {currency} من هنا: {url}",
            amount = due.open,
            currency = due.currency,
            url = link.url,
        ),
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
        stream: Default::default(),
        list_unsubscribe: None,
    };
    attome_jobs::enqueue_in_tx(
        tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(message)),
    )
    .await
    .map_err(AppError::internal)
}

/// Applies a card updater's event to the saved method with its token on
/// this gateway system; `false` when no method has it.
pub async fn apply_card_update_in_tx(
    tx: &mut attome_db::Tx<'_>,
    system_id: Uuid,
    update: &CardUpdate,
) -> Result<bool, AppError> {
    let last4 = update
        .last4
        .as_deref()
        .map(|l| l.chars().filter(char::is_ascii_digit).collect::<String>())
        .filter(|l| l.len() == 4);
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE saved_payment_method SET \
             brand = COALESCE($3, brand), last4 = COALESCE($4, last4), \
             expiry_month = COALESCE($5, expiry_month), expiry_year = COALESCE($6, expiry_year), \
             modified_at = now(), row_version = row_version + 1 \
         WHERE token = $1 AND gateway_system_ref = $2 \
           AND (is_active IS NULL OR is_active = true) \
         RETURNING id",
    )
    .bind(&update.token)
    .bind(system_id.to_string())
    .bind(update.brand.as_deref())
    .bind(last4)
    .bind(update.expiry_month)
    .bind(update.expiry_year)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for id in &ids {
        emit_named(
            tx,
            "saved_payment_method",
            *id,
            ChangeOperation::Update,
            "billing.saved_method.updated",
        )
        .await?;
    }
    Ok(!ids.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_follow_the_days_then_stop() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 18).unwrap();
        let days = [1, 3, 7];
        assert_eq!(
            next_retry(today, 1, &days),
            NaiveDate::from_ymd_opt(2026, 10, 19)
        );
        assert_eq!(
            next_retry(today, 2, &days),
            NaiveDate::from_ymd_opt(2026, 10, 21)
        );
        assert_eq!(
            next_retry(today, 3, &days),
            NaiveDate::from_ymd_opt(2026, 10, 25)
        );
        assert_eq!(next_retry(today, 4, &days), None);
        assert_eq!(next_retry(today, 0, &days), None);
    }

    #[test]
    fn attempt_keys_differ_per_attempt() {
        let invoice = Uuid::nil();
        assert_ne!(attempt_key(invoice, 1), attempt_key(invoice, 2));
        assert_eq!(
            attempt_key(invoice, 1),
            format!("invoice:{invoice}:attempt:1")
        );
    }
}
