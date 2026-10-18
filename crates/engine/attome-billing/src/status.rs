//! Payment status (roadmap F4-T10): derived, never set by hand.
//!
//! - [`refresh_status`] recomputes one issued invoice's `paid_total` (its
//!   live, unreversed `payment_allocation` rows), `open_total` (grand total
//!   less paid and less `written_off_total`, F4-T12) and `payment_status`: `paid` when nothing is open, `overdue`
//!   past the due date, `partly_paid` when something is paid, else `open`.
//!   A written-off invoice keeps `written_off`. Payments (F5) call it after
//!   allocating; the sweep below catches the passage of time.
//! - The `BillingOverdueSweep` job (nightly) marks issued invoices past due
//!   with something open as `overdue`, 500 per statement until none are
//!   left.
//! - The billing pack's changeset `0009` disables `payment_status`,
//!   `paid_total` and `open_total` on issued invoices for every writer but
//!   this engine, so there is no manual "mark paid".
//!
//! Both write the derived columns directly (they are this engine's, like
//! the issue fields) and bump `row_version`, so a client holding an older
//! version sees a conflict rather than overwriting them.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

/// Invoices marked overdue per statement.
const OVERDUE_BATCH: i64 = 500;

/// What an invoice owes after its payments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PaymentState {
    pub invoice_id: Uuid,
    pub paid_total: String,
    pub open_total: String,
    pub payment_status: String,
}

/// The payment status for these amounts.
pub fn derive(
    grand: Decimal,
    paid: Decimal,
    written_off: Decimal,
    due: Option<NaiveDate>,
    today: NaiveDate,
    current: Option<&str>,
) -> &'static str {
    if current == Some("written_off") {
        return "written_off";
    }
    let open = grand - paid - written_off;
    if open <= Decimal::ZERO && written_off > Decimal::ZERO {
        return "written_off";
    }
    if open <= Decimal::ZERO {
        "paid"
    } else if due.is_some_and(|d| d < today) {
        "overdue"
    } else if paid > Decimal::ZERO {
        "partly_paid"
    } else {
        "open"
    }
}

type InvoiceRow = (
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
);

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// Recomputes an issued invoice's paid and open totals and its status.
pub async fn refresh_status(
    state: &EngineState,
    invoice_id: Uuid,
) -> Result<PaymentState, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<InvoiceRow> = sqlx::query_as(
        "SELECT status, grand_total::text, due_date::date, payment_status, \
                written_off_total::text \
         FROM invoice WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
         FOR UPDATE",
    )
    .bind(invoice_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((status, grand, due, current, written_off)) = row else {
        return Err(AppError::NotFound);
    };
    if matches!(status.as_deref().unwrap_or("draft"), "draft" | "void") {
        return Err(AppError::Conflict(
            "only an issued invoice has a payment status",
        ));
    }
    let paid: Option<String> = sqlx::query_scalar(
        "SELECT SUM(amount)::text FROM payment_allocation \
         WHERE invoice_ref = $1 AND COALESCE(reversed, false) = false \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let grand = decimal(grand.as_deref());
    let paid = decimal(paid.as_deref());
    let written_off = decimal(written_off.as_deref());
    let open = grand - paid - written_off;
    let derived = derive(
        grand,
        paid,
        written_off,
        due,
        Utc::now().date_naive(),
        current.as_deref(),
    );
    sqlx::query(
        "UPDATE invoice SET paid_total = $2::numeric, open_total = $3::numeric, \
             payment_status = $4, modified_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND (paid_total IS DISTINCT FROM $2::numeric \
           OR open_total IS DISTINCT FROM $3::numeric OR payment_status IS DISTINCT FROM $4)",
    )
    .bind(invoice_id)
    .bind(paid.to_string())
    .bind(open.to_string())
    .bind(derived)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(PaymentState {
        invoice_id,
        paid_total: paid.to_string(),
        open_total: open.to_string(),
        payment_status: derived.to_owned(),
    })
}

/// Marks issued invoices past due with something open as overdue; returns
/// how many.
pub async fn overdue_sweep(state: &EngineState) -> Result<u64, AppError> {
    let today = Utc::now().date_naive();
    let mut marked = 0;
    loop {
        let done = sqlx::query(
            "UPDATE invoice SET payment_status = 'overdue', modified_at = now(), \
                 row_version = row_version + 1 \
             WHERE id IN ( \
                 SELECT id FROM invoice \
                 WHERE COALESCE(status, 'draft') IN ('issued', 'sent', 'overdue') \
                   AND COALESCE(payment_status, 'open') IN ('open', 'partly_paid') \
                   AND due_date::date < $1 AND open_total > 0 \
                   AND (is_active IS NULL OR is_active = true) \
                 ORDER BY id LIMIT $2)",
        )
        .bind(today)
        .bind(OVERDUE_BATCH)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        marked += done;
        if done < OVERDUE_BATCH as u64 {
            break;
        }
    }
    Ok(marked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, day).unwrap()
    }

    #[test]
    fn status_follows_payments_and_the_due_date() {
        let hundred = Decimal::from(100);
        let zero = Decimal::ZERO;
        let today = d(18);
        assert_eq!(
            derive(hundred, hundred, zero, Some(d(1)), today, None),
            "paid"
        );
        assert_eq!(
            derive(hundred, zero, zero, Some(d(17)), today, None),
            "overdue"
        );
        assert_eq!(
            derive(hundred, Decimal::from(40), zero, Some(d(20)), today, None),
            "partly_paid"
        );
        assert_eq!(
            derive(hundred, zero, zero, Some(d(18)), today, None),
            "open"
        );
        assert_eq!(
            derive(hundred, zero, zero, Some(d(1)), today, Some("written_off")),
            "written_off"
        );
        // Paid 60, the rest written off: written off, not paid.
        assert_eq!(
            derive(
                hundred,
                Decimal::from(60),
                Decimal::from(40),
                Some(d(1)),
                today,
                None
            ),
            "written_off"
        );
    }
}
