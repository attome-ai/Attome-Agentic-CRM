//! F8-T8: risky orders, held for a person.
//!
//! [`assess`] runs after a shop order is written (portal checkout and guest
//! checkout) and computes its signals ([`signals`], pure):
//!
//! - cash on delivery above [`COD_LIMIT_SETTING`] (0, the default, is off);
//! - [`FAILED_PAYMENTS`] or more failed card payments for the order's
//!   account in the last 24 hours (not for the shared guest account, where
//!   one buyer's failures say nothing about another's);
//! - a billing country other than the delivery country, once orders carry
//!   both (they carry neither yet, so this never fires today).
//!
//! When any fires, a `risky_order_review` (`open`, the reasons) is written
//! through the record engine. While it is open, fulfilment opens a `fraud`
//! hold on the order's fulfilment orders, so nothing ships until a person
//! clears the hold; the person sets the review `released` or `cancelled`
//! through the generic record API. No agent action changes either.

use std::str::FromStr;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde_json::json;
use uuid::Uuid;

/// Cash on delivery above this is held (0: never).
pub const COD_LIMIT_SETTING: &str = "commerce.risk.cod_limit";
/// Failed card payments in 24 hours that hold an order.
pub const FAILED_PAYMENTS: i64 = 3;

/// The reasons an order looks risky. Pure.
pub fn signals(
    cod_amount: Option<Decimal>,
    cod_limit: Decimal,
    failed_payments: i64,
    billing_country: Option<&str>,
    delivery_country: Option<&str>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Some(cod) = cod_amount
        && cod_limit > Decimal::ZERO
        && cod > cod_limit
    {
        reasons.push(format!(
            "cash on delivery of {cod} is above the {cod_limit} limit"
        ));
    }
    if failed_payments >= FAILED_PAYMENTS {
        reasons.push(format!(
            "{failed_payments} failed card payments in the last 24 hours"
        ));
    }
    if let (Some(billing), Some(delivery)) = (billing_country, delivery_country)
        && !billing.trim().eq_ignore_ascii_case(delivery.trim())
    {
        reasons.push(format!("billed in {billing} but delivered to {delivery}"));
    }
    reasons
}

fn cod_limit(state: &EngineState) -> Decimal {
    crate::commerce::setting(state, COD_LIMIT_SETTING)
        .as_f64()
        .and_then(|v| Decimal::from_str(&v.to_string()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// Assesses `order` and opens its risk review when a signal fires; the
/// review's id.
pub async fn assess(
    state: &EngineState,
    ctx: &SecurityContext,
    order: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let db = &state.base.db;
    let row: Option<(Option<String>, Option<Uuid>)> =
        sqlx::query_as("SELECT cod_amount::text, account_ref FROM \"order\" WHERE id = $1")
            .bind(order)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some((cod, account)) = row else {
        return Err(AppError::NotFound);
    };
    let guest = crate::commerce::setting(state, crate::guest_checkout::GUEST_ACCOUNT_SETTING)
        .as_str()
        .and_then(|s| Uuid::parse_str(s.trim()).ok());
    let failed: i64 = match account {
        Some(account) if Some(account) != guest => sqlx::query_scalar(
            "SELECT count(*) FROM customer_payment \
              WHERE payer_account_ref = $1 AND status::text = 'failed' \
                AND method::text IN ('card', 'mada', 'apple_pay') \
                AND modified_at > now() - interval '24 hours'",
        )
        .bind(account)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?,
        _ => 0,
    };
    let reasons = signals(
        cod.as_deref().and_then(|c| Decimal::from_str(c).ok()),
        cod_limit(state),
        failed,
        None,
        None,
    );
    if reasons.is_empty() {
        return Ok(None);
    }
    let (id, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "risky_order_review",
        json!({
            "order_ref": order,
            "reasons": reasons.join("; "),
            "status": "open",
        }),
    )
    .await?;
    Ok(Some(id))
}

/// [`assess`] after an order is written: a failure is logged, never the
/// buyer's error (the order stands; staff confirm it as usual).
pub async fn assess_logged(state: &EngineState, ctx: &SecurityContext, order: Uuid) {
    if let Err(error) = assess(state, ctx, order).await {
        tracing::error!(%order, %error, "shop order: the risk review could not be opened");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn risk_signals_fire_on_their_thresholds() {
        assert!(signals(Some(d("900")), d("1000"), 2, None, None).is_empty());
        assert_eq!(signals(Some(d("1200")), d("1000"), 0, None, None).len(), 1);
        assert!(
            signals(Some(d("5000")), Decimal::ZERO, 0, None, None).is_empty(),
            "no limit set"
        );
        assert_eq!(signals(None, Decimal::ZERO, 3, None, None).len(), 1);
        assert_eq!(
            signals(None, Decimal::ZERO, 0, Some("SA"), Some("ae")).len(),
            1
        );
        assert!(signals(None, Decimal::ZERO, 0, Some("SA"), Some("sa")).is_empty());
    }
}
