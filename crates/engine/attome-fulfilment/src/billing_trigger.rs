//! F6-T13: an order billed on shipment or on delivery asks billing (F4) for
//! exactly what shipped or arrived.
//!
//! An order's `billing_rule` (sales pack 0027) is `on_confirm` (the default:
//! the order confirm asks billing for the whole order, D10-T2),
//! `on_shipment` or `on_delivery`. [`sweep`] reads the change feed with its
//! own cursor ([`CONSUMER`]); for each shipment that changed it runs
//! [`bill_shipment`], which sends one invoice request per shipment line for
//! the shipped quantity once the shipment has left (`on_shipment`) or
//! arrived (`on_delivery`). Each request is keyed
//! `ship:{shipment_line_id}:{rule}` under `source_kind = shipment_line`, so
//! a rerun, a second node or a shipment that changes again asks once
//! (`attome_billing::requests::submit_request` stores a key once). Nothing
//! here writes an invoice; billing's request sweep makes the drafts.
//!
//! The cursor moves only after every shipment of the batch was handled. A
//! shipment billing refuses for good (no account, a bad currency, a line
//! with no price) is logged with the reason and passed over, so one bad
//! order cannot hold up the feed; any other failure leaves the cursor where
//! it was and the next sweep retries the batch.

use std::collections::HashSet;

use attome_billing::requests::{InvoiceRequest, RequestLine, submit_request};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_types::AppError;
use chrono::Utc;
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-fulfilment/billing";
/// The job's name.
pub const JOB: &str = "fulfilment_billing";
/// The invoice requests' `source_kind`.
pub const SOURCE_KIND: &str = "shipment_line";
/// Change events read per sweep.
const BATCH: i64 = 500;
/// Shipment lines billed per shipment.
const MAX_LINES: i64 = 500;

/// Shipment statuses that mean the goods have left.
const LEFT: [&str; 7] = [
    "picked_up",
    "in_transit",
    "out_for_delivery",
    "delivered",
    "failed_attempt",
    "refused",
    "returned",
];

/// The billing rule a shipment is due under now, if any: `on_shipment` once
/// it has left (`shipped_on` set or a status past booking), `on_delivery`
/// once it is delivered. Any other rule (`on_confirm`, unset) bills at
/// confirm, not here. Pure.
pub fn due_rule(rule: Option<&str>, status: Option<&str>, shipped: bool) -> Option<&'static str> {
    match rule.map(str::trim) {
        Some("on_shipment") if shipped || status.is_some_and(|s| LEFT.contains(&s)) => {
            Some("on_shipment")
        }
        Some("on_delivery") if status == Some("delivered") => Some("on_delivery"),
        _ => None,
    }
}

/// The request key of one shipment line under one rule. Pure.
pub fn idempotency_key(shipment_line: Uuid, rule: &str) -> String {
    format!("ship:{shipment_line}:{rule}")
}

/// An order line's net unit price: its total over its quantity when it has
/// one (discounts are in the total), else its unit price. Pure.
pub fn net_unit_price(
    line_total: Option<f64>,
    quantity: Option<f64>,
    unit_price: Option<f64>,
) -> Option<f64> {
    let unit = match (line_total, quantity.filter(|q| *q > 0.0)) {
        (Some(total), Some(qty)) => Some(total / qty),
        _ => unit_price,
    }?;
    (unit.is_finite() && unit >= 0.0).then(|| (unit * 1_000_000.0).round() / 1_000_000.0)
}

/// The shipment, its fulfilment order's sales order and the order's rule
/// (read from `to_jsonb` so a deployment without the 0027 field reads no
/// rule rather than failing).
type ShipmentRow = (
    Option<String>,
    bool,
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
);

/// One shipment line with its order line's product, description and prices.
type LineRow = (
    Uuid,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// Sends billing the requests a shipment is due; returns how many were new.
pub async fn bill_shipment(state: &EngineState, shipment: Uuid) -> Result<usize, AppError> {
    let db = &state.base.db;
    let row: Option<ShipmentRow> = sqlx::query_as(
        "SELECT s.status::text, s.shipped_on IS NOT NULL, o.id, \
                to_jsonb(o) ->> 'billing_rule', o.account_ref, o.currency, \
                COALESCE(o.owner_ref, o.created_by), o.order_number \
           FROM shipment s \
           JOIN fulfilment_order f ON f.id = s.fulfilment_order_ref \
           JOIN \"order\" o ON o.id = f.order_ref \
          WHERE s.id = $1 \
            AND (s.is_active IS NULL OR s.is_active = true) \
            AND (f.is_active IS NULL OR f.is_active = true) \
            AND (o.is_active IS NULL OR o.is_active = true)",
    )
    .bind(shipment)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, shipped, order, rule, account, currency, owner, number)) = row else {
        return Ok(0);
    };
    let Some(rule) = due_rule(rule.as_deref(), status.as_deref(), shipped) else {
        return Ok(0);
    };
    let account =
        account.ok_or_else(|| AppError::Validation(format!("order {order} has no account")))?;
    let currency = currency
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 3)
        .ok_or_else(|| AppError::Validation(format!("order {order} has no currency")))?;
    let owner = owner.ok_or_else(|| AppError::Validation(format!("order {order} has no owner")))?;

    let lines: Vec<LineRow> = sqlx::query_as(
        "SELECT sl.id, sl.quantity::float8, ol.product_ref, ol.description, \
                ol.quantity::float8, ol.unit_price::float8, ol.line_total::float8 \
           FROM shipment_line sl \
           JOIN fulfilment_order_line fl ON fl.id = sl.fulfilment_order_line_ref \
           LEFT JOIN order_line ol ON ol.id::text = fl.order_line_ref \
                AND (ol.is_active IS NULL OR ol.is_active = true) \
          WHERE sl.shipment_ref = $1 AND (sl.is_active IS NULL OR sl.is_active = true) \
          ORDER BY sl.id LIMIT $2",
    )
    .bind(shipment)
    .bind(MAX_LINES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if lines.is_empty() {
        return Ok(0);
    }

    let ctx = state.base.security.resolve_strict(owner).await?;
    let label = number.unwrap_or_else(|| order.to_string());
    let today = Utc::now().date_naive();
    let mut created = 0;
    for (n, (line, shipped_qty, product, description, qty, unit, total)) in
        lines.into_iter().enumerate()
    {
        let Some(quantity) = shipped_qty.filter(|q| *q > 0.0) else {
            continue;
        };
        let price = net_unit_price(total, qty, unit)
            .ok_or_else(|| AppError::Validation(format!("order {label}: a line has no price")))?;
        let as_number = |v: f64| {
            serde_json::Number::from_f64(v)
                .ok_or_else(|| AppError::Validation(format!("order {label}: a bad amount")))
        };
        let request = InvoiceRequest {
            source_kind: SOURCE_KIND.to_owned(),
            source_ref: line.to_string(),
            idempotency_key: idempotency_key(line, rule),
            account_ref: account,
            currency: currency.clone(),
            request_date: Some(today),
            lines: vec![RequestLine {
                description: description
                    .filter(|d| !d.trim().is_empty())
                    .unwrap_or_else(|| format!("{label} line {}", n + 1)),
                quantity: as_number(quantity)?,
                unit_price: as_number(price)?,
                vat_category: None,
                product_ref: product,
                period_from: None,
                period_to: None,
            }],
        };
        if submit_request(state, &ctx, &request).await?.created {
            created += 1;
        }
    }
    if created > 0 {
        tracing::info!(%shipment, %order, rule, created, "shipment billing requested");
    }
    Ok(created)
}

/// Bills every shipment that changed since the last sweep; returns how many
/// requests were new.
pub async fn sweep(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut created = 0;
    let mut seen = HashSet::new();
    for e in &events {
        if e.entity_logicalname != "shipment"
            || !matches!(
                e.operation(),
                Some(ChangeOperation::Create | ChangeOperation::Update)
            )
            || !seen.insert(e.record_id)
        {
            continue;
        }
        match bill_shipment(state, e.record_id).await {
            Ok(n) => created += n,
            Err(AppError::Validation(reason)) => {
                tracing::warn!(shipment = %e.record_id, %reason, "shipment billing: not requested");
            }
            Err(error) => return Err(error),
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_follows_the_rule_and_the_shipment() {
        assert_eq!(due_rule(None, Some("delivered"), true), None);
        assert_eq!(due_rule(Some("on_confirm"), Some("delivered"), true), None);
        assert_eq!(due_rule(Some("on_shipment"), Some("booked"), false), None);
        assert_eq!(
            due_rule(Some("on_shipment"), Some("booked"), true),
            Some("on_shipment")
        );
        assert_eq!(
            due_rule(Some("on_shipment"), Some("in_transit"), false),
            Some("on_shipment")
        );
        assert_eq!(
            due_rule(Some("on_delivery"), Some("in_transit"), true),
            None
        );
        assert_eq!(
            due_rule(Some("on_delivery"), Some("delivered"), true),
            Some("on_delivery")
        );
    }

    #[test]
    fn net_price_uses_the_total_over_the_quantity() {
        assert_eq!(
            net_unit_price(Some(90.0), Some(2.0), Some(50.0)),
            Some(45.0)
        );
        assert_eq!(net_unit_price(None, Some(2.0), Some(50.0)), Some(50.0));
        assert_eq!(
            net_unit_price(Some(90.0), Some(0.0), Some(50.0)),
            Some(50.0)
        );
        assert_eq!(net_unit_price(None, None, None), None);
        assert_eq!(net_unit_price(None, None, Some(-1.0)), None);
        let line = Uuid::nil();
        assert_eq!(
            idempotency_key(line, "on_shipment"),
            format!("ship:{line}:on_shipment")
        );
    }
}
