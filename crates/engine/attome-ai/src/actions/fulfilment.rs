//! Fulfilment actions (roadmap F6-T16).
//!
//! - `fulfilment.status.read(order_id)`: an order's fulfilment orders, each
//!   with its location, status, promised date, lines and open holds.
//! - `fulfilment.hold.explain(fulfilment_order_id)`: why a fulfilment order
//!   cannot be released: its open holds, what each means and who may clear
//!   it.
//! - `fulfilment.sourcing.propose(order_id)`: which locations would ship an
//!   order's goods under the fewest-shipments rule, from the enabled stock
//!   locations and the stock seam (every location counts as stocked without
//!   inventory). A proposal only; a person applies it.
//!
//! All three only read. There is deliberately no tool that releases,
//! cancels or changes a carrier: those stay with people through the
//! fulfilment routes, which check holds and privileges.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_fulfilment::sourcing::{self, Line, Location, Rule};
use attome_modules::MODULE_FULFILMENT;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const STATUS_READ: &str = "fulfilment.status.read";
pub const HOLD_EXPLAIN: &str = "fulfilment.hold.explain";
pub const SOURCING_PROPOSE: &str = "fulfilment.sourcing.propose";

const ORDER_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "order_id": { "type": "string", "format": "uuid" } },
  "required": ["order_id"],
  "additionalProperties": false
}"#;

const FULFILMENT_ORDER_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "fulfilment_order_id": { "type": "string", "format": "uuid" } },
  "required": ["fulfilment_order_id"],
  "additionalProperties": false
}"#;

/// Most enabled locations a proposal weighs.
const MAX_LOCATIONS: i64 = 200;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_FULFILMENT,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            STATUS_READ,
            "Show how an order is being fulfilled: its fulfilment orders with location, status, \
             promised date, lines (ordered, shipped, backordered) and open holds.",
            ORDER_SCHEMA,
        ),
        read(
            HOLD_EXPLAIN,
            "Explain why a fulfilment order cannot be released: each open hold, what it means and \
             who may clear it. Never clears a hold.",
            FULFILMENT_ORDER_SCHEMA,
        ),
        read(
            SOURCING_PROPOSE,
            "Propose which stock locations would ship an order's goods with the fewest shipments, \
             and what no location can cover. A proposal only; nothing is changed.",
            ORDER_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(StatusRead),
        Box::new(HoldExplain),
        Box::new(SourcingPropose),
    ]
}

/// One fulfilment order: id, location, status, promised date.
type OrderRow = (
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
);
/// One fulfilment line: product, quantity, shipped, backordered.
type LineRow = (Option<Uuid>, Option<f64>, Option<f64>, Option<f64>);

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>>;

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

/// What a hold kind means and who clears it. Pure.
pub fn hold_meaning(kind: &str) -> &'static str {
    match kind {
        "credit" => {
            "The customer's account failed the credit check for this order's total. Finance clears it once credit is extended or payment arrives."
        }
        "prepayment" => {
            "The payment terms ask for payment before shipping. Someone with fulfilment_hold.release clears it once the payment is in."
        }
        "address" => {
            "The order has goods but no delivery address. Add the address, then clear the hold."
        }
        "fraud" => "The order was flagged for a fraud review. The reviewer clears it.",
        "manual" => "A person put the order on hold; the reason says why.",
        _ => "A hold that stops release until someone with fulfilment_hold.release clears it.",
    }
}

async fn open_holds(state: &EngineState, fulfilment_order: Uuid) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, kind::text, reason FROM fulfilment_hold \
          WHERE fulfilment_order_ref = $1 AND released_at IS NULL \
            AND (is_active IS NULL OR is_active = true) ORDER BY created_at",
    )
    .bind(fulfilment_order)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, reason)| {
            let kind = kind.unwrap_or_default();
            json!({ "hold_id": id, "kind": kind, "reason": reason, "meaning": hold_meaning(&kind) })
        })
        .collect())
}

struct StatusRead;

impl Action for StatusRead {
    fn id(&self) -> ActionId {
        ActionId(STATUS_READ)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let order = uuid_arg(args, "order_id")?;
            ctx.security.require("fulfilment_order", "read")?;
            let orders: Vec<OrderRow> =
                sqlx::query_as(
                    "SELECT id, location_ref, status::text, promised_date FROM fulfilment_order \
                      WHERE order_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY created_at",
                )
                .bind(order)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            let mut out = Vec::with_capacity(orders.len());
            for (id, location, status, promised) in orders {
                let lines: Vec<LineRow> = sqlx::query_as(
                    "SELECT product_ref, quantity::float8, quantity_shipped::float8, \
                            quantity_backordered::float8 FROM fulfilment_order_line \
                      WHERE fulfilment_order_ref = $1 AND (is_active IS NULL OR is_active = true) \
                      ORDER BY created_at",
                )
                .bind(id)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                let lines: Vec<Value> = lines
                    .into_iter()
                    .map(|(product, qty, shipped, backordered)| {
                        json!({
                            "product_id": product, "quantity": qty.unwrap_or(0.0),
                            "shipped": shipped.unwrap_or(0.0), "backordered": backordered.unwrap_or(0.0),
                        })
                    })
                    .collect();
                out.push(json!({
                    "fulfilment_order_id": id, "location_id": location, "status": status,
                    "promised_date": promised, "lines": lines,
                    "open_holds": open_holds(state, id).await?,
                }));
            }
            Ok(ActionResult::plain(json!({
                "order_id": order,
                "split": !out.is_empty(),
                "fulfilment_orders": out,
            })))
        })
    }
}

struct HoldExplain;

impl Action for HoldExplain {
    fn id(&self) -> ActionId {
        ActionId(HOLD_EXPLAIN)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let id = uuid_arg(args, "fulfilment_order_id")?;
            ctx.security.require("fulfilment_order", "read")?;
            let status: Option<Option<String>> = sqlx::query_scalar(
                "SELECT status::text FROM fulfilment_order \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let status = status.ok_or(AppError::NotFound)?;
            let holds = open_holds(state, id).await?;
            Ok(ActionResult::plain(json!({
                "fulfilment_order_id": id,
                "status": status,
                "can_release": holds.is_empty(),
                "holds": holds,
            })))
        })
    }
}

struct SourcingPropose;

impl Action for SourcingPropose {
    fn id(&self) -> ActionId {
        ActionId(SOURCING_PROPOSE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let order = uuid_arg(args, "order_id")?;
            ctx.security.require("order", "read")?;
            ctx.security.require("stock_location", "read")?;
            let rows: Vec<(Uuid, Option<Uuid>, Option<f64>)> = sqlx::query_as(
                "SELECT id, product_ref, quantity::float8 FROM order_line \
                  WHERE order_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
            )
            .bind(order)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            // Goods only: a line without a product is a service.
            let lines: Vec<Line> = rows
                .into_iter()
                .filter_map(|(id, product, qty)| {
                    Some(Line {
                        id,
                        product: product?,
                        quantity: qty.unwrap_or(1.0).max(0.0).ceil() as u32,
                    })
                })
                .collect();
            let location_ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM stock_location \
                  WHERE COALESCE(is_enabled, true) AND (is_active IS NULL OR is_active = true) \
                  ORDER BY id LIMIT $1",
            )
            .bind(MAX_LOCATIONS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let mut locations = Vec::with_capacity(location_ids.len());
            for id in location_ids {
                let stock = match &state.stock_source {
                    Some(source) => {
                        let mut per_product = BTreeMap::new();
                        for line in &lines {
                            let free = source
                                .available(line.product, id)
                                .await?
                                .map(|a| a.free())
                                .unwrap_or_default();
                            let free = free.trunc().to_string().parse::<u32>().unwrap_or(0);
                            per_product.insert(line.product, free);
                        }
                        Some(per_product)
                    }
                    None => None,
                };
                // Delivery coordinates are not on orders yet, so every
                // location is equally near.
                locations.push(Location {
                    id,
                    distance_km: 0.0,
                    stock,
                });
            }
            let plan = sourcing::source(Rule::FewestShipments, &lines, &locations);
            let allocations: Vec<Value> = plan
                .allocations
                .iter()
                .map(|a| {
                    json!({
                        "order_line_id": a.line, "location_id": a.location,
                        "quantity": a.quantity, "reason": a.reason,
                    })
                })
                .collect();
            let short: Vec<Value> = plan
                .short
                .iter()
                .map(|(line, qty)| json!({ "order_line_id": line, "quantity": qty }))
                .collect();
            Ok(ActionResult::plain(json!({
                "order_id": order,
                "rule": "fewest_shipments",
                "shipments": plan.shipments(),
                "allocations": allocations,
                "short": short,
                "stock_known": state.stock_source.is_some(),
                "applied": false,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fulfilment_tools_registered() {
        let all: Vec<&str> = crate::actions::all().iter().map(|d| d.id.0).collect();
        let executors: Vec<&str> = crate::actions::all_executors()
            .iter()
            .map(|e| e.id().0)
            .collect();
        for id in [STATUS_READ, HOLD_EXPLAIN, SOURCING_PROPOSE] {
            assert!(all.contains(&id), "{id} is not registered");
            assert!(executors.contains(&id), "{id} has no executor");
        }
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{} only reads", d.id.0);
        }
    }

    #[test]
    fn fulfilment_no_release_tool() {
        for d in crate::actions::all() {
            let id = d.id.0;
            if id.starts_with("fulfilment.") {
                for verb in ["release", "cancel", "carrier", "clear", "ship"] {
                    assert!(
                        !id.contains(verb),
                        "{id}: agents may not release, cancel, clear holds or change carriers"
                    );
                }
            }
        }
    }

    #[test]
    fn every_hold_kind_is_explained() {
        for kind in [
            "credit",
            "prepayment",
            "address",
            "fraud",
            "manual",
            "other",
        ] {
            assert!(!hold_meaning(kind).is_empty());
        }
    }
}
