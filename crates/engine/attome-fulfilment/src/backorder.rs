//! F6-T7: backorders and partial shipments.
//!
//! [`plan_shipment`] (pure) says what ships now and what waits, by the
//! fulfilment order's `ship_policy`: `ship_complete` ships nothing until
//! every line is covered; `ship_as_available` ships what is there and
//! backorders the rest.
//!
//! [`allocate_released`] gives stock that arrives at a location to the
//! lines waiting for that product there, highest order priority first and
//! oldest order first among equals, in one transaction under the lock
//! `attome-fulfilment/allocate:{product}:{location}`. Inventory (I6) emits
//! no receipt event yet, so a person or an integration calls
//! `POST /api/v1/fulfilment/backorders/allocate` when stock arrives.

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::hold::FulfilmentOrderUpdate;

/// A fulfilment order's shipping policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipPolicy {
    ShipComplete,
    ShipAsAvailable,
}

impl ShipPolicy {
    /// The stored choice; anything else ships as available.
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("ship_complete") => Self::ShipComplete,
            _ => Self::ShipAsAvailable,
        }
    }
}

/// One line to plan: what is still to ship and what is available for it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlanLine {
    pub id: Uuid,
    pub open: f64,
    pub available: f64,
}

/// What ships now and what waits, per line (only non-zero quantities).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ShipPlan {
    pub ship: Vec<(Uuid, f64)>,
    pub backorder: Vec<(Uuid, f64)>,
}

/// What ships now under `policy`. Pure.
pub fn plan_shipment(lines: &[PlanLine], policy: ShipPolicy) -> ShipPlan {
    let mut plan = ShipPlan::default();
    let complete = lines.iter().all(|l| l.available >= l.open);
    for line in lines.iter().filter(|l| l.open > 0.0) {
        let ship = match policy {
            ShipPolicy::ShipComplete if !complete => 0.0,
            _ => line.open.min(line.available.max(0.0)),
        };
        if ship > 0.0 {
            plan.ship.push((line.id, ship));
        }
        let wait = line.open - ship;
        if wait > 0.0 {
            plan.backorder.push((line.id, wait));
        }
    }
    plan
}

/// One waiting line, in allocation order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Waiting {
    pub line: Uuid,
    pub backordered: f64,
}

/// How `quantity` is shared over `waiting` (already in priority order):
/// each line takes what it waits for until the quantity runs out. Pure.
pub fn share(waiting: &[Waiting], quantity: f64) -> Vec<(Uuid, f64)> {
    let mut left = quantity.max(0.0);
    let mut out = Vec::new();
    for w in waiting {
        if left <= 0.0 {
            break;
        }
        let take = w.backordered.min(left);
        if take > 0.0 {
            out.push((w.line, take));
            left -= take;
        }
    }
    out
}

/// Gives `quantity` newly available units of `product` at `location` to
/// the lines waiting for them; returns each line and what it got.
pub async fn allocate_released(
    state: &EngineState,
    product: Uuid,
    location: Uuid,
    quantity: f64,
    actor: Uuid,
) -> Result<Vec<(Uuid, f64)>, AppError> {
    if quantity <= 0.0 || !quantity.is_finite() {
        return Err(AppError::Validation("quantity is a positive number".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-fulfilment/allocate:{product}:{location}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "stock for this product and location is being allocated",
        ));
    }
    let rows: Vec<(Uuid, Option<f64>)> = sqlx::query_as(
        "SELECT l.id, l.quantity_backordered::float8 \
           FROM fulfilment_order_line l \
           JOIN fulfilment_order o ON o.id = l.fulfilment_order_ref \
          WHERE l.product_ref = $1 AND o.location_ref = $2 \
            AND COALESCE(l.quantity_backordered, 0) > 0 \
            AND (l.is_active IS NULL OR l.is_active = true) \
            AND (o.is_active IS NULL OR o.is_active = true) \
            AND COALESCE(o.status::text, '') NOT IN ('cancelled', 'shipped', 'delivered') \
          ORDER BY o.priority DESC NULLS LAST, o.created_at, l.id \
          FOR UPDATE OF l",
    )
    .bind(product)
    .bind(location)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let waiting: Vec<Waiting> = rows
        .into_iter()
        .map(|(line, backordered)| Waiting {
            line,
            backordered: backordered.unwrap_or(0.0),
        })
        .collect();
    let given = share(&waiting, quantity);
    for (line, take) in &given {
        sqlx::query(
            "UPDATE fulfilment_order_line \
                SET quantity_backordered = GREATEST(quantity_backordered - $2, 0), \
                    modified_at = now(), row_version = row_version + 1 \
              WHERE id = $1",
        )
        .bind(line)
        .bind(take)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        change_feed::emit_tx(
            &mut tx,
            "fulfilment_order_line",
            *line,
            ChangeOperation::Update,
        )
        .await?;
    }
    let placed: f64 = given.iter().map(|(_, q)| q).sum();
    write_business_event_in_tx(
        &mut tx,
        &audit_service(state),
        BusinessEvent::new(
            "stock_location",
            location,
            AuditOperation::Update,
            "fulfilment.backorders_allocated",
            actor,
        )
        .comment(format!(
            "product {product}: {placed} of {quantity} given to {} waiting lines",
            given.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(given)
}

/// Newly available stock to give to waiting lines.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AllocateBody {
    pub product_id: Uuid,
    pub location_id: Uuid,
    /// How many units arrived (positive).
    pub quantity: f64,
}

/// One line and what it got.
#[derive(Debug, Serialize, ToSchema)]
pub struct Allocated {
    pub fulfilment_order_line_id: Uuid,
    pub quantity: f64,
}

/// What an allocation gave.
#[derive(Debug, Serialize, ToSchema)]
pub struct AllocateResult {
    pub allocated: Vec<Allocated>,
    /// Units no waiting line needed.
    pub left_over: f64,
}

/// Give arrived stock to backorders
///
/// F6-T7: shares `quantity` units of a product at a location over the lines
/// waiting for them, highest priority and oldest order first.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/backorders/allocate",
    operation_id = "fulfilment_backorders_allocate",
    tag = "fulfilment",
    request_body = AllocateBody,
    responses(
        (status = 200, description = "What each waiting line got", body = AllocateResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.update", body = ErrorResponse),
        (status = 409, description = "Another allocation for this product and location is running", body = ErrorResponse),
        (status = 422, description = "The quantity is not positive", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn allocate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FulfilmentOrderUpdate>>,
    Json(body): Json<AllocateBody>,
) -> Result<Json<AllocateResult>, AppError> {
    let given = allocate_released(
        &state,
        body.product_id,
        body.location_id,
        body.quantity,
        ctx.user_id,
    )
    .await?;
    let placed: f64 = given.iter().map(|(_, q)| q).sum();
    Ok(Json(AllocateResult {
        allocated: given
            .into_iter()
            .map(|(line, quantity)| Allocated {
                fulfilment_order_line_id: line,
                quantity,
            })
            .collect(),
        left_over: (body.quantity - placed).max(0.0),
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/fulfilment/backorders/allocate", post(allocate))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(allocate),
    components(schemas(AllocateBody, Allocated, AllocateResult))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(open: f64, available: f64) -> PlanLine {
        PlanLine {
            id: Uuid::now_v7(),
            open,
            available,
        }
    }

    #[test]
    fn backorder_ship_complete_waits() {
        let lines = [line(5.0, 5.0), line(3.0, 1.0)];
        let plan = plan_shipment(&lines, ShipPolicy::ShipComplete);
        assert!(
            plan.ship.is_empty(),
            "nothing ships until every line is covered"
        );
        assert_eq!(plan.backorder, vec![(lines[0].id, 5.0), (lines[1].id, 3.0)]);
        let covered = [line(5.0, 9.0), line(3.0, 3.0)];
        let plan = plan_shipment(&covered, ShipPolicy::ShipComplete);
        assert_eq!(plan.ship.len(), 2);
        assert!(plan.backorder.is_empty());
    }

    #[test]
    fn backorder_ship_as_available_splits() {
        let lines = [line(5.0, 5.0), line(3.0, 1.0), line(2.0, 0.0)];
        let plan = plan_shipment(&lines, ShipPolicy::ShipAsAvailable);
        assert_eq!(plan.ship, vec![(lines[0].id, 5.0), (lines[1].id, 1.0)]);
        assert_eq!(plan.backorder, vec![(lines[1].id, 2.0), (lines[2].id, 2.0)]);
    }

    #[test]
    fn arrived_stock_goes_in_order_until_it_runs_out() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let c = Uuid::now_v7();
        let waiting = [
            Waiting {
                line: a,
                backordered: 2.0,
            },
            Waiting {
                line: b,
                backordered: 4.0,
            },
            Waiting {
                line: c,
                backordered: 1.0,
            },
        ];
        assert_eq!(share(&waiting, 5.0), vec![(a, 2.0), (b, 3.0)]);
        assert!(share(&waiting, 0.0).is_empty());
        assert_eq!(share(&waiting, 10.0), vec![(a, 2.0), (b, 4.0), (c, 1.0)]);
        assert_eq!(
            ShipPolicy::parse(Some("ship_complete")),
            ShipPolicy::ShipComplete
        );
        assert_eq!(ShipPolicy::parse(None), ShipPolicy::ShipAsAvailable);
    }
}
