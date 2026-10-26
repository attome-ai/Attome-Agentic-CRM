//! F6-T17: a sales order's fulfilment, line by line, for the order's
//! Fulfilment panel.
//!
//! `GET /api/v1/fulfilment/orders?order_id=` (`fulfilment_order.read`)
//! answers, for every line of every fulfilment order of the sales order:
//! ordered, shipped, delivered and backordered quantities, the promised
//! date (the line's expected date, else its fulfilment order's), and the
//! shipments that carry it with their carrier, tracking number and status.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `fulfilment_order.read`.
#[derive(Debug)]
pub struct FulfilmentOrderRead;

impl PrivilegeKey for FulfilmentOrderRead {
    const KEY: &'static str = "fulfilment_order.read";
}

/// Most lines one answer holds.
pub const MAX_LINES: i64 = 500;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OrderQuery {
    /// The sales order.
    pub order_id: Uuid,
}

/// A shipment carrying a line.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LineShipment {
    pub shipment_id: Uuid,
    pub carrier: Option<String>,
    pub tracking_number: Option<String>,
    pub status: Option<String>,
    pub quantity: Option<f64>,
}

/// One line's fulfilment.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LineRollup {
    pub line_id: Uuid,
    pub fulfilment_order_id: Uuid,
    pub order_line_ref: Option<String>,
    pub product_ref: Option<Uuid>,
    pub ordered: f64,
    pub shipped: f64,
    pub delivered: f64,
    pub backordered: f64,
    pub promised_date: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub shipments: Vec<LineShipment>,
}

/// A sales order's fulfilment.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrderFulfilment {
    pub order_id: Uuid,
    pub lines: Vec<LineRollup>,
}

type LineRow = (
    Uuid,
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<DateTime<Utc>>,
    Option<String>,
);

type ShipmentRow = (
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<f64>,
);

/// The order's lines and their shipments.
pub async fn order_fulfilment(
    state: &EngineState,
    order: Uuid,
) -> Result<OrderFulfilment, AppError> {
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT l.id, f.id, l.order_line_ref, l.product_ref, l.quantity::float8, \
                l.quantity_shipped::float8, l.quantity_delivered::float8, \
                l.quantity_backordered::float8, COALESCE(l.expected_date, f.promised_date), \
                f.status::text \
           FROM fulfilment_order f \
           JOIN fulfilment_order_line l ON l.fulfilment_order_ref = f.id \
                AND (l.is_active IS NULL OR l.is_active = true) \
          WHERE f.order_ref = $1 AND (f.is_active IS NULL OR f.is_active = true) \
          ORDER BY f.created_at, l.created_at, l.id LIMIT $2",
    )
    .bind(order)
    .bind(MAX_LINES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let line_ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let shipments: Vec<ShipmentRow> = if line_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT sl.fulfilment_order_line_ref, s.id, s.carrier::text, s.tracking_number, \
                        s.status::text, sl.quantity::float8 \
                   FROM shipment_line sl JOIN shipment s ON s.id = sl.shipment_ref \
                  WHERE sl.fulfilment_order_line_ref = ANY($1) \
                    AND (sl.is_active IS NULL OR sl.is_active = true) \
                    AND (s.is_active IS NULL OR s.is_active = true) \
                  ORDER BY s.created_at, s.id",
        )
        .bind(&line_ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
    };
    let mut by_line: BTreeMap<Uuid, Vec<LineShipment>> = BTreeMap::new();
    for (line, id, carrier, tracking, status, quantity) in shipments {
        by_line.entry(line).or_default().push(LineShipment {
            shipment_id: id,
            carrier,
            tracking_number: tracking,
            status,
            quantity,
        });
    }
    let lines = rows
        .into_iter()
        .map(
            |(
                id,
                fo,
                order_line,
                product,
                qty,
                shipped,
                delivered,
                backordered,
                promised,
                status,
            )| {
                LineRollup {
                    line_id: id,
                    fulfilment_order_id: fo,
                    order_line_ref: order_line,
                    product_ref: product,
                    ordered: qty.unwrap_or(0.0),
                    shipped: shipped.unwrap_or(0.0),
                    delivered: delivered.unwrap_or(0.0),
                    backordered: backordered.unwrap_or(0.0),
                    promised_date: promised,
                    status,
                    shipments: by_line.remove(&id).unwrap_or_default(),
                }
            },
        )
        .collect();
    Ok(OrderFulfilment {
        order_id: order,
        lines,
    })
}

/// A sales order's fulfilment
///
/// F6-T17: every line of the order's fulfilment orders with ordered,
/// shipped, delivered and backordered quantities, the promised date, and the
/// shipments carrying it.
#[utoipa::path(
    get,
    path = "/api/v1/fulfilment/orders",
    operation_id = "fulfilment_order_rollup",
    tag = "fulfilment",
    params(OrderQuery),
    responses(
        (status = 200, description = "The order's lines", body = OrderFulfilment),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_order(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<FulfilmentOrderRead>>,
    Query(q): Query<OrderQuery>,
) -> Result<Json<OrderFulfilment>, AppError> {
    order_fulfilment(&state, q.order_id).await.map(Json)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/fulfilment/orders", get(get_order))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_order),
    components(schemas(OrderFulfilment, LineRollup, LineShipment))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
