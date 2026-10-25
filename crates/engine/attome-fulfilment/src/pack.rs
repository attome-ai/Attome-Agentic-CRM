//! F6-T8: picking and packing a released fulfilment order.
//!
//! - `GET /api/v1/fulfilment/orders/{id}/pick-list`: the goods still to
//!   ship, one group per product (inventory bins are not tracked yet, so a
//!   picker walks by product), with the quantity to pick.
//! - `POST /api/v1/fulfilment/orders/{id}/packages`: records the packages a
//!   released (or picking) order went into, as one shipment with its
//!   packages and a shipment line per goods line still to ship, and marks
//!   the order `packed`, in one transaction.
//!
//! The packing slip and delivery note are document templates from the
//! fulfilment pack (`docgen_template` "Packing slip" and "Delivery note",
//! Arabic and English side by side, a row per `fulfilment_order_line`),
//! rendered by the document route like any other.

use std::collections::BTreeMap;

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::hold::FulfilmentOrderUpdate;

/// `fulfilment_order.read`: who sees a pick list.
#[derive(Debug)]
pub struct FulfilmentOrderRead;

impl PrivilegeKey for FulfilmentOrderRead {
    const KEY: &'static str = "fulfilment_order.read";
}

/// Most packages one call records.
pub const MAX_PACKAGES: usize = 50;

/// One goods line still to ship.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenLine {
    pub line: Uuid,
    pub product: Option<Uuid>,
    pub open: f64,
}

/// One group of a pick list: a product and how many to pick.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct PickGroup {
    pub product_id: Option<Uuid>,
    pub quantity: f64,
    pub lines: Vec<Uuid>,
}

/// A fulfilment order's pick list.
#[derive(Debug, Serialize, ToSchema)]
pub struct PickList {
    pub fulfilment_order_id: Uuid,
    pub location_id: Option<Uuid>,
    pub groups: Vec<PickGroup>,
}

/// The goods to pick, grouped by product in a stable order. Pure.
pub fn group_by_product(lines: &[OpenLine]) -> Vec<PickGroup> {
    let mut groups: BTreeMap<Option<Uuid>, PickGroup> = BTreeMap::new();
    for line in lines.iter().filter(|l| l.open > 0.0) {
        let group = groups.entry(line.product).or_insert_with(|| PickGroup {
            product_id: line.product,
            quantity: 0.0,
            lines: Vec::new(),
        });
        group.quantity += line.open;
        group.lines.push(line.line);
    }
    groups.into_values().collect()
}

/// A fulfilment line as read: id, product, quantity, shipped.
type LineRow = (Uuid, Option<Uuid>, Option<f64>, Option<f64>);

async fn open_goods(
    conn: &mut sqlx::PgConnection,
    fulfilment_order: Uuid,
) -> Result<Vec<OpenLine>, AppError> {
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT id, product_ref, quantity::float8, quantity_shipped::float8 \
           FROM fulfilment_order_line \
          WHERE fulfilment_order_ref = $1 AND COALESCE(line_kind::text, 'goods') = 'goods' \
            AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(fulfilment_order)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(line, product, quantity, shipped)| OpenLine {
            line,
            product,
            open: (quantity.unwrap_or(0.0) - shipped.unwrap_or(0.0)).max(0.0),
        })
        .collect())
}

/// A fulfilment order's pick list
///
/// F6-T8: the goods still to ship, one group per product.
#[utoipa::path(
    get,
    path = "/api/v1/fulfilment/orders/{id}/pick-list",
    operation_id = "fulfilment_pick_list",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The fulfilment order")),
    responses(
        (status = 200, description = "What to pick", body = PickList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.read", body = ErrorResponse),
        (status = 404, description = "No such fulfilment order", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn pick_list(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<FulfilmentOrderRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PickList>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let location: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT location_ref FROM fulfilment_order \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let location = location.ok_or(AppError::NotFound)?;
    let lines = open_goods(&mut conn, id).await?;
    Ok(Json(PickList {
        fulfilment_order_id: id,
        location_id: location,
        groups: group_by_product(&lines),
    }))
}

/// One package.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageBody {
    pub weight_kg: f64,
    #[serde(default)]
    pub length_cm: Option<f64>,
    #[serde(default)]
    pub width_cm: Option<f64>,
    #[serde(default)]
    pub height_cm: Option<f64>,
}

/// The packages an order went into.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PackBody {
    pub packages: Vec<PackageBody>,
    /// `own_fleet`, `aramex`, `smsa`, `dhl` or `other`; chosen later when absent.
    #[serde(default)]
    pub carrier: Option<String>,
}

/// What packing wrote.
#[derive(Debug, Serialize, ToSchema)]
pub struct Packed {
    pub fulfilment_order_id: Uuid,
    pub shipment_id: Uuid,
    pub package_ids: Vec<Uuid>,
    pub status: String,
}

const CARRIERS: [&str; 5] = ["own_fleet", "aramex", "smsa", "dhl", "other"];

fn check_packages(body: &PackBody) -> Result<(), AppError> {
    if body.packages.is_empty() || body.packages.len() > MAX_PACKAGES {
        return Err(AppError::Validation(format!(
            "packages lists 1 to {MAX_PACKAGES} packages"
        )));
    }
    let positive = |v: f64| v.is_finite() && v > 0.0;
    for (i, p) in body.packages.iter().enumerate() {
        let dims_ok = [p.length_cm, p.width_cm, p.height_cm]
            .into_iter()
            .flatten()
            .all(positive);
        if !positive(p.weight_kg) || !dims_ok {
            return Err(AppError::Validation(format!(
                "packages[{i}]: weight and sizes are positive numbers"
            )));
        }
    }
    if let Some(carrier) = body.carrier.as_deref()
        && !CARRIERS.contains(&carrier)
    {
        return Err(AppError::Validation(format!(
            "carrier is one of {}",
            CARRIERS.join(", ")
        )));
    }
    Ok(())
}

/// Pack a fulfilment order
///
/// F6-T8: records the packages as one shipment (with a line per goods line
/// still to ship) and marks the order `packed`.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/orders/{id}/packages",
    operation_id = "fulfilment_order_pack",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The fulfilment order")),
    request_body = PackBody,
    responses(
        (status = 201, description = "Packed", body = Packed),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.update", body = ErrorResponse),
        (status = 404, description = "No such fulfilment order", body = ErrorResponse),
        (status = 409, description = "The order is not released or being picked", body = ErrorResponse),
        (status = 422, description = "No packages, too many, or a size that is not positive", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn pack(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FulfilmentOrderUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<PackBody>,
) -> Result<(StatusCode, Json<Packed>), AppError> {
    check_packages(&body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let status: Option<Option<String>> = sqlx::query_scalar(
        "SELECT status::text FROM fulfilment_order \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let status = status.ok_or(AppError::NotFound)?;
    if !matches!(status.as_deref(), Some("released" | "picking")) {
        return Err(AppError::Conflict(
            "only a released or picking fulfilment order is packed",
        ));
    }
    let lines = open_goods(&mut tx, id).await?;
    let shipment = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO shipment (id, fulfilment_order_ref, carrier, created_by, owner_ref) \
         VALUES ($1, $2, $3, $4, $4)",
    )
    .bind(shipment)
    .bind(id)
    .bind(body.carrier.as_deref())
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    change_feed::emit_tx(&mut tx, "shipment", shipment, ChangeOperation::Create).await?;
    let mut package_ids = Vec::with_capacity(body.packages.len());
    for p in &body.packages {
        let package = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO shipment_package (id, shipment_ref, weight_kg, length_cm, width_cm, \
                 height_cm, created_by, owner_ref) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
        )
        .bind(package)
        .bind(shipment)
        .bind(p.weight_kg)
        .bind(p.length_cm)
        .bind(p.width_cm)
        .bind(p.height_cm)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        change_feed::emit_tx(
            &mut tx,
            "shipment_package",
            package,
            ChangeOperation::Create,
        )
        .await?;
        package_ids.push(package);
    }
    for line in lines.iter().filter(|l| l.open > 0.0) {
        let row = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO shipment_line (id, shipment_ref, fulfilment_order_line_ref, quantity, \
                 created_by, owner_ref) \
             VALUES ($1, $2, $3, $4, $5, $5)",
        )
        .bind(row)
        .bind(shipment)
        .bind(line.line)
        .bind(line.open)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        change_feed::emit_tx(&mut tx, "shipment_line", row, ChangeOperation::Create).await?;
    }
    sqlx::query(
        "UPDATE fulfilment_order SET status = 'packed', modified_at = now(), \
                row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    change_feed::emit_tx(&mut tx, "fulfilment_order", id, ChangeOperation::Update).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "fulfilment_order",
            id,
            AuditOperation::Create,
            "fulfilment.packed",
            ctx.user_id,
        )
        .comment(format!(
            "{} packages in shipment {shipment}",
            package_ids.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(Packed {
            fulfilment_order_id: id,
            shipment_id: shipment,
            package_ids,
            status: "packed".into(),
        }),
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/fulfilment/orders/{id}/pick-list", get(pick_list))
        .route("/api/v1/fulfilment/orders/{id}/packages", post(pack))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(pick_list, pack),
    components(schemas(PickList, PickGroup, PackBody, PackageBody, Packed))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_list_groups_by_product_and_skips_shipped_lines() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let (l1, l2, l3) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let groups = group_by_product(&[
            OpenLine {
                line: l1,
                product: Some(a),
                open: 2.0,
            },
            OpenLine {
                line: l2,
                product: Some(a),
                open: 3.0,
            },
            OpenLine {
                line: l3,
                product: Some(b),
                open: 0.0,
            },
        ]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].product_id, Some(a));
        assert!((groups[0].quantity - 5.0).abs() < 1e-9);
        assert_eq!(groups[0].lines, vec![l1, l2]);
    }

    #[test]
    fn packages_need_positive_sizes_and_a_known_carrier() {
        let ok = PackBody {
            packages: vec![PackageBody {
                weight_kg: 1.5,
                length_cm: Some(30.0),
                width_cm: None,
                height_cm: None,
            }],
            carrier: Some("aramex".into()),
        };
        assert!(check_packages(&ok).is_ok());
        let heavy_nothing = PackBody {
            packages: vec![PackageBody {
                weight_kg: 0.0,
                length_cm: None,
                width_cm: None,
                height_cm: None,
            }],
            carrier: None,
        };
        assert!(check_packages(&heavy_nothing).is_err());
        let carrier = PackBody {
            packages: vec![PackageBody {
                weight_kg: 1.0,
                length_cm: None,
                width_cm: None,
                height_cm: None,
            }],
            carrier: Some("pigeon".into()),
        };
        assert!(check_packages(&carrier).is_err());
        assert!(
            check_packages(&PackBody {
                packages: vec![],
                carrier: None
            })
            .is_err()
        );
    }
}
