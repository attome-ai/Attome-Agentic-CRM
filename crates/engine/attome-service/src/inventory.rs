//! I6-T2: the stock ledger.
//!
//! Every change to stock is an append-only `stock_movement` written in the
//! same transaction as the `stock_balance` it changes. The balance row of a
//! product at a location is locked (`FOR UPDATE`) for the transaction, so
//! two movers of the same stock queue behind each other and the balance is
//! always the sum of its movements; a balance row created for the first
//! movement is guarded by a try-lock on `attome-service/stock:{product}:
//! {location}`, so two first movements never make two rows (the loser gets
//! a retryable conflict).
//!
//! **Rules** ([`apply`]): stock that leaves (an issue, a transfer out, a
//! negative adjustment) may only come from what is available (on hand less
//! reserved); a reservation may only hold what is available; issuing a
//! reservation takes it from on hand and from reserved together. A balance
//! with `allow_negative` set skips the availability checks.
//!
//! **Work orders**: the `stock_ledger` job (every minute) reserves each
//! part line of a scheduled, dispatched or in-progress work order at its
//! `location_code`, issues it when the work order is completed (from its
//! reservation, or from free stock when it was never reserved), and
//! releases the reservation of a cancelled one. Each step is keyed by the
//! line (`work_order_line:{id}`), so a repeated tick does nothing twice. A
//! line that cannot be reserved for lack of stock is left for the next tick.
//!
//! People move stock through `POST /api/v1/service/stock/movements`,
//! reserve through `POST /api/v1/service/stock/reservations` and release
//! through `POST /api/v1/service/stock/reservations/{id}/release`.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "stock_ledger";
/// Lines one tick handles per step.
pub const BATCH: i64 = 500;
/// Quantities within this of zero are zero.
const EPSILON: f64 = 1e-9;

/// A balance as the rules see it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Balance {
    pub on_hand: f64,
    pub reserved: f64,
}

impl Balance {
    pub fn available(self) -> f64 {
        self.on_hand - self.reserved
    }
}

/// One change to a balance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Change {
    /// Stock in (positive) or out (negative), not from a reservation.
    Move(f64),
    Reserve(f64),
    Release(f64),
    /// A reservation leaves stock.
    IssueReserved(f64),
}

/// Not enough stock: what was asked and what was available.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shortfall {
    pub asked: f64,
    pub available: f64,
}

/// The balance after a change, or the shortfall that refuses it. Pure.
pub fn apply(b: Balance, change: Change, allow_negative: bool) -> Result<Balance, Shortfall> {
    let short = |asked: f64| -> Result<(), Shortfall> {
        if allow_negative || asked <= b.available() + EPSILON {
            Ok(())
        } else {
            Err(Shortfall {
                asked,
                available: b.available().max(0.0),
            })
        }
    };
    match change {
        Change::Move(delta) => {
            if delta < 0.0 {
                short(-delta)?;
            }
            Ok(Balance {
                on_hand: b.on_hand + delta,
                ..b
            })
        }
        Change::Reserve(q) => {
            short(q)?;
            Ok(Balance {
                reserved: b.reserved + q,
                ..b
            })
        }
        Change::Release(q) => Ok(Balance {
            reserved: (b.reserved - q).max(0.0),
            ..b
        }),
        Change::IssueReserved(q) => {
            let from_reserved = q.min(b.reserved);
            // Anything beyond the reservation comes from free stock.
            if q > from_reserved + EPSILON {
                short(q - from_reserved)?;
            }
            Ok(Balance {
                on_hand: b.on_hand - q,
                reserved: b.reserved - from_reserved,
            })
        }
    }
}

/// The movement kinds and the sign each puts on the quantity.
/// `adjustment` keeps its own sign. Pure.
pub fn signed(kind: &str, quantity: f64) -> Option<f64> {
    match kind {
        "receipt" | "transfer_in" | "return" => Some(quantity.abs()),
        "issue" | "transfer_out" => Some(-quantity.abs()),
        "adjustment" => Some(quantity),
        _ => None,
    }
}

fn shortfall_error(s: Shortfall) -> AppError {
    AppError::Validation(format!(
        "not enough stock: {} asked, {} available",
        s.asked, s.available
    ))
}

/// The locked balance row of a product at a location, created when it has
/// none. `(id, balance, allow_negative)`.
async fn lock_balance(
    tx: &mut attome_db::Tx<'_>,
    product: Uuid,
    location: &str,
) -> Result<(Uuid, Balance, bool), AppError> {
    let select = "SELECT id, COALESCE(on_hand, 0)::float8, COALESCE(reserved, 0)::float8, \
                         COALESCE((to_jsonb(b) ->> 'allow_negative')::boolean, false) \
                    FROM stock_balance b \
                   WHERE product_ref = $1 AND location_code = $2 \
                     AND (is_active IS NULL OR is_active = true) \
                   ORDER BY id LIMIT 1 FOR UPDATE";
    let found: Option<(Uuid, f64, f64, bool)> = sqlx::query_as(select)
        .bind(product)
        .bind(location)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if let Some((id, on_hand, reserved, allow)) = found {
        return Ok((id, Balance { on_hand, reserved }, allow));
    }
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-service/stock:{product}:{location}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this stock is being created by another request; try again",
        ));
    }
    // Another transaction may have created it and committed meanwhile.
    let again: Option<(Uuid, f64, f64, bool)> = sqlx::query_as(select)
        .bind(product)
        .bind(location)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if let Some((id, on_hand, reserved, allow)) = again {
        return Ok((id, Balance { on_hand, reserved }, allow));
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO stock_balance (product_ref, location_code, on_hand, reserved, available) \
         VALUES ($1, $2, 0, 0, 0) RETURNING id",
    )
    .bind(product)
    .bind(location)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok((
        id,
        Balance {
            on_hand: 0.0,
            reserved: 0.0,
        },
        false,
    ))
}

async fn write_balance(tx: &mut attome_db::Tx<'_>, id: Uuid, b: Balance) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE stock_balance SET on_hand = $2::float8::numeric, reserved = $3::float8::numeric, \
             available = $4::float8::numeric, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(b.on_hand)
    .bind(b.reserved)
    .bind(b.available())
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// One movement to record.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewMovement {
    pub product_id: Uuid,
    pub location_code: String,
    /// `receipt`, `issue`, `transfer_in`, `transfer_out`, `adjustment`
    /// (signed) or `return`.
    pub kind: String,
    pub quantity: f64,
    /// What caused it (an order, a work order line, a count).
    pub reference: Option<String>,
    pub serial_id: Option<Uuid>,
    pub lot_id: Option<Uuid>,
}

/// A recorded movement and the balance after it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MovementRecorded {
    pub movement_id: Uuid,
    pub on_hand: f64,
    pub reserved: f64,
    pub available: f64,
}

/// Records one movement and its balance change in the caller's
/// transaction.
pub async fn record_in_tx(
    tx: &mut attome_db::Tx<'_>,
    m: &NewMovement,
    moved_by: Option<Uuid>,
    from_reservation: bool,
) -> Result<MovementRecorded, AppError> {
    let location = m.location_code.trim();
    if location.is_empty() || location.len() > 100 {
        return Err(AppError::Validation(
            "location_code: 1 to 100 characters".into(),
        ));
    }
    if !m.quantity.is_finite() || m.quantity.abs() < EPSILON {
        return Err(AppError::Validation(
            "quantity: a number other than zero".into(),
        ));
    }
    let delta = signed(&m.kind, m.quantity).ok_or_else(|| {
        AppError::Validation(
            "kind: receipt, issue, transfer_in, transfer_out, adjustment or return".into(),
        )
    })?;
    let (balance_id, before, allow) = lock_balance(tx, m.product_id, location).await?;
    let change = if from_reservation && delta < 0.0 {
        Change::IssueReserved(-delta)
    } else {
        Change::Move(delta)
    };
    let after = apply(before, change, allow).map_err(shortfall_error)?;
    let movement: Uuid = sqlx::query_scalar(
        "INSERT INTO stock_movement (product_ref, location_code, kind, quantity, moved_at, \
             reference, serial_ref, lot_ref, moved_by) \
         VALUES ($1, $2, $3, $4::float8::numeric, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(m.product_id)
    .bind(location)
    .bind(&m.kind)
    .bind(delta)
    .bind(Utc::now().date_naive())
    .bind(m.reference.as_deref())
    .bind(m.serial_id)
    .bind(m.lot_id)
    .bind(moved_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    write_balance(tx, balance_id, after).await?;
    Ok(MovementRecorded {
        movement_id: movement,
        on_hand: after.on_hand,
        reserved: after.reserved,
        available: after.available(),
    })
}

/// Holds `quantity` for `reference` in the caller's transaction.
pub async fn reserve_in_tx(
    tx: &mut attome_db::Tx<'_>,
    product: Uuid,
    location: &str,
    quantity: f64,
    reference: &str,
    expires_at: Option<NaiveDate>,
) -> Result<Uuid, AppError> {
    if !quantity.is_finite() || quantity <= 0.0 {
        return Err(AppError::Validation("quantity: more than zero".into()));
    }
    let (balance_id, before, allow) = lock_balance(tx, product, location.trim()).await?;
    let after = apply(before, Change::Reserve(quantity), allow).map_err(shortfall_error)?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO stock_reservation (product_ref, location_code, quantity, reference, \
             expires_at, status) \
         VALUES ($1, $2, $3::float8::numeric, $4, $5, 'held') RETURNING id",
    )
    .bind(product)
    .bind(location.trim())
    .bind(quantity)
    .bind(reference)
    .bind(expires_at)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    write_balance(tx, balance_id, after).await?;
    Ok(id)
}

/// Ends a held reservation in the caller's transaction: `released` gives
/// the stock back, `consumed` issues it. `false` when it was not held.
pub async fn end_reservation_in_tx(
    tx: &mut attome_db::Tx<'_>,
    reservation: Uuid,
    consume: bool,
    moved_by: Option<Uuid>,
) -> Result<bool, AppError> {
    let held: Option<(Uuid, String, f64, Option<String>)> = sqlx::query_as(
        "SELECT product_ref, location_code, quantity::float8, reference FROM stock_reservation \
          WHERE id = $1 AND status = 'held' AND (is_active IS NULL OR is_active = true) \
          FOR UPDATE",
    )
    .bind(reservation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((product, location, quantity, reference)) = held else {
        return Ok(false);
    };
    if consume {
        record_in_tx(
            tx,
            &NewMovement {
                product_id: product,
                location_code: location,
                kind: "issue".into(),
                quantity,
                reference,
                serial_id: None,
                lot_id: None,
            },
            moved_by,
            true,
        )
        .await?;
    } else {
        let (balance_id, before, allow) = lock_balance(tx, product, &location).await?;
        let after = apply(before, Change::Release(quantity), allow).map_err(shortfall_error)?;
        write_balance(tx, balance_id, after).await?;
    }
    sqlx::query(
        "UPDATE stock_reservation SET status = $2, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(reservation)
    .bind(if consume { "consumed" } else { "released" })
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}

// ── Work orders ─────────────────────────────────────────────────────────────

type PartLine = (Uuid, Uuid, String, f64, Option<Uuid>);

/// Part lines of scheduled work with no reservation yet.
const TO_RESERVE: &str = "SELECT l.id, l.product_ref, l.location_code, \
        COALESCE(l.quantity, 1)::float8, w.assigned_to \
   FROM work_order_line l JOIN work_order w ON w.id = l.work_order_ref \
  WHERE l.line_kind = 'part' AND l.product_ref IS NOT NULL \
    AND COALESCE(l.location_code, '') <> '' AND (l.is_active IS NULL OR l.is_active = true) \
    AND w.status IN ('scheduled', 'dispatched', 'in_progress') \
    AND NOT EXISTS (SELECT 1 FROM stock_reservation r \
                     WHERE r.reference = 'work_order_line:' || l.id::text) \
  ORDER BY l.id LIMIT $1";

/// Part lines of completed work not issued yet.
const TO_ISSUE: &str = "SELECT l.id, l.product_ref, l.location_code, \
        COALESCE(l.quantity, 1)::float8, w.assigned_to \
   FROM work_order_line l JOIN work_order w ON w.id = l.work_order_ref \
  WHERE l.line_kind = 'part' AND l.product_ref IS NOT NULL \
    AND COALESCE(l.location_code, '') <> '' AND (l.is_active IS NULL OR l.is_active = true) \
    AND w.status = 'completed' \
    AND NOT EXISTS (SELECT 1 FROM stock_movement m \
                     WHERE m.kind = 'issue' AND m.reference = 'work_order_line:' || l.id::text) \
  ORDER BY l.id LIMIT $1";

/// One tick of the work order steps. Answers the lines changed.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('work_order_line') IS NOT NULL \
            AND to_regclass('stock_reservation') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let mut changed = 0;

    // Reserve for scheduled work.
    let to_reserve: Vec<PartLine> = sqlx::query_as(TO_RESERVE)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    for (line, product, location, quantity, _) in to_reserve {
        let mut tx = attome_db::tx::begin(db).await?;
        match reserve_in_tx(
            &mut tx,
            product,
            &location,
            quantity,
            &format!("work_order_line:{line}"),
            None,
        )
        .await
        {
            Ok(_) => {
                attome_db::tx::commit(tx).await?;
                changed += 1;
            }
            Err(error) => {
                tracing::info!(%line, %error, "stock: work order line not reserved yet");
            }
        }
    }

    // Issue for completed work.
    let to_issue: Vec<PartLine> = sqlx::query_as(TO_ISSUE)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    for (line, product, location, quantity, user) in to_issue {
        let reference = format!("work_order_line:{line}");
        let mut tx = attome_db::tx::begin(db).await?;
        let held: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM stock_reservation WHERE reference = $1 AND status = 'held' \
              ORDER BY id LIMIT 1",
        )
        .bind(&reference)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let done = match held {
            Some(reservation) => end_reservation_in_tx(&mut tx, reservation, true, user)
                .await
                .map(|_| ()),
            None => record_in_tx(
                &mut tx,
                &NewMovement {
                    product_id: product,
                    location_code: location,
                    kind: "issue".into(),
                    quantity,
                    reference: Some(reference),
                    serial_id: None,
                    lot_id: None,
                },
                user,
                false,
            )
            .await
            .map(|_| ()),
        };
        match done {
            Ok(()) => {
                attome_db::tx::commit(tx).await?;
                changed += 1;
            }
            Err(error) => {
                tracing::warn!(%line, %error, "stock: completed work order line not issued");
            }
        }
    }

    // Release for cancelled work.
    let to_release: Vec<Uuid> = sqlx::query_scalar(
        "SELECT r.id FROM stock_reservation r \
           JOIN work_order_line l ON r.reference = 'work_order_line:' || l.id::text \
           JOIN work_order w ON w.id = l.work_order_ref \
          WHERE r.status = 'held' AND w.status = 'cancelled' ORDER BY r.id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for reservation in to_release {
        let mut tx = attome_db::tx::begin(db).await?;
        if end_reservation_in_tx(&mut tx, reservation, false, None).await? {
            changed += 1;
        }
        attome_db::tx::commit(tx).await?;
    }
    Ok(changed)
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// `stock_movement.create`: may move stock.
#[derive(Debug)]
pub struct StockMove;

impl PrivilegeKey for StockMove {
    const KEY: &'static str = "stock_movement.create";
}

/// `stock_reservation.create`: may reserve and release stock.
#[derive(Debug)]
pub struct StockReserve;

impl PrivilegeKey for StockReserve {
    const KEY: &'static str = "stock_reservation.create";
}

async fn audit(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    entity: &str,
    id: Uuid,
    operation: attome_audit::AuditOperation,
    event: &str,
    user: Uuid,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(entity, id, operation, event, user),
    )
    .await?;
    Ok(())
}

/// Record a stock movement
///
/// An append-only movement and the balance it changes, in one transaction under the balance row's
/// lock, so the balance is always the sum of its movements. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/stock/movements",
    operation_id = "post_stock_movement",
    tag = "service",
    request_body = NewMovement,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The movement and the balance after it", body = MovementRecorded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks stock_movement.create", body = ErrorResponse),
        (status = 409, description = "The same stock is being created by another request; retry", body = ErrorResponse),
        (status = 422, description = "Not enough stock, or an unknown kind or quantity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Records a stock movement and its balance change.
async fn post_movement(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<StockMove>>,
    Json(body): Json<NewMovement>,
) -> Result<(StatusCode, Json<MovementRecorded>), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let recorded = record_in_tx(&mut tx, &body, Some(ctx.user_id), false).await?;
    audit(
        &state,
        &mut tx,
        "stock_movement",
        recorded.movement_id,
        attome_audit::AuditOperation::Create,
        "stock.moved",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(recorded)))
}

/// A reservation to hold.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewReservation {
    pub product_id: Uuid,
    pub location_code: String,
    pub quantity: f64,
    pub reference: String,
    pub expires_at: Option<NaiveDate>,
}

/// The held reservation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReservationHeld {
    pub reservation_id: Uuid,
}

/// Reserve stock
///
/// Holds a quantity of a product at a location for a reference, until it is released or expires.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/stock/reservations",
    operation_id = "post_stock_reservation",
    tag = "service",
    request_body = NewReservation,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The reservation is held", body = ReservationHeld),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks stock_reservation.create", body = ErrorResponse),
        (status = 409, description = "The same stock is being created by another request; retry", body = ErrorResponse),
        (status = 422, description = "Not enough stock available", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Holds stock for a reference.
async fn post_reservation(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<StockReserve>>,
    Json(body): Json<NewReservation>,
) -> Result<(StatusCode, Json<ReservationHeld>), AppError> {
    let reference = body.reference.trim();
    if reference.is_empty() || reference.len() > 200 {
        return Err(AppError::Validation(
            "reference: 1 to 200 characters".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = reserve_in_tx(
        &mut tx,
        body.product_id,
        &body.location_code,
        body.quantity,
        reference,
        body.expires_at,
    )
    .await?;
    audit(
        &state,
        &mut tx,
        "stock_reservation",
        id,
        attome_audit::AuditOperation::Create,
        "stock.reserved",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(ReservationHeld { reservation_id: id }),
    ))
}

/// Release a stock reservation
///
/// The held quantity is free again. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/stock/reservations/{id}/release",
    operation_id = "post_stock_reservation_release",
    tag = "service",
    params(("id" = Uuid, Path, description = "The reservation")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Released; its stock is available again"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks stock_reservation.create", body = ErrorResponse),
        (status = 409, description = "The reservation is not held", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Releases a held reservation.
async fn post_release(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<StockReserve>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !end_reservation_in_tx(&mut tx, id, false, Some(ctx.user_id)).await? {
        return Err(AppError::Conflict("the reservation is not held"));
    }
    audit(
        &state,
        &mut tx,
        "stock_reservation",
        id,
        attome_audit::AuditOperation::Update,
        "stock.released",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service/stock/movements", post(post_movement))
        .route("/api/v1/service/stock/reservations", post(post_reservation))
        .route(
            "/api/v1/service/stock/reservations/{id}/release",
            post(post_release),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_movement, post_reservation, post_release),
    components(schemas(NewMovement, MovementRecorded, NewReservation, ReservationHeld))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod inventory_ledger {
    use super::*;

    fn b(on_hand: f64, reserved: f64) -> Balance {
        Balance { on_hand, reserved }
    }

    #[test]
    fn stock_out_comes_only_from_available() {
        let start = b(10.0, 4.0);
        assert_eq!(apply(start, Change::Move(-6.0), false), Ok(b(4.0, 4.0)));
        assert_eq!(
            apply(start, Change::Move(-7.0), false),
            Err(Shortfall {
                asked: 7.0,
                available: 6.0
            })
        );
        assert_eq!(apply(start, Change::Move(-7.0), true), Ok(b(3.0, 4.0)));
        assert_eq!(apply(start, Change::Move(5.0), false), Ok(b(15.0, 4.0)));
    }

    #[test]
    fn reservations_hold_available_stock_and_issue_from_it() {
        let start = b(10.0, 0.0);
        let held = apply(start, Change::Reserve(8.0), false).unwrap();
        assert_eq!(held, b(10.0, 8.0));
        assert!(apply(held, Change::Reserve(3.0), false).is_err());
        assert_eq!(
            apply(held, Change::IssueReserved(8.0), false),
            Ok(b(2.0, 0.0))
        );
        assert_eq!(apply(held, Change::Release(8.0), false), Ok(b(10.0, 0.0)));
        // Issuing more than was reserved takes the rest from free stock.
        assert_eq!(
            apply(held, Change::IssueReserved(9.0), false),
            Ok(b(1.0, 0.0))
        );
        assert!(apply(held, Change::IssueReserved(11.0), false).is_err());
    }

    #[test]
    fn kinds_carry_their_sign() {
        assert_eq!(signed("receipt", 3.0), Some(3.0));
        assert_eq!(signed("issue", 3.0), Some(-3.0));
        assert_eq!(signed("transfer_out", -3.0), Some(-3.0));
        assert_eq!(signed("adjustment", -2.0), Some(-2.0));
        assert_eq!(signed("teleport", 1.0), None);
    }

    #[test]
    fn serialized_movers_never_oversell() {
        // The row lock makes concurrent movers apply one after another;
        // replaying any order of competing issues never goes below zero.
        let mut balance = b(5.0, 0.0);
        let mut granted = 0;
        for _ in 0..10 {
            if let Ok(next) = apply(balance, Change::Move(-1.0), false) {
                balance = next;
                granted += 1;
            }
        }
        assert_eq!(granted, 5);
        assert_eq!(balance, b(0.0, 0.0));
    }
}
