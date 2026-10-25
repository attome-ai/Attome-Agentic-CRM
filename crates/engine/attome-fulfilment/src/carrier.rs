//! F6-T9: booking a packed shipment with its carrier and reading its status,
//! through the carrier seam (`attome_integration::carrier`, Aramex first).
//!
//! - `POST /api/v1/fulfilment/shipments/{id}/book`: books the shipment with
//!   the consignee the caller gives (orders carry no delivery address yet),
//!   its packages' weight and count unless given, and stores the waybill as
//!   `tracking_number` with status `booked`. The label is the carrier's URL
//!   in the answer.
//! - `POST /api/v1/fulfilment/shipments/{id}/track`: reads the waybill's
//!   latest update and moves the shipment's status, `last_event_key` and
//!   `last_event_at` (and `delivered_on`) when it is new.
//!
//! The carrier is called outside any transaction. A booking first claims the
//! shipment (`last_event_key = 'booking'`, stale after five minutes), so a
//! second click does not book twice; a carrier refusal or failure clears the
//! claim.

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_integration::carrier as seam;
use attome_integration::connector::adapters::carrier_aramex::{Parcel, Party};
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::hold::FulfilmentOrderUpdate;

/// The claim a booking holds while it calls the carrier.
const BOOKING_CLAIM: &str = "booking";

/// Who receives the shipment.
#[derive(Debug, Deserialize, ToSchema)]
pub struct Consignee {
    pub name: String,
    #[serde(default)]
    pub company: Option<String>,
    pub phone: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Street and building.
    pub line1: String,
    pub city: String,
    /// ISO 3166-1 alpha-2, such as `SA`.
    pub country_code: String,
}

/// A booking request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BookBody {
    pub consignee: Consignee,
    /// Total weight; the packages' weights when absent.
    #[serde(default)]
    pub weight_kg: Option<f64>,
    /// Pieces; the number of packages when absent.
    #[serde(default)]
    pub pieces: Option<u32>,
    /// What is inside, for customs and the label.
    #[serde(default)]
    pub description: Option<String>,
}

/// A booked shipment.
#[derive(Debug, Serialize, ToSchema)]
pub struct Booked {
    pub shipment_id: Uuid,
    pub carrier: String,
    pub tracking_number: String,
    /// The carrier's label, when it returned one.
    pub label_url: Option<String>,
}

/// A shipment's status after a tracking read.
#[derive(Debug, Serialize, ToSchema)]
pub struct Tracked {
    pub shipment_id: Uuid,
    pub status: Option<String>,
    /// The carrier's latest update code, when it has one.
    pub last_event_key: Option<String>,
    /// Whether this read moved the shipment.
    pub changed: bool,
}

/// What a booking request must hold. Pure.
pub fn check_booking(body: &BookBody) -> Result<(), AppError> {
    let c = &body.consignee;
    let mut missing: Vec<&str> = Vec::new();
    for (name, value) in [
        ("consignee.name", &c.name),
        ("consignee.phone", &c.phone),
        ("consignee.line1", &c.line1),
        ("consignee.city", &c.city),
    ] {
        if value.trim().is_empty() {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        return Err(AppError::Validation(format!(
            "required: {}",
            missing.join(", ")
        )));
    }
    let code = c.country_code.trim();
    if code.len() != 2 || !code.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Err(AppError::Validation(
            "consignee.country_code is a two-letter country code".into(),
        ));
    }
    if body.weight_kg.is_some_and(|w| !w.is_finite() || w <= 0.0) {
        return Err(AppError::Validation("weight_kg must be positive".into()));
    }
    if body.pieces == Some(0) {
        return Err(AppError::Validation("pieces must be at least 1".into()));
    }
    Ok(())
}

async fn release_claim(state: &EngineState, id: Uuid) {
    let released = sqlx::query(
        "UPDATE shipment SET last_event_key = NULL WHERE id = $1 AND last_event_key = $2",
    )
    .bind(id)
    .bind(BOOKING_CLAIM)
    .execute(&state.base.db)
    .await;
    if let Err(error) = released {
        tracing::warn!(%error, shipment = %id, "fulfilment: could not release a booking claim");
    }
}

/// Book a shipment with its carrier
///
/// Books a packed shipment with its carrier and stores the waybill as its
/// tracking number (status `booked`). Weight and pieces default to the
/// shipment's packages.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/shipments/{id}/book",
    operation_id = "fulfilment_shipment_book",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The shipment")),
    request_body = BookBody,
    responses(
        (status = 200, description = "Booked", body = Booked),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.update", body = ErrorResponse),
        (status = 404, description = "No such shipment", body = ErrorResponse),
        (status = 409, description = "Already booked or being booked, or the carrier is not set up", body = ErrorResponse),
        (status = 422, description = "A missing consignee field, or the carrier refused the booking", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn book(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FulfilmentOrderUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<BookBody>,
) -> Result<Json<Booked>, AppError> {
    check_booking(&body)?;
    // Claim it: not booked, and nobody else booking it right now.
    let claimed: Option<Option<String>> = sqlx::query_scalar(
        "UPDATE shipment SET last_event_key = $2, last_event_at = now() \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
            AND tracking_number IS NULL \
            AND (last_event_key IS DISTINCT FROM $2 OR last_event_at < now() - interval '5 minutes') \
          RETURNING carrier::text",
    )
    .bind(id)
    .bind(BOOKING_CLAIM)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(carrier) = claimed else {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM shipment WHERE id = $1 \
                             AND (is_active IS NULL OR is_active = true))",
        )
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::Conflict("this shipment is already booked or being booked")
        } else {
            AppError::NotFound
        });
    };
    let carrier = carrier.unwrap_or_else(|| "aramex".to_owned());
    let result = book_claimed(&state, id, &carrier, &body).await;
    let booking = match result {
        Ok(booking) => booking,
        Err(error) => {
            release_claim(&state, id).await;
            return Err(error);
        }
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE shipment SET tracking_number = $2, carrier = $3, status = 'booked', \
                last_event_key = NULL, last_event_at = now(), modified_at = now(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND tracking_number IS NULL",
    )
    .bind(id)
    .bind(&booking.tracking_number)
    .bind(&carrier)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        tracing::warn!(
            shipment = %id,
            waybill = %booking.tracking_number,
            "fulfilment: the shipment was booked meanwhile; this waybill is unused at the carrier"
        );
        return Err(AppError::Conflict("this shipment was booked meanwhile"));
    }
    change_feed::emit_tx(&mut tx, "shipment", id, ChangeOperation::Update).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "shipment",
            id,
            AuditOperation::Update,
            "fulfilment.shipment_booked",
            ctx.user_id,
        )
        .comment(format!("{carrier} waybill {}", booking.tracking_number)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(Booked {
        shipment_id: id,
        carrier,
        tracking_number: booking.tracking_number,
        label_url: booking.label_url,
    }))
}

async fn book_claimed(
    state: &EngineState,
    id: Uuid,
    carrier: &str,
    body: &BookBody,
) -> Result<seam::Booking, AppError> {
    let (weight, count): (Option<f64>, i64) = sqlx::query_as(
        "SELECT SUM(weight_kg)::float8, COUNT(*) FROM shipment_package \
          WHERE shipment_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let weight_kg = body
        .weight_kg
        .or(weight.filter(|w| *w > 0.0))
        .ok_or_else(|| {
            AppError::Validation("weight_kg is required: the packages carry no weight".into())
        })?;
    let pieces = body
        .pieces
        .unwrap_or_else(|| u32::try_from(count.max(1)).unwrap_or(1));
    let c = &body.consignee;
    let consignee = Party {
        name: c.name.trim().to_owned(),
        company: c.company.clone().unwrap_or_default(),
        phone: c.phone.trim().to_owned(),
        email: c.email.clone().unwrap_or_default(),
        line1: c.line1.trim().to_owned(),
        city: c.city.trim().to_owned(),
        country_code: c.country_code.trim().to_ascii_uppercase(),
    };
    let parcel = Parcel {
        reference: id.to_string(),
        weight_kg,
        pieces,
        description: body
            .description
            .clone()
            .unwrap_or_else(|| "Goods".to_owned()),
    };
    seam::book(state, carrier, &consignee, &parcel)
        .await?
        .ok_or(AppError::Conflict(
            "this shipment's carrier is not set up as an integration system",
        ))
}

/// Read a shipment's tracking status
///
/// Reads the latest update of the shipment's waybill from its carrier and
/// moves the shipment's status when the update is new.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/shipments/{id}/track",
    operation_id = "fulfilment_shipment_track",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The shipment")),
    responses(
        (status = 200, description = "The shipment's status", body = Tracked),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.update", body = ErrorResponse),
        (status = 404, description = "No such shipment", body = ErrorResponse),
        (status = 409, description = "The shipment is not booked with a carrier", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn track(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FulfilmentOrderUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Tracked>, AppError> {
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT carrier::text, tracking_number, status::text, last_event_key FROM shipment \
              WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (carrier, tracking, status, last_key) = row.ok_or(AppError::NotFound)?;
    let (Some(carrier), Some(tracking)) = (carrier, tracking) else {
        return Err(AppError::Conflict(
            "this shipment is not booked with a carrier",
        ));
    };
    let Some(update) = seam::track(&state, &carrier, &tracking).await? else {
        return Ok(Json(Tracked {
            shipment_id: id,
            status,
            last_event_key: last_key,
            changed: false,
        }));
    };
    if last_key.as_deref() == Some(update.code.as_str()) {
        return Ok(Json(Tracked {
            shipment_id: id,
            status,
            last_event_key: last_key,
            changed: false,
        }));
    }
    let at = update
        .at_ms
        .and_then(chrono::DateTime::from_timestamp_millis)
        .unwrap_or_else(chrono::Utc::now);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE shipment SET status = $2, last_event_key = $3, last_event_at = $4, \
                delivered_on = CASE WHEN $2 = 'delivered' THEN $4 ELSE delivered_on END, \
                modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(update.status)
    .bind(&update.code)
    .bind(at)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    change_feed::emit_tx(&mut tx, "shipment", id, ChangeOperation::Update).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "shipment",
            id,
            AuditOperation::Update,
            "fulfilment.shipment_tracked",
            ctx.user_id,
        )
        .comment(format!("{carrier} {}: {}", update.code, update.status)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(Tracked {
        shipment_id: id,
        status: Some(update.status.to_owned()),
        last_event_key: Some(update.code),
        changed: true,
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/fulfilment/shipments/{id}/book", post(book))
        .route("/api/v1/fulfilment/shipments/{id}/track", post(track))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(book, track),
    components(schemas(Consignee, BookBody, Booked, Tracked))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(country: &str) -> BookBody {
        BookBody {
            consignee: Consignee {
                name: "Sara".into(),
                company: None,
                phone: "+966500000000".into(),
                email: None,
                line1: "King Fahd Rd".into(),
                city: "Riyadh".into(),
                country_code: country.into(),
            },
            weight_kg: Some(1.2),
            pieces: None,
            description: None,
        }
    }

    #[test]
    fn a_booking_needs_the_consignee_and_a_positive_weight() {
        assert!(check_booking(&body("SA")).is_ok());
        assert!(check_booking(&body("Saudi")).is_err());
        let mut no_city = body("SA");
        no_city.consignee.city = " ".into();
        assert!(check_booking(&no_city).is_err());
        let mut heavy = body("SA");
        heavy.weight_kg = Some(0.0);
        assert!(check_booking(&heavy).is_err());
        let mut none = body("SA");
        none.pieces = Some(0);
        assert!(check_booking(&none).is_err());
    }
}
